"""Bounded, scope-authorized API, load and passive ZAP jobs."""
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

import yaml

from cyberaudit.kali.scope import ScopeGuard
from cyberaudit.kali.tool_registry import RiskLevel
from cyberaudit.web_auditor.browser_probes import check_http_url
from cyberaudit.integrations.authentication import auth_settings

NETWORK_TOOLS = ("schemathesis", "k6", "zap")


def authorize_step(step):
    check_http_url(step["url"])
    return ScopeGuard.from_file(step["scope"]).authorize(step["url"], RiskLevel.INTRUSIVE).to_dict()


def zap_command(root):
    if os.name != "nt":
        executable = shutil.which("zaproxy") or shutil.which("zap.sh")
        return [executable] if executable else None
    java = next((root / ".tools/java").glob("*/bin/java.exe"), None)
    jar = next((root / ".tools/zap").glob("*/zap-*.jar"), None)
    return [str(java), "-Xmx1024m", "-jar", str(jar)] if java and jar else None


def prepare_network(step, directory, executable):
    tool, url = step["tool"], check_http_url(step["url"])
    auth = auth_settings(step, resolve_secret=False)
    if tool == "k6":
        artifact = directory / "k6-summary.json"
        duration = step.get("duration_seconds", 10)
        vus = step.get("vus", 1)
        threshold = step.get("p95_ms", 1000)
        for value, maximum in ((duration, 60), (vus, 10), (threshold, 60000)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("Límite k6 inválido")
        config = {"vus": vus, "duration": f"{duration}s", "maxRedirects": 0,
                  "thresholds": {"http_req_duration": [f"p(95)<{threshold}"], "http_req_failed": ["rate<0.01"]}}
        script = ("import http from 'k6/http'; import {sleep} from 'k6';\n"
                  f"export const options = {json.dumps(config)};\n"
                  f"export default function() {{ http.get({json.dumps(url)}, {{timeout:'10s',redirects:0}}); sleep(0.5); }}\n"
                  f"export function handleSummary(data) {{return {{[{json.dumps(str(artifact))}]: JSON.stringify(data)}};}}\n")
        script_path = directory / "load.js"
        script_path.write_text(script, encoding="utf-8")
        return [executable, "run", str(script_path)], artifact, (0, 99)
    if tool == "schemathesis":
        schema = yaml.safe_load(Path(step["schema"]).read_text(encoding="utf-8"))
        def validate(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "$ref" and (not isinstance(item, str) or not item.startswith("#")):
                        raise ValueError("Solo se admiten referencias locales dentro del esquema")
                    validate(item)
            elif isinstance(value, list):
                for item in value:
                    validate(item)
        validate(schema)
        if not isinstance(schema, dict) or not schema.get("paths"):
            raise ValueError("Se requiere un esquema OpenAPI con paths")
        # Copy reviewed input to evidence directory. The CLI base URL overrides servers.
        schema_path = directory / "openapi.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        artifact = directory / "schemathesis.xml"
        prefix = [executable]
        if auth:
            config_path = directory / "schemathesis.toml"
            config_path.write_text('headers = {' + json.dumps(auth["header"]) + ' = "${CYBERAUDIT_SCAN_CREDENTIAL}"}\n', encoding="utf-8")
            prefix += ["--config-file", str(config_path)]
        return prefix + ["run", str(schema_path), "--url", url, "--workers", "1",
                "--include-method", "GET", "--phases", "examples,fuzzing", "--max-examples", "10",
                "--max-failures", "10", "--request-timeout", "10", "--max-redirects", "0",
                "--rate-limit", "5/s", "--report", "junit", "--report-junit-path", str(artifact)], artifact, (0, 1)
    if tool == "zap":
        command = zap_command(Path(__file__).resolve().parents[2])
        if not command:
            raise FileNotFoundError("ZAP o Java no instalado")
        parts = urlsplit(url)
        base = f"{parts.scheme}://{parts.netloc}"
        plan = {"env": {"contexts": [{"name": "authorized", "urls": [url],
            "includePaths": [re.escape(base) + r"/.*"]}], "parameters": {"failOnError": True, "failOnWarning": True}},
            "jobs": [{"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True}},
                     {"type": "spider", "parameters": {"context": "authorized", "url": url, "maxDuration": 1,
                        "maxDepth": 2, "processForm": False, "postForm": False}},
                     {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
                     {"type": "report", "parameters": {"template": "traditional-json", "reportDir": str(directory),
                        "reportFile": "zap-report", "reportTitle": "CyberAudit passive web audit"}}]}
        plan_path = directory / "zap-plan.yaml"
        if auth:
            script = directory / "scoped-auth.js"
            script.write_text('''var System = Java.type('java.lang.System');
function sendingRequest(msg, initiator, helper) {
  var u = msg.getRequestHeader().getURI();
  var port = u.getPort() < 0 ? (String(u.getScheme()) === 'https' ? 443 : 80) : u.getPort();
  var allowed = String(u.getScheme()) === SCHEME && String(u.getHost()) === HOST && port === PORT;
  msg.getRequestHeader().setHeader(HEADER, allowed ? System.getenv('CYBERAUDIT_SCAN_CREDENTIAL') : null);
}
function responseReceived(msg, initiator, helper) {
  msg.getRequestHeader().setHeader(HEADER, null);
}
'''.replace('SCHEME', json.dumps(parts.scheme)).replace('HOST', json.dumps(parts.hostname)).replace('PORT', str(parts.port or (443 if parts.scheme == 'https' else 80))).replace('HEADER', json.dumps(auth["header"])), encoding="utf-8")
            plan["jobs"].insert(0, {"type": "script", "parameters": {"action": "add", "type": "httpsender",
                "engine": "ECMAScript : Graal.js", "name": "cyberaudit-scoped-auth", "source": str(script)}})
        plan_path.write_text(yaml.safe_dump(plan), encoding="utf-8")
        home = directory / "zap-home"
        home.mkdir()
        return command + ["-cmd", "-silent", "-dir", str(home), "-autorun", str(plan_path)], directory / "zap-report.json", (0,)
    raise ValueError("Herramienta de red desconocida")
