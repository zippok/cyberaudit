"""Reproducible external audit jobs with explicit coverage and preserved evidence."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from cyberaudit.core.models import ScanReport, Severity
from cyberaudit.core.sarif_exporter import generate_sarif_report
from cyberaudit.integrations.external_reports import FORMATS, MAX_REPORT_BYTES, parse_report
from cyberaudit.kali.executor import KaliExecutor, KaliExecutionDisabled
from cyberaudit.kali.tool_registry import KaliTool, KaliCategory, RiskLevel
from cyberaudit.integrations.network_steps import NETWORK_TOOLS, authorize_step, prepare_network, zap_command
from cyberaudit.kali.scope import ScopeViolationError
from cyberaudit.integrations.authentication import auth_settings, verify_authentication
from cyberaudit.web.organization import confined_path

LOCAL_TOOLS = ("semgrep", "trivy", "checkov")


class ExternalExecutor(KaliExecutor):
    def __init__(self, *args, credential=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.credential = credential

    def _sanitized_env(self):
        env = super()._sanitized_env()
        home = Path(self.work_dir) / "tool-home"
        home.mkdir(exist_ok=True)
        for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            env[key] = str(home)
        cache = Path(__file__).resolve().parents[2] / ".tools/cache/trivy"
        cache.mkdir(parents=True, exist_ok=True)
        env["TRIVY_CACHE_DIR"] = str(cache)
        env["PYTHONUTF8"] = "1"
        if self.credential:
            env["CYBERAUDIT_SCAN_CREDENTIAL"] = self.credential
        return env
PROFILES = {
    "source": ("semgrep", "trivy"),
    "infrastructure": ("checkov", "trivy"),
    "web": ("semgrep", "trivy", "zap", "schemathesis", "k6"),
    "complete": ("semgrep", "trivy", "checkov", "zap", "schemathesis", "k6", "junit"),
}


def inventory():
    return [{"tool": name, "executable": resolve_executable(name),
             "execution": "local" if name in LOCAL_TOOLS else "scoped-network" if name in NETWORK_TOOLS else "import",
             "formats": "junit" if name == "schemathesis" else name}
            for name in FORMATS]


def resolve_executable(name):
    installed = shutil.which(name)
    if installed:
        return installed
    root = Path(__file__).resolve().parents[2]
    tools_dir = root / (".tools" if os.name == "nt" else ".tools/linux")
    if os.name == "nt" and name == "semgrep":
        wrapper = root / ".tools/semgrep/Scripts/pysemgrep.exe"
        if wrapper.is_file():
            return str(wrapper)
    if name == "zap":
        command = zap_command(root)
        return command[0] if command else None
    native = tools_dir / "bin" / (name + ".exe" if os.name == "nt" else name)
    if native.is_file():
        return str(native)
    if name == "checkov":
        python = tools_dir / "checkov" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if python.is_file():
            return str(python)
    isolated = tools_dir / name / ("Scripts" if os.name == "nt" else "bin") / (name + ".exe" if os.name == "nt" else name)
    return str(isolated) if isolated.is_file() else None


def _atomic_json(path, data):
    path = Path(path)
    temp = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("x", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def load_plan(path):
    """Resolve all paths relative to the plan, never the caller's cwd."""
    path = confined_path(path).resolve(strict=True)
    with path.open(encoding="utf-8-sig") as handle:
        plan = json.load(handle)
    if not isinstance(plan, dict) or plan.get("version") != 1:
        raise ValueError("Plan debe declarar version: 1")
    if set(plan) - {"version", "target", "profile", "steps", "fail_on"}:
        raise ValueError("Campos desconocidos en el plan")
    target = confined_path(path.parent / plan["target"]).resolve(strict=True)
    if not target.is_dir():
        raise ValueError("target debe ser un directorio")
    plan["target"] = str(target)
    if plan.get("profile", "complete") not in PROFILES:
        raise ValueError("Perfil desconocido")
    if plan.get("fail_on", "HIGH") not in Severity.__members__:
        raise ValueError("fail_on inválido")
    if not isinstance(plan.get("steps"), list) or not plan["steps"]:
        raise ValueError("El plan debe contener steps")
    seen = set()
    for step in plan["steps"]:
        if not isinstance(step, dict) or set(step) - {"tool", "mode", "report", "config", "timeout", "url", "scope", "schema", "vus", "duration_seconds", "p95_ms", "auth"}:
            raise ValueError("Paso inválido o con campos desconocidos")
        tool = step.get("tool")
        if tool not in FORMATS or tool in seen:
            raise ValueError("Herramienta desconocida o duplicada")
        seen.add(tool)
        if "auth" in step:
            auth_settings(step, resolve_secret=False)
        mode = step.get("mode", "import")
        if "auth" in step and mode != "run":
            raise ValueError("La autenticación requiere ejecución real; no se acredita mediante importación")
        if mode not in ("import", "run") or (mode == "run" and tool not in LOCAL_TOOLS + NETWORK_TOOLS):
            raise ValueError("Herramienta sin ejecución directa")
        if mode == "run" and tool in NETWORK_TOOLS:
            if not step.get("url") or not step.get("scope"):
                raise ValueError("Las pruebas de red requieren url y scope")
            if tool == "schemathesis" and not step.get("schema"):
                raise ValueError("Schemathesis requiere schema local")
        timeout = step.get("timeout", 300)
        if type(timeout) is not int or not 1 <= timeout <= 3600:
            raise ValueError("timeout debe ser entero entre 1 y 3600")
        if mode == "import" and "report" not in step:
            raise ValueError("Falta report en paso de importación")
        if mode == "run" and tool == "semgrep" and "config" not in step:
            raise ValueError("Semgrep requiere reglas locales explícitas en config")
        for key in ("report", "config", "scope", "schema"):
            if key in step:
                local = confined_path(path.parent / step[key]).resolve(strict=True)
                if not local.is_file():
                    raise ValueError(f"{key} debe ser un archivo local")
                step[key] = str(local)
    return plan


def build_argv(tool, executable, target, config=None):
    if tool == "semgrep":
        if not config:
            raise ValueError("Se requieren reglas Semgrep")
        # An ancestor Git repository can otherwise make native Windows discovery
        # traverse the user's entire home. The plan target is the project boundary.
        return [executable, "scan", "--config", config, "--json", "--metrics=off",
                "--disable-version-check", "--project-root", target, target]
    if tool == "trivy":
        return [executable, "filesystem", "--format", "json", "--scanners", "vuln,misconfig,secret",
                "--exit-code", "0", target]
    if tool == "checkov":
        prefix = [executable, "-m", "checkov.main"] if Path(executable).stem.lower().startswith("python") else [executable]
        return prefix + ["--directory", target, "--output", "json", "--compact", "--soft-fail", "--skip-download"]
    raise ValueError("Herramienta no ejecutable")


def run_plan(plan_path, output_root="reports/external", execute=False):
    """Default is a dry plan. Imports are processed only with execute=True too."""
    plan = load_plan(plan_path)
    root = Path(output_root).resolve() / uuid.uuid4().hex
    root.mkdir(parents=True, exist_ok=False)
    report = ScanReport(target_path=plan["target"])
    job = {"schema_version": 1, "id": root.name, "status": "RUNNING",
           "started_at": datetime.now(timezone.utc).isoformat(), "plan": plan,
           "coverage": {}, "evidence": [], "report": None}
    _atomic_json(root / "job.json", job)
    required = PROFILES[plan.get("profile", "complete")]
    job["coverage"] = {name: {"status": "NOT_RUN", "reason": "No incluido en el plan"} for name in required}
    try:
        for index, step in enumerate(plan["steps"]):
            tool = step["tool"]
            record = {"tool": tool, "mode": step.get("mode", "import"), "status": "NOT_RUN"}
            job["coverage"][tool] = record
            directory = root / f"{index:02d}-{tool}"
            directory.mkdir()
            try:
                if record["mode"] == "run":
                    executable = resolve_executable(tool)
                    network = tool in NETWORK_TOOLS
                    artifact = None
                    accepted_codes = (0,)
                    if network:
                        argv, artifact, accepted_codes = prepare_network(step, directory, executable or tool)
                    else:
                        argv = build_argv(tool, executable or tool, plan["target"], step.get("config"))
                    record["argv"] = argv
                    if not execute:
                        record["reason"] = "Plan sin ejecutar"
                        continue
                    if not executable:
                        record["reason"] = "Herramienta no instalada en PATH"
                        continue
                    if network:
                        record["authorization"] = authorize_step(step)
                    authentication = auth_settings(step) if network else None
                    if authentication:
                        record["authentication_before"] = verify_authentication(step)
                    descriptor = KaliTool(key=tool, binaries=(tool,), title=tool,
                        category=KaliCategory.FORENSIC, description="Auditoría externa", risk=RiskLevel.INTRUSIVE if network else RiskLevel.PASSIVE,
                        profiles=(), install_hint="Instalar desde el proveedor", reference="")
                    run = ExternalExecutor(str(directory), max_output_bytes=MAX_REPORT_BYTES,
                        credential=authentication["secret"] if authentication else None).run(
                        descriptor, argv, timeout=step.get("timeout", 300), artifact_paths=[str(artifact)] if artifact else [])
                    record["process"] = run.to_dict()
                    if run.error or run.returncode not in accepted_codes:
                        raise ValueError(run.error or f"Proceso terminó con código {run.returncode}")
                    if authentication:
                        record["authentication_after"] = verify_authentication(step)
                    source = artifact or Path(run.stdout_path)
                else:
                    if not execute:
                        record["reason"] = "Plan sin importar"
                        continue
                    source = Path(step["report"])
                # Copy bounded bytes once: parsing and digest cover the preserved copy.
                with source.open("rb") as handle:
                    raw = handle.read(MAX_REPORT_BYTES + 1)
                if len(raw) > MAX_REPORT_BYTES:
                    raise ValueError("Evidencia excede 32 MiB")
                evidence = directory / ("evidence.xml" if tool in ("junit", "schemathesis") else "evidence.json")
                with evidence.open("xb") as handle:
                    handle.write(raw)
                entry = {"tool": tool, "path": str(evidence.relative_to(root)),
                         "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                         "origin": "imported" if record["mode"] == "import" else "executed"}
                job["evidence"].append(entry)
                parsed = parse_report(tool, evidence)
                if record["mode"] == "run" and tool == "zap" and parsed.metrics.get("sites", 0) > 0:
                    parsed.status = "PASS"
                    parsed.metrics["execution_profile"] = "bounded passive DAST; no active exploitation"
                if record["mode"] == "run" and tool in NETWORK_TOOLS and run.returncode != 0 and not parsed.findings:
                    parsed.errors.append("Proceso no exitoso sin fallos explicados en el reporte")
                    parsed.status = "ERROR"
                record.update(status=parsed.status, metrics=parsed.metrics, errors=parsed.errors,
                              findings=len(parsed.findings), provenance=entry["origin"])
                report.findings.extend(parsed.findings)
                if parsed.status == "PASS":
                    report.scanners_executed.append(f"external:{tool}")
                if parsed.errors:
                    report.execution_errors.append({"scanner": tool, "error": "; ".join(parsed.errors)})
            except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError, KaliExecutionDisabled, ScopeViolationError) as exc:
                record.update(status="ERROR", reason=str(exc))
                report.execution_errors.append({"scanner": tool, "error": str(exc)})
            finally:
                _atomic_json(root / "job.json", job)
        statuses = [entry["status"] for entry in job["coverage"].values()]
        report.execution_status = ("NOT_RUN" if not execute else "ERROR" if "ERROR" in statuses
                                   else "PASS" if all(s == "PASS" for s in statuses) else "INCONCLUSIVE")
        report.scanner_results = list(job["coverage"].values())
        # Evidence manifest hash is NOT a source-tree digest usable for certification.
        job["evidence_digest"] = hashlib.sha256(json.dumps(job["evidence"], sort_keys=True).encode()).hexdigest()
        threshold = Severity[plan.get("fail_on", "HIGH")].rank
        job["gate"] = ("BLOCKED" if report.execution_status != "PASS" else
                       "FAIL" if any(f.severity.rank >= threshold for f in report.findings) else "PASS")
        job["status"] = "COMPLETED" if execute else "PLANNED"
        job["report"] = report.to_dict()
        _atomic_json(root / "report.json", job["report"])
        _atomic_json(root / "report.sarif", generate_sarif_report(report, base_dir=plan["target"]))
    except BaseException:
        job["status"] = "INTERRUPTED"
        raise
    finally:
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
        _atomic_json(root / "job.json", job)
    return job, root


def verify_evidence(job_dir):
    root = Path(job_dir).resolve(strict=True)
    job = json.loads((root / "job.json").read_text(encoding="utf-8"))
    errors = []
    expected = hashlib.sha256(json.dumps(job["evidence"], sort_keys=True).encode()).hexdigest()
    if job.get("evidence_digest") != expected:
        errors.append("Manifiesto de evidencia modificado o incompleto")
    for evidence in job["evidence"]:
        path = (root / evidence["path"]).resolve()
        if not path.is_relative_to(root):
            errors.append(f"Ruta fuera del trabajo: {evidence['path']}")
            continue
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_REPORT_BYTES + 1)
            if len(raw) != evidence["bytes"] or hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
                errors.append(f"Evidencia modificada: {evidence['path']}")
        except OSError:
            errors.append(f"Evidencia ausente: {evidence['path']}")
    return errors
