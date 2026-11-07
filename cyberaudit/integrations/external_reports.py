"""Strict, offline normalization of external audit evidence.

An imported report proves what was supplied, not the provenance or completeness
of the original scan. Keep that distinction in the coverage record.
"""
from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from cyberaudit.core.models import Finding, Pillar, Severity

FORMATS = ("semgrep", "trivy", "checkov", "zap", "schemathesis", "junit", "k6", "sarif")
MAX_REPORT_BYTES = 32 * 1024 * 1024


@dataclass
class ImportedEvidence:
    findings: list[Finding] = field(default_factory=list)
    status: str = "PASS"
    errors: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    sha256: str = ""


def _list(value, label):
    if not isinstance(value, list):
        raise ValueError(f"{label}: se esperaba una lista")
    return value


def _severity(value):
    return {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM,
            "NOTE": Severity.LOW, "NONE": Severity.INFO}.get(
                str(value).upper(), Severity.__members__.get(str(value).upper(), Severity.MEDIUM))


def _finding(tool, rule, title, path, description="", severity="MEDIUM", line=None,
             remediation=None, cve=None, cwe=None, pillar=Pillar.SECURITY_ENGINEER):
    identity = json.dumps([tool, str(rule), str(path), line, str(title)], ensure_ascii=False)
    return Finding(
        id=f"EXT-{tool}-{hashlib.sha256(identity.encode()).hexdigest()[:20]}",
        title=str(title), description=str(description), severity=_severity(severity),
        pillar=pillar, scanner_name=f"external:{tool}", file_path=str(path),
        line_number=line, remediation=remediation, cve_id=cve, cwe_id=cwe,
    )


def parse_report(tool: str, path: str | Path) -> ImportedEvidence:
    if tool not in FORMATS:
        raise ValueError(f"Formato desconocido: {tool}")
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Reporte supera el límite de 32 MiB")
    result = ImportedEvidence(sha256=hashlib.sha256(raw).hexdigest())
    if tool in ("junit", "schemathesis"):
        _junit(raw, tool, result)
    else:
        data = json.loads(raw)
        if not isinstance(data, dict) and not (tool == "checkov" and isinstance(data, list)):
            raise ValueError("Raíz JSON inválida")
        globals()[f"_{tool}"](data, result)
    # Stable identity removes duplicate entries without merging distinct engines.
    result.findings = list({f.id: f for f in result.findings}.values())
    if result.errors:
        result.status = "ERROR"
    return result


def _semgrep(data, result):
    rows = _list(data["results"], "results")
    result.errors.extend(str(e) for e in _list(data.get("errors", []), "errors"))
    scanned = _list(data.get("paths", {}).get("scanned", []), "paths.scanned")
    result.metrics["files_scanned"] = len(scanned)
    if not scanned:
        result.status = "INCONCLUSIVE"
    for row in rows:
        extra = row["extra"]
        result.findings.append(_finding("semgrep", row["check_id"], extra["message"], row["path"],
                                       severity=extra["severity"], line=row["start"]["line"]))


def _trivy(data, result):
    if data.get("SchemaVersion") != 2:
        raise ValueError("Solo se admite el esquema JSON Trivy 2")
    rows = _list(data.get("Results", []), "Results")
    result.metrics["targets"] = len(rows)
    if not rows:
        result.status = "INCONCLUSIVE"
    for row in rows:
        target = row["Target"]
        for vuln in _list(row.get("Vulnerabilities") or [], "Vulnerabilities"):
            vid = vuln["VulnerabilityID"]
            result.findings.append(_finding("trivy", vid,
                f"{vid}: {vuln['PkgName']} {vuln.get('InstalledVersion', '')}", target,
                vuln.get("Description", ""), vuln.get("Severity"),
                remediation=f"Versión corregida: {vuln.get('FixedVersion') or 'no informada'}",
                cve=vid if vid.startswith("CVE-") else None))
        for issue in _list(row.get("Misconfigurations") or [], "Misconfigurations"):
            if issue.get("Status", "FAIL") == "PASS":
                continue
            result.findings.append(_finding("trivy", issue["ID"], issue["Title"], target,
                issue.get("Message", ""), issue.get("Severity"), remediation=issue.get("Resolution")))
        for secret in _list(row.get("Secrets") or [], "Secrets"):
            # Never copy the matched secret into the normalized finding.
            result.findings.append(_finding("trivy", secret["RuleID"], secret["Title"], target,
                "Secreto potencial detectado; revisar evidencia restringida.", secret.get("Severity"),
                line=secret.get("StartLine")))


def _checkov(data, result):
    blocks = data if isinstance(data, list) else [data]
    passed = failed = skipped = 0
    if not blocks:
        result.status = "INCONCLUSIVE"
    for block in blocks:
        checks = block["results"]
        passed += len(_list(checks.get("passed_checks", []), "passed_checks"))
        skipped += len(_list(checks.get("skipped_checks", []), "skipped_checks"))
        result.errors.extend(str(e) for e in _list(checks.get("parsing_errors", []), "parsing_errors"))
        for check in _list(checks["failed_checks"], "failed_checks"):
            failed += 1
            lines = check.get("file_line_range") or []
            result.findings.append(_finding("checkov", check["check_id"], check["check_name"],
                check["file_path"], str(check.get("resource", "")), check.get("severity") or "MEDIUM",
                line=lines[0] if lines else None, remediation=check.get("guideline"),
                pillar=Pillar.CLOUD_DEFENSE))
    result.metrics.update(passed=passed, failed=failed, skipped=skipped)
    if not passed + failed or skipped:
        result.status = "INCONCLUSIVE"


def _zap(data, result):
    sites = _list(data["site"], "site")
    result.metrics["sites"] = len(sites)
    # An alerts report alone cannot establish completed crawling/active scanning.
    result.status = "INCONCLUSIVE"
    for site in sites:
        for alert in _list(site["alerts"], "alerts"):
            severity = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}[str(alert["riskcode"])]
            instances = _list(alert.get("instances", []), "instances") or [{"uri": site["@name"]}]
            for instance in instances:
                result.findings.append(_finding("zap", alert["pluginid"], alert["alert"], instance["uri"],
                    alert.get("desc", ""), severity, remediation=alert.get("solution"),
                    cwe=f"CWE-{alert['cweid']}" if str(alert.get("cweid", "0")) != "0" else None,
                    pillar=Pillar.PENETRATION_TESTER))


def _k6(data, result):
    metrics = data["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("metrics debe ser objeto")
    count = failures = 0
    for name, metric in metrics.items():
        for expression, state in metric.get("thresholds", {}).items():
            # Modern handleSummary format uses {ok: bool}; legacy summary-export
            # uses a boolean indicating FAILURE, i.e. the inverse of ok.
            ok = state.get("ok") if isinstance(state, dict) else (not state if type(state) is bool else None)
            if type(ok) is not bool:
                raise ValueError("Resultado de umbral k6 inválido")
            count += 1
            if not ok:
                failures += 1
                result.findings.append(_finding("k6", f"{name}:{expression}",
                    f"Umbral incumplido: {name} {expression}", name,
                    json.dumps(metric.get("values", {})), "HIGH", pillar=Pillar.SOFTWARE_QA))
    result.metrics.update(thresholds=count, failed_thresholds=failures)
    result.metrics["measurements"] = {name: value.get("values", {}) for name, value in metrics.items()}
    if not count:
        result.status = "INCONCLUSIVE"


def _junit(raw, tool, result):
    # Reject DTD/entity declarations before ElementTree to avoid entity expansion.
    text = raw.decode("utf-8-sig")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("DTD y entidades XML no permitidas")
    root = ET.fromstring(text)
    if root.tag not in ("testsuite", "testsuites"):
        raise ValueError("Raíz JUnit inválida")
    cases = list(root.iter("testcase"))
    skipped = 0
    for case in cases:
        skipped += case.find("skipped") is not None
        error = case.find("error")
        failure = case.find("failure")
        if error is not None:
            result.errors.append(f"{case.get('name')}: {error.get('message', '')}")
        if failure is not None:
            result.findings.append(_finding(tool, case.get("classname", ""), case.get("name", "Sin nombre"),
                case.get("file", case.get("classname", "")),
                failure.get("message", "") + "\n" + (failure.text or ""), "HIGH", pillar=Pillar.SOFTWARE_QA))
    declared = sum(int(s.get("tests", "0")) for s in root.iter("testsuite") if not list(s.findall("testsuite")))
    if declared and declared != len(cases):
        result.errors.append("Conteo JUnit no coincide con los casos preservados")
    result.metrics.update(tests=len(cases), skipped=skipped, failures=len(result.findings), errors=len(result.errors))
    if not cases or skipped:
        result.status = "INCONCLUSIVE"


def _sarif(data, result):
    if data.get("version") != "2.1.0":
        raise ValueError("Solo se admite SARIF 2.1.0")
    runs = _list(data["runs"], "runs")
    if not runs:
        result.status = "INCONCLUSIVE"
    for run in runs:
        engine = run["tool"]["driver"]["name"]
        invocations = run.get("invocations", [])
        if not invocations or any(i.get("executionSuccessful") is not True for i in invocations):
            result.status = "INCONCLUSIVE"
        for row in _list(run.get("results", []), "results"):
            locations = row.get("locations", [])
            loc = locations[0].get("physicalLocation", {}) if locations else {}
            result.findings.append(_finding(f"sarif:{engine}", row.get("ruleId", "unknown"),
                row["message"].get("text") or row["message"].get("markdown", "Sin descripción"),
                loc.get("artifactLocation", {}).get("uri", ""), severity=row.get("level", "warning"),
                line=loc.get("region", {}).get("startLine")))
