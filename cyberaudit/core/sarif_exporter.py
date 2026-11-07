"""
CyberAudit SARIF 2.1.0 Compliance Exporter
Produces OASIS Static Analysis Results Interchange Format (SARIF) v2.1.0 JSON reports
fully compatible with GitHub Advanced Security and GitLab Security Dashboard.
"""

import json
import os
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from cyberaudit.core.models import ScanReport, Finding, Severity
from cyberaudit.core.finding_correlator import FindingFingerprinter


SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _severity_to_sarif_level(severity: Severity) -> str:
    """Maps CyberAudit Severity to SARIF 2.1.0 result level."""
    val = severity.value if isinstance(severity, Severity) else str(severity).upper()
    if val in ("CRITICAL", "HIGH"):
        return "error"
    elif val == "MEDIUM":
        return "warning"
    else:
        return "note"


def _severity_to_security_score(severity: Severity) -> str:
    """
    Maps Severity to GitHub Advanced Security numeric security-severity score (0.0 to 10.0 CVSS scale).
    """
    val = severity.value if isinstance(severity, Severity) else str(severity).upper()
    scores = {
        "CRITICAL": "9.8",
        "HIGH": "7.5",
        "MEDIUM": "5.0",
        "LOW": "2.5",
        "INFO": "0.5",
    }
    return scores.get(val, "5.0")


def _cwe_to_help_uri(cwe_id: Optional[str]) -> Optional[str]:
    """Generates canonical MITRE CWE reference URL if CWE ID is present."""
    if not cwe_id:
        return None
    m = re.search(r"(\d+)", cwe_id)
    if m:
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
    return None


def generate_sarif_report(report: ScanReport, base_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Transforms a CyberAudit ScanReport into an OASIS SARIF v2.1.0 dictionary.
    
    Compatible with:
    - GitHub Advanced Security Code Scanning (ghas)
    - GitLab Security Dashboard (SAST artifact)
    - Azure DevOps CodeAnalysis (SARIF viewer)
    """
    root_dir = os.path.abspath(base_dir or report.target_path or ".")
    
    # Build unique rules table for driver
    rules_map: Dict[str, int] = {}
    sarif_rules: List[Dict[str, Any]] = []

    for f in report.findings:
        rule_id = f.id or f.scanner_name or "GENERIC_SECURITY_RULE"
        if rule_id not in rules_map:
            rule_idx = len(sarif_rules)
            rules_map[rule_id] = rule_idx

            rule_level = _severity_to_sarif_level(f.severity)
            sec_score = _severity_to_security_score(f.severity)
            help_uri = _cwe_to_help_uri(f.cwe_id)

            tags = ["security"]
            if f.cwe_id:
                tags.append(f"external/cwe/{f.cwe_id.lower().replace(' ', '-')}")
            if f.mitre_id:
                tags.append(f"mitre/{f.mitre_id.lower()}")
            if f.stride_category:
                tags.append(f"stride/{f.stride_category.lower()}")

            rule_obj: Dict[str, Any] = {
                "id": rule_id,
                "name": re.sub(r"[^a-zA-Z0-9_-]", "_", f.title)[:64] if f.title else rule_id,
                "shortDescription": {
                    "text": f.title or rule_id
                },
                "fullDescription": {
                    "text": f.description or f.title or rule_id
                },
                "defaultConfiguration": {
                    "level": rule_level
                },
                "properties": {
                    "tags": tags,
                    "precision": "very-high",
                    "security-severity": sec_score,
                    "problem.severity": "error" if rule_level == "error" else ("warning" if rule_level == "warning" else "recommendation")
                }
            }

            if help_uri:
                rule_obj["helpUri"] = help_uri
            if f.remediation:
                rule_obj["help"] = {
                    "text": f"Remediation Guidance:\n{f.remediation}",
                    "markdown": f"### Remediation Guidance\n{f.remediation}"
                }

            sarif_rules.append(rule_obj)

    # Build results list
    sarif_results: List[Dict[str, Any]] = []
    fingerprinter = FindingFingerprinter()

    for f in report.findings:
        rule_id = f.id or f.scanner_name or "GENERIC_SECURITY_RULE"
        rule_idx = rules_map.get(rule_id, 0)
        level = _severity_to_sarif_level(f.severity)

        # Normalize relative path with forward slashes for cross-platform SARIF
        file_path = f.file_path or "unknown_source.py"
        if os.path.isabs(file_path):
            try:
                rel_path = os.path.relpath(file_path, root_dir)
            except ValueError:
                rel_path = file_path
        else:
            rel_path = file_path
        normalized_uri = rel_path.replace("\\", "/")

        start_line = max(1, f.line_number or 1)

        result_msg = f"{f.title}: {f.description}" if f.description and f.description != f.title else f.title

        location_obj: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": normalized_uri,
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": start_line,
                    "startColumn": 1,
                    "endLine": start_line,
                    "endColumn": 80
                }
            }
        }

        if f.code_snippet:
            location_obj["physicalLocation"]["region"]["snippet"] = {
                "text": f.code_snippet.strip()
            }

        # Calculate structural invariant fingerprint
        finding_dict = f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else {})
        struct_fp = fingerprinter.fingerprint(finding_dict)

        result_obj: Dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_idx,
            "level": level,
            "message": {
                "text": result_msg
            },
            "locations": [location_obj],
            "partialFingerprints": {
                "primaryLocationLineHash": struct_fp
            },
            "properties": {
                "scanner": f.scanner_name,
                "cwe": f.cwe_id,
                "mitre": f.mitre_id,
                "mitreTactic": f.mitre_tactic,
                "remediation": f.remediation
            }
        }

        sarif_results.append(result_obj)

    sarif_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CyberAudit Suite",
                        "fullName": "CyberAudit Suite Enterprise AST & Security Engine",
                        "version": "2.0.0",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/cyberaudit/cyberaudit",
                        "rules": sarif_rules
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report.execution_status == "PASS" and not report.execution_errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": str(error.get("error", error))}}
                            for error in report.execution_errors
                        ],
                        "endTimeUtc": datetime.now(timezone.utc).isoformat()
                    }
                ],
                "results": sarif_results
            }
        ]
    }

    return sarif_doc


def export_sarif_file(report: ScanReport, output_file: str, base_dir: Optional[str] = None) -> str:
    """
    Serializes a ScanReport to a SARIF 2.1.0 JSON file on disk.
    Returns the absolute path to the generated SARIF file.
    """
    output_path = os.path.abspath(output_file)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    sarif_data = generate_sarif_report(report, base_dir=base_dir)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2, ensure_ascii=False)
        
    return output_path
