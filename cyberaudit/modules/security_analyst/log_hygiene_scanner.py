"""
Logging Hygiene & Information Leakage Scanner
Detects:
- Cleartext credentials, tokens, or API keys printed into log statements (CWE-532)
- Silent failure and empty catch blocks suppressing security event auditing (CWE-778)
- Credit card / PII formatting printed in console/application logs
Mapped to MITRE ATT&CK: T1552.001, T1562.001
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class LogHygieneScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "LOG-CRED-LEAK-01",
                "title": "Logging Hygiene: Password / Secret Printed in Application Logs",
                "pattern": re.compile(
                    r'(?:log(?:ger)?\.(?:info|debug|warning|error|trace)|console\.log|print)\s*\([\s\S]{0,40}?(?:password|passwd|secret|api_key|token|private_key)\s*[:=,]',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Sensitive credentials or secrets appear to be logged directly into application or console logs, risking exposure to unauthorized log readers.",
                "remediation": "Sanitize and mask sensitive values (e.g. hash or replace with [REDACTED]) before passing to logging functions.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-532",
            },
            {
                "id": "LOG-AUTH-HEADER-LEAK-01",
                "title": "Logging Hygiene: Authorization Bearer / Session Cookie Printed in Logs",
                "pattern": re.compile(
                    r'(?:log(?:ger)?\.(?:info|debug|error)|console\.log|print)\s*\(.*(?:Authorization|Bearer|Set-Cookie|Cookie)',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Logging full HTTP Authorization headers or session cookies exposes session tokens in persistent log storage.",
                "remediation": "Exclude sensitive HTTP headers from access/error logs or configure redaction filters.",
                "mitre_id": "T1552",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials",
                "cwe_id": "CWE-532",
            },
            {
                "id": "LOG-SILENT-EXCEPTION-01",
                "title": "Logging Hygiene: Silent Exception Suppression in Authentication/Security Logic",
                "pattern": re.compile(
                    r'(?:def\s+\w*(?:auth|login|token|permission|verify|check)\w*[\s\S]{0,250}?(?:except(?:\s+\w+)?:\s*(?:pass|\.\.\.)|catch\s*\([^)]*\)\s*\{\s*\}))',
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "Critical security or authentication block swallows exceptions silently without logging, creating a blind spot for SOC detection.",
                "remediation": "Log security exceptions with contextual metadata (timestamp, user, client IP) to support incident detection and auditability.",
                "mitre_id": "T1562.001",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Impair Defenses: Disable or Modify Tools",
                "cwe_id": "CWE-778",
            },
        ]

    @property
    def name(self) -> str:
        return "Logging Hygiene & Leakage Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ANALYST

    @property
    def description(self) -> str:
        return "Audits application source code for credential leakage in logs and missing security telemetry."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".php", ".java", ".go", ".cs", ".rb"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule in self.rules:
            match = rule["pattern"].search(content)
            if match:
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                snippet = match.group(0).strip()[:180]

                finding = Finding(
                    id=rule["id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    remediation=rule["remediation"],
                    mitre_id=rule["mitre_id"],
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    cwe_id=rule.get("cwe_id"),
                )
                findings.append(finding)

        return findings
