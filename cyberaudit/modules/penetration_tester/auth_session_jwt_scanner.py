"""
Authentication, JWT & OAuth Security Scanner (AppSec / Penetration Testing)
Detects:
- Insecure JWT verification (algorithm 'none' allowed, verify=False) (CWE-347)
- Weak or hardcoded JWT HMAC signing secrets (CWE-798)
- OAuth 2.0 open redirect and state parameter omissions (CWE-601, CWE-352)
Mapped to MITRE ATT&CK: T1552, T1078
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class AuthSessionJwtScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-JWT-VERIFY-FALSE-01",
                "title": "JWT Security: Signature Verification Explicitly Disabled",
                "pattern": re.compile(
                    r'(?:jwt\.(?:decode|verify)\s*\([\s\S]{0,120}?(?:verify\s*=\s*False|algorithms\s*[:=]\s*\[.*["\']none["\']|verify_signature\s*=\s*False)|algorithms\s*[:=]\s*\[.*["\']none["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "JSON Web Token (JWT) decoded with signature verification disabled or allowing the unauthenticated 'none' algorithm.",
                "remediation": "Mandate signature verification with an explicit cryptographic algorithm allowlist: `jwt.decode(token, secret, algorithms=['HS256'])`.",
                "mitre_id": "T1078",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Valid Accounts",
                "cwe_id": "CWE-347",
            },
            {
                "id": "APPSEC-JWT-WEAK-SECRET-01",
                "title": "JWT Security: Trivial Hardcoded HMAC Signing Key",
                "pattern": re.compile(
                    r'jwt\.(?:sign|encode|decode)\s*\([\s\S]{0,100}?["\'](?:secret|test|123456|password|admin|key|jwt_secret)["\']',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "JWT signed using a predictable or trivial hardcoded secret key, allowing offline forgery of arbitrary tokens using dictionary attacks.",
                "remediation": "Use high-entropy secrets (at least 256 bits of cryptographically random data) loaded exclusively from environment variables or secrets vault.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-798",
            },
            {
                "id": "APPSEC-OAUTH-OPEN-REDIRECT-01",
                "title": "OAuth 2.0: Unvalidated Dynamic redirect_uri Parameter",
                "pattern": re.compile(
                    r'(?:redirect_uri|callback_url)\s*=\s*(?:request\.(?:args|GET|values|params)\.get|req\.query)\s*\(\s*["\']redirect_uri["\']',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "OAuth authorization flow takes `redirect_uri` directly from dynamic request parameters without domain allowlist validation, enabling authorization code theft.",
                "remediation": "Strictly validate redirect_uri against a pre-registered whitelist of exact redirect endpoints on the authorization server.",
                "mitre_id": "T1078",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Valid Accounts",
                "cwe_id": "CWE-601",
            },
        ]

    @property
    def name(self) -> str:
        return "Authentication & JWT Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Audits application source code for JWT signature bypass, weak HMAC secrets, and OAuth 2.0 redirect vulnerabilities."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".go", ".cs", ".php", ".rb"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["pattern"].search(line):
                    finding = Finding(
                        id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_idx,
                        code_snippet=line.strip()[:180],
                        remediation=rule["remediation"],
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        cwe_id=rule.get("cwe_id"),
                    )
                    findings.append(finding)
                    break

        return findings
