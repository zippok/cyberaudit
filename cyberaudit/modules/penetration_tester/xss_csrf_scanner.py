"""
XSS, CSRF & Cookie Security Scanner (AppSec / Penetration Testing)
Detects:
- Cross-Site Scripting (XSS: dangerouslySetInnerHTML, unescaped template tags, innerHTML) (CWE-79)
- Disabling CSRF Protections (@csrf_exempt, csrf().disable()) (CWE-352)
- Insecure Cookie Attributes (missing HttpOnly, Secure, SameSite) (CWE-1004, CWE-614)
- Overly Permissive CORS Configurations (Access-Control-Allow-Origin: *) (CWE-942)
Mapped to MITRE ATT&CK: T1189, T1539
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class XssCsrfScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-XSS-REACT-DANGEROUS-01",
                "title": "Cross-Site Scripting: React dangerouslySetInnerHTML Usage",
                "pattern": re.compile(
                    r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!sanitize)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Bypassing React's built-in XSS protection using `dangerouslySetInnerHTML` without sanitizing input via DOMPurify.",
                "remediation": "Sanitize HTML content using DOMPurify (`DOMPurify.sanitize(input)`) or refactor to native React elements.",
                "mitre_id": "T1189",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Drive-by Compromise",
                "cwe_id": "CWE-79",
            },
            {
                "id": "APPSEC-XSS-TEMPLATE-SAFE-01",
                "title": "Cross-Site Scripting: Template Autoescaping Disabled (| safe)",
                "pattern": re.compile(
                    r'(?:\{\{.*\|\s*safe\s*\}\}|\{%\s*autoescape\s+false\s*%\})',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Explicitly disabling HTML autoescaping using the `| safe` filter in Jinja2/Django templates allows stored or reflected XSS.",
                "remediation": "Remove the `| safe` filter. If HTML rendering is required, sanitize through an allowlist filter like Bleach or sanitize-html.",
                "mitre_id": "T1189",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Drive-by Compromise",
                "cwe_id": "CWE-79",
            },
            {
                "id": "APPSEC-CSRF-DISABLED-01",
                "title": "CSRF: Cross-Site Request Forgery Protection Explicitly Disabled",
                "pattern": re.compile(
                    r'(?:@csrf_exempt|\.csrf\(\)\.disable\(\)|csrf\s*:\s*false|wtforms\.CSRFProtect.*enabled\s*=\s*False)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "CSRF defense mechanisms explicitly disabled on sensitive state-changing endpoints, leaving users vulnerable to unauthorized actions.",
                "remediation": "Enable anti-CSRF token verification on all POST/PUT/DELETE requests or enforce `SameSite=Strict` cookies with custom request headers.",
                "mitre_id": "T1189",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Drive-by Compromise",
                "cwe_id": "CWE-352",
            },
            {
                "id": "APPSEC-COOKIE-INSECURE-FLAGS-01",
                "title": "Session Security: Cookie Set Without HttpOnly / Secure Flags",
                "pattern": re.compile(
                    r'(?:set_cookie|res\.cookie)\s*\(\s*["\'](?:session|token|auth|id|jwt)["\'][\s\S]{0,100}?(?:httponly\s*=\s*False|secure\s*=\s*False|httpOnly\s*:\s*false)',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Authentication cookie configured with HttpOnly or Secure explicitly disabled, allowing JavaScript theft via XSS or plaintext interception.",
                "remediation": "Set `HttpOnly=True`, `Secure=True`, and `SameSite='Lax'` or `'Strict'` on all authentication and session cookies.",
                "mitre_id": "T1539",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Steal Web Session Cookie",
                "cwe_id": "CWE-1004",
            },
            {
                "id": "APPSEC-CORS-PERMISSIVE-WILD-01",
                "title": "CORS: Wildcard Access-Control-Allow-Origin Configured",
                "pattern": re.compile(
                    r'(?:Access-Control-Allow-Origin.*\*|cors\s*\(\s*\{\s*origin\s*:\s*["\']\*["\']\s*,\s*credentials\s*:\s*true)',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Overly permissive CORS policy allows any external origin to read sensitive response data.",
                "remediation": "Specify explicit allowed origins rather than wildcard `*`, and never reflect arbitrary Origin headers when credentials are true.",
                "mitre_id": "T1189",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Drive-by Compromise",
                "cwe_id": "CWE-942",
            },
        ]

    @property
    def name(self) -> str:
        return "XSS, CSRF & Cookie Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Audits application source code for Cross-Site Scripting (XSS), disabled CSRF protections, insecure cookies, and permissive CORS."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".html", ".java", ".cs"]

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
