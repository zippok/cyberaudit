"""
SSRF, Path Traversal & XXE Scanner (AppSec / Penetration Testing)
Detects:
- Server-Side Request Forgery (SSRF) via unvalidated outbound requests (CWE-918)
- Path Traversal & Local File Inclusion (LFI) via unvalidated file opens (CWE-22)
- XML External Entity (XXE) injection via insecure XML parsers (CWE-611)
- Prototype Pollution patterns in JavaScript/Node.js (CWE-1321)
Mapped to MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class SsrfTraversalScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-SSRF-OUTBOUND-01",
                "title": "Server-Side Request Forgery: Dynamic URL in Outbound HTTP Request",
                "pattern": re.compile(
                    r'(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|httpx\.(?:get|post)|axios\.(?:get|post)|fetch)\s*\(\s*(?:req|request|url|param|target)\b',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Outbound HTTP request executed against a dynamic, user-supplied URL without private subnet or cloud metadata (169.254.169.254) validation.",
                "remediation": "Validate target URLs against an explicit allowlist. Disallow private IP ranges (RFC 1918) and cloud instance metadata addresses.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-918",
            },
            {
                "id": "APPSEC-TRAVERSAL-LFI-01",
                "title": "Path Traversal / LFI: Unvalidated File Path Concatenation",
                "pattern": re.compile(
                    r'(?:open|file_get_contents|readfile|include|require|fs\.readFile(?:Sync)?)\s*\(\s*(?:f["\'][\s\S]*?\{.*\}|.*?\+\s*(?:req|filename|file|path|param))',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "File system access invoked using directly concatenated or formatted user input without canonicalization or directory traversal guards (`../`).",
                "remediation": "Use `os.path.basename()` to strip directory paths, resolve with `os.path.realpath()`, and verify the path remains inside the designated base directory.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-22",
            },
            {
                "id": "APPSEC-XXE-PARSER-01",
                "title": "XML External Entity (XXE): XML Parsing with Entities Enabled",
                "pattern": re.compile(
                    r'(?:etree\.parse|etree\.fromstring|xml\.dom\.minidom\.parse|DocumentBuilderFactory)\s*\([\s\S]{0,120}?(?:resolve_entities\s*=\s*True|load_dtd\s*=\s*True|disallow-doctype-decl.*false)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "XML parser configured to resolve external entities or DTDs, exposing internal files and enabling SSRF through XXE.",
                "remediation": "Disable external entity resolution (e.g. `defusedxml` in Python, or set `resolve_entities=False`).",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-611",
            },
            {
                "id": "APPSEC-PROTO-POLLUTION-01",
                "title": "Prototype Pollution: Direct Object Merge into __proto__",
                "pattern": re.compile(
                    r'(?:\[["\']__proto__["\']\]|\.__proto__\b|Object\.assign\s*\(\s*(?:\{\}|target)\s*,\s*req\.body)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Modifying or merging untrusted input into the JavaScript Object prototype chain (__proto__), risking property injection and denial of service.",
                "remediation": "Freeze Object prototype (`Object.freeze(Object.prototype)`) or use `Object.create(null)` for key-value dictionaries.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-1321",
            },
        ]

    @property
    def name(self) -> str:
        return "SSRF, Path Traversal & XXE Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Audits application source code for SSRF, Path Traversal/LFI, XXE, and Prototype Pollution vulnerabilities."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".php", ".java", ".go", ".cs", ".rb"]

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
