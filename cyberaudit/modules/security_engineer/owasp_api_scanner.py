"""
OWASP API Security Top 10 Scanner (Security Engineer & AppSec)
Detects critical API vulnerability patterns:
- API1:2023 - Broken Object Level Authorization (BOLA / IDOR)
- API2:2023 - Broken Authentication (Public endpoints without auth decorators)
- API3:2023 - Broken Object Property Level Authorization (Mass Assignment)
- API4:2023 - Unrestricted Resource Consumption (Missing Rate Limiting)
- Insecure CORS with credentials (CWE-942)
Mapped to MITRE ATT&CK: T1190, T1078, T1499
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class OwaspApiScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-API-BOLA-IDOR-01",
                "title": "OWASP API1:2023 - Broken Object Level Authorization (BOLA / IDOR)",
                "pattern": re.compile(
                    r'(?:findById|findOne|get_object_or_404|objects\.get)\s*\(\s*(?:id\s*=\s*(?:req\.params|request\.(?:GET|args|params))|req\.params\.\w+|request\.(?:GET|args)\[["\'](?:id|user_id|account_id)["\']\])',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "PCI_DSS": "Req 6.2",
                    "ISO_27001": "A.14.2.5",
                    "GDPR": "Art. 32",
                    "OWASP_API": "API1:2023",
                },
                "description": "Database query retrieves objects directly by user-supplied ID parameter without verifying that the requesting user owns the object or belongs to the authorized tenant (BOLA/IDOR).",
                "remediation": "Scope all database lookups to the authenticated session context: `UserRecord.objects.get(id=obj_id, owner=current_user)`.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-639",
            },
            {
                "id": "APPSEC-API-BROKEN-AUTH-01",
                "title": "OWASP API2:2023 - Unprotected Sensitive Endpoint (Missing Auth Middleware)",
                "pattern": re.compile(
                    r'@(?:app|router)\.(?:post|put|delete|patch)\s*\(\s*["\']/(?:api/v\d+/)?(?:admin|users|accounts|transfer|keys|tokens|config)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.SPOOFING.value,
                "compliance": {
                    "PCI_DSS": "Req 8.2",
                    "ISO_27001": "A.9.4.2",
                    "SOC2": "CC6.1",
                    "OWASP_API": "API2:2023",
                },
                "description": "Administrative, payment, or account mutation endpoint defined without explicit authentication decorator (`@login_required`, `@jwt_required`, or `Depends(get_current_user)`).",
                "remediation": "Enforce mandatory authentication middleware or security dependencies across all sensitive API routes.",
                "mitre_id": "T1078",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Valid Accounts",
                "cwe_id": "CWE-306",
            },
            {
                "id": "APPSEC-API-MASS-ASSIGNMENT-01",
                "title": "OWASP API3:2023 - Mass Assignment in Model Mutation",
                "pattern": re.compile(
                    r'(?:\.create|\.update|\.save|Model)\s*\(\s*(?:\*\*request\.(?:data|get_json\(\)|json)|req\.body)\b',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "PCI_DSS": "Req 6.2",
                    "ISO_27001": "A.14.2.5",
                    "OWASP_API": "API3:2023",
                },
                "description": "Client-supplied request payload unpacked directly into database model constructor without schema filtering, allowing attackers to overwrite sensitive attributes (`is_admin`, `role`, `balance`).",
                "remediation": "Use Data Transfer Objects (DTOs), Pydantic schemas, or explicit field allowlists when mutating models.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-915",
            },
            {
                "id": "APPSEC-API-RATE-LIMIT-01",
                "title": "OWASP API4:2023 - Missing Rate Limiting on Sensitive Endpoint",
                "pattern": re.compile(
                    r'@(?:app|router)\.post\s*\(\s*["\']/(?:api/)?(?:login|signin|auth|forgot-password|reset-password|otp|verify)',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "stride": StrideCategory.DENIAL_OF_SERVICE.value,
                "compliance": {
                    "PCI_DSS": "Req 8.3",
                    "ISO_27001": "A.12.1.3",
                    "OWASP_API": "API4:2023",
                },
                "description": "Authentication or password reset endpoint declared without visible rate limiting middleware, exposing the service to brute-force credential stuffing and DoS.",
                "remediation": "Attach rate limiting policies (e.g., `@limiter.limit('5/minute')` or `express-rate-limit`) to prevent abuse.",
                "mitre_id": "T1499",
                "mitre_tactic": "Impact",
                "mitre_technique": "Endpoint Denial of Service",
                "cwe_id": "CWE-770",
            },
            {
                "id": "APPSEC-API-CORS-WILDCARD-01",
                "title": "Insecure CORS Policy: Wildcard Origin with Credentials Allowed",
                "pattern": re.compile(
                    r'(?:Access-Control-Allow-Origin\s*[:=]\s*["\']\*["\'].*allow_credentials\s*[:=]\s*True|allow_origins\s*=\s*\[["\']\*["\']\].*allow_credentials\s*=\s*True|credentials\s*:\s*true[\s\S]{0,60}?origin\s*:\s*["\']\*["\']|origin\s*:\s*["\']\*["\'][\s\S]{0,60}?credentials\s*:\s*true)',
                    re.IGNORECASE | re.DOTALL,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "PCI_DSS": "Req 6.2",
                    "ISO_27001": "A.14.1.2",
                    "GDPR": "Art. 32",
                },
                "description": "Cross-Origin Resource Sharing (CORS) configured with wildcard origin `*` while enabling credentials (`allow_credentials=True`), permitting cross-site data theft.",
                "remediation": "Specify an explicit allowlist of trusted origins when enabling credentials in CORS configuration.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-942",
            },
        ]

    @property
    def name(self) -> str:
        return "OWASP API Security Top 10 Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Audits REST/GraphQL APIs for BOLA/IDOR, Broken Authentication, Mass Assignment, Rate Limiting, and Insecure CORS."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".go", ".java", ".php", ".cs", ".rb"]

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
                        stride_category=rule.get("stride"),
                        compliance_controls=rule.get("compliance", {}),
                    )
                    findings.append(finding)

        # Multi-line check for CORS wildcard with credentials
        for rule in self.rules:
            if "CORS" in rule["id"]:
                match = rule["pattern"].search(content)
                if match:
                    line_num = content[: match.start()].count("\n") + 1
                    if not any(f.id == rule["id"] and f.line_number == line_num for f in findings):
                        findings.append(
                            Finding(
                                id=rule["id"],
                                title=rule["title"],
                                description=rule["description"],
                                severity=rule["severity"],
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=match.group(0).strip()[:180],
                                remediation=rule["remediation"],
                                mitre_id=rule["mitre_id"],
                                mitre_tactic=rule["mitre_tactic"],
                                mitre_technique=rule["mitre_technique"],
                                cwe_id=rule.get("cwe_id"),
                                stride_category=rule.get("stride"),
                                compliance_controls=rule.get("compliance", {}),
                            )
                        )

        return findings
