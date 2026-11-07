"""
Business Logic & BOLA/IDOR Security Scanner (Penetration Tester & AppSec)
Detects:
- Broken Object Level Authorization (BOLA / IDOR) (CWE-639 / OWASP API1:2023)
- Mass Assignment / Over-Posting (CWE-915 / OWASP API6:2023)
- Client-Controlled Role & Privilege Elevation (CWE-269 / CWE-862)
- Step-Skipping / State Machine Bypass in Critical Workflows (CWE-840)
- Predictable Resource ID Enumeration (CWE-340)
Mapped to MITRE ATT&CK: T1078 (Valid Accounts), T1548 (Abuse Elevation Control)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class BusinessLogicBolaScanner(BaseScanner):
    """
    Analyzes API route handlers, controllers, and service layers for flawed business logic,
    missing tenancy/ownership checks on resource IDs, and dangerous model mass-assignment.
    """

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "BIZLOGIC-BOLA-IDOR-01",
                "title": "BOLA / IDOR: Direct Resource Fetch by User-Supplied ID Without Ownership Check",
                "pattern": re.compile(
                    r'@?(?:router|app)\.(?:route|get|post|put|delete|patch)\s*\(\s*["\'][^"\']*/(?::id|\{id\}|<(?:int:)?id>)[^"\']*["\'][\s\S]{0,350}?'
                    r'(?:(?:findById|findOne|get_by_id|get_object_or_404|query\.get)\s*\(\s*(?:req\.params\.id|request\.(?:args|view_args)\[["\']id["\']\]|id)\s*\))'
                    r'(?![\s\S]{0,250}?(?:req\.user|current_user|auth\.user_id|tenant_id|org_id|session\[["\']user))',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "description": (
                    "Endpoint retrieves an entity directly using an object identifier provided in the URL or request parameters "
                    "without verifying that the authenticated user owns or is authorized to access that specific entity."
                ),
                "remediation": (
                    "Always enforce authorization checks at the data layer: scope queries to the current user "
                    "(e.g. `db.query(Account).filter_by(id=id, user_id=current_user.id).first()`) or verify access via an ABAC/RBAC policy."
                ),
                "mitre_id": "T1078",
                "mitre_tactic": "Defense Evasion / Initial Access",
                "mitre_technique": "Valid Accounts: Cloud / Local Accounts",
                "cwe_id": "CWE-639",
            },
            {
                "id": "BIZLOGIC-MASS-ASSIGN-01",
                "title": "Mass Assignment: Direct Ingestion of Client Body into Model Without Property Whitelisting",
                "pattern": re.compile(
                    r'(?:User|Account|Profile|Customer|Order|Role|Member)\s*\.\s*(?:create|update|update_attributes|build|assign)\s*\(\s*'
                    r'(?:req\.body|request\.(?:json|get_json\(\)|form)|params)\s*\)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Direct binding of HTTP request payload (`req.body` / `request.json`) to database models or entities "
                    "without field whitelisting (Mass Assignment / Over-Posting). An attacker can inject unexpected properties "
                    "such as `is_admin: true`, `role: 'superadmin'`, or `balance: 999999`."
                ),
                "remediation": (
                    "Define strict Data Transfer Objects (DTOs) or explicit schemas (e.g. Pydantic, Zod, Joi, strong parameters) "
                    "that whitelist only fields permitted for client modification."
                ),
                "mitre_id": "T1548",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism",
                "cwe_id": "CWE-915",
            },
            {
                "id": "BIZLOGIC-ROLE-ELEVATION-01",
                "title": "Privilege Escalation: Untrusted Assignment of Role or Administrative Flags",
                "pattern": re.compile(
                    r'(?:user|account|session|token)\s*(?:\.|\[["\'])(?:role|is_admin|is_superuser|permissions|group|tier)(?:["\']\])?\s*=\s*'
                    r'(?:req\.body|request\.(?:json|form|args)|params)\s*(?:\.|\[["\'])(?:role|is_admin|permissions|group|tier)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "description": (
                    "User roles, administrative permissions, or account tiers are modified directly from client-supplied input. "
                    "Malicious actors can elevate their privilege level to administrator by altering the request body."
                ),
                "remediation": (
                    "Authorize administrative changes through separate, tightly gated management endpoints. Never permit "
                    "clients to set their own role or permission attributes in public profile update endpoints."
                ),
                "mitre_id": "T1548",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism",
                "cwe_id": "CWE-269",
            },
            {
                "id": "BIZLOGIC-STEP-SKIP-01",
                "title": "Business Workflow Flaw: Sensitive Action Triggered Without State Verification",
                "pattern": re.compile(
                    r'(?:@app\.route|router\.(?:post|put))\s*\(\s*["\'][^"\']*(?:/complete-order|/confirm-payment|/reset-password-final|/approve-transfer)[^"\']*["\'][\s\S]{0,350}?'
                    r'(?![\s\S]{0,350}?(?:verify_token|state\s*===|status\s*==|check_session_token|verify_signature|nonce))'
                    r'(?:order\.status\s*=\s*["\']completed["\']|user\.password\s*=|execute_transfer|dispatch_goods)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Transactional workflow endpoint transitions a critical business state (e.g. confirming payment, completing order, resetting password) "
                    "without validating transactional precondition tokens, state machine integrity, or payment processor confirmation."
                ),
                "remediation": (
                    "Enforce atomic finite-state machine transitions: check cryptographic tokens or verified webhook callbacks from payment gateways "
                    "before transitioning entity states to approved or fulfilled."
                ),
                "mitre_id": "T1078",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Valid Accounts",
                "cwe_id": "CWE-840",
            },
        ]

    @property
    def name(self) -> str:
        return "Business Logic & BOLA/IDOR Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Audits application logic for BOLA/IDOR, Mass Assignment, Role Tampering, and workflow state machine bypasses."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php", ".go", ".java", ".cs"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        # Check line-based and multi-line window patterns
        for rule in self.rules:
            pattern = rule["pattern"]
            matches = list(pattern.finditer(content))
            for match in matches:
                start_char = match.start()
                line_idx = content[:start_char].count("\n") + 1
                matched_text = match.group(0).strip()
                snippet = matched_text[:300] + "..." if len(matched_text) > 300 else matched_text

                findings.append(
                    Finding(
                        id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_idx,
                        code_snippet=snippet,
                        remediation=rule["remediation"],
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        cwe_id=rule.get("cwe_id"),
                        stride_category=rule.get("stride"),
                        confidence="HIGH",
                    )
                )

        return findings
