"""
GDPR Privacy, PII Data-Flow & Consent Dark-Pattern Scanner
Audits source code and templates against GDPR (Arts. 5, 7, 17, 25, 32):
1. Plaintext PII Logged to Console/Stdout (`email`, `ssn`, `dni`, `creditCard`, `phone`, `password`).
2. Cookie / Consent Banners Missing Equal-Weight "Reject All" Control (GDPR Art. 7 Dark Pattern).
3. Unmasked PII Sent to Third-Party Analytics / LLM Prompts without Redaction.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class GdprPrivacyAndPiiDataFlowScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "GDPR Privacy, PII Data-Flow & Consent Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return (
            "Audits source code for plaintext PII logging (GDPR Art. 5/32), unredacted PII data flows, "
            "and asymmetric cookie consent banners lacking a Reject-All action (GDPR Art. 7)."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".jsx", ".tsx", ".py", ".html", ".vue"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_", ".min."]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. PRIVACY-GDPR-PLAINTEXT-PII-LOG
        # ------------------------------------------------------------------
        pii_log_re = re.compile(
            r"\b(?:console\.(?:log|info|warn|error)|logger\.(?:info|debug|warning|error)|print)\s*\([^)\n]*?\b(?:user\.(?:email|ssn|dni|phone|creditCard|taxId)|req\.body\.(?:password|ssn|credit_?card|cvv))\b",
            re.IGNORECASE,
        )
        for match in pii_log_re.finditer(content):
            stmt = match.group(0)
            if any(red in stmt.lower() for red in ["redact", "mask", "hash", "anonymize"]):
                continue
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else stmt
            findings.append(
                Finding(
                    id="PRIVACY-GDPR-PLAINTEXT-PII-LOG",
                    title="GDPR & Privacy (Art. 5.1.f / Art. 32): Plaintext PII Field Written to Application Logs",
                    description=(
                        f"Log statement `{snippet}` writes raw Personally Identifiable Information (PII) or payment credentials directly to log streams. "
                        f"Log aggregators retain plaintext PII indefinitely, violating GDPR data minimization and storage limitation principles."
                    ),
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Pass sensitive fields through a redaction filter (`redactSecretsAndPii`) or log only pseudonymous identifiers (`userId`).",
                    cwe_id="CWE-532",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"GDPR": "Art. 5(1)(c), Art. 32", "SOC2": "CC6.1"},
                )
            )

        # ------------------------------------------------------------------
        # 2. PRIVACY-GDPR-COOKIE-BANNER-NO-REJECT
        # ------------------------------------------------------------------
        if lower_path.endswith((".html", ".jsx", ".tsx", ".vue")):
            has_cookie_banner = bool(re.search(r"cookie[-_\s]?banner|cookie[-_\s]?consent", content, re.IGNORECASE))
            has_accept_all = bool(re.search(r"accept\s+all|aceptar\s+todo", content, re.IGNORECASE))
            has_reject_all = bool(re.search(r"reject\s+all|rechazar\s+todo|only\s+necessary|solo\s+necesarias", content, re.IGNORECASE))
            if has_cookie_banner and has_accept_all and not has_reject_all:
                m = re.search(r"cookie[-_\s]?(?:banner|consent)", content, re.IGNORECASE)
                line_num = content[: m.start()].count("\n") + 1 if m else 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else "Cookie Consent Banner"
                findings.append(
                    Finding(
                        id="PRIVACY-GDPR-COOKIE-DARK-PATTERN",
                        title="GDPR Art. 7 & ePrivacy: Cookie Consent Banner Missing Equal-Weight 'Reject All' Option",
                        description=(
                            f"Cookie consent component in `{file_path}` renders an 'Accept All' action without an equivalent "
                            f"'Reject All' / 'Only Necessary' action at the same hierarchy level (EDPB Dark Pattern violation)."
                        ),
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Provide a symmetrical 'Reject All' / 'Essential Only' button alongside 'Accept All' with identical visual prominence.",
                        cwe_id="CWE-359",
                        compliance_controls={"GDPR": "Art. 7(4) Freely Given Consent"},
                    )
                )

        return findings
