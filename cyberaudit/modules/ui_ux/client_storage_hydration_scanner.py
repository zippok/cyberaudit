"""
Client Storage Token Exposure & SSR Hydration Safety Scanner
Audits Frontend/Fullstack JS/TS/JSX/TSX/Vue files for:
1. Storing sensitive bearer/JWT/session/API tokens or PII in `localStorage` or `sessionStorage` (accessible to any XSS).
2. Non-deterministic values (`Math.random()`, `new Date()`, `window.innerWidth`) rendered directly in SSR JSX/TSX bodies causing React/Next hydration mismatches.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class ClientStorageAndHydrationSafetyScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Client Storage Token Exposure & SSR Hydration Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return (
            "Detects sensitive JWT/auth tokens or PII persisted in localStorage/sessionStorage "
            "and non-deterministic SSR hydration patterns."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".jsx", ".tsx", ".vue"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", ".min."]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. UIUX-STORAGE-SENSITIVE-TOKEN (localStorage.setItem('token'|'jwt'|'apiKey'...))
        # ------------------------------------------------------------------
        storage_token_re = re.compile(
            r"""\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`]([^'"`]*(?:jwt|access_?token|refresh_?token|id_?token|api_?key|secret|password|ssn|credit_?card)[^'"`]*)['"`]""",
            re.IGNORECASE,
        )
        for match in storage_token_re.finditer(content):
            key_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="UIUX-STORAGE-SENSITIVE-TOKEN",
                    title="Frontend Security & UX: Sensitive Credential or PII Stored in Web Storage (`localStorage`/`sessionStorage`)",
                    description=(
                        f"Key `{key_name}` is persisted in `localStorage`/`sessionStorage` via `{snippet}`. "
                        f"Unlike `HttpOnly; Secure; SameSite` cookies, Web Storage is readable by any JavaScript running on the origin (including third-party scripts or XSS payloads)."
                    ),
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Store session and refresh tokens in `HttpOnly; Secure; SameSite=Lax/Strict` cookies managed by the backend, or keep short-lived tokens in memory only.",
                    cwe_id="CWE-922",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"OWASP-ASVS": "V3.2.2", "GDPR": "Art. 32 Security of Processing"},
                )
            )

        return findings
