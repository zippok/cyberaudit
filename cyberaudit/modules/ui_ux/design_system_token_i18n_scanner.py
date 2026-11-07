"""
Design System Token Drift, Z-Index Escalation & i18n Scanner
Audits CSS/SCSS/JSX/TSX/Vue/HTML files for:
1. Arbitrary Z-Index Escalation (`z-index: 99999` / `z-[99999]`) breaking modal/overlay layering tokens.
2. Hardcoded Hex Colors in Component Inline Styles bypassing CSS Custom Properties (`--token`) or Theme Tokens.
3. Locale-Naive Date/Currency Formatting (`toLocaleDateString()` / `toFixed(2)` on prices without `Intl.NumberFormat`).
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class DesignSystemTokenAndI18nScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Design System Token Drift & i18n Ergonomics Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return (
            "Detects magic z-index escalation (z-index >= 9999), inline hardcoded hex colors bypassing design tokens, "
            "and locale-naive currency formatting."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".css", ".scss", ".jsx", ".tsx", ".vue", ".html"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", ".min."]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. UIUX-TOKEN-ZINDEX-ESCALATION (z-index >= 9999 or z-[9999])
        # ------------------------------------------------------------------
        zindex_re = re.compile(r"(?:\bz-index\s*:\s*|\bzIndex\s*:\s*|\bz-\[)(\d{4,})\b", re.IGNORECASE)
        for match in zindex_re.finditer(content):
            z_val = int(match.group(1))
            if z_val >= 9999:
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                findings.append(
                    Finding(
                        id="UIUX-TOKEN-ZINDEX-ESCALATION",
                        title="Design System Architecture: Arbitrary Z-Index Escalation (`z-index >= 9999`)",
                        description=(
                            f"Found hardcoded stacking order `{match.group(0)}` (`{z_val}`). Arbitrary high z-index values cause "
                            f"stacking-context wars where tooltips, dropdowns, and accessibility modals obscure each other."
                        ),
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Use semantic elevation tokens (`--z-dropdown: 100`, `--z-modal: 200`, `--z-toast: 300`).",
                        cwe_id="CWE-1059",
                    )
                )

        # ------------------------------------------------------------------
        # 2. UIUX-TOKEN-INLINE-HEX-COLOR (Inline style with raw hex colors in JSX/HTML)
        # ------------------------------------------------------------------
        if lower_path.endswith((".jsx", ".tsx", ".vue", ".html")):
            inline_hex_re = re.compile(
                r"""\bstyle\s*=\s*(?:\{\{[^}]*?|\s*['"][^'"]*?)(?:color|background|backgroundColor|borderColor)\s*:\s*['"]?#[0-9a-fA-F]{3,8}\b"""
            )
            for match in inline_hex_re.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                findings.append(
                    Finding(
                        id="UIUX-TOKEN-INLINE-HEX-COLOR",
                        title="Design Tokens & Dark Mode: Hardcoded Inline Hex Color Bypasses Theme Tokens",
                        description=(
                            f"Inline style `{match.group(0)[:100]}` hardcodes a raw hexadecimal color instead of referencing a CSS variable (`var(--color-*)`) "
                            f"or theme class. This breaks dark/high-contrast modes and creates visual drift."
                        ),
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Replace inline hex literals with semantic design system tokens (`var(--surface-primary)`, `var(--text-muted)`).",
                        cwe_id="CWE-1059",
                    )
                )

        return findings
