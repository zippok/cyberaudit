"""
Cognitive Ergonomics & Usability Heuristics Scanner (UI/UX)
Audits source code for:
- Destructive operations lacking confirmation safeguards (Nielsen Heuristic #5: Error Prevention)
- State and status indicators communicated exclusively through color (WCAG 1.4.1: Use of Color)
- Absolute hex colors conflicting with dark mode themes (WCAG 1.4.3: Contrast Inversion)
"""

import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class CognitiveErgonomicsScanner(BaseScanner):
    __test__ = False  # Prevent pytest from collecting this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Cognitive Ergonomics & Usability Heuristics Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return "Audits Nielsen usability heuristics (unconfirmed destructive actions, error prevention), color-only status indicators, and dark mode contrast safety."

    @property
    def supported_extensions(self) -> Set[str]:
        return {
            ".html", ".htm", ".vue", ".jsx", ".tsx", ".js", ".ts", ".css", ".scss", ".less"
        }

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip non-relevant and minified assets
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock", ".svg"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ----------------------------------------------------------------------
        # 1. UIUX-ERGONOMICS-UNCONFIRMED-DESTRUCTIVE-ACTION
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".vue", ".jsx", ".tsx", ".js", ".ts"]):
            # Check for buttons or click handlers with destructive words without confirmation safeguards
            destructive_pattern = re.compile(
                r'<(?:button|a)\b[^>]*?(?:onClick|onclick)\s*=\s*["\'{](?:[^{}]*?(?:delete|drop|purge|truncate|destroy|eliminar|remove)[^{}]*?)["\'}][^>]*>',
                re.IGNORECASE
            )
            has_confirm_mechanism = any(k in content for k in [
                "confirm(", "dialog", "modal", "prompt(", "sweetalert", "swal",
                "AlertDialog", "ConfirmDialog", "Popconfirm", "confirmDelete", "undo"
            ])
            if not has_confirm_mechanism:
                for match in destructive_pattern.finditer(content):
                    tag = match.group(0)
                    # Ignore harmless actions like removeClass or removeItem
                    if "removeclass" in tag.lower() or "removeitem" in tag.lower() or "removelistener" in tag.lower():
                        continue
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-ERGONOMICS-UNCONFIRMED-DESTRUCTIVE-ACTION",
                            title="UI/UX Usability: Destructive Operation Dispatched Without Confirmation Guard (Nielsen Heurística #5)",
                            description=(
                                f"Destructive element (`{matched_line[:80]}`) executes deletion/purging directly on click without a confirmation "
                                f"dialogue, two-step challenge, or undo buffer. Violates Jakob Nielsen's Usability Heuristic #5 (Error Prevention) "
                                f"and Heuristic #3 (User Control and Freedom). Slips and accidental clicks cause irreversible data loss."
                            ),
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Require user confirmation before executing destructive calls (e.g., confirmation modal, prompt, or timed undo mechanism).",
                            cwe_id="CWE-1078",
                            compliance_controls={"Nielsen": "Heuristic 5 Error Prevention", "ISO-9241-110": "Error Tolerance"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 2. UIUX-A11Y-COLOR-ONLY-STATUS
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".vue", ".jsx", ".tsx"]):
            # Status badge/dot relying solely on color
            # e.g., <span class="... bg-green-500 ..."></span> with no text and no aria-label
            color_dot_pattern = re.compile(
                r'<(?:span|div|i)\b([^>]*?class\s*=\s*["\'][^"\']*(?:bg-(?:green|red|emerald|rose|amber)-[0-9]+|badge-(?:success|danger|error)|status-(?:online|offline))[^"\']*["\'][^>]*?)>\s*</(?:span|div|i)>',
                re.IGNORECASE
            )
            for match in color_dot_pattern.finditer(content):
                attrs = match.group(1)
                has_accessible_name = (
                    "aria-label=" in attrs or
                    "aria-labelledby=" in attrs or
                    "title=" in attrs or
                    'role="status"' in attrs
                )
                if not has_accessible_name:
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-A11Y-COLOR-ONLY-STATUS",
                            title="UI/UX Accessibility: Status Communicated Exclusively Through Color (WCAG 1.4.1)",
                            description=(
                                f"Empty indicator element communicates state solely through color class styling. "
                                f"This violates WCAG 2.1 Level A Criterion 1.4.1 (Use of Color). "
                                f"Users with color blindness (deuteranopia, protanopia, tritanopia) or screen reader users cannot perceive the status."
                            ),
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Complement color indicators with visible textual labels, distinct iconography, or an explicit `aria-label`.",
                            cwe_id="CWE-1078",
                            compliance_controls={"WCAG-2.1": "1.4.1 Use of Color", "Section-508": "1194.22(c)"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 3. UIUX-DARK-MODE-CONTRAST-COLLISION
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".css", ".scss", ".less"]):
            has_dark_query = "prefers-color-scheme" in content
            if has_dark_query:
                # Look for hardcoded white backgrounds or black text outside css variables
                hardcoded_color_pattern = re.compile(
                    r'(?:^|\{|\;)\s*(?:background|background-color)\s*:\s*(?:#ffffff|#fff|white)\b\s*[\;\}]',
                    re.IGNORECASE | re.MULTILINE
                )
                for match in hardcoded_color_pattern.finditer(content):
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    # Check if the line is inside a prefers-color-scheme: light block or comment
                    if "light" in matched_line or matched_line.startswith(("//", "/*", "*")):
                        continue
                    findings.append(
                        Finding(
                            id="UIUX-DARK-MODE-CONTRAST-COLLISION",
                            title="UI/UX Design Systems: Absolute Hex Background Risks Contrast Inversion in Dark Mode",
                            description=(
                                f"Stylesheet implements dark mode media queries (`prefers-color-scheme`) but sets hardcoded "
                                f"absolute background colors (`{matched_line[:60]}`). Under active dark themes, inverted text styles "
                                f"placed over hardcoded white backgrounds result in catastrophic contrast failure (white-on-white text)."
                            ),
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Replace static hex values with dynamic CSS Custom Properties (e.g. `var(--color-bg-primary)`).",
                            cwe_id="CWE-1078",
                            compliance_controls={"WCAG-2.1": "1.4.3 Contrast (Minimum)", "Design-Systems": "Theme-Tokens"},
                        )
                    )

        return findings
