"""
WCAG 2.2 Modern Compliance & Assistive Tech Scanner (UI/UX)
Audits source code for:
- Clipboard paste blocking on inputs (WCAG 2.2 Criterion 3.3.8: Accessible Authentication)
- Fixed/sticky banners obscuring keyboard focus (WCAG 2.2 Criterion 2.4.11: Focus Not Obscured)
- Inline decorative SVGs missing aria-hidden="true" (WCAG 1.1.1: Screen Reader Noise)
- Placeholders used as replacement for persistent labels (WCAG 3.3.2: Labels or Instructions)
"""

import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class Wcag22ModernComplianceScanner(BaseScanner):
    __test__ = False  # Prevent pytest from collecting this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "WCAG 2.2 Modern Compliance & Assistive Tech Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return "Audits WCAG 2.2 criteria (paste prevention, focus obscuring), decorative SVG pollution, and placeholder label misuse."

    @property
    def supported_extensions(self) -> Set[str]:
        return {
            ".html", ".htm", ".vue", ".jsx", ".tsx", ".css", ".scss", ".less", ".js", ".ts"
        }

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip non-relevant and minified assets
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ----------------------------------------------------------------------
        # 1. UIUX-WCAG22-PASTE-PREVENTED
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".vue", ".jsx", ".tsx", ".js", ".ts"]):
            paste_block_patterns = [
                (re.compile(r'\bonpaste\s*=\s*["\'](?:return\s+false;?|event\.preventDefault\(\);?)["\']', re.IGNORECASE), "Inline onpaste block attribute"),
                (re.compile(r'\bonPaste\s*=\s*\{(?:\s*\(?[^)]*\)?\s*=>\s*)?[^}]*preventDefault\(\)\s*\}'), "React onPaste event handler blocking paste"),
                (re.compile(r'\baddEventListener\s*\(\s*["\']paste["\']\s*,\s*(?:[^{]*?=>\s*\{[^{]*?preventDefault\(\)|function[^{]*?\{[^{]*?preventDefault\(\))'), "DOM paste listener preventing default"),
            ]
            for pattern, desc in paste_block_patterns:
                for match in pattern.finditer(content):
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-WCAG22-PASTE-PREVENTED",
                            title="UI/UX & A11y: Input Field Blocks Clipboard Paste (WCAG 2.2 Criterio 3.3.8)",
                            description=(
                                f"Input control intentionally suppresses clipboard pasting (`{match.group(0)}`). "
                                f"This violates WCAG 2.2 Level AA Criterion 3.3.8 (Accessible Authentication) and NIST SP 800-63B Section 5.1.1.2. "
                                f"Blocking paste breaks password managers (Bitwarden, 1Password, Apple Keychain), preventing users from pasting "
                                f"cryptographically strong credentials and severely penalizing users with motor or cognitive impairments."
                            ),
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Remove the paste blocker. Allow users and assistive password managers to paste arbitrary credentials freely.",
                            cwe_id="CWE-1078",
                            compliance_controls={"WCAG-2.2": "3.3.8 Accessible Authentication", "NIST": "SP 800-63B Section 5.1.1.2"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 2. UIUX-WCAG22-FOCUS-OBSCURED-FIXED
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".css", ".scss", ".less", ".html", ".vue"]):
            has_fixed_sticky = bool(re.search(r'\bposition\s*:\s*(?:fixed|sticky)\b', content, re.IGNORECASE))
            has_scroll_margin = any(k in content for k in ["scroll-margin", "scroll-padding"])
            if has_fixed_sticky and not has_scroll_margin:
                fixed_match = re.search(r'([.#\w\-]+)\s*\{[^}]*?\bposition\s*:\s*(?:fixed|sticky)\b', content, re.IGNORECASE)
                if fixed_match:
                    start_pos = fixed_match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-WCAG22-FOCUS-OBSCURED-FIXED",
                            title="UI/UX Accessibility: Sticky/Fixed Header Lacks Scroll Margins (WCAG 2.2 Criterio 2.4.11)",
                            description=(
                                f"Selector `{fixed_match.group(1)}` specifies `position: fixed/sticky` but the document provides no "
                                f"`scroll-margin-top` or `scroll-padding-top`. When keyboard users Tab into inputs or anchor links, "
                                f"the focused item scrolls underneath the fixed bar, violating WCAG 2.2 Criterion 2.4.11 (Focus Not Obscured)."
                            ),
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Add `html { scroll-padding-top: 5rem; }` or configure `scroll-margin-top` on headings and form sections.",
                            cwe_id="CWE-1078",
                            compliance_controls={"WCAG-2.2": "2.4.11 Focus Not Obscured (Minimum)"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 3. UIUX-A11Y-NOISY-DECORATIVE-SVG
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".vue", ".jsx", ".tsx"]):
            svg_pattern = re.compile(r'<svg\b([^>]*?)>', re.IGNORECASE)
            for match in svg_pattern.finditer(content):
                attrs = match.group(1)
                is_hidden = 'aria-hidden="true"' in attrs or "aria-hidden='true'" in attrs
                has_label = (
                    "aria-label=" in attrs or
                    "aria-labelledby=" in attrs or
                    'role="img"' in attrs
                )
                if not is_hidden and not has_label:
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-A11Y-NOISY-DECORATIVE-SVG",
                            title="UI/UX Accessibility: Decorative Inline SVG Lacks aria-hidden='true' (Screen Reader Noise)",
                            description=(
                                "Inline `<svg>` element lacks `aria-hidden='true'` and contains no accessible label or title. "
                                "Screen readers (NVDA, JAWS, VoiceOver) announce unlabelled vector graphics as noisy generic objects "
                                "or vocalize internal `<path>` coordinate coordinates, disrupting auditory comprehension."
                            ),
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Add `aria-hidden=\"true\"` to decorative SVGs or provide an accessible `<title>` / `aria-label` if communicative.",
                            cwe_id="CWE-1078",
                            compliance_controls={"WCAG-2.1": "1.1.1 Non-text Content", "WAI-ARIA": "Graphics-Accessibility"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 4. UIUX-A11Y-PLACEHOLDER-AS-LABEL
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".vue", ".jsx", ".tsx"]):
            # Look for input or textarea that has placeholder but no aria-label, aria-labelledby, or id linked to label
            input_pattern = re.compile(r'<(?:input|textarea)\b([^>]*?placeholder\s*=\s*["\'][^"\']+["\'][^>]*?)>', re.IGNORECASE)
            for match in input_pattern.finditer(content):
                attrs = match.group(1)
                # Check for explicit label attributes
                has_accessible_name = (
                    "aria-label=" in attrs or
                    "aria-labelledby=" in attrs or
                    'type="hidden"' in attrs or
                    'type="submit"' in attrs or
                    'type="button"' in attrs
                )
                # Check if input has an id and if that id is referenced by a label
                id_match = re.search(r'\bid\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                has_label_for = False
                if id_match:
                    elem_id = id_match.group(1)
                    has_label_for = f'for="{elem_id}"' in content or f"for='{elem_id}'" in content or f'htmlFor="{elem_id}"' in content

                if not has_accessible_name and not has_label_for:
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-A11Y-PLACEHOLDER-AS-LABEL",
                            title="UI/UX Usability: Input Relies Exclusively on Placeholder Instead of Accessible Label (WCAG 3.3.2)",
                            description=(
                                "Form field declares a `placeholder` attribute without an associated persistent `<label>` or `aria-label`. "
                                "Placeholders vanish the moment a user begins typing, forcing users to recall what data was requested. "
                                "This violates WCAG 3.3.2 (Labels or Instructions) and Nielsen Usability Heuristic #6 (Recognition over Recall)."
                            ),
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Provide a persistent `<label for='...'>` element or supply an explicit `aria-label` attribute.",
                            cwe_id="CWE-1078",
                            compliance_controls={"WCAG-2.1": "3.3.2 Labels or Instructions", "Nielsen": "Heuristic 6"},
                        )
                    )

        return findings
