"""
Advanced UX Heuristics & Accessibility Scanner (UI/UX)
Audits source code for:
- Killed focus indicators (outline: none / outline: 0 without focus replacement)
- Duplicate DOM element IDs (breaking accessibility tree associations)
- Missing autocomplete attributes on sensitive form inputs (WCAG 1.3.5)
- Continuous animations without prefers-reduced-motion queries (WCAG 2.3.3)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class UxAdvancedHeuristicsScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Advanced UX Heuristics & Form Accessibility Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return "Audits focus visibility (killed outlines), duplicate DOM IDs, missing autocomplete semantics, and vestibular motion preferences."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip non-relevant and minified assets
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock", ".svg"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # 1. Killed Focus Outline in CSS / HTML (<style>)
        if any(lower_path.endswith(ext) for ext in [".css", ".scss", ".sass", ".less", ".html", ".vue"]):
            # Look for outline: none or outline: 0
            outline_none_pattern = re.compile(
                r"(?:^|\s|\{|\;)(?:outline\s*:\s*(?:none|0)\s*(?:!important)?\s*[\;\}])",
                re.MULTILINE | re.IGNORECASE,
            )
            has_focus_visible = ":focus-visible" in content or "box-shadow:" in content
            for match in outline_none_pattern.finditer(content):
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                if matched_line.startswith(("//", "/*", "*")):
                    continue
                # If file defines outline: none without providing alternative focus style
                if not has_focus_visible:
                    findings.append(
                        Finding(
                            id="UIUX-KILLED-FOCUS-OUTLINE",
                            title="UI/UX Accessibility: Killed Focus Outline Without Visible Alternative (WCAG 2.4.7)",
                            description="CSS disables the default browser focus ring (`outline: none / 0`) without providing an accessible visual `:focus-visible` or `box-shadow` indicator. Keyboard-only navigation becomes virtually unusable.",
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Do not strip `outline: none` globally. Instead, customize it: `:focus-visible { outline: 2px solid #3b82f6; outline-offset: 2px; }`.",
                            cwe_id="CWE-1078",
                        )
                    )

        # 2. Duplicate DOM Element IDs in HTML / Vue / JSX templates
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".vue", ".jsx", ".tsx"]):
            id_pattern = re.compile(r'\bid\s*=\s*["\']([a-zA-Z0-9_\-]+)["\']', re.IGNORECASE)
            seen_ids: Dict[str, int] = {}
            for match in id_pattern.finditer(content):
                dom_id = match.group(1).strip()
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                # Ignore dynamic template IDs (e.g., id="item-${index}" or vue id=":id")
                if "{" in dom_id or "$" in dom_id:
                    continue
                if dom_id in seen_ids:
                    first_line = seen_ids[dom_id]
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-DUPLICATE-DOM-ID",
                            title=f"UI/UX DOM Integrity: Duplicate ID '{dom_id}' Detected (WCAG 4.1.1)",
                            description=f"HTML document defines duplicate `id='{dom_id}'` (first declared on line {first_line}). Duplicate IDs break `<label for='{dom_id}'>`, ARIA object references (`aria-labelledby`), and assistive DOM trees.",
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation=f"Ensure every element `id` attribute is globally unique in the DOM tree.",
                            cwe_id="CWE-1078",
                        )
                    )
                else:
                    seen_ids[dom_id] = line_num

        # 3. Missing Autocomplete Attributes on Sensitive Form Inputs
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".vue", ".jsx", ".tsx", ".php"]):
            input_pattern = re.compile(r'<input\s+[^>]*?type\s*=\s*["\']password["\'][^>]*>', re.IGNORECASE)
            for match in input_pattern.finditer(content):
                tag = match.group(0)
                if "autocomplete" not in tag.lower():
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="UIUX-FORM-MISSING-AUTOCOMPLETE",
                            title="UI/UX Usability: Password Input Missing Autocomplete Attribute (WCAG 1.3.5)",
                            description="Password input field lacks an explicit `autocomplete` attribute (`current-password` or `new-password`). Prevents password managers (Bitwarden, 1Password, iCloud Keychain) from autofilling securely.",
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation='Add `autocomplete="current-password"` for login forms or `autocomplete="new-password"` for registration/reset forms.',
                            cwe_id="CWE-1078",
                        )
                    )

        # 4. Continuous Animations Without Prefers-Reduced-Motion
        if any(lower_path.endswith(ext) for ext in [".css", ".scss", ".less"]):
            has_infinite_anim = bool(re.search(r"animation\s*:[^;]*?\binfinite\b", content, re.IGNORECASE))
            has_reduced_motion = "prefers-reduced-motion" in content
            if has_infinite_anim and not has_reduced_motion:
                infinite_match = re.search(r"animation\s*:[^;]*?\binfinite\b", content, re.IGNORECASE)
                start_pos = infinite_match.start() if infinite_match else 0
                line_num = content[:start_pos].count("\n") + 1
                matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                findings.append(
                    Finding(
                        id="UIUX-MOTION-SENSITIVITY-MISSING",
                        title="UI/UX Accessibility: Infinite CSS Animation Lacks prefers-reduced-motion (WCAG 2.3.3)",
                        description="Continuous loop animation detected without media query `@media (prefers-reduced-motion: reduce)`. Excessive motion triggers vestibular disorders, dizziness, and nausea in sensitive users.",
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=matched_line[:180],
                        remediation="Wrap infinite animations in `@media (prefers-reduced-motion: no-preference)` or provide `animation: none !important;` under reduced-motion.",
                        cwe_id="CWE-1078",
                    )
                )

        return findings
