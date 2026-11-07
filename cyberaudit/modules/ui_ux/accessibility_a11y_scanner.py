"""
Web & Mobile Accessibility (a11y) Scanner
Audits HTML, JSX, TSX, and templates against WCAG 2.1 / 2.2 Standards:
- Non-text Content without alternative text (WCAG 1.1.1 Level A)
- Icon-only buttons lacking accessible names (WCAG 4.1.2 Level A)
- Form inputs without accessible labels (WCAG 3.3.2 Level A)
- Positive tabindex disrupting natural keyboard navigation (WCAG 2.4.3 Level A)
- Missing primary document language attribute (WCAG 3.1.1 Level A)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class AccessibilityA11yScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "UIUX-A11Y-MISSING-ALT",
                "title": "UI/UX a11y: Missing Alternative Text on Image (WCAG 1.1.1)",
                "pattern": re.compile(
                    r"<img\b(?![^>]*?\balt\s*=)[^>]*?>",
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Image element lacks an `alt` attribute. Screen readers cannot describe the graphic, rendering essential visual information inaccessible to visually impaired users.",
                "remediation": "Provide descriptive `alt=\"Description of image\"` or `alt=\"\"` with `role=\"presentation\"` if purely decorative.",
                "file_types": [".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".php"],
                "compliance": {"WCAG": "1.1.1 Non-text Content (Level A)", "Section508": "1194.22(a)"},
            },
            {
                "id": "UIUX-A11Y-UNLABELLED-BUTTON",
                "title": "UI/UX a11y: Icon-Only Button Without Accessible Label (WCAG 4.1.2)",
                "pattern": re.compile(
                    r"<(?:button|a)\b(?![^>]*?(?:aria-label|aria-labelledby|title)\s*=)[^>]*?>\s*<(?:i|svg|span)\b[^>]*?class=[^>]*?(?:fa-|icon|material-icons)[^>]*?>[\s\S]*?<\/(?:i|svg|span)>\s*<\/(?:button|a)>",
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Interactive button or anchor contains only an icon with no text or `aria-label`. Assistive technologies will announce 'button' with no name or purpose.",
                "remediation": "Add an explicit `aria-label=\"Description of action\"` or a visually hidden text element (`<span class=\"sr-only\">...</span>`).",
                "file_types": [".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".php"],
                "compliance": {"WCAG": "4.1.2 Name, Role, Value (Level A)", "EN301549": "9.4.1.2"},
            },
            {
                "id": "UIUX-A11Y-POSITIVE-TABINDEX",
                "title": "UI/UX a11y: Positive Tabindex Disrupts Natural Keyboard Flow (WCAG 2.4.3)",
                "pattern": re.compile(
                    r"\btabindex\s*=\s*['\"](?:[1-9][0-9]*)['\"]",
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "Elements using `tabindex` greater than 0 override the logical DOM tab sequence, confusing keyboard and screen reader users navigating complex interfaces.",
                "remediation": "Use `tabindex=\"0\"` to place elements in natural tab order, or `tabindex=\"-1\"` for programmatically focusable widgets.",
                "file_types": [".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".js", ".ts"],
                "compliance": {"WCAG": "2.4.3 Focus Order (Level A)"},
            },
            {
                "id": "UIUX-A11Y-MISSING-HTML-LANG",
                "title": "UI/UX a11y: Missing Primary Document Language Attribute (WCAG 3.1.1)",
                "pattern": re.compile(
                    r"<html\b(?![^>]*?\blang\s*=)[^>]*?>",
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "The `<html>` root element does not declare a `lang` attribute. Screen readers default to the OS language, causing severe pronunciation errors when synthesizing multilingual text.",
                "remediation": "Declare document language on root tag: `<html lang=\"es\">` or `<html lang=\"en\">`.",
                "file_types": [".html", ".htm", ".php"],
                "compliance": {"WCAG": "3.1.1 Language of Page (Level A)"},
            },
        ]

    @property
    def name(self) -> str:
        return "UI/UX Accessibility & WCAG Standards Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return "Audits markup and UI components for compliance with WCAG 2.1/2.2 accessibility, screen readers, and keyboard navigation."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip vendor / minified
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock"]):
            return []

        lines = content.splitlines()

        for rule in self.rules:
            if rule.get("file_types"):
                if not any(lower_path.endswith(ext) for ext in rule["file_types"]):
                    continue

            matches = rule["pattern"].finditer(content)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                snippet = match.group(0).strip()[:180]

                # Ignore comments
                matched_line = lines[line_num - 1].strip() if line_num - 1 < len(lines) else ""
                if matched_line.startswith(("<!--", "//", "/*", "*")):
                    continue

                finding = Finding(
                    id=rule["id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    remediation=rule["remediation"],
                    cwe_id="CWE-1078",
                    compliance_controls=rule.get("compliance", {}),
                )
                findings.append(finding)

        # Form Input Missing Label check
        if any(lower_path.endswith(ext) for ext in [".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte"]):
            # Look for input without aria-label or id or label
            input_pattern = re.compile(
                r"<input\b(?![^>]*?(?:type\s*=\s*['\"](?:hidden|submit|button|reset|image)['\"]|aria-label|aria-labelledby|id\s*=))[^>]*?>",
                re.IGNORECASE,
            )
            for match in input_pattern.finditer(content):
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                snippet = match.group(0).strip()[:180]
                matched_line = lines[line_num - 1].strip() if line_num - 1 < len(lines) else ""
                if matched_line.startswith(("<!--", "//", "/*")):
                    continue

                findings.append(
                    Finding(
                        id="UIUX-A11Y-MISSING-FORM-LABEL",
                        title="UI/UX a11y: Form Input Lacks Accessible Label or Name (WCAG 3.3.2)",
                        description="Input field rendered without `<label for=\"...\">`, `aria-label`, or `aria-labelledby`. Users of assistive technologies cannot discern what input is requested.",
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet,
                        remediation="Associate a `<label for=\"inputId\">` or provide `aria-label=\"Nombre de usuario\"`.",
                        cwe_id="CWE-1078",
                        compliance_controls={"WCAG": "3.3.2 Labels or Instructions (Level A)"},
                    )
                )

        return findings
