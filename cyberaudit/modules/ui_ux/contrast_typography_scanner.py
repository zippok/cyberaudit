"""
Color Contrast & Typography Usability Scanner
Audits stylesheets and markup for visual accessibility and readability:
- Low contrast foreground/background color combinations (WCAG 1.4.3 Contrast Minimum)
- Tiny sub-readable typography under 11px
- Text selection disabled globally (user-select: none anti-pattern)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class ContrastTypographyScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "UIUX-TYPOGRAPHY-LOW-CONTRAST",
                "title": "UI/UX Contrast: Low Color Contrast Ratio (WCAG 1.4.3)",
                "pattern": re.compile(
                    r'(?:color\s*:\s*#(?:ccc|ddd|eee|bbb|aaa)\b[\s\S]{0,40}?background(?:-color)?\s*:\s*#(?:fff|fafafa|f8f9fa|f0f0f0)|background(?:-color)?\s*:\s*#(?:fff|fafafa|f8f9fa|f0f0f0)[\s\S]{0,40}?color\s*:\s*#(?:ccc|ddd|eee|bbb|aaa)\b|color\s*:\s*#(?:111|222|333)\b[\s\S]{0,40}?background(?:-color)?\s*:\s*#(?:000|0a0f1d|070b14|111827))',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Visual element applies a text-to-background contrast ratio below the WCAG 2.1 AA threshold of 4.5:1. Users with moderate visual impairments cannot comfortably read the content.",
                "remediation": "Adjust text or background color values to satisfy at least 4.5:1 contrast for regular text (or 3:1 for large text 18pt+).",
                "file_types": [".css", ".scss", ".sass", ".html", ".jsx", ".tsx"],
                "compliance": {"WCAG": "1.4.3 Contrast (Minimum) Level AA"},
            },
            {
                "id": "UIUX-TYPOGRAPHY-TINY-FONT",
                "title": "UI/UX Typography: Sub-Readable Font Size Below 11px",
                "pattern": re.compile(
                    r'(?:font-size\s*:\s*(?:[6-9]|10)px|text-\[(?:[6-9]|10)px\])',
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "Font size declared at 10px or smaller. Extreme small type severely degrades legibility, causes eye fatigue, and renders information unreadable on high-DPI displays.",
                "remediation": "Maintain a minimum font size of 12px for microcopy/labels and 14-16px for body copy.",
                "file_types": [".css", ".scss", ".sass", ".html", ".jsx", ".tsx"],
                "compliance": {"WCAG": "1.4.4 Resize Text (Level AA)"},
            },
            {
                "id": "UIUX-USABILITY-USER-SELECT-NONE",
                "title": "UI/UX Usability: Global Text Selection Disabled (user-select: none)",
                "pattern": re.compile(
                    r'(?:body|html|:root|\.app|\.main|#app)\s*\{[^{}]*?(?:-webkit-user-select|user-select)\s*:\s*none',
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "Global text selection disabled across the entire document or body container (`user-select: none`). This disrupts screen readers, dictionary lookups, and users attempting to copy error codes or snippets.",
                "remediation": "Apply `user-select: none` only to specific non-text interactive drag handles or icons, never globally to document text.",
                "file_types": [".css", ".scss", ".html", ".jsx", ".tsx"],
                "compliance": {"Usability": "Nielsen Norman Group Heuristic #3: User Control and Freedom"},
            },
        ]

    @property
    def name(self) -> str:
        return "UI/UX Color Contrast & Typography Usability Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return "Audits text-to-background contrast ratios, minimum font size thresholds, and anti-selection usability issues."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

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

                matched_line = lines[line_num - 1].strip() if line_num - 1 < len(lines) else ""
                if matched_line.startswith(("<!--", "//", "/*", "*")):
                    continue

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
                        code_snippet=snippet,
                        remediation=rule["remediation"],
                        cwe_id="CWE-1078",
                        compliance_controls=rule.get("compliance", {}),
                    )
                )

        return findings
