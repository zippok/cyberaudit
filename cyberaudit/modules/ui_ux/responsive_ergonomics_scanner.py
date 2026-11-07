"""
Mobile Responsiveness & Touch Ergonomics Scanner
Audits templates and styles for mobile usability and responsive design:
- Disabled pinch-to-zoom in viewport meta (WCAG 1.4.4 Resize Text)
- Fixed desktop-only pixel dimensions inducing mobile horizontal scrolling
- Sub-standard interactive tap targets violating Apple HIG & Google Material specs
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class ResponsiveErgonomicsScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "UIUX-MOBILE-VIEWPORT-DISABLED",
                "title": "UI/UX Mobile: Viewport Zoom Disabled (WCAG 1.4.4)",
                "pattern": re.compile(
                    r'<meta\b[^>]*?\bname\s*=\s*[\'"]viewport[\'"][^>]*?\bcontent\s*=\s*[\'"][^\'"]*?(?:user-scalable\s*=\s*(?:no|0)|maximum-scale\s*=\s*1(?:\.0)?)[^\'"]*?[\'"][^>]*>',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Viewport `<meta>` tag explicitly disables user zoom (`user-scalable=no` or `maximum-scale=1.0`). This prevents low-vision users from enlarging text and content on mobile devices, violating WCAG 1.4.4.",
                "remediation": "Remove `user-scalable=no` and `maximum-scale=1.0`. Standard compliant tag: `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">`.",
                "file_types": [".html", ".htm", ".php", ".jsx", ".tsx"],
                "compliance": {"WCAG": "1.4.4 Resize Text (Level AA)", "ADA": "Mobile Accessibility Guidelines"},
            },
            {
                "id": "UIUX-LAYOUT-FIXED-OVERFLOW",
                "title": "UI/UX Responsive: Fixed Width Induces Mobile Horizontal Scrolling",
                "pattern": re.compile(
                    r'(?<![a-zA-Z\-])(?:width|min-width)\s*:\s*(?:8\d\d|9\d\d|[1-9]\d{3,})\s*px',
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "Container elements configured with excessive fixed pixel width (800px+). On mobile viewports (360px - 430px), this induces broken horizontal scrollbars and truncated cards.",
                "remediation": "Use fluid units (`max-width: 100%`, `w-full`, `clamp(...)`) or responsive CSS media queries / flexbox / grid.",
                "file_types": [".css", ".scss", ".sass", ".html", ".jsx", ".tsx"],
                "compliance": {"WCAG": "1.4.10 Reflow (Level AA)"},
            },
            {
                "id": "UIUX-ERGONOMICS-TINY-TAP-TARGET",
                "title": "UI/UX Ergonomics: Touch Target Below Mobile Standard (WCAG 2.5.8)",
                "pattern": re.compile(
                    r'(?:\.btn|button|\.clickable)[^{}]*?\{\s*[^}]*?(?:width\s*:\s*(?:[1-2][0-9])px;?\s*height\s*:\s*(?:[1-2][0-9])px|height\s*:\s*(?:[1-2][0-9])px;?\s*width\s*:\s*(?:[1-2][0-9])px)',
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "Interactive touch elements sized smaller than 24-32px without padding. Violates touch ergonomics (Apple HIG recommends 44x44pt; Google Material Design recommends 48x48dp minimum target area).",
                "remediation": "Increase button hit box to at least 44x44px or provide sufficient padding (`padding: 12px`).",
                "file_types": [".css", ".scss", ".html", ".jsx", ".tsx"],
                "compliance": {"WCAG": "2.5.8 Target Size (Minimum Level AA)", "AppleHIG": "Touch Targets 44x44pt"},
            },
        ]

    @property
    def name(self) -> str:
        return "UI/UX Responsive Layout & Touch Ergonomics Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return "Evaluates responsive viewport configurations, fluid reflow constraints, and touch target sizing."

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

                # Skip comment lines
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
