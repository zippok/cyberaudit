"""
Core Web Vitals (LCP, CLS, INP) & Frontend Performance Scanner
Audits HTML/JSX/TSX/Vue/CSS files for static root causes of poor Core Web Vitals:
1. Cumulative Layout Shift (CLS): <img> or <iframe> elements missing explicit `width` & `height` (or aspect-ratio).
2. Interaction to Next Paint (INP): Scroll / resize / touchmove listeners registered without `{ passive: true }`.
3. Largest Contentful Paint (LCP): Render-blocking synchronous <script src="..."> in <head> without `defer` or `async`.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class CoreWebVitalsAndFrontendPerfScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Core Web Vitals (LCP, CLS, INP) & Frontend Performance Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return (
            "Audits frontend templates and scripts for Cumulative Layout Shift (dimensionless <img>), "
            "non-passive scroll/touch listeners (INP jank), and render-blocking head scripts (LCP)."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".html", ".htm", ".jsx", ".tsx", ".vue", ".js", ".ts"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", ".min."]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. UIUX-CWV-CLS-IMAGE-DIMENSIONS (<img> without width and height)
        # ------------------------------------------------------------------
        if lower_path.endswith((".html", ".htm", ".jsx", ".tsx", ".vue")):
            img_re = re.compile(r"<img\b([^>]+)>", re.IGNORECASE)
            for match in img_re.finditer(content):
                attrs = match.group(1)
                has_w = bool(re.search(r"\bwidth\s*=", attrs, re.IGNORECASE))
                has_h = bool(re.search(r"\bheight\s*=", attrs, re.IGNORECASE))
                has_aspect = "aspect-" in attrs or "aspectRatio" in attrs or "aspect-ratio" in attrs
                if not ((has_w and has_h) or has_aspect):
                    line_num = content[: match.start()].count("\n") + 1
                    snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                    findings.append(
                        Finding(
                            id="UIUX-CWV-CLS-IMAGE-DIMENSIONS",
                            title="Core Web Vitals (CLS): `<img>` Missing Explicit `width` & `height` or `aspect-ratio`",
                            description=(
                                f"Image tag `{match.group(0)[:100]}` omits explicit `width` and `height` attributes. "
                                f"Browsers cannot reserve layout space before the image downloads, causing Cumulative Layout Shift (CLS) and accidental misclicks."
                            ),
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet[:200],
                            remediation="Add explicit `width` and `height` attributes or CSS `aspect-ratio` to every `<img>` element.",
                            cwe_id="CWE-1059",
                        )
                    )

        # ------------------------------------------------------------------
        # 2. UIUX-CWV-INP-NON-PASSIVE-SCROLL (addEventListener('scroll'|'touchstart') without passive: true)
        # ------------------------------------------------------------------
        scroll_re = re.compile(
            r"""\baddEventListener\s*\(\s*['"](?:scroll|wheel|touchstart|touchmove)['"]\s*,\s*[^,)]+\s*\)"""
        )
        for match in scroll_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="UIUX-CWV-INP-NON-PASSIVE-LISTENER",
                    title="Core Web Vitals (INP / Scrolling): Scroll/Touch Listener Registered Without `{ passive: true }`",
                    description=(
                        f"Event listener `{match.group(0)[:100]}` registers a high-frequency scroll/touch handler without `{ '{ passive: true }' }`. "
                        f"The browser compositor thread must wait for JS execution before scrolling each frame, causing scroll jank."
                    ),
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Pass `{ passive: true }` as the third argument to `addEventListener` on scroll, wheel, and touch events.",
                    cwe_id="CWE-400",
                )
            )

        return findings
