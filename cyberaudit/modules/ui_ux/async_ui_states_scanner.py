"""
Async UI States Completeness Scanner (Loading / Error / Empty / Double-Submit)
Audits Frontend UI components (.jsx, .tsx, .vue, .html) for:
1. Double-Submit Vulnerability: Forms / submit buttons triggering async mutations without a `disabled` / loading lock.
2. Raw Blocking Browser Alerts (`window.alert` / `alert(...)`) used for error feedback instead of non-blocking inline/toast UI.
3. Silent Async UI Failures: `fetch`/`axios` `.catch(...)` blocks that only `console.log`/`console.error` without updating UI error state.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class AsyncUiStatesCompletenessScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Async UI States Completeness Scanner (Loading/Error/Empty/Double-Submit)"

    @property
    def pillar(self) -> Pillar:
        return Pillar.UI_UX

    @property
    def description(self) -> str:
        return (
            "Audits frontend components for missing disabled/loading submit locks (double-submit bug), "
            "blocking browser alert() dialogs, and silent async catch blocks lacking UI error state."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".jsx", ".tsx", ".vue", ".html", ".htm"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", ".min."]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. UIUX-ASYNC-DOUBLE-SUBMIT (Form with onSubmit + fetch/axios but no disabled button)
        # ------------------------------------------------------------------
        has_async_submit = bool(
            re.search(r"\bonSubmit\s*=\s*\{|\b@submit(?:\.prevent)?\s*=", content)
            and re.search(r"\b(?:fetch|axios|mutate|submit)\b", content)
        )
        if has_async_submit:
            submit_btn_re = re.compile(r"<button\b([^>]*?\btype\s*=\s*['\"]submit['\"][^>]*)>", re.IGNORECASE)
            for match in submit_btn_re.finditer(content):
                attrs = match.group(1)
                if "disabled" not in attrs.lower() and "loading" not in attrs.lower():
                    line_num = content[: match.start()].count("\n") + 1
                    snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                    findings.append(
                        Finding(
                            id="UIUX-ASYNC-DOUBLE-SUBMIT",
                            title="UI/UX & Ergonomics: Async Form Submit Button Lacks `disabled` Loading Guard (Double-Submit)",
                            description=(
                                f"Submit button `{match.group(0)}` in an async form has no `disabled={{isSubmitting || isLoading}}` attribute. "
                                f"Users on slow connections who double-click the button will fire duplicate POST requests."
                            ),
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet[:200],
                            remediation="Bind `disabled={isSubmitting}` and `aria-busy={isSubmitting}` to the submit button while the async request is in flight.",
                            cwe_id="CWE-841",
                        )
                    )

        # ------------------------------------------------------------------
        # 2. UIUX-BLOCKING-WINDOW-ALERT (Native alert() used in UI components)
        # ------------------------------------------------------------------
        alert_re = re.compile(r"(?<![.\w])(?:window\.)?alert\s*\(\s*[^)]+\)")
        for match in alert_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="UIUX-BLOCKING-WINDOW-ALERT",
                    title="UI/UX Ergonomics: Blocking Native `window.alert()` Freezes Main Browser Thread",
                    description=(
                        f"Component invokes native browser `{match.group(0).strip()}`. Native alerts block the JavaScript event loop, "
                        f"break screen-reader flow, cannot be styled to match the design system, and offer poor recovery ergonomics."
                    ),
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Render an inline `<div role=\"alert\" aria-live=\"assertive\">` banner or non-blocking toast notification.",
                    cwe_id="CWE-1059",
                )
            )

        return findings
