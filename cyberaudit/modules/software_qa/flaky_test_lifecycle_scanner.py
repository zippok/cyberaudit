"""
Flaky Test, Mutation Quality & Lifecycle Memory Scanner (Software QA)
Audits source code for:
- Flaky tests caused by non-deterministic arbitrary sleeps (QA-FLAKY-ARBITRARY-SLEEP)
- Unfrozen system clock dependencies in test suites (QA-FLAKY-TIMEZONE-CLOCK)
- Tautological and placebo assertions with zero mutation sensitivity (QA-TEST-TAUTOLOGICAL-ASSERTION)
- Missing unmount cleanup / teardown functions in reactive hooks (QA-MEMORY-HOOK-MISSING-CLEANUP)
"""

import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class FlakyTestLifecycleScanner(BaseScanner):
    __test__ = False  # Prevent pytest from collecting this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Flaky Test, Mutation Quality & Lifecycle Memory Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Audits test flakiness (arbitrary sleeps, unmocked system clocks), placebo assertions, and reactive hook memory leaks."

    @property
    def supported_extensions(self) -> Set[str]:
        return {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte",
            ".java", ".go", ".cs", ".rb", ".php"
        }

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip non-code and minified assets
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock", ".svg"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        is_test_file = (
            "test" in lower_path or "spec" in lower_path or
            "/tests/" in lower_path or "\\tests\\" in lower_path or
            "/__tests__/" in lower_path or "\\__tests__\\" in lower_path
        )

        # ----------------------------------------------------------------------
        # 1 & 2 & 3. Test-Specific Scans: Sleeps, Clock, and Tautologies
        # ----------------------------------------------------------------------
        if is_test_file:
            # 1. QA-FLAKY-ARBITRARY-SLEEP
            sleep_patterns = [
                (re.compile(r'\btime\.sleep\s*\(\s*(\d+(?:\.\d+)?)\s*\)'), "Python time.sleep() delay"),
                (re.compile(r'\bThread\.sleep\s*\(\s*(\d+)\s*\)'), "Java/C# Thread.sleep() delay"),
                (re.compile(r'\bawait\s+new\s+Promise\s*\(\s*(?:\w+\s*=>\s*)?setTimeout\b'), "JavaScript Promise/setTimeout delay"),
                (re.compile(r'\bawait\s+delay\s*\(\s*(\d+)\s*\)'), "Async delay() delay"),
            ]
            for pattern, desc in sleep_patterns:
                for match in pattern.finditer(content):
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    if matched_line.startswith(("#", "//", "/*", "*")):
                        continue
                    findings.append(
                        Finding(
                            id="QA-FLAKY-ARBITRARY-SLEEP",
                            title=f"Software QA: Flaky Test Hazard Due to Hardcoded Sleep Delay ({desc})",
                            description=(
                                f"Test file relies on arbitrary hardcoded sleep ({match.group(0)}). Under congested CI/CD runners or "
                                f"varying CPU throttling, fixed delays fail unpredictably or unnecessarily prolong test suite runtimes. "
                                f"Flaky tests erode team confidence and mask real software regressions."
                            ),
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Replace arbitrary sleep delays with deterministic polling or event conditions (e.g. `await waitFor(...)`, pytest polling fixtures).",
                            cwe_id="CWE-1078",
                            compliance_controls={"IEEE-829": "Test-Determinism", "ISO-25010": "Test-Reliability"},
                        )
                    )

            # 2. QA-FLAKY-TIMEZONE-CLOCK
            has_temporal_mock = any(k in content for k in [
                "freezegun", "freeze_time", "time_machine", "useFakeTimers", "fakeTimers", "clock.tick", "sinon"
            ])
            if not has_temporal_mock:
                clock_patterns = [
                    (re.compile(r'\bdatetime\.(?:now|today)\s*\(\s*\)'), "datetime.now() in test without freeze_time"),
                    (re.compile(r'\b(?:new\s+Date\s*\(\s*\)|Date\.now\s*\(\s*\))'), "Date.now() in test without useFakeTimers"),
                ]
                for pattern, desc in clock_patterns:
                    for match in pattern.finditer(content):
                        start_pos = match.start()
                        line_num = content[:start_pos].count("\n") + 1
                        matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                        if matched_line.startswith(("#", "//", "/*", "*")):
                            continue
                        findings.append(
                            Finding(
                                id="QA-FLAKY-TIMEZONE-CLOCK",
                                title=f"Software QA: Flaky Test Vulnerability Due to Real System Clock Dependency",
                                description=(
                                    f"Test evaluates real system clock ({match.group(0)}) without temporal freezing. "
                                    f"Tests that compute current dates or timestamps break unpredictably at month ends, "
                                    f"leap years, daylight saving time (DST) shifts, or across CI servers in differing UTC timezones."
                                ),
                                severity=Severity.MEDIUM,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=matched_line[:180],
                                remediation="Freeze temporal execution using `freezegun` (@freeze_time) in Python or `jest.useFakeTimers()` in JavaScript/TypeScript.",
                                cwe_id="CWE-1078",
                                compliance_controls={"IEEE-829": "Temporal-Invariance", "ISO-25010": "Maintainability"},
                            )
                        )

            # 3. QA-TEST-TAUTOLOGICAL-ASSERTION
            tautology_patterns = [
                re.compile(r'\bassert\s+True\b'),
                re.compile(r'\bassert\s+1\s*==\s*1\b'),
                re.compile(r'\bself\.assertTrue\s*\(\s*True\s*\)'),
                re.compile(r'\bexpect\s*\(\s*true\s*\)\.toBe\s*\(\s*true\s*\)'),
                re.compile(r'\bexpect\s*\(\s*1\s*\)\.toBe\s*\(\s*1\s*\)'),
                re.compile(r'\bassert\.equal\s*\(\s*true\s*,\s*true\s*\)'),
            ]
            for pattern in tautology_patterns:
                for match in pattern.finditer(content):
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    if matched_line.startswith(("#", "//", "/*", "*")):
                        continue
                    findings.append(
                        Finding(
                            id="QA-TEST-TAUTOLOGICAL-ASSERTION",
                            title="Software QA: Tautological Placebo Assertion in Test Case (Zero Mutation Score)",
                            description=(
                                f"Test contains a tautological assertion (`{match.group(0)}`) that can never fail under any circumstance. "
                                f"Placebo assertions artificially inflate code coverage metrics while providing 0% defect detection capability "
                                f"and surviving all synthetic mutations."
                            ),
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Assert real business logic invariants and expected return values against the System Under Test (SUT).",
                            cwe_id="CWE-1078",
                            compliance_controls={"IEEE-829": "Mutation-Testing-Quality", "SQALE": "Reliability"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 4. Lifecycle Memory Leaks in Component Hooks (React, Vue)
        # ----------------------------------------------------------------------
        if any(lower_path.endswith(ext) for ext in [".jsx", ".tsx", ".js", ".ts", ".vue"]):
            # Scan for useEffect or useLayoutEffect registering subscriptions
            effect_pattern = re.compile(
                r'\buse(?:Layout)?Effect\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*\{([\s\S]*?)\}\s*,\s*\[',
                re.MULTILINE
            )
            for match in effect_pattern.finditer(content):
                body = match.group(1)
                # Check if it adds an event listener or interval
                has_listener = (
                    "addEventListener" in body or
                    "setInterval" in body or
                    ".subscribe(" in body or
                    "socket.on(" in body
                )
                if has_listener:
                    # Check for cleanup return
                    has_cleanup = (
                        "removeEventListener" in body or
                        "clearInterval" in body or
                        "unsubscribe" in body or
                        "disconnect" in body or
                        re.search(r'return\s+(?:\(\s*\)\s*=>|function)', body)
                    )
                    if not has_cleanup:
                        start_pos = match.start()
                        line_num = content[:start_pos].count("\n") + 1
                        matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                        findings.append(
                            Finding(
                                id="QA-MEMORY-HOOK-MISSING-CLEANUP",
                                title="Software QA & UI Memory Leak: Reactive Hook Lacks Teardown Cleanup Function",
                                description=(
                                    "A `useEffect` hook binds global event listeners, intervals, or WebSocket subscriptions without "
                                    "returning a teardown cleanup function. When this component re-renders or unmounts, subscriptions "
                                    "accumulate in memory, triggering ghost callbacks, state corruption on unmounted DOM nodes, and severe browser memory leaks."
                                ),
                                severity=Severity.HIGH,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=matched_line[:180],
                                remediation="Return a cleanup function from the hook: `return () => window.removeEventListener('...', handler);` or clear intervals.",
                                cwe_id="CWE-401",
                                stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                                compliance_controls={"ISO-25010": "Resource-Utilization", "W3C": "DOM-Lifecycle"},
                            )
                        )

        return findings
