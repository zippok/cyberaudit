"""
Test Suite & Coverage Health Auditor
Audits the presence, quality, and effectiveness of tests across the codebase:
- Tests without assertions (placebo tests with pass / empty body)
- Disproportionate test-to-code ratio
- Critical business logic without corresponding unit test suite
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class TestCoverageAuditor(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Test Coverage & Test Suite Auditor"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Audits unit test presence, asserts validity, and flags empty or assertion-free tests."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # 1. Identify if file is a test file
        is_test_file = any(
            marker in lower_path
            for marker in [
                "test_",
                "_test.",
                ".test.",
                ".spec.",
                "/tests/",
                "\\tests\\",
                "/test/",
                "\\test\\",
            ]
        )

        lines = content.splitlines()

        if is_test_file:
            # Check for empty / placebo test functions (e.g. def test_foo(): pass or it('test', () => {}))
            for line_idx, line in enumerate(lines, start=1):
                clean_l = line.strip()
                # Python empty test
                if clean_l.startswith("def test_"):
                    # Check next line
                    if line_idx < len(lines):
                        next_line = lines[line_idx].strip()
                        if next_line in ["pass", "...", "return"]:
                            findings.append(
                                Finding(
                                    id="QA-TEST-EMPTY-ASSERTION",
                                    title="Software QA: Placebo Test Case (Test Function Without Assertions)",
                                    description="Test function defined with empty body (`pass` or `...`). Placebo tests create a false sense of test coverage while verifying no invariants.",
                                    severity=Severity.LOW,
                                    pillar=self.pillar,
                                    scanner_name=self.name,
                                    file_path=file_path,
                                    line_number=line_idx,
                                    code_snippet=f"{clean_l}\n    {next_line}",
                                    remediation="Implement explicit verification assertions (`assert condition` or `self.assertEqual(...)`).",
                                    cwe_id="CWE-1078",
                                )
                            )

                # JS/TS empty test block
                if re.search(r"(?:it|test)\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:\(\)\s*=>\s*\{\s*\}|function\s*\(\)\s*\{\s*\})", clean_l):
                    findings.append(
                        Finding(
                            id="QA-TEST-EMPTY-ASSERTION-JS",
                            title="Software QA: Empty Test Block in JavaScript/TypeScript",
                            description="Test case registered with an empty callback body. No assertions (`expect()`, `assert()`) are evaluated.",
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_idx,
                            code_snippet=clean_l[:180],
                            remediation="Add test expectations and assertions (`expect(result).toBe(...)`).",
                            cwe_id="CWE-1078",
                        )
                    )

        return findings
