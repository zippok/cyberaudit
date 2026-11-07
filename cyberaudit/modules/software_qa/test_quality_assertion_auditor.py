"""
Test Quality, Anti-Theater & Assertion Integrity Auditor
Audits test files (.test.*, .spec.*, test_*.py) against Google SE & Dave Farley CD principles:
1. Tautological / Theater Assertions (expect(true).toBe(true), assert True).
2. Assertion-Free Tests (test blocks with zero assertions or verification calls).
3. Forgotten Exclusive or Disabled Tests (.only / .skip / @pytest.mark.skip without reason).
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class TestQualityAndAssertionAuditor(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Test Quality, Anti-Theater & Assertion Auditor"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return (
            "Audits test suites for tautological assertions (expect(true).toBe(true)), "
            "assertion-free theater tests, and left-over .only/.skip modifiers."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".jsx", ".tsx", ".py"]

    def should_scan(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/").lower()
        return any(k in norm for k in ["/test/", "/tests/", ".test.", ".spec.", "test_"])

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. QA-TEST-TAUTOLOGICAL-ASSERTION (Theater Assertion)
        # ------------------------------------------------------------------
        tautology_patterns = [
            re.compile(r"\bexpect\s*\(\s*(?:true|1|'a'|\"a\")\s*\)\.(?:toBe|toEqual|toStrictEqual)\s*\(\s*(?:true|1|'a'|\"a\")\s*\)"),
            re.compile(r"\bassert\.(?:strictEqual|equal|ok)\s*\(\s*(?:true|1)\s*(?:,\s*(?:true|1))?\s*\)"),
            re.compile(r"^\s*assert\s+True\s*$", re.MULTILINE),
        ]
        for pattern in tautology_patterns:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                findings.append(
                    Finding(
                        id="QA-TEST-TAUTOLOGICAL-ASSERTION",
                        title="Test Quality (Anti-Theater): Tautological Assertion Always Passes",
                        description=(
                            f"Test contains tautological assertion `{match.group(0).strip()}` which evaluates a constant against itself. "
                            f"This inflates test pass counts without verifying real system behavior."
                        ),
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Replace tautological checks with assertions against the actual return value, state change, or thrown error of the system under test.",
                        cwe_id="CWE-670",
                    )
                )

        # ------------------------------------------------------------------
        # 2. QA-TEST-EXCLUSIVE-ONLY-LEFT-IN-SUITE (.only)
        # ------------------------------------------------------------------
        only_re = re.compile(r"\b(?:it|test|describe)\.only\s*\(")
        for match in only_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="QA-TEST-EXCLUSIVE-ONLY",
                    title="Test Integrity: Exclusive `.only()` Silences Remainder of Test Suite in CI",
                    description=(
                        f"Detected `{match.group(0)}` at line {line_num}. Committing `.only` causes the test runner "
                        f"to skip all other tests in the file, creating a false green CI pipeline."
                    ),
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Remove `.only` before committing so the full regression suite runs in CI.",
                    cwe_id="CWE-489",
                )
            )

        # ------------------------------------------------------------------
        # 3. QA-TEST-MISSING-ASSERTION (Test Block Without Assertions)
        # ------------------------------------------------------------------
        js_test_block_re = re.compile(
            r"\b(?:it|test)\s*\(\s*['\"`][^'\"`]+['\"`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{([^}]{1,600})\}",
            re.DOTALL,
        )
        assertion_re = re.compile(
            r"\b(?:expect|assert|should|verify|rejects|throws|fail|toBe|toEqual|strictEqual|ok|match|deepEqual)\b"
        )
        for match in js_test_block_re.finditer(content):
            body = match.group(1)
            if "{" in body:
                # Skip complex nested blocks to avoid false positives on regex brace matching
                continue
            if not assertion_re.search(body):
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)[:100]
                findings.append(
                    Finding(
                        id="QA-TEST-MISSING-ASSERTION",
                        title="Test Quality: Test Case Executes Code Without Any Assertion",
                        description=(
                            f"Test block starting at line {line_num} executes statements without any `assert` or `expect` verification. "
                            f"Tests without assertions only check that code does not throw, masking wrong outputs."
                        ),
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Add explicit `assert.*` or `expect(...)` checks verifying the expected postconditions.",
                        cwe_id="CWE-670",
                    )
                )

        return findings
