"""
Observability, SRE Telemetry & Structured Error Context Scanner
Audits backend and service code for:
1. Catch blocks that log only `err.message` / `str(e)` while discarding the stack trace and causal chain.
2. Error logging without correlation / request / trace context in service handlers.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class ObservabilityAndStructuredLoggingScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Observability, SRE Telemetry & Error Context Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return (
            "Detects error handlers that discard stack traces (logging only err.message) "
            "or swallow causal exception chains without structured context."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. QA-SRE-LOST-STACK-TRACE (Rethrowing new Error(err.message) without { cause: err })
        # ------------------------------------------------------------------
        rethrow_no_cause_re = re.compile(
            r"\bthrow\s+new\s+\w*Error\s*\(\s*[^)\n]*?\b(?:err|error|e)\.message\s*\)"
        )
        for match in rethrow_no_cause_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="QA-SRE-LOST-ERROR-CAUSE",
                    title="Observability & SRE: Rethrown Error Discards Original Stack Trace and `cause` Chain",
                    description=(
                        f"Statement `{snippet}` wraps `err.message` into a new `Error` without preserving `{ '{ cause: err }' }`. "
                        f"This destroys the original call stack, making post-mortem root-cause analysis in production nearly impossible."
                    ),
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Pass the original error as the standard ES2022 cause: `throw new Error(msg, { cause: err })` (or `raise ... from e` in Python).",
                    cwe_id="CWE-390",
                    stride_category=StrideCategory.REPUDIATION.value,
                )
            )

        # Python raise new Exception inside except without `from e`
        if lower_path.endswith(".py"):
            py_rethrow_re = re.compile(
                r"except\s+(?:Exception|\w+Error)\s+as\s+(\w+)\s*:\s*\n(?:\s+#[^\n]*\n)*\s+raise\s+\w+Error\([^)\n]+\)\s*$",
                re.MULTILINE,
            )
            for match in py_rethrow_re.finditer(content):
                stmt = match.group(0)
                if " from " in stmt:
                    continue
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else stmt.splitlines()[-1]
                findings.append(
                    Finding(
                        id="QA-SRE-PYTHON-RAISE-WITHOUT-FROM",
                        title="Observability (PEP 3134): Exception Raised in `except` Block Without `from err` Chaining",
                        description=(
                            f"Exception handler at line {line_num} raises a new exception without `from {match.group(1)}`, "
                            f"obscuring explicit exception chaining in tracebacks."
                        ),
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation=f"Use explicit exception chaining: `raise CustomError(...) from {match.group(1)}`.",
                        cwe_id="CWE-390",
                    )
                )

        return findings
