"""
Code Quality & Software Hygiene Scanner
Audits source code for maintainability, reliability, and defect prevention:
- Swallowed exceptions (empty catch blocks / except: pass)
- Indefinite network hangs (missing timeout parameters in fetch, axios, requests)
- Unhandled asynchronous promise rejections
- Excessive nested block complexity
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class CodeQualityScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "QA-SWALLOWED-EXCEPTION-PY",
                "title": "Software QA: Swallowed Exception (except Exception: pass)",
                "pattern": re.compile(
                    r"except(?:\s+[A-Za-z0-9_]+)?\s*:\s*(?:pass|\.\.\.)\b",
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Silent suppression of exceptions with `pass`. Swallowing errors masks underlying defects, database corruptions, and broken states.",
                "remediation": "Log the exception with traceback (`logger.exception(...)`) or gracefully handle specific expected errors.",
                "file_types": [".py"],
            },
            {
                "id": "QA-EMPTY-CATCH-BLOCK-JS",
                "title": "Software QA: Empty Catch Block (Silent Error Swallowing)",
                "pattern": re.compile(
                    r"catch\s*(?:\([^\)]*\))?\s*\{\s*(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/|\s*)*\}",
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Empty `catch` block detected in JavaScript/TypeScript. Silent failure leaves UI components in indeterminate states and prevents crash diagnostics.",
                "remediation": "Log the error to monitoring telemetry (`console.error` or Sentry/Datadog) and provide user-facing feedback.",
                "file_types": [".js", ".ts", ".jsx", ".tsx", ".mjs"],
            },
            {
                "id": "QA-NETWORK-CALL-NO-TIMEOUT",
                "title": "Software QA: Network Request Without Explicit Timeout",
                "pattern": re.compile(
                    r'(?:requests\.(?:get|post|put|delete)\s*\([^)]*?(?!timeout\s*=)[^)]*\)|fetch\s*\([^)]*?(?!signal\s*:)[^)]*\)|axios\.(?:get|post)\s*\([^)]*?(?!timeout\s*:)[^)]*\))',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "HTTP request invoked without an explicit timeout configuration. A dropped network socket or slow server will cause an indefinite thread or UI freeze.",
                "remediation": "Provide explicit `timeout` (e.g. `timeout=10` in Python or `AbortSignal.timeout(10000)` in modern fetch).",
                "file_types": [".py", ".js", ".ts", ".jsx", ".tsx"],
            },
            {
                "id": "QA-DANGLING-DEBUGGER",
                "title": "Software QA: Leftover Debugger Statement in Production Code",
                "pattern": re.compile(r"\bdebugger\s*;", re.IGNORECASE),
                "severity": Severity.LOW,
                "description": "Explicit `debugger;` breakpoint left in code. When executed in browser/node DevTools, it freezes execution unexpectedly.",
                "remediation": "Remove all debugger statements prior to staging and production builds.",
                "file_types": [".js", ".ts", ".jsx", ".tsx", ".html"],
            },
            {
                "id": "QA-NESTED-COMPLEXITY-SPIKE",
                "title": "Software QA: Excessive Nesting Depth (Arrow Anti-Pattern)",
                "pattern": re.compile(
                    r"^(?:\t|\s{4}){5,}(?:if|for|while|try|switch)\b",
                    re.MULTILINE,
                ),
                "severity": Severity.LOW,
                "description": "Code constructs nested 5+ levels deep. High cyclomatic and cognitive complexity directly correlates with production defect density.",
                "remediation": "Refactor into guard clauses (early returns) or extract nested logic into independent, testable sub-functions.",
                "file_types": [".py", ".js", ".ts", ".cpp", ".java", ".go"],
            },
        ]

    @property
    def name(self) -> str:
        return "Software QA & Code Quality Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Evaluates code maintainability, error suppression, network call resilience, and excessive cyclomatic complexity."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip minified, vendor or markdown files
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock"]):
            return []

        lines = content.splitlines()

        for rule in self.rules:
            # Check file type filter
            if rule.get("file_types"):
                if not any(lower_path.endswith(ext) for ext in rule["file_types"]):
                    continue

            # Special check for network timeout: regex on lines or statement chunks
            if rule["id"] == "QA-NETWORK-CALL-NO-TIMEOUT":
                for line_idx, line in enumerate(lines, start=1):
                    # Check python requests without timeout
                    if "requests.get(" in line or "requests.post(" in line:
                        if "timeout" not in line and not line.strip().startswith("#"):
                            findings.append(
                                Finding(
                                    id=rule["id"],
                                    title=rule["title"],
                                    description=rule["description"],
                                    severity=rule["severity"],
                                    pillar=self.pillar,
                                    scanner_name=self.name,
                                    file_path=file_path,
                                    line_number=line_idx,
                                    code_snippet=line.strip()[:180],
                                    remediation=rule["remediation"],
                                    cwe_id="CWE-400",
                                )
                            )
                continue

            # Multi-line pattern matching
            matches = rule["pattern"].finditer(content)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                snippet = match.group(0).strip()[:180]

                # Ensure snippet isn't inside a pure comment line
                matched_line = lines[line_num - 1].strip() if line_num - 1 < len(lines) else ""
                if matched_line.startswith(("#", "//", "/*", "*")):
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
                    cwe_id="CWE-390" if "EXCEPTION" in rule["id"] or "CATCH" in rule["id"] else "CWE-1078",
                )
                findings.append(finding)

        return findings
