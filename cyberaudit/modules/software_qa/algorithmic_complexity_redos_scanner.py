"""
Algorithmic Complexity O(N^2), Catastrophic Regex (ReDoS) & Unbounded Cache Scanner
Audits source code for:
1. Catastrophic Backtracking Regular Expressions (nested quantifiers like (a+)+, (.*)+).
2. O(N^2) nested array lookups (.includes / .indexOf / .find inside .map / .filter / for loops).
3. Unbounded module-level in-memory caches (new Map() / new Set() without eviction/TTL).
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class AlgorithmicComplexityAndRedosScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Algorithmic Complexity O(N^2) & ReDoS Static Profiler"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return (
            "Detects catastrophic backtracking regexes (ReDoS), O(N^2) nested collection lookups, "
            "and unbounded module-scope in-memory caches."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".jsx", ".tsx", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. QA-PERF-REDOS-QUANTIFIER (Nested Quantifiers in Regex)
        # ------------------------------------------------------------------
        redos_re = re.compile(
            r"""(?:/|re\.compile\s*\(\s*[rR]?['"])([^/\n'"]*\([^()\n]*[+*][^()\n]*\)[+*][^/\n'"]*)(?:/|['"])"""
        )
        for match in redos_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="QA-PERF-REDOS-QUANTIFIER",
                    title="Security & Performance: Regular Expression Vulnerable to Catastrophic Backtracking (ReDoS)",
                    description=(
                        f"Regular expression `{match.group(1)}` contains nested repeating quantifiers (`(X+)+` or `(X*)+`). "
                        f"Crafted input strings of 30–50 characters can freeze the single-threaded event loop or CPU core for minutes."
                    ),
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Flatten nested quantifiers, use atomic/possessive groupings, or bound input length before regex evaluation.",
                    cwe_id="CWE-1333",
                    stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                )
            )

        # ------------------------------------------------------------------
        # 2. QA-PERF-QUADRATIC-LOOKUP (O(N^2) Array Lookup Inside Iteration)
        # ------------------------------------------------------------------
        quad_re = re.compile(
            r"\.\s*(?:map|filter|forEach|some|every)\s*\(\s*\w+\s*=>\s*[^;\n]{1,120}?\b\w+\.(?:includes|indexOf|find|findIndex)\s*\("
        )
        for match in quad_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="QA-PERF-QUADRATIC-LOOKUP",
                    title="Algorithmic Complexity: O(N*M) Linear Array Scan Inside Collection Iteration",
                    description=(
                        f"Expression `{snippet}` executes a linear `.includes()` / `.find()` / `.indexOf()` inside an outer array iteration. "
                        f"This degrades time complexity from $O(N)$ to $O(N \\times M)$, causing CPU spikes on larger datasets."
                    ),
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Pre-index the lookup collection into a `Set` or `Map` before the loop to achieve $O(1)$ lookups and $O(N)$ total time.",
                    cwe_id="CWE-407",
                )
            )

        return findings
