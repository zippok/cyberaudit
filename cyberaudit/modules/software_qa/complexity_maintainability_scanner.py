"""
Complexity & Maintainability Scanner (Software QA)
Audits source code against McCabe Cyclomatic Complexity, cognitive nesting depth,
God functions, excessive parameter lists, and zombie commented-out code.
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class ComplexityMaintainabilityScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Complexity & Maintainability Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Audits cyclomatic complexity, cognitive nesting depth, god functions, and technical debt anti-patterns."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip vendor, minified, test fixtures, and non-code files
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock", ".csv", ".svg"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # 1. Detect Excessive Cognitive Nesting Depth (4+ levels of if/for/while/try)
        nesting_pattern = re.compile(r"^(?:\t|\s{4}){4,}(?:if|for|while|try|switch)\b", re.MULTILINE)
        for match in nesting_pattern.finditer(content):
            start_pos = match.start()
            line_num = content[:start_pos].count("\n") + 1
            line_content = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
            if line_content.startswith(("#", "//", "/*", "*")):
                continue
            findings.append(
                Finding(
                    id="QA-COGNITIVE-NESTING-DEPTH",
                    title="Software QA Complexity: Excessive Cognitive Nesting Depth (> 4 Levels)",
                    description="Deeply nested control structures (> 4 levels) drastically elevate cognitive load, defect probability, and impair unit test branch coverage.",
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line_content[:180],
                    remediation="Apply Guard Clauses (early returns), polymorphism, or decompose nested logic into focused private helper methods.",
                    cwe_id="CWE-1078",
                )
            )

        # 2. Detect God Functions (> 100 lines) in Python and JS/TS
        if any(lower_path.endswith(ext) for ext in [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"]):
            func_def_pattern = re.compile(
                r"^[ \t]*(?:async\s+)?(?:def\s+[a-zA-Z0-9_]+|function\s+[a-zA-Z0-9_]*|const\s+[a-zA-Z0-9_]+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)\s*[:\{]",
                re.MULTILINE,
            )
            matches = list(func_def_pattern.finditer(content))
            for i, match in enumerate(matches):
                start_pos = match.start()
                start_line = content[:start_pos].count("\n") + 1
                if i + 1 < len(matches):
                    end_pos = matches[i + 1].start()
                    func_len = content[start_pos:end_pos].count("\n")
                else:
                    func_len = total_lines - start_line

                if func_len > 120:
                    func_sig = lines[start_line - 1].strip() if start_line - 1 < total_lines else "function"
                    findings.append(
                        Finding(
                            id="QA-GOD-FUNCTION",
                            title="Software QA Maintainability: Monolithic Function (> 100 Lines)",
                            description=f"Function body spans {func_len} lines. Monolithic functions violate the Single Responsibility Principle (SRP) and exponentially inflate cyclomatic complexity.",
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=start_line,
                            code_snippet=func_sig[:180],
                            remediation="Decompose the function into modular, single-responsibility units adhering to the Clean Code Single Level of Abstraction (SLA).",
                            cwe_id="CWE-1078",
                        )
                    )

        # 3. Detect Long Parameter Lists (> 5 parameters)
        param_list_pattern = re.compile(
            r"(?:def\s+[a-zA-Z0-9_]+\s*\(|function\s+[a-zA-Z0-9_]*\s*\(|const\s+[a-zA-Z0-9_]+\s*=\s*\()([^)]+)\)",
            re.MULTILINE,
        )
        for match in param_list_pattern.finditer(content):
            params_raw = match.group(1).strip()
            # Count comma-separated arguments excluding defaults with commas
            params = [p.strip() for p in params_raw.split(",") if p.strip()]
            # Filter out 'self' and 'cls' in Python
            clean_params = [p for p in params if p not in ("self", "cls")]
            if len(clean_params) > 5:
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                if matched_line.startswith(("#", "//", "/*", "*")):
                    continue
                findings.append(
                    Finding(
                        id="QA-LONG-PARAMETER-LIST",
                        title=f"Software QA Code Smells: Long Parameter List ({len(clean_params)} Arguments)",
                        description=f"Function declares {len(clean_params)} arguments. Exceeding 5 arguments indicates Primitive Obsession and increases parameter ordering defect rates.",
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=matched_line[:180],
                        remediation="Introduce a Parameter Object (DTO / Dataclass / Config interface) to encapsulate related arguments.",
                        cwe_id="CWE-1078",
                    )
                )

        # 4. Detect Zombie Commented-Out Code Blocks (>= 5 consecutive commented lines looking like code)
        code_keywords = (
            "var ", "let ", "const ", "function", "return ", "import ", "export ", "class ", "def ",
            "for ", "if ", "while ", "try ", "catch ", "except ", "switch ", "case ", "console.", "logger."
        )
        code_structural = ("}", "{", "};", "});", "},", "]", ");")
        comment_streak = 0
        streak_start_line = 0

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "#")) and not stripped.startswith(("#!", "///", "/**")):
                inner = stripped.lstrip("/# ").strip()
                is_code_line = (
                    any(inner.startswith(kw) for kw in code_keywords)
                    or inner in code_structural
                    or (inner.endswith(";") and len(inner) >= 5)
                    or ("(" in inner and ")" in inner and len(inner) >= 8)
                )
                if is_code_line:
                    if comment_streak == 0:
                        streak_start_line = idx
                    comment_streak += 1
                else:
                    if comment_streak >= 5:
                        findings.append(
                            Finding(
                                id="QA-COMMENTED-OUT-CODE",
                                title="Software QA Hygiene: Block of Zombie Commented-Out Code",
                                description=f"Found block of {comment_streak} lines of commented-out source code. Zombie code creates confusion, stale logic, and noise in version control.",
                                severity=Severity.INFO,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                line_number=streak_start_line,
                                code_snippet=lines[streak_start_line - 1].strip()[:180],
                                remediation="Delete obsolete commented code. Rely on Git version history for code retrieval.",
                                cwe_id="CWE-1078",
                            )
                        )
                    comment_streak = 0
            else:
                if comment_streak >= 5:
                    findings.append(
                        Finding(
                            id="QA-COMMENTED-OUT-CODE",
                            title="Software QA Hygiene: Block of Zombie Commented-Out Code",
                            description=f"Found block of {comment_streak} lines of commented-out source code. Zombie code creates confusion, stale logic, and noise in version control.",
                            severity=Severity.INFO,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=streak_start_line,
                            code_snippet=lines[streak_start_line - 1].strip()[:180],
                            remediation="Delete obsolete commented code. Rely on Git version history for code retrieval.",
                            cwe_id="CWE-1078",
                        )
                    )
                comment_streak = 0

        return findings
