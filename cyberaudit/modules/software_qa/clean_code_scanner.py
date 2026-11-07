"""
Clean Code, Anti-Hardcoding & Best Practices Scanner
Audits source code for:
1. Hardcoded absolute system paths (C:\\..., /home/...) and local network endpoints (12-Factor App)
2. Leftover debugging artifacts (console.log, print(), System.out.println, var_dump)
3. Active breakpoints and debugger statements (debugger;, pdb.set_trace)
4. Abandoned technical debt markers (TODO, FIXME, HACK, XXX)
5. Complex nested ternary operators (code readability and cognitive ergonomics)
"""

import os
import re
from typing import List, Set, Tuple
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class CleanCodeBestPracticesScanner(BaseScanner):
    __test__ = False  # Prevent pytest collector from discovering this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Clean Code, Anti-Hardcoding & Best Practices Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Audits source code for hardcoded local paths and IPs (12-Factor App), leftover debugging logs (console.log, print), debugger traps, nested ternaries, and technical debt tags."

    @property
    def supported_extensions(self) -> Set[str]:
        return {
            ".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".kt",
            ".cs", ".go", ".php", ".rb", ".vue", ".html", ".cpp", ".c"
        }

    def should_scan(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.supported_extensions

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower().replace("\\", "/")

        # Skip scanning test files or build output files for certain rules
        is_test_file = any(t in lower_path for t in ["/test/", "/tests/", "test_", "_test.", ".spec.", ".test."])

        lines = content.splitlines()

        # 1. Hardcoded Local Absolute System Paths
        findings.extend(self._scan_hardcoded_paths(file_path, lines))

        # 2. Hardcoded Local Network Endpoints (localhost / private IPs)
        if not is_test_file:
            findings.extend(self._scan_hardcoded_endpoints(file_path, lines))

        # 3. Leftover Debugging Output (console.log, print, var_dump)
        if not is_test_file:
            findings.extend(self._scan_leftover_debug_logs(file_path, lines))

        # 4. Leftover Breakpoints & Debugger Traps
        findings.extend(self._scan_breakpoints(file_path, lines))

        # 5. Technical Debt Markers (TODO, FIXME, HACK)
        findings.extend(self._scan_technical_debt(file_path, lines))

        # 6. Nested Ternary Operators
        findings.extend(self._scan_nested_ternaries(file_path, lines))

        return findings

    def _scan_hardcoded_paths(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        # Windows absolute paths: e.g. "C:\Users\..." or "D:/project/..."
        win_path_re = re.compile(r'["\']([a-zA-Z]:[\\/][a-zA-Z0-9_\.\-\\/]{4,})["\']')
        # Unix absolute user/server paths: e.g. "/home/username/..." or "/var/www/..."
        unix_path_re = re.compile(r'["\'](\/(?:home|Users|var|root|tmp|opt)\/[a-zA-Z0-9_\.\-\/]{3,})["\']')

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue

            match_win = win_path_re.search(line)
            if match_win:
                matched_path = match_win.group(1)
                findings.append(Finding(
                    id="CLEAN-HARDCODED-ABSOLUTE-PATH",
                    title=f"Hardcoded Local File Path Detected ('{matched_path[:40]}...')",
                    description=f"The source code references an absolute local file system path ('{matched_path}'). Hardcoded paths break application portability across different machines, CI/CD runners, and production operating systems, violating The 12-Factor App (Factor III: Config).",
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip()[:180],
                    remediation="Use relative paths computed dynamically via path.resolve(__dirname, ...) in Node.js, pathlib.Path(__file__).parent in Python, or pass directory paths through environment variables.",
                    cwe_id="CWE-588",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"12-Factor App": "Factor III: Config", "ISO/IEC 25010": "Portability & Maintainability"},
                ))
                continue

            match_unix = unix_path_re.search(line)
            if match_unix:
                matched_path = match_unix.group(1)
                findings.append(Finding(
                    id="CLEAN-HARDCODED-ABSOLUTE-PATH",
                    title=f"Hardcoded Unix Absolute Path Detected ('{matched_path[:40]}...')",
                    description=f"The source code embeds a hardcoded Unix filesystem path ('{matched_path}'). This creates hard coupling to a specific server directory layout.",
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip()[:180],
                    remediation="Convert to dynamic relative path resolution or externalize to environment configuration.",
                    cwe_id="CWE-588",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"12-Factor App": "Factor III: Config", "ISO/IEC 25010": "Portability"},
                ))

        return findings

    def _scan_hardcoded_endpoints(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        endpoint_re = re.compile(
            r'["\']https?://(localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::(\d+))?([^"\']*)["\']',
            re.IGNORECASE
        )

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue

            match = endpoint_re.search(line)
            if match:
                host = match.group(1)
                port = match.group(2) or ""
                findings.append(Finding(
                    id="CLEAN-HARDCODED-LOCAL-ENDPOINT",
                    title=f"Hardcoded Local Network Endpoint ('{host}{f':{port}' if port else ''}')",
                    description=f"The application contains a hardcoded local URL/IP endpoint ('{match.group(0)}'). If deployed to staging or production, network requests will target the wrong host or fail completely.",
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip()[:180],
                    remediation="Externalize API base URLs into environment variables (e.g. process.env.API_BASE_URL or os.environ.get('API_URL')).",
                    cwe_id="CWE-588",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"12-Factor App": "Factor III: Config", "CIS": "Configuration Hygiene"},
                ))

        return findings

    def _scan_leftover_debug_logs(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        ext = os.path.splitext(file_path)[1].lower()

        # Debug log patterns per language
        debug_patterns: List[Tuple[re.Pattern, str, str]] = []
        if ext in {".js", ".ts", ".jsx", ".tsx", ".vue"}:
            debug_patterns.append((re.compile(r'\bconsole\.(log|debug|dir|trace)\s*\('), "JavaScript/TypeScript console.log/debug", "console.log"))
        elif ext == ".py":
            # Avoid matching logger.print or print as part of word
            debug_patterns.append((re.compile(r'(?<![a-zA-Z0-9_\.])print\s*\('), "Python built-in print() statement", "print()"))
        elif ext in {".java", ".kt"}:
            debug_patterns.append((re.compile(r'\bSystem\.(out|err)\.println\s*\('), "Java/Kotlin System.out.println", "System.out.println"))
        elif ext == ".php":
            debug_patterns.append((re.compile(r'\b(var_dump|print_r|dd)\s*\('), "PHP var_dump/print_r/dd debug function", "var_dump"))
        elif ext == ".go":
            debug_patterns.append((re.compile(r'\bfmt\.(Println|Printf|Print)\s*\('), "Go fmt.Print leftover debug call", "fmt.Println"))

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*"):
                continue

            for pattern, desc, tag in debug_patterns:
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"CLEAN-LEFTOVER-DEBUG-LOG-{tag.upper().replace('()', '').replace('.', '-')}",
                        title=f"Leftover Debugging Statement in Production Code ({desc})",
                        description=f"A raw debugging output statement ('{tag}') was detected. Residual debug logs degrade throughput under high concurrency, pollute system log collectors, and frequently leak sensitive user state or tokens to browser developer consoles.",
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip()[:180],
                        remediation="Remove raw debug logging or route messages through a structured, leveled production logging framework (e.g. winston/pino in Node, logging in Python, slf4j/logback in Java) configured for INFO/WARN in release builds.",
                        cwe_id="CWE-1078",
                        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                        compliance_controls={"Clean Code": "Logging Hygiene", "ISO/IEC 25010": "Efficiency"},
                    ))
                    break  # One debug log finding per line

        return findings

    def _scan_breakpoints(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        breakpoint_patterns = [
            (re.compile(r'\bdebugger\s*;'), "JavaScript debugger statement", "debugger"),
            (re.compile(r'\b(pdb\.set_trace|breakpoint)\s*\('), "Python debugger breakpoint", "pdb/breakpoint"),
            (re.compile(r'\bbinding\.pry\b'), "Ruby binding.pry breakpoint", "binding.pry"),
        ]

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue

            for pattern, desc, tag in breakpoint_patterns:
                if pattern.search(line):
                    findings.append(Finding(
                        id="CLEAN-ACTIVE-BREAKPOINT",
                        title=f"Active Debugger Breakpoint Left in Source Code ({desc})",
                        description=f"The code contains an active breakpoint directive ('{tag}'). If encountered during execution in an environment with devtools or a debugger attached, the runtime freezes indefinitely.",
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip()[:180],
                        remediation="Remove all breakpoint statements prior to committing code or staging builds.",
                        cwe_id="CWE-489",
                        stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                        compliance_controls={"Clean Code": "Debugging Traps", "OWASP": "Omission of Debugging Code"},
                    ))

        return findings

    def _scan_technical_debt(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        # Must match genuine uppercase debt markers (TODO, FIXME, etc.) and NOT the Spanish word "todo/todos"
        debt_re = re.compile(r'(?://|#|/\*|--)\s*(TODO|FIXME|HACK|XXX|TEMP|OPTIMIZE)\b\s*[:\-]?(.*)')

        for idx, line in enumerate(lines, 1):
            match = debt_re.search(line)
            if match:
                tag = match.group(1).upper()
                comment_text = match.group(2).strip()[:100]
                findings.append(Finding(
                    id=f"CLEAN-TECH-DEBT-{tag}",
                    title=f"Technical Debt Marker: {tag} ({comment_text or 'Unspecified task'})",
                    description=f"A technical debt comment marker ('{tag}: {comment_text}') was discovered. Accumulation of unresolved TODO and FIXME comments signals unfinished functionality, temporary workarounds, and lack of systematic backlog tracking under SQALE standards.",
                    severity=Severity.INFO,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip()[:180],
                    remediation="Resolve the underlying issue or create a formal ticket in the issue tracking system (Jira/GitHub Issues) and remove the in-code marker.",
                    cwe_id="CWE-546",
                    stride_category=StrideCategory.REPUDIATION.value,
                    compliance_controls={"SQALE": "Technical Debt Index", "ISO/IEC 25010": "Maintainability"},
                ))

        return findings

    def _scan_nested_ternaries(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        nested_ternary_re = re.compile(r'\?[^:?\n]+\?[^:?\n]+:')

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue

            if nested_ternary_re.search(line):
                findings.append(Finding(
                    id="CLEAN-NESTED-TERNARY",
                    title="Deeply Nested Ternary Operator (Cognitive Complexity Anti-Pattern)",
                    description="The code contains multiple nested ternary operators ('? :') on the same statement. Nested ternaries severely impair readability, impede code review comprehension, and are a notorious source of off-by-one logic errors.",
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip()[:180],
                    remediation="Refactor nested ternaries into clear 'if-else' statements, guard clauses, or a lookup dictionary/map.",
                    cwe_id="CWE-1078",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"Clean Code": "Cognitive Ergonomics", "SonarQube": "Nested Ternary Rule"},
                ))

        return findings
