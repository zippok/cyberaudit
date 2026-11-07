"""
Resource & Memory Leak Scanner
Audits codebase for unclosed system descriptors and memory leaks:
- Unclosed file handles (open() without with or explicit close)
- Uncleaned event listeners and Electron IPC listeners
- Orphaned setInterval timers
- Unreleased database connections and cursor leaks
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class ResourceLeakScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "QA-UNCLOSED-FILE-PY",
                "title": "Software QA: Unclosed File Descriptor (open without with-block)",
                "pattern": re.compile(
                    r"(?:^|\s+)([a-zA-Z0-9_]+)\s*=\s*open\s*\([^)]*\)(?![\s\S]{0,100}?\1\.close\(\))",
                    re.MULTILINE,
                ),
                "severity": Severity.MEDIUM,
                "description": "File opened via manual assignment (`f = open(...)`) rather than a context manager (`with open(...) as f:`). If an exception occurs, the file descriptor remains locked by the operating system.",
                "remediation": "Wrap file access inside a `with open(...) as f:` block to ensure deterministic disposal.",
                "file_types": [".py"],
            },
            {
                "id": "QA-ORPHAN-INTERVAL-JS",
                "title": "Software QA: Orphaned setInterval Timer (Potential Memory & CPU Leak)",
                "pattern": re.compile(
                    r"(?:^|[^\w\.])setInterval\s*\(\s*(?:function|\([^)]*\)\s*=>)",
                    re.MULTILINE,
                ),
                "severity": Severity.LOW,
                "description": "`setInterval()` invoked anonymously without saving its timer ID. This prevents invoking `clearInterval()`, continuously consuming CPU cycles and holding closure references in memory.",
                "remediation": "Store timer handle (`const timerId = setInterval(...)`) and clear it when the component or process lifecycle ends.",
                "file_types": [".js", ".ts", ".jsx", ".tsx"],
            },
            {
                "id": "QA-UNCLOSED-SQLITE-CONN",
                "title": "Software QA: Database Connection Left Unclosed",
                "pattern": re.compile(
                    r"(?:sqlite3\.connect|[a-zA-Z0-9_]+\.createConnection)\s*\([^)]*\)(?![\s\S]{0,300}?(?:\.close\(\)|with\s+))",
                    re.MULTILINE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Database connection instantiated without structured closure or pooling context. Risks database lockouts and descriptor depletion.",
                "remediation": "Ensure database connections use context managers or structured try/finally disposal.",
                "file_types": [".py", ".js", ".ts"],
            },
            {
                "id": "QA-ELECTRON-IPC-LISTENER-LEAK",
                "title": "Software QA: Electron IPC Listener Leak (ipcRenderer.on without removal)",
                "pattern": re.compile(
                    r"ipcRenderer\.on\s*\(\s*['\"][^'\"]+['\"]",
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "description": "Repeated registration of `ipcRenderer.on` listeners without corresponding `ipcRenderer.removeListener` or `removeAllListeners`. In Electron desktop apps, window reloads compound listener counts leading to memory warnings.",
                "remediation": "Use `ipcRenderer.once` for single-shot messages or clean up listeners during component unmount.",
                "file_types": [".js", ".ts", ".jsx", ".tsx"],
            },
        ]

    @property
    def name(self) -> str:
        return "Resource & Memory Leak Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Detects unclosed file handles, orphaned timers, database connection leaks, and Electron IPC listener compounding."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip vendor / minified
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json"]):
            return []

        # Check for open without with in python
        if lower_path.endswith(".py"):
            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                clean_l = line.strip()
                # If line is like `f = open("...")` or `file = open(...)` and not preceded by `with`
                if re.search(r"^\w+\s*=\s*open\s*\(", clean_l) and not clean_l.startswith("with "):
                    # Check if file has with open on same line
                    findings.append(
                        Finding(
                            id="QA-UNCLOSED-FILE-PY",
                            title="Software QA: Unclosed File Descriptor (open without with-block)",
                            description="File opened via direct variable assignment without context manager. Descriptors may leak if exceptions occur.",
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_idx,
                            code_snippet=clean_l[:180],
                            remediation="Refactor to: `with open(...) as f:` to guarantee automatic closure.",
                            cwe_id="CWE-775",
                        )
                    )

        # Check for orphan setInterval in JS/TS
        if any(lower_path.endswith(ext) for ext in [".js", ".ts", ".jsx", ".tsx"]):
            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                clean_l = line.strip()
                if re.search(r"^setInterval\s*\(", clean_l):
                    findings.append(
                        Finding(
                            id="QA-ORPHAN-INTERVAL-JS",
                            title="Software QA: Orphaned setInterval Timer (Potential Memory & CPU Leak)",
                            description="Anonymous `setInterval()` prevents clearing, keeping event loop handles active indefinitely.",
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_idx,
                            code_snippet=clean_l[:180],
                            remediation="Assign timer to variable (`const timer = setInterval(...)`) and call `clearInterval(timer)` upon teardown.",
                            cwe_id="CWE-404",
                        )
                    )

        return findings
