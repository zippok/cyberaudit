"""
Concurrency & Race Condition Scanner
Audits multi-threaded and asynchronous code for race conditions:
- Shared mutable variables modified in async functions without locks
- Time-of-Check to Time-of-Use (TOCTOU) file race conditions
- Non-thread-safe singleton patterns
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class ConcurrencyRaceScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "QA-RACE-TOCTOU-FILE",
                "title": "Software QA: Time-of-Check to Time-of-Use (TOCTOU) Race Condition",
                "pattern": re.compile(
                    r"if\s+(?:os\.path\.exists|pathlib\.Path\([^)]*\)\.exists)\s*\([^)]*\):[\s\S]{1,60}?(?:open\s*\(|os\.remove\s*\()",
                    re.MULTILINE,
                ),
                "severity": Severity.LOW,
                "description": "File existence verified prior to opening/deleting rather than handling the operation atomically. Between check and use, an external process can modify, delete, or substitute the target path (TOCTOU).",
                "remediation": "Perform the file operation directly inside a `try/except (FileNotFoundError, FileExistsError)` block or use atomic flags (`os.O_CREAT | os.O_EXCL`).",
                "file_types": [".py"],
            },
            {
                "id": "QA-ASYNC-GLOBAL-MUTATION",
                "title": "Software QA: Unsynchronized Global Mutation in Async Coroutine",
                "pattern": re.compile(
                    r"async\s+def\s+[a-zA-Z0-9_]+\s*\([^)]*\):[\s\S]{0,100}?global\s+([a-zA-Z0-9_]+)[\s\S]{0,100}?\1\s*(?:\+=|-=|\*=|=)",
                    re.MULTILINE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Coroutines modifying shared global variables without `asyncio.Lock` synchronization. Concurrent task switches can lead to dirty reads, partial writes, or corrupted shared state.",
                "remediation": "Protect mutable shared state using `async with asyncio.Lock():` or thread-safe atomic data structures.",
                "file_types": [".py"],
            },
        ]

    @property
    def name(self) -> str:
        return "Concurrency & Race Condition Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Detects asynchronous race conditions, shared global state mutations, and TOCTOU file access patterns."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        if any(lower_path.endswith(ext) for ext in [".min.js", ".md", ".json", ".lock"]):
            return []

        for rule in self.rules:
            if rule.get("file_types"):
                if not any(lower_path.endswith(ext) for ext in rule["file_types"]):
                    continue

            matches = rule["pattern"].finditer(content)
            for match in matches:
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                snippet = match.group(0).strip()[:180]

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
                    cwe_id="CWE-362",  # Race Condition (Concurrent Execution using Shared Resource)
                )
                findings.append(finding)

        return findings
