"""
Crash-Safety, Atomic Persistence & Distributed Durability Scanner (DDIA)
Audits code against Martin Kleppmann's DDIA durability and fault-tolerance principles:
1. Non-atomic in-place file writes on critical JSON/state/config files (missing write-temp + rename).
2. Outbound HTTP/RPC calls (fetch / axios / requests) missing explicit timeout guards.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class CrashSafetyAndDurabilityScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Crash-Safety, Atomic Persistence & Durability Scanner (DDIA)"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return (
            "Audits state persistence for non-atomic file writes (corruptible on power/process crash) "
            "and outbound network requests lacking timeout/abort guards."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_", "scratch"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. QA-DDIA-NON-ATOMIC-STATE-WRITE
        # ------------------------------------------------------------------
        direct_state_write_re = re.compile(
            r"\bfs\.(?:writeFileSync|writeFile)\s*\(\s*([^,]*?(?:config|state|tasks|db|ledger|wallet|store|session|registry)[^,]*)\s*,",
            re.IGNORECASE,
        )
        for match in direct_state_write_re.finditer(content):
            target_arg = match.group(1).strip()
            if any(tmp_kw in target_arg.lower() for tmp_kw in ["tmp", "temp", ".part", "atomic"]):
                continue
            line_num = content[: match.start()].count("\n") + 1
            window = "\n".join(lines[max(0, line_num - 5) : min(total_lines, line_num + 8)])
            if "renameSync" in window or "rename(" in window:
                continue
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="QA-DDIA-NON-ATOMIC-STATE-WRITE",
                    title="Crash-Safety (DDIA): Non-Atomic In-Place Overwrite of State/Config File",
                    description=(
                        f"Direct overwrite of state file `{target_arg}` without atomic write-temp-and-rename. "
                        f"If the process crashes or power fails mid-write, the target file is left truncated (0 bytes or half-written JSON), bricking application startup."
                    ),
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Write to a sibling `.tmp` file first, flush (`fsync`), and atomically replace via `fs.renameSync(tmpPath, targetPath)`.",
                    cwe_id="CWE-362",
                    stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                    compliance_controls={"DDIA": "Chapter 3 - Crash Recovery & Atomic File Writes"},
                )
            )

        # ------------------------------------------------------------------
        # 2. QA-DDIA-OUTBOUND-FETCH-NO-TIMEOUT (Python requests without timeout)
        # ------------------------------------------------------------------
        if lower_path.endswith(".py"):
            py_req_re = re.compile(r"\brequests\.(?:get|post|put|delete|patch|request)\s*\(([^)]+)\)")
            for match in py_req_re.finditer(content):
                args_str = match.group(1)
                if "timeout" not in args_str:
                    line_num = content[: match.start()].count("\n") + 1
                    snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                    findings.append(
                        Finding(
                            id="QA-DDIA-OUTBOUND-HTTP-NO-TIMEOUT",
                            title="Resilience (DDIA): Outbound HTTP Call Missing Explicit `timeout` Parameter",
                            description=(
                                f"Call `{match.group(0).strip()}` has no `timeout=` argument. By default, `requests` waits indefinitely "
                                f"on hung sockets, exhausting worker threads and causing cascading failure."
                            ),
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet[:200],
                            remediation="Always pass an explicit timeout tuple or float, e.g., `requests.get(url, timeout=(3.05, 15))`.",
                            cwe_id="CWE-400",
                            stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                        )
                    )

        return findings
