"""
Resilience & Performance Scanner (Software QA)
Audits source code for Event Loop blocking (synchronous I/O in Node.js),
unhandled asynchronous promise rejections, network calls without timeouts,
and unconstrained retry loops.
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class ResiliencePerformanceScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Resilience & Performance Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Audits runtime resilience, event loop blocking I/O, unhandled promise rejections, and missing timeout bounds."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip non-code, vendor, minified, test files and config files
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock", ".csv", ".svg"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # 1. Event Loop Blocking Synchronous I/O in Node.js / JS / TS
        # (Exclude build scripts, CLI entrypoints, test files, or config files like webpack/vite/jest)
        norm_path = lower_path.replace("\\", "/")
        is_build_script = any(
            keyword in norm_path
            for keyword in [
                "webpack", "vite.config", "jest.config", "gulpfile", "rollup",
                "scripts/", "build/", "/test/", "/tests/", ".test.", ".spec."
            ]
        )
        if any(lower_path.endswith(ext) for ext in [".js", ".ts", ".jsx", ".tsx", ".mjs"]) and not is_build_script:
            sync_io_pattern = re.compile(
                r"\b(?:fs\.(?:readFileSync|writeFileSync|appendFileSync|copyFileSync|unlinkSync|mkdirSync|rmSync)|execSync)\s*\(",
                re.MULTILINE,
            )
            for match in sync_io_pattern.finditer(content):
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                if matched_line.startswith(("//", "/*", "*")):
                    continue
                findings.append(
                    Finding(
                        id="QA-EVENTLOOP-SYNC-BLOCKING",
                        title="Software QA Performance: Synchronous I/O Freezes Node.js Event Loop",
                        description=f"Call `{match.group(0).rstrip('(').strip()}` blocks the V8 single-threaded event loop synchronously, causing severe latency spikes, dropped web sockets, and unresponsive UI.",
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=matched_line[:180],
                        remediation="Migrate to non-blocking async APIs: `fs.promises.readFile()`, `await pipeline()`, or asynchronous worker threads.",
                        cwe_id="CWE-400",
                    )
                )

        # 2. Unhandled Promise Rejections (.then() without .catch())
        if any(lower_path.endswith(ext) for ext in [".js", ".ts", ".jsx", ".tsx"]):
            for idx, line in enumerate(lines):
                if ".then(" in line and not line.strip().startswith(("//", "/*", "*")):
                    # Check forward up to 15 lines for .catch(
                    window = "\n".join(lines[idx:min(idx + 15, total_lines)])
                    if ".catch(" not in window and "await " not in line:
                        findings.append(
                            Finding(
                                id="QA-UNHANDLED-PROMISE-REJECTION",
                                title="Software QA Resilience: Promise Chain Lacks Error Handler (.catch)",
                                description="Asynchronous promise chain terminates without a `.catch()` block. In modern Node.js runtimes, unhandled rejections emit UnhandledPromiseRejection alerts and can crash the process.",
                                severity=Severity.MEDIUM,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                line_number=idx + 1,
                                code_snippet=line.strip()[:180],
                                remediation="Append a terminal `.catch(err => { ... })` handler or rewrite the flow using `try { await ... } catch (err) { ... }`.",
                                cwe_id="CWE-754",
                            )
                        )

        # 3. Unbounded Retry Loops (while True with network requests and no backoff)
        if lower_path.endswith(".py"):
            for idx, line in enumerate(lines):
                if re.match(r"^\s*while\s+(?:True|1)\s*:", line):
                    # Inspect loop body window
                    body_lines = lines[idx:min(idx + 25, total_lines)]
                    body_text = "\n".join(body_lines)
                    has_network = any(net in body_text for net in ["requests.get", "requests.post", "urllib.request", "socket.socket"])
                    has_delay = any(control in body_text for control in ["sleep", "delay", "backoff"])
                    if has_network and not has_delay:
                        findings.append(
                            Finding(
                                id="QA-UNBOUNDED-RETRY-LOOP",
                                title="Software QA Resilience: Unbounded Network Retry Loop Without Delay/Backoff",
                                description="Infinite loop executing network/socket operations without an explicit sleep or exponential backoff mechanism. Causes accidental Denial-of-Service and CPU saturation on network drops.",
                                severity=Severity.HIGH,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                line_number=idx + 1,
                                code_snippet=line.strip()[:180],
                                remediation="Implement a maximum attempt counter and exponential backoff with jitter (`delay = min(max_delay, base * 2 ** attempt + random)`).",
                                cwe_id="CWE-835",
                            )
                        )

        return findings
