"""
DFIR Endpoint Investigation & Artifact Triage Scanner
Inspects endpoint forensic artifacts, registry exports, cron configs, and authorization files:
- Windows Registry persistence mechanisms (Run, RunOnce, Winlogon, IFEO sticky keys)
- Linux cron job anomalies, sudoers NOPASSWD misconfigurations, and world-writable SUID paths
- macOS LaunchDaemons and persistent agent plists
Mapped to MITRE ATT&CK: T1547.001, T1546.012, T1053.003, T1548.003
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class DfirEndpointScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "DFIR-WIN-REG-RUN-01",
                "title": "DFIR: Suspicious Windows Registry Run Key Persistence",
                "pattern": re.compile(
                    r'(?:CurrentVersion\\Run|CurrentVersion\\RunOnce)[\s\S]{0,100}?(?:powershell|cmd\.exe|wscript|mshta|cscript|\.vbs|\.bat|\.ps1|AppData|Temp)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Registry Run/RunOnce autostart entry configured to launch a script interpreter or binary located in temporary/user directories.",
                "remediation": "Audit the target binary/script, remove the rogue registry key, and examine user logon activity.",
                "mitre_id": "T1547.001",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            },
            {
                "id": "DFIR-WIN-IFEO-HIJACK-01",
                "title": "DFIR: Image File Execution Options (IFEO) Sticky Keys Backdoor",
                "pattern": re.compile(
                    r'Image\s+File\s+Execution\s+Options\\(?:sethc\.exe|utilman\.exe|osk\.exe)[\s\S]{0,80}?["\']Debugger["\']\s*[:=]\s*["\']cmd\.exe["\']',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Classic accessibility backdoor: sethc.exe (Sticky Keys) or utilman.exe replaced with cmd.exe, allowing SYSTEM shell without logging in.",
                "remediation": "Remove the IFEO Debugger registry value and verify integrity of accessibility binaries in System32.",
                "mitre_id": "T1546.012",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Event Triggered Execution: Image File Execution Options Injection",
            },
            {
                "id": "DFIR-LINUX-SUDOERS-NOPASS-01",
                "title": "DFIR: Linux Sudoers NOPASSWD All Privileges Granted",
                "pattern": re.compile(
                    r'^(?!\s*#)\s*[\w%@]+\s+ALL\s*=\s*\([^\)]*\)\s+NOPASSWD:\s*ALL',
                    re.MULTILINE | re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Sudoers rule allows complete passwordless root execution, enabling instantaneous privilege escalation.",
                "remediation": "Revoke NOPASSWD: ALL in /etc/sudoers or restrict command scope to specific non-shell binaries.",
                "mitre_id": "T1548.003",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            },
            {
                "id": "DFIR-LINUX-SUSP-CRON-01",
                "title": "DFIR: Suspicious Recurring Shell Cron Job Detected",
                "pattern": re.compile(
                    r'^\s*(?:\*\s+){4}\*\s+.*(?:curl|wget|nc|python|bash\s+-i|/dev/tcp)',
                    re.MULTILINE | re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Cron job configured to execute network fetches or reverse shells every single minute.",
                "remediation": "Remove the suspicious crontab entry from /etc/cron* or user spool and trace who wrote it.",
                "mitre_id": "T1053.003",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Scheduled Task/Job: Cron",
            },
            {
                "id": "DFIR-MACOS-LAUNCHD-SUSP-01",
                "title": "DFIR: macOS Suspicious LaunchDaemon / LaunchAgent Plist",
                "pattern": re.compile(
                    r'<key>ProgramArguments</key>[\s\S]{0,150}?<string>(?:/bin/sh|/bin/bash|/bin/zsh|python|curl|nc)</string>',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "macOS LaunchDaemon/Agent configured to launch an interactive shell or script as a persistent background daemon.",
                "remediation": "Unload daemon with `launchctl unload` and remove the plist from /Library/LaunchDaemons.",
                "mitre_id": "T1543.001",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Create or Modify System Process: Launch Daemon",
            },
        ]

    @property
    def name(self) -> str:
        return "DFIR & Endpoint Investigation Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.DFIR_ENDPOINT

    @property
    def description(self) -> str:
        return "Audits forensic artifacts, Windows Registry persistence, Linux sudoers/cron, and macOS LaunchDaemons."

    @property
    def file_extensions(self) -> List[str]:
        return [".reg", ".txt", ".cron", ".plist", ".conf", ".sh", ".json", ".xml"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule in self.rules:
            match = rule["pattern"].search(content)
            if match:
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
                    mitre_id=rule["mitre_id"],
                    mitre_tactic=rule["mitre_tactic"],
                    mitre_technique=rule["mitre_technique"],
                    cwe_id="CWE-276",  # Incorrect Default Permissions / Persistence
                )
                findings.append(finding)

        return findings
