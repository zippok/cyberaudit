"""
LOLBAS & GTFOBins Detection Engine
Detects abuse of native living-off-the-land binaries on Windows (LOLBAS)
and Unix/Linux (GTFOBins) commonly leveraged by adversaries for proxy execution,
file transfer, and defense evasion without dropping new tools.
Mapped to MITRE ATT&CK: T1218, T1105, T1059.004
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class LolbasDetector(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "LOLBAS-CERTUTIL-DOWNLOAD-01",
                "title": "LOLBAS: CertUtil Download Cradle Detected",
                "pattern": re.compile(
                    r"certutil(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*(?:-urlcache\s+-[fF]|-split\s+-[fF])\s+https?://",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "CertUtil.exe invoked with -urlcache / -split flags to download remote files from the internet, bypassing browser security controls.",
                "remediation": "Block CertUtil network outbound connections using Windows Defender Application Control (WDAC) or AppLocker.",
                "mitre_id": "T1105",
                "mitre_tactic": "Command and Control",
                "mitre_technique": "Ingress Tool Transfer",
            },
            {
                "id": "LOLBAS-MSHTA-EXEC-01",
                "title": "LOLBAS: Mshta Script Proxy Execution Detected",
                "pattern": re.compile(
                    r"mshta(?:\.exe)?\s+(?:javascript:|vbscript:|https?://.*(?:\.hta|\.html|\.txt))",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Mshta.exe used to execute inline scripts or fetch remote HTA payloads directly into memory.",
                "remediation": "Disable or restrict mshta.exe execution policies. Block MSHTA from making outbound internet connections.",
                "mitre_id": "T1218.005",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "System Binary Proxy Execution: Mshta",
            },
            {
                "id": "LOLBAS-REGSVR32-SQUIBLYDOO-01",
                "title": "LOLBAS: Regsvr32 Scriptlet Remote Execution (Squiblydoo)",
                "pattern": re.compile(
                    r"regsvr32(?:\.exe)?\s+(?:/[a-zA-Z]+\s+)*(?:/i:https?://|/i:ftp://).*scrobj\.dll",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Regsvr32 invoking scrobj.dll to download and execute remote COM scriptlets (Squiblydoo technique).",
                "remediation": "Enforce WDAC application whitelisting and block regsvr32 outbound network connections at host firewall.",
                "mitre_id": "T1218.010",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "System Binary Proxy Execution: Regsvr32",
            },
            {
                "id": "LOLBAS-BITSADMIN-TRANSFER-01",
                "title": "LOLBAS: BITSAdmin Asynchronous Job Download",
                "pattern": re.compile(
                    r"bitsadmin(?:\.exe)?\s+/transfer\s+\w+\s+(?:/download\s+)?https?://",
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "BITSAdmin utilized to schedule background file downloads using Windows Background Intelligent Transfer Service.",
                "remediation": "Monitor BITS job creation (Event ID 16403/16404) and restrict access to bitsadmin CLI.",
                "mitre_id": "T1197",
                "mitre_tactic": "Persistence",
                "mitre_technique": "BITS Jobs",
            },
            {
                "id": "GTFOBINS-LINUX-REVSHELL-01",
                "title": "GTFOBins: Linux Interactive Reverse Shell One-Liner Detected",
                "pattern": re.compile(
                    r'(?:bash\s+-i\s+>&?\s*/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+\s+0>&1|nc(?:\.traditional)?\s+(?:-e\s+/bin/(?:ba)?sh|-c\s+/bin/sh)|python(?:\d+)?\s+-c\s+["\'].*import\s+socket,subprocess,os.*connect\s*\()',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Standard interactive reverse shell one-liner executing a remote shell back to an attacker listener.",
                "remediation": "Identify the process or script spawning the connection, kill the PID, and inspect root cause entry vector.",
                "mitre_id": "T1059.004",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter: Unix Shell",
            },
            {
                "id": "GTFOBINS-CURL-PIPE-BASH-01",
                "title": "GTFOBins: Unverified Curl / Wget Piped Directly to Shell",
                "pattern": re.compile(
                    r"(?:curl\s+(?:-[a-zA-Z]+\s+)*https?://\S+|wget\s+(?:-[a-zA-Z]+\s+)*https?://\S+\s+-O-)\s*\|\s*(?:ba)?sh",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Downloading unverified remote scripts and immediately executing them via pipe to bash without integrity hash verification.",
                "remediation": "Download scripts to disk first, verify cryptographic SHA256 checksum, and inspect before execution.",
                "mitre_id": "T1105",
                "mitre_tactic": "Command and Control",
                "mitre_technique": "Ingress Tool Transfer",
            },
        ]

    @property
    def name(self) -> str:
        return "LOLBAS & GTFOBins Detector"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ANALYST

    @property
    def description(self) -> str:
        return "Detects abuse of native Windows binaries (LOLBAS) and Linux utilities (GTFOBins) for proxy execution and file transfer."

    @property
    def file_extensions(self) -> List[str]:
        return [".bat", ".cmd", ".ps1", ".sh", ".py", ".bash", ".yml", ".yaml", ".txt", "Dockerfile"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["pattern"].search(line):
                    finding = Finding(
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
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        cwe_id="CWE-78",
                    )
                    findings.append(finding)
                    break

        return findings
