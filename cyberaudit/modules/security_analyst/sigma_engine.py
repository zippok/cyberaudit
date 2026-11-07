"""
Sigma Detection Engineering & Telemetry Scanner
Implements standardized Sigma-compatible detection rules to analyze:
- Windows Sysmon / Event Log exports (Process Creation, Network, Driver)
- Web Server Access Logs (Apache, Nginx, IIS)
- Linux Auth Logs (SSH brute force, Sudo abuse)
Mapped to MITRE ATT&CK: T1003.001, T1490, T1190, T1110, T1059
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class SigmaEngine(BaseScanner):
    def __init__(self):
        super().__init__()
        # Collection of Sigma-derived detection rules
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "SIGMA-WIN-MIMIKATZ-01",
                "title": "Sigma: Mimikatz Credential Dumping Command Detected",
                "pattern": re.compile(
                    r"(?:sekurlsa::logonpasswords|lsadump::sam|lsadump::lsa|lsadump::dcsync|kerberos::golden|privilege::debug)",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Observed execution arguments specifically indicating Mimikatz or derived credential dumping tools.",
                "remediation": "Isolate the host immediately. Reset domain admin credentials and initiate an active intrusion investigation.",
                "mitre_id": "T1003.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "OS Credential Dumping: LSASS Memory",
            },
            {
                "id": "SIGMA-WIN-RANSOM-VSS-01",
                "title": "Sigma: Volume Shadow Copies Deletion (Ransomware Preparation)",
                "pattern": re.compile(
                    r"(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+catalog|bcdedit(?:\.exe)?\s+/set.*recoveryenabled\s+no)",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Command-line attempt to delete shadow copies or disable recovery, a hallmark behavior of ransomware deployment.",
                "remediation": "Immediately sever network connection of the host to prevent lateral ransomware spread. Review EDR telemetry.",
                "mitre_id": "T1490",
                "mitre_tactic": "Impact",
                "mitre_technique": "Inhibit System Recovery",
            },
            {
                "id": "SIGMA-WIN-LSASS-DUMP-01",
                "title": "Sigma: LSASS Memory Dumping via ProcDump / Rundll32",
                "pattern": re.compile(
                    r"(?:procdump(?:\.exe)?\s+.*-ma\s+lsass\.exe|comsvcs\.dll.*MiniDump.*lsass)",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Process memory dump of lsass.exe using native or legitimate sysinternals utilities.",
                "remediation": "Enable LSA Protection (RunAsPPL) and Credential Guard. Restrict debug privileges on endpoints.",
                "mitre_id": "T1003.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "OS Credential Dumping: LSASS Memory",
            },
            {
                "id": "SIGMA-WEB-SQLI-PROBE-01",
                "title": "Sigma: SQL Injection Probe in Web Access Log",
                "pattern": re.compile(
                    r"(?:UNION(?:\+ALL|\s+ALL)?[\+\s]+SELECT|OR(?:\+|\%20|\s)+1=1|WAITFOR[\+\s]+DELAY|SLEEP\(\d+\)|benchmark\(\d+,|INFORMATION_SCHEMA\.TABLES)",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "HTTP request containing SQL injection attack vectors targeting database queries via web endpoints.",
                "remediation": "Implement parameterized queries (Prepared Statements) in backend code and deploy WAF filtering rules.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
            },
            {
                "id": "SIGMA-WEB-LFI-01",
                "title": "Sigma: Directory Traversal / LFI Probe in Web Access Log",
                "pattern": re.compile(
                    r"(?:\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e/)(?:etc/passwd|windows/win\.ini|boot\.ini)",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Directory traversal payload attempting to read sensitive system configuration files.",
                "remediation": "Sanitize and whitelist file path inputs. Enforce strict filesystem chroot/jail on web server processes.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
            },
            {
                "id": "SIGMA-WEB-LOG4SHELL-01",
                "title": "Sigma: Log4Shell JNDI Lookup Attempt",
                "pattern": re.compile(
                    r"\$\{(?:\$\{lower:j\}|\$\{upper:j\}|j)ndi:(?:ldap|rmi|dns|nis|iiop):",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Log4j JNDI remote code execution exploit attempt (CVE-2021-44228).",
                "remediation": "Ensure log4j is upgraded to 2.17.1+ or set -Dlog4j2.formatMsgNoLookups=true in JVM flags.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cve_id": "CVE-2021-44228",
            },
            {
                "id": "SIGMA-LINUX-SSH-BRUTE-01",
                "title": "Sigma: SSH Brute Force / Dictionary Attack Signatures",
                "pattern": re.compile(
                    r"(?:Failed password for (?:invalid user\s+)?\w+\s+from\s+\d+\.\d+\.\d+\.\d+|authentication failure.*rhost=\d+\.\d+\.\d+\.\d+)",
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Repeated authentication failures indicating automated credential stuffing or SSH brute forcing.",
                "remediation": "Deploy Fail2ban or CrowdSec, disable password authentication for SSH and enforce public key / MFA access.",
                "mitre_id": "T1110.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Brute Force: Password Guessing",
            },
        ]

    @property
    def name(self) -> str:
        return "Sigma Detection Engineering Engine"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ANALYST

    @property
    def description(self) -> str:
        return "Evaluates event logs, Sysmon exports, and web telemetry using standardized Sigma detection rules."

    @property
    def file_extensions(self) -> List[str]:
        return [".log", ".txt", ".json", ".csv", ".syslog", ".evtx_dump"]

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
                        code_snippet=line.strip()[:200],
                        remediation=rule["remediation"],
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        cwe_id="CWE-778",  # Insufficient Logging / Detected Attack Log
                        cve_id=rule.get("cve_id"),
                    )
                    findings.append(finding)
                    # Once matched on a line for a rule, continue to next rule
                    break

        return findings
