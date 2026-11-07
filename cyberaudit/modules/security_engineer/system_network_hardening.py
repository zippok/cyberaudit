"""
System & Network Hardening Scanner (Security Engineer Pillar)
Audits operating system, service configs, and application networking:
- Insecure SSH daemon configuration (PermitRootLogin, PermitEmptyPasswords)
- Plaintext/unencrypted network protocols (Telnet, FTP, unencrypted LDAP, SNMP defaults)
- TLS certificate validation bypass and legacy protocol downgrades
- Overly permissive file system permissions (chmod 777)
Mapped to MITRE ATT&CK: T1040, T1562.001, T1078
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class SystemNetworkHardeningScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "HARDENING-SSH-ROOT-LOGIN-01",
                "title": "SSH Hardening: Root Login or Empty Passwords Permitted",
                "pattern": re.compile(
                    r'^\s*(?:PermitRootLogin\s+yes|PermitEmptyPasswords\s+yes|PasswordAuthentication\s+yes\s*(?:#.*public|#.*bastion)?)\b',
                    re.IGNORECASE | re.MULTILINE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "CIS_BENCHMARK": "5.2.10",
                    "PCI_DSS": "Req 2.2",
                    "ISO_27001": "A.9.4.2",
                },
                "description": "SSH daemon configuration permits direct root login or empty password authentication, violating least privilege and exposing bastion nodes to credential attacks.",
                "remediation": "Set `PermitRootLogin no` and `PermitEmptyPasswords no` in `/etc/ssh/sshd_config`. Enforce SSH key-based authentication exclusively.",
                "mitre_id": "T1078",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Valid Accounts",
                "cwe_id": "CWE-250",
            },
            {
                "id": "HARDENING-CLEARTEXT-PROTOCOLS-01",
                "title": "Network Security: Insecure Plaintext Protocol in Use (Telnet / FTP / Plain LDAP)",
                "pattern": re.compile(
                    r'(?:telnet://|ftp://|ldap://(?!.*389/.*starttls)|snmp\.CommunityData\s*\(\s*["\'](?:public|private)["\']|COMMUNITY\s*=\s*["\']public["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "PCI_DSS": "Req 4.1",
                    "ISO_27001": "A.13.1.1",
                    "HIPAA": "164.312(e)(1)",
                },
                "description": "Application or configuration uses legacy plaintext network protocols (Telnet, FTP, plain LDAP, or default SNMP community strings), transmitting credentials in cleartext.",
                "remediation": "Replace plaintext protocols with encrypted equivalents: SSH/SFTP instead of Telnet/FTP, LDAPS (port 636) instead of plain LDAP, and SNMPv3 with authPriv.",
                "mitre_id": "T1040",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Network Sniffing",
                "cwe_id": "CWE-319",
            },
            {
                "id": "HARDENING-TLS-BYPASS-01",
                "title": "TLS Security: Certificate Verification Disabled or Deprecated Protocol",
                "pattern": re.compile(
                    r'(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0["\']?|ssl\.PROTOCOL_TLSv1\b|ssl\.PROTOCOL_SSLv23\b|check_hostname\s*=\s*False|curl\s+-[a-zA-Z]*k[a-zA-Z]*\b)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "PCI_DSS": "Req 4.1",
                    "ISO_27001": "A.10.1.1",
                    "SOC2": "CC6.6",
                },
                "description": "TLS/SSL certificate validation is explicitly disabled (e.g. `verify=False` or `curl -k`), or deprecated protocols (SSLv3/TLSv1.0) are utilized, exposing traffic to Man-in-the-Middle (MitM) attacks.",
                "remediation": "Enable strict TLS certificate validation (`verify=True`) and enforce modern TLS 1.2+ cipher suites.",
                "mitre_id": "T1562.001",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Impair Defenses: Disable or Modify Tools",
                "cwe_id": "CWE-295",
            },
            {
                "id": "HARDENING-FILE-PERMISSIONS-01",
                "title": "System Hardening: Overly Permissive File Permissions (chmod 777)",
                "pattern": re.compile(
                    r'(?:chmod\s+(?:-R\s+)?(?:777|0777)|os\.chmod\s*\([\s\S]{0,50}?(?:0o777|0777|stat\.S_IRWXO))',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "CIS_BENCHMARK": "6.1.10",
                    "PCI_DSS": "Req 7.1",
                    "ISO_27001": "A.9.2.3",
                },
                "description": "Files or directories assigned world-writable permissions (777), allowing unprivileged local users or processes to modify sensitive application files.",
                "remediation": "Restrict permissions using principle of least privilege: 640 or 600 for sensitive files, 750 or 700 for directories.",
                "mitre_id": "T1222",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "File and Directory Permissions Modification",
                "cwe_id": "CWE-732",
            },
        ]

    @property
    def name(self) -> str:
        return "System & Network Hardening Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Audits SSH configurations, plaintext protocols (Telnet/FTP), TLS certificate bypasses, and file permissions."

    @property
    def file_extensions(self) -> List[str]:
        return [".conf", ".cfg", ".ini", ".sh", ".bash", ".py", ".js", ".ts", ".yml", ".yaml", "sshd_config"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["pattern"].search(line):
                    findings.append(
                        Finding(
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
                            cwe_id=rule.get("cwe_id"),
                            stride_category=rule.get("stride"),
                            compliance_controls=rule.get("compliance", {}),
                        )
                    )

        return findings
