"""
Active Directory Security Auditor
Audits Active Directory scripts, GPO exports, LDAP dumps, and configuration files.
Detects:
- Kerberoasting vulnerabilities (SPNs with weak encryption / service account misuse)
- AS-REP Roasting risk (DONT_REQ_PREAUTH enabled)
- DCSync rights & dangerous ACL configurations (DS-Replication-Get-Changes)
- Group Policy Preferences (GPP) cpassword leaks (MS14-025)
- Unconstrained delegation risks
Mapped to MITRE ATT&CK: T1558.003, T1558.004, T1003.006, T1552.001
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class ActiveDirectoryAuditScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "AD-GPP-CPASSWORD-01",
                "title": "Active Directory: Group Policy Preferences (GPP) cpassword Leak",
                "pattern": re.compile(r'cpassword\s*=\s*"([A-Za-z0-9+/=]{20,})"', re.IGNORECASE),
                "severity": Severity.CRITICAL,
                "description": "Found hardcoded encrypted 'cpassword' in Group Policy file. The AES decryption key for GPP was publicly released by Microsoft (MS14-025), making this trivially reversible to plaintext.",
                "remediation": "Delete obsolete GPP XML files from SYSVOL. Install KB2962486 and rotate all affected user/administrator credentials.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cve_id": "MS14-025",
            },
            {
                "id": "AD-ASREP-ROASTING-01",
                "title": "Active Directory: Kerberos Pre-Authentication Disabled (AS-REP Roasting)",
                "pattern": re.compile(
                    r"(?:DONT_REQ_PREAUTH|userAccountControl.*4194304|DoesNotRequirePreAuth\s*:\s*\$true)",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Account configured without Kerberos pre-authentication. Any user in the domain can request an AS-REP ticket for this account and crack its password hash offline.",
                "remediation": "Enable Kerberos pre-authentication for the account (ensure 'Do not require Kerberos preauthentication' is unchecked).",
                "mitre_id": "T1558.004",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
            },
            {
                "id": "AD-REVERSIBLE-ENC-01",
                "title": "Active Directory: Reversible Encryption Password Policy Enabled",
                "pattern": re.compile(
                    r"(?:userAccountControl\s*:\s*128\b|userAccountControl\s*[:=]\s*\d*128|ENCRYPTED_TEXT_PASSWORD_ALLOWED)",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Account configured with reversible password encryption allowed, enabling attackers with directory read access to recover plaintext passwords.",
                "remediation": "Disable 'Store passwords using reversible encryption' policy across Domain Accounts.",
                "mitre_id": "T1552",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials",
            },
            {
                "id": "AD-KERBEROAST-WEAK-ENC-01",
                "title": "Active Directory: Kerberoasting SPN Registration Detected",
                "pattern": re.compile(
                    r"(?:msDS-SupportedEncryptionTypes\s*[:=]\s*[04]\b|servicePrincipalName.*|Add-KrbSPN.*|Set-ADUser.*ServicePrincipalName)",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "SPN registered with legacy RC4-HMAC encryption enabled, facilitating rapid offline password cracking of Kerberos TGS tickets (Kerberoasting).",
                "remediation": "Migrate service accounts to Group Managed Service Accounts (gMSA) with 128-char randomized passwords and enforce AES-256 Kerberos encryption.",
                "mitre_id": "T1558.003",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Steal or Forge Kerberos Tickets: Kerberoasting",
            },
            {
                "id": "AD-DCSYNC-RIGHTS-01",
                "title": "Active Directory: Dangerous Replication Rights / DCSync Permission Granted",
                "pattern": re.compile(
                    r"(?:DS-Replication-Get-Changes-All|DS-Replication-Get-Changes-In-Filtered-Set|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Directory Services replication rights granted on domain root object. Allows non-domain-controller entities to request password hashes for all domain users via DCSync.",
                "remediation": "Audit ACLs on the Domain Root. Revoke Replicating Directory Changes rights from all non-Domain Controller accounts.",
                "mitre_id": "T1003.006",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "OS Credential Dumping: DCSync",
            },
            {
                "id": "AD-UNCONSTRAINED-DELEG-01",
                "title": "Active Directory: Unconstrained Delegation Enabled",
                "pattern": re.compile(
                    r"(?:TRUSTED_FOR_DELEGATION|TrustedForDelegation\s*:\s*\$true)",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Server account configured for Unconstrained Delegation. If a high-privilege account authenticates to this host, its TGT is cached in LSASS, enabling full domain compromise.",
                "remediation": "Replace with Kerberos Constrained Delegation (KCD) or Resource-Based Constrained Delegation (RBCD). Mark sensitive admin accounts as 'Account is sensitive and cannot be delegated'.",
                "mitre_id": "T1558",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Steal or Forge Kerberos Tickets",
            },
            {
                "id": "AD-HARDCODED-CRED-SCRIPT-01",
                "title": "Active Directory: Hardcoded Domain Credentials in Script",
                "pattern": re.compile(
                    r'(?:ConvertTo-SecureString\s+["\'][^"\']+["\']\s+-AsPlainText\s+-Force|System\.Management\.Automation\.PSCredential\s*\(\s*["\'][^"\']+["\']\s*,\s*["\'][^"\']+["\']\)|Connect-ExchangeOnline.*-Password\s+["\'][^"\']+["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Cleartext or trivially extractable domain credentials hardcoded inside administrative automation script.",
                "remediation": "Remove hardcoded credentials. Use Azure Key Vault, Managed Identities, or gMSA for script authentication.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
            },
        ]

    @property
    def name(self) -> str:
        return "Active Directory Security Auditor"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ANALYST

    @property
    def description(self) -> str:
        return "Audits Active Directory scripts, GPO XMLs, and configurations for Kerberoasting, AS-REP Roasting, DCSync and GPP flaws."

    @property
    def file_extensions(self) -> List[str]:
        return [".ps1", ".psm1", ".xml", ".ldif", ".json", ".csv", ".txt", ".conf", ".gpo"]

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
                        cwe_id="CWE-259",  # Hard-coded Password / Weak Security Config
                        cve_id=rule.get("cve_id"),
                    )
                    findings.append(finding)
                    break

        return findings
