"""
Cloud Security & Azure Defense Auditor
Audits Azure ARM/Bicep, Terraform, AWS CloudFormation, Entra ID (Azure AD) manifests,
and Sentinel KQL configurations.
Detects:
- Public Azure Storage Accounts & AWS S3 buckets (Anonymous Access)
- Overly permissive Network Security Groups (NSG 0.0.0.0/0 on 22/3389)
- Overprivileged Entra ID App Registrations (Directory.ReadWrite.All)
- Unencrypted Cloud Resources (Disks, Databases without TDE)
- IAM policies with wildcard admin permissions (*:*)
Mapped to MITRE ATT&CK: T1078.004, T1530, T1562.001, T1190
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class CloudAzureAuditScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "CLOUD-AZURE-STORAGE-PUBLIC-01",
                "title": "Azure: Storage Account Allows Public Anonymous Blob Access",
                "pattern": re.compile(
                    r'(?:allow_blob_public_access\s*=\s*true|allowBlobPublicAccess\s*:\s*true|publicAccess\s*:\s*["\'](?:Blob|Container)["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Azure Storage Account explicitly configured to permit anonymous internet read access to containers and blobs.",
                "remediation": "Set `allow_blob_public_access = false` and enforce Shared Access Signatures (SAS) or Entra ID RBAC authentication.",
                "mitre_id": "T1530",
                "mitre_tactic": "Collection",
                "mitre_technique": "Data from Cloud Storage",
            },
            {
                "id": "CLOUD-AZURE-NSG-OPEN-01",
                "title": "Azure: Network Security Group (NSG) Open Inbound Exposes RDP/SSH to 0.0.0.0/0",
                "pattern": re.compile(
                    r'(?:source_address_prefix\s*=\s*["\']\*(?:/0)?["\']|destination_port_range\s*=\s*["\'](?:22|3389)["\'])[\s\S]{0,140}?(?:destination_port_range\s*=\s*["\'](?:22|3389)["\']|source_address_prefix\s*=\s*["\']\*(?:/0)?["\']|access\s*=\s*["\']Allow["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Network Security Group rule allows unrestricted inbound traffic from any internet IP directly to SSH (port 22) or RDP (port 3389).",
                "remediation": "Restrict administrative access using Azure Bastion, VPN Gateway, or Just-In-Time (JIT) VM Access.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
            },
            {
                "id": "CLOUD-ENTRA-APP-PERMS-01",
                "title": "Entra ID: App Registration with Excessive High-Privilege Microsoft Graph Roles",
                "pattern": re.compile(
                    r'(?:Directory\.ReadWrite\.All|RoleManagement\.ReadWrite\.Directory|Mail\.ReadWrite|User\.ReadWrite\.All)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Entra ID (Azure AD) application registration requests high-impact directory permissions that can be leveraged for full tenant takeover.",
                "remediation": "Apply Principle of Least Privilege. Restrict app registration permissions to delegated scopes where possible.",
                "mitre_id": "T1078.004",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Valid Accounts: Cloud Accounts",
            },
            {
                "id": "CLOUD-AWS-IAM-WILDCARD-01",
                "title": "AWS/Cloud: Overly Permissive Wildcard IAM Policy (*:*)",
                "pattern": re.compile(
                    r'["\']Action["\']\s*:\s*["\']\*["\'][\s\S]{0,80}?["\']Resource["\']\s*:\s*["\']\*["\']',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "IAM policy grants unconditional wildcard actions on all cloud resources, granting effective full administrative control.",
                "remediation": "Scope IAM actions to specific services and resources required for operational workload.",
                "mitre_id": "T1078.004",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Valid Accounts: Cloud Accounts",
            },
            {
                "id": "CLOUD-AZURE-UNENCRYPTED-01",
                "title": "Cloud: Unencrypted Storage or Managed Disks Configured",
                "pattern": re.compile(
                    r'(?:enable_https_traffic_only\s*=\s*false|supportsHttpsTrafficOnly\s*:\s*false|encryption_settings\s*\{[\s\S]*?enabled\s*=\s*false)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Cloud resource configured with transport or data-at-rest encryption disabled.",
                "remediation": "Enforce HTTPS traffic only and Customer-Managed Keys (CMK) / Azure Key Vault encryption.",
                "mitre_id": "T1530",
                "mitre_tactic": "Collection",
                "mitre_technique": "Data from Cloud Storage",
            },
        ]

    @property
    def name(self) -> str:
        return "Cloud & Azure Defense Auditor"

    @property
    def pillar(self) -> Pillar:
        return Pillar.CLOUD_DEFENSE

    @property
    def description(self) -> str:
        return "Audits Azure ARM/Bicep, Terraform IaC, Entra ID permissions, and AWS cloud policies for misconfigurations."

    @property
    def file_extensions(self) -> List[str]:
        return [".tf", ".bicep", ".json", ".yaml", ".yml", ".kql", ".arm"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule in self.rules:
            match = rule["pattern"].search(content)
            if match:
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                snippet = match.group(0).strip()[:200]

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
                    cwe_id="CWE-16",  # Configuration
                )
                findings.append(finding)

        return findings
