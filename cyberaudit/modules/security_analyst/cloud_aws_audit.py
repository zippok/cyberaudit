"""
Cloud & AWS Security Defense Auditor (Security Analyst & Cloud Defense)
Audits AWS Terraform (.tf), CloudFormation, and IAM policies against CIS AWS Foundations:
- Overprivileged IAM policies ("Action": "*", "Resource": "*")
- Overly permissive IAM Trust Relationships (Principal: "*")
- Wide-Open Security Groups (0.0.0.0/0 on SSH, RDP, Database ports)
- EC2 Metadata IMDSv1 token exposure (vulnerable to SSRF credential theft)
- Publicly accessible S3 buckets (ACL public-read / public access block disabled)
- Unencrypted S3 buckets & public EBS snapshots
Mapped to MITRE ATT&CK: T1530, T1078.004, T1190, T1552.005
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class CloudAwsAuditScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "CLOUD-AWS-IAM-WILDCARD-ADMIN-01",
                "title": "AWS IAM Security: Overprivileged Wildcard Admin Policy (Action: *, Resource: *)",
                "pattern": re.compile(
                    r'(?:["\']?Action["\']?\s*[:=]\s*(?:["\']\*["\']|\[\s*["\']\*["\']\s*\])[\s\S]{0,150}?["\']?Resource["\']?\s*[:=]\s*(?:["\']\*["\']|\[\s*["\']\*["\']\s*\])|actions\s*=\s*\[["\']\*["\']\][\s\S]{0,150}?resources\s*=\s*\[["\']\*["\']\])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "CIS_AWS": "1.16",
                    "PCI_DSS": "Req 7.2",
                    "ISO_27001": "A.9.2.3",
                    "SOC2": "CC6.3",
                },
                "description": "IAM policy statement grants universal wildcard permissions (`Action: *`) across all cloud resources (`Resource: *`), granting full administrative dominance.",
                "remediation": "Apply principle of least privilege: scope actions to specific services (e.g. `s3:GetObject`) and restrict resources to explicit ARNs.",
                "mitre_id": "T1078.004",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Valid Accounts: Cloud Accounts",
                "cwe_id": "CWE-732",
            },
            {
                "id": "CLOUD-AWS-IAM-OPEN-TRUST-01",
                "title": "AWS IAM Security: Open Trust Relationship (AssumeRole Principal: *)",
                "pattern": re.compile(
                    r'"Principal"\s*:\s*(?:["\']\*["\']|\{\s*["\']AWS["\']\s*:\s*["\']\*["\']\s*\})',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.SPOOFING.value,
                "compliance": {
                    "CIS_AWS": "1.20",
                    "SOC2": "CC6.1",
                },
                "description": "IAM Role trust policy configures `Principal: *` without condition keys, allowing any AWS account in the world to assume the role if ARN is discovered.",
                "remediation": "Restrict the trust relationship to specific trusted AWS account IDs or IAM user/role ARNs with external IDs.",
                "mitre_id": "T1078.004",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Valid Accounts: Cloud Accounts",
                "cwe_id": "CWE-287",
            },
            {
                "id": "CLOUD-AWS-SG-EXPOSED-PORTS-01",
                "title": "AWS Network Security: Security Group Open to 0.0.0.0/0 on Sensitive Ports",
                "pattern": re.compile(
                    r'(?:cidr_blocks\s*=\s*\[["\']0\.0\.0\.0/0["\']\][\s\S]{0,120}?(?:from_port\s*=\s*(?:22|3389|3306|5432|6379|27017|9200)|to_port\s*=\s*(?:22|3389|3306|5432|6379|27017|9200))|(?:from_port\s*=\s*(?:22|3389|3306|5432|6379|27017|9200)|to_port\s*=\s*(?:22|3389|3306|5432|6379|27017|9200))[\s\S]{0,120}?cidr_blocks\s*=\s*\[["\']0\.0\.0\.0/0["\']\])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "CIS_AWS": "4.1",
                    "PCI_DSS": "Req 1.3",
                    "ISO_27001": "A.13.1.1",
                },
                "description": "Security group permits unrestricted public ingress (`0.0.0.0/0`) to management ports (SSH 22, RDP 3389) or internal database services (MySQL, Postgres, Redis, MongoDB).",
                "remediation": "Restrict ingress rules to corporate VPN/bastion IP ranges, or connect via AWS Systems Manager (SSM) Session Manager without opening inbound ports.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-284",
            },
            {
                "id": "CLOUD-AWS-EC2-IMDSV1-SSRF-01",
                "title": "AWS Compute Security: EC2 Metadata Service Configured with Legacy IMDSv1",
                "pattern": re.compile(
                    r'http_tokens\s*=\s*["\']optional["\']',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "CIS_AWS": "7.1",
                    "PCI_DSS": "Req 2.2",
                    "SOC2": "CC6.1",
                },
                "description": "EC2 instance metadata service is configured with `http_tokens = \"optional\"`, leaving the instance vulnerable to IMDSv1 credential theft via SSRF vulnerabilities.",
                "remediation": "Enforce IMDSv2 by setting `http_tokens = \"required\"` and `http_endpoint = \"enabled\"` in `metadata_options`.",
                "mitre_id": "T1552.005",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Cloud Instance Metadata API",
                "cwe_id": "CWE-918",
            },
            {
                "id": "CLOUD-AWS-S3-PUBLIC-BUCKET-01",
                "title": "AWS Storage Security: S3 Bucket with Public Access (Public Read) Enabled",
                "pattern": re.compile(
                    r'(?:acl\s*=\s*["\']public-(?:read|read-write)["\']|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "CIS_AWS": "2.1.1",
                    "PCI_DSS": "Req 3.4",
                    "GDPR": "Art. 32",
                    "HIPAA": "164.312(a)(1)",
                },
                "description": "S3 bucket configured with public-read ACL or public access block disabled, exposing confidential corporate assets to the public Internet.",
                "remediation": "Enable `aws_s3_bucket_public_access_block` with all four flags set to `true`: `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`.",
                "mitre_id": "T1530",
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "Data from Cloud Storage Object",
                "cwe_id": "CWE-732",
            },
            {
                "id": "CLOUD-AWS-S3-UNENCRYPTED-01",
                "title": "AWS Storage Security: S3 Bucket Missing Server-Side Encryption",
                "pattern": re.compile(
                    r'resource\s+["\']aws_s3_bucket["\']\s+["\']\w+["\']\s+\{(?![^}]+server_side_encryption)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "CIS_AWS": "2.1.2",
                    "PCI_DSS": "Req 3.4",
                    "ISO_27001": "A.10.1.1",
                },
                "description": "S3 bucket declared without an explicit server-side encryption rule (`aws_s3_bucket_server_side_encryption_configuration`), risking plaintext exposure if underlying media is breached.",
                "remediation": "Configure default encryption using AWS KMS (`aws:kms`) or Amazon S3-managed keys (`AES256`).",
                "mitre_id": "T1530",
                "mitre_tactic": "Collection",
                "mitre_technique": "Data from Cloud Storage Object",
                "cwe_id": "CWE-311",
            },
            {
                "id": "CLOUD-AWS-PUBLIC-SNAPSHOT-01",
                "title": "AWS Storage Security: EBS or RDS Snapshot Shared Publicly",
                "pattern": re.compile(
                    r'(?:restorable_by_user_ids|create_volume_permission)[\s\S]{0,40}?(?:all|0\.0\.0\.0)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "CIS_AWS": "2.2.1",
                    "PCI_DSS": "Req 3.4",
                    "SOC2": "CC6.1",
                },
                "description": "EBS or RDS snapshot shared with `all` users, allowing anyone with an AWS account to restore the snapshot and dump disk/database contents.",
                "remediation": "Restrict snapshot restore permissions to explicit, authorized AWS account IDs only.",
                "mitre_id": "T1530",
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "Data from Cloud Storage Object",
                "cwe_id": "CWE-732",
            },
        ]

    @property
    def name(self) -> str:
        return "Cloud & AWS Security Defense Auditor"

    @property
    def pillar(self) -> Pillar:
        return Pillar.CLOUD_DEFENSE

    @property
    def description(self) -> str:
        return "Audits AWS infrastructure (Terraform, CloudFormation, IAM) for wildcard admin policies, IMDSv1, open SGs, and public S3 buckets."

    @property
    def file_extensions(self) -> List[str]:
        return [".tf", ".json", ".yaml", ".yml"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_content = content.lower()

        # Only scan files that reference AWS resources or IAM policies
        is_aws = any(
            marker in lower_content
            for marker in [
                "aws_",
                "arn:aws:",
                "type: aws::",
                "awstemplateformversion",
                "provider \"aws\"",
                "\"action\":",
                "\"action\" :",
                "actions =",
                "\"resource\":",
            ]
        )
        if not is_aws:
            return []

        lines = content.splitlines()

        # Line-by-line checks
        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["id"] in ["CLOUD-AWS-EC2-IMDSV1-SSRF-01", "CLOUD-AWS-S3-PUBLIC-BUCKET-01"]:
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

        # Multi-line checks
        for rule in self.rules:
            if rule["id"] not in ["CLOUD-AWS-EC2-IMDSV1-SSRF-01", "CLOUD-AWS-S3-PUBLIC-BUCKET-01"]:
                matches = rule["pattern"].finditer(content)
                for match in matches:
                    line_num = content[: match.start()].count("\n") + 1
                    snippet = match.group(0).strip()[:180]
                    if not any(f.id == rule["id"] and f.line_number == line_num for f in findings):
                        findings.append(
                            Finding(
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
                                cwe_id=rule.get("cwe_id"),
                                stride_category=rule.get("stride"),
                                compliance_controls=rule.get("compliance", {}),
                            )
                        )

        return findings
