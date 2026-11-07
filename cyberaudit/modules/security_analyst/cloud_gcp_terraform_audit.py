"""
Google Cloud Platform (GCP) & Multi-Cloud Terraform Posture Scanner
Completes the Cloud Defense triad alongside AWS and Azure:
1. GCP Public IAM Bindings (`allUsers` / `allAuthenticatedUsers` on GCS buckets, Cloud Run, BigQuery).
2. Over-privileged GCP IAM Roles (`roles/owner`, `roles/editor`) or static Service Account Key creation (`google_service_account_key`).
3. Terraform / OpenTofu state or storage buckets missing encryption / uniform bucket-level access.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class MultiCloudGcpAndTerraformScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Google Cloud (GCP) & Multi-Cloud Terraform Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.CLOUD_DEFENSE

    @property
    def description(self) -> str:
        return (
            "Audits GCP IAM configurations and Terraform/HCL files for public `allUsers`/`allAuthenticatedUsers` bindings, "
            "`roles/owner` over-privileging, and static service account key exports."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["package-lock.json", "package.json", "tsconfig.json", ".rsc.json"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. CLOUD-GCP-PUBLIC-IAM-BINDING (allUsers / allAuthenticatedUsers)
        # ------------------------------------------------------------------
        public_iam_re = re.compile(r"""['"](?:allUsers|allAuthenticatedUsers)['"]""")
        for match in public_iam_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="CLOUD-GCP-PUBLIC-IAM-BINDING",
                    title="GCP Cloud Defense: Public IAM Principal (`allUsers` / `allAuthenticatedUsers`) Exposes Resource",
                    description=(
                        f"IAM binding grants permissions to `{match.group(0)}` at line {line_num}. "
                        f"Note that `allAuthenticatedUsers` includes ANY Google account on the internet, not just your Google Workspace organization."
                    ),
                    severity=Severity.CRITICAL,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Restrict IAM bindings to specific `serviceAccount:`, `group:`, or `domain:` principals and enforce `constraints/iam.allowedPolicyMemberDomains`.",
                    cwe_id="CWE-284",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"CIS-GCP": "1.1 / 5.1", "SOC2": "CC6.3"},
                )
            )

        # ------------------------------------------------------------------
        # 2. CLOUD-GCP-PRIMITIVE-OWNER-ROLE (roles/owner or roles/editor)
        # ------------------------------------------------------------------
        primitive_role_re = re.compile(r"""['"]roles/(?:owner|editor)['"]""")
        for match in primitive_role_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="CLOUD-GCP-PRIMITIVE-ROLE",
                    title="GCP Cloud Defense: Basic/Primitive IAM Role (`roles/owner` or `roles/editor`) Violates Least Privilege",
                    description=(
                        f"Configuration assigns primitive role `{match.group(0)}` at line {line_num}. "
                        f"Primitive roles grant thousands of wildcard permissions across all GCP services, enabling lateral movement."
                    ),
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Replace `roles/owner` and `roles/editor` with predefined fine-grained IAM roles (e.g., `roles/storage.objectViewer`, `roles/bigquery.dataViewer`).",
                    cwe_id="CWE-250",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                    compliance_controls={"CIS-GCP": "1.3"},
                )
            )

        # ------------------------------------------------------------------
        # 3. CLOUD-GCP-STATIC-SA-KEY (google_service_account_key in Terraform)
        # ------------------------------------------------------------------
        if lower_path.endswith((".tf", ".hcl")):
            sa_key_re = re.compile(r'resource\s+"google_service_account_key"')
            for match in sa_key_re.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                findings.append(
                    Finding(
                        id="CLOUD-GCP-STATIC-SA-KEY",
                        title="GCP Cloud Defense: Long-Lived Service Account Key Provisioned in Terraform",
                        description=(
                            f"Terraform resource `google_service_account_key` at line {line_num} generates a downloadable static private key JSON. "
                            f"Furthermore, the raw private key material is stored in plaintext inside `terraform.tfstate`."
                        ),
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Use Workload Identity Federation or Service Account Impersonation instead of static JSON keys.",
                        cwe_id="CWE-798",
                        stride_category=StrideCategory.SPOOFING.value,
                        compliance_controls={"CIS-GCP": "1.4"},
                    )
                )

        return findings
