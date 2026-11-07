"""
CI/CD Pipeline Security Scanner (DevSecOps Pillar)
Audits GitHub Actions, GitLab CI, and Jenkins build pipelines:
- Unpinned third-party actions (Software Supply Chain / SLSA)
- Dangerous pull_request_target triggers with checkout (PwnRequest / Script Injection)
- Overprivileged GITHUB_TOKEN permissions
- Unverified curl-to-bash execution patterns
- Secret printing / leakage into build logs
Mapped to MITRE ATT&CK: T1195.001, T1059, T1552
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class CicdPipelineScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "DEVSECOPS-CICD-UNPINNED-ACTION-01",
                "title": "CI/CD Supply Chain: Unpinned Third-Party Action in Workflow",
                "pattern": re.compile(
                    r'uses:\s*(?!actions/|docker/)[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+@(?!([0-9a-f]{40}))([a-zA-Z0-9_.-]+)',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "SLSA": "Build Level 3",
                    "OpenSSF": "Pinning-Dependencies",
                    "ISO_27001": "A.14.2.8",
                },
                "description": "Third-party GitHub Action referenced using a mutable branch or release tag instead of an immutable 40-character commit SHA, exposing the pipeline to supply-chain tampering if the upstream repository is compromised.",
                "remediation": "Pin all third-party actions to full commit SHAs: `uses: owner/repo@<commit-sha> # tag`.",
                "mitre_id": "T1195.001",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise: Compromise Software Dependencies",
                "cwe_id": "CWE-1357",
            },
            {
                "id": "DEVSECOPS-CICD-PWN-REQUEST-01",
                "title": "CI/CD Security: Insecure pull_request_target Trigger with PR Checkout",
                "pattern": re.compile(
                    r'pull_request_target[\s\S]{0,400}?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "OpenSSF": "Dangerous-Workflow",
                    "SOC2": "CC7.1",
                },
                "description": "Workflow combines `pull_request_target` trigger with checkout of untrusted pull request HEAD. This grants external contributors access to repository secrets and write tokens (PwnRequest vulnerability).",
                "remediation": "Use `pull_request` instead of `pull_request_target` when checking out PR code, or isolate privileged steps to separate post-merge workflows.",
                "mitre_id": "T1195",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise",
                "cwe_id": "CWE-94",
            },
            {
                "id": "DEVSECOPS-CICD-CURL-PIPE-BASH-01",
                "title": "CI/CD Execution: Insecure Remote Script Piping (curl | bash)",
                "pattern": re.compile(
                    r'(?:curl\s+[\s\S]{0,60}?\bhttps?://[^\s|]+\s*\|\s*(?:ba|z)?sh|wget\s+[\s\S]{0,60}?-O-\s+[^\s|]+\s*\|\s*(?:ba|z)?sh)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "OpenSSF": "Security-Tooling",
                    "CIS_BENCHMARK": "Software-Integrity",
                },
                "description": "Build step downloads and directly executes remote scripts without verifying integrity via cryptographic hashes (SHA-256) or GPG signatures.",
                "remediation": "Download scripts to disk, verify their SHA-256 checksum against an expected value, and then execute.",
                "mitre_id": "T1059.004",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter: Unix Shell",
                "cwe_id": "CWE-494",
            },
            {
                "id": "DEVSECOPS-CICD-SECRET-ECHO-01",
                "title": "CI/CD Data Leakage: Secret Printed into Build Logs",
                "pattern": re.compile(
                    r'(?:echo|printf|print)\s+["\'].*?\$\{\{\s*secrets\.\w+\s*\}\}',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "PCI_DSS": "Req 6.2",
                    "ISO_27001": "A.9.4.2",
                    "SOC2": "CC6.1",
                },
                "description": "Workflow step explicitly prints repository secrets into console output, risking credential exposure in public or persistent build logs.",
                "remediation": "Never echo secrets in workflow steps. Pass secrets directly via environment variables to the target process.",
                "mitre_id": "T1552",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials",
                "cwe_id": "CWE-532",
            },
        ]

    @property
    def name(self) -> str:
        return "CI/CD Pipeline Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Audits GitHub Actions, GitLab CI, and build workflows for supply chain risks, PwnRequest, and secret leaks."

    @property
    def file_patterns(self) -> List[str]:
        return ["*.yml", "*.yaml", "Jenkinsfile*", ".gitlab-ci*"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Only scan CI/CD workflow directories or files
        if not (".github" in lower_path or "gitlab" in lower_path or "jenkins" in lower_path or "workflow" in lower_path or "ci" in lower_path):
            return []

        lines = content.splitlines()

        # Line-by-line checks
        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["id"] != "DEVSECOPS-CICD-PWN-REQUEST-01":
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

        # Multi-line check for pull_request_target + checkout
        for rule in self.rules:
            if rule["id"] == "DEVSECOPS-CICD-PWN-REQUEST-01":
                match = rule["pattern"].search(content)
                if match:
                    line_num = content[: match.start()].count("\n") + 1
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
                            code_snippet=match.group(0).strip()[:180],
                            remediation=rule["remediation"],
                            mitre_id=rule["mitre_id"],
                            mitre_tactic=rule["mitre_tactic"],
                            mitre_technique=rule["mitre_technique"],
                            cwe_id=rule.get("cwe_id"),
                            stride_category=rule.get("stride"),
                            compliance_controls=rule.get("compliance", {}),
                        )
                    )

        # Check for top-level permissions directive in GitHub Actions
        if ".github" in lower_path and ("workflows" in lower_path or lower_path.endswith(".yml") or lower_path.endswith(".yaml")):
            if not re.search(r"^\s*permissions:\s*", content, re.MULTILINE):
                findings.append(
                    Finding(
                        id="DEVSECOPS-CICD-OVERPRIVILEGED-TOKEN-01",
                        title="CI/CD Hardening: Missing Top-Level Permissions Block in Workflow",
                        description="The GitHub Actions workflow does not declare an explicit `permissions:` block, defaulting to broad write permissions for the automatic GITHUB_TOKEN.",
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=1,
                        code_snippet="[Missing top-level permissions block]",
                        remediation="Add `permissions: read-all` at the top of the workflow file and grant write access only to specific jobs.",
                        mitre_id="T1078",
                        mitre_tactic="Defense Evasion",
                        mitre_technique="Valid Accounts",
                        cwe_id="CWE-250",
                        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                        compliance_controls={"OpenSSF": "Token-Permissions", "SOC2": "CC6.1"},
                    )
                )

        return findings
