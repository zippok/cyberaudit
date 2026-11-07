"""
Software Supply Chain & SBOM Security Scanner
Audits software packages, manifests, and CI/CD pipelines for supply chain risks,
SLSA (Supply-chain Levels for Software Artifacts) compliance, malicious package lifecycle hooks,
unpinned dependencies, and SBOM readiness according to CISA, NIST SP 800-161r1, and OpenSSF.
"""

import json
import os
import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class SupplyChainSbomScanner(BaseScanner):
    __test__ = False  # Prevent pytest collector from discovering this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Software Supply Chain & SBOM Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Detects supply chain threats including malicious npm/pip lifecycle scripts, unpinned dependencies, unpinned GitHub Actions, and unencrypted repository endpoints according to SLSA Framework and CISA guidance."

    @property
    def supported_extensions(self) -> Set[str]:
        return {".json", ".txt", ".yml", ".yaml", ".toml", ".gradle", ".xml"}

    def should_scan(self, file_path: str) -> bool:
        basename = os.path.basename(file_path).lower()
        norm_path = file_path.replace("\\", "/").lower()

        target_files = {
            "package.json",
            "requirements.txt",
            "pipfile",
            "pyproject.toml",
            "build.gradle",
            "pom.xml",
            ".npmrc",
            "pip.conf",
        }
        if basename in target_files:
            return True
        if ".github/workflows/" in norm_path and (norm_path.endswith(".yml") or norm_path.endswith(".yaml")):
            return True
        if norm_path.endswith(".gitlab-ci.yml"):
            return True
        return False

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        basename = os.path.basename(file_path).lower()
        norm_path = file_path.replace("\\", "/").lower()

        if basename == "package.json":
            findings.extend(self._scan_package_json(file_path, content))
        elif basename == "requirements.txt":
            findings.extend(self._scan_requirements_txt(file_path, content))
        elif ".github/workflows/" in norm_path or basename == ".gitlab-ci.yml":
            findings.extend(self._scan_ci_actions(file_path, content))

        # Check for cleartext HTTP registry URLs in any dependency config
        findings.extend(self._scan_cleartext_registries(file_path, content))

        return findings

    def _scan_package_json(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(content)
        except Exception:
            return findings

        # 1. Suspicious Lifecycle Scripts (preinstall, postinstall, etc.)
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            dangerous_commands = [
                (re.compile(r'\b(curl|wget)\b', re.IGNORECASE), "Remote payload download via curl/wget"),
                (re.compile(r'\b(powershell|pwsh)\b.*(-enc|-encodedcommand|-e\s)', re.IGNORECASE), "Encoded PowerShell command execution"),
                (re.compile(r'\b(sh|bash|zsh)\s+-c\b', re.IGNORECASE), "Shell subshell command execution"),
                (re.compile(r'\b(certutil|bitsadmin)\b', re.IGNORECASE), "Living-off-the-land Windows binary download"),
                (re.compile(r'\b(base64\s+-d|atob)\b', re.IGNORECASE), "Base64 payload deobfuscation in install script"),
            ]
            lifecycle_hooks = ["preinstall", "postinstall", "install", "preuninstall", "postuninstall"]

            for hook in lifecycle_hooks:
                cmd_str = scripts.get(hook)
                if cmd_str and isinstance(cmd_str, str):
                    for pattern, threat_desc in dangerous_commands:
                        if pattern.search(cmd_str):
                            findings.append(Finding(
                                id=f"SLSA-MALICIOUS-HOOK-{hook.upper()}",
                                title=f"Suspicious NPM Lifecycle Hook '{hook}': {threat_desc}",
                                description=f"The package.json declares an automated '{hook}' script executing '{cmd_str}'. Package lifecycle hooks execute automatically upon 'npm install' with full local user permissions, which is the #1 vector for software supply chain compromise and token stealers.",
                                severity=Severity.HIGH,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                code_snippet=f'"{hook}": "{cmd_str}"',
                                remediation="Avoid arbitrary command execution in npm lifecycle scripts. Use explicit build scripts ('npm run build') rather than automatic pre/postinstall hooks, or install with '--ignore-scripts' in CI.",
                                mitre_id="T1195.001",
                                mitre_tactic="Initial Access",
                                mitre_technique="Supply Chain Compromise: Compromise Software Dependencies",
                                cwe_id="CWE-78",
                                stride_category=StrideCategory.TAMPERING.value,
                                compliance_controls={"SLSA": "Build L3", "NIST SP 800-161r1": "RA-3", "ISO 27001": "A.8.30"},
                            ))

        # 2. Wildcard or Unpinned Dependencies
        for dep_type in ["dependencies", "devDependencies"]:
            deps = data.get(dep_type, {})
            if isinstance(deps, dict):
                for pkg, version in deps.items():
                    if isinstance(version, str) and version in {"*", "latest"} or version.startswith(">="):
                        findings.append(Finding(
                            id="SLSA-UNPINNED-DEPENDENCY",
                            title=f"Unpinned Supply Chain Dependency '{pkg}': Version '{version}'",
                            description=f"Package '{pkg}' is referenced with a floating/wildcard version constraint ('{version}'). This allows upstream maintainer account compromises or dependency confusion attacks to inject untrusted code into automated builds without developer consent.",
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            code_snippet=f'"{pkg}": "{version}"',
                            remediation=f"Pin the package to an exact semantic version (e.g. '1.2.3' or '~1.2.3') and commit a verified package-lock.json to repository control.",
                            mitre_id="T1195.001",
                            mitre_tactic="Initial Access",
                            mitre_technique="Supply Chain Compromise",
                            cwe_id="CWE-1104",
                            stride_category=StrideCategory.TAMPERING.value,
                            compliance_controls={"SLSA": "Source L2", "OpenSSF": "Pin-Dependencies"},
                        ))

        return findings

    def _scan_requirements_txt(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#") or cleaned.startswith("-"):
                continue

            # Check if line specifies package without pinned version or equality operator
            if re.match(r'^[a-zA-Z0-9_\-\.]+$', cleaned):
                findings.append(Finding(
                    id="SLSA-PYTHON-UNPINNED-PACKAGE",
                    title=f"Unpinned Python Dependency '{cleaned}' in requirements.txt",
                    description=f"Dependency '{cleaned}' does not specify an exact version pinning (e.g. 'package==1.2.3'). Each build will pull the latest version from PyPI, creating reproducible build failure and exposing the environment to poisoned releases.",
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=cleaned,
                    remediation=f"Pin dependency using exact version equality: '{cleaned}==X.Y.Z' and consider generating pip-compile hashes via pip-tools or uv.lock.",
                    mitre_id="T1195.001",
                    mitre_tactic="Initial Access",
                    mitre_technique="Supply Chain Compromise",
                    cwe_id="CWE-1104",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"SLSA": "Build L2", "NIST SP 800-161r1": "SR-3"},
                ))

        return findings

    def _scan_ci_actions(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Check for unpinned GitHub Actions (e.g., uses: actions/checkout@main or @master or @v1 instead of 40-char SHA)
        action_pattern = re.compile(r'uses:\s*([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)@(main|master|latest|v\d+[\.\d]*)', re.IGNORECASE)

        for idx, line in enumerate(lines, 1):
            match = action_pattern.search(line)
            if match:
                action_name = match.group(1)
                action_ref = match.group(2)
                # Flag mutable branch references as HIGH, tag references as MEDIUM
                is_mutable_branch = action_ref.lower() in {"main", "master", "latest"}
                findings.append(Finding(
                    id="SLSA-GITHUB-ACTION-MUTABLE-REF",
                    title=f"GitHub Action '{action_name}' Uses Mutable Reference '@{action_ref}'",
                    description=f"The CI/CD pipeline imports an external GitHub Action using a mutable tag or branch ('@{action_ref}') rather than an immutable Git commit SHA. If the third-party maintainer repository is hijacked or modified, malicious code will run inside your CI/CD runner with pipeline access tokens and secrets.",
                    severity=Severity.HIGH if is_mutable_branch else Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation=f"Pin third-party GitHub Actions to their full 40-character commit SHA (e.g. 'uses: {action_name}@40_CHAR_SHA # tag={action_ref}').",
                    mitre_id="T1195.002",
                    mitre_tactic="Initial Access",
                    mitre_technique="Supply Chain Compromise: Compromise Software Supply Chain Pipeline",
                    cwe_id="CWE-829",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"SLSA": "Source L3", "OpenSSF": "Scorecard-Pinned-Dependencies", "CIS": "CI/CD 2.1"},
                ))

        return findings

    def _scan_cleartext_registries(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        insecure_pattern = re.compile(r'http://(registry\.npmjs\.org|pypi\.python\.org|pypi\.org|repo\.maven\.apache\.org)', re.IGNORECASE)

        for idx, line in enumerate(lines, 1):
            if insecure_pattern.search(line):
                findings.append(Finding(
                    id="SLSA-CLEARTEXT-REGISTRY",
                    title="Insecure Cleartext HTTP Package Registry URL Detected",
                    description="The configuration references a package repository via unencrypted HTTP (http://). An attacker with local network positioning (ARP spoofing, coffee shop Wi-Fi, rogue ISP) can modify packages in flight to deliver trojanized binaries.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Always enforce HTTPS for package repositories (e.g. https://registry.npmjs.org or https://pypi.org/simple).",
                    mitre_id="T1557",
                    mitre_tactic="Credential Access",
                    mitre_technique="Adversary-in-the-Middle",
                    cwe_id="CWE-319",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"SLSA": "Source L1", "PCI-DSS": "Requirement 4.1"},
                ))

        return findings

    def scan_directory(self, dir_path: str) -> List[Finding]:
        findings: List[Finding] = []
        # Check if project contains dependency manifests but lacks an SBOM (CycloneDX or SPDX)
        manifests = ["package.json", "requirements.txt", "pom.xml", "build.gradle"]
        sbom_files = ["bom.json", "bom.xml", "cyclonedx.json", "spdx.json", "spdx.spdx"]

        has_manifest = any(os.path.isfile(os.path.join(dir_path, m)) for m in manifests)
        has_sbom = any(os.path.isfile(os.path.join(dir_path, s)) for s in sbom_files)

        if has_manifest and not has_sbom:
            findings.append(Finding(
                id="SLSA-SBOM-MISSING",
                title="Software Bill of Materials (SBOM) Missing in Production Repository",
                description="The project maintains third-party dependency manifests but does not publish a standardized Software Bill of Materials (CycloneDX or SPDX format). Executive Order 14028 and CISA require machine-readable SBOMs to track known CVE vulnerabilities across the software supply chain.",
                severity=Severity.LOW,
                pillar=self.pillar,
                scanner_name=self.name,
                file_path=dir_path,
                remediation="Generate an automated CycloneDX or SPDX SBOM during CI/CD build steps using 'syft . -o cyclonedx-json=bom.json' or '@cyclonedx/cyclonedx-npm'.",
                mitre_id="T1195",
                mitre_tactic="Initial Access",
                mitre_technique="Supply Chain Compromise",
                cwe_id="CWE-1104",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                compliance_controls={"CISA": "SBOM Minimum Elements", "NIST SP 800-161r1": "CM-8", "Executive Order": "EO 14028"},
            ))

        return findings
