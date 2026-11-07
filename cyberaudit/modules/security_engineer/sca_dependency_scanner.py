"""
Software Composition Analysis (SCA) & Dependency Scanner (DevSecOps Pillar)
Audits dependency manifest files for supply chain vulnerabilities:
- requirements.txt, package.json, pom.xml, go.mod, Pipfile
- Wildcard/unpinned versions enabling dependency confusion / poisoned updates
- Insecure plaintext package registries (HTTP)
- Known compromised or vulnerable packages (event-stream, log4j-core 2.14, colors 1.4.1)
Mapped to MITRE ATT&CK: T1195.001
"""

import os
import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class ScaDependencyScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "DEVSECOPS-SCA-WILDCARD-VERSION-01",
                "title": "SCA Supply Chain: Unpinned / Wildcard Dependency Version",
                "pattern": re.compile(
                    r'(?:^[a-zA-Z0-9_.-]+\s*==\s*\*|["\'][a-zA-Z0-9_.-]+["\']\s*:\s*["\'](?:\*|latest|>=0\.0\.1)["\'])',
                    re.MULTILINE,
                ),
                "severity": Severity.MEDIUM,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "SLSA": "Build Level 2",
                    "OpenSSF": "Pinning-Dependencies",
                    "ISO_27001": "A.14.2.8",
                },
                "description": "Dependency version declared as wildcard (`*`), `latest`, or unrestricted range, allowing upstream package compromise or breaking changes to automatically inject into builds.",
                "remediation": "Pin all dependencies to exact versions (e.g. `requests==2.31.0` or `\"express\": \"4.18.2\"`) and maintain lockfiles with cryptographic checksums.",
                "mitre_id": "T1195.001",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise: Compromise Software Dependencies",
                "cwe_id": "CWE-1357",
            },
            {
                "id": "DEVSECOPS-SCA-INSECURE-REGISTRY-01",
                "title": "SCA Security: Insecure Plaintext Package Registry URL",
                "pattern": re.compile(
                    r'(?:--index-url\s+http://|--extra-index-url\s+http://|registry\s*=\s*["\']?http://)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "PCI_DSS": "Req 4.1",
                    "ISO_27001": "A.13.1.1",
                },
                "description": "Package manager configured to fetch dependencies over unencrypted HTTP, allowing on-path network attackers to execute Man-in-the-Middle (MitM) package tampering.",
                "remediation": "Enforce HTTPS for all package repository and registry URLs.",
                "mitre_id": "T1195.001",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise",
                "cwe_id": "CWE-319",
            },
            {
                "id": "DEVSECOPS-SCA-KNOWN-VULN-PACKAGE-01",
                "title": "SCA Vulnerability: Known Compromised / Critical Vulnerable Package",
                "pattern": re.compile(
                    r'(?:event-stream\s*==\s*3\.3\.6|log4j-core.*2\.(?:14|13|12|11|10|[0-9])\b|colors\s*==\s*1\.4\.1|faker\s*==\s*6\.6\.6)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "PCI_DSS": "Req 6.2",
                    "ISO_27001": "A.12.6.1",
                    "SOC2": "CC7.1",
                },
                "description": "Manifest declares a package release with confirmed malicious backdoor code or critical remote code execution flaw (e.g. Log4Shell CVE-2021-44228 or compromised event-stream).",
                "remediation": "Upgrade package to an audited, non-vulnerable release immediately or replace with an alternative library.",
                "mitre_id": "T1195.001",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise",
                "cwe_id": "CWE-1357",
            },
        ]

    @property
    def name(self) -> str:
        return "SCA & Dependency Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Audits requirements.txt, package.json, and lockfiles for wildcards, insecure registries, and known vulnerable packages."

    @property
    def file_patterns(self) -> List[str]:
        return ["*requirements*.txt", "package*.json", "Pipfile*", "pom.xml", "go.mod"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Check if file matches dependency manifests
        is_manifest = any(
            p in lower_path
            for p in ["requirements", "package.json", "package-lock.json", "pipfile", "pom.xml", "go.mod"]
        )
        if not is_manifest:
            return []

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

        # ── Cross-reference Reachability Analysis ────────────────────────────
        try:
            from cyberaudit.core.reachability_engine import ReachabilityEngine, ReachabilityStatus
            base_dir = os.path.dirname(os.path.abspath(file_path))
            m_type = "package.json" if "package.json" in lower_path else "requirements.txt"
            engine = ReachabilityEngine(project_root=base_dir)
            reach_results = engine.analyze_reachability(content, manifest_type=m_type)

            for r in reach_results:
                if r.status == ReachabilityStatus.CONFIRMED_REACHABLE:
                    findings.append(
                        Finding(
                            id=f"DEVSECOPS-SCA-REACHABLE-{r.package_name.upper()}-01",
                            title=f"SCA Reachable Vulnerability: {r.package_name} ({r.cve_id}) Confirmed in Call-Graph",
                            description=(
                                f"La dependencia '{r.package_name}' ({r.cve_id}) es ALCANZABLE en el código fuente ejecutable. "
                                f"Se detectaron {len(r.call_sites)} sitio(s) de llamada invocando símbolos vulnerables: {', '.join(r.vulnerable_symbols_defined)}."
                            ),
                            severity=Severity.CRITICAL,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=1,
                            code_snippet=r.call_chain[0] if r.call_chain else f"{r.package_name}=={r.installed_version}",
                            remediation=r.recommendation,
                            mitre_id="T1195.001",
                            mitre_tactic="Initial Access",
                            mitre_technique="Supply Chain Compromise",
                            cwe_id="CWE-1104",
                            compliance_controls={"EndorLabs": "Reachable Vulnerability", "SLSA": "Build Level 3"},
                        )
                    )
                elif r.status == ReachabilityStatus.UNREACHABLE_ADVISORY:
                    findings.append(
                        Finding(
                            id=f"DEVSECOPS-SCA-ADVISORY-{r.package_name.upper()}-01",
                            title=f"SCA Advisory: {r.package_name} ({r.cve_id}) Unreachable in Execution Paths",
                            description=(
                                f"La dependencia '{r.package_name}' posee un CVE conocido, pero sus símbolos vulnerables "
                                f"({', '.join(r.vulnerable_symbols_defined)}) NO son invocados en ninguna ruta de llamada del proyecto. "
                                f"Riesgo directo mitigado por inalcanzabilidad (Reducción de Fatiga de Alertas)."
                            ),
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=1,
                            code_snippet=f"{r.package_name}=={r.installed_version} [UNREACHABLE]",
                            remediation=r.recommendation,
                            mitre_id="T1195.001",
                            mitre_tactic="Initial Access",
                            mitre_technique="Supply Chain Compromise",
                            cwe_id="CWE-1104",
                            compliance_controls={"EndorLabs": "Unreachable Advisory"},
                        )
                    )
        except Exception:
            pass

        return findings
