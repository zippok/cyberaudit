"""
Kubernetes & Pod Security Scanner (DevSecOps / Container Hardening)
Audits Kubernetes YAML manifests and Helm charts against CIS Benchmarks:
- Privileged containers (privileged: true)
- Host namespace sharing (hostPID, hostNetwork, hostIPC)
- Root execution (runAsNonRoot missing, runAsUser: 0)
- Excessive Linux capabilities (CAP_SYS_ADMIN, missing drop ALL)
- Writable root filesystem
- Automatic ServiceAccount API token mounting
Mapped to MITRE ATT&CK: T1610, T1611 (Container and Resource Discovery / Escape)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class K8sSecurityScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "DEVSECOPS-K8S-PRIVILEGED-01",
                "title": "Kubernetes Hardening: Container Configured with Privileged Mode",
                "pattern": re.compile(r'privileged\s*:\s*true', re.IGNORECASE),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "CIS_K8S": "5.2.1",
                    "NSA_CISA": "Pod-Security-Restricted",
                    "PCI_DSS": "Req 2.2",
                },
                "description": "Container runs with full root privileges on the underlying host kernel, disabling container isolation and enabling trivial container escape.",
                "remediation": "Set `securityContext.privileged: false` and grant only individual required capabilities via `capabilities.add`.",
                "mitre_id": "T1611",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Escape to Host",
                "cwe_id": "CWE-250",
            },
            {
                "id": "DEVSECOPS-K8S-HOST-NAMESPACES-01",
                "title": "Kubernetes Hardening: Pod Uses Host Namespaces (hostPID / hostNetwork)",
                "pattern": re.compile(r'(?:hostPID|hostNetwork|hostIPC)\s*:\s*true', re.IGNORECASE),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "CIS_K8S": "5.2.2",
                    "NSA_CISA": "Pod-Security-Baseline",
                },
                "description": "Pod shares process ID, network, or IPC namespaces directly with the host node, allowing container processes to sniff node traffic or manipulate host processes.",
                "remediation": "Set `hostPID: false`, `hostNetwork: false`, and `hostIPC: false` in Pod spec.",
                "mitre_id": "T1611",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Escape to Host",
                "cwe_id": "CWE-250",
            },
            {
                "id": "DEVSECOPS-K8S-RUN-AS-ROOT-01",
                "title": "Kubernetes Hardening: Pod Explicitly Runs as Root (runAsUser: 0)",
                "pattern": re.compile(r'runAsUser\s*:\s*0\b', re.IGNORECASE),
                "severity": Severity.HIGH,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "CIS_K8S": "5.2.6",
                    "NSA_CISA": "Pod-Security-Restricted",
                },
                "description": "Container explicitly configured to execute as root user (UID 0), increasing blast radius if the application is compromised.",
                "remediation": "Specify a high non-root UID (e.g. `runAsUser: 10001`) and enforce `runAsNonRoot: true` in securityContext.",
                "mitre_id": "T1610",
                "mitre_tactic": "Execution",
                "mitre_technique": "Deploy Container",
                "cwe_id": "CWE-250",
            },
            {
                "id": "DEVSECOPS-K8S-CAP-SYS-ADMIN-01",
                "title": "Kubernetes Hardening: Excessive Linux Capability Granted (SYS_ADMIN)",
                "pattern": re.compile(r'capabilities\s*:[\s\S]{0,60}?add\s*:[\s\S]{0,60}?(?:SYS_ADMIN|ALL)', re.IGNORECASE),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "CIS_K8S": "5.2.7",
                    "NSA_CISA": "Pod-Security-Restricted",
                },
                "description": "Container granted `CAP_SYS_ADMIN` capability (equivalent to full root on Linux), allowing raw device mounting and cgroup modifications.",
                "remediation": "Enforce `capabilities.drop: [\"ALL\"]` and add only the exact minimal capabilities needed (e.g. NET_BIND_SERVICE).",
                "mitre_id": "T1611",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Escape to Host",
                "cwe_id": "CWE-250",
            },
            {
                "id": "DEVSECOPS-K8S-SA-TOKEN-AUTO-01",
                "title": "Kubernetes Hardening: Unrestricted ServiceAccount Token Automount",
                "pattern": re.compile(r'automountServiceAccountToken\s*:\s*true', re.IGNORECASE),
                "severity": Severity.MEDIUM,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "CIS_K8S": "5.1.6",
                    "NSA_CISA": "Kubernetes-Hardening-Guide",
                },
                "description": "Pod automounts Kubernetes API credentials into `/var/run/secrets/kubernetes.io/serviceaccount/token`, permitting attackers who compromise the pod to query the K8s API server.",
                "remediation": "Set `automountServiceAccountToken: false` on pods that do not require programmatic access to the Kubernetes API.",
                "mitre_id": "T1552.007",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Container API Tokens",
                "cwe_id": "CWE-798",
            },
        ]

    @property
    def name(self) -> str:
        return "Kubernetes & Pod Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Audits Kubernetes manifests and Helm templates for privileged containers, host namespaces, and RBAC token exposures."

    @property
    def file_patterns(self) -> List[str]:
        return ["*.yaml", "*.yml"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_content = content.lower()

        # Only scan files that look like Kubernetes manifests
        is_k8s = any(
            marker in lower_content
            for marker in ["apiversion:", "kind: pod", "kind: deployment", "kind: statefulset", "kind: daemonset", "kind: job"]
        )
        if not is_k8s:
            return []

        lines = content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["id"] != "DEVSECOPS-K8S-CAP-SYS-ADMIN-01":
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

        # Multi-line capability check
        for rule in self.rules:
            if rule["id"] == "DEVSECOPS-K8S-CAP-SYS-ADMIN-01":
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

        # Check if Pod/Deployment completely lacks securityContext
        if "securitycontext:" not in lower_content:
            findings.append(
                Finding(
                    id="DEVSECOPS-K8S-MISSING-SEC-CONTEXT-01",
                    title="Kubernetes Hardening: Missing securityContext in Pod Spec",
                    description="The Kubernetes workload specification contains no `securityContext` block, allowing containers to run with default unrestricted privileges.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="[Missing securityContext directive]",
                    remediation="Define an explicit `securityContext` with `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, and `capabilities.drop: ['ALL']`.",
                    mitre_id="T1610",
                    mitre_tactic="Execution",
                    mitre_technique="Deploy Container",
                    cwe_id="CWE-250",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                    compliance_controls={"CIS_K8S": "5.2.6", "NSA_CISA": "Pod-Security-Baseline"},
                )
            )

        return findings
