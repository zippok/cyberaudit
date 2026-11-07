"""
Docker & Container IaC Hardening Scanner (DevSecOps / Security Engineering)
Audits Dockerfiles and docker-compose.yml files for security anti-patterns:
- Running containers as root (missing USER non-root directive)
- Sensitive files copied into image (COPY .env, private keys)
- Privileged container flags (privileged: true, host PID)
- Mounting host Docker socket (/var/run/docker.sock)
Mapped to MITRE ATT&CK: T1610 (Deploy Container)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class DockerIacScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "SECENG-DOCKER-ROOT-USER-01",
                "title": "Container Hardening: Container Executes as Root User",
                "pattern": re.compile(r"^USER\s+(?:root|0)\b", re.MULTILINE | re.IGNORECASE),
                "severity": Severity.MEDIUM,
                "description": "Container process explicitly configured to run as root user. If compromised, attackers can break out to host kernel namespaces.",
                "remediation": "Create and switch to an unprivileged non-root user: `RUN useradd -u 888 appuser && USER appuser`.",
                "mitre_id": "T1610",
                "mitre_tactic": "Execution",
                "mitre_technique": "Deploy Container",
                "cwe_id": "CWE-250",
            },
            {
                "id": "SECENG-DOCKER-SECRET-COPY-01",
                "title": "Container Hardening: Sensitive Secret File Copied into Image",
                "pattern": re.compile(
                    r'^(?:COPY|ADD)\s+.*(?:\.env|id_rsa|id_dsa|\.pem|\.key|credentials\.json|secrets/)\s+',
                    re.MULTILINE | re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Embedding secrets or environment files directly into container image layers permanently stores credentials in image registries.",
                "remediation": "Do not copy secrets into container images. Inject secrets at runtime using environment variables or Docker/K8s Secret mounts.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-798",
            },
            {
                "id": "SECENG-DOCKER-PRIVILEGED-FLAG-01",
                "title": "Container Hardening: Container Runs with Privileged Mode Enabled",
                "pattern": re.compile(r'privileged\s*:\s*true|--privileged\b', re.IGNORECASE),
                "severity": Severity.CRITICAL,
                "description": "Running container with `--privileged` or `privileged: true` grants full root capabilities to all host devices, eliminating container isolation.",
                "remediation": "Remove `privileged: true`. Grant only specific Linux capabilities using `cap_add` (e.g. NET_ADMIN) where strictly required.",
                "mitre_id": "T1610",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Deploy Container",
                "cwe_id": "CWE-250",
            },
            {
                "id": "SECENG-DOCKER-SOCKET-MOUNT-01",
                "title": "Container Hardening: Host Docker Socket Mounted into Container",
                "pattern": re.compile(r'/var/run/docker\.sock\s*:\s*/var/run/docker\.sock', re.IGNORECASE),
                "severity": Severity.CRITICAL,
                "description": "Mounting `/var/run/docker.sock` grants the container full API access to the host Docker daemon, allowing immediate host takeover.",
                "remediation": "Remove docker.sock mounts. Use container orchestration APIs or rootless Docker architectures.",
                "mitre_id": "T1610",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Deploy Container",
                "cwe_id": "CWE-250",
            },
        ]

    @property
    def name(self) -> str:
        return "Docker & Container Hardening Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Audits Dockerfile and compose configurations for root user execution, secret leaks, and privileged container flags."

    @property
    def file_patterns(self) -> List[str]:
        return ["Dockerfile*", "*docker-compose*.yml", "*docker-compose*.yaml"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Only scan Dockerfiles and Compose files
        if not ("dockerfile" in lower_path or "compose" in lower_path):
            return []

        for rule in self.rules:
            match = rule["pattern"].search(content)
            if match:
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                snippet = match.group(0).strip()[:180]

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
                    cwe_id=rule.get("cwe_id"),
                )
                findings.append(finding)

        # Check if Dockerfile completely lacks any USER instruction (runs as root by default)
        if "dockerfile" in lower_path and not re.search(r"^USER\s+\w+", content, re.MULTILINE | re.IGNORECASE):
            findings.append(
                Finding(
                    id="SECENG-DOCKER-DEFAULT-ROOT-01",
                    title="Container Hardening: Dockerfile Has No Non-Root USER Directive",
                    description="The Dockerfile does not specify a non-root USER directive, causing the container to execute with default root privileges.",
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="[Missing USER directive]",
                    remediation="Add `USER <non-root-user>` before the ENTRYPOINT or CMD instruction.",
                    mitre_id="T1610",
                    mitre_tactic="Execution",
                    mitre_technique="Deploy Container",
                    cwe_id="CWE-250",
                )
            )

        return findings
