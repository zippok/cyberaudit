"""
AI Supply Chain & Model Checkpoint Scanner (AI Security Pillar)
Audits AI/ML pipelines for supply chain attacks:
- Insecure PyTorch model checkpoint deserialization (torch.load without weights_only=True / Pickle RCE)
- HuggingFace from_pretrained() model loading without commit SHA pinning
- Legacy pickle format usage instead of modern Safetensors
Mapped to MITRE ATLAS: AML.T0010 (ML Supply Chain Compromise), MITRE ATT&CK: T1195.002
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class AiSupplyChainScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "AISEC-SUPPLY-CHAIN-PICKLE-WEIGHTS-01",
                "title": "AI Supply Chain: Insecure Model Checkpoint Pickle Deserialization (RCE)",
                "pattern": re.compile(
                    r'(?:torch\.load\s*\([\s\S]{0,80}?(?:weights_only\s*=\s*False|(?!weights_only)\))|joblib\.load\s*\([\s\S]{0,60}?\.(?:pt|pth|pkl|bin|ckpt|joblib)|pickle\.loads?\s*\([\s\S]{0,60}?\.(?:pt|pth|pkl|bin|ckpt))',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "OWASP_LLM": "LLM08:2025",
                    "MITRE_ATLAS": "AML.T0010",
                    "ISO_27001": "A.14.2.8",
                },
                "description": "Loading machine learning model checkpoints using Python pickle or `torch.load(..., weights_only=False)` permits arbitrary code execution (RCE) embedded inside crafted weights (__reduce__ payload).",
                "remediation": "Migrate to `safetensors` format (`safetensors.torch.load_file()`) or enforce `torch.load(..., weights_only=True)` on PyTorch 2.4+.",
                "mitre_id": "T1195.002",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise: Compromise Software Supply Chain",
                "cwe_id": "CWE-502",
            },
            {
                "id": "AISEC-SUPPLY-CHAIN-UNPINNED-HF-01",
                "title": "AI Supply Chain: Unpinned HuggingFace Hub Model Repository",
                "pattern": re.compile(
                    r'(?:from_pretrained|pipeline)\s*\(\s*["\'][a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+["\'](?![^)]*revision\s*=)',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "OWASP_LLM": "LLM08:2025",
                    "MITRE_ATLAS": "AML.T0010",
                },
                "description": "AI model or tokenizer loaded from HuggingFace Hub without specifying an immutable `revision` (commit SHA). If the upstream repository is compromised or modified, malicious weights will execute automatically.",
                "remediation": "Pin model downloads to an exact commit SHA: `AutoModel.from_pretrained('org/repo', revision='<commit-sha>')`.",
                "mitre_id": "T1195.002",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise",
                "cwe_id": "CWE-1357",
            },
            {
                "id": "AISEC-SUPPLY-CHAIN-PICKLE-FORMAT-ALERT-01",
                "title": "AI Model Format: Legacy Pickle Checkpoint Format (.pt / .bin) in Codebase",
                "pattern": re.compile(
                    r'["\'][a-zA-Z0-9_./-]+\.(?:pt|pth|bin|ckpt)["\']',
                    re.IGNORECASE,
                ),
                "severity": Severity.LOW,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "OWASP_LLM": "LLM08:2025",
                },
                "description": "Codebase references legacy PyTorch `.pt`/`.bin` model checkpoint files which are based on insecure Python pickle format.",
                "remediation": "Convert legacy checkpoints to the secure, zero-copy HuggingFace `safetensors` format.",
                "mitre_id": "T1195.002",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Supply Chain Compromise",
                "cwe_id": "CWE-502",
            },
        ]

    @property
    def name(self) -> str:
        return "AI Supply Chain & Model Checkpoint Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.AI_SECURITY

    @property
    def description(self) -> str:
        return "Audits AI pipelines for PyTorch pickle deserialization RCE, unpinned HuggingFace weights, and safetensors migration."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".ipynb", ".sh", ".yaml", ".yml"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["id"] != "AISEC-SUPPLY-CHAIN-PICKLE-FORMAT-ALERT-01":
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
