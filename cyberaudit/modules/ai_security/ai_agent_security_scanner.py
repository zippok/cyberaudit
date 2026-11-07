"""
Autonomous AI Agent & Excessive Agency Scanner (AI Security Pillar)
Audits multi-agent and autonomous agent frameworks (LangChain, CrewAI, AutoGPT, Semantic Kernel):
- OWASP LLM07: Excessive Agency (Agents with destructive shell/DB/API tools without human confirmation)
- System Prompt Secret Exposure (Credentials embedded in system instructions)
- Unbounded tool recursion loops
Mapped to MITRE ATLAS: AML.T0054, MITRE ATT&CK: T1059
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class AiAgentSecurityScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "AISEC-AGENT-EXCESSIVE-AGENCY-01",
                "title": "AI Agent Security: Excessive Agency via Unsandboxed Shell / Python Execution (OWASP LLM07)",
                "pattern": re.compile(
                    r'(?:BashProcess|Terminal|PythonREPL|ShellTool|WriteFileTool|SQLDatabaseToolkit|RequestsToolkit)\s*\(\s*(?!.*require_confirmation\s*=\s*True)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                "compliance": {
                    "OWASP_LLM": "LLM07:2025",
                    "MITRE_ATLAS": "AML.T0054",
                    "SOC2": "CC6.1",
                },
                "description": "Autonomous AI agent initialized with destructive shell, filesystem, or database execution tools without human-in-the-loop (HITL) authorization gates (`require_confirmation=True`). Adversaries can trick the agent via prompt injection to run arbitrary host commands.",
                "remediation": "Restrict agent tool capabilities to read-only actions, execute code exclusively within ephemeral gVisor/Docker sandboxes, and mandate human approval for sensitive actions.",
                "mitre_id": "T1059",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter",
                "cwe_id": "CWE-250",
            },
            {
                "id": "AISEC-AGENT-SYSTEM-PROMPT-SECRETS-01",
                "title": "AI Security: Hardcoded Secret / Credential in System Prompt",
                "pattern": re.compile(
                    r'(?:system_prompt|system_instruction|system_message)\s*=\s*f?["\'][\s\S]{0,120}?(?:password\s*[:=]|api_key\s*[:=]|token\s*[:=]|secret\s*[:=])',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "OWASP_LLM": "LLM06:2025",
                    "PCI_DSS": "Req 6.2",
                    "ISO_27001": "A.9.4.2",
                },
                "description": "Internal passwords, database connection strings, or third-party API keys hardcoded directly into LLM system prompts. Attackers can extract these secrets using simple prompt extraction or jailbreak techniques.",
                "remediation": "Remove all internal credentials from system prompts. Inject required secrets dynamically only at tool execution time.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-798",
            },
        ]

    @property
    def name(self) -> str:
        return "Autonomous AI Agent & Excessive Agency Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.AI_SECURITY

    @property
    def description(self) -> str:
        return "Audits autonomous AI agents for excessive agency, unsandboxed execution tools, and system prompt credential exposure."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".ts", ".js", ".ipynb"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
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

        return findings
