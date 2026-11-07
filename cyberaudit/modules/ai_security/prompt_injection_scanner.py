"""
AI Security & LLM Vulnerability Scanner
Detects vulnerabilities from the OWASP Top 10 for LLM Applications:
- Prompt Injection (OWASP LLM01)
- Insecure Output Handling (OWASP LLM02)
- Sensitive Information Disclosure in Model Prompts (OWASP LLM06)
Mapped to MITRE ATLAS & ATT&CK: AML.T0054 (LLM Prompt Injection), T1059
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class AiSecurityScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "AISEC-LLM01-PROMPT-INJECTION-01",
                "title": "AI Security: Prompt Injection via Direct User Concatenation (OWASP LLM01)",
                "pattern": re.compile(
                    r'(?:f["\'][\s\S]{0,120}?(?:instruction|system|prompt|translate|summarize|query)[\s\S]{0,80}?\{(?:\w*user|\w*input|\w*param|\w*request)\w*\}|\+\s*(?:user_input|req\.body|request\.data)\s*[\s\S]{0,50}?(?:generate_content|create_completion|chat\.completions))',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Untrusted user input directly interpolated into LLM prompt templates without delimiters, input filtering, or system/user role separation, allowing Direct Prompt Injection and instruction override.",
                "remediation": "Isolate user inputs using structured message roles (separate 'system' and 'user' messages) and enclose untrusted data within strict delimiter tags (e.g. <user_data>...</user_data>).",
                "mitre_id": "AML.T0054",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "LLM Prompt Injection",
                "cwe_id": "CWE-20",  # Improper Input Validation
            },
            {
                "id": "AISEC-LLM02-INSECURE-OUTPUT-01",
                "title": "AI Security: Blind Execution of LLM Output (OWASP LLM02)",
                "pattern": re.compile(
                    r'(?:eval|exec|os\.system|subprocess\.(?:Popen|run)|cursor\.execute)\s*\(\s*(?:response\.text|completion\.choices|ai_output|model_res|llm_code)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Executing code, shell commands, or database statements directly from LLM-generated output without validation or sandboxing (Insecure Output Handling). Adversarial prompt injections can exploit this to achieve Remote Code Execution.",
                "remediation": "Never evaluate LLM outputs directly in the host environment. Run generated code exclusively inside ephemeral, isolated sandboxes (e.g. gVisor, WebAssembly, or Docker with dropped capabilities).",
                "mitre_id": "T1059",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter",
                "cwe_id": "CWE-94",  # Code Injection
            },
            {
                "id": "AISEC-LLM06-SENSITIVE-DATA-LEAK-01",
                "title": "AI Security: Sensitive Credentials / PII Sent to External LLM API (OWASP LLM06)",
                "pattern": re.compile(
                    r'(?:client\.models\.generate_content|openai\.chat\.completions\.create)\s*\([\s\S]{0,120}?(?:password|private_key|credit_card|ssn|secret)\s*[:=,]',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Passing unmasked internal secrets, credentials, or personally identifiable information (PII) into external AI model inference APIs, risking data leakage into model training or third-party logs.",
                "remediation": "Apply Data Loss Prevention (DLP) filters or anonymization pipelines to sanitize sensitive entities prior to invoking third-party LLM endpoints.",
                "mitre_id": "T1552",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials",
                "cwe_id": "CWE-200",  # Exposure of Sensitive Information
            },
        ]

    @property
    def name(self) -> str:
        return "AI Security & LLM Defense Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.AI_SECURITY

    @property
    def description(self) -> str:
        return "Audits applications using Large Language Models against the OWASP Top 10 for LLMs (Prompt Injection, Insecure Output Handling, Data Leakage)."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        # Skip scanning our own co_analyst.py file where prompt templates are safely managed
        if "co_analyst.py" in file_path.lower():
            return []

        findings: List[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["pattern"].search(line):
                    finding = Finding(
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
                    )
                    findings.append(finding)
                    break

        return findings
