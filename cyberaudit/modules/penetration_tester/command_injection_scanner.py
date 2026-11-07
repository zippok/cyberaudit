"""
Command Injection, Deserialization & SSTI Scanner
Detects:
- OS Command Injection (subprocess with shell=True, os.system, exec, eval) (CWE-78)
- Insecure Deserialization (Python pickle, PyYAML unsafe loader, PHP unserialize) (CWE-502)
- Server-Side Template Injection (SSTI in Jinja2 / Flask render_template_string) (CWE-1336)
Mapped to MITRE ATT&CK: T1059, T1190
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class CommandInjectionScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-CMDI-SUBPROCESS-01",
                "title": "Command Injection: Subprocess Invoked with shell=True",
                "pattern": re.compile(
                    r'(?:subprocess\.(?:Popen|run|call|check_output)|child_process\.exec)\s*\([\s\S]{0,120}?(?:shell\s*=\s*True|\+\s*(?:req|input|param|cmd))',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Executing system commands through a shell interpreter (`shell=True`) with dynamic variables permits arbitrary operating system command execution (RCE).",
                "remediation": "Set `shell=False` and pass arguments as an explicit array of strings: `subprocess.run(['ping', '-c', '1', host])`.",
                "mitre_id": "T1059",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter",
                "cwe_id": "CWE-78",
            },
            {
                "id": "APPSEC-CMDI-OS-SYSTEM-01",
                "title": "Command Injection: Untrusted Input in os.system / eval / exec",
                "pattern": re.compile(
                    r'(?:os\.system|popen|exec|eval)\s*\(\s*(?:f["\'][\s\S]*?\{.*\}|(?:["\'][^"\']*["\']|\w+)\s*\+\s*(?:req|input|param|arg|\$|\w*user|\w*cmd))',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Direct concatenation of untrusted variables into os.system, eval, or exec functions.",
                "remediation": "Avoid invoking shell interpreters with formatted strings. Use safe native APIs without shell wrapping.",
                "mitre_id": "T1059",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter",
                "cwe_id": "CWE-78",
            },
            {
                "id": "APPSEC-DESERIAL-PICKLE-01",
                "title": "Insecure Deserialization: Untrusted Object Deserialization (pickle / unserialize)",
                "pattern": re.compile(
                    r'(?:pickle\.loads?\s*\(|unserialize\s*\(|yaml\.load\s*\([\s\S]{0,60}?Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader)|BinaryFormatter\.Deserialize)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Deserializing untrusted data streams (via Python pickle, PHP unserialize, or PyYAML unsafe loader) allows arbitrary code execution via magic methods (__reduce__, __wakeup__).",
                "remediation": "Use safe serialization formats like JSON, Protocol Buffers, or `yaml.safe_load()`. Never deserialize raw binary streams from untrusted sources.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-502",
            },
            {
                "id": "APPSEC-SSTI-JINJA-01",
                "title": "Server-Side Template Injection: Untrusted Input in render_template_string",
                "pattern": re.compile(
                    r'render_template_string\s*\(\s*(?:f["\'][\s\S]*?\{.*\}|.*?\+\s*(?:req|user|input|param))',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Passing user-controlled input directly into the template string rather than context variables exposes the server to SSTI and Remote Code Execution.",
                "remediation": "Use static template files with `render_template('template.html', var=user_input)` so variables are treated as data, not code.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-1336",
            },
        ]

    @property
    def name(self) -> str:
        return "Command Injection & Deserialization Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Detects OS command injection, untrusted deserialization (pickle/PyYAML), and Server-Side Template Injection (SSTI)."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".php", ".java", ".go", ".cs", ".rb"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
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
