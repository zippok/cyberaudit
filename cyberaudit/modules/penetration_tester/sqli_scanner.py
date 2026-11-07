"""
SQL & NoSQL Injection Scanner (AppSec / Penetration Testing)
Detects:
- SQL query string concatenation and f-strings without parameter binding (CWE-89)
- Unsafe raw ORM query execution (SQLAlchemy, Django, Hibernate)
- NoSQL injection vectors in MongoDB queries ($where, raw object query injection) (CWE-943)
Mapped to MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class SqlInjectionScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-SQLI-CONCAT-01",
                "title": "SQL Injection: String Concatenation in SQL Query",
                "pattern": re.compile(
                    r'(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[\w\s,*()=\'"]{1,60}?(?:\+\s*(?:req|request|input|param|\$|user|id)|f["\'].*\{.*\}["\']|%\s*\w+)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "SQL statement constructed by directly concatenating or formatting user-controlled variables, exposing the database to SQL Injection (SQLi).",
                "remediation": "Use parameterized queries (Prepared Statements) with placeholders (?, %s, or named parameters :param) instead of string concatenation.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-89",
            },
            {
                "id": "APPSEC-SQLI-RAW-EXEC-01",
                "title": "SQL Injection: Direct Execution of Raw Unescaped SQL Statement",
                "pattern": re.compile(
                    r'(?:cursor\.execute|db\.raw|session\.execute)\s*\(\s*f["\'][\s\S]{0,150}?(?:SELECT|INSERT|UPDATE|DELETE)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Raw database query executed using Python f-string or string formatting without bound parameters.",
                "remediation": "Pass parameters as a tuple/dictionary in the execute() method: `cursor.execute('SELECT * FROM tbl WHERE id = %s', (val,))`.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-89",
            },
            {
                "id": "APPSEC-NOSQLI-MONGODB-01",
                "title": "NoSQL Injection: Raw Request Body Passed into MongoDB Query",
                "pattern": re.compile(
                    r'(?:find|findOne|deleteMany|updateOne)\s*\(\s*(?:req\.body|request\.get_json\(\)|req\.query)\s*\)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Passing entire unvalidated request payloads into MongoDB query functions allows attackers to inject query selectors ($ne, $gt, $regex) to bypass authentication.",
                "remediation": "Validate input schema and sanitize parameters. Ensure query filters explicitly cast inputs to primitives (e.g. String(req.body.user)).",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-943",
            },
            {
                "id": "APPSEC-NOSQLI-WHERE-EVAL-01",
                "title": "NoSQL Injection: MongoDB $where JavaScript Evaluation",
                "pattern": re.compile(
                    r'["\']?\$where["\']?\s*:\s*(?:req|request|input|f["\']|`.*`|\+)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Dynamic evaluation of arbitrary JavaScript via MongoDB $where clause with untrusted input.",
                "remediation": "Avoid using $where clauses. Refactor queries into native MongoDB aggregation pipelines and standard operators.",
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-943",
            },
        ]

    @property
    def name(self) -> str:
        return "SQL & NoSQL Injection Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Audits application source code for SQL injection, raw query concatenation, and MongoDB NoSQL injection."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".php", ".java", ".go", ".cs", ".rb"]

    def should_scan(self, file_path: str) -> bool:
        import os
        norm = file_path.replace("\\", "/").lower()
        if norm.endswith((".min.js", ".min.css", ".bundle.js", ".map")):
            return False
        parts = set(norm.split("/"))
        if any(d in parts for d in {"libs", "vendor", "node_modules", "3rdparty", "third_party"}):
            return False
        ext = os.path.splitext(norm)[1]
        return ext in self.file_extensions

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
