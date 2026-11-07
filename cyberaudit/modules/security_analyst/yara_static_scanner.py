"""
YARA & Static Malware Analysis Scanner
Implements pattern-matching rules and heuristics covering:
- Web Shell signatures (PHP, JSP, ASPX, Python)
- Obfuscated malicious scripts (PowerShell download cradles, base64 payloads)
- Malicious office macros and MalDoc droppers (VBA AutoOpen, ShellExecute)
- Packed binary indicators (UPX headers, anomalous sections)
Mapped to MITRE ATT&CK: T1505.003, T1059.001, T1027, T1204.002
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class YaraStaticScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        # Precompiled detection signatures (regex-based YARA-equivalent rules)
        self.signatures = [
            {
                "id": "MAL-WEBSHELL-PHP-01",
                "title": "PHP Web Shell - Dynamic Code Execution with Obfuscation",
                "pattern": re.compile(
                    r"(?:eval|assert|passthru|shell_exec|system)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Detected obfuscated execution payload typically characteristic of PHP web shells (e.g. c99, r57, b374k).",
                "remediation": "Isolate the file immediately. Inspect for unauthorized access and remove backdoors from web root.",
                "mitre_id": "T1505.003",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Server Software Component: Web Shell",
                "file_types": [".php", ".phtml", ".php5", ".inc", ".txt"],
            },
            {
                "id": "MAL-WEBSHELL-PHP-02",
                "title": "PHP Raw Request Command Execution (Web Shell)",
                "pattern": re.compile(
                    r"(?:eval|assert|system|exec|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\[",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Unsanitized direct execution of HTTP parameters into shell execution functions (one-liner web shell).",
                "remediation": "Remove the backdoor code. Audit web server access logs for requests to this file.",
                "mitre_id": "T1505.003",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Server Software Component: Web Shell",
                "file_types": [".php", ".phtml", ".php5"],
            },
            {
                "id": "MAL-WEBSHELL-JSP-01",
                "title": "JSP Web Shell - Runtime Process Execution",
                "pattern": re.compile(
                    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter\s*\(",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "JSP backdoor allowing remote command execution via HTTP request parameters.",
                "remediation": "Remove the JSP file, verify servlet container permissions and rotate admin credentials.",
                "mitre_id": "T1505.003",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Server Software Component: Web Shell",
                "file_types": [".jsp", ".jspx"],
            },
            {
                "id": "MAL-PS-CRADLE-01",
                "title": "PowerShell In-Memory Download Cradle",
                "pattern": re.compile(
                    r"(?:IEX|Invoke-Expression)\s*(?:\(|;|\s)+(?:New-Object\s+Net\.WebClient|\[Net\.HttpWebRequest\]|iwr|Invoke-WebRequest|Invoke-RestMethod).*(?:DownloadString|DownloadData)",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Classic PowerShell download cradle used to fetch and execute secondary payloads directly in memory without writing to disk.",
                "remediation": "Review the script origin. Ensure PowerShell Constrained Language Mode (CLM) and Script Block Logging (EID 4104) are enforced.",
                "mitre_id": "T1059.001",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter: PowerShell",
                "file_types": [".ps1", ".bat", ".cmd", ".vbs", ".sh", ".py"],
            },
            {
                "id": "MAL-PS-OBFUSC-01",
                "title": "Suspicious Obfuscated PowerShell Command-Line Flags",
                "pattern": re.compile(
                    r"powershell(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*(?:-w(?:indowstyle)?\s+hidden|-nop(?:rofile)?|-enc(?:odedcommand)?)\s+[A-Za-z0-9+/=]{40,}",
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "PowerShell execution with hidden window and Base64 encoded payload, typical of dropper scripts and living-off-the-land attacks.",
                "remediation": "Decode and analyze the Base64 payload. Block unauthorized PowerShell execution via AppLocker / WDAC.",
                "mitre_id": "T1027",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Obfuscated Files or Information",
                "file_types": [".ps1", ".bat", ".cmd", ".txt", ".json", ".yml", ".yaml"],
            },
            {
                "id": "MAL-MALDOC-VBA-01",
                "title": "Malicious VBA Macro Execution Pattern",
                "pattern": re.compile(
                    r"(?:AutoOpen|Workbook_Open|Document_Open)\s*\(\s*\)[\s\S]*?(?:ShellExecute|WScript\.Shell|URLDownloadToFile|CreateObject\s*\(\s*\"WScript\.Shell\")",
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "VBA Macro document automatically executing shell commands or downloading files upon opening.",
                "remediation": "Disable office macros globally via Group Policy (GPO) for all internet-origin documents.",
                "mitre_id": "T1204.002",
                "mitre_tactic": "Execution",
                "mitre_technique": "User Execution: Malicious File",
                "file_types": [".vba", ".bas", ".vbs", ".cls", ".txt"],
            },
            {
                "id": "MAL-PACKER-UPX-01",
                "title": "UPX Packed Executable Signature Detected",
                "pattern": re.compile(r"\.UPX0[\x00-\x20].{0,100}?\bUPX1|\bUPX0\x00[\s\S]{0,32}UPX1\x00", re.IGNORECASE),
                "severity": Severity.MEDIUM,
                "description": "File contains UPX packer section headers commonly used to pack and compress malware to evade basic AV signatures.",
                "remediation": "Unpack the binary with `upx -d` and submit for full dynamic sandbox analysis.",
                "mitre_id": "T1027.002",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Obfuscated Files: Software Packing",
                "file_types": [".exe", ".dll", ".bin", ".sys"],
            },
        ]

    @property
    def name(self) -> str:
        return "YARA & Static Malware Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ANALYST

    @property
    def description(self) -> str:
        return "Static analysis engine detecting web shells, obfuscated PowerShell cradles, MalDoc macros, and packed binaries."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        for sig in self.signatures:
            # Check if this rule applies to this file type
            if sig.get("file_types"):
                if not any(lower_path.endswith(ext) for ext in sig["file_types"]):
                    continue

            # Check match
            match = sig["pattern"].search(content)
            if match:
                # Calculate line number
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1

                # Extract snippet
                snippet_start = max(0, start_pos - 40)
                snippet_end = min(len(content), match.end() + 60)
                snippet = content[snippet_start:snippet_end].replace("\r", "")

                finding = Finding(
                    id=sig["id"],
                    title=sig["title"],
                    description=sig["description"],
                    severity=sig["severity"],
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet.strip(),
                    remediation=sig["remediation"],
                    mitre_id=sig["mitre_id"],
                    mitre_tactic=sig["mitre_tactic"],
                    mitre_technique=sig["mitre_technique"],
                    cwe_id="CWE-506",  # Embedded Malicious Code
                )
                findings.append(finding)

        return findings
