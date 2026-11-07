"""
Insecure Deserialization Scanner (Penetration Tester & AppSec)
Detects:
- Python: pickle.loads(), _pickle.loads(), marshal.loads(), shelve.open() (CWE-502)
- Python: yaml.load() without SafeLoader (PyYAML unsafe deserialization)
- Node.js: node-serialize.unserialize(), serialize-javascript with eval()
- Java: ObjectInputStream.readObject(), XMLDecoder.readObject()
- .NET / C#: BinaryFormatter.Deserialize(), NetDataContractSerializer
- PHP: unserialize() on untrusted user payloads
- Ruby: Marshal.load() on arbitrary input streams
Mapped to MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class DeserializationScanner(BaseScanner):
    """
    Dedicated scanner inspecting object deserialization mechanisms across Python,
    Java, Node.js, .NET, PHP, and Ruby for unsafe arbitrary object instantiation.
    """

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "APPSEC-DESERIAL-PYTHON-PICKLE-01",
                "title": "Insecure Deserialization: Python pickle / marshal / shelve Ingestion",
                "pattern": re.compile(
                    r'(?:pickle|_pickle|cPickle|marshal|_marshal)\s*\.\s*(?:loads?|load)\s*\(|shelve\.open\s*\(',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Deserializing data with Python's standard `pickle` or `marshal` module executes arbitrary code "
                    "embedded in the serialized stream via the `__reduce__` or `__reduce_ex__` magic methods. "
                    "Pickle is explicitly not secure against erroneous or maliciously constructed data."
                ),
                "remediation": (
                    "Replace pickle with safe, standard data interchange formats such as JSON, Protocol Buffers, or MessagePack. "
                    "If binary serialization is mandatory, sign payloads with HMAC (SHA-256) and verify the signature before unpickling."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-502",
            },
            {
                "id": "APPSEC-DESERIAL-PYYAML-UNSAFE-01",
                "title": "Insecure Deserialization: PyYAML yaml.load() Without SafeLoader",
                "pattern": re.compile(
                    r'yaml\s*\.\s*load\s*\([\s\S]{0,120}?(?:Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader|CLoader|FullLoader)|(?!\s*Loader\s*=\s*(?:yaml\.)?SafeLoader)\s*[,)])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Calling `yaml.load()` without specifying `Loader=yaml.SafeLoader` permits execution of arbitrary Python code "
                    "through YAML tags such as `!!python/object/apply:os.system`."
                ),
                "remediation": (
                    "Always use `yaml.safe_load(stream)` or explicitly provide `Loader=yaml.SafeLoader`."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-502",
            },
            {
                "id": "APPSEC-DESERIAL-NODE-SERIALIZE-01",
                "title": "Insecure Deserialization: Node.js node-serialize.unserialize() Execution",
                "pattern": re.compile(
                    r'(?:require\s*\(\s*["\']node-serialize["\']\s*\)[\s\S]{0,500}?\.\s*unserialize\s*\(|(?:serialize|nodeSerialize)\.unserialize\s*\()',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "The `node-serialize` package executes Immediately Invoked Function Expressions (IIFE) "
                    "embedded in serialized payloads (`_$$ND_FUNC$$_...()`), leading to remote code execution in Node.js."
                ),
                "remediation": (
                    "Remove `node-serialize`. Parse data using standard `JSON.parse()` with schema validation (e.g. Zod or AJV)."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-502",
            },
            {
                "id": "APPSEC-DESERIAL-JAVA-OBJECTINPUT-01",
                "title": "Insecure Deserialization: Java ObjectInputStream.readObject() / XMLDecoder",
                "pattern": re.compile(
                    r'(?:ObjectInputStream[\s\S]{0,150}?\breadObject\s*\(|XMLDecoder[\s\S]{0,150}?\breadObject\s*\(|new\s+ObjectInputStream\s*\([^)]+\)\s*\.readObject\s*\()',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "Java `readObject()` deserializes arbitrary byte streams. When gadget classes (e.g. Apache Commons Collections, "
                    "Spring, Groovy) exist on the classpath, an attacker can construct chains leading to arbitrary command execution."
                ),
                "remediation": (
                    "Migrate from Java native serialization to JSON/protobuf. If legacy serialization is required, implement "
                    "an `ObjectInputFilter` (JEP 290) to strictly whitelist authorized classes."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-502",
            },
            {
                "id": "APPSEC-DESERIAL-DOTNET-BINARYFORMATTER-01",
                "title": "Insecure Deserialization: .NET BinaryFormatter.Deserialize()",
                "pattern": re.compile(
                    r'(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter)\s*\.\s*Deserialize\s*\(',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "`BinaryFormatter` in .NET is inherently insecure and cannot be made secure. Deserializing untrusted binary streams "
                    "allows attackers to instantiate arbitrary types and achieve code execution via type confusion gadget chains."
                ),
                "remediation": (
                    "Microsoft officially discourages `BinaryFormatter`. Replace with `System.Text.Json.JsonSerializer` or `XmlSerializer`."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-502",
            },
            {
                "id": "APPSEC-DESERIAL-PHP-UNSERIALIZE-01",
                "title": "Insecure Deserialization: PHP unserialize() Without Class Whitelist",
                "pattern": re.compile(
                    r'unserialize\s*\(\s*(?:\$_GET|\$_POST|\$_COOKIE|\$_REQUEST|\$input|\$data)(?![\s\S]{0,60}?allowed_classes\s*=>\s*false)',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "stride": StrideCategory.TAMPERING.value,
                "description": (
                    "PHP `unserialize()` triggers magic methods (`__wakeup`, `__destruct`, `__toString`) on instantiated objects. "
                    "Property-Oriented Programming (POP) chains in installed vendor packages enable arbitrary code execution."
                ),
                "remediation": (
                    "Use `json_decode()` instead of `unserialize()`. If `unserialize()` is unavoidable, enforce `['allowed_classes' => false]`."
                ),
                "mitre_id": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "cwe_id": "CWE-502",
            },
        ]

    @property
    def name(self) -> str:
        return "Insecure Deserialization Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Audits binary and object deserialization APIs (pickle, PyYAML, Java readObject, BinaryFormatter, PHP unserialize) for arbitrary code execution vectors."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".php", ".rb", ".cs", ".go"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule in self.rules:
            pattern = rule["pattern"]
            matches = list(pattern.finditer(content))
            for match in matches:
                start_char = match.start()
                line_idx = content[:start_char].count("\n") + 1
                matched_text = match.group(0).strip()
                snippet = matched_text[:300] + "..." if len(matched_text) > 300 else matched_text

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
                        code_snippet=snippet,
                        remediation=rule["remediation"],
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        cwe_id=rule.get("cwe_id"),
                        stride_category=rule.get("stride"),
                        confidence="HIGH",
                    )
                )

        return findings
