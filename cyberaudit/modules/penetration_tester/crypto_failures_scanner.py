"""
Cryptographic Failures & Randomness Scanner (AppSec / Red Teaming)
Detects:
- Use of broken or obsolete cryptographic hash algorithms (MD5, SHA1 for passwords) (CWE-328)
- Insecure block cipher modes (AES in ECB mode) (CWE-327)
- Predictable pseudo-random number generators for tokens/secrets (CWE-338)
- Hardcoded encryption keys and initialization vectors (CWE-321)
Mapped to MITRE ATT&CK: T1552.001, T1027
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class CryptoFailuresScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "CRYPTO-HASH-MD5-SHA1-01",
                "title": "Cryptographic Failure: Broken Hash Algorithm Used (MD5 / SHA-1)",
                "pattern": re.compile(
                    r'(?:hashlib\.(?:md5|sha1)|crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']|MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1)["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "MD5 and SHA-1 suffer from proven cryptographic collision attacks and must not be used for digital signatures, password hashing, or integrity guarantees.",
                "remediation": "For passwords, use Argon2id, bcrypt, or PBKDF2. For data integrity and signatures, use SHA-256 or SHA-512.",
                "mitre_id": "T1552",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials",
                "cwe_id": "CWE-328",
            },
            {
                "id": "CRYPTO-CIPHER-ECB-MODE-01",
                "title": "Cryptographic Failure: Insecure Block Cipher Mode (ECB Mode)",
                "pattern": re.compile(
                    r'(?:AES\.MODE_ECB|modes\.ECB\(\)|AES/ECB/PKCS5Padding|Cipher\.getInstance\s*\(\s*["\']AES["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "ECB (Electronic Codebook) mode encrypts identical plaintext blocks into identical ciphertext blocks, revealing data patterns and vulnerable to block replay attacks.",
                "remediation": "Use authenticated encryption modes like AES-GCM (Galois/Counter Mode) or ChaCha20-Poly1305 with unique nonces.",
                "mitre_id": "T1027",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Obfuscated Files or Information",
                "cwe_id": "CWE-327",
            },
            {
                "id": "CRYPTO-INSECURE-RANDOM-01",
                "title": "Cryptographic Failure: Predictable PRNG Used for Security Tokens",
                "pattern": re.compile(
                    r'(?:token|secret|key|salt|nonce|password)\s*=\s*.*(?:random\.random\(\)|random\.randint|Math\.random\(\)|rand\(\))',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "description": "Using non-cryptographic pseudo-random number generators (PRNGs) for security tokens, session keys, or password resets allows attackers to predict future values.",
                "remediation": "Use cryptographically secure random number generators: `secrets.token_hex()` in Python, `crypto.randomBytes()` in Node.js, or `SecureRandom` in Java.",
                "mitre_id": "T1552",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials",
                "cwe_id": "CWE-338",
            },
            {
                "id": "CRYPTO-HARDCODED-AES-KEY-01",
                "title": "Cryptographic Failure: Hardcoded Symmetric Encryption Key",
                "pattern": re.compile(
                    r'(?:AES\.new|Cipher\s*\(\s*algorithms\.AES)\s*\(\s*(?:b["\'][A-Za-z0-9+/=_-]{16,32}["\']|["\'][A-Za-z0-9+/=_-]{16,32}["\'])',
                    re.IGNORECASE,
                ),
                "severity": Severity.CRITICAL,
                "description": "Symmetric encryption key embedded directly in source code allows anyone with codebase access to decrypt all ciphertext.",
                "remediation": "Load encryption keys securely at runtime from Hardware Security Modules (HSM), Key Management Services (KMS), or environment secrets.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-321",
            },
        ]

    @property
    def name(self) -> str:
        return "Cryptographic Failures Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Detects broken hash algorithms (MD5/SHA-1), insecure block cipher modes (ECB), predictable PRNGs, and hardcoded keys."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".go", ".cs", ".php", ".rb"]

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
