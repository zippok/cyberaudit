"""
Cryptographic Agility & Post-Quantum (PQC) Readiness Scanner
Audits modern applications for broken/obsolete cryptography (DES, RC4, MD5, SHA-1),
static/zeroed initialization vectors (IVs), insufficient RSA key lengths (<2048 bits),
and evaluates cryptographic agility and post-quantum preparedness based on NIST FIPS 203 (ML-KEM)
and FIPS 204 (ML-DSA).
"""

import os
import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class CryptoPqcAgilityScanner(BaseScanner):
    __test__ = False  # Prevent pytest collector from discovering this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Cryptographic Agility & Post-Quantum (PQC) Readiness Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Audits applications for obsolete ciphers (DES/RC4), weak digests (MD5/SHA1), static IVs, insufficient RSA key lengths, and evaluates PQC transition posture."

    @property
    def supported_extensions(self) -> Set[str]:
        return {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".cs", ".c", ".cpp", ".rs", ".php"}

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # 1. Broken / Deprecated Ciphers (DES, 3DES, RC4, Blowfish)
        broken_cipher_patterns = [
            (re.compile(r'\b(DES|ARC4|Blowfish)\.new\b', re.IGNORECASE), "DES/RC4/Blowfish in Python PyCryptodome"),
            (re.compile(r'Cipher\.getInstance\s*\(\s*["\'](DES|DESede|RC4|ARCFOUR|Blowfish)\b', re.IGNORECASE), "Legacy cipher in Java/Kotlin Cryptography Architecture"),
            (re.compile(r'createCipher(iv)?\s*\(\s*["\'](des|des-ede3|rc4|blowfish)\b', re.IGNORECASE), "Deprecated cipher in Node.js Crypto API"),
            (re.compile(r'mcrypt_encrypt\s*\(', re.IGNORECASE), "Obsolete PHP mcrypt extension"),
        ]

        for idx, line in enumerate(lines, 1):
            for pattern, desc in broken_cipher_patterns:
                if pattern.search(line):
                    findings.append(Finding(
                        id="CRYPTO-BROKEN-CIPHER",
                        title=f"Broken / Deprecated Symmetric Cipher Detected: {desc}",
                        description="The application instantiates obsolete ciphers (DES, 3DES, RC4, or Blowfish). DES and RC4 have known practical cryptanalytic breaks (Sweet32 64-bit block collision, RC4 keystream bias), enabling plaintext recovery.",
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        remediation="Migrate immediately to AES-256-GCM or ChaCha20-Poly1305 with authenticated encryption (AEAD).",
                        mitre_id="T1553",
                        mitre_tactic="Defense Evasion",
                        mitre_technique="Subvert Trust Controls: Compromised Cryptography",
                        cwe_id="CWE-327",
                        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                        compliance_controls={"NIST SP 800-131A": "Deprecated", "PCI-DSS": "Requirement 3.4", "ISO 27001": "A.8.24"},
                    ))

        # 2. Insecure / Collidable Hashes (MD5, SHA-1 in cryptographic contexts)
        weak_hash_patterns = [
            (re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE), "Python hashlib MD5/SHA-1"),
            (re.compile(r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-?1)["\']\s*\)', re.IGNORECASE), "Java MessageDigest MD5/SHA-1"),
            (re.compile(r'crypto\.createHash\s*\(\s*["\'](md5|sha1)["\']\s*\)', re.IGNORECASE), "Node.js crypto MD5/SHA-1"),
        ]

        for idx, line in enumerate(lines, 1):
            for pattern, desc in weak_hash_patterns:
                if pattern.search(line):
                    # Exclude non-cryptographic comment tags or clearly non-security hash (e.g. gravatar)
                    if "gravatar" in line.lower() or "etag" in line.lower():
                        continue
                    findings.append(Finding(
                        id="CRYPTO-WEAK-HASH-ALGORITHM",
                        title=f"Weak Cryptographic Hash Function ({desc})",
                        description="The application uses MD5 or SHA-1 for hashing. Both algorithms suffer from practical collision attacks (SHAttered, Flame malware MD5 collision). They MUST NOT be used for digital signatures, token generation, or integrity validation.",
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        remediation="Upgrade to SHA-256, SHA-384, SHA-512, or SHA-3 for digest operations. For password storage, use Argon2id, bcrypt, or scrypt.",
                        mitre_id="T1110",
                        mitre_tactic="Credential Access",
                        mitre_technique="Brute Force: Weak Cryptographic Hash",
                        cwe_id="CWE-328",
                        stride_category=StrideCategory.TAMPERING.value,
                        compliance_controls={"NIST FIPS 180-4": "SHA-256 Minimum", "PCI-DSS": "Requirement 3.4"},
                    ))

        # 3. Static or Zeroed Initialization Vector (IV) / Nonce Re-use
        static_iv_patterns = [
            (re.compile(r'iv\s*=\s*(b["\'][0-9a-zA-Z\s]{8,32}["\']|["\'][0-9a-zA-Z]{16,32}["\'])', re.IGNORECASE), "Hardcoded static string literal used as IV"),
            (re.compile(r'iv\s*=\s*(b["\']\\x00{16}["\']|new\s+byte\[16\]\s*;|Buffer\.alloc\(16,\s*0\))', re.IGNORECASE), "Zeroed static buffer used as IV"),
            (re.compile(r'createCipheriv\s*\(\s*[^,]+,\s*[^,]+,\s*Buffer\.from\(["\'][0-9a-fA-F]{16,32}["\']', re.IGNORECASE), "Static hex string passed as IV in createCipheriv"),
        ]

        for idx, line in enumerate(lines, 1):
            for pattern, desc in static_iv_patterns:
                if pattern.search(line):
                    findings.append(Finding(
                        id="CRYPTO-STATIC-INITIALIZATION-VECTOR",
                        title=f"Static or Hardcoded Initialization Vector (IV): {desc}",
                        description="The cryptographic operation employs a hardcoded, static, or zeroed Initialization Vector (IV). Reusing IVs with the same secret key in CBC mode allows ciphertext malleability and pattern leakage; in GCM or CTR modes, IV reuse completely breaks confidentiality and allows keystream recovery.",
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        remediation="Generate a fresh, cryptographically secure pseudo-random IV for every encryption operation using secrets.token_bytes(16) in Python, crypto.randomBytes(12/16) in Node.js, or SecureRandom in Java.",
                        mitre_id="T1553",
                        mitre_tactic="Defense Evasion",
                        mitre_technique="Subvert Trust Controls: Predictable IV",
                        cwe_id="CWE-329",
                        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                        compliance_controls={"NIST SP 800-38A": "Unpredictable IV", "PCI-DSS": "Requirement 3.5"},
                    ))

        # 4. Insufficient RSA Key Length (< 2048 bits)
        weak_key_patterns = [
            re.compile(r'RSA\.generate\s*\(\s*(512|1024)\b'),
            re.compile(r'modulusLength\s*:\s*(512|1024)\b'),
            re.compile(r'keySize\s*=\s*(512|1024)\b'),
            re.compile(r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']\s*\).*\.initialize\s*\(\s*(512|1024)\b'),
        ]

        for idx, line in enumerate(lines, 1):
            for pattern in weak_key_patterns:
                match = pattern.search(line)
                if match:
                    bits = match.group(1)
                    findings.append(Finding(
                        id="CRYPTO-INSUFFICIENT-RSA-KEY-SIZE",
                        title=f"Insufficient RSA Key Size ({bits} bits < 2048 minimum standard)",
                        description=f"The application generates or requires an RSA key of {bits} bits. RSA keys under 2048 bits are factorable by modern computing clusters using the General Number Field Sieve (GNFS) and violate international security compliance mandates.",
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        remediation="Ensure RSA keys are at least 3072 bits (or minimum 2048 bits for legacy transition), or migrate to Elliptic Curve Cryptography (Ed25519, NIST P-384).",
                        mitre_id="T1552",
                        mitre_tactic="Credential Access",
                        mitre_technique="Unsecured Credentials: Weak Cryptographic Keys",
                        cwe_id="CWE-326",
                        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                        compliance_controls={"NIST SP 800-57": "Part 1 Rev. 5", "PCI-DSS": "Requirement 3.5", "BSI TR-02102": "3000 bits"},
                    ))

        # 5. Post-Quantum Cryptography (PQC) Agility & Readiness Check
        classical_pki_patterns = [
            re.compile(r'\b(generateKeyPair|KeyPairGenerator|RSA\.generate|ecdh\.computeSecret)\b'),
        ]

        has_classical_pki = False
        pki_line = 0
        for idx, line in enumerate(lines, 1):
            for pattern in classical_pki_patterns:
                if pattern.search(line):
                    has_classical_pki = True
                    pki_line = idx
                    break
            if has_classical_pki:
                break

        if has_classical_pki:
            findings.append(Finding(
                id="CRYPTO-PQC-AGILITY-ADVISORY",
                title="Cryptographic Agility: Classical Asymmetric Cryptography Without PQC Hybrid Shielding",
                description="The module utilizes classical public-key cryptography (RSA/ECDH/ECDSA). Under Shor's Algorithm running on Cryptanalytically Relevant Quantum Computers (CRQCs), all standard discrete-log and factorization schemes will be compromised. Sensitive data with high longevity is vulnerable to 'Harvest Now, Decrypt Later' (HNDL).",
                severity=Severity.LOW,
                pillar=self.pillar,
                scanner_name=self.name,
                file_path=file_path,
                line_number=pki_line,
                code_snippet="Classical Asymmetric PKI / Key Exchange in use",
                remediation="Incorporate Cryptographic Agility architecture: isolate cryptographic primitives behind abstraction interfaces to enable plug-and-play migration to NIST FIPS 203 (ML-KEM / Kyber) and NIST FIPS 204 (ML-DSA / Dilithium) hybrid key exchange schemes.",
                mitre_id="T1553",
                mitre_tactic="Defense Evasion",
                mitre_technique="Subvert Trust Controls: Quantum Vulnerability",
                cwe_id="CWE-327",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                compliance_controls={"NIST PQC": "FIPS 203 / FIPS 204", "NSA CNSA 2.0": "PQC Timeline", "ISO 27001": "A.8.24"},
            ))

        return findings
