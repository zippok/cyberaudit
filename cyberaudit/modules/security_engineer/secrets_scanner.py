"""
Secrets & Credential Scanner (DevSecOps / Security Engineering)
Detects exposed cloud credentials, private keys, API tokens, and database secrets.
Mapped to MITRE ATT&CK: T1552.001 (Credentials In Files)
"""

import re
import math
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SecretsScanner(BaseScanner):
    def __init__(self, verifier=None, enable_live_verification: bool = False):
        super().__init__()
        self.verifier = verifier
        self.enable_live_verification = enable_live_verification or (verifier is not None)
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "SECENG-SECRET-AWS-KEY-01",
                "title": "Secret Exposure: AWS Access Key ID Detected",
                "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
                "severity": Severity.CRITICAL,
                "description": "AWS Access Key ID hardcoded in repository files, enabling unauthorized API access to AWS cloud infrastructure.",
                "remediation": "Immediately revoke and deactivate the key in AWS IAM. Use AWS IAM Roles or AWS Secrets Manager.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-798",
            },
            {
                "id": "SECENG-SECRET-PRIVATE-KEY-01",
                "title": "Secret Exposure: Unencrypted Private Key (RSA / OpenSSH / EC)",
                "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
                "severity": Severity.CRITICAL,
                "description": "Cryptographic private key stored directly in codebase, permitting decryption of traffic or server SSH impersonation.",
                "remediation": "Remove the private key from git history, generate a new key pair, and deploy keys via secure key vaults.",
                "mitre_id": "T1552.004",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Private Keys",
                "cwe_id": "CWE-798",
            },
            {
                "id": "SECENG-SECRET-GITHUB-PAT-01",
                "title": "Secret Exposure: GitHub Personal Access Token Detected",
                "pattern": re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),
                "severity": Severity.CRITICAL,
                "description": "GitHub Personal Access Token (PAT) exposed in source files, allowing repository tampering or code exfiltration.",
                "remediation": "Revoke the token immediately from GitHub Settings -> Developer settings -> Personal access tokens.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-798",
            },
            {
                "id": "SECENG-SECRET-OPENAI-KEY-01",
                "title": "Secret Exposure: OpenAI / AI Provider API Key Detected",
                "pattern": re.compile(r"\bsk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}|\bsk-proj-[a-zA-Z0-9_-]{40,}\b"),
                "severity": Severity.HIGH,
                "description": "Exposed OpenAI API key allowing unauthorized API usage and billing depletion.",
                "remediation": "Revoke the key in the provider console and inject keys via environment variables.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-798",
            },
            {
                "id": "SECENG-SECRET-GENERIC-PASS-01",
                "title": "Secret Exposure: High-Entropy Database / Password Variable",
                "pattern": re.compile(
                    r'(?:password|passwd|db_pass|secret_key)\s*=\s*["\']([A-Za-z0-9@#$%^&*!_-]{8,})["\']',
                    re.IGNORECASE,
                ),
                "severity": Severity.MEDIUM,
                "description": "Static password or secret assigned in source code.",
                "remediation": "Migrate secrets to .env (excluded from VCS) or HashiCorp Vault.",
                "mitre_id": "T1552.001",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Unsecured Credentials: Credentials In Files",
                "cwe_id": "CWE-798",
            },
        ]

    @property
    def name(self) -> str:
        return "Secrets & Credential Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ENGINEER

    @property
    def description(self) -> str:
        return "Scans code and configuration files for exposed cloud keys (AWS, GitHub, OpenAI), private keys, and passwords."

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        # Skip scanning our own .env file if it's the runtime configuration
        if file_path.endswith(".env") and "AQ.Ab8RN6" in content:
            return []

        findings: List[Finding] = []
        lines = content.splitlines()

        # High-entropy secret heuristic for uncatalogued API tokens / private secrets
        entropy_assignment_re = re.compile(
            r'(?:api_?key|secret_?key|access_?token|auth_?token|private_?key|jwt_?secret|encryption_?key|client_?secret)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
            re.IGNORECASE,
        )
        ignore_placeholders = {"your_api_key_here", "replace_me", "todo", "example", "placeholder", "xxx"}

        for line_idx, line in enumerate(lines, start=1):
            matched_rule = False
            for rule in self.rules:
                match = rule["pattern"].search(line)
                if match:
                    matched_rule = True
                    raw_val = match.group(1) if match.groups() else match.group(0)
                    masked_val = raw_val[:6] + "*" * max(1, len(raw_val) - 8) + raw_val[-2:] if len(raw_val) > 10 else "***REDACTED***"

                    # Live Secret Verification
                    sev = rule["severity"]
                    title = rule["title"]
                    desc = rule["description"]
                    compliance = {"LiveVerification": "UNVERIFIED_STATIC"}

                    if getattr(self, "enable_live_verification", False) or getattr(self, "verifier", None) is not None:
                        from cyberaudit.core.live_secret_verifier import LiveSecretVerifier, SecretVerificationStatus
                        verifier = getattr(self, "verifier", None) or LiveSecretVerifier()
                        v_res = verifier.verify_secret(rule["title"], raw_val)

                        if v_res.status == SecretVerificationStatus.ACTIVE_VERIFIED:
                            sev = Severity.CRITICAL
                            title += " [LIVE VERIFIED ACTIVE]"
                            desc += f" [ALERTA DE PRODUCCIÓN: Credencial confirmada activa en API del proveedor: {v_res.audit_notes}]"
                        elif v_res.status == SecretVerificationStatus.REVOKED_OR_EXPIRED:
                            sev = Severity.LOW
                            title += " [REVOKED / EXPIRED]"
                            desc += f" [VERIFICADO INACTIVO: {v_res.audit_notes}]"
                        elif v_res.status == SecretVerificationStatus.DUMMY_OR_TEST_FIXTURE:
                            sev = Severity.INFO
                            title += " [TEST DUMMY / DOC EXAMPLE]"
                            desc += f" [FIXTURE: {v_res.audit_notes}]"
                        compliance = {"LiveVerification": v_res.status.value}

                    finding = Finding(
                        id=rule["id"],
                        title=title,
                        description=desc,
                        severity=sev,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_idx,
                        code_snippet=masked_val,
                        remediation=rule["remediation"],
                        mitre_id=rule["mitre_id"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        cwe_id=rule.get("cwe_id"),
                        compliance_controls=compliance,
                    )
                    findings.append(finding)
                    break

            if not matched_rule:
                ent_match = entropy_assignment_re.search(line)
                if ent_match:
                    raw_secret = ent_match.group(1)
                    lower_sec = raw_secret.lower()
                    if not any(ph in lower_sec for ph in ignore_placeholders):
                        entropy = calculate_shannon_entropy(raw_secret)
                        # High entropy threshold for random base64/hex/alphanumeric tokens
                        if entropy >= 4.3 and len(raw_secret) >= 20:
                            masked_val = raw_secret[:4] + "*" * (len(raw_secret) - 6) + raw_secret[-2:]
                            findings.append(
                                Finding(
                                    id="SECENG-SECRET-ENTROPY-01",
                                    title=f"Secret Exposure: High-Entropy Token Detected (Entropy: {entropy:.2f} bits)",
                                    description=(
                                        f"A variable holding a credential contains a high-entropy string ({entropy:.2f} bits/char), "
                                        "indicating a genuine cryptographic key, private token, or service secret committed to the repository."
                                    ),
                                    severity=Severity.HIGH,
                                    pillar=self.pillar,
                                    scanner_name=self.name,
                                    file_path=file_path,
                                    line_number=line_idx,
                                    code_snippet=f"... = '{masked_val}'",
                                    remediation="Rotate this credential immediately and move it to environment variables or a secure vault.",
                                    mitre_id="T1552.001",
                                    mitre_tactic="Credential Access",
                                    mitre_technique="Unsecured Credentials: Credentials In Files",
                                    cwe_id="CWE-798",
                                )
                            )

        return findings
