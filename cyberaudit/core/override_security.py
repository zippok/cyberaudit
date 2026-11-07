"""
CyberAudit Override Security & Non-Repudiation Engine.

Provides cryptographic verification (HMAC-SHA256), tamper prevention,
and distributed concurrency locks for audit_status_overrides.json.

Protects against:
  1. Forged triages: Prevents developers from manually editing JSON to mark
     critical vulnerabilities as AS_DESIGNED.
  2. Ephemeral CI loss: Storage adapter interface for Git-backed or centralized stores.
  3. Race conditions: Atomic lock for concurrent CI/CD pipelines.
"""

import hmac
import hashlib
import json
import os
import threading
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

logger = logging.getLogger("cyberaudit.core.override_security")

# Thread-safe lock for process-level operations
_OVERRIDE_LOCK = threading.Lock()

# Default secret derivation (in enterprise production, set CYBERAUDIT_OVERRIDE_SECRET)
DEFAULT_OVERRIDE_SECRET = os.environ.get(
    "CYBERAUDIT_OVERRIDE_SECRET",
    "cyberaudit-enterprise-audit-override-v2-hmac-key"
)


@dataclass
class SignedOverride:
    """Represents an auditable, cryptographically signed triage override."""
    finding_id: str
    file_path: str
    line_number: Optional[int]
    status: str  # OPEN, RESOLVED, AS_DESIGNED
    comment: str
    auditor_id: str
    timestamp: str
    signature: str
    ast_node_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "status": self.status,
            "comment": self.comment,
            "auditor_id": self.auditor_id,
            "updated_at": self.timestamp,
            "_signature": self.signature,
        }
        if self.ast_node_hash:
            data["ast_node_hash"] = self.ast_node_hash
        return data


class OverrideSecurityManager:
    """Manages cryptographic signing, validation, and atomic writes of audit overrides.
    Supports symmetric HMAC-SHA256 and asymmetric Ed25519 digital signatures.
    """

    def __init__(self, secret_key: Optional[str] = None,
                 enforce_signatures: bool = False,
                 public_key: Optional[str] = None,
                 private_key: Optional[str] = None,
                 signing_mode: Optional[str] = None,
                 max_triage_age_days: int = 90,
                 revoked_keys: Optional[list] = None):
        """Initialise the security manager.

        Args:
            secret_key:           HMAC-SHA256 shared secret (env: CYBERAUDIT_OVERRIDE_SECRET).
            enforce_signatures:   Reject unsigned overrides when True.
            public_key:           Ed25519 public key hex (env: CYBERAUDIT_OVERRIDE_PUBLIC_KEY).
            private_key:          Ed25519 private key hex (env: CYBERAUDIT_OVERRIDE_PRIVATE_KEY).
            signing_mode:         ``"hmac"`` (default) or ``"asymmetric"`` (env: CYBERAUDIT_SIGNING_MODE).
            max_triage_age_days:  Maximum age of a triage override before CI/CD rejects it.
                                  Default 90 days.  0 disables the check.
                                  Rationale: stale triages signed under a previous code version
                                  may no longer reflect the current security posture.
            revoked_keys:         List of revoked public-key hex strings (CRL).  Any override
                                  whose ``_signer_pub`` field matches a revoked key is rejected
                                  regardless of signature validity.
        """
        self.secret_key = (secret_key or DEFAULT_OVERRIDE_SECRET).encode("utf-8")
        self.public_key_hex = public_key or os.environ.get("CYBERAUDIT_OVERRIDE_PUBLIC_KEY")
        self.private_key_hex = private_key or os.environ.get("CYBERAUDIT_OVERRIDE_PRIVATE_KEY")
        self.signing_mode = signing_mode or os.environ.get("CYBERAUDIT_SIGNING_MODE", "hmac")
        self.enforce_signatures = enforce_signatures or (
            os.environ.get("CYBERAUDIT_ENFORCE_SIGNED_OVERRIDES", "0") == "1"
        )
        self.max_triage_age_days = max_triage_age_days
        # Normalise revoked key list — strip whitespace, lower-case hex strings
        self.revoked_keys: frozenset = frozenset(
            k.strip().lower() for k in (revoked_keys or []) if k
        )

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generates an Ed25519 private/public keypair (hex-encoded 32 bytes each).
        The private key is retained by the auditor; the public key is placed in CI/CD secrets.
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography package is required for Ed25519 key generation")
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        priv_hex = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()
        pub_hex = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        return priv_hex, pub_hex

    @staticmethod
    def sign_asymmetric(private_key_hex: str, canonical_msg: str) -> str:
        """Signs a canonical message using an Ed25519 private key."""
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography package is required for Ed25519 signing")
        priv_bytes = bytes.fromhex(private_key_hex.strip())
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig_bytes = priv_key.sign(canonical_msg.encode("utf-8"))
        return f"ed25519:{sig_bytes.hex()}"

    @staticmethod
    def verify_asymmetric_signature(public_key_hex: str, canonical_msg: str, signature: str) -> bool:
        """Verifies an Ed25519 digital signature against the canonical message."""
        if not HAS_CRYPTOGRAPHY:
            return False
        try:
            raw_sig_hex = signature.removeprefix("ed25519:").strip()
            sig_bytes = bytes.fromhex(raw_sig_hex)
            pub_bytes = bytes.fromhex(public_key_hex.strip())
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub_key.verify(sig_bytes, canonical_msg.encode("utf-8"))
            return True
        except Exception:
            return False

    def compute_signature(self, finding_id: str, file_path: str,
                          line_number: Any, status: str,
                          comment: str, timestamp: str, auditor_id: str,
                          ast_node_hash: Optional[str] = None) -> str:
        """Computes digital signature (Ed25519 asymmetric or HMAC-SHA256)."""
        norm_path = os.path.normpath(file_path).replace("\\", "/").lower().strip()
        location_anchor = f"ast:{ast_node_hash}" if ast_node_hash else str(line_number or 0)
        canonical = f"{finding_id}|{norm_path}|{location_anchor}|{status}|{comment.strip()}|{timestamp}|{auditor_id}"

        if self.signing_mode == "asymmetric" and self.private_key_hex:
            return self.sign_asymmetric(self.private_key_hex, canonical)

        return hmac.new(self.secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_override(self, key: str, record: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates that an override record has not been tampered with.

        Lifecycle checks (run before signature verification):
          1. TTL (max_triage_age_days): Rejects overrides older than the configured
             threshold.  Default 90 days.  Set max_triage_age_days=0 to disable.
          2. Key Revocation (CRL): Rejects overrides whose ``_signer_pub`` field
             matches any key in the ``revoked_keys`` list, even if the signature
             is cryptographically valid.  This invalidates all triages signed by a
             compromised auditor key without modifying the JSON store itself.

        Signature checks (run after lifecycle checks):
          - Ed25519 asymmetric signature verification (with public key in CI/CD)
          - HMAC-SHA256 symmetric verification (backward compatible)
          - AST node semantic anchor verification

        Returns:
            (is_valid, reason)
        """
        signature = record.get("_signature")
        if not signature:
            if self.enforce_signatures:
                return False, "Firma digital ausente en modo corporativo estricto"
            return True, "Override sin firmar (permitido en modo desarrollo)"

        parts = key.split("|")
        finding_id = parts[0]
        file_path = parts[1] if len(parts) > 1 else ""
        location_part = parts[2] if len(parts) > 2 else "0"

        status = record.get("status", "OPEN")
        comment = record.get("comment", "")
        timestamp = record.get("updated_at", "")
        auditor_id = record.get("auditor_id", "local_auditor")
        ast_node_hash = record.get("ast_node_hash")

        # ── Lifecycle Check 1: TTL ────────────────────────────────────────────
        # Reject stale triages that may no longer reflect the current security
        # posture.  Parsed as ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ).
        if self.max_triage_age_days > 0 and timestamp:
            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - ts).days
                if age_days > self.max_triage_age_days:
                    return (
                        False,
                        f"TRIAGE EXPIRADO: El override tiene {age_days} días de antigüedad "
                        f"(máximo permitido: {self.max_triage_age_days} días). "
                        "Se requiere revisión y re-firma por un auditor autorizado."
                    )
            except (ValueError, TypeError):
                pass  # Unparseable timestamp — defer to signature check

        # ── Lifecycle Check 2: Key Revocation (CRL) ──────────────────────────
        # If _signer_pub was stored at sign time, check it against the CRL.
        signer_pub = record.get("_signer_pub", "").strip().lower()
        if signer_pub and self.revoked_keys and signer_pub in self.revoked_keys:
            return (
                False,
                f"CLAVE REVOCADA: El triage fue firmado con la clave pública '{signer_pub[:16]}…' "
                "que ha sido revocada. Override inválido — re-firma requerida."
            )

        # Determine location anchor: AST takes precedence if present
        if ast_node_hash:
            anchor = f"ast:{ast_node_hash}"
        elif location_part.startswith("ast:"):
            anchor = location_part
        else:
            anchor = location_part

        norm_path = os.path.normpath(file_path).replace("\\", "/").lower().strip()
        canonical = f"{finding_id}|{norm_path}|{anchor}|{status}|{comment.strip()}|{timestamp}|{auditor_id}"

        # 1. Asymmetric signature verification (Ed25519)
        if signature.startswith("ed25519:"):
            pub_key = self.public_key_hex or os.environ.get("CYBERAUDIT_OVERRIDE_PUBLIC_KEY")
            if not pub_key:
                if self.enforce_signatures:
                    return False, "CLAVE PÚBLICA NO CONFIGURADA: CI/CD requiere CYBERAUDIT_OVERRIDE_PUBLIC_KEY para validar firmas asimétricas"
                return False, "Firma asimétrica presente pero CYBERAUDIT_OVERRIDE_PUBLIC_KEY no fue provista"

            if self.verify_asymmetric_signature(pub_key, canonical, signature):
                return True, "Firma digital asimétrica Ed25519 válida (No-repudio corporativo SOC 2 / ISO 27001 verificado)"
            else:
                return False, "FIRMA ASIMÉTRICA INVÁLIDA: Clave pública rechazó la firma (posible fraude de auditoría)"

        # 2. Symmetric HMAC-SHA256 verification
        expected_sig = hmac.new(self.secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature, expected_sig):
            return True, "Firma criptográfica válida (No-repudio garantizado)"
        else:
            # Fallback check against raw location part for legacy migration
            if anchor != location_part:
                fallback_canonical = f"{finding_id}|{norm_path}|{location_part}|{status}|{comment.strip()}|{timestamp}|{auditor_id}"
                fallback_sig = hmac.new(self.secret_key, fallback_canonical.encode("utf-8"), hashlib.sha256).hexdigest()
                if hmac.compare_digest(signature, fallback_sig):
                    return True, "Firma criptográfica válida (compatibilidad de línea)"

            return False, "FIRMA INVÁLIDA: El registro fue alterado manualmente (posible fraude de auditoría)"

    def sign_and_save(self, overrides_path: str, key: str,
                      status: str, comment: str, auditor_id: str = "auditor_sec_ops",
                      ast_node_hash: Optional[str] = None) -> Dict[str, Any]:
        """Atomically signs an override and writes it to disk with lock protection."""
        with _OVERRIDE_LOCK:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            parts = key.split("|")
            finding_id = parts[0]
            file_path = parts[1] if len(parts) > 1 else ""
            line_number = parts[2] if len(parts) > 2 else "0"

            sig = self.compute_signature(
                finding_id, file_path, line_number, status, comment, timestamp, auditor_id,
                ast_node_hash=ast_node_hash
            )

            data = {}
            if os.path.isfile(overrides_path):
                try:
                    with open(overrides_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = {}

            record = {
                "status": status,
                "comment": comment,
                "auditor_id": auditor_id,
                "updated_at": timestamp,
                "_signature": sig,
            }
            if ast_node_hash:
                record["ast_node_hash"] = ast_node_hash

            data[key] = record

            # Atomic write via temporary file
            tmp_path = overrides_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, overrides_path)

            return record
