"""
cyberaudit/core/live_secret_verifier.py
=======================================
Bidirectional Secret Scanning with Non-Destructive Live Verification.

Addresses the fatal flaw of traditional secret scanning (which generates 60%+
false positives on revoked keys, test fixtures, and mock documentation examples).

Performs non-destructive, read-only identity queries to provider metadata APIs
to classify secrets as:
  * ACTIVE_VERIFIED: Production key is confirmed alive and authorized (CRITICAL / BLOCKING).
  * REVOKED_OR_EXPIRED: Provider confirms key is revoked, invalid or dead (LOW / ADVISORY).
  * DUMMY_OR_TEST_FIXTURE: Matched against standard provider test vectors (INFO).
  * UNVERIFIED_STATIC: Live verification skipped (offline / air-gapped / unsupported).
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberaudit.core.live_secret_verifier")


class SecretVerificationStatus(str, Enum):
    ACTIVE_VERIFIED = "ACTIVE_VERIFIED"
    REVOKED_OR_EXPIRED = "REVOKED_OR_EXPIRED"
    DUMMY_OR_TEST_FIXTURE = "DUMMY_OR_TEST_FIXTURE"
    UNVERIFIED_STATIC = "UNVERIFIED_STATIC"


@dataclass
class SecretVerificationResult:
    secret_type: str
    masked_secret: str
    status: SecretVerificationStatus
    provider: str
    identity_metadata: Dict[str, str] = field(default_factory=dict)
    http_status: Optional[int] = None
    audit_notes: str = ""

    def to_dict(self) -> Dict:
        return {
            "secret_type": self.secret_type,
            "masked_secret": self.masked_secret,
            "status": self.status.value,
            "provider": self.provider,
            "identity_metadata": self.identity_metadata,
            "http_status": self.http_status,
            "audit_notes": self.audit_notes,
        }


def mask_secret(secret: str) -> str:
    """Masks secret preserving only the prefix and suffix for forensics."""
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}...{secret[-4:]}"


# Well-known dummy / mock secret samples used in documentation or testing
KNOWN_DUMMY_SECRETS = {
    "AKIA_DUMMY_EXAMPLE_KEY",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ghp_DUMMY_MOCK_GITHUB_TOKEN_FOR_AUDIT",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xoxb-DUMMY-SAMPLE-TOKEN-NOT-REAL",
    "sk_test_mock_1234567890abcdef",
    "sk-proj-DUMMY_OPENAI_MOCK_TOKEN",
}


class LiveSecretVerifier:
    """
    Motor de verificación en vivo de credenciales.
    Realiza llamadas de solo lectura ultraligeras con timeouts estrictos (3.0s).
    """

    def __init__(
        self,
        enable_live_network: bool = False,
        timeout: float = 3.0,
        mock_adapter: Optional[Callable[[str, str], Optional[Tuple[int, Dict]]]] = None,
        offline_mode: bool = False,
    ):
        is_env_offline = os.environ.get("CYBERAUDIT_OFFLINE", "0").lower() in ("1", "true", "yes")
        self.offline_mode = offline_mode or is_env_offline
        self.enable_live_network = enable_live_network and not self.offline_mode
        self.timeout = timeout
        self.mock_adapter = mock_adapter

    def verify_secret(self, secret_type: str, raw_secret: str) -> SecretVerificationResult:
        masked = mask_secret(raw_secret)

        # 1. Fast check for known documentation dummies / test fixtures
        if raw_secret in KNOWN_DUMMY_SECRETS or "example" in raw_secret.lower() or "xxxx" in raw_secret.lower():
            return SecretVerificationResult(
                secret_type=secret_type,
                masked_secret=masked,
                status=SecretVerificationStatus.DUMMY_OR_TEST_FIXTURE,
                provider="N/A",
                audit_notes="Coincidencia con vector de prueba o ejemplo de documentación pública (no explotable)."
            )

        # 2. Check if mock adapter is provided (for isolated CI or hermetic tests)
        if self.mock_adapter:
            mock_res = self.mock_adapter(secret_type, raw_secret)
            if mock_res:
                status_code, body = mock_res
                return self._parse_provider_response(secret_type, masked, status_code, body)

        # 3. If live network queries are disabled or offline mode active, return unverified static (air-gap)
        if self.offline_mode or not self.enable_live_network:
            return SecretVerificationResult(
                secret_type=secret_type,
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider=self._get_provider_name(secret_type),
                audit_notes="Verificación en vivo desactivada por modo offline / air-gapped (--offline / CYBERAUDIT_OFFLINE). Cero egress leak garantizado."
            )


        # 4. Dispatch to provider verification handler
        st_lower = secret_type.lower()
        if "github" in st_lower:
            return self._verify_github(raw_secret, masked)
        elif "slack" in st_lower:
            return self._verify_slack(raw_secret, masked)
        elif "stripe" in st_lower:
            return self._verify_stripe(raw_secret, masked)
        elif "aws" in st_lower:
            return self._verify_aws_format(raw_secret, masked)
        elif "gitlab" in st_lower:
            return self._verify_gitlab(raw_secret, masked)

        return SecretVerificationResult(
            secret_type=secret_type,
            masked_secret=masked,
            status=SecretVerificationStatus.UNVERIFIED_STATIC,
            provider="Unknown",
            audit_notes="Proveedor no soporta verificación de solo lectura no destructiva."
        )

    def _verify_github(self, token: str, masked: str) -> SecretVerificationResult:
        url = "https://api.github.com/user"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "CyberAudit-LiveSecretVerifier/2.0",
                "Accept": "application/vnd.github+json",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                scopes = response.headers.get("X-OAuth-Scopes", "")
                data = json.loads(response.read().decode("utf-8"))
                return SecretVerificationResult(
                    secret_type="GitHub Token",
                    masked_secret=masked,
                    status=SecretVerificationStatus.ACTIVE_VERIFIED,
                    provider="GitHub",
                    identity_metadata={
                        "login": data.get("login", ""),
                        "type": data.get("type", ""),
                        "scopes": scopes,
                    },
                    http_status=status,
                    audit_notes=f"CONFIRMADO ACTIVO: Token válido para usuario '{data.get('login')}'. Scopes: {scopes or 'none'}."
                )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return SecretVerificationResult(
                    secret_type="GitHub Token",
                    masked_secret=masked,
                    status=SecretVerificationStatus.REVOKED_OR_EXPIRED,
                    provider="GitHub",
                    http_status=e.code,
                    audit_notes="REVOCADO / INVÁLIDO: La API de GitHub devolvió 401 Unauthorized."
                )
            return SecretVerificationResult(
                secret_type="GitHub Token",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="GitHub",
                http_status=e.code,
                audit_notes=f"Error transitorio de API: HTTP {e.code}"
            )
        except Exception as e:
            return SecretVerificationResult(
                secret_type="GitHub Token",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="GitHub",
                audit_notes=f"Error de conexión durante verificación: {e}"
            )

    def _verify_slack(self, token: str, masked: str) -> SecretVerificationResult:
        url = "https://slack.com/api/auth.test"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "CyberAudit-LiveSecretVerifier/2.0",
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                data = json.loads(response.read().decode("utf-8"))
                if data.get("ok"):
                    return SecretVerificationResult(
                        secret_type="Slack Token",
                        masked_secret=masked,
                        status=SecretVerificationStatus.ACTIVE_VERIFIED,
                        provider="Slack",
                        identity_metadata={
                            "team": data.get("team", ""),
                            "user": data.get("user", ""),
                            "bot_id": data.get("bot_id", ""),
                        },
                        http_status=status,
                        audit_notes=f"CONFIRMADO ACTIVO: Slack token operativo para equipo '{data.get('team')}'.",
                    )
                else:
                    return SecretVerificationResult(
                        secret_type="Slack Token",
                        masked_secret=masked,
                        status=SecretVerificationStatus.REVOKED_OR_EXPIRED,
                        provider="Slack",
                        http_status=status,
                        audit_notes=f"REVOCADO / INVÁLIDO: Slack API auth.test error: {data.get('error', 'invalid_auth')}",
                    )
        except Exception as e:
            return SecretVerificationResult(
                secret_type="Slack Token",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="Slack",
                audit_notes=f"Error durante llamada a Slack API: {e}",
            )

    def _verify_stripe(self, key: str, masked: str) -> SecretVerificationResult:
        url = "https://api.stripe.com/v1/balance"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {key}",
                "User-Agent": "CyberAudit-LiveSecretVerifier/2.0",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                return SecretVerificationResult(
                    secret_type="Stripe Key",
                    masked_secret=masked,
                    status=SecretVerificationStatus.ACTIVE_VERIFIED,
                    provider="Stripe",
                    http_status=status,
                    audit_notes="CONFIRMADO ACTIVO: API Key autorizada con acceso a balance financiero.",
                )
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return SecretVerificationResult(
                    secret_type="Stripe Key",
                    masked_secret=masked,
                    status=SecretVerificationStatus.REVOKED_OR_EXPIRED,
                    provider="Stripe",
                    http_status=e.code,
                    audit_notes="REVOCADO / INVÁLIDO: Stripe devolvió 401 Unauthorized.",
                )
            return SecretVerificationResult(
                secret_type="Stripe Key",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="Stripe",
                http_status=e.code,
                audit_notes=f"Respuesta inesperada de Stripe: {e.code}",
            )
        except Exception as e:
            return SecretVerificationResult(
                secret_type="Stripe Key",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="Stripe",
                audit_notes=f"Error conectando a Stripe: {e}",
            )

    def _verify_aws_format(self, key: str, masked: str) -> SecretVerificationResult:
        # AWS AKIA syntax validation
        if re.match(r"^AKIA[0-9A-Z]{16}$", key):
            return SecretVerificationResult(
                secret_type="AWS Access Key ID",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="AWS",
                audit_notes="Formato de Access Key ID estándar AWS válido (20 caracteres Base32). Requiere secret key para query STS.",
            )
        return SecretVerificationResult(
            secret_type="AWS Access Key ID",
            masked_secret=masked,
            status=SecretVerificationStatus.DUMMY_OR_TEST_FIXTURE,
            provider="AWS",
            audit_notes="Formato no cumple especificación de AWS IAM Access Key ID.",
        )

    def _verify_gitlab(self, token: str, masked: str) -> SecretVerificationResult:
        url = "https://gitlab.com/api/v4/user"
        req = urllib.request.Request(
            url,
            headers={
                "PRIVATE-TOKEN": token,
                "User-Agent": "CyberAudit-LiveSecretVerifier/2.0",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status = response.status
                data = json.loads(response.read().decode("utf-8"))
                return SecretVerificationResult(
                    secret_type="GitLab Token",
                    masked_secret=masked,
                    status=SecretVerificationStatus.ACTIVE_VERIFIED,
                    provider="GitLab",
                    identity_metadata={"username": data.get("username", "")},
                    http_status=status,
                    audit_notes=f"CONFIRMADO ACTIVO: Token válido para usuario '{data.get('username')}'.",
                )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return SecretVerificationResult(
                    secret_type="GitLab Token",
                    masked_secret=masked,
                    status=SecretVerificationStatus.REVOKED_OR_EXPIRED,
                    provider="GitLab",
                    http_status=e.code,
                    audit_notes="REVOCADO / INVÁLIDO: GitLab devolvió 401 Unauthorized.",
                )
            return SecretVerificationResult(
                secret_type="GitLab Token",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="GitLab",
                http_status=e.code,
                audit_notes=f"HTTP {e.code}",
            )
        except Exception as e:
            return SecretVerificationResult(
                secret_type="GitLab Token",
                masked_secret=masked,
                status=SecretVerificationStatus.UNVERIFIED_STATIC,
                provider="GitLab",
                audit_notes=f"Error conectando a GitLab: {e}",
            )

    def _parse_provider_response(self, secret_type: str, masked: str, status_code: int, body: Dict) -> SecretVerificationResult:
        provider = self._get_provider_name(secret_type)
        if status_code == 200:
            if body.get("ok") is False:
                return SecretVerificationResult(
                    secret_type=secret_type,
                    masked_secret=masked,
                    status=SecretVerificationStatus.REVOKED_OR_EXPIRED,
                    provider=provider,
                    http_status=status_code,
                    audit_notes=f"REVOCADO: API devolvió error de autenticación: {body.get('error')}",
                )
            return SecretVerificationResult(
                secret_type=secret_type,
                masked_secret=masked,
                status=SecretVerificationStatus.ACTIVE_VERIFIED,
                provider=provider,
                identity_metadata={k: str(v) for k, v in body.items() if isinstance(v, (str, int, bool))},
                http_status=status_code,
                audit_notes="CONFIRMADO ACTIVO: Verificación de identidad exitosa vía API mockeada/en vivo.",
            )
        elif status_code in (401, 403):
            return SecretVerificationResult(
                secret_type=secret_type,
                masked_secret=masked,
                status=SecretVerificationStatus.REVOKED_OR_EXPIRED,
                provider=provider,
                http_status=status_code,
                audit_notes=f"REVOCADO / EXPIRADO: API devolvió código {status_code}.",
            )
        return SecretVerificationResult(
            secret_type=secret_type,
            masked_secret=masked,
            status=SecretVerificationStatus.UNVERIFIED_STATIC,
            provider=provider,
            http_status=status_code,
            audit_notes=f"Respuesta no concluyente: HTTP {status_code}",
        )

    def _get_provider_name(self, secret_type: str) -> str:
        st = secret_type.lower()
        if "github" in st:
            return "GitHub"
        if "slack" in st:
            return "Slack"
        if "stripe" in st:
            return "Stripe"
        if "aws" in st:
            return "AWS"
        if "gitlab" in st:
            return "GitLab"
        return "Generic"
