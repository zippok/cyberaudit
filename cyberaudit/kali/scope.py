"""
CyberAudit Kali Engagement Scope & Rules of Engagement Guard
Enforces *deny-by-default* authorization before any Kali tool touches a target:

1. An explicit, declared engagement scope must exist (``.cyberaudit-scope.yaml``).
2. The target must match an ``allow`` entry (CIDR, domain or ``*.wildcard``) and must
   not match any ``deny`` entry.
3. Private/loopback/link-local ranges require an explicit ``allow_private`` opt-in.
4. INTRUSIVE tools (exploitation, credential attacks, capture) require ``allow_intrusive``.
5. Expired engagements are rejected automatically.

The guard is deliberately independent from the network layer: it never contacts the
target, it only reasons about declarations the operator signed off on.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cyberaudit.kali.tool_registry import KaliToolError, RiskLevel

DEFAULT_SCOPE_FILE = ".cyberaudit-scope.yaml"
SCOPE_ENV_VAR = "CYBERAUDIT_SCOPE_FILE"


class ScopeViolationError(Exception):
    """Raised when a requested action falls outside the authorized engagement scope."""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_date(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text.replace("Z", "+0000"), fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ScopeViolationError(f"Fecha de alcance inválida (usa ISO-8601, p.ej. 2026-12-31): {text!r}")


@dataclass
class EngagementScope:
    """Declarative authorization envelope for an authorized penetration test."""

    authorized: bool = False
    client: str = ""
    engagement_id: str = ""
    authorized_by: str = ""
    start_date: Optional[str] = None
    expires: Optional[str] = None
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    allow_intrusive: bool = False
    allow_private: bool = False
    # Techo adicional opcional sobre el riesgo permitido. Por defecto no añade restricción:
    # los permisos reales los otorgan explícitamente 'allow_intrusive' y 'allow_private'.
    max_risk: str = "INTRUSIVE"
    notes: str = ""
    source_path: Optional[str] = None

    # ── Serialization ────────────────────────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        return {
            "authorized": self.authorized,
            "client": self.client,
            "engagement_id": self.engagement_id,
            "authorized_by": self.authorized_by,
            "start_date": self.start_date,
            "expires": self.expires,
            "allow": list(self.allow),
            "deny": list(self.deny),
            "allow_intrusive": self.allow_intrusive,
            "allow_private": self.allow_private,
            "max_risk": self.max_risk,
            "notes": self.notes,
            "source_path": self.source_path,
        }

    def summary(self) -> str:
        who = self.client or "cliente no especificado"
        ref = self.engagement_id or "sin ID"
        window = f"{self.start_date or '?'} → {self.expires or 'sin caducidad'}"
        return (
            f"{who} ({ref}) | ventana: {window} | allow: {len(self.allow)} entradas | "
            f"intrusivo: {'sí' if self.allow_intrusive else 'no'} | "
            f"redes privadas: {'permitidas' if self.allow_private else 'bloqueadas'}"
        )

    # ── Loading ──────────────────────────────────────────────────────────────
    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_path: Optional[str] = None) -> "EngagementScope":
        if not isinstance(data, dict):
            raise ScopeViolationError("El archivo de alcance debe contener un objeto (mapa) de configuración.")

        def _boolean(key: str) -> bool:
            value = data.get(key, False)
            if type(value) is not bool:
                raise ScopeViolationError(f"{key} debe ser booleano true/false, no texto ni número.")
            return value

        def _as_list(value: Any) -> List[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [v.strip() for v in value.split(",") if v.strip()]
            if isinstance(value, (list, tuple)):
                return [str(v).strip() for v in value if str(v).strip()]
            raise ScopeViolationError(f"Se esperaba una lista o cadena para el alcance, se obtuvo: {type(value).__name__}")

        return cls(
            authorized=_boolean("authorized"),
            client=str(data.get("client", "") or ""),
            engagement_id=str(data.get("engagement_id", "") or ""),
            authorized_by=str(data.get("authorized_by", "") or ""),
            start_date=str(data["start_date"]) if data.get("start_date") else None,
            expires=str(data["expires"]) if data.get("expires") else None,
            allow=_as_list(data.get("allow")),
            deny=_as_list(data.get("deny")),
            allow_intrusive=_boolean("allow_intrusive"),
            allow_private=_boolean("allow_private"),
            max_risk=str(data.get("max_risk", "ACTIVE") or "ACTIVE").upper(),
            notes=str(data.get("notes", "") or ""),
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: Optional[str] = None) -> "EngagementScope":
        """Loads the engagement scope from YAML or JSON. Missing file → unauthorized scope."""
        candidate = path or os.getenv(SCOPE_ENV_VAR, "").strip() or DEFAULT_SCOPE_FILE
        resolved = os.path.realpath(os.path.expanduser(candidate))
        if not os.path.isfile(resolved):
            return cls(authorized=False)
        with open(resolved, "r", encoding="utf-8") as handle:
            raw = handle.read()
        data: Any
        if resolved.lower().endswith((".yaml", ".yml")):
            try:
                import yaml  # type: ignore
            except ImportError:
                raise ScopeViolationError(
                    "PyYAML no está instalado: usa un archivo .json para el alcance o instala pyyaml."
                )
            data = yaml.safe_load(raw) or {}
        else:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ScopeViolationError(f"El archivo de alcance JSON es inválido: {exc}")
        return cls.from_dict(data, source_path=resolved)

    @classmethod
    def from_cli(
        cls,
        targets: List[str],
        allow_private: bool = False,
        allow_intrusive: bool = False,
        engagement_id: str = "",
        client: str = "",
    ) -> "EngagementScope":
        """Builds an in-memory scope from explicit CLI authorization flags."""
        return cls(
            authorized=bool(targets),
            client=client,
            engagement_id=engagement_id or "CLI-DECLARED",
            authorized_by="operator (declaración explícita en línea de comandos)",
            start_date=_now_utc().strftime("%Y-%m-%d"),
            allow=list(targets),
            allow_private=allow_private,
            allow_intrusive=allow_intrusive,
            notes="Alcance declarado mediante flags de CLI (--authorized). No persistido en disco.",
            source_path=None,
        )


@dataclass
class ScopeAuthorization:
    """Result of a successful scope check, suitable for the immutable audit trail."""

    target: str
    host: str
    resolved_ips: List[str]
    risk: RiskLevel
    matched_rule: str
    engagement_id: str
    client: str
    timestamp: str = field(default_factory=lambda: _now_utc().strftime("%Y-%m-%d %H:%M:%S UTC"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "resolved_ips": list(self.resolved_ips),
            "risk": self.risk.value,
            "matched_rule": self.matched_rule,
            "engagement_id": self.engagement_id,
            "client": self.client,
            "timestamp": self.timestamp,
        }


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_private_or_reserved(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return bool(
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified
        )
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
        return bool(
            net.is_private or net.is_loopback or net.is_link_local or net.is_multicast
            or net.is_reserved or net.is_unspecified
        )
    except ValueError:
        return True


def _resolve_ips(host: str) -> List[str]:
    if _is_ip_literal(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def _match_rule(entry: str, host: str, resolved_ips: List[str]) -> bool:
    """Returns True when `host`/its IPs fall inside the scope `entry`."""
    rule = entry.strip()
    if not rule:
        return False

    if rule.lower() == host.lower():
        return True

    # CIDR / IP network
    if "/" in rule:
        try:
            network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
        if "/" in host:
            try:
                target_net = ipaddress.ip_network(host, strict=False)
                if target_net.subnet_of(network):
                    return True
            except ValueError:
                pass
        for ip_str in resolved_ips:
            try:
                if ipaddress.ip_address(ip_str) in network:
                    return True
            except ValueError:
                continue
        return False

    # Wildcard subdomain
    if rule.startswith("*."):
        suffix = rule[2:].lower().rstrip(".")
        lowered = host.lower().rstrip(".")
        return lowered == suffix or lowered.endswith("." + suffix)

    # Plain IP
    if _is_ip_literal(rule):
        return rule in resolved_ips or rule == host

    # Plain hostname (case-insensitive, trailing dot tolerant)
    return rule.lower().rstrip(".") == host.lower().rstrip(".")


class ScopeGuard:
    """Validates every Kali tool invocation against the engagement scope."""

    def __init__(self, scope: EngagementScope):
        self.scope = scope

    # ── Construction helpers ─────────────────────────────────────────────────
    @classmethod
    def from_file(cls, path: Optional[str] = None) -> "ScopeGuard":
        return cls(EngagementScope.load(path))

    @classmethod
    def from_cli(cls, targets: List[str], **kwargs) -> "ScopeGuard":
        return cls(EngagementScope.from_cli(targets, **kwargs))

    @property
    def authorized(self) -> bool:
        return self.scope.authorized

    # ── Validation ───────────────────────────────────────────────────────────
    def _check_declarations(self) -> None:
        scope = self.scope
        for key in ("authorized", "allow_intrusive", "allow_private"):
            if type(getattr(scope, key)) is not bool:
                raise ScopeViolationError(f"{key} debe ser booleano")
        if not scope.authorized:
            raise ScopeViolationError(
                "No existe una autorización de engagement válida. Los escaneos con herramientas ofensivas "
                f"requieren un alcance declarado ({DEFAULT_SCOPE_FILE}, generado con 'python cli.py kali-scope init') "
                "o la declaración explícita --authorized en línea de comandos."
            )
        if not scope.allow:
            raise ScopeViolationError(
                "El alcance autorizado no declara ninguna entrada en 'allow': política deny-by-default activa."
            )
        expires = _parse_date(scope.expires)
        if expires and expires < _now_utc():
            raise ScopeViolationError(
                f"El engagement '{scope.engagement_id or 'sin ID'}' expiró el {expires.strftime('%Y-%m-%d')}. "
                "Renueva la autorización antes de continuar."
            )

    def authorize(self, target: str, risk: RiskLevel) -> ScopeAuthorization:
        """Validates `target` for the given risk level, returning the audit record."""
        self._check_declarations()
        scope = self.scope

        try:
            from cyberaudit.core.target_verifier import TargetVerifier
            host, _port = TargetVerifier.extract_host(target)
        except Exception:
            host = target.strip()

        resolved_ips = _resolve_ips(host)

        # 1. Explicit deny list always wins.
        for denied in scope.deny:
            if _match_rule(denied, host, resolved_ips):
                raise ScopeViolationError(
                    f"El objetivo '{host}' coincide con la regla de exclusión '{denied}' del engagement. Operación abortada."
                )

        # 2. Allow list (deny-by-default).
        matched = ""
        for entry in scope.allow:
            if _match_rule(entry, host, resolved_ips):
                matched = entry
                break
        if not matched:
            raise ScopeViolationError(
                f"El objetivo '{host}' no está dentro del alcance autorizado. "
                f"Entradas autorizadas: {', '.join(scope.allow)}. "
                "Añade el objetivo al alcance del engagement (o usa --allow-local con --authorized en un laboratorio aislado)."
            )

        # 3. Private / reserved ranges require explicit opt-in.
        private_ips = [ip for ip in resolved_ips if _is_private_or_reserved(ip)]
        if private_ips and not scope.allow_private:
            raise ScopeViolationError(
                f"El objetivo '{host}' resuelve a direcciones privadas/reservadas ({', '.join(private_ips)}). "
                "Establece 'allow_private: true' en el alcance (o --allow-local) únicamente para laboratorios propios aislados."
            )

        # 4. Intrusive actions require an explicit declaration.
        if risk.rank >= RiskLevel.INTRUSIVE.rank and not scope.allow_intrusive:
            raise ScopeViolationError(
                f"La acción solicitada es de riesgo {risk.value} (explotación/fuerza bruta/captura) pero el engagement "
                "no declara 'allow_intrusive: true' (o --allow-intrusive). Requiere autorización escrita del cliente."
            )

        max_risk = (scope.max_risk or "ACTIVE").upper()
        if max_risk in RiskLevel.__members__ and risk.rank > RiskLevel[max_risk].rank:
            raise ScopeViolationError(
                f"El riesgo máximo autorizado del engagement es {max_risk} y se solicitó {risk.value}."
            )

        return ScopeAuthorization(
            target=target,
            host=host,
            resolved_ips=resolved_ips,
            risk=risk,
            matched_rule=matched,
            engagement_id=scope.engagement_id,
            client=scope.client,
        )

    def authorize_local_floor(self, target: str) -> None:
        """Applies the platform-wide Anti-SSRF floor on top of the scope declaration."""
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                if (network.is_private or network.is_loopback or network.is_reserved) and not self.scope.allow_private:
                    raise ScopeViolationError(
                        f"El rango CIDR '{target}' pertenece a redes privadas/reservadas y allow_private=False."
                    )
                return
            except ValueError:
                pass

        from cyberaudit.core.target_verifier import TargetVerificationError, TargetVerifier

        try:
            TargetVerifier.validate_safe_target(target, allow_local=self.scope.allow_private)
        except TargetVerificationError as exc:
            raise ScopeViolationError(str(exc))


SCOPE_TEMPLATE: str = """\
# ─────────────────────────────────────────────────────────────────────────────
# CyberAudit · Autorización de Engagement (Rules of Engagement)
# Completa, firma y guarda este archivo como .cyberaudit-scope.yaml
# Sin 'authorized: true' NINGUNA herramienta ofensiva podrá ejecutarse.
# ─────────────────────────────────────────────────────────────────────────────
authorized: false                # Cámbialo a true SOLO con autorización escrita del cliente
client: "Cliente S.A."
engagement_id: "ENG-2026-001"
authorized_by: "Nombre y cargo del responsable que firma la autorización"
start_date: "2026-01-01"
expires: "2026-12-31"            # Tras esta fecha el alcance se rechaza automáticamente

allow:                           # Deny-by-default: sólo estos objetivos son auditables
  - "app.cliente.com"
  - "*.cliente.com"
  - "203.0.113.10"               # IP suelta
  - "198.51.100.0/24"            # Rango CIDR

deny:                            # Exclusiones explícitas (ganan siempre)
  - "portal.pagos.cliente.com"
  - "10.0.0.0/8"

allow_intrusive: false           # true sólo si se autoriza explotación, fuerza bruta o captura de tráfico
allow_private: false             # true sólo en laboratorios propios aislados (RFC1918/loopback)
max_risk: "ACTIVE"               # PASSIVE | ACTIVE | INTRUSIVE
notes: "Ventana de pruebas acordada, contacto de guardia y limitaciones técnicas."
"""


def write_scope_template(path: Optional[str] = None, force: bool = False) -> str:
    """Writes the engagement scope template, returning the resolved path."""
    target = os.path.realpath(os.path.expanduser(path or DEFAULT_SCOPE_FILE))
    if os.path.exists(target) and not force:
        raise ScopeViolationError(f"El archivo {target} ya existe. Usa --force para sobrescribirlo.")
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(SCOPE_TEMPLATE)
    return target


__all__ = [
    "EngagementScope",
    "ScopeAuthorization",
    "ScopeGuard",
    "ScopeViolationError",
    "KaliToolError",
    "SCOPE_TEMPLATE",
    "write_scope_template",
    "DEFAULT_SCOPE_FILE",
    "SCOPE_ENV_VAR",
]
