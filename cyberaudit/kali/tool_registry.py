"""
CyberAudit Kali Linux Tool Registry
Declarative catalog of the offensive-security binaries shipped with Kali Linux,
their risk classification, safe ``argv`` builders and runtime availability discovery.

Design principles:
- **No shell, ever.** Every tool invocation is an explicit ``argv`` list built from
  validated parameters, so no user input can be interpreted by a shell.
- **Per-parameter validation.** Hosts, URLs, port specs, wordlists and numbers are
  validated against strict patterns before they are ever placed in an argument.
- **Explicit risk taxonomy.** PASSIVE / ACTIVE / INTRUSIVE tools are separated so the
  orchestrator can gate intrusive actions behind an explicit authorization flag.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple


class KaliToolError(Exception):
    """Raised when a tool invocation cannot be safely constructed."""


class KaliCategory(str, Enum):
    """Professional category of the tool, drives pillar mapping in findings."""

    RECON = "Reconocimiento & OSINT"
    WEB = "Auditoría Web (DAST)"
    NETWORK = "Auditoría de Redes y Servicios"
    AD = "Active Directory, SMB & LDAP"
    CREDENTIAL = "Credenciales & Criptografía"
    EXPLOIT = "Explotación & Verificación"
    FORENSIC = "Forense & Tráfico"
    WIRELESS = "Redes Inalámbricas"


class RiskLevel(str, Enum):
    """Blast-radius classification of a tool invocation."""

    PASSIVE = "PASSIVE"      # No contact with the target (local DB, offline cracking).
    ACTIVE = "ACTIVE"        # Interrogates the target (scanning, enumeration, fuzzing).
    INTRUSIVE = "INTRUSIVE"  # Exploitation, credential attacks or traffic capture.

    @property
    def rank(self) -> int:
        return {"PASSIVE": 1, "ACTIVE": 2, "INTRUSIVE": 3}.get(self.value, 0)


# ── Parameter sanitizers ─────────────────────────────────────────────────────

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._:-]{0,253})$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](?:-?[A-Za-z0-9_])*\.)+[A-Za-z]{2,63}\.?$")
_IPV4_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_PORT_SPEC_RE = re.compile(r"^[0-9][0-9,\-]{0,118}$")
_SEVERITY_FILTER_RE = re.compile(r"^[a-z]+(,[a-z]+){0,4}$")
_SERVICE_RE = re.compile(r"^[a-z0-9_\-]{1,32}$")
_TECH_TERM_RE = re.compile(r"^[A-Za-z0-9 ._&+/-]{1,60}$")
_EXTENSIONS_RE = re.compile(r"^[A-Za-z0-9,]{1,80}$")

_SHELL_METACHARS = set(";|&$`<>\\\"'\n\r\t\x00")


def _reject_control_chars(value: str, label: str) -> str:
    if any(ch in value for ch in _SHELL_METACHARS):
        raise KaliToolError(
            f"Parámetro '{label}' contiene caracteres no permitidos (metacaracteres de shell o control): {value!r}"
        )
    return value


def sanitize_token(
    value: object,
    label: str,
    *,
    pattern: Optional[re.Pattern] = None,
    max_length: int = 512,
    allow_spaces: bool = False,
) -> str:
    """Validates a single non-whitespace CLI token.

    Rejects control characters, shell metacharacters and (optionally) anything not
    matching the provided pattern. This is defense-in-depth: arguments are never
    passed to a shell, but a strict token contract keeps the audit trail trustworthy.
    """
    if value is None or str(value).strip() == "":
        raise KaliToolError(f"El parámetro '{label}' es obligatorio y no puede estar vacío.")
    text = _reject_control_chars(str(value).strip(), label)
    if not allow_spaces and any(ch.isspace() for ch in text):
        raise KaliToolError(f"El parámetro '{label}' no puede contener espacios: {text!r}")
    if len(text) > max_length:
        raise KaliToolError(f"El parámetro '{label}' excede la longitud máxima de {max_length} caracteres.")
    if pattern is not None and not pattern.match(text):
        raise KaliToolError(f"El parámetro '{label}' tiene un formato inválido: {text!r}")
    return text


def sanitize_host(value: object, label: str = "host") -> str:
    """Validates a hostname, IPv4/IPv6 literal or IPv4 CIDR range."""
    text = sanitize_token(value, label, max_length=253)
    if not (_HOST_RE.match(text) or _IPV4_CIDR_RE.match(text)):
        raise KaliToolError(f"El parámetro '{label}' no es un host, IP o rango CIDR válido: {text!r}")
    return text


def sanitize_domain(value: object, label: str = "dominio") -> str:
    text = sanitize_token(value, label, pattern=_DOMAIN_RE, max_length=253)
    return text.rstrip(".")


def sanitize_port_spec(value: object, label: str = "puertos") -> str:
    return sanitize_token(value, label, pattern=_PORT_SPEC_RE, max_length=120)


def sanitize_positive_int(value: object, label: str, minimum: int = 1, maximum: int = 65535) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise KaliToolError(f"El parámetro '{label}' debe ser un número entero: {value!r}")
    if number < minimum or number > maximum:
        raise KaliToolError(f"El parámetro '{label}' debe estar entre {minimum} y {maximum}: {number}")
    return number


def sanitize_existing_file(value: object, label: str) -> str:
    """Validates that a path exists, is a regular readable file and resolves it."""
    if value is None or str(value).strip() == "":
        raise KaliToolError(f"El parámetro '{label}' es obligatorio (ruta a un archivo).")
    path = os.path.realpath(os.path.expanduser(str(value).strip()))
    if not os.path.isfile(path):
        raise KaliToolError(f"El parámetro '{label}' apunta a un archivo inexistente: {path}")
    if not os.access(path, os.R_OK):
        raise KaliToolError(f"El parámetro '{label}' apunta a un archivo ilegible: {path}")
    return path


def sanitize_url(value: object, label: str = "url", allowed_schemes: Tuple[str, ...] = ("http", "https")) -> str:
    """Validates an absolute HTTP(S) URL and returns its normalized form."""
    from urllib.parse import urlparse, urlunparse

    text = _reject_control_chars(str(value or "").strip(), label)
    if any(ch.isspace() for ch in text):
        raise KaliToolError(f"El parámetro '{label}' no puede contener espacios: {text!r}")
    parsed = urlparse(text)
    if parsed.scheme.lower() not in allowed_schemes:
        raise KaliToolError(
            f"El parámetro '{label}' debe usar un esquema {allowed_schemes}: {text!r}"
        )
    if not parsed.hostname:
        raise KaliToolError(f"El parámetro '{label}' no contiene un host válido: {text!r}")
    sanitize_host(parsed.hostname, f"{label}.host")
    if parsed.username or parsed.password:
        raise KaliToolError(f"El parámetro '{label}' no puede incluir credenciales embebidas (userinfo).")
    netloc = parsed.netloc
    if parsed.port is not None:
        sanitize_positive_int(parsed.port, f"{label}.port")
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, ""))


# ── Wordlist resolution ──────────────────────────────────────────────────────

DEFAULT_WORDLIST_CANDIDATES: Tuple[str, ...] = (
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirb/small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)

DEFAULT_USERLIST_CANDIDATES: Tuple[str, ...] = (
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/wordlists/metasploit/unix_users.txt",
    "/usr/share/wordlists/dirb/common.txt",
)

def resolve_default_wordlist() -> Optional[str]:
    """Returns the first available bundled wordlist (env override wins)."""
    override = os.getenv("CYBERAUDIT_WORDLIST", "").strip()
    if override and os.path.isfile(override):
        return os.path.realpath(override)
    for candidate in DEFAULT_WORDLIST_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return None


def resolve_default_file(candidates: Tuple[str, ...]) -> Optional[str]:
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


# ── Invocation request ───────────────────────────────────────────────────────

@dataclass
class ToolRequest:
    """All the context a tool builder may need to assemble a validated argv."""

    target: str
    host: str
    work_dir: str
    url: Optional[str] = None
    scheme: str = "https"
    port: Optional[int] = None
    ports: Optional[str] = None
    base_path: str = "/"
    wordlist: Optional[str] = None
    userlist: Optional[str] = None
    passlist: Optional[str] = None
    hash_file: Optional[str] = None
    capture_file: Optional[str] = None
    community_file: Optional[str] = None
    service: str = "ssh"
    term: Optional[str] = None
    sudo: bool = False
    threads: int = 10
    rate_limit: int = 50
    timeout_seconds: int = 300
    duration_seconds: int = 30
    severity_filter: str = "critical,high,medium"
    extras: Dict[str, str] = field(default_factory=dict)

    def artifact(self, filename: str) -> str:
        """Returns an absolute artifact path inside the engagement workspace."""
        return os.path.join(self.work_dir, filename)


# ── Tool definition ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KaliTool:
    """Declarative definition of a Kali tool integration."""

    key: str
    binaries: Tuple[str, ...]
    title: str
    category: KaliCategory
    description: str
    risk: RiskLevel
    profiles: Tuple[str, ...]
    install_hint: str
    reference: str = ""
    requires_root: bool = False
    default_timeout: int = 300
    version_args: Tuple[str, ...] = ("--version",)
    requires_path: Optional[str] = None

    @property
    def binary(self) -> str:
        return self.binaries[0]


RECON, WEB, NETWORK, AD, CRED, EXPLOIT, FORENSIC, WIRELESS = (
    KaliCategory.RECON,
    KaliCategory.WEB,
    KaliCategory.NETWORK,
    KaliCategory.AD,
    KaliCategory.CREDENTIAL,
    KaliCategory.EXPLOIT,
    KaliCategory.FORENSIC,
    KaliCategory.WIRELESS,
)
PASSIVE, ACTIVE, INTRUSIVE = RiskLevel.PASSIVE, RiskLevel.ACTIVE, RiskLevel.INTRUSIVE


KALI_TOOL_LIST: Tuple[KaliTool, ...] = (
    KaliTool(key="testssl", binaries=("testssl", "testssl.sh"), title="testssl — Protocolos y cifrados TLS",
             category=CRED, risk=ACTIVE, profiles=("web", "infra", "full", "all"),
             description="Comprobaciones de protocolos y cifrados TLS con evidencia JSON.",
             install_hint="apt install testssl.sh", reference="https://www.kali.org/tools/testssl.sh/", default_timeout=600),
    KaliTool(key="feroxbuster", binaries=("feroxbuster",), title="Feroxbuster — Descubrimiento web acotado",
             category=WEB, risk=ACTIVE, profiles=("web", "full", "all"),
             description="Descubrimiento de rutas sin recursión ni seguimiento de redirecciones.",
             install_hint="apt install feroxbuster", reference="https://www.kali.org/tools/feroxbuster/", default_timeout=300),

    # ── Reconocimiento / OSINT ───────────────────────────────────────────────
    KaliTool(
        key="nmap", binaries=("nmap",), title="Nmap — Escáner de Puertos y Servicios",
        category=NETWORK, risk=ACTIVE,
        profiles=("recon", "web", "infra", "ad", "full", "all"),
        description=(
            "Descubrimiento de puertos TCP, detección de versiones de servicio (-sV) y ejecución "
            "de scripts NSE (default/vuln) para identificar vulnerabilidades conocidas."
        ),
        install_hint="apt install nmap", reference="https://nmap.org/book/man.html",
        default_timeout=600, version_args=("--version",),
    ),
    KaliTool(
        key="masscan", binaries=("masscan",), title="Masscan — Descubrimiento Masivo de Puertos",
        category=NETWORK, risk=ACTIVE,
        profiles=("infra", "all"),
        description="Escáner asíncrono de alta velocidad para inventariar puertos abiertos en rangos CIDR amplios.",
        install_hint="apt install masscan", reference="https://github.com/robertdavidgraham/masscan",
        requires_root=True, default_timeout=300, version_args=("--version",),
    ),
    KaliTool(
        key="dnsrecon", binaries=("dnsrecon",), title="DNSRecon — Enumeración DNS",
        category=RECON, risk=ACTIVE,
        profiles=("recon", "osint", "full", "all"),
        description="Enumeración de registros DNS (A, MX, NS, TXT, SPF), validación de DNSSEC y transferencias de zona.",
        install_hint="apt install dnsrecon", reference="https://github.com/darkoperator/dnsrecon",
        default_timeout=300, version_args=("--version",),
    ),
    KaliTool(
        key="amass", binaries=("amass",), title="OWASP Amass — Superficie de Ataque Externa",
        category=RECON, risk=PASSIVE,
        profiles=("recon", "osint", "all"),
        description="Mapeo pasivo de subdominios y activos externos a partir de fuentes OSINT públicas.",
        install_hint="apt install amass", reference="https://github.com/owasp-amass/amass",
        default_timeout=600, version_args=(), requires_path="/usr/lib/amass/amass",
    ),
    KaliTool(
        key="whatweb", binaries=("whatweb",), title="WhatWeb — Fingerprinting de Tecnologías",
        category=WEB, risk=ACTIVE,
        profiles=("recon", "web", "full", "all"),
        description="Identifica CMS, frameworks, servidores web y versiones expuestas por el objetivo.",
        install_hint="apt install whatweb", reference="https://github.com/urbanadventurer/WhatWeb",
        default_timeout=300, version_args=("--version",),
    ),
    KaliTool(
        key="wafw00f", binaries=("wafw00f",), title="WAFW00F — Detección de WAF",
        category=WEB, risk=PASSIVE,
        profiles=("recon", "web", "all"),
        description="Identifica el Web Application Firewall (Cloudflare, AWS WAF, Imperva...) que protege al objetivo.",
        install_hint="apt install wafw00f", reference="https://github.com/EnableSecurity/wafw00f",
        default_timeout=120, version_args=("--version",),
    ),
    KaliTool(
        key="httpx", binaries=("httpx-toolkit", "httpx"), title="httpx — Sondeo HTTP Masivo",
        category=WEB, risk=ACTIVE,
        profiles=("recon", "web", "full", "all"),
        description="Sondeo HTTP de endpoints: códigos de estado, títulos, tecnologías y servidor web.",
        install_hint="apt install httpx-toolkit", reference="https://github.com/projectdiscovery/httpx",
        default_timeout=300, version_args=("-version",),
    ),
    # ── Auditoría Web (DAST) ─────────────────────────────────────────────────
    KaliTool(
        key="nikto", binaries=("nikto",), title="Nikto — Escáner de Servidores Web",
        category=WEB, risk=ACTIVE,
        profiles=("web", "full", "all"),
        description="Auditoría de servidores web: archivos peligrosos, CGI obsoletos, cabeceras inseguras y desajustes de versión.",
        install_hint="apt install nikto", reference="https://github.com/sullo/nikto",
        default_timeout=900, version_args=("-Version",),
    ),
    KaliTool(
        key="nuclei", binaries=("nuclei",), title="Nuclei — Plantillas de Vulnerabilidades",
        category=WEB, risk=ACTIVE,
        profiles=("web", "infra", "full", "all"),
        description="Motor DAST basado en plantillas YAML de la comunidad (CVE, CVSS, misconfiguraciones y exposiciones).",
        install_hint="apt install nuclei", reference="https://github.com/projectdiscovery/nuclei",
        default_timeout=900, version_args=("-version",),
    ),
    KaliTool(
        key="gobuster", binaries=("gobuster",), title="Gobuster — Enumeración de Directorios",
        category=WEB, risk=ACTIVE,
        profiles=("web", "all"),
        description="Fuerza bruta de rutas, archivos y extensiones ocultas en el servidor web objetivo.",
        install_hint="apt install gobuster", reference="https://github.com/OJ/gobuster",
        default_timeout=600, version_args=("--version",),
    ),
    KaliTool(
        key="ffuf", binaries=("ffuf",), title="FFuf — Fuzzing Web de Alto Rendimiento",
        category=WEB, risk=ACTIVE,
        profiles=("web", "all"),
        description="Fuzzing de rutas/parámetros con filtrado automático de respuestas y salida JSON estructurada.",
        install_hint="apt install ffuf", reference="https://github.com/ffuf/ffuf",
        default_timeout=600, version_args=("-V",),
    ),
    KaliTool(
        key="dirb", binaries=("dirb",), title="DIRB — Descubrimiento de Contenido Web",
        category=WEB, risk=ACTIVE,
        profiles=("web", "all"),
        description="Escáner clásico de contenido web basado en diccionarios, útil como validación cruzada de Gobuster.",
        install_hint="apt install dirb", reference="https://gitlab.com/kalilinux/packages/dirb",
        default_timeout=600, version_args=(),
    ),
    KaliTool(
        key="wpscan", binaries=("wpscan",), title="WPScan — Auditoría de WordPress",
        category=WEB, risk=ACTIVE,
        profiles=("web", "all"),
        description="Enumeración de versiones, plugins, temas y usuarios de WordPress con correlación de vulnerabilidades.",
        install_hint="apt install wpscan", reference="https://github.com/wpscanteam/wpscan",
        default_timeout=900, version_args=("--version",),
    ),
    # ── Redes, SMB y Active Directory ────────────────────────────────────────
    KaliTool(
        key="nbtscan", binaries=("nbtscan",), title="NBTscan — Inventario NetBIOS",
        category=NETWORK, risk=ACTIVE,
        profiles=("infra", "ad", "all"),
        description="Consulta de nombres NetBIOS en la red para inventariar hosts Windows y sus roles.",
        install_hint="apt install nbtscan", reference="https://github.com/resurrecting-open-source-projects/nbtscan",
        default_timeout=120, version_args=(),
    ),
    KaliTool(
        key="enum4linux", binaries=("enum4linux-ng", "enum4linux"), title="enum4linux — Enumeración SMB/NetBIOS",
        category=AD, risk=ACTIVE,
        profiles=("infra", "ad", "all"),
        description="Enumeración de usuarios, grupos, recursos compartidos y políticas de contraseñas vía SMB/RPC.",
        install_hint="apt install enum4linux", reference="https://github.com/CiscoCXSecurity/enum4linux",
        default_timeout=600, version_args=("-h",),
    ),
    KaliTool(
        key="smbclient", binaries=("smbclient",), title="smbclient — Enumeración de Recursos SMB",
        category=AD, risk=ACTIVE,
        profiles=("infra", "ad", "all"),
        description="Lista recursos compartidos SMB y valida acceso anónimo/null session sin credenciales.",
        install_hint="apt install smbclient", reference="https://www.samba.org/samba/docs/current/man-html/smbclient.1.html",
        default_timeout=120, version_args=("-V",),
    ),
    KaliTool(
        key="nxc", binaries=("nxc", "crackmapexec"), title="NetExec — Post-Explotación AD",
        category=AD, risk=ACTIVE,
        profiles=("ad", "all"),
        description="Enumeración autenticada de SMB/AD: recursos, sesiones, políticas y detección de SMB signing deshabilitado.",
        install_hint="apt install netexec", reference="https://github.com/Pennyw0rth/NetExec",
        default_timeout=300, version_args=("--version",),
    ),
    KaliTool(
        key="snmpwalk", binaries=("snmpwalk",), title="snmpwalk — Auditoría SNMP",
        category=NETWORK, risk=ACTIVE,
        profiles=("infra", "all"),
        description="Consulta del árbol MIB con comunidades por defecto para detectar SNMP expuesto sin autenticación robusta.",
        install_hint="apt install snmp", reference="https://www.net-snmp.org/docs/man/snmpwalk.html",
        default_timeout=120, version_args=(),
    ),
    KaliTool(
        key="onesixtyone", binaries=("onesixtyone",), title="onesixtyone — Descubrimiento SNMP",
        category=NETWORK, risk=ACTIVE,
        profiles=("infra", "all"),
        description="Descubrimiento rápido de agentes SNMP y validación de cadenas de comunidad por defecto.",
        install_hint="apt install onesixtyone", reference="https://github.com/trapni/onesixtyone",
        default_timeout=120, version_args=(),
    ),
    KaliTool(
        key="smtp_user_enum", binaries=("smtp-user-enum",), title="smtp-user-enum — Enumeración de Usuarios SMTP",
        category=NETWORK, risk=ACTIVE,
        profiles=("infra", "all"),
        description="Enumeración de buzones válidos vía VRFY/EXPN/RCPT TO en servidores SMTP mal configurados.",
        install_hint="apt install smtp-user-enum", reference="https://github.com/pentestmonkey/smtp-user-enum",
        default_timeout=300, version_args=(),
    ),
    KaliTool(
        key="sslscan", binaries=("sslscan",), title="sslscan — Auditoría Criptográfica TLS",
        category=CRED, risk=ACTIVE,
        profiles=("infra", "web", "full", "all"),
        description="Enumeración de protocolos, suites de cifrado y certificados TLS con salida XML estructurada.",
        install_hint="apt install sslscan", reference="https://github.com/rbsec/sslscan",
        default_timeout=180, version_args=("--version",),
    ),
    # ── Credenciales y explotación (INTRUSIVE) ───────────────────────────────
    KaliTool(
        key="sqlmap", binaries=("sqlmap",), title="sqlmap — Verificación de Inyección SQL",
        category=EXPLOIT, risk=INTRUSIVE,
        profiles=("intrusive", "all"),
        description="Confirmación empírica de inyección SQL y técnica de explotación sobre parámetros vulnerables.",
        install_hint="apt install sqlmap", reference="https://github.com/sqlmapproject/sqlmap",
        default_timeout=900, version_args=("--version",),
    ),
    KaliTool(
        key="commix", binaries=("commix",), title="commix — Inyección de Comandos",
        category=EXPLOIT, risk=INTRUSIVE,
        profiles=("intrusive", "all"),
        description="Detección y explotación automatizada de inyección de comandos del sistema operativo.",
        install_hint="apt install commix", reference="https://github.com/commixproject/commix",
        default_timeout=600, version_args=("--version",),
    ),
    KaliTool(
        key="hydra", binaries=("hydra",), title="Hydra — Auditoría de Fuerza Bruta",
        category=CRED, risk=INTRUSIVE,
        profiles=("intrusive", "all"),
        description="Prueba controlada de robustez de credenciales en servicios de red usando diccionarios autorizados.",
        install_hint="apt install hydra", reference="https://github.com/vanhauser-thc/thc-hydra",
        default_timeout=900, version_args=("-h",),
    ),
    KaliTool(
        key="john", binaries=("john",), title="John the Ripper — Auditoría de Hashes",
        category=CRED, risk=PASSIVE,
        profiles=("intrusive", "all"),
        description="Auditoría offline de la fortaleza de hashes de contraseñas obtenidos durante el engagement.",
        install_hint="apt install john", reference="https://www.openwall.com/john/",
        default_timeout=1800, version_args=(),
    ),
    KaliTool(
        key="hashcat", binaries=("hashcat",), title="Hashcat — Recuperación de Claves Acelerada",
        category=CRED, risk=PASSIVE,
        profiles=("intrusive", "all"),
        description="Auditoría offline de hashes con aceleración GPU/CPU para evaluar políticas de contraseñas.",
        install_hint="apt install hashcat", reference="https://hashcat.net/hashcat/",
        default_timeout=1800, version_args=("--version",),
    ),
    KaliTool(
        key="impacket_secretsdump", binaries=("impacket-secretsdump",), title="impacket secretsdump — Volcado de Credenciales",
        category=AD, risk=INTRUSIVE,
        profiles=("all",),
        description="Extracción remota de hashes SAM/LSA/NTDS (DCSync) con credenciales previamente autorizadas.",
        install_hint="apt install impacket-scripts", reference="https://github.com/fortra/impacket",
        default_timeout=900, version_args=("-h",),
    ),
    KaliTool(
        key="responder", binaries=("responder",), title="Responder — Envenenamiento LLMNR/NBT-NS",
        category=AD, risk=INTRUSIVE,
        profiles=("all",),
        description="Captura de hashes NetNTLM mediante envenenamiento de resolución de nombres en la red auditada.",
        install_hint="apt install responder", reference="https://github.com/lgandx/Responder",
        requires_root=True, default_timeout=600, version_args=("-h",),
    ),
    # ── Forense y tráfico ────────────────────────────────────────────────────
    KaliTool(
        key="tcpdump", binaries=("tcpdump",), title="tcpdump — Captura de Tráfico",
        category=FORENSIC, risk=INTRUSIVE,
        profiles=("forensic", "all"),
        description="Captura acotada de tráfico a archivo PCAP para análisis forense y validación de cifrado en tránsito.",
        install_hint="apt install tcpdump", reference="https://www.tcpdump.org/manpages/tcpdump.1.html",
        requires_root=True, default_timeout=300, version_args=("--version",),
    ),
    KaliTool(
        key="tshark", binaries=("tshark",), title="tshark — Análisis de Tráfico",
        category=FORENSIC, risk=INTRUSIVE,
        profiles=("forensic", "all"),
        description="Captura e inspección de protocolos con Wireshark/tshark para evidencias forenses de red.",
        install_hint="apt install tshark", reference="https://www.wireshark.org/docs/man-pages/tshark.html",
        requires_root=True, default_timeout=300, version_args=("--version",),
    ),
    # ── Redes inalámbricas ───────────────────────────────────────────────────
    KaliTool(
        key="airodump_ng", binaries=("airodump-ng",), title="airodump-ng — Captura 802.11",
        category=WIRELESS, risk=INTRUSIVE,
        profiles=("wireless", "all"),
        description="Captura de tramas 802.11 (beacons, handshakes WPA) a fichero PCAP para análisis posterior.",
        install_hint="apt install aircrack-ng", reference="https://www.aircrack-ng.org/doku.php?id=airodump-ng",
        requires_root=True, default_timeout=300, version_args=("--help",),
    ),
    KaliTool(
        key="aircrack_ng", binaries=("aircrack-ng",), title="aircrack-ng — Auditoría de Claves Wi-Fi",
        category=WIRELESS, risk=PASSIVE,
        profiles=("wireless", "all"),
        description="Auditoría offline de la robustez de la clave WPA/WPA2 a partir de una captura de handshake aportada.",
        install_hint="apt install aircrack-ng", reference="https://www.aircrack-ng.org/doku.php?id=aircrack-ng",
        default_timeout=1800, version_args=("--help",),
    ),

    # ── Correlación de exploits (offline) ────────────────────────────────────
    KaliTool(
        key="searchsploit", binaries=("searchsploit",), title="searchsploit — Correlación con Exploit-DB",
        category=RECON, risk=PASSIVE,
        profiles=("osint", "web", "infra", "all"),
        description="Búsqueda local (offline) en Exploit-DB para correlacionar las tecnologías detectadas con exploits públicos.",
        install_hint="apt install exploitdb", reference="https://gitlab.com/exploit-database/exploitdb",
        default_timeout=120, version_args=("-h",),
    ),
)

KALI_TOOLS: Dict[str, KaliTool] = {tool.key: tool for tool in KALI_TOOL_LIST}


# ── Argv builders ────────────────────────────────────────────────────────────

def _base_dir_arg(req: ToolRequest, fallback: str = "/") -> str:
    path = (req.base_path or fallback).strip() or fallback
    if not path.startswith("/"):
        path = "/" + path
    if any(ch.isspace() for ch in path) or "\\" in path:
        raise KaliToolError(f"El parámetro 'base_path' tiene un formato inválido: {path!r}")
    return path


def _require_url(req: ToolRequest) -> str:
    if not req.url:
        raise KaliToolError("Esta herramienta requiere un objetivo HTTP(S) (--url o un target con esquema).")
    return sanitize_url(req.url)


def _require_wordlist(req: ToolRequest) -> str:
    if req.wordlist:
        return sanitize_existing_file(req.wordlist, "wordlist")
    auto = resolve_default_wordlist()
    if not auto:
        raise KaliToolError(
            "No se encontró ningún diccionario de palabras. Instala seclists (apt install seclists) "
            "o especifica uno con --wordlist."
        )
    return auto


def _build_nmap(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    args = ["-sV", "-Pn", "-T4", "-oX", req.artifact("nmap.xml"), "-oN", req.artifact("nmap.txt")]
    if req.ports:
        args += ["-p", sanitize_port_spec(req.ports)]
    else:
        args += ["--top-ports", "200"]
    scripts = (req.extras.get("nmap_scripts") or "").strip()
    if not scripts and str(req.extras.get("nmap_vuln", "")).lower() in ("1", "true", "yes"):
        scripts = "default,vuln"
    if scripts:
        args += ["--script", sanitize_token(scripts, "nmap_scripts", pattern=re.compile(r"^[A-Za-z0-9_,.*\-]{1,200}$"))]
    if req.sudo:
        args += ["-O", "--osscan-guess"]
    args += ["--host-timeout", f"{max(60, int(req.timeout_seconds) - 30)}s"]
    args.append(host)
    return args


def _build_masscan(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    ports = sanitize_port_spec(req.ports) if req.ports else "1-1024,3306,3389,5432,6379,8080,8443,9200,27017"
    return [
        host, f"-p{ports}", "-oX", req.artifact("masscan.xml"),
        "--rate", str(sanitize_positive_int(req.rate_limit, "rate_limit", 1, 100000)),
        "--wait", "2", "--open-only",
    ]


def _build_dnsrecon(req: ToolRequest) -> List[str]:
    domain = sanitize_domain(req.host)
    args = ["-d", domain, "-j", req.artifact("dnsrecon.json"), "--lifetime", "5", "--threads", "8"]
    if str(req.extras.get("dns_zone_transfer", "")).lower() in ("1", "true", "yes"):
        args += ["-t", "axfr"]
    else:
        args += ["-t", "std"]
    return args


def _build_amass(req: ToolRequest) -> List[str]:
    domain = sanitize_domain(req.host)
    return [
        "enum", "-passive", "-d", domain, "-o", req.artifact("amass.txt"),
        "-timeout", str(max(1, min(10, int(req.timeout_seconds) // 60 or 5))),
    ]


def _build_whatweb(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    return ["--no-errors", "--aggression", "3", f"--log-json={req.artifact('whatweb.json')}", url]


def _build_wafw00f(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    return ["-a", "-f", "json", "-o", req.artifact("wafw00f.json"), url]


def _build_httpx(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    return [
        "-u", url, "-json", "-o", req.artifact("httpx.jsonl"), "-silent", "-nc",
        "-sc", "-title", "-td", "-server", "-location", "-cl",
        "-rl", str(sanitize_positive_int(req.rate_limit, "rate_limit", 1, 1000)),
        "-timeout", str(max(1, min(60, int(req.timeout_seconds) // 10 or 10))),
    ]


def _build_nikto(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    max_seconds = max(60, min(3600, int(req.timeout_seconds) - 60))
    return [
        "-h", url, "-Format", "json", "-output", req.artifact("nikto.json"),
        "-nointeractive", "-maxtime", f"{max_seconds}s", "-ask", "no",
    ]


def _build_nuclei(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    severity = sanitize_token(req.severity_filter or "critical,high,medium", "severity_filter", pattern=_SEVERITY_FILTER_RE)
    return [
        "-u", url, "-jsonl", "-o", req.artifact("nuclei.jsonl"), "-silent", "-nc",
        "-no-interactsh", "-stats=false", "-severity", severity,
        "-rl", str(sanitize_positive_int(req.rate_limit, "rate_limit", 1, 1000)),
        "-timeout", "10", "-retries", "1",
    ]


def _build_gobuster(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    args = [
        "dir", "-u", url, "-w", _require_wordlist(req), "-q", "-o", req.artifact("gobuster.txt"),
        "-t", str(sanitize_positive_int(req.threads, "threads", 1, 100)),
        "-r", "--no-error", "--no-progress", "--no-color",
    ]
    extensions = (req.extras.get("extensions") or "").strip()
    if extensions:
        args += ["-x", sanitize_token(extensions, "extensions", pattern=_EXTENSIONS_RE)]
    if str(req.extras.get("insecure_tls", "")).lower() in ("1", "true", "yes"):
        args += ["-k"]
    return args


def _build_ffuf(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    target_url = url.rstrip("/") + "/FUZZ"
    args = [
        "-u", target_url, "-w", _require_wordlist(req), "-of", "json", "-o", req.artifact("ffuf.json"),
        "-s", "-noninteractive", "-ac", "-t", str(sanitize_positive_int(req.threads, "threads", 1, 100)),
    ]
    if str(req.extras.get("insecure_tls", "")).lower() in ("1", "true", "yes"):
        args += ["-k"]
    return args


def _build_dirb(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    return [url, _require_wordlist(req), "-S", "-N", "404", "-o", req.artifact("dirb.txt")]


def _build_wpscan(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    return [
        "--url", url, "--format", "json", "--output", req.artifact("wpscan.json"),
        "--no-banner", "--random-user-agent", "--disable-tls-checks",
        "--request-timeout", "15", "--connect-timeout", "10",
    ]


def _build_nbtscan(req: ToolRequest) -> List[str]:
    return ["-v", sanitize_host(req.host)]


def _build_enum4linux(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    args = ["-a"]
    username = (req.extras.get("smb_username") or "").strip()
    password = (req.extras.get("smb_password") or "").strip()
    if username:
        args += ["-u", sanitize_token(username, "smb_username", max_length=64)]
    if password:
        args += ["-p", sanitize_token(password, "smb_password", max_length=128)]
    args.append(host)
    return args


def _build_smbclient(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    return ["-L", f"//{host}", "-N", "-g", "-m", "SMB3"]


def _build_nxc(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    return ["smb", host, "--no-progress", "--timeout", "10"]


def _build_snmpwalk(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    community = sanitize_token(req.extras.get("snmp_community", "public"), "snmp_community", max_length=64)
    return ["-v2c", "-c", community, "-t", "5", "-r", "1", "-On", host]


def _build_onesixtyone(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    community_file = req.community_file
    if not community_file:
        community_file = os.path.join(req.work_dir, "snmp_communities.txt")
    args = ["-c", community_file, "-o", req.artifact("onesixtyone.txt"), host]
    return args


def _build_smtp_user_enum(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    userlist = req.userlist or resolve_default_file(DEFAULT_USERLIST_CANDIDATES)
    if not userlist:
        raise KaliToolError("smtp-user-enum requiere un listado de usuarios (--userlist).")
    userlist = sanitize_existing_file(userlist, "userlist")
    return ["-M", "VRFY", "-U", userlist, "-t", host, "-w", "5"]


def _build_sslscan(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    port = sanitize_positive_int(req.port or 443, "port")
    return ["--no-colour", f"--xml={req.artifact('sslscan.xml')}", f"{host}:{port}"]


def _build_sqlmap(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    return [
        "-u", url, "--batch", "--level", "2", "--risk", "1", "--threads", "4",
        "--output-dir", os.path.join(req.work_dir, "sqlmap"),
        "--flush-session", "--disable-coloring", "--timeout", "15", "--retries", "1",
    ]


def _build_commix(req: ToolRequest) -> List[str]:
    url = _require_url(req)
    return ["--url", url, "--batch", f"--output-dir={os.path.join(req.work_dir, 'commix')}", "--timeout=15"]


def _build_hydra(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    service = sanitize_token(req.service or "ssh", "service", pattern=_SERVICE_RE)
    # Las listas de credenciales las declara el operador y deben estar aprobadas en el alcance:
    # un ataque de fuerza bruta nunca usa diccionarios del sistema por defecto.
    userlist = req.userlist
    passlist = req.passlist
    if not userlist or not passlist:
        raise KaliToolError(
            "hydra requiere que el operador declare los diccionarios autorizados: --userlist y --passlist. "
            "No se emplean listas del sistema por defecto en pruebas de fuerza bruta."
        )
    userlist = sanitize_existing_file(userlist, "userlist")
    passlist = sanitize_existing_file(passlist, "passlist")
    args = [
        "-L", userlist, "-P", passlist, "-t", "4", "-f", "-I",
        "-o", req.artifact("hydra.txt"), "-s", str(sanitize_positive_int(req.port or _default_port(service), "port")),
    ]
    if req.service in ("https", "https-get", "smtps", "imaps", "pop3s", "ftps", "ldaps"):
        args += ["-S"]
    args += [service, host]
    return args


def _default_port(service: str) -> int:
    return {
        "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25, "http": 80, "http-get": 80,
        "https": 443, "https-get": 443, "smb": 445, "rdp": 3389, "vnc": 5900,
        "mysql": 3306, "postgres": 5432, "redis": 6379, "mongodb": 27017,
    }.get((service or "").lower(), 22)


def _build_john(req: ToolRequest) -> List[str]:
    hash_file = sanitize_existing_file(req.hash_file, "hash_file")
    args = [f"--pot={req.artifact('john.pot')}"]
    if req.wordlist:
        args.append(f"--wordlist={sanitize_existing_file(req.wordlist, 'wordlist')}")
    args.append(hash_file)
    return args


def _build_hashcat(req: ToolRequest) -> List[str]:
    hash_file = sanitize_existing_file(req.hash_file, "hash_file")
    wordlist = sanitize_existing_file(req.wordlist, "wordlist") if req.wordlist else None
    mode = sanitize_token(req.extras.get("hashcat_mode", "0"), "hashcat_mode", max_length=5)
    if not wordlist:
        raise KaliToolError("hashcat requiere un diccionario de palabras autorizado (--wordlist).")
    return [
        "-m", mode, "-a", "0", hash_file, wordlist,
        f"--potfile-path={req.artifact('hashcat.potfile')}",
        "--quiet", "--status", "--status-timer=30", "--force",
    ]


def _build_impacket_secretsdump(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host)
    domain = sanitize_token(req.extras.get("ad_domain", "WORKGROUP"), "ad_domain", max_length=64)
    username = req.extras.get("ad_username") or ""
    password = req.extras.get("ad_password") or ""
    if not username or not password:
        raise KaliToolError(
            "impacket-secretsdump requiere credenciales autorizadas (extras ad_username / ad_password)."
        )
    username = sanitize_token(username, "ad_username", max_length=64)
    password = sanitize_token(password, "ad_password", max_length=128)
    return [
        f"{domain}/{username}:{password}@{host}",
        "-outputfile", req.artifact("secretsdump"),
        "-just-dc-ntlm", "-dc-ip", host,
    ]


def _build_responder(req: ToolRequest) -> List[str]:
    interface = sanitize_token(req.extras.get("interface", "eth0"), "interface", pattern=re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$"))
    return ["-I", interface, "-A", "-w", "-v", "--lm", "0"]


def _build_tcpdump(req: ToolRequest) -> List[str]:
    duration = sanitize_positive_int(req.duration_seconds, "duration_seconds", 1, 3600)
    return [
        "-i", sanitize_token(req.extras.get("interface", "any"), "interface", pattern=re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")),
        "-s", "0", "-w", req.artifact("capture.pcap"), "-a",
        "-G", str(duration), "-W", "1",
    ]


def _build_tshark(req: ToolRequest) -> List[str]:
    duration = sanitize_positive_int(req.duration_seconds, "duration_seconds", 1, 3600)
    return [
        "-i", sanitize_token(req.extras.get("interface", "any"), "interface", pattern=re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")),
        "-a", f"duration:{duration}", "-w", req.artifact("capture.pcapng"),
    ]


def _build_airodump(req: ToolRequest) -> List[str]:
    interface = sanitize_token(
        req.extras.get("interface", "wlan0"), "interface",
        pattern=re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$"),
    )
    return [
        "--write", os.path.join(req.work_dir, "airodump"),
        "--output-format", "pcap", "--update", "5", "--berlin", "60", interface,
    ]


def _build_aircrack(req: ToolRequest) -> List[str]:
    capture = sanitize_existing_file(req.capture_file, "capture_file")
    wordlist = sanitize_existing_file(req.wordlist, "wordlist") if req.wordlist else resolve_default_wordlist()
    if not wordlist:
        raise KaliToolError(
            "aircrack-ng requiere un diccionario de palabras (--wordlist) para el ataque offline autorizado."
        )
    return ["-q", "-w", wordlist, "-l", req.artifact("aircrack.key"), capture]


def _build_searchsploit(req: ToolRequest) -> List[str]:
    term = req.term or req.extras.get("term") or ""
    term = sanitize_token(term, "term", pattern=_TECH_TERM_RE, max_length=60, allow_spaces=True)
    return ["--json", term]


def _build_testssl(req: ToolRequest) -> List[str]:
    host = sanitize_host(req.host or req.target)
    if "/" in host:
        raise KaliToolError("testssl requiere un host, no un rango")
    if ":" in host:
        host = f"[{host}]"
    port = sanitize_positive_int(req.port or 443, "port", 1, 65535)
    return ["--quiet", "--warnings", "batch", "--color", "0", "--protocols", "--std",
            "--connect-timeout", "10", "--openssl-timeout", "10",
            "--jsonfile", req.artifact("testssl.json"), f"{host}:{port}"]


def _build_feroxbuster(req: ToolRequest) -> List[str]:
    return ["--url", _require_url(req), "--wordlist", _require_wordlist(req),
            "--json", "--output", req.artifact("feroxbuster.jsonl"), "--quiet", "--no-state",
            "--no-recursion", "--dont-extract-links", "--auto-bail",
            "--threads", str(sanitize_positive_int(req.threads, "threads", 1, 20)),
            "--rate-limit", str(sanitize_positive_int(req.rate_limit, "rate_limit", 1, 100)),
            "--time-limit", f"{max(1, min(300, req.timeout_seconds))}s"]


_BUILDERS: Dict[str, Callable[[ToolRequest], List[str]]] = {
    "testssl": _build_testssl,
    "feroxbuster": _build_feroxbuster,
    "nmap": _build_nmap,
    "masscan": _build_masscan,
    "dnsrecon": _build_dnsrecon,
    "amass": _build_amass,
    "whatweb": _build_whatweb,
    "wafw00f": _build_wafw00f,
    "httpx": _build_httpx,
    "nikto": _build_nikto,
    "nuclei": _build_nuclei,
    "gobuster": _build_gobuster,
    "ffuf": _build_ffuf,
    "dirb": _build_dirb,
    "wpscan": _build_wpscan,
    "nbtscan": _build_nbtscan,
    "enum4linux": _build_enum4linux,
    "smbclient": _build_smbclient,
    "nxc": _build_nxc,
    "snmpwalk": _build_snmpwalk,
    "onesixtyone": _build_onesixtyone,
    "smtp_user_enum": _build_smtp_user_enum,
    "sslscan": _build_sslscan,
    "sqlmap": _build_sqlmap,
    "commix": _build_commix,
    "hydra": _build_hydra,
    "john": _build_john,
    "hashcat": _build_hashcat,
    "impacket_secretsdump": _build_impacket_secretsdump,
    "responder": _build_responder,
    "airodump_ng": _build_airodump,
    "aircrack_ng": _build_aircrack,
    "tcpdump": _build_tcpdump,
    "tshark": _build_tshark,
    "searchsploit": _build_searchsploit,
}

# Artifact produced by each tool: (filename, text-or-binary)
TOOL_ARTIFACTS: Dict[str, str] = {
    "testssl": "testssl.json",
    "feroxbuster": "feroxbuster.jsonl",
    "nmap": "nmap.xml",
    "masscan": "masscan.xml",
    "dnsrecon": "dnsrecon.json",
    "amass": "amass.txt",
    "whatweb": "whatweb.json",
    "wafw00f": "wafw00f.json",
    "httpx": "httpx.jsonl",
    "nikto": "nikto.json",
    "nuclei": "nuclei.jsonl",
    "gobuster": "gobuster.txt",
    "ffuf": "ffuf.json",
    "dirb": "dirb.txt",
    "wpscan": "wpscan.json",
    "sslscan": "sslscan.xml",
    "onesixtyone": "onesixtyone.txt",
    "smtp_user_enum": "smtp_user_enum.txt",
    "hydra": "hydra.txt",
    "john": "john.pot",
    "hashcat": "hashcat.potfile",
    "tcpdump": "capture.pcap",
    "tshark": "capture.pcapng",
    "airodump_ng": "airodump-01.cap",
    "aircrack_ng": "aircrack.key",
}

BINARY_ARTIFACTS = {"capture.pcap", "capture.pcapng", "airodump-01.cap"}

STANDARD_BIN_DIRS = (
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
)


def search_path() -> str:
    """PATH used for binary resolution: session PATH plus standard system dirs."""
    existing = os.environ.get("PATH", "")
    parts: List[str] = [p for p in existing.split(os.pathsep) if p]
    for directory in STANDARD_BIN_DIRS:
        if directory not in parts:
            parts.append(directory)
    return os.pathsep.join(parts)


def resolve_binary(tool: KaliTool) -> Optional[str]:
    """Returns the absolute path of the first available binary candidate, if any."""
    for candidate in tool.binaries:
        path = shutil.which(candidate, path=search_path())
        if path:
            return os.path.realpath(path)
    return None


def build_command(tool_key: str, request: ToolRequest) -> List[str]:
    """Builds the fully validated argv for a tool.

    Raises :class:`KaliToolError` when parameters are missing, malformed or when the
    tool requires root privileges that were not granted.
    """
    tool = KALI_TOOLS.get(tool_key)
    if tool is None:
        raise KaliToolError(f"Herramienta desconocida: {tool_key!r}")
    if tool.requires_root:
        if not request.sudo:
            raise KaliToolError(
                f"{tool.title} requiere privilegios de root (raw sockets). Ejecuta con --sudo "
                f"sobre una sesión con sudo sin contraseña configurado (sudo -n)."
            )
    builder = _BUILDERS.get(tool_key)
    if builder is None:
        raise KaliToolError(f"La herramienta {tool_key!r} no tiene constructor de argumentos registrado.")
    binary_path = resolve_binary(tool) or tool.binary
    args = list(builder(request))
    _assert_no_control_chars(args)
    return [binary_path] + args


def _assert_no_control_chars(args: List[str]) -> None:
    for arg in args:
        if any(ch in str(arg) for ch in ("\n", "\r", "\x00")):
            raise KaliToolError(f"Se detectaron caracteres de control en un argumento generado: {arg!r}")


# ── Availability discovery ───────────────────────────────────────────────────

@dataclass
class ToolStatus:
    """Runtime availability of a registered Kali tool."""

    tool: KaliTool
    path: Optional[str] = None
    version: Optional[str] = None
    available: bool = False
    notes: str = ""

    @property
    def key(self) -> str:
        return self.tool.key

    def to_dict(self) -> Dict[str, object]:
        return {
            "key": self.tool.key,
            "title": self.tool.title,
            "category": self.tool.category.value,
            "risk": self.tool.risk.value,
            "requires_root": self.tool.requires_root,
            "profiles": list(self.tool.profiles),
            "description": self.tool.description,
            "install_hint": self.tool.install_hint,
            "reference": self.tool.reference,
            "path": self.path,
            "version": self.version,
            "available": self.available,
            "notes": self.notes,
        }


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?)")

_DISCOVERY_CACHE: Dict[str, ToolStatus] = {}


def _probe_version(path: str, version_args: Tuple[str, ...], timeout: float = 6.0) -> Optional[str]:
    if not version_args:
        return None
    try:
        proc = subprocess.run(
            [path] + list(version_args),
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    blob = f"{proc.stdout}\n{proc.stderr}"
    blob = re.sub(r"\x1b\[[0-9;]*m", "", blob)
    for line in blob.splitlines():
        match = _VERSION_RE.search(line)
        if match and line.strip() and not line.strip().startswith("Usage"):
            return match.group(1)
    return None


def discover_tools(force: bool = False) -> List[ToolStatus]:
    """Returns availability and version for every registered tool (cached)."""
    if force:
        _DISCOVERY_CACHE.clear()
    results: List[ToolStatus] = []
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    for tool in KALI_TOOL_LIST:
        cached = _DISCOVERY_CACHE.get(tool.key)
        if cached is not None:
            results.append(cached)
            continue

        path = resolve_binary(tool)
        status = ToolStatus(tool=tool, path=path, available=bool(path))
        notes: List[str] = []
        if path:
            status.version = _probe_version(path, tool.version_args)
            if tool.requires_root and not is_root:
                notes.append("Requiere root (ejecutar con --sudo en sesión con sudo -n habilitado).")
        else:
            notes.append(f"No instalado. Instalación sugerida: {tool.install_hint}")
        if tool.requires_path and not os.path.exists(tool.requires_path):
            status.available = False
            notes.append(f"Datos auxiliares ausentes en {tool.requires_path}. Ejecuta la provisión de datos del paquete.")
        status.notes = " ".join(notes)
        _DISCOVERY_CACHE[tool.key] = status
        results.append(status)
    return results


def tool_status_map(force: bool = False) -> Dict[str, ToolStatus]:
    return {status.key: status for status in discover_tools(force=force)}


def available_tool_keys(force: bool = False) -> List[str]:
    return [status.key for status in discover_tools(force=force) if status.available]
