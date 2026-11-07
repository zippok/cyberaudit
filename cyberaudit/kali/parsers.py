"""
CyberAudit Kali Output Parsers
Deterministic, side-effect-free parsers that convert raw tool output (JSON, JSONL,
XML or text) into normalized :class:`ToolObservation` records.

Every parser is defensive: malformed or partial output never raises, it degrades to
an empty list so a broken tool run cannot abort the whole audit.
"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from cyberaudit.core.models import Severity, StrideCategory
from cyberaudit.infra.port_hygiene import EXPOSED_SERVICE_CATALOG

MAX_EVIDENCE_CHARS = 900


@dataclass
class ToolObservation:
    """Normalized, report-ready observation produced by a Kali tool."""

    tool_key: str
    title: str
    severity: Severity
    description: str
    slug: Optional[str] = None
    evidence: str = ""
    host: str = ""
    port: Optional[int] = None
    service: str = ""
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    stride_category: Optional[str] = None
    compliance_controls: Dict[str, str] = field(default_factory=dict)
    confidence: str = "HIGH"
    remediation: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.evidence and len(self.evidence) > MAX_EVIDENCE_CHARS:
            self.evidence = self.evidence[:MAX_EVIDENCE_CHARS] + " ... [TRUNCADO]"
        if self.remediation is None:
            self.remediation = _default_remediation(self.tool_key, self.severity)


def _default_remediation(tool_key: str, severity: Severity) -> str:
    hints = {
        "nmap": "Cerrar los puertos no necesarios en el firewall/perímetro, aplicar parches de versión y "
                "restringir la exposición de servicios administrativos a redes de gestión o VPN.",
        "masscan": "Reducir la superficie de exposición: cerrar puertos no utilizados y publicar servicios "
                   "únicamente a través de balanceadores o bastiones con control de acceso.",
        "nikto": "Actualizar el servidor web, eliminar archivos y CGI obsoletos, endurecer cabeceras de "
                 "seguridad y deshabilitar listados de directorio.",
        "nuclei": "Aplicar la actualización o mitigación indicada por la plantilla que disparó el hallazgo "
                  "y validar la corrección repitiendo el escaneo.",
        "gobuster": "Deshabilitar el listado de directorios, retirar recursos obsoletos o de respaldo del "
                    "document root y exigir autenticación en rutas sensibles.",
        "ffuf": "Retirar endpoints ocultos/no documentados del entorno productivo y proteger las rutas "
                "administrativas con autenticación fuerte y control de acceso por rol.",
        "dirb": "Eliminar del servidor web los recursos residuales (backups, paneles antiguos) y aplicar "
                "cabeceras de seguridad.",
        "wpscan": "Actualizar WordPress, plugins y temas; eliminar componentes no usados y establecer "
                  "rotación de contraseñas con MFA en el panel administrativo.",
        "whatweb": "Minimizar la divulgación de versiones (cabeceras Server/X-Powered-By) y mantener el "
                   "software en versiones soportadas con parcheo continuo.",
        "wafw00f": "Verificar que el WAF aplica reglas OWASP CRS en modo bloqueo y no sólo en modo monitor.",
        "httpx": "Revisar los endpoints expuestos y retirar los que no sean necesarios en producción.",
        "dnsrecon": "Deshabilitar transferencias de zona (AXFR) no autorizadas y revisar la exposición de "
                    "registros internos en el DNS público.",
        "amass": "Reducir la superficie de exposición externa retirando subdominios huérfanos y publicando "
                 "sólo los servicios necesarios.",
        "enum4linux": "Deshabilitar null sessions y sesiones anónimas, endurecer la política de contraseñas "
                      "y restringir los permisos de los recursos compartidos SMB.",
        "smbclient": "Restringir los recursos compartidos a usuarios autenticados y deshabilitar el acceso anónimo.",
        "nxc": "Habilitar SMB signing, deshabilitar la cuenta Invitado y aplicar el principio de mínimo privilegio "
               "en las cuentas de servicio de Active Directory.",
        "snmpwalk": "Migrar a SNMPv3 con autenticación y cifrado, cambiar las cadenas de comunidad por defecto "
                    "y filtrar el acceso UDP/161 a los gestores autorizados.",
        "onesixtyone": "Cambiar las cadenas de comunidad por defecto y migrar a SNMPv3 con autenticación.",
        "smtp_user_enum": "Deshabilitar VRFY/EXPN y aplicar respuestas genéricas para evitar la enumeración de buzones.",
        "nbtscan": "Deshabilitar NetBIOS sobre TCP/IP donde no sea imprescindible y segmentar la red.",
        "sslscan": "Deshabilitar protocolos obsoletos (SSLv2/SSLv3/TLS 1.0-1.1), retirar cifrados débiles y "
                   "renovar certificados con algoritmos fuertes (RSA-2048+/ECDSA).",
        "sqlmap": "Parametrizar todas las consultas SQL (prepared statements), validar la entrada en el servidor "
                  "con listas permitidas y aplicar mínimo privilegio a la cuenta de base de datos.",
        "commix": "Evitar la construcción de comandos con entrada del usuario y usar APIs del sistema sin shell.",
        "hydra": "Aplicar bloqueo por intentos fallidos, MFA y contraseñas robustas; rotar inmediatamente las "
                 "credenciales comprometidas y revisar accesos en los logs.",
        "john": "Imponer políticas de contraseñas robustas (longitud y entropía), migrar a algoritmos de hash "
                "con KDF (bcrypt/argon2) y forzar el cambio de contraseñas débiles.",
        "hashcat": "Imponer políticas de contraseñas robustas y migrar el almacenamiento de secretos a KDF "
                   "resistentes a GPU (argon2id/bcrypt).",
        "impacket_secretsdump": "Restringir los privilegios de replicación de Active Directory, habilitar "
                                "LSA Protection/Credential Guard y monitorizar eventos de DCSync.",
        "responder": "Deshabilitar LLMNR y NBT-NS, exigir SMB signing y segmentar la red para eliminar el "
                     "envenenamiento de resolución de nombres.",
        "tcpdump": "Revisar si el tráfico capturado debía circular en claro y forzar TLS en todos los servicios.",
        "tshark": "Revisar si el tráfico capturado debía circular en claro y forzar TLS en todos los servicios.",
        "searchsploit": "Priorizar la actualización de los componentes detectados y revisar si las versiones "
                        "expuestas están dentro del soporte del fabricante.",
    }
    base = hints.get(tool_key, "Revisar el hallazgo, aplicar la mitigación correspondiente y revalidar con una nueva ejecución.")
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return base + " Documentar la corrección con evidencia de validación posterior."
    return base


# ── Helpers ──────────────────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.INFO,
}

WEAK_TLS_KEYWORDS: Tuple[Tuple[str, Severity, str], ...] = (
    ("RC4", Severity.HIGH, "Cifrador de flujo RC4 criptográficamente roto."),
    ("3DES", Severity.HIGH, "Triple-DES vulnerable al ataque Sweet32 (CVE-2016-2183)."),
    ("DES-CBC3", Severity.HIGH, "Triple-DES (CBC3) vulnerable a Sweet32."),
    ("NULL", Severity.CRITICAL, "Suite sin cifrado (tráfico en claro)."),
    ("EXPORT", Severity.CRITICAL, "Cifrados de exportación débiles (vulnerable a FREAK/Logjam)."),
    ("MD5", Severity.HIGH, "Algoritmo MD5 vulnerable a colisiones."),
    ("ANON", Severity.CRITICAL, "Intercambio de claves anónimo: sin autenticación del servidor."),
)

#: Protocolos TLS/SSL obsoletos en forma canónica (type+version sin separadores), p.ej. 'ssl3', 'tls1.1'
DEPRECATED_TLS_CANONICAL = {"ssl2", "ssl3", "tls1", "tls1.0", "tls1.1", "tls10", "tls11"}


def _sev(value: Any, default: Severity = Severity.INFO) -> Severity:
    if isinstance(value, Severity):
        return value
    return _SEV_MAP.get(str(value or "").strip().lower(), default)


def _first_cve(text: str) -> Optional[str]:
    match = _CVE_RE.search(text or "")
    return match.group(0).upper() if match else None


def _all_cves(text: str) -> List[str]:
    return sorted({m.upper() for m in _CVE_RE.findall(text or "")})


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, dict):
        return [str(v) for v in value.values() if str(v).strip()]
    return [str(value)]


def _load_json(content: str) -> Any:
    try:
        return json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None


def _iter_jsonl(content: str) -> Iterable[Dict[str, Any]]:
    for line in (content or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{") and not line.startswith("["):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    yield item


def _port_catalog_entry(port: int):
    return EXPOSED_SERVICE_CATALOG.get(int(port))


def _http_url_from_url(value: str) -> str:
    value = (value or "").strip()
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value}" if value else value


# ── Nmap / Masscan ───────────────────────────────────────────────────────────

_NMAP_SCRIPT_RULES: Tuple[Tuple[str, Severity, str, str], ...] = (
    (r"^smb-vuln-ms17-010$", Severity.CRITICAL, "SMB vulnerable a MS17-010 (EternalBlue)",
     "El objetivo es explotable mediante MS17-010, permitiendo ejecución remota de código como SYSTEM."),
    (r"^smb-vuln-ms08-067$", Severity.CRITICAL, "SMB vulnerable a MS08-067",
     "Vulnerabilidad crítica de ejecución remota de código en el servicio Server."),
    (r"^smb-vuln-", Severity.HIGH, "Vulnerabilidad SMB confirmada por script NSE",
     "Un script NSE de Nmap confirmó una vulnerabilidad en el servicio SMB del objetivo."),
    (r"^http-shellshock$", Severity.CRITICAL, "CGI vulnerable a Shellshock (CVE-2014-6271)",
     "Un CGI del servidor web es vulnerable a Shellshock, permitiendo ejecución remota de comandos."),
    (r"^ssl-heartbleed$", Severity.CRITICAL, "OpenSSL vulnerable a Heartbleed (CVE-2014-0160)",
     "El servicio TLS es vulnerable a Heartbleed, exponiendo memoria del proceso."),
    (r"^http-vuln-cve2017-5638$", Severity.CRITICAL, "Apache Struts2 vulnerable a CVE-2017-5638",
     "El endpoint es vulnerable a ejecución remota de código mediante el header Content-Type."),
    (r"^rdp-vuln-ms12-020$", Severity.CRITICAL, "RDP vulnerable a MS12-020",
     "El servicio RDP permite provocar un fallo remoto de denegación de servicio."),
    (r"^ftp-anon$", Severity.HIGH, "Acceso anónimo FTP habilitado",
     "El servidor FTP permite autenticación anónima, exponiendo los archivos publicados."),
    (r"^(mysql|ms-sql|oracle)-empty-password", Severity.CRITICAL, "Credenciales de base de datos en blanco",
     "El servicio de base de datos acepta autenticación con contraseña vacía."),
    (r"^vnc-brute", Severity.CRITICAL, "Servicio VNC sin autenticación efectiva",
     "El servidor VNC aceptó autenticación trivial o en blanco."),
    (r"^smb-enum-shares$", Severity.MEDIUM, "Recursos compartidos SMB enumerados",
     "Nmap pudo listar recursos compartidos SMB, incluyendo metadatos y permisos."),
    (r"^smb-os-discovery$", Severity.INFO, "Descubrimiento de sistema operativo vía SMB",
     "El objetivo divulga el sistema operativo, el nombre de equipo y el dominio a través de SMB."),
    (r"^snmp-", Severity.MEDIUM, "Información divulgada por SNMP",
     "El agente SNMP responde a la comunidad por defecto y expone información del sistema."),
    (r"^tls-|^ssl-enum-ciphers$", Severity.LOW, "Configuración TLS/SMTP enumerada",
     "La configuración criptográfica del servicio pudo enumerarse y contiene parámetros a revisar."),
    (r"^http-csrf$", Severity.MEDIUM, "Formulario sin protección CSRF",
     "Se detectó al menos un formulario sin token anti-CSRF."),
    (r"^http-sql-injection$", Severity.HIGH, "Posible inyección SQL detectada por Nmap NSE",
     "El script NSE de Nmap identificó un parámetro potencialmente inyectable."),
    (r"^http-stored-xss$|^http-dombased-xss$|^http-phpself-xss$", Severity.HIGH, "Posible XSS detectado por Nmap NSE",
     "El script NSE de Nmap identificó un vector de Cross-Site Scripting."),
    (r"^http-put$", Severity.HIGH, "Método HTTP PUT habilitado",
     "El servidor web admite subida de archivos mediante PUT, permitiendo publicar contenido arbitrario."),
    (r"^http-iis-webdav-vuln$", Severity.CRITICAL, "IIS WebDAV vulnerable",
     "WebDAV en IIS permite la ejecución de archivos subidos."),
    (r"^ipmi-cipher-zero$", Severity.CRITICAL, "IPMI con cifrado cero (CVE-2013-4786)",
     "La interfaz IPMI expone hashes de contraseña recuperables con cipher zero."),
    (r"^http-config-backup$", Severity.HIGH, "Copias de configuración accesibles",
     "Se localizaron archivos de configuración/respaldo accesibles públicamente."),
)

_NMAP_INTERESTING_INFO_SCRIPTS = {
    "http-title": "Título de página",
    "http-server-header": "Cabecera Server",
    "http-headers": "Cabeceras HTTP",
    "ssh-hostkey": "Claves SSH del host",
    "ssl-cert": "Certificado TLS",
}


def _nmap_script_observation(tool_key: str, host: str, port: Optional[int], script_id: str,
                             output: str, service: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    lowered = (output or "").lower()

    for pattern, severity, title, description in _NMAP_SCRIPT_RULES:
        if re.search(pattern, script_id, re.IGNORECASE):
            if severity is Severity.INFO and "vulnerable" not in lowered and len(observations) > 0:
                continue
            observations.append(ToolObservation(
                tool_key=tool_key,
                slug=f"{script_id}-{port or 0}",
                title=f"{title} ({host}{':' + str(port) if port else ''})",
                severity=severity,
                description=description,
                evidence=f"[{script_id}] {output}",
                host=host,
                port=port,
                service=service,
                cwe_id="CWE-1395" if severity in (Severity.CRITICAL, Severity.HIGH) else "CWE-200",
                cve_id=_first_cve(f"{script_id} {output}"),
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value if severity in (Severity.CRITICAL, Severity.HIGH)
                else StrideCategory.INFORMATION_DISCLOSURE.value,
                confidence="HIGH",
                raw={"script_id": script_id, "output": output[:2000]},
            ))
            return observations

    if script_id in _NMAP_INTERESTING_INFO_SCRIPTS and output.strip():
        label = _NMAP_INTERESTING_INFO_SCRIPTS[script_id]
        observations.append(ToolObservation(
            tool_key=tool_key,
            slug=f"{script_id}-{port or 0}",
            title=f"{label}: {output.strip()[:80]}",
            severity=Severity.INFO,
            description=f"Nmap recolectó información del servicio mediante el script NSE '{script_id}'.",
            evidence=f"[{script_id}] {output}",
            host=host,
            port=port,
            service=service,
            cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
            confidence="HIGH",
            raw={"script_id": script_id, "output": output[:2000]},
        ))
        return observations

    # Generic fallback: any NSE output mentioning VULNERABLE or a CVE is reported.
    cves = _all_cves(f"{script_id} {output}")
    if "vulnerable" in lowered or cves:
        severity = Severity.HIGH if cves else Severity.MEDIUM
        observations.append(ToolObservation(
            tool_key=tool_key,
            slug=f"{script_id}-{port or 0}",
            title=f"Resultado relevante del script NSE '{script_id}' ({host}{':' + str(port) if port else ''})",
            severity=severity,
            description="El script NSE reportó indicios de vulnerabilidad que requieren validación manual.",
            evidence=f"[{script_id}] {output}",
            host=host,
            port=port,
            service=service,
            cwe_id="CWE-1395",
            cve_id=cves[0] if cves else None,
            references=[f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cves[:5]],
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
            confidence="MEDIUM",
            raw={"script_id": script_id, "output": output[:2000]},
        ))
    return observations


def parse_nmap_xml(content: str, target: str = "") -> List[ToolObservation]:
    """Parses Nmap/masscan XML output into port and NSE-script observations."""
    return _parse_port_scan_xml(content, target, tool_key="nmap")


def parse_masscan_xml(content: str, target: str = "") -> List[ToolObservation]:
    return _parse_port_scan_xml(content, target, tool_key="masscan")


def _parse_port_scan_xml(content: str, target: str, tool_key: str) -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return observations

    for host_node in root.iter("host"):
        host = target
        for address in host_node.findall("address"):
            if address.get("addrtype") in ("ipv4", "ipv6"):
                host = address.get("addr") or host
                break
        for hostname in host_node.iter("hostname"):
            name = hostname.get("name")
            if name:
                host = f"{name} ({host})" if host and host != name else name
                break

        for port_node in host_node.iter("port"):
            state = port_node.find("state")
            if state is None or state.get("state") not in ("open", "open|filtered"):
                continue
            try:
                port = int(port_node.get("portid", "0"))
            except ValueError:
                continue
            protocol = port_node.get("protocol", "tcp")
            service_node = port_node.find("service")
            service_name = service_node.get("name", "") if service_node is not None else ""
            product = service_node.get("product", "") if service_node is not None else ""
            version = service_node.get("version", "") if service_node is not None else ""
            banner = " ".join(part for part in (service_name, product, version) if part).strip()

            catalog = _port_catalog_entry(port)
            if catalog:
                svc_label, category, description, severity, cwe, remediation = catalog
                observations.append(ToolObservation(
                    tool_key=tool_key,
                    slug=f"port-{port}",
                    title=f"Servicio crítico expuesto: {svc_label} en {host}:{port}/{protocol}",
                    severity=severity,
                    description=f"{description} Categoría: {category}. Servicio detectado: {banner or svc_label}.",
                    evidence=f"{host}:{port}/{protocol} abierto — servicio: {banner or svc_label}",
                    host=host,
                    port=port,
                    service=service_name or svc_label,
                    cwe_id=cwe,
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    remediation=remediation,
                    confidence="HIGH",
                    raw={"banner": banner, "protocol": protocol},
                ))
            else:
                observations.append(ToolObservation(
                    tool_key=tool_key,
                    slug=f"port-{port}",
                    title=f"Puerto abierto {port}/{protocol} en {host}",
                    severity=Severity.INFO if port not in (22, 3389) else Severity.LOW,
                    description=(
                        f"El puerto {port}/{protocol} acepta conexiones. Servicio identificado: "
                        f"{banner or 'no identificado'}. Inventariar y confirmar si debe estar expuesto."
                    ),
                    evidence=f"{host}:{port}/{protocol} open — {banner or 'sin banner'}",
                    host=host,
                    port=port,
                    service=service_name,
                    cwe_id="CWE-200",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    confidence="HIGH",
                    raw={"banner": banner, "protocol": protocol},
                ))

            for script in port_node.iter("script"):
                script_id = script.get("id", "")
                output = script.get("output", "") or ""
                observations.extend(_nmap_script_observation(tool_key, host, port, script_id, output, service_name))

        for script in host_node.findall("./hostscript/script"):
            script_id = script.get("id", "")
            output = script.get("output", "") or ""
            observations.extend(_nmap_script_observation(tool_key, host, None, script_id, output))

        os_matches = [m.get("name", "") for m in host_node.iter("osmatch") if m.get("name")]
        if os_matches:
            observations.append(ToolObservation(
                tool_key=tool_key, slug="os-fingerprint",
                title=f"Sistema operativo identificado: {os_matches[0]}",
                severity=Severity.INFO,
                description="La huella TCP/IP permitió identificar el sistema operativo del objetivo.",
                evidence=f"Coincidencias: {', '.join(os_matches[:3])}",
                host=host, cwe_id="CWE-200",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                confidence="MEDIUM",
            ))
    return observations


# ── Web DAST ─────────────────────────────────────────────────────────────────

def parse_nuclei_jsonl(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    for item in _iter_jsonl(content):
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        severity = _sev(info.get("severity"))
        template_id = str(item.get("template-id") or item.get("templateID") or "nuclei-template")
        name = str(info.get("name") or template_id)
        matched_at = str(item.get("matched-at") or item.get("matched") or item.get("host") or target)
        cves = _as_list(classification.get("cve-id")) or _all_cves(json.dumps(info))
        cwe = _as_list(classification.get("cwe-id"))
        references = _as_list(info.get("reference")) or [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:3]]
        evidence_bits = [f"template: {template_id}", f"matched: {matched_at}"]
        if item.get("matcher-name"):
            evidence_bits.append(f"matcher: {item.get('matcher-name')}")
        if item.get("extracted-results"):
            evidence_bits.append(f"extraído: {item.get('extracted-results')}")
        if item.get("curl-command"):
            evidence_bits.append(f"petición: {str(item.get('curl-command'))[:300]}")

        observations.append(ToolObservation(
            tool_key="nuclei",
            slug=f"{template_id}-{_slugify(matched_at)}",
            title=f"{name} — {matched_at}",
            severity=severity,
            description=str(info.get("description") or f"Plantilla {template_id} de Nuclei disparada sobre el objetivo."),
            evidence="\n".join(evidence_bits),
            host=str(item.get("host") or target),
            cwe_id=cwe[0] if cwe else None,
            cve_id=cves[0] if cves else None,
            references=[r for r in references if r][:5],
            stride_category=_stride_for_severity(severity),
            compliance_controls=_compliance_for_cves(cves),
            confidence="HIGH",
            raw={k: v for k, v in item.items() if k in ("type", "host", "matched-at", "ip", "timestamp", "template-id")},
        ))
    return observations


def parse_nikto_json(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    payload = _load_json(content)
    if payload is None:
        return _parse_nikto_text(content, target)
    hosts = payload if isinstance(payload, list) else [payload]
    for host_entry in hosts:
        if not isinstance(host_entry, dict):
            continue
        host = str(host_entry.get("host") or target)
        port = host_entry.get("port")
        banner = str(host_entry.get("server_banner") or "")
        for item in host_entry.get("vulnerabilities", []) or []:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or "")
            message = str(item.get("msg") or "")
            url = str(item.get("url") or "")
            method = str(item.get("method") or "GET")
            references = _as_list(item.get("references"))
            cves = _all_cves(f"{item_id} {message} {' '.join(references)}")
            severity = Severity.HIGH if cves or "injection" in message.lower() else Severity.MEDIUM
            if re.search(
                r"outdated|obsolete|default (password|file|account)|backup file|config\.? file|\.env|\.git|\bshellshock\b|disclosure",
                message, re.IGNORECASE,
            ):
                severity = Severity.HIGH
            observations.append(ToolObservation(
                tool_key="nikto",
                slug=f"{item_id or 'finding'}-{_slugify(url)}"[:120],
                title=f"Nikto {item_id}: {message[:110]}",
                severity=severity,
                description=(
                    f"El escáner de servidores web reportó el hallazgo {item_id or 'sin identificador'} sobre "
                    f"{url or host}. Banner del servidor: {banner or 'no disponible'}."
                ),
                evidence=f"{method} {url}\n{item_id}: {message}\n{('refs: ' + ', '.join(references)) if references else ''}",
                host=host,
                port=int(port) if isinstance(port, int) and str(port).isdigit() else None,
                cwe_id="CWE-200",
                cve_id=cves[0] if cves else None,
                references=[r for r in references if r.startswith("http")][:5],
                stride_category=_stride_for_severity(severity),
                confidence="MEDIUM",
                raw={"nikto_id": item_id, "method": method, "url": url},
            ))
    return observations


def _parse_nikto_text(content: str, target: str) -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    for line in (content or "").splitlines():
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()
        if ":" not in body:
            continue
        item_id, _, message = body.partition(":")
        if not item_id.startswith(("OSVDB", "CVE", "001", "002", "003", "004", "005", "006", "007", "008", "009", "01")):
            continue
        cves = _all_cves(f"{item_id} {message}")
        observations.append(ToolObservation(
            tool_key="nikto",
            slug=f"{item_id.strip()}-{_slugify(message[:40])}",
            title=f"Nikto {item_id.strip()}: {message.strip()[:110]}",
            severity=Severity.HIGH if cves else Severity.MEDIUM,
            description="El escáner Nikto reportó este hallazgo sobre el servidor web objetivo.",
            evidence=line.strip(),
            host=target,
            cwe_id="CWE-200",
            cve_id=cves[0] if cves else None,
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
            confidence="MEDIUM",
        ))
    return observations


def parse_whatweb_json(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    payload = _load_json(content)
    if payload is None:
        return observations

    # WhatWeb writes either a dict keyed by URL or a list of scan entries.
    if isinstance(payload, list):
        entries: List[Tuple[str, Any]] = [
            (str(item.get("target") or target), item) for item in payload if isinstance(item, dict)
        ]
    elif isinstance(payload, dict):
        entries = [(str(url), entry) for url, entry in payload.items()]
    else:
        return observations

    for url, entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins") if isinstance(entry.get("plugins"), dict) else {}
        techs: List[str] = []
        versioned: List[str] = []
        noise = {"IP", "Country", "UncommonHeaders", "Cookies", "HttpOnly", "Account", "RedirectLocation", "Title"}
        for name, data in plugins.items():
            if name in noise:
                continue
            versions = _as_list((data or {}).get("version")) if isinstance(data, dict) else []
            strings = _as_list((data or {}).get("string")) if isinstance(data, dict) else []
            label = name
            if versions:
                label += f" {versions[0]}"
                versioned.append(f"{name} {versions[0]}")
            elif strings:
                label += f" ({strings[0][:60]})"
            techs.append(label)

        if techs:
            observations.append(ToolObservation(
                tool_key="whatweb",
                slug=f"fingerprint-{_slugify(str(url))}",
                title=f"Huella tecnológica del objetivo: {', '.join(techs[:5])}",
                severity=Severity.INFO,
                description=(
                    "WhatWeb identificó las tecnologías expuestas por el objetivo. Esta huella permite correlacionar "
                    "versiones con vulnerabilidades públicas conocidas."
                ),
                evidence=f"{url}\n" + "\n".join(f"- {t}" for t in techs[:15]),
                host=str(entry.get("target") or url),
                cwe_id="CWE-200",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                confidence="HIGH",
                raw={"plugins": list(plugins.keys())[:30]},
            ))
        if versioned:
            observations.append(ToolObservation(
                tool_key="whatweb",
                slug=f"version-disclosure-{_slugify(str(url))}",
                title=f"Divulgación de versiones software ({len(versioned)} componentes)",
                severity=Severity.LOW,
                description=(
                    "El servidor publica versiones exactas de sus componentes, facilitando la búsqueda de exploits "
                    "específicos (CWE-200, OWASP A05:2021 Security Misconfiguration)."
                ),
                evidence=", ".join(versioned[:12]),
                host=str(entry.get("target") or url),
                cwe_id="CWE-200",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                confidence="HIGH",
            ))
    return observations


def parse_wafw00f_json(content: str, target: str = "") -> List[ToolObservation]:
    payload = _load_json(content)
    if payload is None:
        return _parse_wafw00f_text(content, target)
    entries = payload if isinstance(payload, list) else [payload]
    observations: List[ToolObservation] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or target)
        detected = bool(entry.get("detected"))
        firewall = str(entry.get("firewall") or "no identificado")
        if detected:
            observations.append(ToolObservation(
                tool_key="wafw00f", slug=f"waf-{_slugify(url)}",
                title=f"WAF detectado: {firewall}",
                severity=Severity.INFO,
                description="El objetivo está protegido por un WAF. Verificar que opera en modo bloqueo y con reglas actualizadas.",
                evidence=f"Objetivo: {url}\nWAF: {firewall}\nFabricante: {entry.get('manufacturer') or 'n/d'}",
                host=url, cwe_id="CWE-693",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                confidence="MEDIUM",
            ))
        else:
            observations.append(ToolObservation(
                tool_key="wafw00f", slug=f"no-waf-{_slugify(url)}",
                title="Sin WAF detectado delante del servicio web",
                severity=Severity.LOW,
                description=(
                    "No se identificó ninguna protección WAF. El servicio queda expuesto directamente a ataques "
                    "automatizados de aplicación (OWASP A05:2021 Security Misconfiguration)."
                ),
                evidence=f"Objetivo: {url}\nResultado: no se detectó un WAF reconocible.",
                host=url, cwe_id="CWE-693",
                stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                confidence="MEDIUM",
            ))
    return observations


def _parse_wafw00f_text(content: str, target: str) -> List[ToolObservation]:
    lowered = (content or "").lower()
    observations: List[ToolObservation] = []
    match = re.search(r"is behind\s+(.+?)\s+waf", lowered)
    if match:
        observations.append(ToolObservation(
            tool_key="wafw00f", slug=f"waf-{_slugify(target)}",
            title=f"WAF detectado: {match.group(1).strip()}",
            severity=Severity.INFO,
            description="El objetivo está protegido por un WAF.",
            evidence=content[-500:], host=target, cwe_id="CWE-693",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="MEDIUM",
        ))
    elif "no waf detected" in lowered:
        observations.append(ToolObservation(
            tool_key="wafw00f", slug=f"no-waf-{_slugify(target)}",
            title="Sin WAF detectado delante del servicio web",
            severity=Severity.LOW,
            description="No se identificó ninguna protección WAF delante del servicio.",
            evidence=content[-500:], host=target, cwe_id="CWE-693",
            stride_category=StrideCategory.DENIAL_OF_SERVICE.value, confidence="MEDIUM",
        ))
    return observations


def parse_httpx_jsonl(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    for item in _iter_jsonl(content):
        url = str(item.get("url") or target)
        status = item.get("status_code") or item.get("status-code")
        tech = _as_list(item.get("tech") or item.get("technologies"))
        server = str(item.get("webserver") or item.get("web-server") or "")
        title = str(item.get("title") or "")
        cdn = str(item.get("cdn_name") or "")
        bits = [f"URL: {url}"]
        if status:
            bits.append(f"HTTP {status}")
        if title:
            bits.append(f"Título: {title[:120]}")
        if server:
            bits.append(f"Servidor: {server}")
        if tech:
            bits.append(f"Tecnologías: {', '.join(tech[:12])}")
        if cdn:
            bits.append(f"CDN: {cdn}")
        severity = Severity.INFO
        if isinstance(status, int) and status >= 500:
            severity = Severity.LOW
        observations.append(ToolObservation(
            tool_key="httpx", slug=f"probe-{_slugify(url)}",
            title=f"Endpoint HTTP activo ({status or 'sin código'}): {url}",
            severity=severity,
            description="Sondeo HTTP del endpoint: tecnología, servidor y metadatos de respuesta.",
            evidence="\n".join(bits),
            host=str(item.get("host") or url),
            cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
            confidence="HIGH",
        ))
    return observations


def parse_gobuster_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    # gobuster 3.x prints the discovered path with or without a leading slash
    pattern = re.compile(
        r"^(?P<path>/?\S*)\s+\(Status:\s*(?P<status>\d{3})\)"
        r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
        r"(?:.*?\[-->\s*(?P<redirect>\S+)\])?\s*$"
    )
    for line in (content or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        status = int(match.group("status"))
        path = match.group("path") or "/"
        if not path.startswith("/"):
            path = "/" + path
        size = match.group("size") or "n/d"
        redirect = match.group("redirect") or ""
        if status in (404,):
            continue
        severity = Severity.MEDIUM if status == 200 else Severity.LOW
        if status in (401, 403):
            severity = Severity.INFO
        observations.append(ToolObservation(
            tool_key="gobuster",
            slug=f"path-{_slugify(path)}",
            title=f"Ruta descubierta ({status}): {path}",
            severity=severity,
            description=(
                f"La enumeración de directorios localizó el recurso '{path}' con respuesta HTTP {status} "
                f"({size} bytes){' redirigiendo a ' + redirect if redirect else ''}. "
                "Confirmar si el recurso debe estar publicado y si exige autenticación."
            ),
            evidence=line.strip(),
            host=target,
            cwe_id="CWE-200" if status == 200 else "CWE-693",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
            confidence="HIGH",
            raw={"path": path, "status": status, "size": size, "redirect": redirect},
        ))
    return observations


def parse_dirb_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    found_re = re.compile(r"^\+ (?P<url>https?://\S*) \(CODE:(?P<code>\d+)\|SIZE:(?P<size>\d+)\)")
    dir_re = re.compile(r"^==> DIRECTORY: (?P<url>\S+)")
    seen: set = set()
    for line in (content or "").splitlines():
        line = line.strip()
        match = found_re.match(line)
        if match:
            url, code, size = match.group("url"), int(match.group("code")), match.group("size")
            if url in seen:
                continue
            seen.add(url)
            severity = Severity.MEDIUM if code == 200 else (Severity.INFO if code in (401, 403) else Severity.LOW)
            observations.append(ToolObservation(
                tool_key="dirb", slug=f"path-{_slugify(url)}",
                title=f"Recurso accesible ({code}): {url}",
                severity=severity,
                description=f"DIRB localizó el recurso {url} con código HTTP {code} y {size} bytes de respuesta.",
                evidence=line, host=target, cwe_id="CWE-200",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
            ))
            continue
        match = dir_re.match(line)
        if match:
            url = match.group("url")
            if url in seen:
                continue
            seen.add(url)
            observations.append(ToolObservation(
                tool_key="dirb", slug=f"dir-{_slugify(url)}",
                title=f"Directorio accesible: {url}",
                severity=Severity.MEDIUM,
                description=(
                    f"Se identificó el directorio {url}. Verificar el listado de ficheros, la existencia de "
                    "indexado automático y si contiene material sensible."
                ),
                evidence=line, host=target, cwe_id="CWE-548",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
            ))
    return observations


def parse_ffuf_json(content: str, target: str = "") -> List[ToolObservation]:
    payload = _load_json(content)
    observations: List[ToolObservation] = []
    if not isinstance(payload, dict):
        return observations
    for item in payload.get("results", []) or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or target)
        status = item.get("status")
        length = item.get("length")
        words = item.get("words")
        input_data = item.get("input") if isinstance(item.get("input"), dict) else {}
        payload_value = next(iter(input_data.values()), "") if input_data else ""
        severity = Severity.MEDIUM if status == 200 else Severity.LOW
        if status in (401, 403):
            severity = Severity.INFO
        observations.append(ToolObservation(
            tool_key="ffuf", slug=f"path-{_slugify(url)}",
            title=f"Recurso descubierto por fuzzing ({status}): {url}",
            severity=severity,
            description=(
                f"El fuzzing con FFuf encontró el recurso '{payload_value}' con respuesta HTTP {status} "
                f"({length} bytes, {words} palabras)."
            ),
            evidence=f"{url}\nstatus={status} length={length} words={words} payload={payload_value}",
            host=str(item.get("host") or target),
            cwe_id="CWE-200" if status == 200 else "CWE-693",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
            confidence="HIGH",
            raw={"status": status, "url": url},
        ))
    return observations


def parse_wpscan_json(content: str, target: str = "") -> List[ToolObservation]:
    payload = _load_json(content)
    observations: List[ToolObservation] = []
    if not isinstance(payload, dict):
        return observations

    site = str(payload.get("target_url") or payload.get("effective_url") or target)
    banner = payload.get("banner") if isinstance(payload.get("banner"), dict) else {}
    if banner:
        observations.append(ToolObservation(
            tool_key="wpscan", slug="fingerprint",
            title=f"WordPress identificado: {banner.get('version') or 'versión no determinada'}",
            severity=Severity.INFO,
            description="WPScan confirmó la presencia de WordPress y su versión expuesta.",
            evidence=json.dumps(banner, ensure_ascii=False)[:600],
            host=site, cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
        ))

    version = payload.get("version") if isinstance(payload.get("version"), dict) else {}
    if version.get("status") and str(version.get("status")).lower() not in ("latest", "newest"):
        observations.append(ToolObservation(
            tool_key="wpscan", slug="core-outdated",
            title=f"WordPress desactualizado: {version.get('number')} ({version.get('status')})",
            severity=Severity.HIGH,
            description=(
                f"El núcleo de WordPress está en la versión {version.get('number')} con estado "
                f"'{version.get('status')}'. Las versiones no soportadas acumulan vulnerabilidades públicas sin parche."
            ),
            evidence=json.dumps(version, ensure_ascii=False)[:800],
            host=site, cwe_id="CWE-1104",
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value, confidence="HIGH",
        ))
    for vuln in version.get("vulnerabilities", []) or []:
        if not isinstance(vuln, dict):
            continue
        cves = _as_list((vuln.get("references") or {}).get("cve")) if isinstance(vuln.get("references"), dict) else []
        observations.append(ToolObservation(
            tool_key="wpscan", slug=f"core-vuln-{_slugify(str(vuln.get('title'))[:40])}",
            title=f"Vulnerabilidad en el núcleo de WordPress: {vuln.get('title')}",
            severity=_severity_from_cvss(vuln.get("cvss")),
            description=f"El núcleo de WordPress es vulnerable: {vuln.get('title')} (corregido en {vuln.get('fixed_in') or 'n/d'}).",
            evidence=json.dumps(vuln, ensure_ascii=False)[:800],
            host=site, cwe_id="CWE-1395",
            cve_id=cves[0] if cves else None,
            references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:5]],
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value, confidence="HIGH",
        ))

    for component in ("plugins", "themes"):
        entries = payload.get(component) if isinstance(payload.get(component), dict) else {}
        for slug, data in entries.items():
            if not isinstance(data, dict):
                continue
            version_str = ""
            if isinstance(data.get("version"), dict):
                version_str = str(data["version"].get("number") or "")
            if data.get("vulnerabilities"):
                for vuln in data["vulnerabilities"][:5]:
                    if not isinstance(vuln, dict):
                        continue
                    cves = _as_list((vuln.get("references") or {}).get("cve")) if isinstance(vuln.get("references"), dict) else []
                    observations.append(ToolObservation(
                        tool_key="wpscan", slug=f"{component}-{_slugify(slug)}-vuln",
                        title=f"{_COMPONENT_LABELS.get(component, component)} vulnerable: {slug} {version_str}".strip(),
                        severity=_severity_from_cvss(vuln.get("cvss")),
                        description=f"{vuln.get('title')} (corregido en {vuln.get('fixed_in') or 'n/d'}).",
                        evidence=json.dumps(vuln, ensure_ascii=False)[:800],
                        host=site, cwe_id="CWE-1395",
                        cve_id=cves[0] if cves else None,
                        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value, confidence="HIGH",
                    ))
            elif data.get("outdated"):
                observations.append(ToolObservation(
                    tool_key="wpscan", slug=f"{component}-{_slugify(slug)}-outdated",
                    title=f"{_COMPONENT_LABELS.get(component, component)} desactualizado: {slug} {version_str}".strip(),
                    severity=Severity.MEDIUM,
                    description=(
                        f"El componente '{slug}' ({version_str}) no está en su última versión "
                        f"({data.get('latest_version') or 'n/d'}). Actualizarlo para reducir superficie de ataque."
                    ),
                    evidence=json.dumps(data, ensure_ascii=False)[:600],
                    host=site, cwe_id="CWE-1104",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                    confidence="MEDIUM",
                ))

    for finding in payload.get("interesting_findings", []) or []:
        if not isinstance(finding, dict):
            continue
        confidence_score = finding.get("confidence") or 0
        try:
            confidence_score = int(confidence_score)
        except (TypeError, ValueError):
            confidence_score = 0
        severity = Severity.MEDIUM if confidence_score >= 90 else (Severity.LOW if confidence_score >= 50 else Severity.INFO)
        observations.append(ToolObservation(
            tool_key="wpscan", slug=f"interesting-{_slugify(str(finding.get('type') or finding.get('to_s'))[:40])}",
            title=f"Hallazgo de interés: {str(finding.get('to_s') or finding.get('type'))[:110]}",
            severity=severity,
            description=f"WPScan marcó este hallazgo con confianza {confidence_score}/100.",
            evidence=json.dumps(finding, ensure_ascii=False)[:700],
            host=site, cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="MEDIUM",
        ))

    users = payload.get("users") if isinstance(payload.get("users"), dict) else {}
    if users:
        observations.append(ToolObservation(
            tool_key="wpscan", slug="user-enumeration",
            title=f"Enumeración de usuarios de WordPress ({len(users)} identificados)",
            severity=Severity.MEDIUM,
            description=(
                "WPScan identificó nombres de usuario válidos, lo que habilita ataques de fuerza bruta dirigidos "
                "y facilita el phishing (OWASP A07:2021)."
            ),
            evidence="Usuarios: " + ", ".join(list(users.keys())[:20]),
            host=site, cwe_id="CWE-200",
            stride_category=StrideCategory.SPOOFING.value, confidence="HIGH",
        ))
    return observations


_COMPONENT_LABELS = {"plugins": "Plugin", "themes": "Tema"}


def _severity_from_cvss(cvss: Any) -> Severity:
    if isinstance(cvss, dict):
        score = cvss.get("score")
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW
    return Severity.HIGH


# ── Redes / SMB / AD ─────────────────────────────────────────────────────────

def parse_dnsrecon_json(content: str, target: str = "") -> List[ToolObservation]:
    payload = _load_json(content)
    observations: List[ToolObservation] = []
    records: List[Dict[str, Any]] = []
    if isinstance(payload, dict):
        records = [r for r in payload.get("records", []) or [] if isinstance(r, dict)]
    elif isinstance(payload, list):
        records = [r for r in payload if isinstance(r, dict)]
    if not records:
        return observations

    by_type: Dict[str, List[str]] = {}
    for record in records:
        rtype = str(record.get("type") or "UNKNOWN").upper()
        if rtype in ("ZONE TRANSFER", "AXFR"):
            axfr_names = _as_list(record.get("name") or record.get("records"))
            observations.append(ToolObservation(
                tool_key="dnsrecon", slug="zone-transfer",
                title="Transferencia de zona DNS (AXFR) permitida",
                severity=Severity.HIGH,
                description=(
                    "El servidor DNS permite transferencias de zona a clientes no autorizados, exponiendo el "
                    "inventario completo de registros internos (CWE-200, PCI-DSS 1.3)."
                ),
                evidence=json.dumps(record, ensure_ascii=False)[:700] or ", ".join(axfr_names[:20]),
                host=target, cwe_id="CWE-200",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
            ))
            continue
        value = record.get("address") or record.get("target") or record.get("exchange") or record.get("strings") or record.get("name")
        by_type.setdefault(rtype, []).append(str(value)[:80])

    for rtype, values in by_type.items():
        observations.append(ToolObservation(
            tool_key="dnsrecon", slug=f"records-{_slugify(rtype)}",
            title=f"Registros DNS {rtype} publicados ({len(values)})",
            severity=Severity.INFO,
            description=f"Inventario de registros DNS de tipo {rtype} publicados por el dominio objetivo.",
            evidence=", ".join(values[:20]),
            host=target, cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
        ))
    return observations


def parse_amass_text(content: str, target: str = "") -> List[ToolObservation]:
    hosts = sorted({line.strip() for line in (content or "").splitlines() if line.strip() and "." in line.strip()})
    if not hosts:
        return []
    return [ToolObservation(
        tool_key="amass", slug="external-assets",
        title=f"Superficie de exposición externa: {len(hosts)} activos descubiertos",
        severity=Severity.INFO,
        description=(
            "OWASP Amass descubrió activos externos (subdominios) asociados al dominio objetivo. Revisar cuáles "
            "están obsoletos o no inventariados (riesgo de subdomain takeover)."
        ),
        evidence=", ".join(hosts[:25]),
        host=target, cwe_id="CWE-200",
        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="MEDIUM",
    )]


def parse_nbtscan_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    row_re = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<name>\S+)\s+(?P<rest>.*)$")
    for line in (content or "").splitlines():
        match = row_re.match(line.strip())
        if not match:
            continue
        ip, name, rest = match.group("ip"), match.group("name"), match.group("rest").strip()
        observations.append(ToolObservation(
            tool_key="nbtscan", slug=f"host-{_slugify(ip)}",
            title=f"Host NetBIOS inventariado: {ip} ({name})",
            severity=Severity.INFO,
            description="NBTscan identificó un host Windows con su nombre NetBIOS, exponiendo información de inventario interno.",
            evidence=line.strip(),
            host=ip, cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="MEDIUM",
            raw={"netbios_name": name, "details": rest},
        ))
    return observations


def parse_enum4linux_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    text = content or ""
    lowered = text.lower()

    if re.search(r"(allows sessions using username ''|null session|session setup failed)", lowered):
        if re.search(r"allows sessions using username ''", lowered):
            observations.append(ToolObservation(
                tool_key="enum4linux", slug="null-session",
                title="SMB permite null session (sesión anónima)",
                severity=Severity.HIGH,
                description=(
                    "El servidor permite establecer sesiones SMB anónimas, habilitando la enumeración de usuarios, "
                    "grupos y recursos compartidos sin credenciales (CWE-287, CIS Windows 2.3.x)."
                ),
                evidence=_grep_lines(text, r"session", limit=5),
                host=target, cwe_id="CWE-287",
                stride_category=StrideCategory.SPOOFING.value, confidence="HIGH",
            ))

    share_lines = re.findall(r"^\s*//\S+/\S+.*$", text, re.MULTILINE)
    if share_lines:
        observations.append(ToolObservation(
            tool_key="enum4linux", slug="shares",
            title=f"Recursos compartidos SMB enumerados ({len(share_lines)})",
            severity=Severity.MEDIUM,
            description="Se enumeraron recursos compartidos SMB. Verificar permisos efectivos y datos sensibles expuestos.",
            evidence="\n".join(share_lines[:12]),
            host=target, cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
        ))

    user_lines = re.findall(r"^(?:user|username)\s*[:=]\s*(\S+)|^\s*Index:\s*\d+\s+RID:\s*\S+\s+Account:\s*(\S+)\s+Name:\s*(.*)$", text, re.MULTILINE)
    users = {(u[0] or u[1] or "").strip() for u in user_lines if (u[0] or u[1])}
    users.discard("")
    if users:
        observations.append(ToolObservation(
            tool_key="enum4linux", slug="users",
            title=f"Enumeración de cuentas SMB/AD ({len(users)} identificadas)",
            severity=Severity.MEDIUM,
            description=(
                "Se obtuvieron nombres de cuenta válidos del dominio, facilitando ataques de fuerza bruta dirigidos "
                "y de credenciales por defecto."
            ),
            evidence=", ".join(sorted(users)[:25]),
            host=target, cwe_id="CWE-200",
            stride_category=StrideCategory.SPOOFING.value, confidence="HIGH",
        ))

    policy = re.search(r"Minimum password length:\s*(\d+)[\s\S]{0,200}?Password history length:\s*(\d+)", text, re.IGNORECASE)
    if policy:
        min_len, history = int(policy.group(1)), int(policy.group(2))
        if min_len < 12 or history < 10:
            observations.append(ToolObservation(
                tool_key="enum4linux", slug="password-policy",
                title=f"Política de contraseñas débil (longitud mínima {min_len}, historial {history})",
                severity=Severity.MEDIUM,
                description=(
                    f"La política de contraseñas del dominio permite contraseñas de {min_len} caracteres con "
                    f"historial de {history}. NIST SP 800-63B y CIS recomiendan 12+ caracteres y bloqueo por intentos."
                ),
                evidence=_grep_lines(text, r"Minimum password length|Password history length|Lockout", limit=6),
                host=target, cwe_id="CWE-521",
                stride_category=StrideCategory.SPOOFING.value, confidence="MEDIUM",
            ))
    return observations


def parse_smbclient_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    shares: List[str] = []
    for line in (content or "").splitlines():
        line = line.strip()
        if line.startswith("Disk|"):
            parts = line.split("|")
            if len(parts) >= 2:
                shares.append(f"{parts[1]} ({parts[2] if len(parts) > 2 else 'sin descripción'})")
        elif line.startswith("Anonymous access:"):
            access = line.split(":", 1)[1].strip()
            if access.upper() != "NONE":
                observations.append(ToolObservation(
                    tool_key="smbclient", slug="anonymous-access",
                    title=f"Acceso anónimo SMB permitido ({access})",
                    severity=Severity.HIGH if access.upper() != "READ" else Severity.HIGH,
                    description=(
                        "El servidor SMB acepta conexiones anónimas con nivel de acceso otorgado. Esto permite "
                        "enumerar y potencialmente leer recursos sin credenciales (CWE-287)."
                    ),
                    evidence=line, host=target, cwe_id="CWE-287",
                    stride_category=StrideCategory.SPOOFING.value, confidence="HIGH",
                ))
    if shares:
        observations.append(ToolObservation(
            tool_key="smbclient", slug="share-list",
            title=f"Recursos SMB publicados ({len(shares)})",
            severity=Severity.MEDIUM,
            description="Se listaron recursos compartidos SMB accesibles sin autenticación previa.",
            evidence=", ".join(shares[:15]),
            host=target, cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
        ))
    return observations


def parse_nxc_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    text = content or ""

    for line in text.splitlines():
        if "(Pwn3d!)" in line:
            observations.append(ToolObservation(
                tool_key="nxc", slug=f"pwn3d-{_slugify(line[-60:])}",
                title="Acceso administrativo confirmado con las credenciales probadas",
                severity=Severity.CRITICAL,
                description=(
                    "NetExec confirmó privilegios administrativos en el objetivo con las credenciales auditadas. "
                    "Compromiso total del host vía SMB."
                ),
                evidence=line.strip(), host=target, cwe_id="CWE-269",
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value, confidence="HIGH",
            ))
        elif re.search(r"\[\+\]\s+\S+\\\S+:\S+", line):
            observations.append(ToolObservation(
                tool_key="nxc", slug=f"valid-creds-{_slugify(line[-60:])}",
                title="Credenciales válidas confirmadas por NetExec",
                severity=Severity.CRITICAL,
                description=(
                    "Las credenciales suministradas fueron aceptadas por el servicio SMB del objetivo. "
                    "Rotar de inmediato y revisar la trazabilidad del acceso."
                ),
                evidence=line.strip(), host=target, cwe_id="CWE-521",
                stride_category=StrideCategory.SPOOFING.value, confidence="HIGH",
            ))
        elif re.search(r"signing:\s*(False|disabled)", line, re.IGNORECASE) or "SMB signing: False" in line:
            observations.append(ToolObservation(
                tool_key="nxc", slug="smb-signing-disabled",
                title="SMB signing deshabilitado",
                severity=Severity.MEDIUM,
                description=(
                    "El host no exige firma SMB, lo que habilita ataques de relay NTLM (CWE-345, CIS Windows 2.3.11.1)."
                ),
                evidence=line.strip(), host=target, cwe_id="CWE-345",
                stride_category=StrideCategory.TAMPERING.value, confidence="HIGH",
            ))
        elif re.search(r"(Guest|guest) account", line) and "[+]" in line:
            observations.append(ToolObservation(
                tool_key="nxc", slug="guest-enabled",
                title="Cuenta Invitado (Guest) habilitada en SMB",
                severity=Severity.HIGH,
                description="La cuenta Guest está activa y aceptada en el servicio SMB, permitiendo acceso no autenticado.",
                evidence=line.strip(), host=target, cwe_id="CWE-287",
                stride_category=StrideCategory.SPOOFING.value, confidence="HIGH",
            ))

    fingerprint = re.search(r"\[\*\]\s+(Windows[^\n]*|.*build[^\n]*)", text)
    if fingerprint:
        observations.append(ToolObservation(
            tool_key="nxc", slug="host-fingerprint",
            title=f"Huella del host: {fingerprint.group(1).strip()[:100]}",
            severity=Severity.INFO,
            description="NetExec identificó el sistema operativo y build del objetivo a través de SMB.",
            evidence=fingerprint.group(1).strip(), host=target, cwe_id="CWE-200",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
        ))
    return observations


def parse_snmpwalk_text(content: str, target: str = "", tool_key: str = "snmpwalk") -> List[ToolObservation]:
    text = content or ""
    if "Timeout" in text and "no response" in text.lower():
        return []
    # Acepta OIDs simbólicos (sysDescr.0) y numéricos (iso.3.6.1.2.1.1.1.0), como emite 'snmpwalk -On'.
    sysdescr = re.search(
        r"(?:sysDescr(?:\.0)?|\.?(?:1|iso)\.3\.6\.1\.2\.1\.1\.1\.0)\s*=\s*(?:STRING:\s*)?\"?([^\"\n]{1,160})",
        text, re.IGNORECASE,
    )
    sysname = re.search(
        r"(?:sysName(?:\.0)?|\.?(?:1|iso)\.3\.6\.1\.2\.1\.1\.5\.0)\s*=\s*(?:STRING:\s*)?\"?([^\"\n]{1,80})",
        text, re.IGNORECASE,
    )
    oids = len(re.findall(r"^\S*\.?\d+(?:\.\d+)+ = ", text, re.MULTILINE)) or len(re.findall(r"= (?:STRING|INTEGER|OID|Hex-STRING|Timeticks)", text))
    if not (sysdescr or sysname or oids):
        return []
    evidence_lines = []
    if sysdescr:
        evidence_lines.append(f"sysDescr: {sysdescr.group(1).strip()}")
    if sysname:
        evidence_lines.append(f"sysName: {sysname.group(1).strip()}")
    evidence_lines.append(f"OIDs recuperados: {oids}")
    return [ToolObservation(
        tool_key=tool_key, slug="snmp-exposed",
        title="SNMP accesible y con información del sistema expuesta",
        severity=Severity.HIGH,
        description=(
            "El agente SNMP respondió y devolvió información operativa del sistema (descripción, nombre, "
            "interfaces). Si se logró con una comunidad por defecto, el servicio está efectivamente sin "
            "autenticación (CWE-1188, CIS Linux/Switch SNMP hardening)."
        ),
        evidence="\n".join(evidence_lines),
        host=target, cwe_id="CWE-1188",
        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
    )]


def parse_onesixtyone_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    for line in (content or "").splitlines():
        match = re.match(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\[(?P<community>[^\]]+)\]\s*(?P<descr>.*)$", line.strip())
        if not match:
            continue
        community = match.group("community")
        observations.append(ToolObservation(
            tool_key="onesixtyone", slug=f"snmp-{_slugify(match.group('ip'))}",
            title=f"SNMP responde a la comunidad '{community}' ({match.group('ip')})",
            severity=Severity.HIGH if community.lower() in ("public", "private", "community") else Severity.MEDIUM,
            description=(
                f"El agente SNMP aceptó la cadena de comunidad '{community}' y devolvió la descripción del sistema. "
                "El uso de comunidades por defecto permite lectura (y en algunos casos escritura) no autenticada de "
                "la configuración del dispositivo (CWE-1188)."
            ),
            evidence=line.strip(),
            host=match.group("ip"), cwe_id="CWE-1188",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
        ))
    return observations


def parse_smtp_user_enum_text(content: str, target: str = "") -> List[ToolObservation]:
    users = []
    for line in (content or "").splitlines():
        match = re.match(r"^\s*(?:\[\+\])?\s*(?P<host>\S+):\s*(?P<user>[^\s]+)\s+(?:exists|found)", line.strip(), re.IGNORECASE)
        if match:
            users.append(match.group("user"))
    if not users:
        return []
    return [ToolObservation(
        tool_key="smtp_user_enum", slug="mailbox-enumeration",
        title=f"Enumeración de buzones SMTP ({len(users)} válidos)",
        severity=Severity.MEDIUM,
        description=(
            "El servidor SMTP confirmó la existencia de buzones mediante VRFY/RCPT TO, permitiendo enumerar "
            "cuentas válidas para campañas de phishing o fuerza bruta (CWE-200)."
        ),
        evidence=", ".join(sorted(set(users))[:25]),
        host=target, cwe_id="CWE-200",
        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
    )]


def parse_sslscan_xml(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return observations

    for test in root.iter("ssltest"):
        host = test.get("host") or target
        port = int(test.get("port") or 0) or None
        display = f"{host}:{port}" if port else host

        tls_established = False
        deprecated: List[str] = []
        for protocol in test.findall("protocol"):
            kind = (protocol.get("type") or "").strip().lower()
            raw_version = (protocol.get("version") or "").strip().lower()
            # sslscan emits type="tls" version="1.2" → forma canónica 'tls1.2' / 'ssl3'
            canonical = f"{kind}{raw_version}".replace("v", "").replace(" ", "")
            label = f"{kind.upper()} {raw_version}".replace("TLS 1.0", "TLS 1.0").strip()
            if protocol.get("enabled") == "1":
                tls_established = True
                if canonical in DEPRECATED_TLS_CANONICAL:
                    deprecated.append(label)
        if deprecated:
            observations.append(ToolObservation(
                tool_key="sslscan", slug=f"deprecated-protocols-{port or 443}",
                title=f"Protocolos TLS obsoletos habilitados en {display}: {', '.join(deprecated)}",
                severity=Severity.HIGH,
                description=(
                    "El servicio acepta versiones de protocolo deprecadas (SSLv2/SSLv3/TLS 1.0/1.1), vulnerables a "
                    "POODLE, DROWN y BEAST. PCI-DSS 4.0 exige TLS 1.2 o superior."
                ),
                evidence=f"Protocolos habilitados obsoletos: {', '.join(deprecated)}",
                host=host, port=port, cwe_id="CWE-327",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Req 4.2.1", "ISO_27001": "A.8.24"},
                confidence="HIGH",
            ))

        weak: List[str] = []
        accepted: List[str] = []
        for cipher in test.findall("cipher"):
            if cipher.get("status") != "accepted":
                continue
            name = cipher.get("cipher") or ""
            accepted.append(f"{name} ({cipher.get('sslversion', '')})")
            for keyword, severity, reason in WEAK_TLS_KEYWORDS:
                if keyword in name.upper():
                    weak.append(f"{name}: {reason}")
                    break
        if weak:
            observations.append(ToolObservation(
                tool_key="sslscan", slug=f"weak-ciphers-{port or 443}",
                title=f"Suites de cifrado débiles aceptadas en {display}",
                severity=Severity.HIGH,
                description="El servicio negocia cifrados criptográficamente obsoletos o sin autenticación.",
                evidence="\n".join(sorted(set(weak))[:10]),
                host=host, port=port, cwe_id="CWE-327",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
            ))

        for cert in test.findall("certificate"):
            not_after = cert.findtext("not-valid-after") or ""
            signature = cert.findtext("signature-algorithm") or ""
            key_node = cert.find("pk")
            bits = key_node.get("bits") if key_node is not None else ""
            key_type = key_node.get("type") if key_node is not None else ""
            issues = []
            if "sha1" in signature.lower() or "md5" in signature.lower():
                issues.append(f"Firma débil: {signature}")
            try:
                bit_count = int(bits or 0)
            except ValueError:
                bit_count = 0
            if key_type.upper() in ("RSA", "RSA-2048") and 0 < bit_count < 2048:
                issues.append(f"Clave RSA de {bit_count} bits (<2048)")
            if issues:
                observations.append(ToolObservation(
                    tool_key="sslscan", slug=f"weak-cert-{port or 443}",
                    title=f"Certificado TLS con parámetros débiles ({display})",
                    severity=Severity.HIGH,
                    description="El certificado del servicio usa algoritmos o longitudes de clave consideradas débiles.",
                    evidence="\n".join(issues) + f"\nVálido hasta: {not_after}",
                    host=host, port=port, cwe_id="CWE-326",
                    stride_category=StrideCategory.SPOOFING.value, confidence="HIGH",
                ))
            if not_after:
                observations.append(ToolObservation(
                    tool_key="sslscan", slug=f"cert-info-{port or 443}",
                    title=f"Certificado TLS de {display} (válido hasta {not_after})",
                    severity=Severity.INFO,
                    description="Metadatos del certificado presentado por el servicio TLS.",
                    evidence=f"Algoritmo de firma: {signature or 'n/d'}\nClave: {key_type} {bits}\nVálido hasta: {not_after}",
                    host=host, port=port, cwe_id="CWE-200",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="HIGH",
                ))

        if not tls_established and not accepted:
            observations.append(ToolObservation(
                tool_key="sslscan", slug=f"no-tls-{port or 0}",
                title=f"No se pudo establecer una sesión TLS en {display}",
                severity=Severity.LOW,
                description=(
                    "El puerto no completó un handshake TLS durante la auditoría: puede tratarse de un servicio sin "
                    "cifrado en tránsito (HTTP/otros) o de un servicio que no está escuchando. Verificar el protocolo real "
                    "y forzar TLS donde corresponda (CWE-319)."
                ),
                evidence=_grep_lines(content, r"error|failed|could not", limit=3) or f"ssltest {display}: sin protocolos habilitados.",
                host=host, port=port, cwe_id="CWE-319",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="MEDIUM",
            ))
        elif not deprecated and not weak and accepted:
            observations.append(ToolObservation(
                tool_key="sslscan", slug=f"tls-ok-{port or 443}",
                title=f"Configuración TLS aceptable en {display}",
                severity=Severity.INFO,
                description="No se detectaron protocolos obsoletos ni cifrados débiles aceptados por el servicio.",
                evidence=f"Suites aceptadas (muestra): {', '.join(sorted(set(accepted))[:8])}",
                host=host, port=port, cwe_id="CWE-327",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="MEDIUM",
            ))
    return observations


# ── Explotación / credenciales ───────────────────────────────────────────────

def parse_sqlmap_text(content: str, target: str = "") -> List[ToolObservation]:
    text = content or ""
    observations: List[ToolObservation] = []

    if re.search(r"does not seem to be injectable|all tested parameters do not appear to be injectable", text, re.IGNORECASE):
        observations.append(ToolObservation(
            tool_key="sqlmap", slug="no-injection",
            title="Verificación de inyección SQL sin hallazgos",
            severity=Severity.INFO,
            description="sqlmap no logró confirmar inyección SQL en los parámetros evaluados: control compensatorio verificado.",
            evidence=_grep_lines(text, r"not appear to be injectable|does not seem to be injectable", limit=3),
            host=target, cwe_id="CWE-89", confidence="HIGH",
        ))

    if re.search(r"is vulnerable\.|identified the following injection point", text, re.IGNORECASE):
        parameters = re.findall(r"Parameter:\s*(?P<param>[^\s(]+)\s*\((?P<where>[^)]+)\)", text)
        techniques = sorted(set(re.findall(r"Type:\s*([^\n]+)", text)))
        dbms = re.findall(r"back-end DBMS:\s*([^\n]+)", text)
        cves = _all_cves(text)
        param_desc = ", ".join(f"{p[0]} ({p[1]})" for p in parameters[:6]) or "parámetro no especificado"
        observations.append(ToolObservation(
            tool_key="sqlmap", slug=f"sqli-{_slugify(param_desc)}",
            title=f"Inyección SQL confirmada empíricamente en {param_desc}",
            severity=Severity.CRITICAL,
            description=(
                "sqlmap confirmó la inyección SQL explotando el parámetro indicado. Impacto: lectura/escritura de la "
                "base de datos, potencial extracción de credenciales y en algunos motores ejecución de comandos."
            ),
            evidence=(
                f"Parámetros: {param_desc}\n"
                f"Técnicas: {', '.join(t.strip() for t in techniques[:6]) or 'n/d'}\n"
                f"DBMS: {', '.join(d.strip() for d in dbms[:3]) or 'n/d'}"
            ),
            host=target, cwe_id="CWE-89",
            cve_id=cves[0] if cves else None,
            references=["https://owasp.org/Top10/A03_2021-Injection/"],
            stride_category=StrideCategory.TAMPERING.value,
            compliance_controls={"OWASP": "OWASP Top 10 A03:2021 Injection", "PCI_DSS": "PCI-DSS 4.0 Req 6.2.4",
                                 "ISO_27001": "A.8.28", "OWASP_API": "API8:2023"},
            confidence="HIGH",
            raw={"parameters": parameters[:10], "techniques": techniques[:10]},
        ))
    return observations


def parse_commix_text(content: str, target: str = "") -> List[ToolObservation]:
    text = content or ""
    if not re.search(r"is vulnerable|injectable|injection point", text, re.IGNORECASE):
        return []
    parameter = re.search(r"parameter\s+'([^']+)'", text, re.IGNORECASE)
    observation = ToolObservation(
        tool_key="commix", slug=f"cmdi-{_slugify(parameter.group(1) if parameter else 'param')}",
        title=f"Inyección de comandos confirmada{f' en el parámetro {parameter.group(1)}' if parameter else ''}",
        severity=Severity.CRITICAL,
        description=(
            "commix confirmó la inyección de comandos del sistema operativo a través del parámetro indicado, "
            "habilitando ejecución remota de código en el servidor."
        ),
        evidence=_grep_lines(text, r"vulnerable|injectable|Type:", limit=8),
        host=target, cwe_id="CWE-78",
        references=["https://owasp.org/Top10/A03_2021-Injection/"],
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
        compliance_controls={"OWASP": "OWASP Top 10 A03:2021 Injection", "PCI_DSS": "PCI-DSS 4.0 Req 6.2.4",
                             "ISO_27001": "A.8.28"},
        confidence="HIGH",
    )
    return [observation]


def parse_hydra_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    pattern = re.compile(
        r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<login>\S+)\s+password:\s*(?P<password>.*)"
    )
    for line in (content or "").splitlines():
        match = pattern.search(line)
        if not match:
            continue
        observations.append(ToolObservation(
            tool_key="hydra", slug=f"weak-creds-{_slugify(match.group('login'))}-{match.group('port')}",
            title=f"Credenciales débiles válidas en {match.group('service')} ({match.group('host')}:{match.group('port')})",
            severity=Severity.CRITICAL,
            description=(
                f"La auditoría de fuerza bruta autorizada obtuvo credenciales válidas para el servicio "
                f"{match.group('service')} con el usuario '{match.group('login')}'. Rotar de inmediato la credencial, "
                "habilitar MFA y bloqueo por intentos fallidos."
            ),
            evidence=line.strip(),
            host=match.group("host"),
            port=int(match.group("port")),
            service=match.group("service"),
            cwe_id="CWE-521",
            stride_category=StrideCategory.SPOOFING.value,
            compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Req 8.3", "ISO_27001": "A.5.17", "NIST": "NIST SP 800-63B"},
            confidence="HIGH",
            raw={"login": match.group("login"), "password": match.group("password")},
        ))
    return observations


def parse_john_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    cracked = re.findall(r"^(?P<pwd>[^\s(]+)\s+\((?P<user>[^)]+)\)", content or "", re.MULTILINE)
    for password, user in cracked[:25]:
        observations.append(ToolObservation(
            tool_key="john", slug=f"cracked-{_slugify(user)}",
            title=f"Contraseña débil recuperada para '{user}'",
            severity=Severity.CRITICAL,
            description=(
                "John the Ripper recuperó la contraseña de este usuario a partir de su hash: la política de "
                "contraseñas no resiste un ataque de diccionario offline (CWE-521)."
            ),
            evidence=f"usuario: {user} — contraseña recuperada: {password}",
            host=target, cwe_id="CWE-521",
            stride_category=StrideCategory.SPOOFING.value,
            compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Req 8.3.6", "ISO_27001": "A.5.17"},
            confidence="HIGH",
        ))
    if re.search(r"No password hashes loaded|could not be loaded", content or "", re.IGNORECASE):
        observations.append(ToolObservation(
            tool_key="john", slug="no-hashes",
            title="Sin hashes cargados para auditoría offline",
            severity=Severity.INFO,
            description="John no cargó hashes: verifica el formato del archivo aportado al engagement.",
            evidence=_grep_lines(content or "", r"No password hashes loaded|could not be loaded", limit=3),
            host=target, confidence="HIGH",
        ))
    return observations


def parse_hashcat_text(content: str, target: str = "", artifact_path: Optional[str] = None) -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    pairs: List[Tuple[str, str]] = []
    source = content or ""
    if artifact_path and os.path.isfile(artifact_path):
        try:
            with open(artifact_path, "r", encoding="utf-8", errors="replace") as handle:
                source += "\n" + handle.read(200_000)
        except OSError:
            pass
    for line in source.splitlines():
        if line.count(":") >= 1 and not line.startswith(("Session", "Status", "Hash.Target", "Time")):
            hash_part, _, plain = line.rpartition(":")
            if hash_part and plain and len(hash_part) >= 16:
                pairs.append((hash_part, plain))
    for hash_part, plain in pairs[:25]:
        observations.append(ToolObservation(
            tool_key="hashcat", slug=f"cracked-{hash_part[:12]}",
            title="Hash recuperado por Hashcat (contraseña débil)",
            severity=Severity.CRITICAL,
            description=(
                "Hashcat recuperó el texto en claro de un hash de contraseña, evidenciando que la política de "
                "credenciales no resiste ataques offline con GPU (CWE-521, CWE-916)."
            ),
            evidence=f"hash: {hash_part[:24]}… — contraseña recuperada: {plain}",
            host=target, cwe_id="CWE-521",
            stride_category=StrideCategory.SPOOFING.value,
            compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Req 8.3.6", "ISO_27001": "A.5.17"},
            confidence="HIGH",
        ))
    return observations


def parse_secretsdump_text(content: str, target: str = "") -> List[ToolObservation]:
    observations: List[ToolObservation] = []
    text = content or ""
    hash_lines = [line for line in text.splitlines() if line.count(":::") >= 1]
    if hash_lines:
        users = []
        for line in hash_lines:
            match = re.match(r"^(?P<domain>[^\\]+)\\(?P<user>[^:]+):", line)
            if match:
                users.append(f"{match.group('domain')}\\{match.group('user')}")
        observations.append(ToolObservation(
            tool_key="impacket_secretsdump", slug="ntds-dump",
            title=f"Hashes de credenciales de dominio extraídos ({len(hash_lines)} registros)",
            severity=Severity.CRITICAL,
            description=(
                "Se extrajeron hashes NTLM de la base de datos de Active Directory (NTDS.dit/DCSync). Con estos "
                "hashes es posible autenticarse en cualquier servicio del dominio (Pass-the-Hash) si el dominio no "
                "aplica protecciones de credenciales."
            ),
            evidence="\n".join(hash_lines[:10]),
            host=target, cwe_id="CWE-522",
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
            compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Req 8.2", "ISO_27001": "A.5.17", "MITRE": "T1003.003"},
            confidence="HIGH",
            raw={"accounts": users[:40], "count": len(hash_lines)},
        ))
    elif re.search(r"account\s+.*\s+does not exist|STATUS_LOGON_FAILURE", text, re.IGNORECASE):
        observations.append(ToolObservation(
            tool_key="impacket_secretsdump", slug="logon-failed",
            title="Intento de volcado de credenciales fallido",
            severity=Severity.INFO,
            description="Las credenciales probadas no permitieron el volcado de secretos (control compensatorio verificado).",
            evidence=_grep_lines(text, r"STATUS_LOGON_FAILURE|does not exist", limit=3),
            host=target, confidence="HIGH",
        ))
    return observations


def parse_searchsploit_json(content: str, target: str = "", term: str = "") -> List[ToolObservation]:
    payload = _load_json(content)
    if not isinstance(payload, dict):
        return []
    results = [r for r in payload.get("RESULTS_EXPLOIT", []) or [] if isinstance(r, dict)]
    search_term = payload.get("SEARCH") or term or target
    if not results:
        return []
    lines = []
    cves: List[str] = []
    for item in results[:10]:
        codes = str(item.get("Codes") or "")
        item_cves = _all_cves(codes)
        cves.extend(item_cves)
        lines.append(
            f"EDB-{item.get('EDB-ID')} · {str(item.get('Title'))[:90]} "
            f"[{item.get('Type')}/{item.get('Platform')}] {codes}"
        )
    return [ToolObservation(
        tool_key="searchsploit", slug=f"exploitdb-{_slugify(str(search_term))}",
        title=f"Exploits públicos correlacionados con '{search_term}' ({len(results)} en Exploit-DB)",
        severity=Severity.MEDIUM,
        description=(
            "La correlación local con Exploit-DB devolvió exploits públicos aplicables a la tecnología detectada. "
            "Requiere validación manual para confirmar la exposición real de la versión en el objetivo."
        ),
        evidence="\n".join(lines),
        host=target, cwe_id="CWE-1104", cve_id=cves[0] if cves else None,
        references=[f"https://www.exploit-db.com/exploits/{item.get('EDB-ID')}" for item in results[:5]],
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
        confidence="MEDIUM",
        raw={"results": len(results), "cves": sorted(set(cves))[:15]},
    )]


def parse_capture_artifact(content: str, target: str = "") -> List[ToolObservation]:
    """Registers a packet capture as forensic evidence without interpreting it here."""
    path = (content or "").strip().splitlines()[0] if (content or "").strip() else ""
    if path and os.path.isfile(path):
        size = os.path.getsize(path)
        evidence = f"Captura PCAP: {path} ({size} bytes). Analizar con tshark/Wireshark para validar cifrado en tránsito."
    else:
        size = 0
        evidence = "No se generó el archivo de captura esperado."
    return [ToolObservation(
        tool_key="tcpdump", slug="packet-capture",
        title="Captura de tráfico registrada como evidencia forense",
        severity=Severity.INFO,
        description=(
            "Se registró una captura acotada del tráfico del segmento auditado. La evidencia permite validar si "
            "existen protocolos en texto claro y sustentar hallazgos de cifrado en tránsito."
        ),
        evidence=evidence,
        host=target, cwe_id="CWE-319",
        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
        confidence="HIGH",
        raw={"pcap": path, "bytes": size},
    )]


def parse_aircrack_text(content: str, target: str = "") -> List[ToolObservation]:
    """Parses aircrack-ng output for recovered WPA/WEP keys."""
    text = content or ""
    observations: List[ToolObservation] = []
    key_match = re.search(r"KEY FOUND!\s*\[\s*(?P<key>[^\]]+?)\s*\]", text)
    if key_match:
        observations.append(ToolObservation(
            tool_key="aircrack_ng", slug="key-recovered",
            title="Clave Wi-Fi recuperada a partir de la captura (política de contraseñas débil)",
            severity=Severity.CRITICAL,
            description=(
                "La auditoría offline recuperó la clave de la red inalámbrica con un ataque de diccionario. "
                "Una clave predecible compromete la confidencialidad de todo el tráfico WPA/WPA2 del segmento."
            ),
            evidence=f"KEY FOUND! [{key_match.group('key').strip()}]",
            host=target, cwe_id="CWE-521",
            stride_category=StrideCategory.SPOOFING.value,
            compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Req 11.2 (pruebas de segmentación inalámbrica)",
                                 "ISO_27001": "A.8.20", "NIST": "NIST SP 800-63B"},
            confidence="HIGH",
        ))
    elif re.search(r"Passphrase not in dictionary|Key not found", text, re.IGNORECASE):
        observations.append(ToolObservation(
            tool_key="aircrack_ng", slug="key-not-recovered",
            title="Clave Wi-Fi no recuperada con el diccionario utilizado",
            severity=Severity.INFO,
            description=(
                "El ataque de diccionario no recuperó la clave en el tiempo asignado: la contraseña no figura en "
                "el diccionario probado. Repetir con diccionarios más amplios para concluir sobre su robustez."
            ),
            evidence=_grep_lines(text, r"Passphrase not in dictionary|Key not found", limit=3) or text[-300:],
            host=target, cwe_id="CWE-521", confidence="MEDIUM",
        ))
    return observations


def parse_airodump_capture(content: str, target: str = "", artifact_path: Optional[str] = None) -> List[ToolObservation]:
    """Registers a 802.11 capture as evidence (aircrack-ng consumes it in the next step)."""
    path = (artifact_path or content or "").strip().splitlines()[0] if (artifact_path or content or "").strip() else ""
    if path and os.path.isfile(path):
        size = os.path.getsize(path)
        if size > 24:
            evidence = f"Captura 802.11: {path} ({size} bytes). Analizar handshakes con aircrack-ng/tshark."
            severity = Severity.INFO
        else:
            evidence = (
                f"El fichero de captura {path} está vacío ({size} bytes): la interfaz no estaba en modo monitor "
                "o no hubo tráfico 802.11 en el canal durante la ventana de captura."
            )
            severity = Severity.LOW
    else:
        evidence = "No se generó el fichero de captura 802.11 esperado (verifica modo monitor e interfaz)."
        severity = Severity.LOW
    return [ToolObservation(
        tool_key="airodump_ng", slug="wireless-capture",
        title="Captura 802.11 registrada para auditoría inalámbrica",
        severity=severity,
        description=(
            "Se ejecutó una captura acotada de tramas 802.11 como evidencia. Sobre esta captura se puede verificar "
            "la configuración de cifrado de los puntos de acceso y la robustez de las claves."
        ),
        evidence=evidence,
        host=target, cwe_id="CWE-319",
        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value, confidence="MEDIUM",
    )]


def parse_plain_output(content: str, target: str = "", tool_key: str = "kali") -> List[ToolObservation]:
    text = (content or "").strip()
    if not text:
        return []
    cves = _all_cves(text)
    lowered = text.lower()
    severity = Severity.MEDIUM if ("vulnerab" in lowered or "pwn3d" in lowered) else Severity.INFO
    return [ToolObservation(
        tool_key=tool_key, slug="raw-output",
        title=f"Salida de {tool_key} registrada como evidencia",
        severity=severity,
        description=(
            "La herramienta no dispone de parser estructurado en CyberAudit: se conserva su salida íntegra como "
            "evidencia para revisión manual del auditor."
        ),
        evidence=text,
        host=target, cve_id=cves[0] if cves else None,
        references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:5]],
        confidence="LOW",
    )]


# ── Dispatch table ───────────────────────────────────────────────────────────

def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "")).strip("-").lower()
    return cleaned[:60] or "item"


def _stride_for_severity(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return StrideCategory.ELEVATION_OF_PRIVILEGE.value
    if severity == Severity.MEDIUM:
        return StrideCategory.TAMPERING.value
    return StrideCategory.INFORMATION_DISCLOSURE.value


def _compliance_for_cves(cves: List[str]) -> Dict[str, str]:
    if cves:
        return {
            "PCI_DSS": "PCI-DSS 4.0 Req 6.3.3 (gestión de vulnerabilidades)",
            "ISO_27001": "A.8.8 (gestión de vulnerabilidades técnicas)",
            "NIST_CSF": "ID.RA-01 / PR.PS-02",
        }
    return {}


def _grep_lines(text: str, pattern: str, limit: int = 5) -> str:
    matches = [line.strip() for line in (text or "").splitlines() if re.search(pattern, line, re.IGNORECASE)]
    return "\n".join(matches[:limit])


def parse_testssl_json(content: str, target: str = "") -> List[ToolObservation]:
    data = json.loads(content)
    if not isinstance(data, list):
        raise ValueError("testssl debe emitir una lista JSON")
    observations = []
    for entry in data:
        level = str(entry.get("severity", "")).upper()
        if level in ("OK", "INFO", "DEBUG"):
            continue
        if level not in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "WARN"):
            continue
        severity = Severity.MEDIUM if level == "WARN" else Severity[level]
        observations.append(ToolObservation(
            tool_key="testssl", title="TLS: " + str(entry.get("id", "finding")),
            severity=severity, description=str(entry.get("finding", "")),
            slug=str(entry.get("id", "finding")), host=target,
            evidence=json.dumps(entry, ensure_ascii=False), raw=entry,
        ))
    return observations


def parse_feroxbuster_jsonl(content: str, target: str = "") -> List[ToolObservation]:
    observations = []
    for line in content.splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("type") != "response":
            continue
        url = str(entry.get("url", ""))
        status = int(entry.get("status", 0))
        if url and 200 <= status < 400:
            observations.append(ToolObservation(
                tool_key="feroxbuster", title=f"Ruta descubierta: {url}",
                severity=Severity.INFO, description=f"Respuesta HTTP {status}; requiere revisar exposición y permisos.",
                slug=url, host=target, evidence=json.dumps(entry, ensure_ascii=False), raw=entry,
            ))
    return observations


PARSERS: Dict[str, Callable[..., List[ToolObservation]]] = {
    "testssl": parse_testssl_json,
    "feroxbuster": parse_feroxbuster_jsonl,
    "nmap": parse_nmap_xml,
    "masscan": parse_masscan_xml,
    "dnsrecon": parse_dnsrecon_json,
    "amass": parse_amass_text,
    "whatweb": parse_whatweb_json,
    "wafw00f": parse_wafw00f_json,
    "httpx": parse_httpx_jsonl,
    "nikto": parse_nikto_json,
    "nuclei": parse_nuclei_jsonl,
    "gobuster": parse_gobuster_text,
    "ffuf": parse_ffuf_json,
    "dirb": parse_dirb_text,
    "wpscan": parse_wpscan_json,
    "nbtscan": parse_nbtscan_text,
    "enum4linux": parse_enum4linux_text,
    "smbclient": parse_smbclient_text,
    "nxc": parse_nxc_text,
    "snmpwalk": parse_snmpwalk_text,
    "onesixtyone": parse_onesixtyone_text,
    "smtp_user_enum": parse_smtp_user_enum_text,
    "sslscan": parse_sslscan_xml,
    "sqlmap": parse_sqlmap_text,
    "commix": parse_commix_text,
    "hydra": parse_hydra_text,
    "john": parse_john_text,
    "hashcat": parse_hashcat_text,
    "impacket_secretsdump": parse_secretsdump_text,
    "tcpdump": parse_capture_artifact,
    "tshark": parse_capture_artifact,
    "airodump_ng": lambda content, target: parse_airodump_capture(content, target),
    "aircrack_ng": parse_aircrack_text,
    "searchsploit": parse_searchsploit_json,
    "responder": parse_plain_output,
}


def parse_tool_output(
    tool_key: str,
    content: str,
    target: str = "",
    artifact_path: Optional[str] = None,
    allow_plain_fallback: bool = True,
    strict: bool = False,
) -> List[ToolObservation]:
    """Parses raw tool output, returning normalized observations (never raises).

    ``allow_plain_fallback`` should be disabled when the tool run itself failed
    (non-zero exit code or timeout): in that case an unstructured dump of a failure
    message would only add noise as an ``INFO`` finding.
    """
    if not content and not artifact_path:
        return []
    parser = PARSERS.get(tool_key)
    try:
        if parser is None:
            return parse_plain_output(content, target, tool_key) if allow_plain_fallback else []
        if tool_key in ("hashcat",):
            return parse_hashcat_text(content, target, artifact_path=artifact_path)
        if tool_key == "searchsploit":
            return parse_searchsploit_json(content, target)
        if tool_key == "airodump_ng":
            return parse_airodump_capture(content, target, artifact_path=artifact_path)
        observations = parser(content, target)
        if not observations and (content or "").strip() and allow_plain_fallback:
            return parse_plain_output(content, target, tool_key)
        return observations
    except Exception:  # Standalone legacy callers may request tolerant parsing.
        if strict:
            raise
        return []


__all__ = [
    "ToolObservation",
    "PARSERS",
    "parse_tool_output",
    "parse_nmap_xml",
    "parse_masscan_xml",
    "parse_nuclei_jsonl",
    "parse_nikto_json",
    "parse_whatweb_json",
    "parse_wafw00f_json",
    "parse_httpx_jsonl",
    "parse_gobuster_text",
    "parse_ffuf_json",
    "parse_dirb_text",
    "parse_wpscan_json",
    "parse_dnsrecon_json",
    "parse_amass_text",
    "parse_nbtscan_text",
    "parse_enum4linux_text",
    "parse_smbclient_text",
    "parse_nxc_text",
    "parse_snmpwalk_text",
    "parse_onesixtyone_text",
    "parse_smtp_user_enum_text",
    "parse_sslscan_xml",
    "parse_sqlmap_text",
    "parse_commix_text",
    "parse_hydra_text",
    "parse_john_text",
    "parse_hashcat_text",
    "parse_secretsdump_text",
    "parse_searchsploit_json",
    "parse_capture_artifact",
    "parse_aircrack_text",
    "parse_airodump_capture",
    "parse_plain_output",
]
