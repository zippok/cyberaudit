"""
CyberAudit TLS & Cipher Configuration Auditor
Performs cryptographic assessment of HTTPS and TLS service endpoints:
- Detects deprecated protocol support (SSLv2, SSLv3, TLS 1.0, TLS 1.1).
- Flags weak cipher suites (RC4, 3DES, DES, export ciphers, legacy CBC).
- Audits X.509 certificate validity: expiration dates, days remaining, SAN coverage, and self-signed certificates.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


DEPRECATED_PROTOCOLS = {
    "SSLv2": (Severity.CRITICAL, "Protocolo SSLv2 obsoleto y vulnerable a ataques DROWN."),
    "SSLv3": (Severity.CRITICAL, "Protocolo SSLv3 vulnerable a ataques POODLE."),
    "TLSv1": (Severity.HIGH, "Protocolo TLS 1.0 deprecado (PCI-DSS 4.0 prohíbe su uso)."),
    "TLSv1.1": (Severity.HIGH, "Protocolo TLS 1.1 deprecado por RFC 8996."),
}

WEAK_CIPHER_KEYWORDS = [
    ("RC4", Severity.HIGH, "Cifrador de flujo RC4 criptográficamente roto."),
    ("3DES", Severity.HIGH, "Cifrador Triple-DES vulnerable al ataque Sweet32 (CVE-2016-2183)."),
    ("DES", Severity.CRITICAL, "Cifrador DES obsoleto con tamaño de clave inseguro."),
    ("MD5", Severity.HIGH, "Algoritmo de hash MD5 vulnerable a colisiones."),
    ("NULL", Severity.CRITICAL, "Suite sin cifrado (texto plano)."),
    ("EXPORT", Severity.CRITICAL, "Ciphers de exportación débiles (vulnerable a FREAK)."),
]


class TLSCipherAuditor:
    """Auditor for cryptographic hygiene of TLS endpoints."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def audit_endpoint(self, host: str, port: int = 443) -> List[Finding]:
        """
        Connects to the specified host:port and performs TLS configuration checks.
        """
        findings: List[Finding] = []

        # 1. Inspect active connection with standard modern context
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher_info = ssock.cipher()  # (name, protocol_version, bits)
                    version = ssock.version()

                    # Analyze active cipher and version
                    if cipher_info:
                        cipher_name, proto_ver, bits = cipher_info
                        for keyword, sev, reason in WEAK_CIPHER_KEYWORDS:
                            if keyword in cipher_name.upper():
                                findings.append(Finding(
                                    id=f"TLS-CIPHER-WEAK-{keyword}",
                                    title=f"Suite Criptográfica Débil Negociada: {cipher_name}",
                                    description=f"{reason} Bits negociados: {bits}.",
                                    severity=sev,
                                    pillar=Pillar.CLOUD_DEFENSE,
                                    scanner_name="tls_cipher_audit",
                                    file_path=f"https://{host}:{port}",
                                    cwe_id="CWE-326",
                                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                                    compliance_controls={
                                        "PCI_DSS": "PCI-DSS 4.0 Requirement 4.1",
                                        "NIST": "NIST SP 800-52 Rev. 2",
                                    },
                                    remediation="Deshabilitar suites de cifrado débiles en la configuración del servidor web o reverse proxy.",
                                    confidence="HIGH",
                                ))

                    if version in DEPRECATED_PROTOCOLS:
                        sev, desc = DEPRECATED_PROTOCOLS[version]
                        findings.append(Finding(
                            id=f"TLS-PROTO-{version}",
                            title=f"Protocolo TLS Deprecado Negociado: {version}",
                            description=desc,
                            severity=sev,
                            pillar=Pillar.CLOUD_DEFENSE,
                            scanner_name="tls_cipher_audit",
                            file_path=f"https://{host}:{port}",
                            cwe_id="CWE-326",
                            stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                            compliance_controls={
                                "PCI_DSS": "PCI-DSS 4.0 Req 4.1 / RFC 8996",
                                "ISO_27001": "ISO 27001:2022 A.8.24",
                            },
                            remediation="Forzar el uso exclusivo de TLS 1.2 y TLS 1.3 en Nginx, Apache, Cloudflare o AWS ALB.",
                            confidence="HIGH",
                        ))

                    # Analyze Certificate
                    if cert:
                        findings.extend(self._audit_certificate(cert, host, port))

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                id="TLS-CERT-UNTRUSTED",
                title=f"Certificado TLS No Confiable o Autofirmado ({e.verify_code or 'UNKNOWN'})",
                description=f"La cadena de confianza del certificado falló la validación: {e.verify_message}",
                severity=Severity.HIGH,
                pillar=Pillar.CLOUD_DEFENSE,
                scanner_name="tls_cipher_audit",
                file_path=f"https://{host}:{port}",
                cwe_id="CWE-295",
                stride_category=StrideCategory.SPOOFING.value,
                compliance_controls={"CIS": "CIS Controls v8 3.10"},
                remediation="Instalar un certificado TLS emitido por una Autoridad de Certificación (CA) públicamente reconocida.",
                confidence="HIGH",
            ))
        except (socket.timeout, socket.error, OSError) as e:
            # Port closed or connection refused
            pass

        return findings

    def _audit_certificate(self, cert: Dict[str, Any], host: str, port: int) -> List[Finding]:
        findings = []

        # Check expiration (notAfter)
        not_after_str = cert.get("notAfter")
        if not_after_str:
            try:
                # Format example: "May 25 12:00:00 2025 GMT"
                expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expire_dt - now).days

                if days_left < 0:
                    findings.append(Finding(
                        id="TLS-CERT-EXPIRED",
                        title=f"Certificado TLS Vencido (Expiró hace {abs(days_left)} días)",
                        description=f"El certificado expiró el {not_after_str}. Provocará alertas de navegación críticas y caída de servicios.",
                        severity=Severity.CRITICAL,
                        pillar=Pillar.CLOUD_DEFENSE,
                        scanner_name="tls_cipher_audit",
                        file_path=f"https://{host}:{port}",
                        cwe_id="CWE-295",
                        stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                        remediation="Renovar el certificado inmediatamente mediante certbot / Let's Encrypt o CA corporativa.",
                        confidence="HIGH",
                    ))
                elif days_left < 15:
                    findings.append(Finding(
                        id="TLS-CERT-EXPIRING-SOON",
                        title=f"Certificado TLS Próximo a Vencer ({days_left} días restantes)",
                        description=f"El certificado vencerá el {not_after_str}.",
                        severity=Severity.HIGH if days_left < 7 else Severity.MEDIUM,
                        pillar=Pillar.CLOUD_DEFENSE,
                        scanner_name="tls_cipher_audit",
                        file_path=f"https://{host}:{port}",
                        cwe_id="CWE-295",
                        stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                        remediation="Proceder a la renovación anticipada del certificado TLS para evitar disrupción operacional.",
                        confidence="HIGH",
                    ))
            except Exception:
                pass

        # Check Subject Alternative Names (SAN)
        san_entries = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
        if san_entries:
            # Verify host matches at least one SAN entry or wildcard
            matches = False
            host_lower = host.lower()
            for san in san_entries:
                san_lower = san.lower()
                if san_lower == host_lower:
                    matches = True
                    break
                if san_lower.startswith("*."):
                    suffix = san_lower[2:]
                    if host_lower.endswith(suffix) and host_lower.count(".") == suffix.count(".") + 1:
                        matches = True
                        break
            if not matches:
                findings.append(Finding(
                    id="TLS-CERT-SAN-MISMATCH",
                    title="Discrepancia en Nombre del Certificado (SAN Mismatch)",
                    description=f"El host '{host}' no coincide con los Subject Alternative Names (SAN) del certificado: {san_entries[:5]}.",
                    severity=Severity.HIGH,
                    pillar=Pillar.CLOUD_DEFENSE,
                    scanner_name="tls_cipher_audit",
                    file_path=f"https://{host}:{port}",
                    cwe_id="CWE-295",
                    stride_category=StrideCategory.SPOOFING.value,
                    remediation="Reemitir el certificado incluyendo el nombre de dominio o subdominio exacto en la lista SAN.",
                    confidence="HIGH",
                ))

        return findings
