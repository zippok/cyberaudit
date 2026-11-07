"""
CyberAudit HTTP Headers & Cookie Security Auditor
Inspects response headers and cookies for defense-in-depth security best practices.
"""

from typing import List, Dict, Any, Optional
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class HeadersAndCookieAuditor:
    """Audits HTTP response headers, CORS configurations, and cookie flags."""

    AUTH_COOKIE_KEYWORDS = [
        "session", "sess", "jwt", "token", "auth", "access_token",
        "id_token", "connect.sid", "phpsessid", "jsessionid", "csrftoken",
    ]

    def audit_headers(self, headers: Dict[str, str], url: str) -> List[Finding]:
        """
        Audits HTTP security headers from the main page response.
        """
        findings: List[Finding] = []
        h = {k.lower(): v.strip() for k, v in headers.items()}
        is_https = url.lower().startswith("https://")

        # 1. Content-Security-Policy (CSP)
        csp = h.get("content-security-policy")
        if not csp:
            findings.append(Finding(
                id="WEB-CSP-MISSING",
                title="Cabecera Content-Security-Policy (CSP) Ausente",
                description="La aplicación no define directivas CSP para restringir orígenes de scripts, hojas de estilo y recursos.",
                severity=Severity.HIGH,
                pillar=Pillar.PENETRATION_TESTER,
                scanner_name="headers_cookies",
                file_path=url,
                cwe_id="CWE-693",
                stride_category=StrideCategory.TAMPERING.value,
                compliance_controls={
                    "OWASP": "OWASP Top 10 A05:2021 Security Misconfiguration",
                    "PCI_DSS": "PCI-DSS 4.0 Requirement 6.4.3",
                },
                remediation="Implementar la cabecera 'Content-Security-Policy' con directivas restrictivas 'default-src https:; object-src none;'.",
                confidence="HIGH",
            ))
        else:
            csp_lower = csp.lower()
            if "'unsafe-inline'" in csp_lower:
                findings.append(Finding(
                    id="WEB-CSP-UNSAFE-INLINE",
                    title="Directiva Insegura 'unsafe-inline' en Content-Security-Policy",
                    description="La directiva CSP autoriza la ejecución de scripts inline arbitrarios, neutralizando la protección anti-XSS.",
                    severity=Severity.MEDIUM,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="headers_cookies",
                    file_path=url,
                    cwe_id="CWE-693",
                    stride_category=StrideCategory.TAMPERING.value,
                    remediation="Reemplazar scripts inline por archivos externos firmados con nonces ('nonce-...') o hashes SHA-256.",
                    confidence="HIGH",
                ))
            if "'unsafe-eval'" in csp_lower:
                findings.append(Finding(
                    id="WEB-CSP-UNSAFE-EVAL",
                    title="Directiva Insegura 'unsafe-eval' en Content-Security-Policy",
                    description="La política CSP permite el uso de eval() y Function() dinámicos, aumentando la superficie de ataque para inyecciones de código.",
                    severity=Severity.MEDIUM,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="headers_cookies",
                    file_path=url,
                    cwe_id="CWE-693",
                    stride_category=StrideCategory.TAMPERING.value,
                    remediation="Eliminar 'unsafe-eval' refactorizando el código para prescindir de generación dinámica de funciones desde strings.",
                    confidence="HIGH",
                ))

        # 2. Strict-Transport-Security (HSTS)
        if is_https:
            hsts = h.get("strict-transport-security")
            if not hsts:
                findings.append(Finding(
                    id="WEB-HSTS-MISSING",
                    title="Cabecera Strict-Transport-Security (HSTS) Ausente",
                    description="El sitio HTTPS no emite HSTS, permitiendo que navegadores intenten conexiones HTTP en texto plano previas a la redirección.",
                    severity=Severity.MEDIUM,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="headers_cookies",
                    file_path=url,
                    cwe_id="CWE-319",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Requirement 4.1"},
                    remediation="Agregar 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                    confidence="HIGH",
                ))
            else:
                if "includesubdomains" not in hsts.lower():
                    findings.append(Finding(
                        id="WEB-HSTS-NO-SUBDOMAINS",
                        title="HSTS Sin Directiva 'includeSubDomains'",
                        description="La política HSTS actual no cubre subdominios, dejando desprotegidos endpoints derivados.",
                        severity=Severity.LOW,
                        pillar=Pillar.PENETRATION_TESTER,
                        scanner_name="headers_cookies",
                        file_path=url,
                        cwe_id="CWE-319",
                        remediation="Añadir la directiva 'includeSubDomains' a la cabecera Strict-Transport-Security.",
                        confidence="MEDIUM",
                    ))

        # 3. X-Frame-Options (Clickjacking)
        xfo = h.get("x-frame-options")
        if not xfo and ("frame-ancestors" not in (csp or "").lower()):
            findings.append(Finding(
                id="WEB-CLICKJACKING-XFO",
                title="Protección Anti-Clickjacking Ausente (X-Frame-Options)",
                description="La página no especifica 'X-Frame-Options' ni directiva CSP 'frame-ancestors', permitiendo ser embebida en <iframe> maliciosos.",
                severity=Severity.MEDIUM,
                pillar=Pillar.PENETRATION_TESTER,
                scanner_name="headers_cookies",
                file_path=url,
                cwe_id="CWE-1021",
                stride_category=StrideCategory.SPOOFING.value,
                remediation="Configurar 'X-Frame-Options: DENY' o 'X-Frame-Options: SAMEORIGIN'.",
                confidence="HIGH",
            ))

        # 4. X-Content-Type-Options (MIME-Sniffing)
        xcto = h.get("x-content-type-options")
        if xcto != "nosniff":
            findings.append(Finding(
                id="WEB-MIME-NOSNIFF",
                title="Cabecera X-Content-Type-Options Ausente o Incorrecta",
                description="Sin 'X-Content-Type-Options: nosniff', los navegadores pueden interpretar respuestas de tipo texto como scripts ejecutables.",
                severity=Severity.LOW,
                pillar=Pillar.PENETRATION_TESTER,
                scanner_name="headers_cookies",
                file_path=url,
                cwe_id="CWE-79",
                stride_category=StrideCategory.TAMPERING.value,
                remediation="Configurar la cabecera 'X-Content-Type-Options: nosniff' en todas las respuestas HTTP.",
                confidence="HIGH",
            ))

        # 5. Referrer-Policy
        ref_pol = h.get("referrer-policy")
        if not ref_pol or ref_pol.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append(Finding(
                id="WEB-REFERRER-POLICY-WEAK",
                title="Política de Referrer Débil o Ausente",
                description=f"La cabecera Referrer-Policy ({ref_pol or 'Ausente'}) puede filtrar parámetros sensibles de la URL a orígenes de terceros.",
                severity=Severity.LOW,
                pillar=Pillar.PENETRATION_TESTER,
                scanner_name="headers_cookies",
                file_path=url,
                cwe_id="CWE-200",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                remediation="Configurar 'Referrer-Policy: strict-origin-when-cross-origin' o 'no-referrer'.",
                confidence="MEDIUM",
            ))

        # 6. CORS Misconfiguration check
        cors_origin = h.get("access-control-allow-origin")
        cors_creds = h.get("access-control-allow-credentials", "").lower() == "true"
        if cors_origin == "*" and cors_creds:
            findings.append(Finding(
                id="WEB-CORS-WILDCARD-CREDS",
                title="Configuración Crítica de CORS (Comodín con Credenciales)",
                description="Access-Control-Allow-Origin está configurado como '*' permitiendo a la vez envío de credenciales autenticadas.",
                severity=Severity.CRITICAL,
                pillar=Pillar.PENETRATION_TESTER,
                scanner_name="headers_cookies",
                file_path=url,
                cwe_id="CWE-942",
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                remediation="Definir una lista blanca explícita de orígenes autorizados en lugar del comodín '*'.",
                confidence="HIGH",
            ))

        # 7. Server / Technology Leakage
        server_header = h.get("server") or h.get("x-powered-by")
        if server_header:
            findings.append(Finding(
                id="WEB-SERVER-BANNER-LEAK",
                title=f"Fuga de Versión en Encabezado de Servidor ({server_header})",
                description=f"El servidor revela su identidad y tecnología mediante cabeceras HTTP: '{server_header}'.",
                severity=Severity.LOW,
                pillar=Pillar.SECURITY_ENGINEER,
                scanner_name="headers_cookies",
                file_path=url,
                cwe_id="CWE-200",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                remediation="Ofuscar o suprimir las cabeceras 'Server' y 'X-Powered-By' en el servidor web.",
                confidence="HIGH",
            ))

        return findings

    def audit_cookies(self, cookies: List[Dict[str, Any]], url: str) -> List[Finding]:
        """
        Audits browser cookies collected during page lifecycle.
        Expected cookie dict keys: name, value, domain, path, secure, httpOnly, sameSite.
        """
        findings: List[Finding] = []
        is_https = url.lower().startswith("https://")

        for c in cookies:
            name = c.get("name", "")
            is_secure = c.get("secure", False)
            is_httponly = c.get("httpOnly", False)
            same_site = (c.get("sameSite") or "").capitalize()

            # Check if cookie resembles an auth or session token
            is_sensitive = any(kw in name.lower() for kw in self.AUTH_COOKIE_KEYWORDS)

            if is_sensitive and not is_httponly:
                findings.append(Finding(
                    id="WEB-COOKIE-NO-HTTPONLY",
                    title=f"Cookie de Sesión Sin Flag 'HttpOnly' ({name})",
                    description=f"La cookie '{name}' puede contener datos de autenticación y es accesible desde JavaScript en el DOM (vulnerable a robo por XSS).",
                    severity=Severity.HIGH,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="headers_cookies",
                    file_path=f"{url} [cookie:{name}]",
                    cwe_id="CWE-1004",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"OWASP": "OWASP ASVS v4.0 V3.4.1"},
                    remediation=f"Establecer la directiva 'HttpOnly' al emitir la cookie '{name}'.",
                    confidence="HIGH",
                ))

            if is_https and not is_secure:
                findings.append(Finding(
                    id="WEB-COOKIE-NO-SECURE",
                    title=f"Cookie en Sitio HTTPS Sin Flag 'Secure' ({name})",
                    description=f"La cookie '{name}' puede ser transmitida en texto claro si el cliente realiza una petición HTTP accidental.",
                    severity=Severity.HIGH if is_sensitive else Severity.MEDIUM,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="headers_cookies",
                    file_path=f"{url} [cookie:{name}]",
                    cwe_id="CWE-614",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Req 4.1"},
                    remediation=f"Establecer el atributo 'Secure' al emitir la cookie '{name}'.",
                    confidence="HIGH",
                ))

            if not same_site or same_site == "None":
                findings.append(Finding(
                    id="WEB-COOKIE-NO-SAMESITE",
                    title=f"Cookie Sin Protección SameSite Restrictiva ({name})",
                    description=f"La cookie '{name}' tiene SameSite={same_site or 'Ausente'}, aumentando el riesgo de ataques Cross-Site Request Forgery (CSRF).",
                    severity=Severity.MEDIUM if is_sensitive else Severity.LOW,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="headers_cookies",
                    file_path=f"{url} [cookie:{name}]",
                    cwe_id="CWE-1275",
                    stride_category=StrideCategory.SPOOFING.value,
                    remediation=f"Configurar 'SameSite=Lax' o 'SameSite=Strict' para la cookie '{name}'.",
                    confidence="HIGH",
                ))

        return findings
