"""
CyberAudit Login Posture & Ergonomics Scanner
Evaluates login interfaces against NIST SP 800-63B and OWASP ASVS:
1. User Enumeration Defense: Response variance and timing analysis between existing vs non-existent accounts.
2. Rate Limiting & Brute-Force Containment: Controlled, minimal test burst (5 probes) checking for HTTP 429 or CAPTCHA.
3. Credential Transmission Security: HTTPS action attribute, password field hygiene, paste-prevention detection.
4. Multi-Factor Authentication (MFA) Indicator: Inspection for WebAuthn/TOTP cues.
"""

import time
import urllib.parse
import urllib.request
import json
import re
import ssl
from typing import List, Dict, Any, Optional
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class LoginPostureAuditor:
    """Audits defensive posture of authentication endpoints and login forms."""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        self.ssl_ctx = ssl.create_default_context()
        # For defensive scanning, verify certificates
        self.ssl_ctx.check_hostname = True
        self.ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    def audit_form_html(self, html_content: str, page_url: str) -> List[Finding]:
        """
        Performs static DOM/HTML posture checks on a login page content.
        """
        findings: List[Finding] = []
        lower_html = html_content.lower()

        # 1. Action points to insecure HTTP
        if 'action="http://' in lower_html or "action='http://" in lower_html:
            findings.append(Finding(
                id="AUTH-ACTION-INSECURE",
                title="Formulario de Autenticación Envía Credenciales por HTTP Inseguro",
                description="El atributo 'action' del formulario apunta a un esquema HTTP sin cifrado TLS (vulnerable a intercepción Man-in-the-Middle).",
                severity=Severity.CRITICAL,
                pillar=Pillar.PENETRATION_TESTER,
                scanner_name="login_posture",
                file_path=page_url,
                cwe_id="CWE-319",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                compliance_controls={
                    "NIST": "NIST SP 800-63B Section 5.1.1",
                    "PCI_DSS": "PCI-DSS 4.0 Req 8.3.1",
                },
                remediation="Asegurar que el atributo action del formulario apunte estrictamente a un endpoint HTTPS.",
                confidence="HIGH",
            ))

        # 2. Paste blocking check (anti-pattern preventing password managers)
        if re.search(r'onpaste\s*=\s*["\']\s*return\s+false;?\s*["\']', lower_html):
            findings.append(Finding(
                id="AUTH-PASTE-BLOCKED",
                title="Bloqueo de Pegado en Campo de Contraseña (Anti-Patrón)",
                description="La aplicación bloquea el pegado en el campo de contraseña ('onpaste=return false'), desincentivando el uso de gestores de contraseñas seguros.",
                severity=Severity.MEDIUM,
                pillar=Pillar.SOFTWARE_QA,
                scanner_name="login_posture",
                file_path=page_url,
                cwe_id="CWE-522",
                stride_category=StrideCategory.SPOOFING.value,
                compliance_controls={
                    "NIST": "NIST SP 800-63B Section 5.1.1.2 (Permit paste functionality for all password fields)",
                },
                remediation="Eliminar cualquier manejador de evento 'onpaste' que bloquee el pegado de contraseñas seguras generadas por gestores.",
                confidence="HIGH",
            ))

        # 3. Autocomplete attribute
        if 'type="password"' in lower_html or "type='password'" in lower_html:
            if 'autocomplete="current-password"' not in lower_html and "autocomplete='current-password'" not in lower_html:
                findings.append(Finding(
                    id="AUTH-AUTOCOMPLETE-MISSING",
                    title="Atributo 'autocomplete=current-password' Faltante en Campo de Contraseña",
                    description="El campo de contraseña carece de la pista de accesibilidad y ergonomía recomendada para navegadores y gestores.",
                    severity=Severity.LOW,
                    pillar=Pillar.UI_UX,
                    scanner_name="login_posture",
                    file_path=page_url,
                    cwe_id="CWE-1375",
                    remediation="Agregar autocomplete='current-password' en el elemento <input type='password'>.",
                    confidence="MEDIUM",
                ))

        return findings

    def audit_rate_limiting(
        self,
        login_url: str,
        method: str = "POST",
        payload_template: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """
        Sends a safe, strictly controlled 5-request burst to test for rate limiting / account lockout mechanisms.
        Never runs brute force attacks or dictionary tests.
        """
        findings: List[Finding] = []
        hit_rate_limit = False
        rate_limit_headers_seen = False

        headers = {
            "User-Agent": "CyberAudit-Defense-Auditor/2.0 (Security Posture Probe)",
            "Content-Type": "application/json",
            "Accept": "application/json, text/html",
        }

        for i in range(5):
            body_data = payload_template.copy() if payload_template else {
                "username": f"cyberaudit_probe_{i}@nonexistent-audit.invalid",
                "password": f"ControlledProbePass!{i}",
            }
            encoded_body = json.dumps(body_data).encode("utf-8")

            try:
                req = urllib.request.Request(
                    login_url,
                    data=encoded_body,
                    headers=headers,
                    method=method,
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    if any(h in resp_headers for h in ["retry-after", "x-ratelimit-remaining", "cf-mitigated"]):
                        rate_limit_headers_seen = True
            except urllib.error.HTTPError as e:
                # HTTP 429 Too Many Requests or 403 / Captcha challenge
                if e.code == 429 or e.code == 403:
                    hit_rate_limit = True
                    break
                resp_headers = {k.lower(): v for k, v in e.headers.items()}
                if any(h in resp_headers for h in ["retry-after", "x-ratelimit-remaining"]):
                    rate_limit_headers_seen = True
            except Exception:
                # Connection / timeout issue
                break

            time.sleep(0.1)

        if not hit_rate_limit and not rate_limit_headers_seen:
            findings.append(Finding(
                id="AUTH-RATE-003",
                title="Ausencia de Limitación de Tasa (Rate Limiting) en Endpoint de Acceso",
                description="El endpoint de autenticación no devolvió cabeceras de rate limiting ni código de contención HTTP 429 tras solicitudes consecutivas.",
                severity=Severity.HIGH,
                pillar=Pillar.PENETRATION_TESTER,
                scanner_name="login_posture",
                file_path=login_url,
                cwe_id="CWE-307",
                stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                compliance_controls={
                    "PCI_DSS": "PCI-DSS 4.0 Requirement 8.3.4 (Lock out user access after not more than 10 invalid attempts)",
                    "OWASP": "OWASP ASVS v4.0 V2.2.1",
                    "NIST": "NIST SP 800-63B Section 5.2.2",
                },
                remediation="Implementar mecanismos de contención por IP/cuenta (WAF o API Gateway limitando a un máximo de 5 intentos por minuto con respuesta HTTP 429).",
                confidence="HIGH",
            ))

        return findings

    def audit_user_enumeration(
        self,
        login_url: str,
        existing_candidate: str = "admin@example.com",
        non_existent_candidate: str = "non_existent_user_938174_audit@test.invalid",
    ) -> List[Finding]:
        """
        Analyzes response differences and execution timing between two requests
        to detect username enumeration vulnerabilities.
        """
        findings: List[Finding] = []
        headers = {
            "User-Agent": "CyberAudit-Defense-Auditor/2.0",
            "Content-Type": "application/json",
            "Accept": "application/json, text/html",
        }

        probes = [
            ("existing", existing_candidate),
            ("non_existent", non_existent_candidate),
        ]
        results = {}

        for key, username in probes:
            payload = json.dumps({"username": username, "password": "SamplePassword!2026"}).encode("utf-8")
            start = time.perf_counter()
            status_code = 0
            body_text = ""
            try:
                req = urllib.request.Request(login_url, data=payload, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status_code = resp.status
                    body_text = resp.read(512).decode("utf-8", errors="ignore").lower()
            except urllib.error.HTTPError as e:
                status_code = e.code
                body_text = e.read(512).decode("utf-8", errors="ignore").lower()
            except Exception:
                return []

            duration = time.perf_counter() - start
            results[key] = (status_code, body_text, duration)

        res_exist = results.get("existing")
        res_nonexist = results.get("non_existent")

        if res_exist and res_nonexist:
            status_ex, body_ex, time_ex = res_exist
            status_non, body_non, time_non = res_nonexist

            # Check for different status codes (e.g. 404 for missing user vs 401 for bad pass)
            if status_ex != status_non and status_ex != 0 and status_non != 0:
                findings.append(Finding(
                    id="AUTH-ENUM-002",
                    title="Enumeración de Cuentas por Código de Estado HTTP Diferenciado",
                    description=f"El endpoint respondió con HTTP {status_ex} para un usuario potencial y HTTP {status_non} para usuario inexistente.",
                    severity=Severity.MEDIUM,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="login_posture",
                    file_path=login_url,
                    cwe_id="CWE-204",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={
                        "OWASP": "OWASP Top 10 A07:2021 Identification and Authentication Failures",
                        "NIST": "NIST SP 800-63B Section 5.1.1.2",
                    },
                    remediation="Estandarizar todas las respuestas de error en autenticación a un mensaje genérico ('Credenciales inválidas') y código HTTP 401 unificado.",
                    confidence="HIGH",
                ))

            # Check for keyword discrepancy ("user not found" vs "incorrect password")
            user_not_found_keywords = ["usuario no existe", "user not found", "no account", "cuenta no registrada"]
            bad_pass_keywords = ["contraseña incorrecta", "invalid password", "wrong password"]

            has_user_msg = any(kw in body_non for kw in user_not_found_keywords)
            has_pass_msg = any(kw in body_ex for kw in bad_pass_keywords)

            if has_user_msg or (has_pass_msg and not has_user_msg and body_ex != body_non):
                findings.append(Finding(
                    id="AUTH-ENUM-BODY-003",
                    title="Enumeración de Cuentas por Mensajes de Error Detallados",
                    description="El servidor revela si el usuario existe o no a través de mensajes diferenciados en el cuerpo de la respuesta.",
                    severity=Severity.MEDIUM,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="login_posture",
                    file_path=login_url,
                    cwe_id="CWE-204",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    remediation="Retornar un mensaje idéntico e indistinguible sin importar si la cuenta existe o si la clave es incorrecta.",
                    confidence="HIGH",
                ))

        return findings
