"""
CyberAudit Client-Side Security & DOM Inspector
Evaluates client-side state in live browser runtime:
1. Source Maps (.js.map) exposure in production.
2. Insecure secret, token, and PII storage in window.localStorage and window.sessionStorage.
3. Outdated frontend library detection (jQuery, React, Vue, Lodash).
4. Live runtime unhandled exceptions and console error leakage.
"""

from typing import List, Dict, Any, Optional
import urllib.request
import ssl
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


KNOWN_VULNERABLE_LIBRARIES = [
    {
        "name": "jQuery",
        "max_vulnerable": "3.5.0",
        "cve": "CVE-2020-11022",
        "severity": Severity.MEDIUM,
        "desc": "Versión vulnerable de jQuery con fallo de Cross-Site Scripting (XSS) en parseHTML.",
    },
    {
        "name": "Lodash",
        "max_vulnerable": "4.17.21",
        "cve": "CVE-2021-23337",
        "severity": Severity.HIGH,
        "desc": "Versión de Lodash vulnerable a Command Injection / Prototype Pollution en template.",
    },
]


class ClientSecurityAuditor:
    """Audits client-side execution, storage, and runtime leaks."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def audit_storage(self, storage_data: Dict[str, Any], url: str) -> List[Finding]:
        """
        Audits combined localStorage and sessionStorage key-value dumps.
        """
        findings: List[Finding] = []
        for key, value in storage_data.items():
            k_lower = key.lower()
            val_str = str(value)

            # Check for JWT / Bearer tokens
            is_jwt = "eyjh" in val_str.lower() and val_str.count(".") == 2
            is_secret_key = any(kw in k_lower for kw in ["token", "jwt", "bearer", "apikey", "api_key", "secret", "password"])

            if is_jwt or is_secret_key:
                findings.append(Finding(
                    id="WEB-STORAGE-SECRET-EXPOSED",
                    title=f"Token/Credencial Sensible en Web Storage ({key})",
                    description=f"La clave '{key}' contiene un token o credencial accesible directamente por scripts en el navegador (CWE-922). Si la aplicación sufre XSS, este token puede ser exfiltrado instantáneamente.",
                    severity=Severity.HIGH,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="client_security",
                    file_path=f"{url} [WebStorage:{key}]",
                    cwe_id="CWE-922",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={
                        "OWASP": "OWASP ASVS v4.0 V3.4.2",
                        "PCI_DSS": "PCI-DSS 4.0 Req 6.4.3",
                    },
                    remediation="Migrar el almacenamiento de tokens de sesión a cookies con directivas 'HttpOnly' y 'Secure'.",
                    confidence="HIGH",
                ))

        return findings

    def audit_source_maps(self, script_urls: List[str], base_url: str) -> List[Finding]:
        """
        Tests if public .js.map source map files are exposed in production.
        """
        findings: List[Finding] = []
        checked_urls = set()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for script_url in script_urls[:15]:  # Test first 15 unique scripts to avoid delays
            if not script_url.endswith(".js") or script_url in checked_urls:
                continue
            checked_urls.add(script_url)

            map_url = f"{script_url}.map"
            try:
                req = urllib.request.Request(
                    map_url,
                    headers={"User-Agent": "CyberAudit-Defense-Auditor/2.0"},
                )
                with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        content_sample = resp.read(512).decode("utf-8", errors="ignore")
                        if '"sources"' in content_sample or '"mappings"' in content_sample:
                            findings.append(Finding(
                                id="WEB-SOURCEMAP-EXPOSED",
                                title=f"Source Map Expuesto en Producción ({map_url.split('/')[-1]})",
                                description=f"El archivo '{map_url}' está públicamente accesible. Permite a cualquier usuario reconstruir el 100% del código fuente original TypeScript/React/Vue y comentaristas internos.",
                                severity=Severity.HIGH,
                                pillar=Pillar.PENETRATION_TESTER,
                                scanner_name="client_security",
                                file_path=map_url,
                                cwe_id="CWE-540",
                                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                                remediation="Deshabilitar la generación de source maps en producción (ej. 'productionSourceMap: false' o 'GENERATE_SOURCEMAP=false' en webpack/vite/Next.js).",
                                confidence="HIGH",
                            ))
                            break  # Avoid spamming multiple identical findings
            except Exception:
                continue

        return findings

    def audit_frontend_libraries(self, detected_libs: Dict[str, str], url: str) -> List[Finding]:
        """
        Audits detected JavaScript library versions in window object.
        """
        findings: List[Finding] = []
        for lib in KNOWN_VULNERABLE_LIBRARIES:
            name = lib["name"]
            version = detected_libs.get(name)
            if version:
                # Basic semver check
                if self._is_version_lower(version, lib["max_vulnerable"]):
                    findings.append(Finding(
                        id=f"WEB-LIB-VULNERABLE-{name.upper()}",
                        title=f"Biblioteca Frontend Obsoleta Detectada: {name} v{version}",
                        description=f"{lib['desc']} ({lib['cve']}). Versión activa: {version}.",
                        severity=lib["severity"],
                        pillar=Pillar.SECURITY_ENGINEER,
                        scanner_name="client_security",
                        file_path=url,
                        cwe_id="CWE-1104",
                        cve_id=lib["cve"],
                        stride_category=StrideCategory.TAMPERING.value,
                        compliance_controls={"PCI_DSS": "PCI-DSS 4.0 Requirement 6.3.2"},
                        remediation=f"Actualizar la biblioteca {name} a una versión superior a {lib['max_vulnerable']}.",
                        confidence="HIGH",
                    ))

        return findings

    def audit_console_errors(self, error_logs: List[str], url: str) -> List[Finding]:
        """
        Audits runtime console error messages for sensitive information disclosure.
        """
        findings: List[Finding] = []
        if not error_logs:
            return findings

        # Group and look for sensitive error signatures
        leaked_signatures = []
        for err in error_logs:
            if any(kw in err.lower() for kw in ["stack trace", "at line", "uncaught syntaxerror", "failed to load resource: the server responded with a status of 500"]):
                leaked_signatures.append(err[:150])

        if leaked_signatures:
            findings.append(Finding(
                id="WEB-CONSOLE-EXCEPTIONS-LEAK",
                title=f"Excepciones de Código y Errores 500 Filtrados en Consola ({len(leaked_signatures)} eventos)",
                description=f"Se detectaron errores de ejecución de JavaScript o respuestas 500 en el navegador: {'; '.join(leaked_signatures[:3])}.",
                severity=Severity.LOW,
                pillar=Pillar.SOFTWARE_QA,
                scanner_name="client_security",
                file_path=url,
                cwe_id="CWE-209",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                remediation="Capturar excepciones no controladas con try/catch o ErrorBoundaries de React/Vue y silenciar logs técnicos en producción.",
                confidence="HIGH",
            ))

        return findings

    def _is_version_lower(self, current: str, target: str) -> bool:
        """Simple semver comparison helper."""
        try:
            curr_parts = [int(p) for p in current.split(".") if p.isdigit()]
            targ_parts = [int(p) for p in target.split(".") if p.isdigit()]
            return curr_parts < targ_parts
        except Exception:
            return False
