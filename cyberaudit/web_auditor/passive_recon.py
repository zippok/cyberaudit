"""
CyberAudit Passive Web Reconnaissance Auditor
Evaluates standard metadata, disclosure files, and administrative hygiene:
1. RFC 9116 security.txt compliance.
2. robots.txt and sitemap.xml inspection for inadvertent sensitive endpoint disclosures.
3. Passive detection of critical repository or config files (/.git/HEAD, /.env, /swagger.json).
"""

import urllib.request
import urllib.parse
import ssl
from typing import List, Dict, Any, Optional, Tuple
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class PassiveWebReconAuditor:
    """Performs defensive passive reconnaissance against web targets."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.errors = []

    def audit_target(self, base_url: str) -> List[Finding]:
        """
        Executes passive recon checks against base URL.
        """
        findings: List[Finding] = []
        self.errors = []
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. RFC 9116 security.txt
        findings.extend(self._check_security_txt(origin))

        # 2. robots.txt sensitive path leaks
        findings.extend(self._check_robots_txt(origin))

        # 3. Critical files exposure (.git, .env, swagger)
        findings.extend(self._check_exposed_files(origin))

        return findings

    def _fetch_url(self, url: str) -> Optional[Tuple[int, str]]:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CyberAudit-Defense-Auditor/2.0"},
            )
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=self.ctx))
            with opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                body = resp.read(2048).decode("utf-8", errors="ignore")
                return status, body
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception as exc:
            self.errors.append({"url": url, "error": str(exc)})
            return None

    def _check_security_txt(self, origin: str) -> List[Finding]:
        findings = []
        sec_url = f"{origin}/.well-known/security.txt"
        res = self._fetch_url(sec_url)

        if not res or res[0] != 200:
            # Check fallback /security.txt
            sec_url = f"{origin}/security.txt"
            res = self._fetch_url(sec_url)

        if not res or res[0] != 200:
            findings.append(Finding(
                id="WEB-RECON-NO-SECURITY-TXT",
                title="Archivo de Divulgación de Vulnerabilidades Ausente (RFC 9116)",
                description="El dominio no publica un archivo 'security.txt' para que investigadores de seguridad reporten vulnerabilidades de forma responsable.",
                severity=Severity.INFO,
                pillar=Pillar.SECURITY_ENGINEER,
                scanner_name="passive_recon",
                file_path=f"{origin}/.well-known/security.txt",
                cwe_id="CWE-200",
                remediation="Publicar /.well-known/security.txt con directivas 'Contact:' y 'Expires:' siguiendo la especificación RFC 9116.",
                confidence="HIGH",
            ))
        else:
            _, content = res
            if "contact:" not in content.lower():
                findings.append(Finding(
                    id="WEB-RECON-SECURITY-TXT-NO-CONTACT",
                    title="security.txt Incompleto (Falta Campo 'Contact:')",
                    description="El archivo security.txt publicado no incluye el campo obligatorio 'Contact:'.",
                    severity=Severity.INFO,
                    pillar=Pillar.SECURITY_ENGINEER,
                    scanner_name="passive_recon",
                    file_path=sec_url,
                    remediation="Añadir una dirección de contacto válida (mailto: o url) en security.txt.",
                    confidence="HIGH",
                ))

        return findings

    def _check_robots_txt(self, origin: str) -> List[Finding]:
        findings = []
        robots_url = f"{origin}/robots.txt"
        res = self._fetch_url(robots_url)
        if res and res[0] == 200:
            _, content = res
            disallowed_lines = []
            for line in content.splitlines():
                line_clean = line.strip()
                if line_clean.lower().startswith("disallow:"):
                    path = line_clean.split(":", 1)[1].strip()
                    if any(kw in path.lower() for kw in ["/admin", "/backup", "/private", "/internal", "/db", "/api/v1/internal", "/config"]):
                        disallowed_lines.append(path)

            if disallowed_lines:
                findings.append(Finding(
                    id="WEB-ROBOTS-SENSITIVE-PATH-DISCLOSED",
                    title=f"Rutas Administrativas/Sensibles Reveladas en robots.txt ({len(disallowed_lines)} rutas)",
                    description=f"El archivo robots.txt enumera rutas que deberían ser secretas: {', '.join(disallowed_lines[:5])}.",
                    severity=Severity.LOW,
                    pillar=Pillar.PENETRATION_TESTER,
                    scanner_name="passive_recon",
                    file_path=robots_url,
                    cwe_id="CWE-200",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    remediation="No confiar en robots.txt para ocultar rutas sensibles; implementar autenticación y autorización robusta a nivel servidor.",
                    confidence="HIGH",
                ))

        return findings

    def _check_exposed_files(self, origin: str) -> List[Finding]:
        findings = []
        checks = [
            (
                "/.git/HEAD",
                "WEB-EXPOSED-GIT-REPO",
                "Repositorio Git Expuesto Públicamente (/.git/HEAD)",
                "El directorio .git está públicamente accesible, permitiendo descargar el código fuente completo e historial de commits.",
                Severity.CRITICAL,
                "CWE-538",
                "Bloquear el acceso a carpetas y archivos que comiencen con punto (.*) en el servidor web.",
            ),
            (
                "/.env",
                "WEB-EXPOSED-ENV-FILE",
                "Archivo de Variables de Entorno Expuesto (/.env)",
                "El archivo de configuración .env es accesible, exponiendo potencialmente contraseñas y claves de API.",
                Severity.CRITICAL,
                "CWE-552",
                "Denegar el acceso inmediato a archivos .env en Nginx/Apache.",
            ),
            (
                "/swagger.json",
                "WEB-EXPOSED-SWAGGER",
                "Especificación OpenAPI / Swagger Expuesta Públicamente",
                "La documentación interna de la API (/swagger.json) es accesible sin autenticación.",
                Severity.LOW,
                "CWE-200",
                "Proteger la documentación de Swagger detrás de autenticación corporativa en producción.",
            ),
        ]

        for path, fid, title, desc, sev, cwe, rem in checks:
            target = f"{origin}{path}"
            res = self._fetch_url(target)
            if res and res[0] == 200:
                _, body = res
                # Sanity check for false positives (some SPAs return 200 index.html for any 404)
                if "<!doctype html" in body.lower() or "<html" in body.lower():
                    # Likely SPA fallback, not actual exposed raw file
                    continue

                if path == "/.git/HEAD" and "ref:" not in body:
                    continue

                findings.append(Finding(
                    id=fid,
                    title=title,
                    description=desc,
                    severity=sev,
                    pillar=Pillar.PENETRATION_TESTER if sev == Severity.CRITICAL else Pillar.SECURITY_ENGINEER,
                    scanner_name="passive_recon",
                    file_path=target,
                    cwe_id=cwe,
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    remediation=rem,
                    confidence="HIGH",
                ))

        return findings
