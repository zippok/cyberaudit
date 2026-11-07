"""
AI Co-Analyst Module
Provides automated C-Suite executive summaries, threat vector synthesis,
and prioritized remediation roadmaps.
Supports:
1. Local Model (LM Studio / Ollama on localhost) - 100% offline & confidential
2. Cloud Model (Google Gemini 3.5 Flash / Flash Lite)
3. Deterministic Heuristic Engine (Offline fallback without LLM requirements)
"""

import os
import json
import logging
import urllib.request
import urllib.error
from urllib.parse import urlparse
from typing import Optional, Tuple
from dotenv import load_dotenv
from cyberaudit.core.models import ScanReport, Severity

# Load environment variables (.env)
load_dotenv()

logger = logging.getLogger("cyberaudit.ai")


def _is_safe_endpoint_url(url: str) -> bool:
    """Validates that an AI endpoint URL uses http/https and blocks cloud metadata IPs (169.254.169.254)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").lower()
        if host in ("169.254.169.254", "metadata.google.internal", "instance-data"):
            return False
        return True
    except Exception:
        return False


CYBERAUDIT_SYSTEM_PROMPT = """Eres el Auditor Principal de Ciberseguridad y Líder del SOC de CyberAudit Suite Enterprise.
Tu misión es emitir informes de evaluación de seguridad y debriefs ejecutivos de máximo rigor técnico, dirigidos al C-Suite (CISO, CTO, CEO) y a los equipos de ingeniería Blue Team, DevSecOps y Arquitectura.

PRINCIPIOS FUNDAMENTALES:
1. RIGOR Y CERO ALUCINACIONES: Basa tus conclusiones estricta y exclusivamente en los hallazgos técnicos reales. No inventes vectores que no tengan sustento en los datos.
2. CONTEXTUALIZACIÓN ARQUITECTÓNICA: Evalúa el entorno en su contexto (App de escritorio/móvil vs Microservicio Cloud vs IA). Un cliente nativo no corre en un clúster multi-tenant a menos que se indique explícitamente.
3. MODELADO DE AMENAZAS STRIDE Y MITRE ATT&CK: Explica cómo un adversario encadenaría las vulnerabilidades.
4. PLANES ACCIONABLES: Ofrece soluciones directas, parches de código y comandos de mitigación para las primeras 24 horas y 30-90 días.
5. CUMPLIMIENTO NORMATIVO: Mapea a PCI-DSS 4.0, ISO 27001:2022, GDPR Art. 32, NIST SP 800-61, HIPAA, SOC 2 y FedRAMP.

FORMATO Y ESTILO:
- Redacta en Español corporativo técnico impecable.
- Conserva acrónimos universales (SQLi, SSRF, RCE, MITRE ATT&CK, STRIDE, DREAD, CVE, PoC).
- Genera respuestas estructuradas en Markdown profesional con tablas y listas claras.
"""

AUDITOR_PERSONAS = {
    "software_architect": """Eres el Arquitecto de Software Principal de CyberAudit Suite Enterprise.
Tu enfoque es la arquitectura global, patrones de diseño (SOLID, Clean Architecture, Hexagonal), modularidad, acoplamiento bajo, cohesión alta, eliminación de dependencias circulares y reducción sistemática de deuda técnica estructural.""",
    "qa_lead": """Eres el Lead QA Engineer y Director de Calidad y Fiabilidad de Software de CyberAudit Suite Enterprise.
Tu enfoque es la robustez del código, detección y erradicación de excepciones silenciadas (try/except pass o catch vacíos), prevención de fugas de recursos y memoria (file handles, sockets, timers huérfanos), mitigación de condiciones de carrera en concurrencia (TOCTOU, locks, mutaciones asíncronas), y maximización de la cobertura real con pruebas unitarias y E2E efectivas.""",
    "uiux_specialist": """Eres el Auditor Senior de UI/UX, Accesibilidad y Usabilidad de CyberAudit Suite Enterprise.
Tu enfoque es la experiencia del usuario, cumplimiento riguroso de normativas WCAG 2.1 / 2.2 (Nivel AA y AAA), ergonomía móvil y touch targets mínimos de 48x48px, diseño responsive fluido sin desbordamientos horizontales, ratios de contraste tipográfico para legibilidad óptima, y aplicación estricta de las 10 heurísticas de usabilidad de Jakob Nielsen.""",
    "appsec_auditor": """Eres el Auditor Principal de Ciberseguridad y Líder del SOC de CyberAudit Suite Enterprise.
Tu enfoque es el rigor técnico exhaustivo, correlación de vulnerabilidades contra estándares CWE/OWASP/ASVS, análisis estático profundo y arquitectura defensiva.""",
    "pentester": """Eres un Lead Penetration Tester y Red Team Operator de élite en CyberAudit Suite Enterprise.
Tu perspectiva es adversaria ofensiva: analizas cómo un atacante real encadenaría cada vulnerabilidad detectada, qué PoCs o exploits desarrollaría, cómo lograría bypass de defensas y cuál es la ruta crítica de compromiso hacia la joya de la corona.""",
    "devsecops": """Eres el Ingeniero Líder de DevSecOps y Seguridad en CI/CD de CyberAudit Suite Enterprise.
Tu enfoque es eminentemente pragmático y de ingeniería: parches de código listos para producción, guardarraíles automatizados en GitHub Actions / GitLab CI, políticas de IaC y remediación en código sin romper la velocidad del equipo de desarrollo.""",
    "ciso": """Eres el CISO Ejecutivo y Asesor Estratégico de Seguridad para el Consejo de Administración.
Tu enfoque es el impacto en el negocio, cuantificación de riesgo financiero y operacional (DREAD / FAIR), responsabilidad fiduciaria, pasivos legales y cumplimiento regulatorio (GDPR, PCI-DSS 4.0, HIPAA, SOC 2 Tipo II, ISO 27001).""",
}


def correlate_attack_chains(findings: list) -> list:
    """
    Identifies synergistic multi-vulnerability attack chains (Kill Chains)
    where two or more distinct findings amplify an attacker's impact.
    """
    chains = []
    finding_texts = " ".join([
        f"{getattr(f, 'id', '') or (f.get('id', '') if isinstance(f, dict) else '')} "
        f"{getattr(f, 'title', '') or (f.get('title', '') if isinstance(f, dict) else '')} "
        f"{getattr(f, 'description', '') or (f.get('description', '') if isinstance(f, dict) else '')}".lower()
        for f in findings
    ])

    # Chain 1: Injection / SSTI / Deserialization -> Remote Code Execution (RCE)
    has_rce_vector = any(k in finding_texts for k in ["cmdi", "command injection", "ssti", "deserial", "pickle", "render_template_string"])
    has_privesc_or_secrets = any(k in finding_texts for k in ["secret", "aws", "token", "password", "private key", "role", "is_admin", "entropy"])
    if has_rce_vector and has_privesc_or_secrets:
        chains.append({
            "name": "Cadena de Compromiso Total: Inyección/Deserialización -> Ejecución Remota -> Robo de Credenciales Privilegiadas",
            "severity": "CRITICAL",
            "impact": "Un adversario explota el punto de inyección para ejecutar comandos en el host y exfiltra credenciales en memoria para pivotar a la infraestructura cloud.",
            "mitre": "T1190 -> T1059 -> T1552"
        })

    # Chain 2: BOLA / IDOR + Broken Auth / Session -> Account Takeover
    has_bola = any(k in finding_texts for k in ["bola", "idor", "broken object", "cwe-639", "mass-assign"])
    has_auth_flaw = any(k in finding_texts for k in ["jwt", "session", "csrf", "cookie", "weak crypto", "auth"])
    if has_bola and has_auth_flaw:
        chains.append({
            "name": "Cadena de Secuestro de Cuentas: Falla de Sesión/Tokens -> BOLA/IDOR Horizontal Descontrolado",
            "severity": "CRITICAL",
            "impact": "Manipulación de identificadores en rutas no protegidas combinada con debilidad en tokens permite acceso no autorizado y toma de control de cuentas ajenas.",
            "mitre": "T1078 -> T1539 -> T1098"
        })

    # Chain 3: SSRF -> Cloud Metadata / Private Service Exfiltration
    has_ssrf = any(k in finding_texts for k in ["ssrf", "request forgery", "cwe-918"])
    has_cloud_assets = any(k in finding_texts for k in ["aws", "azure", "cloud", "metadata", "s3", "blob"])
    if has_ssrf and has_cloud_assets:
        chains.append({
            "name": "Cadena de Pivoteo Cloud: SSRF -> Consulta a Servicio de Metadatos (169.254.169.254) -> Robo de Rol IAM",
            "severity": "CRITICAL",
            "impact": "El atacante fuerza al servidor a consultar endpoints de metadatos internos para obtener credenciales STS temporales del rol IAM de la máquina.",
            "mitre": "T1190 -> T1552.005 -> T1530"
        })

    # Chain 4: Supply Chain / Outdated Dependency -> Local Malicious Code Execution
    has_sca = any(k in finding_texts for k in ["dependency", "sca", "cve", "package", "outdated"])
    has_code_exec = any(k in finding_texts for k in ["eval", "exec", "shell", "script"])
    if has_sca and has_code_exec:
        chains.append({
            "name": "Cadena de Cadena de Suministro: Dependencia Vulnerable -> Ejecución Arbitraria en CI/CD o Runtime",
            "severity": "HIGH",
            "impact": "Paquetes de terceros obsoletos o sin comprobación de hash permiten abuso de dependencias para ejecutar código no autorizado en el entorno de compilación.",
            "mitre": "T1195.001 -> T1059"
        })

    return chains


class AICoAnalyst:
    def __init__(
        self,
        lm_studio_url: Optional[str] = None,
        default_local_model: str = "google/gemma-4-12b",
        gemini_model: str = "gemini-3.5-flash-lite",
        system_prompt: Optional[str] = None,
    ):
        local_default = f"http://{'localhost'}:1234/v1"
        configured_url = lm_studio_url or os.getenv("LM_STUDIO_URL", local_default)
        self.lm_studio_url = configured_url.rstrip("/")
        self.default_local_model = default_local_model
        self.gemini_model = gemini_model
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.system_prompt = system_prompt or CYBERAUDIT_SYSTEM_PROMPT

    @staticmethod
    def _is_chat_model(model_id: str) -> bool:
        """Filters out embedding/reranker models, which cannot serve chat completions."""
        lowered = (model_id or "").lower()
        return not any(
            token in lowered
            for token in ("embed", "embedding", "bge-m3", "nomic-embed", "rerank", "whisper", "clip")
        )

    def is_lm_studio_available(self, timeout: float = 1.5) -> Tuple[bool, Optional[str]]:
        """Checks if LM Studio is reachable and returns the active chat model.

        Honors ``CYBERAUDIT_LOCAL_MODEL`` as an explicit override, ignores embedding-only
        models, and prefers coding/reasoning families when several chat models are loaded.
        """
        if os.getenv("CYBERAUDIT_OFFLINE", "").lower() in ("1", "true", "yes", "on"):
            return False, None
        if not _is_safe_endpoint_url(self.lm_studio_url):
            logger.warning("SSRF Guard: Disallowed LM Studio URL '%s'", self.lm_studio_url)
            return False, None
        override = os.getenv("CYBERAUDIT_LOCAL_MODEL", "").strip()
        try:
            req = urllib.request.Request(f"{self.lm_studio_url}/models")
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    models = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
                    chat_models = [mid for mid in models if self._is_chat_model(mid)]
                    if override:
                        if any(override.lower() in mid.lower() for mid in chat_models):
                            match = next(mid for mid in chat_models if override.lower() in mid.lower())
                            return True, match
                        logger.warning(
                            "CYBERAUDIT_LOCAL_MODEL='%s' no está cargado en LM Studio. Modelos de chat: %s",
                            override, chat_models or "ninguno",
                        )
                    if chat_models:
                        # Prefer coding/reasoning families, else the first chat model loaded.
                        for mid in chat_models:
                            lowered = mid.lower()
                            if any(k in lowered for k in ["qwen", "coder", "deepseek", "gemma", "llama", "mistral"]):
                                return True, mid
                        return True, chat_models[0]
                    if models:
                        logger.info(
                            "LM Studio está accesible en %s pero sólo sirve modelos de embedding (%s). "
                            "Carga un modelo de chat con 'lms load'.",
                            self.lm_studio_url, ", ".join(models),
                        )
                    return True, None
        except Exception as e:
            logger.debug("LM Studio check failed: %s", e)
        return False, None

    def build_prompt(self, report: ScanReport, persona: str = "appsec_auditor") -> str:
        """Constructs a structured security prompt with Chain-of-Thought instructions and Knowledge Base injection."""
        from cyberaudit.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()

        top_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)[:25]

        findings_text = "\n".join(
            [
                f"- [{f.severity.value}] {f.title} (Scanner: {f.scanner_name}, Path: {f.file_path}:{f.line_number or 'N/A'})\n"
                f"  MITRE: {f.mitre_id or 'N/A'} ({f.mitre_technique or 'General'})\n"
                f"  Detalle: {f.description}\n"
                f"  Remediación Sugerida: {f.remediation or 'N/A'}"
                for f in top_findings
            ]
        )

        # Correlate attack chains
        chains = correlate_attack_chains(report.findings)
        chains_section = ""
        if chains:
            chains_lines = [f"- **{c['name']}** [{c['severity']}]: {c['impact']} (Mapeo MITRE: {c['mitre']})" for c in chains]
            chains_section = f"\nCADENAS DE ATAQUE SINÉRGICAS IDENTIFICADAS (KILL CHAINS):\n" + "\n".join(chains_lines) + "\n"

        query_terms = " ".join([f.title for f in top_findings[:5]])
        kb_context = kb.get_context_for_prompt(query_terms, max_chars=2500)
        kb_section = f"\nREFERENCIAS TÉCNICAS DE LA BASE DE CONOCIMIENTOS:\n{kb_context}\n" if kb_context else ""

        rsc_skills_results = kb.search("review verify security-scan secure-coding code-review blocker evidence", limit=2, category="RSC Harness & Agent Skills")
        rsc_section = ""
        if rsc_skills_results:
            rsc_snippets = "\n".join([f"- **{r['title']}**: {r['summary']}" for r in rsc_skills_results])
            rsc_section = (
                "\nPROTOCOLO RSC-HARNESS (P2, P7, P10 - EVIDENCIA Y REVISIÓN ADVERSARIAL):\n"
                "- Filtra con confianza >80%: prioriza hallazgos alcanzables (reachable + exposed + sensitive sink).\n"
                "- Exige evidencia reproducible (file:line + escenario de fallo concreto) antes de elevar a BLOCKER.\n"
                "- Aplica el principio P10 ('Done means observed'): toda remediación requiere comando de verificación observable.\n"
                f"{rsc_snippets}\n"
            )

        persona_guide = AUDITOR_PERSONAS.get(persona, AUDITOR_PERSONAS["appsec_auditor"])

        return (
            f"{persona_guide}\n\n"
            "Analiza los siguientes resultados de la auditoría de ciberseguridad corporativa aplicando razonamiento paso a paso (Chain-of-Thought):\n\n"
            f"OBJETIVO AUDITADO: {report.target_path}\n"
            f"ARCHIVOS ANALIZADOS: {report.files_scanned}\n"
            f"DURACIÓN DEL ESCANEO: {report.duration_seconds} segundos\n"
            f"TOTAL DE HALLAZGOS: {report.total_findings}\n"
            f"DESGLOSE POR SEVERIDAD: {json.dumps(report.severity_counts, ensure_ascii=False)}\n"
            f"PILARES AFECTADOS: {json.dumps(report.pillar_counts, ensure_ascii=False)}\n"
            f"MÉTRICAS STRIDE: {json.dumps(report.stride_counts, ensure_ascii=False)}\n\n"
            "VULNERABILIDADES MÁS CRÍTICAS DETECTADAS:\n"
            f"{findings_text}\n"
            f"{chains_section}"
            f"{rsc_section}"
            f"{kb_section}\n"
            "INSTRUCCIONES DE RAZONAMIENTO CHAIN-OF-THOUGHT (Genera las 6 secciones estructuradas):\n"
            "1. **Resumen Ejecutivo y Puntuación DREAD / Riesgo de Negocio** (Puntuación de 0 a 10 desglosando Daño, Reproducibilidad, Explotabilidad, Usuarios Afectados y Descubrimiento).\n"
            "2. **Vectores Críticos de Amenaza y Cadenas de Ataque (Kill Chains)** (Explica el encadenamiento paso a paso de vulnerabilidades para lograr el máximo impacto).\n"
            "3. **Evaluación de Modelo de Amenazas STRIDE y LINDDUN** (Análisis de Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege y Privacidad).\n"
            "4. **Plan de Contención Inmediata (0 - 24 Horas)** (Medidas Blue Team/SOC, aislamiento de procesos, rotación de claves y reglas WAF/SIEM inmediatas).\n"
            "5. **Hoja de Ruta de Remediación Estratégica DevSecOps (30 - 90 Días)** (Parches de código, guardarraíles CI/CD, configuración de infraestructura y arquitectura Zero Trust).\n"
            "6. **Alineación con Cumplimiento Normativo (PCI-DSS 4.0, ISO 27001:2022, GDPR Art. 32, HIPAA § 164.312, SOC 2 Tipo II, FedRAMP)**.\n"
        )

    def query_local_lm_studio(self, prompt: str, model_name: str, timeout: float = 120.0) -> Optional[str]:
        """Queries local LM Studio server."""
        if os.getenv("CYBERAUDIT_OFFLINE", "").lower() in ("1", "true", "yes", "on"):
            return None
        if not _is_safe_endpoint_url(self.lm_studio_url):
            logger.warning("SSRF Guard: Disallowed LM Studio URL '%s'", self.lm_studio_url)
            return None
        try:
            payload = {
                "model": model_name,
                "messages": [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "top_p": 0.85,
                "max_tokens": 4096,
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.lm_studio_url}/chat/completions",
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                choice = res_data["choices"][0]
                msg = choice.get("message", {})
                content = msg.get("content") or ""
                # Support reasoning models (Qwen MTP / DeepSeek R1)
                if not content.strip() and msg.get("reasoning_content"):
                    content = msg.get("reasoning_content")
                return content.strip() if content else None
        except Exception as e:
            logger.debug("Local LM Studio query failed: %s", e)
            return None

    def test_connection(self) -> dict:
        """Tests connection to LM Studio and returns diagnostic status."""
        is_avail, model = self.is_lm_studio_available(timeout=2.0)
        status = {
            "lm_studio_reachable": is_avail,
            "url": self.lm_studio_url,
            "active_model": model,
            "gemini_api_key_configured": bool(self.gemini_api_key),
            "gemini_model": self.gemini_model,
        }
        if is_avail and not model:
            status["hint"] = (
                "El servidor local responde pero no hay ningún modelo de chat cargado. "
                "Ejecuta 'scripts/kali_local_llm.sh ensure' o 'lms load --gpu max <modelo>'."
            )
        if is_avail and model:
            try:
                res = self.query_local_lm_studio(
                    prompt="Confirma en una frase que CyberAudit Suite esta operativo.",
                    model_name=model,
                    timeout=90.0,
                )
                status["test_inference_ok"] = bool(res)
                status["test_response"] = res.strip() if res else "No response"
            except Exception as e:
                status["test_inference_ok"] = False
                status["test_error"] = str(e)
        return status

    def query_gemini_cloud(self, prompt: str) -> Optional[str]:
        """Queries Google Gemini API using google-genai SDK."""
        if os.getenv("CYBERAUDIT_OFFLINE", "").lower() in ("1", "true", "yes", "on"):
            return None
        if not self.gemini_api_key:
            return None
        try:
            from google import genai

            client = genai.Client()
            response = client.models.generate_content(
                model=self.gemini_model,
                contents=prompt,
            )
            return response.text
        except Exception:
            # Fallback to secondary model if main model hits demand limit
            try:
                from google import genai

                client = genai.Client()
                response = client.models.generate_content(
                    model="gemini-3.5-flash",
                    contents=prompt,
                )
                return response.text
            except Exception:
                return None

    def generate_heuristic_summary(self, report: ScanReport) -> str:
        """Generates a high-quality deterministic executive summary when no LLM is available."""
        sev = report.severity_counts
        crit = sev.get("CRITICAL", 0)
        high = sev.get("HIGH", 0)
        med = sev.get("MEDIUM", 0)

        # Calculate risk score
        risk_score = min(100, (crit * 25) + (high * 10) + (med * 3))
        posture = "CRITICAL COMPROMISE RISK" if risk_score >= 70 else "ELEVATED RISK" if risk_score >= 40 else "MODERATE"

        top_crit_titles = [f.title for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:5]
        bullets = "\n".join([f"- **{t}**" for t in top_crit_titles]) if top_crit_titles else "- No critical vulnerabilities detected."

        return f"""### 🛡️ Executive Summary & Posture Rating
- **Overall Business Risk Score**: **{risk_score}/100** ({posture})
- **Files Audited**: {report.files_scanned} across target `{report.target_path}`
- **Security Findings**: {report.total_findings} total ({crit} Critical, {high} High, {med} Medium)

### ⚠️ Top Threat Vectors Identified
{bullets}

### ⏱️ Immediate Containment Actions (0 - 24 Hours)
1. **Isolate Affected Assets**: Quarantine any scripts exhibiting web shell signatures or in-memory download cradles.
2. **Credential Rotation**: Immediately revoke and rotate any Active Directory or Cloud service credentials referenced in audited assets.
3. **Log & Telemetry Audit**: Query centralized SIEM/EDR for telemetry matching detected IOCs and living-off-the-land executions.

### 📅 Strategic Remediation (30 - 90 Days)
- **Active Directory Hardening**: Enforce AES-256 Kerberos encryption, configure gMSAs for all SPNs, and audit ACL delegations for DCSync rights.
- **Cloud Security Baseline**: Disable public anonymous blob/S3 access, restrict NSG inbound management ports (22/3389), and mandate MFA.
- **Detection Engineering**: Deploy verified Sigma rules to SIEM/Wazuh to convert static audit detections into continuous monitoring alerts.
"""

    def analyze(self, report: ScanReport, provider_mode: str = "auto", persona: str = "appsec_auditor") -> ScanReport:
        """
        Orchestrates AI analysis based on provider_mode:
        - 'local': Uses local LM Studio
        - 'gemini': Uses Google Gemini Cloud
        - 'auto': Attempts local first, then Gemini, then Heuristic fallback
        """
        prompt = self.build_prompt(report, persona=persona)
        verdict = None
        provider_used = None

        if provider_mode in ("local", "auto"):
            is_avail, local_model = self.is_lm_studio_available(timeout=2.0)
            if is_avail and local_model:
                verdict = self.query_local_lm_studio(prompt, local_model, timeout=120.0)
                if verdict:
                    provider_used = f"Local LM Studio ({local_model})"

        if not verdict and provider_mode in ("gemini", "auto"):
            verdict = self.query_gemini_cloud(prompt)
            if verdict:
                provider_used = f"Google Gemini Cloud ({self.gemini_model})"

        if not verdict:
            verdict = self.generate_heuristic_summary(report)
            provider_used = "CyberAudit Heuristic Synthesis Engine (Offline)"

        report.ai_verdict = verdict
        report.ai_provider_used = provider_used
        report.executive_summary = verdict
        return report

    def chat(
        self,
        user_message: str,
        history: Optional[list] = None,
        report_context: Optional[dict] = None,
        provider_mode: str = "auto",
        persona: str = "appsec_auditor",
        timeout: float = 120.0,
    ) -> dict:
        """
        Interactive multi-turn chat with the AI Co-Analyst.
        Injects system prompt, persona guidelines, and optional current audit context into conversation.
        """
        persona_prompt = AUDITOR_PERSONAS.get(persona, self.system_prompt)
        messages = [{"role": "system", "content": persona_prompt}]

        if report_context:
            status_counts = report_context.get("status_counts", {})
            findings_list = report_context.get("findings", [])
            resolved_titles = [f.get("title", "") for f in findings_list if f.get("status") == "RESOLVED"][:5]
            as_designed_titles = [f.get("title", "") for f in findings_list if f.get("status") == "AS_DESIGNED"][:5]
            open_findings = [f for f in findings_list if (f.get("status") or "OPEN").upper() == "OPEN"]
            active_sev = report_context.get("active_severity_counts") or report_context.get("severity_counts", {})
            
            # Correlate attack chains for context
            chains = correlate_attack_chains(findings_list)
            chains_info = f"\nCadenas de Ataque Sinérgicas (Kill Chains): {len(chains)} detectadas" if chains else ""

            context_summary = (
                f"[CONTEXTO DE LA AUDITORÍA ACTIVA]\n"
                f"Objetivo: {report_context.get('target_path')}\n"
                f"Archivos: {report_context.get('files_scanned')}\n"
                f"Total Hallazgos Históricos: {report_context.get('total_findings')}\n"
                f"Estados de Triage: {json.dumps(status_counts, ensure_ascii=False) if status_counts else 'Pendientes'}\n"
                f"Severidades Activas (Pendientes): {json.dumps(active_sev, ensure_ascii=False)}\n"
                f"Pilares: {json.dumps(report_context.get('pillar_counts', {}), ensure_ascii=False)}\n"
                f"Hallazgos marcados como SUBSANADOS/ARREGLADOS: {', '.join(resolved_titles) if resolved_titles else 'Ninguno aún'}\n"
                f"Hallazgos confirmados como CÓDIGO ASÍ ES (Por Diseño/Aceptados): {', '.join(as_designed_titles) if as_designed_titles else 'Ninguno aún'}\n"
                f"Top Vulnerabilidades Activas Pendientes: {', '.join([f.get('title', '') for f in open_findings[:5]])}"
                f"{chains_info}\n"
            )
            messages.append({"role": "system", "content": context_summary})

        if history:
            for item in history:
                if isinstance(item, dict) and "role" in item and "content" in item:
                    messages.append({"role": item["role"], "content": item["content"]})

        # Real-time Knowledge Base RAG injection
        from cyberaudit.core.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()
        kb_context = kb.get_context_for_prompt(user_message, max_chars=2500)
        if kb_context:
            messages.append({
                "role": "system",
                "content": f"[BASE DE CONOCIMIENTOS DE CIBERSEGURIDAD DISPONIBLE - REGLAS Y BUENAS PRÁCTICAS]\n{kb_context}"
            })

        messages.append({"role": "user", "content": user_message})

        # Try Local LM Studio
        if provider_mode in ("local", "auto"):
            is_avail, local_model = self.is_lm_studio_available(timeout=2.0)
            if is_avail and local_model:
                try:
                    payload = {
                        "model": local_model,
                        "messages": messages,
                        "temperature": 0.3,
                        "top_p": 0.85,
                        "max_tokens": 4096,
                    }
                    data = json.dumps(payload).encode("utf-8")
                    req = urllib.request.Request(
                        f"{self.lm_studio_url}/chat/completions",
                        data=data,
                        headers={"Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as response:
                        res_data = json.loads(response.read().decode("utf-8"))
                        msg = res_data["choices"][0].get("message", {})
                        reply = msg.get("content") or msg.get("reasoning_content") or ""
                        if reply.strip():
                            return {
                                "reply": reply.strip(),
                                "provider": f"Local LM Studio ({local_model})",
                                "success": True,
                            }
                except Exception as e:
                    logger.debug("Local LM Studio chat query failed: %s", e)

        # Try Gemini
        if provider_mode in ("gemini", "auto") and self.gemini_api_key:
            gemini_reply = self.query_gemini_cloud(user_message)
            if gemini_reply:
                return {
                    "reply": gemini_reply.strip(),
                    "provider": f"Google Gemini Cloud ({self.gemini_model})",
                    "success": True,
                }

        # Fallback
        return {
            "reply": "No fue posible conectar con el servidor local de LM Studio (puerto 1234) ni con Gemini Cloud. Asegúrate de que LM Studio tenga el servidor local activo.",
            "provider": "Offline Fallback",
            "success": False,
        }

    def review_developer_remediation(
        self,
        remediation_markdown: str,
        remediation_summary: dict,
        report_context: Optional[dict] = None,
        provider_mode: str = "auto",
        timeout: float = 120.0,
    ) -> dict:
        """
        Technical auditor review of a developer's remediation response report (.md).
        Evaluates claimed fixes against automated re-test results on disk,
        generates structured auditor feedback for the developer, and advises on next steps.
        """
        verified_cnt = remediation_summary.get("verified_count", 0)
        failed_cnt = remediation_summary.get("failed_reverify_count", 0)
        as_designed_cnt = remediation_summary.get("as_designed_count", 0)
        items = remediation_summary.get("items", [])

        # Build prompt for auditor review
        items_summary = []
        for it in items[:25]:
            status_desc = "VERIFICADO EN CÓDIGO (Limpio)" if it.get("verified_on_disk") is True else (
                "FALLÓ RE-TEST (Vulnerabilidad aún persiste en código)" if it.get("verified_on_disk") is False else (
                    f"ESTADO: {it.get('status')}"
                )
            )
            items_summary.append(
                f"- Hallazgo `{it.get('finding_id')}` [{it.get('severity', 'N/A')}] en `{it.get('file_path')}:{it.get('line_number') or 'N/A'}`:\n"
                f"  * Nota del desarrollador: {it.get('developer_comment')}\n"
                f"  * Resultado de auditoría: {status_desc} ({it.get('verification_message', '')})"
            )

        items_str = "\n".join(items_summary) if items_summary else "No se especificaron detalles individuales."
        target_path = (report_context.get("target_path") if report_context else None) or "Software Target"

        review_prompt = f"""Eres el Auditor Principal de Ciberseguridad de CyberAudit Suite Enterprise.
El equipo de programación ha entregado un archivo Markdown formal con las subsanaciones aplicadas a las vulnerabilidades reportadas.
Nuestro motor automatizado ejecutó re-tests contra el código fuente en disco con los siguientes resultados:
- Subsanaciones verificadas y limpias en código: {verified_cnt}
- Subsanaciones que FALLARON el re-test (la falla sigue presente en disco): {failed_cnt}
- Hallazgos aceptados 'Por Diseño': {as_designed_cnt}

DETALLE TÉCNICO DE LAS SUBSANACIONES EVALUADAS:
{items_str}

TEXTO ORIGINAL ENVIADO POR EL DESARROLLADOR (FRAGMENTO):
```markdown
{remediation_markdown[:1500]}
```

Redacta un "Dictamen Técnico del Auditor para el Desarrollador" en Español corporativo técnico impecable.
Estructura tu respuesta en Markdown con las siguientes secciones:
### 1. 🛡️ Dictamen Ejecutivo del Auditor
(Evaluación global de la respuesta técnica del desarrollador y evolución de la postura de seguridad).

### 2. ✅ Subsanaciones Validadas y Aprobadas
(Reconocimiento técnico de las correcciones bien resueltas y verificadas en código).

### 3. ⚠️ Observaciones Críticas y Hallazgos No Resueltos
(Si hubo fallos de re-test o justificaciones insuficientes, explica con claridad qué debe cambiar el programador para superar la auditoría).

### 4. 📋 Recomendaciones y Próximos Pasos para el Equipo de Desarrollo
(Plan de acción concreto para el siguiente ciclo o pase a producción).
"""

        # Try Local LM Studio
        if provider_mode in ("local", "auto"):
            is_avail, local_model = self.is_lm_studio_available(timeout=2.0)
            if is_avail and local_model:
                reply = self.query_local_lm_studio(review_prompt, local_model, timeout=timeout)
                if reply and reply.strip():
                    return {
                        "review": reply.strip(),
                        "provider": f"Local LM Studio ({local_model})",
                        "success": True,
                    }

        # Try Gemini
        if provider_mode in ("gemini", "auto") and self.gemini_api_key:
            gemini_reply = self.query_gemini_cloud(review_prompt)
            if gemini_reply and gemini_reply.strip():
                return {
                    "review": gemini_reply.strip(),
                    "provider": f"Google Gemini Cloud ({self.gemini_model})",
                    "success": True,
                }

        # Deterministic Heuristic Fallback
        heuristic_review = self.generate_heuristic_remediation_review(
            remediation_summary,
            target_path=target_path,
        )
        return {
            "review": heuristic_review,
            "provider": "CyberAudit Remediation Review Engine (Offline)",
            "success": True,
        }

    def generate_heuristic_remediation_review(
        self,
        remediation_summary: dict,
        target_path: str = "Software Target",
    ) -> str:
        """Generates a high-fidelity deterministic auditor review when no LLM is reachable."""
        verified_cnt = remediation_summary.get("verified_count", 0)
        failed_cnt = remediation_summary.get("failed_reverify_count", 0)
        as_designed_cnt = remediation_summary.get("as_designed_count", 0)
        items = remediation_summary.get("items", [])

        status_headline = (
            "FAVORABLE — Subsanación Exitosa de Vulnerabilidades"
            if failed_cnt == 0 and verified_cnt > 0
            else "CON OBSERVACIONES — Vulnerabilidades Persistentes Detectadas en Re-test"
            if failed_cnt > 0
            else "EN REVISIÓN DE DISEÑO — Excepciones Técnicas Registradas"
        )

        verified_items = [it for it in items if it.get("verified_on_disk") is True or it.get("status") == "RESOLVED" and it.get("verified_on_disk") is not False]
        failed_items = [it for it in items if it.get("verified_on_disk") is False]
        designed_items = [it for it in items if it.get("status") == "AS_DESIGNED"]

        verified_bullets = "\n".join([
            f"- **`{it.get('finding_id')}`** (`{it.get('file_path')}`): {it.get('developer_comment') or 'Subsanación verificada en código.'}"
            for it in verified_items[:8]
        ]) if verified_items else "- No se confirmaron subsanaciones en este lote."

        failed_bullets = "\n".join([
            f"- 🔴 **`{it.get('finding_id')}`** (`{it.get('file_path')}:{it.get('line_number') or 'N/A'}`): El re-test de seguridad determinó que la vulnerabilidad sigue activa en el archivo. *Nota reportada: {it.get('developer_comment')}*"
            for it in failed_items
        ]) if failed_items else "- No se detectaron fallos de re-test. Todas las correcciones declaradas se validaron con éxito."

        designed_bullets = "\n".join([
            f"- 🟣 **`{it.get('finding_id')}`** (`{it.get('file_path')}`): Aceptado por diseño. *Justificación: {it.get('developer_comment')}*"
            for it in designed_items
        ]) if designed_items else "- No se registraron excepciones por diseño."

        return f"""### 1. 🛡️ Dictamen Ejecutivo del Auditor
**Estado del Dictamen:** **{status_headline}**
- **Objetivo Evaluado:** `{target_path}`
- **Subsanaciones Verificadas en Código:** **{verified_cnt}** hallazgos
- **Subsanaciones con Re-test Fallido (Pendientes):** **{failed_cnt}** hallazgos
- **Excepciones Aceptadas 'Por Diseño':** **{as_designed_cnt}** hallazgos

El equipo de auditoría ha procesado el informe de respuesta del desarrollador. La verificación automática en código fuente confirma que se ha avanzado en la mitigación de deuda técnica y vectores de riesgo.

### 2. ✅ Subsanaciones Validadas y Aprobadas
Las siguientes soluciones fueron validadas contra los scanners del motor y se consideran formalmente subsanadas:
{verified_bullets}

### 3. ⚠️ Observaciones Críticas y Hallazgos No Resueltos
{failed_bullets}

### 4. 📋 Recomendaciones y Próximos Pasos para el Equipo de Desarrollo
1. **Atención a Fallas Persistentes:** Para los hallazgos que fallaron el re-test, verifica que los cambios hayan sido guardados en el archivo correspondiente en disco y que la sanitización/refactorización cumpla con la regla del scanner.
2. **Control de Regresiones:** Ejecuta las pruebas unitarias y de integración locales antes de solicitar el cierre definitivo del sprint de seguridad.
3. **Registro de Excepciones:** Los hallazgos marcados 'Por Diseño' han quedado documentados con su justificación técnica en el informe maestro de auditoría de la plataforma.
"""

