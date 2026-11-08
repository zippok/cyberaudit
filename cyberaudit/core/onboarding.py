"""
CyberAudit Core Onboarding Engine
Provides full 1:1 parity with the RSC (Eric Risco) interactive onboarding protocol:
1. Technical register question ("¿Te hablo en lenguaje técnico o con analogías?")
2. Project discovery & scoping
3. Cryptographic Plan ID generation (PLAN-<sha256>)
4. Explicit user acceptance gate (--accept-plan)
5. Scaffolding of 01-TOOLS/, 02-DOCS/, always-on AGENTS.md, and 48 skills
"""

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def compute_plan_id(plan_dict: Dict[str, Any]) -> str:
    """Computes a deterministic cryptographic Plan ID (PLAN-<sha256[:16]>)."""
    canonical_json = json.dumps(plan_dict, sort_keys=True)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()[:16]
    return f"PLAN-{digest}"


def build_always_on_agents_md(tech_level: str = "technical") -> str:
    """Generates the always-on governance layer for AGENTS.md / CLAUDE.md."""
    return f"""<!-- cyberaudit-suggest:start -->

# cyberaudit-suggest — Capa Always-On de Gobernanza y Auditoría Integral

Tu cuerpo se inyecta al inicio de **cada** sesión y tras cada compactación de contexto. Eres la pieza garantizada que gobierna el proyecto bajo la doctrina de CyberAudit y RSC. Tienes dos cometidos esenciales:

1. **Clasificar cada turno del usuario en exactamente uno de los cuatro carriles** antes de escribir código.
2. **Mantener la sesión equipada y segura** — detectar habilidades faltantes, activar refutadores multi-agente y gobernar la auto-reparación TDD.

---

## 1. El Decisor de Carriles (Lane Decisor)

Cada solicitud del usuario entra obligatoriamente en uno de estos 4 carriles. Nombra siempre el carril elegido en tu primera línea de respuesta:

- **Answer (Consulta / Explicación):** Solicitudes de información, comparación, arquitectura o análisis conceptual. Modo estrictamente solo lectura: no escribe archivos ni crea artefactos. Si la intención es ambigua, haz una sola pregunta de clarificación y mantén este carril.
- **FTD (Fast-Track Development):** Trabajo ordinario de alcance acotado y seguro. Un documento de funcionalidad en `02-DOCS/`; tareas marcadas únicamente tras verificar evidencia observada (*observed proof*).
- **ASDD (Agentic Spec-Driven Development):** Tareas complejas con dependencias mutuas, migraciones o lógica de negocio sensible. El usuario aprueba la especificación técnica y las respuestas de clarificación antes de proceder.
- **Audit & Fix (Auditoría Integral & Auto-Reparación TDD):** Escaneo estático en los 8 pilares de ingeniería (AppSec, DevSecOps, Arquitectura, QA, UI/UX, Compliance, AI Safety, Threat Hunting) o auto-reparación defensiva de hallazgos mediante el ciclo TDD: prueba roja (*Red Test*), parche defensivo atómico (*Green Patch*) y verificación estática sin regresiones.

---

## 2. Panel Refutador Multi-Agente (invoke_subagent)

En revisiones de código, auditorías de seguridad o cambios de impacto medio/alto (Tier 1 o Tier 2):
1. **Invoca en paralelo a 3 subagentes de contexto limpio** mediante `invoke_subagent` (con rol 'research' o 'self'):
   - **CyberAudit Security Refuter:** Busca inyecciones (SQLi, CWE-78), bypass de auth, fugas de secretos y fallos OWASP.
   - **CyberAudit Architecture Refuter:** Revisa modularidad, contratos defensivos, límites de capas y migraciones DB.
   - **CyberAudit QA & Resilience Refuter:** Verifica concurrencia, memory leaks, timeouts de red y aserciones tautológicas.
2. Aplica enfoque *blind-first* (evaluación a ciegas) con un umbral de confianza mínimo del **80%**.
3. Emite un dictamen único estructurado bajo el contrato **`where / why / repro / fix`** y certifica con el sello criptográfico `SELLO-CYBERAUDIT-VERIFICADO`.

---

## 3. Contacto Inicial y Memoria

Antes de procesar la primera tarea de una sesión, verifica el espacio de trabajo:
- Si no existe `02-DOCS/wiki/harness/user-profile.md` ni `.cyberaudit/.no-harness`: realiza primero la pregunta de registro (*"¿Te hablo en lenguaje técnico o con analogías?"*).
- La memoria de decisiones del proyecto se registra de forma inmutable en `02-DOCS/wiki/harness/decisions.md`.

---

## 4. Danger Guard (Seguridad Preventiva)

Para usuarios con registro `non-technical` o `mixed`, se activa un guardián previo que bloquea comandos destructivos irreversibles:
- `rm -rf`, `git push --force`, `git reset --hard`, `DROP TABLE`, `TRUNCATE`, `DELETE` sin `WHERE`, `curl | bash`.
- Exige siempre una alternativa segura o confirmación explícita con nombre del recurso.

---

## 5. Orientación (Siempre)

Habla con la voz de `orient`: frases cortas, una idea por frase, al grano. Cierra cada turno con el **bloque-brújula**:
`📍 Dónde estamos · ✅ Qué hicimos · 🧭 Qué decidimos · ➡️ Siguiente paso (terminando en pregunta)`.
**Nunca termines en seco.**

<!-- cyberaudit-suggest:end -->
"""


class OnboardingEngine:
    def __init__(self, target_dir: str = "."):
        self.target_dir = os.path.abspath(target_dir)

    def scan_target(self) -> Dict[str, Any]:
        manifests = ["package.json", "pyproject.toml", "Cargo.toml", "go.mod", "pubspec.yaml", "requirements.txt", "Dockerfile"]
        detected = [m for m in manifests if os.path.isfile(os.path.join(self.target_dir, m))]
        has_git = os.path.isdir(os.path.join(self.target_dir, ".git"))
        return {
            "root": self.target_dir,
            "has_git": has_git,
            "detected_manifests": detected,
            "is_software": bool(detected or has_git),
        }

    def generate_plan(
        self,
        technical_level: str = "technical",
        project_kind: str = "software",
        goal: str = "Auditoría integral de software, seguridad y gobernanza",
        software_scope: str = "growing",
        workflow: str = "main",
        targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if targets is None:
            targets = ["antigravity", "claude", "cursor"]

        evidence = self.scan_target()
        plan_record = {
            "schema_version": 1,
            "technical_level": technical_level,
            "project_kind": project_kind,
            "goal": goal,
            "software_scope": software_scope,
            "workflow": workflow,
            "targets": targets,
            "detected_manifests": evidence["detected_manifests"],
        }
        plan_id = compute_plan_id(plan_record)

        return {
            "plan_id": plan_id,
            "record": plan_record,
            "selected_components": [
                {"id": "harness/control-plane", "desc": "Operational scaffolding 01-TOOLS/_TEMPLATE/ and 02-DOCS/wiki/harness/"},
                {"id": "always-on/cyberaudit-suggest", "desc": "Four-lane decisor (Answer, FTD, ASDD, Audit & Fix) in AGENTS.md"},
                {"id": "refuters/multi-agent-panel", "desc": "Three fresh-context refuters (Security, Architecture, QA)"},
                {"id": "skills/core", "desc": "Foundational RSC skills (init, harness, orient, review, code-review, secure-coding)"},
                {"id": "skills/cyberaudit", "desc": "8-pillar audit suite (cyberaudit-full) and automated TDD repair (cyberaudit-autofix)"},
                {"id": "tools/external-orchestrator", "desc": "Industry standards (npm audit, pip-audit, gitleaks, trivy) with graceful fallback"},
            ],
            "deferred_components": [
                {"id": "ci-cd/strict-gate", "desc": "Blocking GitHub Actions gate (activated on release readiness)"},
            ],
            "excluded_components": [
                {"id": "remote-telemetry", "desc": "100% local operation with zero remote data collection"},
            ],
            "managed_paths": [
                ".cyberaudit.json",
                ".antigravity/AGENTS.md",
                "02-DOCS/wiki/harness/user-profile.md",
                "02-DOCS/wiki/harness/decisions.md",
                "01-TOOLS/_TEMPLATE/",
            ],
        }

    def apply_plan(self, plan: Dict[str, Any], accepted_plan_id: str) -> Tuple[bool, str]:
        if plan["plan_id"] != accepted_plan_id:
            return False, f"Plan ID mismatch. Expected {plan['plan_id']}, got {accepted_plan_id}."

        plan_id = plan["plan_id"]
        record = plan["record"]
        tech_level = record["technical_level"]
        workflow = record["workflow"]

        # 1. Scaffolding directories
        os.makedirs(os.path.join(self.target_dir, ".cyberaudit"), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, "01-TOOLS", "_TEMPLATE"), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, "02-DOCS", "wiki", "harness"), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, ".antigravity", "rsc"), exist_ok=True)

        # 2. Persist metadata
        meta = {
            "version": 2,
            "harness": "cyberaudit",
            "plan_id": plan_id,
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "record": record,
        }
        with open(os.path.join(self.target_dir, ".cyberaudit.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        with open(os.path.join(self.target_dir, ".rsc.json"), "w", encoding="utf-8") as f:
            json.dump({"version": 1, "targets": record["targets"], "skills": ["cyberaudit-full", "cyberaudit-autofix"]}, f, indent=2)

        # 3. User profile & decisions
        user_profile = f"""# User Profile
- **Technical Level:** {tech_level}
- **Project Kind:** {record['project_kind']}
- **Goal:** {record['goal']}
- **Software Scope:** {record['software_scope']}
- **Workflow:** {workflow}
- **Plan ID:** {plan_id}
- **Installed At:** {datetime.now(timezone.utc).isoformat()}
"""
        with open(os.path.join(self.target_dir, "02-DOCS", "wiki", "harness", "user-profile.md"), "w", encoding="utf-8") as f:
            f.write(user_profile)

        decision_log = f"""# Project Decisions Log
## [{datetime.now(timezone.utc).isoformat()}] CyberAudit Onboarding Accepted
- **Plan ID:** {plan_id}
- **Decision:** Installed CyberAudit meta-harness with 68 scanners, 48 skills, and always-on decisor.
- **Technical Register:** {tech_level}
- **Status:** Ratified
"""
        with open(os.path.join(self.target_dir, "02-DOCS", "wiki", "harness", "decisions.md"), "w", encoding="utf-8") as f:
            f.write(decision_log)

        # 4. Ingest always-on AGENTS.md
        always_on = build_always_on_agents_md(tech_level)
        with open(os.path.join(self.target_dir, ".antigravity", "AGENTS.md"), "w", encoding="utf-8") as f:
            f.write(always_on)
        root_agents = os.path.join(self.target_dir, "AGENTS.md")
        if not os.path.exists(root_agents):
            with open(root_agents, "w", encoding="utf-8") as f:
                f.write(always_on)

        # 5. Copy bundled skills
        pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        skills_src = os.path.join(pkg_root, "skills")
        if os.path.isdir(skills_src):
            dst_rsc = os.path.join(self.target_dir, ".antigravity", "rsc")
            for item in os.listdir(skills_src):
                s_item = os.path.join(skills_src, item)
                d_item = os.path.join(dst_rsc, item)
                if os.path.isdir(s_item) and not os.path.exists(d_item):
                    shutil.copytree(s_item, d_item)

        return True, f"CYBERAUDIT_ONBOARDING_READY {plan_id}"
