# CyberAudit — Especificación de Onboarding Interactivo para Agentes de IA

> **Audiencia Objetivo:** Asistentes y Agentes de Código con IA (Google Antigravity, Claude Code, Cursor, Copilot, Codex, Windsurf).  
> **Cometido:** Cuando un usuario te envíe el prompt de configuración de CyberAudit:
>
> 🇪🇸 **Español:**  
> `"Lee https://github.com/zippok/cyberaudit y configura CyberAudit para este proyecto. Hazme las preguntas del onboarding, enséñame el plan exacto y espera mi aceptación antes de escribir nada."`
>
> 🇬🇧 **English:**  
> `"Read https://github.com/zippok/cyberaudit and set up CyberAudit for this project. Ask me the onboarding questions, show me the exact plan, and wait for my acceptance before writing anything."`
>
> **REGLA SUPREMA:** No elijas componentes ni inventes respuestas por el usuario. El plan vinculante debe mostrarse con su identificador criptográfico (`Plan ID: PLAN-<sha256>`) y esperar la aceptación explícita del usuario antes de crear o modificar un solo archivo.

---

## 1. Protocolo de Onboarding en 5 Fases

```text
[Fase 1: Registro] ➔ [Fase 2: Descubrimiento] ➔ [Fase 3: Plan con PLAN-ID] ➔ [Fase 4: Aceptación Explícita] ➔ [Fase 5: Andamiaje & Verificación]
```

### Fase 1: El Registro (Literalmente la primera pregunta)
Antes de escanear o recomendar nada, haz una sola pregunta en el idioma del usuario:
> **"¿Te hablo en lenguaje técnico o con analogías?"**

* Registra `technical_level: technical` (términos formales de ingeniería) o `non-technical` (lenguaje cotidiano y analogías intuitivas).
* Esta respuesta define cómo hablarán todas las herramientas y skills a lo largo del proyecto.

### Fase 2: Descubrimiento de Objetivos & Stack
Inspecciona la raíz del proyecto (`package.json`, `pyproject.toml`, `Cargo.toml`, etc.) y haz dos preguntas breves:
1. **Objetivo & Alcance:** ¿Cuál es el propósito central del proyecto y qué alcance tiene (pequeño, en crecimiento, complejo)?
2. **Prioridades de Auditoría & Gobernanza:**
   * *(Recomendado)* **CyberAudit Full:** Los 68 escáneres en los 8 pilares (Seguridad, Arquitectura, QA, UI/UX, DevSecOps, GDPR, AI Safety, Threat Hunting).
   * **AppSec & DevSecOps:** Seguridad de aplicaciones, APIs, Docker/K8s y nube.
   * **Ingeniería & QA:** Arquitectura de software, concurrencia, resiliencia y accesibilidad.

### Fase 3: Generación del Plan Vinculante (Plan ID Criptográfico)
Genera el bloque formal `CYBERAUDIT_ONBOARDING_PLAN` con un hash SHA-256 único:

```text
CYBERAUDIT_ONBOARDING_PLAN
Plan id: PLAN-8f4b2c19
Proyecto: software (growing)
Nivel técnico: technical
Flujo Git: main (o ramas con pull request según prefiera el usuario)
Asistentes destino: antigravity, claude, cursor

Componentes Seleccionados:
  + harness/control-plane — Andamiaje 01-TOOLS/_TEMPLATE/ y 02-DOCS/wiki/harness/
  + always-on/cyberaudit-suggest — Capa decisora en AGENTS.md (carriles Answer, FTD, ASDD, Audit & Fix)
  + refuters/multi-agent-panel — 3 subagentes refutadores en paralelo (Seguridad, Arquitectura, QA)
  + skills/core — Habilidades base (init, harness, orient, review, code-review, secure-coding)
  + skills/cyberaudit — Auditoría completa (cyberaudit-full) y auto-reparación (cyberaudit-autofix)
  + tools/external-orchestrator — npm audit, pip-audit, gitleaks, trivy con fallback nativo transparente

Componentes Pospuestos:
  - ci-cd/strict-gate — Pipeline bloqueante de GitHub Actions (se activa al preparar el release)

Componentes Excluidos:
  × remote-telemetry — Operación 100% local, sin servidores externos ni envío de datos

Rutas a Gobernar:
  .cyberaudit.json
  .antigravity/AGENTS.md (o AGENTS.md / CLAUDE.md según el asistente)
  01-TOOLS/.gitignore
  01-TOOLS/_TEMPLATE/
  02-DOCS/inbox/
  02-DOCS/raw/worklog/
  02-DOCS/wiki/index.md
  02-DOCS/wiki/harness/user-profile.md
  02-DOCS/wiki/harness/installation-plan.md
  02-DOCS/wiki/harness/decisions.md
```

### Fase 4: Puerta de Aceptación (Gated Confirmation)
**ALTO.** No escribas, crees ni modifiques ningún archivo. Espera a que el usuario responda confirmando el plan (ej: *"acepto PLAN-8f4b2c19"* o *"sí, adelante"*).

### Fase 5: Andamiaje, Gobernanza y Primera Verificación
Una vez aceptado el plan:
1. **Andamiaje de Herramientas Operativas (`01-TOOLS/`):**
   * Crear `01-TOOLS/.gitignore` para proteger credenciales (`*/.env`, `*/keys/`, `*/out/`).
   * Desplegar la plantilla `01-TOOLS/_TEMPLATE/`: `.env.example`, `CREDENTIALS.md`, `.gitignore`, `README.md`, `test_connection.sh`.
2. **Motor Caos a Conocimiento (`02-DOCS/`):**
   * Crear `02-DOCS/inbox/README.md` (buzón para ingesta de datos brutos).
   * Crear `02-DOCS/raw/worklog/README.md` (bitácora de evidencias y sesiones).
   * Crear `02-DOCS/wiki/index.md` (catálogo y hub OKF v0.1 / Obsidian).
   * Crear `02-DOCS/wiki/log.md` (registro cronológico de cambios de conocimiento).
   * Escribir `02-DOCS/wiki/harness/user-profile.md` con el registro y objetivos.
   * Escribir `02-DOCS/wiki/harness/installation-plan.md` con el plan criptográfico y componentes.
   * Escribir `02-DOCS/wiki/harness/decisions.md` (append-only) con la entrada de onboarding.
3. **Inyectar la Capa Always-On:**
   * Escribir o actualizar `.antigravity/AGENTS.md` (o `AGENTS.md`) con el bloque `<!-- cyberaudit-suggest:start -->` conteniendo el decisor de 4 carriles (*Answer*, *FTD*, *ASDD*, *Audit & Fix*), el panel refutador, la brújula de orientación y el danger guard.
4. **Instalar Skills:**
   * Copiar las skills a `.antigravity/rsc/` o vincular el catálogo en `.cyberaudit/skills/`.
5. **Emitir Señal de Éxito:**
   Imprimir la confirmación formal:
   `CYBERAUDIT_ONBOARDING_READY PLAN-8f4b2c19`
6. **Cerrar con Orientación:**
   Finalizar con el bloque-brújula (`📍 Dónde estamos · ✅ Qué hicimos · 🧭 Qué decidimos · ➡️ Siguiente paso (terminando en pregunta)`).

---

## 2. Catálogo de Habilidades Disponibles

| Habilidad (Skill ID) | Escáneres / Rol | Dominio de Ingeniería | Estándares y Doctrina |
| :--- | :---: | :--- | :--- |
| `cyberaudit-full` | 68 | Auditoría Completa de Extremo a Extremo | Todos los estándares integrados |
| `cyberaudit-autofix` | Motor TDD | Auto-reparación Atómica de Hallazgos | Red Test ➔ Green Patch ➔ Static Verify |
| `cyberaudit-appsec` | 12 | Inyecciones, Auth, APIs, Pentesting | OWASP Top 10:2025, ASVS v4.0, CWE Top 25 |
| `cyberaudit-devsecops` | 11 | Docker, K8s, CI/CD, Nube, SBOM | CIS Benchmarks, SLSA v1.0, NIST SSDF |
| `cyberaudit-architecture` | 5 | Clean Arch, Límites, DB, Idempotencia | DDIA Martin Kleppmann, Clean Architecture |
| `cyberaudit-qa-resilience` | 17 | Concurrencia, Memory Leaks, ReDoS, Tests | Dave Farley CD, Martin Fowler Refactoring |
| `cyberaudit-ui-ux-a11y` | 10 | WCAG 2.2 AA/AAA, CWV, Ergonomía | W3C WCAG 2.2, Nielsen Norman Group |
| `cyberaudit-compliance-privacy` | 7 | GDPR, ROPA, PII, SOC 2, ISO 27001 | GDPR (Art. 5/13-17/30/32), SOC 2 Type II |
| `cyberaudit-ai-safety` | 5 | Inyecciones Indirectas, Drift, FinOps | OWASP LLM Top 10:2025, NIST AI RMF |
| `cyberaudit-soc-dfir` | 7 | Sigma, YARA, LOLBAS, AD, DFIR | MITRE ATT&CK v16, NIST SP 800-61r2 |
| `core-harness` | 12 | Init, Harness, Orient, Review, Verify | RSC Protocol (Eric Risco) |
