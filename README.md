# CyberAudit 🛡️
### The Definitive Full-Spectrum Software Auditor & RSC Skill Harness

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![Scanners](https://img.shields.io/badge/scanners-68%20definitive-emerald.svg)](#the-68-scanner-catalog)
[![Standard](https://img.shields.io/badge/SARIF-2.1.0%20OASIS-orange.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![RSC Compatible](https://img.shields.io/badge/RSC-100%25%20Skill%20Harness-purple.svg)](ONBOARDING.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CyberAudit es la suite definitiva de auditoría estática, ciberseguridad, arquitectura de software, calidad (QA), resiliencia de datos, accesibilidad UI/UX y cumplimiento normativo. 

Combina **68 escáneres estáticos de alto rendimiento** (analiza cientos de archivos en milisegundos) con un **harness de 9 skills para Agentes de IA** compatibles con la doctrina RSC, permitiendo auditar y reparar automáticamente vulnerabilidades mediante TDD asistido por IA.

---

## ⚡ Agent-Driven Onboarding (Instalación con 1 solo Prompt)

Si utilizas un asistente de IA en tu editor (**Google Antigravity, Claude Code, Cursor, Copilot o Windsurf**), no necesitas ejecutar comandos manuales. Solo abre el chat de tu agente en cualquier proyecto y escribe:

> 💬 **Prompt de Instalación en Español (copiar y pegar en el chat de tu agente):**  
> *"Lee https://github.com/zippok/cyberaudit y configura CyberAudit para este proyecto. Hazme las preguntas del onboarding, enséñame el plan exacto y espera mi aceptación antes de escribir nada."*

> 💬 **English Alternative:**  
> *"Read https://github.com/zippok/cyberaudit and set up CyberAudit for this project. Ask me the onboarding questions, show me the exact plan, and wait for my acceptance before writing anything."*

El agente leerá las directivas de [`ONBOARDING.md`](ONBOARDING.md), detectará el stack de tu proyecto, te hará tres preguntas rápidas, te mostrará el plan y dejará todo configurado.

---

## 🚀 Instalación Rápida por Terminal

```bash
# Modo editable local:
pip install -e .

# O instalación directa desde GitHub:
pip install git+https://github.com/zippok/cyberaudit.git
```

Una vez instalado, el comando `cyberaudit` queda disponible globalmente en tu terminal.

---

## 🛠️ Comandos Principales de la CLI

```bash
# 1. Listar las 9 skills especializadas y sus estándares
cyberaudit harness list-skills

# 2. Auditar un proyecto completo con los 68 escáneres
cyberaudit harness run-skill cyberaudit-full /ruta/a/tu/proyecto

# 3. Auditar solo Seguridad de Aplicaciones (AppSec & Pentesting)
cyberaudit harness run-skill cyberaudit-appsec /ruta/a/tu/proyecto --threshold HIGH

# 4. Evaluar el nivel de riesgo y carril de cambios (Tier 0 / 1 / 2 / 3)
cyberaudit harness risk /ruta/a/tu/proyecto

# 5. Emitir un Sello Criptográfico de Verificación Inmutable
cyberaudit harness sello /ruta/a/tu/proyecto --skill cyberaudit-full
# Salida: SELLO-CYBERAUDIT-VERIFICADO: b7a8dd2414ea2810
```

---

## 📦 Catálogo de las 9 Skills y 68 Escáneres

| Skill ID | Escáneres | Área de Enfoque | Estándares & Fundamentos |
| :--- | :---: | :--- | :--- |
| **`cyberaudit-appsec`** | 12 | Inyecciones (SQLi/XSS/Command), Auth, JWT, SSRF, Deserialización, APIs REST/GraphQL/gRPC | OWASP Top 10:2025, OWASP API Top 10, Tanya Janca AppSec |
| **`cyberaudit-devsecops`**| 11 | AWS, GCP, Azure, Terraform, Docker sin root, Kubernetes, Cadena de Suministro (SCA) | CIS Benchmarks, SLSA v1.0, NIST SP 800-190 |
| **`cyberaudit-soc-dfir`** | 7 | Caza de amenazas, reglas Sigma/YARA, Active Directory, LOLBAS y triaje forense | MITRE ATT&CK v16, NIST SP 800-61r2 |
| **`cyberaudit-ai-safety`**| 5 | Inyección de prompts indirecta, FinOps (Denial of Wallet), límites de tokens, RAG hygiene | OWASP Top 10 for LLMs 2025, Chip Huyen AI Engineering |
| **`cyberaudit-architecture`** | 5 | Migraciones DB zero-downtime, N+1 ORM, idempotencia en pagos, ciclos circulares | Martin Kleppmann DDIA, Clean Architecture (Robert C. Martin) |
| **`cyberaudit-qa-resilience`** | 17 | Pruebas anti-teatro (aserciones tautológicas), ReDoS, escrituras atómicas crash-safe | Dave Farley Continuous Delivery, Martin Fowler Refactoring |
| **`cyberaudit-ui-ux-a11y`**| 10 | Accesibilidad WCAG 2.2 AA/AAA, Core Web Vitals (CLS/INP), botones sin loading lock | W3C WCAG 2.2, Jakob Nielsen 10 Usability Heuristics |
| **`cyberaudit-compliance-privacy`** | 7 | PII en texto plano, dark patterns en cookies (Reject All), ROPA Art. 30, SOC 2 | GDPR (EU 2016/679), ISO/IEC 27001, SOC 2 Type II |
| **`cyberaudit-full`** | 68 | Auditoría integral definitiva de espectro completo | Todos los estándares unificados |

---

## 🔄 Protocolo de Auto-Reparación TDD

Cada hallazgo de CyberAudit se emite bajo el contrato **`where / why / repro / fix`**:
1. **RED:** El agente de IA escribe una prueba mínima que falla demostrando la vulnerabilidad o falla de arquitectura.
2. **GREEN:** Aplica la corrección defensiva (`fix`) directamente en el archivo afectado.
3. **REFACTOR:** Limpieza y mantenimiento de contratos.
4. **VERIFY:** Ejecución del script `verify.sh` determinista para confirmar 0 bloqueos y emisión del sello criptográfico.

---

## 🤖 Integración en GitHub Actions (CI/CD)

Crea el archivo `.github/workflows/cyberaudit.yml` en tu proyecto:

```yaml
name: CyberAudit Gatekeeper

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install CyberAudit
        run: pip install git+https://github.com/zippok/cyberaudit.git
      - name: Run CyberAudit Full Gate
        run: cyberaudit harness run-skill cyberaudit-full . --threshold HIGH --fail-on-block
      - name: Emit Verification Seal
        run: cyberaudit harness sello . --skill cyberaudit-full
```

---

## 📄 Licencia

Distribuido bajo la Licencia MIT. Consulta [`LICENSE`](LICENSE) para más detalles.
