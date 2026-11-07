# CyberAudit Agent-Driven Onboarding Specification

> **Target Audience:** AI Assistants & Agents (Google Antigravity, Claude Code, Cursor, Copilot, Codex, Windsurf).
> **Role:** When a user asks you to *"Lee este repositorio y configura CyberAudit para este proyecto"* or *"Read this repo and set up CyberAudit for this project"*, follow this protocol strictly. Always conduct the interview and present the plan in the same language the user prompted you with (Spanish or English).

---

## 1. Operating Protocol for AI Agents

You must follow an **Interactive 5-Step Gated Onboarding Flow**:

```text
[Step 1: Inspect Project] -> [Step 2: Interactive Interview] -> [Step 3: Present Plan] -> [Step 4: User Approval Gate] -> [Step 5: Install & Verify]
```

### Step 1: Inspect the Target Project Stack
Analyze the workspace files to detect the tech stack:
- **Languages:** Node.js/TypeScript (`package.json`), Python (`pyproject.toml`, `requirements.txt`), Go (`go.mod`), Dart/Flutter (`pubspec.yaml`), Rust (`Cargo.toml`).
- **Frameworks:** React/Next.js, FastAPI, Django, Express, NestJS, Tailwind, Prisma, SQLAlchemy.
- **Git State:** Current branch, clean working tree, existing test runners (`npm test`, `pytest`, `go test`).

### Step 2: Interactive Interview (Ask the User 3 Questions)
Ask the user the following questions in a friendly, concise manner:
1. **Auditing Depth:**
   - **(Recommended) CyberAudit Full:** All 68 scanners across Security, Architecture, QA, UI/UX, Cloud, AI and Compliance.
   - **Targeted Security & Privacy:** AppSec (12 scanners) + Cloud/DevSecOps (11 scanners) + GDPR (7 scanners).
   - **Engineering & QA:** Software Architecture (5 scanners) + QA/Resilience (17 scanners) + UI/UX (10 scanners).
2. **Blocking Threshold:**
   - **(Recommended) HIGH:** Block commits/releases only on High and Critical findings (cvss >= 7.0 / cwe major).
   - **CRITICAL:** Block only on exploit-ready Critical vulnerabilities.
3. **Automated Cryptographic Seal:**
   - **(Recommended) Yes:** Emit an immutable `SELLO-CYBERAUDIT-VERIFICADO` (SHA-256) recorded in `.rsc/cyberaudit-sello-log.jsonl`.

### Step 3: Present the Installation Plan Table
Generate a markdown table showing the proposed configuration and wait for explicit confirmation:

```markdown
### Proposed CyberAudit Installation Plan

| Component | Target Location | Description |
| :--- | :--- | :--- |
| **CLI Engine** | System / Python Virtualenv | CyberAudit 2.0 CLI (`cyberaudit harness`) |
| **Skills** | `.antigravity/rsc/` (or `.agents/skills/`) | Selected CyberAudit RSC skills |
| **Threshold** | `HIGH` | Gated verification threshold |
| **Verification Gate** | `bash <skill>/scripts/verify.sh .` | Deterministic pre-commit gate |
| **Audit Seal** | `.rsc/cyberaudit-sello-log.jsonl` | Cryptographic SHA-256 release seal |
```

### Step 4: User Approval Gate (Mandatory)
**DO NOT write or modify any files** until the user explicitly says *"Accept"*, *"Proceed"*, *"Adelante"*, or confirms the plan.

### Step 5: Execute Installation and First Verification
Once approved:
1. **Install Engine:**
   ```bash
   pip install -e /path/to/cyberaudit
   # OR from GitHub:
   pip install git+https://github.com/zippok/cyberaudit.git
   ```
2. **Copy Skills to the Project:**
   Copy the selected skills into the project's agent skills directory:
   - For Antigravity: `.antigravity/rsc/cyberaudit-*`
   - For Claude Code / Cursor: `.agents/skills/cyberaudit-*`
3. **Execute Baseline Scan:**
   Run the verification gate:
   ```bash
   cyberaudit harness run-skill cyberaudit-full . --threshold HIGH
   ```
4. **Report Baseline Findings to User:**
   Present any existing findings using the standard **`where / why / repro / fix`** format and offer to apply TDD remediation (Red $\rightarrow$ Green $\rightarrow$ Refactor).

---

## 2. Available CyberAudit Skills Directory

| Skill ID | Scanners | Domain | Standards |
| :--- | :---: | :--- | :--- |
| `cyberaudit-appsec` | 12 | AppSec, Pentest, Injections, Auth & APIs | OWASP Top 10:2025, OWASP API Top 10 |
| `cyberaudit-devsecops` | 11 | AWS/GCP/Azure, K8s, Docker, Supply Chain | CIS Benchmarks, SLSA v1.0 |
| `cyberaudit-soc-dfir` | 7 | SOC, Threat Hunting, AD & Incident Triage | MITRE ATT&CK v16, NIST SP 800-61r2 |
| `cyberaudit-ai-safety` | 5 | LLM Security, FinOps, Prompt Injection, RAG | OWASP LLM Top 10:2025, NIST AI RMF |
| `cyberaudit-architecture`| 5 | Clean Arch, Zero-Downtime DB, Idempotency | Kleppmann DDIA, Robert C. Martin |
| `cyberaudit-qa-resilience`| 17 | Anti-Theater Testing, ReDoS, Crash-Safety | Dave Farley CD, Martin Fowler Refactoring |
| `cyberaudit-ui-ux-a11y` | 10 | WCAG 2.2 AA/AAA, Core Web Vitals, Design | W3C WCAG 2.2, Nielsen Norman Heuristics |
| `cyberaudit-compliance-privacy` | 7 | GDPR, PII Redaction, SOC 2, ISO 27001 | EU GDPR (Art. 5/13-17/30/32), SOC 2 |
| `cyberaudit-full` | 68 | All 68 Scanners Full-Spectrum Audit | All Integrated Industry Standards |
