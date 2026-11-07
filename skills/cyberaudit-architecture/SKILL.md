---
name: cyberaudit-architecture
description: "Executes all 5 Architecture & Governance scanners: Software Architecture (SOLID/Coupling), RSC-Harness SDD/FTD Governance, Zero-Downtime Database Migrations & ORM N+1 Detector, API Idempotency & Pagination Bounds (DDIA), and Circular Dependency & Clean Layer Boundaries. Executes 5 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, architecture, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit Software Architecture, DB Migrations, API Contracts & Governance Skill (`cyberaudit-architecture`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`5` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- Kleppmann DDIA
- Clean Architecture (Robert C. Martin)
- Google Software Engineering
- rsc-harness P2/P7/P10

## The Pass Order & Verification Matrix

Run these passes systematically. Passes 1–4 are security/correctness critical and are blocking-eligible (`[blocking]`); passes 5–6 address resilience, performance, and ergonomics (`[should-fix]` or `[nit]`). A clean pass is a reportable result ("Pass X: 0 findings, invariant verified").

| # | Pass | The Core Question | Typical Defects Detected |
|---|------|-------------------|---------------------------|
| 1 | Database Migrations & Zero-Downtime Evolvability | Can database migrations cause downtime during rolling deployments? | DROP COLUMN without expand-and-contract, blocking table locks |
| 2 | API Contract Idempotency & Mutations | Are state-changing financial/order routes protected against duplicate requests? | POST/PATCH payment routes missing Idempotency-Key headers |
| 3 | Pagination Bounds & DoS Prevention | Can collection queries fetch millions of records into memory at once? | SELECT * / findMany() lacking limit/take pagination caps |
| 4 | Clean Architecture Layer Boundaries | Do presentation/UI layers import persistence/database layers directly? | React components importing Prisma/database repositories directly |
| 5 | Module Circular Dependencies | Are there cyclic import loops between files (A <-> B)? | Circular requires breaking tree-shaking and module initialization |
| 6 | SDD / FTD Harness Governance | Are constitutional specifications and verification records verified? | Draft constitutions, missing evidence in task checklists |

## Confidence Floor & False-Positive Skip-List

**The 80% Rule:** If you are not at least ~80% confident that a finding is reachable, exposed to untrusted input, or causing real harm, do not elevate it to a blocker. Demote to `[question]` or discard it.

Skip these common false positives outright:

- **Local test files importing mock repositories or test fixtures.** — Local test files importing mock repositories or test fixtures.
- **Migrations executed exclusively in initial project setup before production release.** — Migrations executed exclusively in initial project setup before production release.
- **Type-only circular imports erased at compile-time in TypeScript.** — Type-only circular imports erased at compile-time in TypeScript.

## Scanners Executed by `cyberaudit-architecture` (5 modules)

- **`SoftwareArchitectureScanner`** (*Software Architecture, Performance & Governance Scanner*): Audits software architecture quality, N+1 ORM queries, architectural layer leaks (UI directly accessing DB), and viral copyleft open-source license contamination.
- **`RscHarnessGovernanceScanner`** (*RSC-Harness & Agentic SDD/FTD Governance Scanner*): Audits rsc-harness project memory (02-DOCS/), tool connections (01-TOOLS/), SDD constitution status, verification gates (P2/P10), and installed audit skills.
- **`DatabaseMigrationAndOrmScanner`** (*Database Migration & ORM N+1 Safety Scanner*): Detects blocking/destructive SQL migrations (DROP/ALTER without expand-contract), ORM N+1 queries inside loops, unindexed foreign keys, and unbounded UPDATE/DELETE statements.
- **`ApiIdempotencyAndPaginationScanner`** (*API Contract, Idempotency & Pagination Scanner*): Audits API endpoints for missing Idempotency-Key handling on critical mutations (payments/orders) and unbounded collection queries lacking pagination limits.
- **`CircularDependencyAndBoundaryScanner`** (*Circular Dependency & Clean Architecture Boundary Scanner*): Detects circular module dependencies (A -> B -> A) and Clean Architecture layer violations (e.g., frontend UI components importing database/ORM repositories directly).

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-architecture . --threshold HIGH --json reports/cyberaudit-architecture-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-architecture --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-architecture:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
