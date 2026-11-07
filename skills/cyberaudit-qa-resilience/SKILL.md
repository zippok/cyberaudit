---
name: cyberaudit-qa-resilience
description: "Executes all 17 Software QA, Code Quality & Resilience scanners: Code Quality, Resource Leaks, Test Coverage, Concurrency & Race Conditions, Cyclomatic Complexity, Resilience & Event-Loop Non-Blocking, Clean Code (Fowler/McConnell), Flaky Test Lifecycle, Defensive Contracts, DB Pool Exhaustion, OpenAPI Breaking Changes, Event Listener Leaks, Type Safety & Schema Boundaries, Test Quality Anti-Theater Auditor, DDIA Crash-Safety Atomic Writes, Algorithmic Complexity O(N^2)/ReDoS Profiler, and SRE Observability & Error Context. Executes 17 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, qa-resilience, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit QA, Clean Code, Anti-Theater Testing & DDIA Crash-Safety Skill (`cyberaudit-qa-resilience`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`17` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- Dave Farley Continuous Delivery
- Martin Fowler Refactoring
- Steve McConnell Code Complete
- Kleppmann DDIA

## The Pass Order & Verification Matrix

Run these passes systematically. Passes 1–4 are security/correctness critical and are blocking-eligible (`[blocking]`); passes 5–6 address resilience, performance, and ergonomics (`[should-fix]` or `[nit]`). A clean pass is a reportable result ("Pass X: 0 findings, invariant verified").

| # | Pass | The Core Question | Typical Defects Detected |
|---|------|-------------------|---------------------------|
| 1 | Event Loop Non-Blocking & Resource Leaks | Does any synchronous I/O or unbounded loop freeze the runtime? | fs.readFileSync in requests, unclosed db connections, timer leaks |
| 2 | Concurrency & Race Conditions | Are async shared state mutations atomic and protected? | TOCTOU, dirty writes, lost updates, uncoordinated shared state |
| 3 | DDIA Crash-Safety & Atomic Writes | Can a crash or power cut leave state files corrupted or 0 bytes? | Missing write-temp + fsync + rename on state/config files |
| 4 | Type Safety & Boundary Schema Validation | Are compiler checks bypassed or req.body consumed unvalidated? | @ts-ignore, : any abuse, route handlers reading req.body without Zod/Joi |
| 5 | Test Quality & Anti-Theater Integrity | Do the tests actually prove system behavior or are they theater? | Tautological expect(true).toBe(true), assertion-free tests, .only committed |
| 6 | Algorithmic Complexity & ReDoS | Are there nested O(N^2) searches or catastrophic regular expressions? | Linear .includes inside .map, nested repeating quantifiers (X+)+ |

## Confidence Floor & False-Positive Skip-List

**The 80% Rule:** If you are not at least ~80% confident that a finding is reachable, exposed to untrusted input, or causing real harm, do not elevate it to a blocker. Demote to `[question]` or discard it.

Skip these common false positives outright:

- **Synchronous file operations inside build scripts, CLI entrypoints, or test runners.** — Synchronous file operations inside build scripts, CLI entrypoints, or test runners.
- **Test fixtures or mocks intentionally simulating broken states.** — Test fixtures or mocks intentionally simulating broken states.
- **Simple regexes with fixed length bounds where backtracking cannot occur.** — Simple regexes with fixed length bounds where backtracking cannot occur.

## Scanners Executed by `cyberaudit-qa-resilience` (17 modules)

- **`CodeQualityScanner`** (*Software QA & Code Quality Scanner*): Evaluates code maintainability, error suppression, network call resilience, and excessive cyclomatic complexity.
- **`ResourceLeakScanner`** (*Resource & Memory Leak Scanner*): Detects unclosed file handles, orphaned timers, database connection leaks, and Electron IPC listener compounding.
- **`TestCoverageAuditor`** (*Test Coverage & Test Suite Auditor*): Audits unit test presence, asserts validity, and flags empty or assertion-free tests.
- **`ConcurrencyRaceScanner`** (*Concurrency & Race Condition Scanner*): Detects asynchronous race conditions, shared global state mutations, and TOCTOU file access patterns.
- **`ComplexityMaintainabilityScanner`** (*Complexity & Maintainability Scanner*): Audits cyclomatic complexity, cognitive nesting depth, god functions, and technical debt anti-patterns.
- **`ResiliencePerformanceScanner`** (*Resilience & Performance Scanner*): Audits runtime resilience, event loop blocking I/O, unhandled promise rejections, and missing timeout bounds.
- **`CleanCodeBestPracticesScanner`** (*Clean Code, Anti-Hardcoding & Best Practices Scanner*): Audits source code for hardcoded local paths and IPs (12-Factor App), leftover debugging logs (console.log, print), debugger traps, nested ternaries, and technical debt tags.
- **`FlakyTestLifecycleScanner`** (*Flaky Test, Mutation Quality & Lifecycle Memory Scanner*): Audits test flakiness (arbitrary sleeps, unmocked system clocks), placebo assertions, and reactive hook memory leaks.
- **`DefensiveContractScanner`** (*Defensive Programming & API Contract Scanner*): Audits exception hygiene (stack trace preservation), API boundary contract schemas, and defensive logging diagnostics.
- **`DatabasePoolExhaustionScanner`** (*DatabasePoolExhaustionScanner*): Detecta fugas de descriptores de sockets, transacciones huérfanas y agotamiento de pools de base de datos.
- **`OpenApiBreakingChangesScanner`** (*OpenApiBreakingChangesScanner*): Detecta cambios rompientes de API, parámetros obligatorios sin default y ausencia de modelos de error.
- **`EventListenerLeakScanner`** (*EventListenerLeakScanner*): Detecta fugas de memoria por suscripciones a sockets, EventEmitter y DOM listeners no desuscritos.
- **`TypeSafetyAndSchemaBoundaryScanner`** (*Type Safety & Schema Boundary Validation Scanner*): Detects TypeScript type-safety bypasses (@ts-ignore, @ts-nocheck, excessive `any`) and HTTP route handlers consuming req.body without schema validation.
- **`TestQualityAndAssertionAuditor`** (*Test Quality, Anti-Theater & Assertion Auditor*): Audits test suites for tautological assertions (expect(true).toBe(true)), assertion-free theater tests, and left-over .only/.skip modifiers.
- **`CrashSafetyAndDurabilityScanner`** (*Crash-Safety, Atomic Persistence & Durability Scanner (DDIA)*): Audits state persistence for non-atomic file writes (corruptible on power/process crash) and outbound network requests lacking timeout/abort guards.
- **`AlgorithmicComplexityAndRedosScanner`** (*Algorithmic Complexity O(N^2) & ReDoS Static Profiler*): Detects catastrophic backtracking regexes (ReDoS), O(N^2) nested collection lookups, and unbounded module-scope in-memory caches.
- **`ObservabilityAndStructuredLoggingScanner`** (*Observability, SRE Telemetry & Error Context Scanner*): Detects error handlers that discard stack traces (logging only err.message) or swallow causal exception chains without structured context.

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-qa-resilience . --threshold HIGH --json reports/cyberaudit-qa-resilience-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-qa-resilience --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-qa-resilience:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
