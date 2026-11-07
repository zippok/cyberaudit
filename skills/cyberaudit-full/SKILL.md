---
name: cyberaudit-full
description: "Runs the complete 68-scanner CyberAudit engine + multi-agent adversarial refuter panel (security, architecture, QA/resilience) across all 9 cybersecurity, architecture, QA, UI/UX, AI, and compliance pillars. Emits deduped, exploitability-ranked findings and an immutable cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, full, audit, verify, harness, rsc, multi-agent]
recommends: [verify, review, secure-coding, code-review]
origin: risco
---

# CyberAudit Definitive Full-Spectrum Audit & Multi-Agent Refuter Panel (`cyberaudit-full`)

Tests prove the code works, not that it does what was asked. Scanners find syntax patterns, not architecture flaws. CyberAudit combines **both forces**: the deterministic 68-scanner machine suite (`cyberaudit harness`) with the **adversarial multi-agent refuter panel** (fresh-context subagents) to refute readiness before anything ships.

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. A clean diff/repo gets `APPROVE`, not a manufactured nit. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

---

## The Execution Model — Three Strict Stages

Operate through this three-stage discipline:

```text
[Stage 1: Machine Pre-Flight] -> [Stage 2: Multi-Agent Refuter Panel] -> [Stage 3: Consolidate & Sello]
```

### Stage 1: The Machine Pre-Flight (Deterministic 68 Scanners)

Always execute the deterministic CyberAudit CLI harness first. It inspects hundreds of files in sub-second time, collecting exact line-numbered SARIF/JSON evidence without spending LLM tokens on AST/regex patterns:

```bash
cyberaudit harness run-skill cyberaudit-full "$TARGET" --threshold HIGH
```

Inspect the output:
- `artifact_digest`: SHA-256 hash of the scanned tree state.
- `blocking_findings_count`: Count of findings with severity >= threshold.
- `verdict`: `PASS` or `BLOCKED`.

### Stage 2: Depth by Risk & Multi-Agent Refuter Panel

Determine review depth using `cyberaudit harness risk "$TARGET"`:
- **Tier 0 (docs, copy, markdown):** Silent pass; no subagents.
- **Tier 1 (minor non-critical changes):** Spawn **one fresh-context reviewer** via `invoke_subagent`.
- **Tier 2 / Full Audit (security, auth, DB, payments, public APIs, release gates):** Spawn the **adversarial fresh-context refuter panel** using `invoke_subagent`.

Each subagent is told to **REFUTE** readiness, not confirm it. Fresh context is non-negotiable: a reviewer that shares the implementation conversation inherits its blind spots.

#### Active Refuters for `cyberaudit-full`:
- **`CyberAudit Security Refuter`** (`TypeName: "research"`): Attacks auth boundaries, injection sinks, SSRF, BOLA, JWT signature bypass, and secrets.
- **`CyberAudit Architecture Refuter`** (`TypeName: "research"`): Attacks zero-downtime DB migrations, unindexed foreign keys, N+1 queries, idempotency keys, and Clean Architecture leaks.
- **`CyberAudit QA & Resilience Refuter`** (`TypeName: "research"`): Attacks anti-theater tests, tautological asserts expect(true).toBe(true), ReDoS regexes, and non-atomic state overwrites.


```json
// Subagent: CyberAudit Security Refuter
{
  "TypeName": "research",
  "Role": "CyberAudit Security Refuter",
  "Prompt": "You are an adversarial CyberAudit Security Refuter with fresh context. Attack this target: Attacks auth boundaries, injection sinks, SSRF, BOLA, JWT signature bypass, and secrets. Trace values, verify reachability, and report only reproducible findings using the standard where / why / repro / fix format."
}
```

```json
// Subagent: CyberAudit Architecture Refuter
{
  "TypeName": "research",
  "Role": "CyberAudit Architecture Refuter",
  "Prompt": "You are an adversarial CyberAudit Architecture Refuter with fresh context. Attack this target: Attacks zero-downtime DB migrations, unindexed foreign keys, N+1 queries, idempotency keys, and Clean Architecture leaks. Trace values, verify reachability, and report only reproducible findings using the standard where / why / repro / fix format."
}
```

```json
// Subagent: CyberAudit QA & Resilience Refuter
{
  "TypeName": "research",
  "Role": "CyberAudit QA & Resilience Refuter",
  "Prompt": "You are an adversarial CyberAudit QA & Resilience Refuter with fresh context. Attack this target: Attacks anti-theater tests, tautological asserts expect(true).toBe(true), ReDoS regexes, and non-atomic state overwrites. Trace values, verify reachability, and report only reproducible findings using the standard where / why / repro / fix format."
}
```


**Give each refuter exactly four inputs — no more, no less:**
1. **The task contract or project intent:** The human request and approved requirements.
2. **The exact source state:** `git diff` or changed files list.
3. **The baseline CyberAudit machine evidence:** The SARIF findings emitted in Stage 1.
4. **The test/run entrypoint:** The one command to run checks (`npm test`, `pytest`, `verify.sh`).

**Blind first, compare second:** Each refuter attacks and records findings before seeing the others' conclusions. Skip this and the fresh context is spent confirming previous bias.

### Stage 3: Consolidate Findings, Apply the 80% Floor & Emit the Sello

1. **Merge & Dedupe:** Combine machine scanner findings with subagent refuter attacks.
2. **Apply the 80% Confidence Floor:** If you are not at least ~80% confident that a finding is reachable, exposed to untrusted input, or causing real harm, do not elevate it to a blocker. Demote to `[question]` or discard it.
3. **Emit the Sello:**
   ```bash
   cyberaudit harness sello "$TARGET" --skill cyberaudit-full --threshold HIGH
   ```
   Records the immutable SHA-256 seal in `.rsc/cyberaudit-sello-log.jsonl`.

---

## Confidence Floor & False-Positive Skip-List

Skip these common false positives outright (or demote to `[question]` / `[nit]`):

- **Guarded upstream:** The check occurs two functions up or in a router middleware; trace before you flag.
- **Framework-enforced:** Framework already sanitizes (e.g. Prisma prepared statements, Zod schema validation).
- **Test-only or generated code held to production standards:** Don't demand production-grade error handling in mock fixtures.
- **Behind an off-everywhere flag:** Real flaw but unreachable in deployed environments -> `[nit]`, not `[blocking]`.
- **Style owned by the linter:** Quotes, line breaks, formatting. If an automated linter owns it, do not spend a finding on it.

---

## Severity & Finding Format

Every finding carries **where / why / repro / fix**:

- `[blocking]` — Ships a vulnerability, data loss, invariant breach, or broken contract. Release blocker.
- `[should-fix]` — Real defect with bounded blast radius; fix now or track explicitly.
- `[nit]` — Minor code quality or stylistic issue with zero correctness or security impact.
- `[question]` — Suspected defect where reachability cannot be proven from the diff alone.

```text
[blocking] src/repository/userRepo.js:42 — unvalidated SQL string concatenation
  where:  db.query(`SELECT * FROM users WHERE id = '${userId}'`) at line 42
  why:    userId comes from unvalidated req.params.id; permits SQL injection (CWE-89)
  repro:  GET /users/'%20OR%201=1-- -> dumps the entire user table
  fix:    db.query('SELECT * FROM users WHERE id = $1', [userId])
```

**Rule: no repro or stated mechanism -> it is a `[question]`, not a blocker.**

---

## The Verdict

End every audit review with exactly one verdict:

- **`APPROVE`** — Zero blockers, zero unresolved should-fix. Point the user to `ship`.
- **`APPROVE WITH NITS`** — Mergeable; nits listed but none block delivery.
- **`CHANGES REQUESTED`** — At least one `[blocking]`. List precisely what unblocks it.

---

## Verification Script

Run the deterministic pre-commit verification gate:

```bash
bash .antigravity/rsc/cyberaudit-full/scripts/verify.sh "$TARGET" HIGH
```
