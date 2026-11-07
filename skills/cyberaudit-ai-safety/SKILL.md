---
name: cyberaudit-ai-safety
description: "Executes all 5 AI Security & Engineering scanners: Prompt Injection (OWASP LLM01), AI Supply Chain & Model Serialization (Pickle/Safetensors), RAG Vector Poisoning & Context Sanitization, Autonomous Agent Tool-Call Safety (Kill-switches/HITL), and AI FinOps Token Budget & Output Guards. Executes 5 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, ai-safety, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit AI Security, LLM Guardrails, RAG & AI FinOps Skill (`cyberaudit-ai-safety`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`5` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- OWASP Top 10 for LLM Applications 2025
- NIST AI RMF 1.0
- EU AI Act
- AI Engineering (Chip Huyen)

## The Pass Order & Verification Matrix

Run these passes systematically. Passes 1–4 are security/correctness critical and are blocking-eligible (`[blocking]`); passes 5–6 address resilience, performance, and ergonomics (`[should-fix]` or `[nit]`). A clean pass is a reportable result ("Pass X: 0 findings, invariant verified").

| # | Pass | The Core Question | Typical Defects Detected |
|---|------|-------------------|---------------------------|
| 1 | Prompt Injection & Context Segregation | Is untrusted user input delimited to prevent prompt injection? | OWASP LLM01 direct/indirect injection, missing <user_input> bounds |
| 2 | Model Supply Chain & Serialization | Are unsafe pickle checkpoints or unpinned model weights used? | Arbitrary code execution via torch.load / pickle, missing SHA-256 |
| 3 | RAG Vector Poisoning & Document Hygiene | Are retrieved knowledge chunks validated before injection? | Poisoned vector embeddings, unverified external web retrieval |
| 4 | Autonomous Agent Agency & Tool Gating | Are destructive tool calls gated by HITL approvals and kill-switches? | Unbounded shell execution, missing approval fingerprints |
| 5 | AI FinOps & Denial of Wallet | Are LLM API calls bounded by max_tokens and cost ceilings? | Runaway generation loops, missing max_tokens causing huge billing |

## Confidence Floor & False-Positive Skip-List

**The 80% Rule:** If you are not at least ~80% confident that a finding is reachable, exposed to untrusted input, or causing real harm, do not elevate it to a blocker. Demote to `[question]` or discard it.

Skip these common false positives outright:

- **Local test scripts using mocked LLM responses.** — Local test scripts using mocked LLM responses.
- **Prompts operating strictly in read-only analysis tasks without tool capabilities.** — Prompts operating strictly in read-only analysis tasks without tool capabilities.

## Scanners Executed by `cyberaudit-ai-safety` (5 modules)

- **`AiSecurityScanner`** (*AI Security & LLM Defense Scanner*): Audits applications using Large Language Models against the OWASP Top 10 for LLMs (Prompt Injection, Insecure Output Handling, Data Leakage).
- **`AiSupplyChainScanner`** (*AI Supply Chain & Model Checkpoint Scanner*): Audits AI pipelines for PyTorch pickle deserialization RCE, unpinned HuggingFace weights, and safetensors migration.
- **`RagSecurityScanner`** (*RAG Security & Data Poisoning Scanner*): Audits RAG pipelines for indirect prompt injection, vector data poisoning, and cross-tenant data leaks.
- **`AiAgentSecurityScanner`** (*Autonomous AI Agent & Excessive Agency Scanner*): Audits autonomous AI agents for excessive agency, unsandboxed execution tools, and system prompt credential exposure.
- **`AiEvalDriftAndCostGuardScanner`** (*AI Engineering FinOps, Token Budget & Output Guard Scanner*): Audits LLM calls for missing max_tokens/max_output_tokens cost caps (Denial of Wallet) and unguarded JSON.parse on raw model outputs.

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-ai-safety . --threshold HIGH --json reports/cyberaudit-ai-safety-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-ai-safety --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-ai-safety:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
