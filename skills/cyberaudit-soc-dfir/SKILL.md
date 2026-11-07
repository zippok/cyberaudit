---
name: cyberaudit-soc-dfir
description: "Runs YARA static malware signatures, Sigma SIEM detection rules, Active Directory Kerberos/GPO checks, LOLBAS living-off-the-land binary detection, CTI IOC correlation, Log Hygiene, and DFIR Endpoint persistence triage. Executes 7 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, soc-dfir, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit SOC, Threat Hunting, Active Directory & DFIR Triage Skill (`cyberaudit-soc-dfir`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`7` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- MITRE ATT&CK Enterprise v16
- NIST SP 800-61r2 Incident Handling

## The Pass Order & Verification Matrix

Run these passes systematically. Passes 1–4 are security/correctness critical and are blocking-eligible (`[blocking]`); passes 5–6 address resilience, performance, and ergonomics (`[should-fix]` or `[nit]`). A clean pass is a reportable result ("Pass X: 0 findings, invariant verified").

| # | Pass | The Core Question | Typical Defects Detected |
|---|------|-------------------|---------------------------|
| 1 | Intent Fidelity | Does the system behavior match the stated security/quality contract? | Scope creep, incomplete implementation |
| 2 | Vulnerability & Threat Modeling | Are there exploitable flaws against OWASP/CWE/NIST standards? | Injection, auth bypass, leak |
| 3 | Durability & Resilience | Does the system maintain stability under faults and high load? | Resource exhaustion, unhandled exceptions |
| 4 | Standards Compliance | Are regulatory and framework controls satisfied? | GDPR, SOC 2, ISO 27001, WCAG |
| 5 | Evidence & Verification | Is every claim supported by reproducible tool execution? | Missing command, missing digest |

## Confidence Floor & False-Positive Skip-List

**The 80% Rule:** If you are not at least ~80% confident that a finding is reachable, exposed to untrusted input, or causing real harm, do not elevate it to a blocker. Demote to `[question]` or discard it.

Skip these common false positives outright:

- **Findings guarded upstream by framework-enforced parameterization.** — Findings guarded upstream by framework-enforced parameterization.
- **Internal development fixtures and test files with no production reachability.** — Internal development fixtures and test files with no production reachability.
- **Formatting or stylistic nitpicks owned by the linter.** — Formatting or stylistic nitpicks owned by the linter.

## Scanners Executed by `cyberaudit-soc-dfir` (7 modules)

- **`YaraStaticScanner`** (*YARA & Static Malware Scanner*): Static analysis engine detecting web shells, obfuscated PowerShell cradles, MalDoc macros, and packed binaries.
- **`SigmaEngine`** (*Sigma Detection Engineering Engine*): Evaluates event logs, Sysmon exports, and web telemetry using standardized Sigma detection rules.
- **`ActiveDirectoryAuditScanner`** (*Active Directory Security Auditor*): Audits Active Directory scripts, GPO XMLs, and configurations for Kerberoasting, AS-REP Roasting, DCSync and GPP flaws.
- **`LogHygieneScanner`** (*Logging Hygiene & Leakage Scanner*): Audits application source code for credential leakage in logs and missing security telemetry.
- **`LolbasDetector`** (*LOLBAS & GTFOBins Detector*): Detects abuse of native Windows binaries (LOLBAS) and Linux utilities (GTFOBins) for proxy execution and file transfer.
- **`CtiCorrelator`** (*CTI & Threat Intel Correlator*): Extracts and defangs IOCs (IPs, hashes, domains) and correlates with an explicitly configured, dated local threat feed.
- **`DfirEndpointScanner`** (*DFIR & Endpoint Investigation Scanner*): Audits forensic artifacts, Windows Registry persistence, Linux sudoers/cron, and macOS LaunchDaemons.

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-soc-dfir . --threshold HIGH --json reports/cyberaudit-soc-dfir-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-soc-dfir --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-soc-dfir:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
