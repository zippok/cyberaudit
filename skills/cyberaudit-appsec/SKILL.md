---
name: cyberaudit-appsec
description: "Executes all 12 AppSec & Penetration Testing scanners: SQL/NoSQL Injection, Command Injection/RCE, SSRF/Path Traversal/XXE, XSS/CSRF, Cryptographic Failures, Auth/Session/JWT, BOLA/IDOR Business Logic, SSTI, Insecure Deserialization, Mobile Security, Post-Quantum Crypto Agility, and Realtime WebSocket/GraphQL/gRPC. Executes 12 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, appsec, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit AppSec & Penetration Testing Skill (`cyberaudit-appsec`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`12` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- OWASP Top 10:2025
- OWASP API Security Top 10
- OWASP ASVS v4.0
- MITRE CWE Top 25

## The Pass Order & Verification Matrix

Run these passes systematically. Passes 1–4 are security/correctness critical and are blocking-eligible (`[blocking]`); passes 5–6 address resilience, performance, and ergonomics (`[should-fix]` or `[nit]`). A clean pass is a reportable result ("Pass X: 0 findings, invariant verified").

| # | Pass | The Core Question | Typical Defects Detected |
|---|------|-------------------|---------------------------|
| 1 | Injection & Remote Code Execution | Can untrusted input reach shell/sql/eval/template engines? | SQLi, Command Injection, SSTI, Insecure Deserialization |
| 2 | SSRF & Path Traversal | Can client manipulate URLs, local file paths, or cloud metadata? | CWE-918 SSRF, CWE-22 Path Traversal, XXE |
| 3 | Client-Side & State Forgery | Are cross-site requests or inline scripts sanitised? | Stored/Reflected XSS, CSRF tokens, Cookie SameSite |
| 4 | Authentication & JWT Session Integrity | Are cryptographic signatures, expiration, and session lifecycle verified? | JWT none algorithm, weak HMAC secrets, session fixation |
| 5 | Business Logic & BOLA/IDOR | Can a user access or mutate other users' objects via ID manipulation? | CWE-639 BOLA, horizontal/vertical privilege escalation |
| 6 | Modern Protocols & Post-Quantum Crypto | Are WebSockets, GraphQL and cryptographic primitives agile & bounded? | WS maxPayload, GraphQL introspection, quantum-vulnerable RSA/ECC |

## Confidence Floor & False-Positive Skip-List

**The 80% Rule:** If you are not at least ~80% confident that a finding is reachable, exposed to untrusted input, or causing real harm, do not elevate it to a blocker. Demote to `[question]` or discard it.

Skip these common false positives outright:

- **Input sanitized by a trusted framework parameterization layer (e.g. Prisma prepared statements, ORM bound parameters).** — Input sanitized by a trusted framework parameterization layer (e.g. Prisma prepared statements, ORM bound parameters).
- **Internal routes completely unexposed to untrusted input behind an authenticated API gateway with strict ingress filters.** — Internal routes completely unexposed to untrusted input behind an authenticated API gateway with strict ingress filters.
- **Mock tokens, fixture keys, or sandbox test secrets located inside unit test directories.** — Mock tokens, fixture keys, or sandbox test secrets located inside unit test directories.

## Scanners Executed by `cyberaudit-appsec` (12 modules)

- **`SqlInjectionScanner`** (*SQL & NoSQL Injection Scanner*): Audits application source code for SQL injection, raw query concatenation, and MongoDB NoSQL injection.
- **`CommandInjectionScanner`** (*Command Injection & Deserialization Scanner*): Detects OS command injection, untrusted deserialization (pickle/PyYAML), and Server-Side Template Injection (SSTI).
- **`SsrfTraversalScanner`** (*SSRF, Path Traversal & XXE Scanner*): Audits application source code for SSRF, Path Traversal/LFI, XXE, and Prototype Pollution vulnerabilities.
- **`XssCsrfScanner`** (*XSS, CSRF & Cookie Security Scanner*): Audits application source code for Cross-Site Scripting (XSS), disabled CSRF protections, insecure cookies, and permissive CORS.
- **`CryptoFailuresScanner`** (*Cryptographic Failures Scanner*): Detects broken hash algorithms (MD5/SHA-1), insecure block cipher modes (ECB), predictable PRNGs, and hardcoded keys.
- **`AuthSessionJwtScanner`** (*Authentication & JWT Security Scanner*): Audits application source code for JWT signature bypass, weak HMAC secrets, and OAuth 2.0 redirect vulnerabilities.
- **`BusinessLogicBolaScanner`** (*Business Logic & BOLA/IDOR Scanner*): Audits application logic for BOLA/IDOR, Mass Assignment, Role Tampering, and workflow state machine bypasses.
- **`SstiScanner`** (*Server-Side Template Injection (SSTI) Scanner*): Detects dangerous server-side template injection across Python (Jinja2, Mako), Node.js (EJS, Handlebars), Java, and PHP.
- **`DeserializationScanner`** (*Insecure Deserialization Scanner*): Audits binary and object deserialization APIs (pickle, PyYAML, Java readObject, BinaryFormatter, PHP unserialize) for arbitrary code execution vectors.
- **`MobileSecurityScanner`** (*Mobile Application Security & OWASP MASVS Scanner*): Detects Android/mobile vulnerabilities including tapjacking, insecure WebViews, exported components without permissions, cleartext storage, and network cleartext traffic according to OWASP MASVS.
- **`CryptoPqcAgilityScanner`** (*Cryptographic Agility & Post-Quantum (PQC) Readiness Scanner*): Audits applications for obsolete ciphers (DES/RC4), weak digests (MD5/SHA1), static IVs, insufficient RSA key lengths, and evaluates PQC transition posture.
- **`RealtimeWebsocketGraphqlGrpcScanner`** (*Realtime WebSocket, GraphQL & gRPC Protocol Security Scanner*): Audits WebSocket servers (missing Origin check / maxPayload), GraphQL endpoints (introspection enabled / missing depth limit), and insecure gRPC bindings.

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-appsec . --threshold HIGH --json reports/cyberaudit-appsec-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-appsec --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-appsec:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
