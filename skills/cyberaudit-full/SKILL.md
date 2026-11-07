---
name: cyberaudit-full
description: "Runs the complete 68-scanner CyberAudit engine across all 9 cybersecurity, architecture, QA, UI/UX, AI, and compliance pillars. Executes 68 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, full, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit Definitive Full-Spectrum Audit Skill (All 68 Scanners) (`cyberaudit-full`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`68` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- All CyberAudit Security, Engineering, Architecture, QA, UI/UX, and Compliance Standards

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

## Scanners Executed by `cyberaudit-full` (68 modules)

- **`YaraStaticScanner`** (*YARA & Static Malware Scanner*): Static analysis engine detecting web shells, obfuscated PowerShell cradles, MalDoc macros, and packed binaries.
- **`SigmaEngine`** (*Sigma Detection Engineering Engine*): Evaluates event logs, Sysmon exports, and web telemetry using standardized Sigma detection rules.
- **`ActiveDirectoryAuditScanner`** (*Active Directory Security Auditor*): Audits Active Directory scripts, GPO XMLs, and configurations for Kerberoasting, AS-REP Roasting, DCSync and GPP flaws.
- **`CloudAzureAuditScanner`** (*Cloud & Azure Defense Auditor*): Audits Azure ARM/Bicep, Terraform IaC, Entra ID permissions, and AWS cloud policies for misconfigurations.
- **`CloudAwsAuditScanner`** (*Cloud & AWS Security Defense Auditor*): Audits AWS infrastructure (Terraform, CloudFormation, IAM) for wildcard admin policies, IMDSv1, open SGs, and public S3 buckets.
- **`LogHygieneScanner`** (*Logging Hygiene & Leakage Scanner*): Audits application source code for credential leakage in logs and missing security telemetry.
- **`LolbasDetector`** (*LOLBAS & GTFOBins Detector*): Detects abuse of native Windows binaries (LOLBAS) and Linux utilities (GTFOBins) for proxy execution and file transfer.
- **`CtiCorrelator`** (*CTI & Threat Intel Correlator*): Extracts and defangs IOCs (IPs, hashes, domains) and correlates with an explicitly configured, dated local threat feed.
- **`DfirEndpointScanner`** (*DFIR & Endpoint Investigation Scanner*): Audits forensic artifacts, Windows Registry persistence, Linux sudoers/cron, and macOS LaunchDaemons.
- **`SqlInjectionScanner`** (*SQL & NoSQL Injection Scanner*): Audits application source code for SQL injection, raw query concatenation, and MongoDB NoSQL injection.
- **`CommandInjectionScanner`** (*Command Injection & Deserialization Scanner*): Detects OS command injection, untrusted deserialization (pickle/PyYAML), and Server-Side Template Injection (SSTI).
- **`SsrfTraversalScanner`** (*SSRF, Path Traversal & XXE Scanner*): Audits application source code for SSRF, Path Traversal/LFI, XXE, and Prototype Pollution vulnerabilities.
- **`XssCsrfScanner`** (*XSS, CSRF & Cookie Security Scanner*): Audits application source code for Cross-Site Scripting (XSS), disabled CSRF protections, insecure cookies, and permissive CORS.
- **`CryptoFailuresScanner`** (*Cryptographic Failures Scanner*): Detects broken hash algorithms (MD5/SHA-1), insecure block cipher modes (ECB), predictable PRNGs, and hardcoded keys.
- **`AuthSessionJwtScanner`** (*Authentication & JWT Security Scanner*): Audits application source code for JWT signature bypass, weak HMAC secrets, and OAuth 2.0 redirect vulnerabilities.
- **`BusinessLogicBolaScanner`** (*Business Logic & BOLA/IDOR Scanner*): Audits application logic for BOLA/IDOR, Mass Assignment, Role Tampering, and workflow state machine bypasses.
- **`SstiScanner`** (*Server-Side Template Injection (SSTI) Scanner*): Detects dangerous server-side template injection across Python (Jinja2, Mako), Node.js (EJS, Handlebars), Java, and PHP.
- **`DeserializationScanner`** (*Insecure Deserialization Scanner*): Audits binary and object deserialization APIs (pickle, PyYAML, Java readObject, BinaryFormatter, PHP unserialize) for arbitrary code execution vectors.
- **`SecretsScanner`** (*Secrets & Credential Scanner*): Scans code and configuration files for exposed cloud keys (AWS, GitHub, OpenAI), private keys, and passwords.
- **`DockerIacScanner`** (*Docker & Container Hardening Scanner*): Audits Dockerfile and compose configurations for root user execution, secret leaks, and privileged container flags.
- **`OwaspApiScanner`** (*OWASP API Security Top 10 Scanner*): Audits REST/GraphQL APIs for BOLA/IDOR, Broken Authentication, Mass Assignment, Rate Limiting, and Insecure CORS.
- **`SystemNetworkHardeningScanner`** (*System & Network Hardening Scanner*): Audits SSH configurations, plaintext protocols (Telnet/FTP), TLS certificate bypasses, and file permissions.
- **`CicdPipelineScanner`** (*CI/CD Pipeline Security Scanner*): Audits GitHub Actions, GitLab CI, and build workflows for supply chain risks, PwnRequest, and secret leaks.
- **`ScaDependencyScanner`** (*SCA & Dependency Security Scanner*): Audits requirements.txt, package.json, and lockfiles for wildcards, insecure registries, and known vulnerable packages.
- **`K8sSecurityScanner`** (*Kubernetes & Pod Security Scanner*): Audits Kubernetes manifests and Helm templates for privileged containers, host namespaces, and RBAC token exposures.
- **`AiSecurityScanner`** (*AI Security & LLM Defense Scanner*): Audits applications using Large Language Models against the OWASP Top 10 for LLMs (Prompt Injection, Insecure Output Handling, Data Leakage).
- **`AiSupplyChainScanner`** (*AI Supply Chain & Model Checkpoint Scanner*): Audits AI pipelines for PyTorch pickle deserialization RCE, unpinned HuggingFace weights, and safetensors migration.
- **`RagSecurityScanner`** (*RAG Security & Data Poisoning Scanner*): Audits RAG pipelines for indirect prompt injection, vector data poisoning, and cross-tenant data leaks.
- **`AiAgentSecurityScanner`** (*Autonomous AI Agent & Excessive Agency Scanner*): Audits autonomous AI agents for excessive agency, unsandboxed execution tools, and system prompt credential exposure.
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
- **`AccessibilityA11yScanner`** (*UI/UX Accessibility & WCAG Standards Scanner*): Audits markup and UI components for compliance with WCAG 2.1/2.2 accessibility, screen readers, and keyboard navigation.
- **`ResponsiveErgonomicsScanner`** (*UI/UX Responsive Layout & Touch Ergonomics Scanner*): Evaluates responsive viewport configurations, fluid reflow constraints, and touch target sizing.
- **`ContrastTypographyScanner`** (*UI/UX Color Contrast & Typography Usability Scanner*): Audits text-to-background contrast ratios, minimum font size thresholds, and anti-selection usability issues.
- **`UxAdvancedHeuristicsScanner`** (*Advanced UX Heuristics & Form Accessibility Scanner*): Audits focus visibility (killed outlines), duplicate DOM IDs, missing autocomplete semantics, and vestibular motion preferences.
- **`Wcag22ModernComplianceScanner`** (*WCAG 2.2 Modern Compliance & Assistive Tech Scanner*): Audits WCAG 2.2 criteria (paste prevention, focus obscuring), decorative SVG pollution, and placeholder label misuse.
- **`CognitiveErgonomicsScanner`** (*Cognitive Ergonomics & Usability Heuristics Scanner*): Audits Nielsen usability heuristics (unconfirmed destructive actions, error prevention), color-only status indicators, and dark mode contrast safety.
- **`MobileSecurityScanner`** (*Mobile Application Security & OWASP MASVS Scanner*): Detects Android/mobile vulnerabilities including tapjacking, insecure WebViews, exported components without permissions, cleartext storage, and network cleartext traffic according to OWASP MASVS.
- **`CryptoPqcAgilityScanner`** (*Cryptographic Agility & Post-Quantum (PQC) Readiness Scanner*): Audits applications for obsolete ciphers (DES/RC4), weak digests (MD5/SHA1), static IVs, insufficient RSA key lengths, and evaluates PQC transition posture.
- **`SupplyChainSbomScanner`** (*Software Supply Chain & SBOM Security Scanner*): Detects supply chain threats including malicious npm/pip lifecycle scripts, unpinned dependencies, unpinned GitHub Actions, and unencrypted repository endpoints according to SLSA Framework and CISA guidance.
- **`SoftwareArchitectureScanner`** (*Software Architecture, Performance & Governance Scanner*): Audits software architecture quality, N+1 ORM queries, architectural layer leaks (UI directly accessing DB), and viral copyleft open-source license contamination.
- **`RscHarnessGovernanceScanner`** (*RSC-Harness & Agentic SDD/FTD Governance Scanner*): Audits rsc-harness project memory (02-DOCS/), tool connections (01-TOOLS/), SDD constitution status, verification gates (P2/P10), and installed audit skills.
- **`DatabaseMigrationAndOrmScanner`** (*Database Migration & ORM N+1 Safety Scanner*): Detects blocking/destructive SQL migrations (DROP/ALTER without expand-contract), ORM N+1 queries inside loops, unindexed foreign keys, and unbounded UPDATE/DELETE statements.
- **`ApiIdempotencyAndPaginationScanner`** (*API Contract, Idempotency & Pagination Scanner*): Audits API endpoints for missing Idempotency-Key handling on critical mutations (payments/orders) and unbounded collection queries lacking pagination limits.
- **`CircularDependencyAndBoundaryScanner`** (*Circular Dependency & Clean Architecture Boundary Scanner*): Detects circular module dependencies (A -> B -> A) and Clean Architecture layer violations (e.g., frontend UI components importing database/ORM repositories directly).
- **`TypeSafetyAndSchemaBoundaryScanner`** (*Type Safety & Schema Boundary Validation Scanner*): Detects TypeScript type-safety bypasses (@ts-ignore, @ts-nocheck, excessive `any`) and HTTP route handlers consuming req.body without schema validation.
- **`TestQualityAndAssertionAuditor`** (*Test Quality, Anti-Theater & Assertion Auditor*): Audits test suites for tautological assertions (expect(true).toBe(true)), assertion-free theater tests, and left-over .only/.skip modifiers.
- **`CrashSafetyAndDurabilityScanner`** (*Crash-Safety, Atomic Persistence & Durability Scanner (DDIA)*): Audits state persistence for non-atomic file writes (corruptible on power/process crash) and outbound network requests lacking timeout/abort guards.
- **`AlgorithmicComplexityAndRedosScanner`** (*Algorithmic Complexity O(N^2) & ReDoS Static Profiler*): Detects catastrophic backtracking regexes (ReDoS), O(N^2) nested collection lookups, and unbounded module-scope in-memory caches.
- **`ObservabilityAndStructuredLoggingScanner`** (*Observability, SRE Telemetry & Error Context Scanner*): Detects error handlers that discard stack traces (logging only err.message) or swallow causal exception chains without structured context.
- **`AsyncUiStatesCompletenessScanner`** (*Async UI States Completeness Scanner (Loading/Error/Empty/Double-Submit)*): Audits frontend components for missing disabled/loading submit locks (double-submit bug), blocking browser alert() dialogs, and silent async catch blocks lacking UI error state.
- **`CoreWebVitalsAndFrontendPerfScanner`** (*Core Web Vitals (LCP, CLS, INP) & Frontend Performance Scanner*): Audits frontend templates and scripts for Cumulative Layout Shift (dimensionless <img>), non-passive scroll/touch listeners (INP jank), and render-blocking head scripts (LCP).
- **`DesignSystemTokenAndI18nScanner`** (*Design System Token Drift & i18n Ergonomics Scanner*): Detects magic z-index escalation (z-index >= 9999), inline hardcoded hex colors bypassing design tokens, and locale-naive currency formatting.
- **`ClientStorageAndHydrationSafetyScanner`** (*Client Storage Token Exposure & SSR Hydration Scanner*): Detects sensitive JWT/auth tokens or PII persisted in localStorage/sessionStorage and non-deterministic SSR hydration patterns.
- **`GdprPrivacyAndPiiDataFlowScanner`** (*GDPR Privacy, PII Data-Flow & Consent Scanner*): Audits source code for plaintext PII logging (GDPR Art. 5/32), unredacted PII data flows, and asymmetric cookie consent banners lacking a Reject-All action (GDPR Art. 7).
- **`RealtimeWebsocketGraphqlGrpcScanner`** (*Realtime WebSocket, GraphQL & gRPC Protocol Security Scanner*): Audits WebSocket servers (missing Origin check / maxPayload), GraphQL endpoints (introspection enabled / missing depth limit), and insecure gRPC bindings.
- **`MultiCloudGcpAndTerraformScanner`** (*Google Cloud (GCP) & Multi-Cloud Terraform Security Scanner*): Audits GCP IAM configurations and Terraform/HCL files for public `allUsers`/`allAuthenticatedUsers` bindings, `roles/owner` over-privileging, and static service account key exports.
- **`AiEvalDriftAndCostGuardScanner`** (*AI Engineering FinOps, Token Budget & Output Guard Scanner*): Audits LLM calls for missing max_tokens/max_output_tokens cost caps (Denial of Wallet) and unguarded JSON.parse on raw model outputs.

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-full . --threshold HIGH --json reports/cyberaudit-full-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-full --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-full:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
