---
name: cyberaudit-devsecops
description: "Audits Secrets/Entropy, Dockerfiles, Kubernetes manifests, CI/CD GitHub Actions/GitLab pipelines, SCA dependency lockfiles, SBOM supply chain integrity, and Multi-Cloud posture across AWS, Azure, and GCP/Terraform. Executes 11 deterministic CyberAudit scanners and emits a verifiable gate artifact and cryptographic sello. Compatible with rsc-harness review/verify disciplines."
tags: [cyberaudit, devsecops, audit, verify, harness, rsc]
recommends: [verify, review, secure-coding, code-review]
origin: cyberaudit-harness
---

# CyberAudit DevSecOps, Cloud (AWS/Azure/GCP), Containers & Supply Chain Skill (`cyberaudit-devsecops`)

A **machine-first, evidence-first** deterministic audit skill. Point the specialized CyberAudit scanner suite at a codebase, collect SARIF/JSON evidence, dedupe cross-scanner overlap, and emit a reproducible gate artifact and cryptographic seal (`SELLO-CYBERAUDIT-VERIFICADO`).

**The north star is signal-to-noise.** Report only findings you can defend with concrete line numbers, exact code snippets, and reproducible failure scenarios. High false-positive rates destroy trust; aim for verified findings with zero speculative padding.

## Lane & Execution Contract

- **Default Lane:** `verify`
- **Deterministic Engine:** CyberAudit Definitive Suite (`11` specialized scanners in this domain; `68` total in `cyberaudit-full`).
- **Evidence First (P2 / P10):** Never claim a pass without running the deterministic CyberAudit CLI harness and citing the observed `artifact_digest`, `scanners_executed_count`, `verdict`, and `seal_hash`.
- **Read-only by default:** Scan, triage, gate, and report. Do not silently mutate source files during an audit sweep.

## Normative Standards & Frameworks

- CIS Benchmarks (AWS/Azure/GCP/K8s/Docker)
- SLSA v1.0
- NIST SSDF (SP 800-218)

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

## Scanners Executed by `cyberaudit-devsecops` (11 modules)

- **`CloudAzureAuditScanner`** (*Cloud & Azure Defense Auditor*): Audits Azure ARM/Bicep, Terraform IaC, Entra ID permissions, and AWS cloud policies for misconfigurations.
- **`CloudAwsAuditScanner`** (*Cloud & AWS Security Defense Auditor*): Audits AWS infrastructure (Terraform, CloudFormation, IAM) for wildcard admin policies, IMDSv1, open SGs, and public S3 buckets.
- **`SecretsScanner`** (*Secrets & Credential Scanner*): Scans code and configuration files for exposed cloud keys (AWS, GitHub, OpenAI), private keys, and passwords.
- **`DockerIacScanner`** (*Docker & Container Hardening Scanner*): Audits Dockerfile and compose configurations for root user execution, secret leaks, and privileged container flags.
- **`OwaspApiScanner`** (*OWASP API Security Top 10 Scanner*): Audits REST/GraphQL APIs for BOLA/IDOR, Broken Authentication, Mass Assignment, Rate Limiting, and Insecure CORS.
- **`SystemNetworkHardeningScanner`** (*System & Network Hardening Scanner*): Audits SSH configurations, plaintext protocols (Telnet/FTP), TLS certificate bypasses, and file permissions.
- **`CicdPipelineScanner`** (*CI/CD Pipeline Security Scanner*): Audits GitHub Actions, GitLab CI, and build workflows for supply chain risks, PwnRequest, and secret leaks.
- **`ScaDependencyScanner`** (*SCA & Dependency Security Scanner*): Audits requirements.txt, package.json, and lockfiles for wildcards, insecure registries, and known vulnerable packages.
- **`K8sSecurityScanner`** (*Kubernetes & Pod Security Scanner*): Audits Kubernetes manifests and Helm templates for privileged containers, host namespaces, and RBAC token exposures.
- **`SupplyChainSbomScanner`** (*Software Supply Chain & SBOM Security Scanner*): Detects supply chain threats including malicious npm/pip lifecycle scripts, unpinned dependencies, unpinned GitHub Actions, and unencrypted repository endpoints according to SLSA Framework and CISA guidance.
- **`MultiCloudGcpAndTerraformScanner`** (*Google Cloud (GCP) & Multi-Cloud Terraform Security Scanner*): Audits GCP IAM configurations and Terraform/HCL files for public `allUsers`/`allAuthenticatedUsers` bindings, `roles/owner` over-privileging, and static service account key exports.

## Deterministic Execution Recipes

### 1. Run Domain Skill Audit

```bash
python cyberaudit/cli.py harness run-skill cyberaudit-devsecops . --threshold HIGH --json reports/cyberaudit-devsecops-report.json
```

### 2. Emit Cryptographic Verification Seal (`SELLO-CYBERAUDIT-VERIFICADO`)

```bash
python cyberaudit/cli.py harness sello . --skill cyberaudit-devsecops --threshold HIGH
```

### 3. Evaluate Risk Tier & Recommended Skills

```bash
python cyberaudit/cli.py harness risk .
```

## Standard Finding Format

Every finding reported must carry **where / why / repro / fix**:

```text
[blocking] cyberaudit-devsecops:<file_path>:<line_number> — <finding_title>
  where:  Exact file, line number, and code snippet.
  why:    Invariant, CWE ID, or compliance control violated (e.g., DDIA Cap. 3, OWASP A03).
  repro:  Exact attack vector, malformed input payload, or stress condition that triggers the flaw.
  fix:    Concrete defensive remediation (exact code patch or architectural pattern).
```

## Gate Rules

1. **Verdict `PASS`:** `execution_status == "PASS"` and `0` open findings at or above the configured `--threshold` (default `HIGH`).
2. **Verdict `BLOCK`:** Any open finding at or above `--threshold` blocks release certification until remediated or documented with a time-boxed waiver.
3. **Cryptographic Trail:** Every seal is appended to `.rsc/cyberaudit-sello-log.jsonl` with commit SHA, branch, `artifact_digest`, and `seal_hash`.
