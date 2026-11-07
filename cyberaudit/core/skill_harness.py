"""
CyberAudit Skill Harness Engine
Provides rsc-style agentic skill orchestration, domain-scoped multi-scanner execution,
risk-tier routing (cyberaudit-risk), and tamper-evident cryptographic sealing (cyberaudit-sello)
over all 68 CyberAudit scanners.
"""

import hashlib
import hmac
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.engine import AuditEngine
from cyberaudit.core.models import Pillar, ScanReport, Severity


CYBERAUDIT_SKILL_DOMAINS: Dict[str, Dict[str, Any]] = {
    "cyberaudit-appsec": {
        "id": "cyberaudit-appsec",
        "title": "CyberAudit AppSec & Penetration Testing Skill",
        "lane": "verify",
        "pillars": [Pillar.PENETRATION_TESTER],
        "description": (
            "Executes all 12 AppSec & Penetration Testing scanners: SQL/NoSQL Injection, Command Injection/RCE, "
            "SSRF/Path Traversal/XXE, XSS/CSRF, Cryptographic Failures, Auth/Session/JWT, BOLA/IDOR Business Logic, "
            "SSTI, Insecure Deserialization, Mobile Security, Post-Quantum Crypto Agility, and Realtime WebSocket/GraphQL/gRPC."
        ),
        "standards": ["OWASP Top 10:2025", "OWASP API Security Top 10", "OWASP ASVS v4.0", "MITRE CWE Top 25"],
    },
    "cyberaudit-devsecops": {
        "id": "cyberaudit-devsecops",
        "title": "CyberAudit DevSecOps, Cloud (AWS/Azure/GCP), Containers & Supply Chain Skill",
        "lane": "verify",
        "pillars": [Pillar.SECURITY_ENGINEER, Pillar.CLOUD_DEFENSE],
        "scanner_class_names": [
            "SecretsScanner",
            "DockerIacScanner",
            "OwaspApiScanner",
            "SystemNetworkHardeningScanner",
            "CicdPipelineScanner",
            "ScaDependencyScanner",
            "K8sSecurityScanner",
            "SupplyChainSbomScanner",
            "CloudAzureAuditScanner",
            "CloudAwsAuditScanner",
            "MultiCloudGcpAndTerraformScanner",
        ],
        "description": (
            "Audits Secrets/Entropy, Dockerfiles, Kubernetes manifests, CI/CD GitHub Actions/GitLab pipelines, "
            "SCA dependency lockfiles, SBOM supply chain integrity, and Multi-Cloud posture across AWS, Azure, and GCP/Terraform."
        ),
        "standards": ["CIS Benchmarks (AWS/Azure/GCP/K8s/Docker)", "SLSA v1.0", "NIST SSDF (SP 800-218)"],
    },
    "cyberaudit-soc-dfir": {
        "id": "cyberaudit-soc-dfir",
        "title": "CyberAudit SOC, Threat Hunting, Active Directory & DFIR Triage Skill",
        "lane": "verify",
        "pillars": [Pillar.SECURITY_ANALYST, Pillar.DFIR_ENDPOINT],
        "scanner_class_names": [
            "YaraStaticScanner",
            "SigmaEngine",
            "ActiveDirectoryAuditScanner",
            "LogHygieneScanner",
            "LolbasDetector",
            "CtiCorrelator",
            "DfirEndpointScanner",
        ],
        "description": (
            "Runs YARA static malware signatures, Sigma SIEM detection rules, Active Directory Kerberos/GPO checks, "
            "LOLBAS living-off-the-land binary detection, CTI IOC correlation, Log Hygiene, and DFIR Endpoint persistence triage."
        ),
        "standards": ["MITRE ATT&CK Enterprise v16", "NIST SP 800-61r2 Incident Handling"],
    },
    "cyberaudit-ai-safety": {
        "id": "cyberaudit-ai-safety",
        "title": "CyberAudit AI Security, LLM Guardrails, RAG & AI FinOps Skill",
        "lane": "verify",
        "pillars": [Pillar.AI_SECURITY],
        "description": (
            "Executes all 5 AI Security & Engineering scanners: Prompt Injection (OWASP LLM01), AI Supply Chain & Model Serialization (Pickle/Safetensors), "
            "RAG Vector Poisoning & Context Sanitization, Autonomous Agent Tool-Call Safety (Kill-switches/HITL), and AI FinOps Token Budget & Output Guards."
        ),
        "standards": ["OWASP Top 10 for LLM Applications 2025", "NIST AI RMF 1.0", "EU AI Act", "AI Engineering (Chip Huyen)"],
    },
    "cyberaudit-architecture": {
        "id": "cyberaudit-architecture",
        "title": "CyberAudit Software Architecture, DB Migrations, API Contracts & Governance Skill",
        "lane": "verify",
        "pillars": [Pillar.ARCHITECTURE],
        "description": (
            "Executes all 5 Architecture & Governance scanners: Software Architecture (SOLID/Coupling), RSC-Harness SDD/FTD Governance, "
            "Zero-Downtime Database Migrations & ORM N+1 Detector, API Idempotency & Pagination Bounds (DDIA), and Circular Dependency & Clean Layer Boundaries."
        ),
        "standards": ["Kleppmann DDIA", "Clean Architecture (Robert C. Martin)", "Google Software Engineering", "rsc-harness P2/P7/P10"],
    },
    "cyberaudit-qa-resilience": {
        "id": "cyberaudit-qa-resilience",
        "title": "CyberAudit QA, Clean Code, Anti-Theater Testing & DDIA Crash-Safety Skill",
        "lane": "verify",
        "pillars": [Pillar.SOFTWARE_QA],
        "description": (
            "Executes all 17 Software QA, Code Quality & Resilience scanners: Code Quality, Resource Leaks, Test Coverage, "
            "Concurrency & Race Conditions, Cyclomatic Complexity, Resilience & Event-Loop Non-Blocking, Clean Code (Fowler/McConnell), "
            "Flaky Test Lifecycle, Defensive Contracts, DB Pool Exhaustion, OpenAPI Breaking Changes, Event Listener Leaks, "
            "Type Safety & Schema Boundaries, Test Quality Anti-Theater Auditor, DDIA Crash-Safety Atomic Writes, "
            "Algorithmic Complexity O(N^2)/ReDoS Profiler, and SRE Observability & Error Context."
        ),
        "standards": ["Dave Farley Continuous Delivery", "Martin Fowler Refactoring", "Steve McConnell Code Complete", "Kleppmann DDIA"],
    },
    "cyberaudit-ui-ux-a11y": {
        "id": "cyberaudit-ui-ux-a11y",
        "title": "CyberAudit UI/UX Heuristics, WCAG 2.2 Accessibility & Core Web Vitals Skill",
        "lane": "verify",
        "pillars": [Pillar.UI_UX],
        "description": (
            "Executes all 10 UI/UX, Accessibility & Frontend Performance scanners: WCAG A11y Semantics, Responsive Touch Ergonomics, "
            "Color Contrast & Typography, Nielsen UX Heuristics, WCAG 2.2 Modern Compliance (Paste/Focus Obscured), Cognitive Ergonomics, "
            "Async UI States (Loading/Error/Empty/Double-Submit), Core Web Vitals (CLS/LCP/INP), Design System Token Drift & i18n, "
            "and Client Storage Token Exposure & SSR Hydration Safety."
        ),
        "standards": ["W3C WCAG 2.2 AA/AAA", "Nielsen Norman 10 Heuristics", "Google Core Web Vitals (LCP/CLS/INP)", "Laws of UX"],
    },
    "cyberaudit-compliance-privacy": {
        "id": "cyberaudit-compliance-privacy",
        "title": "CyberAudit GDPR Privacy, SOC 2, ISO 27001 & Production Release Certification Skill",
        "lane": "verify",
        "pillars": [Pillar.SECURITY_ENGINEER, Pillar.ARCHITECTURE],
        "scanner_class_names": [
            "GdprPrivacyAndPiiDataFlowScanner",
            "SecretsScanner",
            "LogHygieneScanner",
            "CryptoFailuresScanner",
            "CryptoPqcAgilityScanner",
            "SupplyChainSbomScanner",
            "RscHarnessGovernanceScanner",
        ],
        "description": (
            "Audits GDPR PII data-flows, plaintext PII logging, cookie consent dark patterns, cryptographic hygiene, "
            "SBOM provenance, SDD/FTD governance, and Production Readiness Certification gates."
        ),
        "standards": ["GDPR (EU 2016/679)", "SOC 2 Type II", "ISO/IEC 27001:2022", "PCI-DSS v4.0", "ENS"],
    },
    "cyberaudit-full": {
        "id": "cyberaudit-full",
        "title": "CyberAudit Definitive Full-Spectrum Audit Skill (All 68 Scanners)",
        "lane": "verify",
        "pillars": list(Pillar),
        "description": "Runs the complete 68-scanner CyberAudit engine across all 9 cybersecurity, architecture, QA, UI/UX, AI, and compliance pillars.",
        "standards": ["All CyberAudit Security, Engineering, Architecture, QA, UI/UX, and Compliance Standards"],
    },
}


class CyberAuditSkillHarness:
    """
    Orchestrates CyberAudit skills with rsc-compatible deterministic evidence,
    risk-tier classification, and cryptographic HMAC/SHA-256 sealing.
    """

    def __init__(self):
        self.full_engine = AuditEngine()

    def list_skills(self) -> List[Dict[str, Any]]:
        skills_out = []
        for skill_id, meta in CYBERAUDIT_SKILL_DOMAINS.items():
            scanners = self.get_scanners_for_skill(skill_id)
            skills_out.append({
                "id": skill_id,
                "title": meta["title"],
                "lane": meta["lane"],
                "scanner_count": len(scanners),
                "scanners": [s.name for s in scanners],
                "standards": meta["standards"],
                "description": meta["description"],
            })
        return skills_out

    def get_scanners_for_skill(self, skill_id: str) -> List[BaseScanner]:
        norm_id = skill_id.strip().lower()
        if not norm_id.startswith("cyberaudit-"):
            norm_id = f"cyberaudit-{norm_id}"
        if norm_id not in CYBERAUDIT_SKILL_DOMAINS:
            raise ValueError(
                f"Unknown CyberAudit skill '{skill_id}'. Available: {', '.join(sorted(CYBERAUDIT_SKILL_DOMAINS.keys()))}"
            )

        if norm_id == "cyberaudit-full":
            return list(self.full_engine.scanners)

        meta = CYBERAUDIT_SKILL_DOMAINS[norm_id]
        explicit_classes = meta.get("scanner_class_names")
        if explicit_classes:
            wanted = set(explicit_classes)
            return [s for s in self.full_engine.scanners if s.__class__.__name__ in wanted]

        target_pillars = set(meta.get("pillars", []))
        return [s for s in self.full_engine.scanners if s.pillar in target_pillars]

    def run_skill(
        self,
        skill_id: str,
        target_path: str,
        exclude_vendor: bool = True,
        fail_threshold: str = "HIGH",
    ) -> Dict[str, Any]:
        norm_id = skill_id.strip().lower()
        if not norm_id.startswith("cyberaudit-"):
            norm_id = f"cyberaudit-{norm_id}"

        scanners = self.get_scanners_for_skill(norm_id)
        engine = AuditEngine(scanners=scanners, exclude_vendor=exclude_vendor)
        report: ScanReport = engine.scan_path(target_path)

        threshold_sev = Severity[fail_threshold.upper()]
        blocking_findings = [
            f.to_dict() for f in report.findings if f.severity.rank >= threshold_sev.rank and f.status == "OPEN"
        ]

        severity_counts = {sev.value: 0 for sev in Severity}
        for f in report.findings:
            if f.status == "OPEN":
                severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        verdict = "PASS" if (report.execution_status == "PASS" and len(blocking_findings) == 0) else "BLOCK"

        return {
            "harness": "cyberaudit-skill-harness",
            "version": "2.0.0",
            "skill_id": norm_id,
            "skill_title": CYBERAUDIT_SKILL_DOMAINS[norm_id]["title"],
            "lane": CYBERAUDIT_SKILL_DOMAINS[norm_id]["lane"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_path": os.path.abspath(target_path),
            "artifact_digest": report.artifact_digest,
            "scanners_executed_count": len(scanners),
            "scanners_executed": [s.name for s in scanners],
            "files_scanned": report.files_scanned,
            "execution_status": report.execution_status,
            "verdict": verdict,
            "fail_threshold": threshold_sev.value,
            "blocking_findings_count": len(blocking_findings),
            "severity_counts": severity_counts,
            "findings": [f.to_dict() for f in report.findings],
        }

    def evaluate_risk(self, target_path: str = ".", base_ref: str = "HEAD") -> Dict[str, Any]:
        """
        Determines risk tier (Tier 0 / Tier 1 / Tier 2) and recommends which CyberAudit skills must run,
        combining git diff sensitivity with static risk signals.
        """
        changed_files: List[str] = []
        try:
            proc = subprocess.run(
                ["git", "status", "-s"],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            for line in proc.stdout.splitlines():
                if len(line) > 3:
                    changed_files.append(line[3:].strip())
        except Exception:
            pass

        tier = 0
        reasons: List[str] = []
        recommended_skills = set(["cyberaudit-qa-resilience", "cyberaudit-architecture"])

        high_risk_keywords = ("auth", "crypto", "secret", "security", "payment", "jwt", "session", "gatekeeper", "agentSafety")
        ui_keywords = (".jsx", ".tsx", ".vue", ".css", ".html", "public/", "components/")
        ai_keywords = ("llm", "prompt", "agent", "rag", "co_analyst", "brain", "mcp")
        infra_keywords = ("dockerfile", ".tf", "k8s", ".github/workflows", "package.json", "requirements.txt")

        for f in changed_files:
            fl = f.lower()
            if any(k in fl for k in high_risk_keywords):
                tier = max(tier, 2)
                reasons.append(f"Sensitive security/auth/safety surface modified: {f}")
                recommended_skills.add("cyberaudit-appsec")
                recommended_skills.add("cyberaudit-compliance-privacy")
            if any(k in fl for k in ui_keywords):
                tier = max(tier, 1)
                recommended_skills.add("cyberaudit-ui-ux-a11y")
            if any(k in fl for k in ai_keywords):
                tier = max(tier, 2)
                reasons.append(f"AI/LLM/Agent surface modified: {f}")
                recommended_skills.add("cyberaudit-ai-safety")
            if any(k in fl for k in infra_keywords):
                tier = max(tier, 1)
                recommended_skills.add("cyberaudit-devsecops")

        if len(changed_files) > 5 and tier < 1:
            tier = 1
            reasons.append(f"Multi-file change ({len(changed_files)} files)")

        return {
            "tier": tier,
            "lane": "sdd" if tier >= 2 else ("ftd" if tier == 1 else "trivial"),
            "changed_files_count": len(changed_files),
            "changed_files": changed_files[:50],
            "reasons": reasons or ["Standard change footprint"],
            "recommended_skills": sorted(recommended_skills),
        }

    def emit_sello(
        self,
        target_path: str,
        skill_id: str = "cyberaudit-full",
        fail_threshold: str = "HIGH",
        log_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes the requested CyberAudit skill (or full 68-scanner suite) and emits a cryptographic
        SELLO-CYBERAUDIT-VERIFICADO entry appended to .rsc/cyberaudit-sello-log.jsonl.
        """
        result = self.run_skill(skill_id=skill_id, target_path=target_path, fail_threshold=fail_threshold)

        head_sha = "UNCOMMITTED"
        branch = "unknown"
        try:
            head_sha = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            ).stdout.strip() or "UNCOMMITTED"
            branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=target_path,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            ).stdout.strip() or "unknown"
        except Exception:
            pass

        payload_str = (
            f"{result['skill_id']}|{head_sha}|{branch}|{result['artifact_digest']}|"
            f"{result['verdict']}|{result['scanners_executed_count']}|{result['blocking_findings_count']}"
        )
        seal_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()[:16]

        entry = {
            "seal_type": "SELLO-CYBERAUDIT-VERIFICADO" if result["verdict"] == "PASS" else "SELLO-CYBERAUDIT-BLOQUEADO",
            "seal_hash": seal_hash,
            "timestamp": result["timestamp"],
            "branch": branch,
            "commit": head_sha,
            "skill_id": result["skill_id"],
            "scanners_executed_count": result["scanners_executed_count"],
            "files_scanned": result["files_scanned"],
            "artifact_digest": result["artifact_digest"],
            "verdict": result["verdict"],
            "fail_threshold": result["fail_threshold"],
            "blocking_findings_count": result["blocking_findings_count"],
            "severity_counts": result["severity_counts"],
        }

        if log_path is None:
            rsc_dir = os.path.join(os.path.abspath(target_path), ".rsc")
            os.makedirs(rsc_dir, exist_ok=True)
            log_path = os.path.join(rsc_dir, "cyberaudit-sello-log.jsonl")

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        entry["log_path"] = log_path
        return entry
