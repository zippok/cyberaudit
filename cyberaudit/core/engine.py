"""
CyberAudit Core Engine
Discovers target files, orchestrates security scanners, filters noise,
and aggregates findings into a unified ScanReport.
"""

import os
import time
import json
import logging
import hashlib
from typing import List, Set, Type
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import ScanReport, Finding, Pillar, Severity

logger = logging.getLogger("cyberaudit.core.engine")

# Security Analyst & DFIR Modules
from cyberaudit.modules.security_analyst.yara_static_scanner import YaraStaticScanner
from cyberaudit.modules.security_analyst.sigma_engine import SigmaEngine
from cyberaudit.modules.security_analyst.ad_audit import ActiveDirectoryAuditScanner
from cyberaudit.modules.security_analyst.cloud_azure_audit import CloudAzureAuditScanner
from cyberaudit.modules.security_analyst.cloud_aws_audit import CloudAwsAuditScanner
from cyberaudit.modules.security_analyst.log_hygiene_scanner import LogHygieneScanner
from cyberaudit.modules.security_analyst.lolbas_detector import LolbasDetector
from cyberaudit.modules.security_analyst.cti_correlator import CtiCorrelator
from cyberaudit.modules.dfir.dfir_triage import DfirEndpointScanner

# Penetration Tester & AppSec Modules
from cyberaudit.modules.penetration_tester.sqli_scanner import SqlInjectionScanner
from cyberaudit.modules.penetration_tester.command_injection_scanner import CommandInjectionScanner
from cyberaudit.modules.penetration_tester.ssrf_traversal_scanner import SsrfTraversalScanner
from cyberaudit.modules.penetration_tester.xss_csrf_scanner import XssCsrfScanner
from cyberaudit.modules.penetration_tester.crypto_failures_scanner import CryptoFailuresScanner
from cyberaudit.modules.penetration_tester.auth_session_jwt_scanner import AuthSessionJwtScanner
from cyberaudit.modules.penetration_tester.business_logic_bola_scanner import BusinessLogicBolaScanner
from cyberaudit.modules.penetration_tester.ssti_scanner import SstiScanner
from cyberaudit.modules.penetration_tester.deserialization_scanner import DeserializationScanner

# Security Engineer & DevSecOps Modules
from cyberaudit.modules.security_engineer.secrets_scanner import SecretsScanner
from cyberaudit.modules.security_engineer.docker_iac_scanner import DockerIacScanner
from cyberaudit.modules.security_engineer.owasp_api_scanner import OwaspApiScanner
from cyberaudit.modules.security_engineer.system_network_hardening import SystemNetworkHardeningScanner
from cyberaudit.modules.security_engineer.cicd_pipeline_scanner import CicdPipelineScanner
from cyberaudit.modules.security_engineer.sca_dependency_scanner import ScaDependencyScanner
from cyberaudit.modules.security_engineer.k8s_security_scanner import K8sSecurityScanner

# AI Security Modules
from cyberaudit.modules.ai_security.prompt_injection_scanner import AiSecurityScanner
from cyberaudit.modules.ai_security.ai_supply_chain_scanner import AiSupplyChainScanner
from cyberaudit.modules.ai_security.rag_security_scanner import RagSecurityScanner
from cyberaudit.modules.ai_security.ai_agent_security_scanner import AiAgentSecurityScanner

# Software QA & Code Quality Modules
from cyberaudit.modules.software_qa.code_quality_scanner import CodeQualityScanner
from cyberaudit.modules.software_qa.resource_leak_scanner import ResourceLeakScanner
from cyberaudit.modules.software_qa.test_coverage_auditor import TestCoverageAuditor
from cyberaudit.modules.software_qa.concurrency_race_scanner import ConcurrencyRaceScanner
from cyberaudit.modules.software_qa.complexity_maintainability_scanner import ComplexityMaintainabilityScanner
from cyberaudit.modules.software_qa.resilience_performance_scanner import ResiliencePerformanceScanner
from cyberaudit.modules.software_qa.clean_code_scanner import CleanCodeBestPracticesScanner
from cyberaudit.modules.software_qa.flaky_test_lifecycle_scanner import FlakyTestLifecycleScanner
from cyberaudit.modules.software_qa.defensive_contract_scanner import DefensiveContractScanner
from cyberaudit.modules.software_qa.db_pool_scanner import DatabasePoolExhaustionScanner
from cyberaudit.modules.software_qa.openapi_diff_scanner import OpenApiBreakingChangesScanner
from cyberaudit.modules.software_qa.event_leak_scanner import EventListenerLeakScanner

# UI/UX & Accessibility Modules
from cyberaudit.modules.ui_ux.accessibility_a11y_scanner import AccessibilityA11yScanner
from cyberaudit.modules.ui_ux.responsive_ergonomics_scanner import ResponsiveErgonomicsScanner
from cyberaudit.modules.ui_ux.contrast_typography_scanner import ContrastTypographyScanner
from cyberaudit.modules.ui_ux.ux_advanced_heuristics_scanner import UxAdvancedHeuristicsScanner
from cyberaudit.modules.ui_ux.wcag22_modern_compliance_scanner import Wcag22ModernComplianceScanner
from cyberaudit.modules.ui_ux.cognitive_ergonomics_scanner import CognitiveErgonomicsScanner

# Mobile Security, Advanced Cryptography & Supply Chain Modules
from cyberaudit.modules.penetration_tester.mobile_security_scanner import MobileSecurityScanner
from cyberaudit.modules.penetration_tester.crypto_pqc_agility_scanner import CryptoPqcAgilityScanner
from cyberaudit.modules.security_engineer.supply_chain_sbom_scanner import SupplyChainSbomScanner

# Software Architecture & Governance Module
from cyberaudit.modules.software_architecture.software_architecture_scanner import SoftwareArchitectureScanner
from cyberaudit.modules.software_architecture.rsc_harness_scanner import RscHarnessGovernanceScanner
from cyberaudit.modules.software_architecture.db_migration_orm_scanner import DatabaseMigrationAndOrmScanner
from cyberaudit.modules.software_architecture.api_idempotency_pagination_scanner import ApiIdempotencyAndPaginationScanner
from cyberaudit.modules.software_architecture.circular_dependency_boundary_scanner import CircularDependencyAndBoundaryScanner

# Extended Definitive Auditor Modules (QA, UI/UX, Cloud GCP, GDPR, Protocols, AI FinOps)
from cyberaudit.modules.software_qa.type_safety_schema_scanner import TypeSafetyAndSchemaBoundaryScanner
from cyberaudit.modules.software_qa.test_quality_assertion_auditor import TestQualityAndAssertionAuditor
from cyberaudit.modules.software_qa.crash_safety_durability_scanner import CrashSafetyAndDurabilityScanner
from cyberaudit.modules.software_qa.algorithmic_complexity_redos_scanner import AlgorithmicComplexityAndRedosScanner
from cyberaudit.modules.software_qa.observability_structured_logging_scanner import ObservabilityAndStructuredLoggingScanner
from cyberaudit.modules.ui_ux.async_ui_states_scanner import AsyncUiStatesCompletenessScanner
from cyberaudit.modules.ui_ux.core_web_vitals_perf_scanner import CoreWebVitalsAndFrontendPerfScanner
from cyberaudit.modules.ui_ux.design_system_token_i18n_scanner import DesignSystemTokenAndI18nScanner
from cyberaudit.modules.ui_ux.client_storage_hydration_scanner import ClientStorageAndHydrationSafetyScanner
from cyberaudit.modules.security_engineer.gdpr_privacy_pii_scanner import GdprPrivacyAndPiiDataFlowScanner
from cyberaudit.modules.penetration_tester.realtime_ws_graphql_grpc_scanner import RealtimeWebsocketGraphqlGrpcScanner
from cyberaudit.modules.security_analyst.cloud_gcp_terraform_audit import MultiCloudGcpAndTerraformScanner
from cyberaudit.modules.ai_security.ai_eval_drift_cost_scanner import AiEvalDriftAndCostGuardScanner


class AuditEngine:
    DEFAULT_EXCLUDES: Set[str] = {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        "dist",
        "build",
        ".idea",
        ".vscode",
        ".gemini",
        ".system_generated",
        "reports",
        "whatsapp_session",
        "_archive_whatsapp",
        "legacy_whatsapp",
        "demo_environment",
        "scratch",
        "conocimientos",
    }

    BINARY_EXTENSIONS: Set[str] = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".7z",
        ".mp4",
        ".mp3",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pyc",
        ".pyo",
        ".pyd",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".sys",
        ".node",
        ".pak",
        ".msi",
        ".iso",
        ".dat",
        ".dex",
        ".apk",
    }

    VENDOR_DIR_NAMES: Set[str] = {
        "node_modules",
        "libs",
        "vendor",
        "3rdparty",
        "third_party",
        "bower_components",
    }

    VENDOR_EXTENSIONS: Set[str] = {
        ".min.js",
        ".min.css",
        ".bundle.js",
    }

    # First-party SAST scanners that should skip vendor/minified code
    SAST_SCANNER_NAMES: Set[str] = {
        "SQL & NoSQL Injection Scanner",
        "Command Injection & RCE Scanner",
        "SSRF, Path Traversal & XXE Scanner",
        "XSS & CSRF Scanner",
        "Cryptographic Failures Scanner",
        "Authentication & Session Scanner",
        "Business Logic & BOLA/IDOR Scanner",
        "Server-Side Template Injection (SSTI) Scanner",
        "Insecure Deserialization Scanner",
    }

    def __init__(
        self,
        scanners: List[BaseScanner] = None,
        exclude_dirs: Set[str] = None,
        exclude_vendor: bool = True,
        archetype: str = "full",
        enable_external_tools: bool = True,
    ):
        self.exclude_vendor = exclude_vendor
        self.archetype = archetype.lower()
        self.enable_external_tools = enable_external_tools
        if scanners is None:
            self.scanners: List[BaseScanner] = [
                # Security Analyst & DFIR
                YaraStaticScanner(),
                SigmaEngine(),
                ActiveDirectoryAuditScanner(),
                CloudAzureAuditScanner(),
                CloudAwsAuditScanner(),
                LogHygieneScanner(),
                LolbasDetector(),
                CtiCorrelator(),
                DfirEndpointScanner(),
                # Penetration Tester & AppSec
                SqlInjectionScanner(),
                CommandInjectionScanner(),
                SsrfTraversalScanner(),
                XssCsrfScanner(),
                CryptoFailuresScanner(),
                AuthSessionJwtScanner(),
                BusinessLogicBolaScanner(),
                SstiScanner(),
                DeserializationScanner(),
                # Security Engineer & DevSecOps
                SecretsScanner(),
                DockerIacScanner(),
                OwaspApiScanner(),
                SystemNetworkHardeningScanner(),
                CicdPipelineScanner(),
                ScaDependencyScanner(),
                K8sSecurityScanner(),
                # AI Security & LLMs
                AiSecurityScanner(),
                AiSupplyChainScanner(),
                RagSecurityScanner(),
                AiAgentSecurityScanner(),
                # Software QA & Code Quality
                CodeQualityScanner(),
                ResourceLeakScanner(),
                TestCoverageAuditor(),
                ConcurrencyRaceScanner(),
                ComplexityMaintainabilityScanner(),
                ResiliencePerformanceScanner(),
                CleanCodeBestPracticesScanner(),
                FlakyTestLifecycleScanner(),
                DefensiveContractScanner(),
                DatabasePoolExhaustionScanner(),
                OpenApiBreakingChangesScanner(),
                EventListenerLeakScanner(),
                # UI/UX & Accessibility
                AccessibilityA11yScanner(),
                ResponsiveErgonomicsScanner(),
                ContrastTypographyScanner(),
                UxAdvancedHeuristicsScanner(),
                Wcag22ModernComplianceScanner(),
                CognitiveErgonomicsScanner(),
                # Mobile & Advanced Cryptography
                MobileSecurityScanner(),
                CryptoPqcAgilityScanner(),
                # Software Supply Chain & SBOM
                SupplyChainSbomScanner(),
                # Software Architecture & Governance
                SoftwareArchitectureScanner(),
                RscHarnessGovernanceScanner(),
                DatabaseMigrationAndOrmScanner(),
                ApiIdempotencyAndPaginationScanner(),
                CircularDependencyAndBoundaryScanner(),
                # Extended Definitive Auditor Modules (QA, UI/UX, Cloud GCP, GDPR, Protocols, AI FinOps)
                TypeSafetyAndSchemaBoundaryScanner(),
                TestQualityAndAssertionAuditor(),
                CrashSafetyAndDurabilityScanner(),
                AlgorithmicComplexityAndRedosScanner(),
                ObservabilityAndStructuredLoggingScanner(),
                AsyncUiStatesCompletenessScanner(),
                CoreWebVitalsAndFrontendPerfScanner(),
                DesignSystemTokenAndI18nScanner(),
                ClientStorageAndHydrationSafetyScanner(),
                GdprPrivacyAndPiiDataFlowScanner(),
                RealtimeWebsocketGraphqlGrpcScanner(),
                MultiCloudGcpAndTerraformScanner(),
                AiEvalDriftAndCostGuardScanner(),
            ]
        else:
            self.scanners = scanners

        self.exclude_dirs = self.DEFAULT_EXCLUDES | (exclude_dirs or set())

    def is_vendor_file(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/").lower()
        parts = set(norm.split("/"))
        if any(d in parts for d in self.VENDOR_DIR_NAMES):
            return True
        ext = os.path.splitext(norm)[1]
        if ext in self.VENDOR_EXTENSIONS or norm.endswith(".min.js"):
            return True
        return False

    def is_binary_file(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.BINARY_EXTENSIONS:
            return True
        # Read initial bytes to check for null bytes
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except Exception:
            return True

    def is_report_file(self, file_path: str) -> bool:
        """Excludes past generated HTML/JSON/MD audit report exports from being scanned as source code."""
        fname = os.path.basename(file_path).lower()
        is_report_name = (
            fname.startswith("audit_report")
            or fname.startswith("self_audit")
            or fname.startswith("auditoria_")
            or "audit_report" in fname
            or "cleancode_audit" in fname
            or "uiux_audit" in fname
            or "arch_audit" in fname
            or "qa_audit" in fname
        )
        return is_report_name and (fname.endswith(".html") or fname.endswith(".json") or fname.endswith(".md"))

    def _adjust_finding_for_archetype(self, finding: Finding) -> None:
        if self.archetype == "client" and ("SSRF" in finding.id or "SSRF" in finding.title):
            finding.title = finding.title.replace("Server-Side Request Forgery:", "Client Outbound Network Request:")
            finding.severity = Severity.LOW
            finding.description += " [Context: Desktop/Client application - Cloud metadata SSRF (169.254.169.254) not applicable]."

    def scan_path(self, target_path: str) -> ScanReport:
        """
        Scans a single file or an entire directory hierarchy.
        """
        target_path = os.path.abspath(target_path)
        report = ScanReport(target_path=target_path)
        states = {id(s): {"name": s.name, "status": "NOT_RUN", "files": 0, "errors": 0} for s in self.scanners}
        for scanner in self.scanners:
            if hasattr(scanner, "evidence_coverage"):
                states[id(scanner)]["coverage"] = scanner.evidence_coverage
        report.scanner_results = list(states.values())
        digest = hashlib.sha256()

        def record_error(scanner, path, error):
            report.execution_errors.append({"scanner": getattr(scanner, "name", None), "path": path, "error": str(error)})
            if scanner is not None:
                states[id(scanner)]["errors"] += 1
                states[id(scanner)]["status"] = "ERROR"

        start_time = time.time()
        files_to_scan: List[str] = []

        if os.path.isfile(target_path):
            if not self.is_report_file(target_path):
                files_to_scan.append(target_path)
        elif os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path, onerror=lambda e: record_error(None, str(e.filename), e)):
                # Prune excluded directories in-place (allow .github for CI/CD workflow auditing)
                dirs[:] = [d for d in dirs if d not in self.exclude_dirs and (not d.startswith(".") or d == ".github")]

                for f in files:
                    if f.startswith(".") and f not in (".rsc.json", ".env", ".gitignore", ".dockerignore"):
                        continue
                    full_path = os.path.join(root, f)
                    if not self.is_binary_file(full_path) and not self.is_report_file(full_path):
                        files_to_scan.append(full_path)

        else:
            record_error(None, target_path, "El objetivo no existe o no es un archivo/directorio.")
        files_to_scan.sort()
        report.files_discovered = len(files_to_scan)

        # Stage 0: External-First Industry Tools (npm audit, pip-audit, gitleaks, trivy)
        # If external tools fail or are absent, graceful fallback ensures native scanners run seamlessly.
        has_devsecops = any(getattr(s, "pillar", None) in (Pillar.SECURITY_ENGINEER, Pillar.CLOUD_DEFENSE) for s in self.scanners)
        if self.enable_external_tools and has_devsecops and os.path.isdir(target_path):
            try:
                from cyberaudit.core.external_orchestrator import ExternalToolOrchestrator
                ext_orch = ExternalToolOrchestrator()
                ext_findings, ext_status = ext_orch.run_external_first(target_path)
                if ext_findings:
                    report.findings.extend(ext_findings)
                if ext_status.get("attempted"):
                    succeeded_tools = ext_status.get("succeeded", [])
                    status_label = "PASS" if succeeded_tools else "FALLBACK"
                    summary_name = f"External Tools ({', '.join(succeeded_tools) or 'Fallback to Native'})"
                    report.scanner_results.append({
                        "name": summary_name,
                        "status": status_label,
                        "files": len(succeeded_tools),
                        "errors": len(ext_status.get("failed", [])),
                        "coverage": "Industry Standard External Tools (npm, pip-audit, gitleaks, trivy) with Graceful Fallback"
                    })
            except Exception as e:
                logger.debug("External tool orchestrator execution skipped: %s", e)

        # Run directory-level scans first
        if os.path.isdir(target_path):
            for scanner in self.scanners:
                try:
                    dir_findings = scanner.scan_directory(target_path)
                    report.findings.extend(dir_findings)
                    if type(scanner).scan_directory is not BaseScanner.scan_directory:
                        states[id(scanner)]["status"] = "PASS"
                except Exception as e:
                    record_error(scanner, target_path, e)

        # Scan each file across all relevant scanners
        for file_path in files_to_scan:
            try:
                with open(file_path, "rb") as f:
                    raw_content = f.read()
                content = raw_content.decode("utf-8", errors="replace")
                relative = os.path.relpath(file_path, target_path if os.path.isdir(target_path) else os.path.dirname(target_path))
                digest.update(relative.replace("\\", "/").encode("utf-8") + b"\0" + hashlib.sha256(raw_content).digest())
                report.files_scanned += 1
            except Exception as e:
                record_error(None, file_path, e)
                continue

            for scanner in self.scanners:
                if self.exclude_vendor and self.is_vendor_file(file_path) and scanner.name in self.SAST_SCANNER_NAMES:
                    # Skip first-party SAST rules on third-party minified vendor files
                    continue

                try:
                    if not scanner.should_scan(file_path):
                        continue
                    findings = scanner.scan_file(file_path, content)
                    states[id(scanner)]["files"] += 1
                    if not states[id(scanner)]["errors"]:
                        states[id(scanner)]["status"] = "PASS"
                    for finding in findings:
                        self._adjust_finding_for_archetype(finding)
                    report.findings.extend(findings)
                except Exception as e:
                    record_error(scanner, file_path, e)

        report.duration_seconds = round(time.time() - start_time, 2)
        report.scanners_executed = [s["name"] for s in report.scanner_results if s["status"] == "PASS"]
        report.artifact_digest = digest.hexdigest() if report.files_scanned else None
        report.execution_status = "ERROR" if report.execution_errors else ("PASS" if report.files_scanned and report.scanners_executed else "NOT_RUN")

        # Deduplicate findings across scanners before applying overrides
        try:
            from cyberaudit.core.finding_correlator import FindingClusterEngine
            raw_count = len(report.findings)
            correlator = FindingClusterEngine()
            deduped_dicts = correlator.deduplicate([f.to_dict() for f in report.findings])

            # Reconstruct Finding objects from deduplicated dicts
            # Models already imported at top-level
            reconstructed = []
            for fd in deduped_dicts:
                sev = Severity.MEDIUM
                for s in Severity:
                    if s.value == fd.get("severity"):
                        sev = s
                        break
                pil = Pillar.PENETRATION_TESTER
                for p in Pillar:
                    if p.value == fd.get("pillar"):
                        pil = p
                        break
                f = Finding(
                    id=fd.get("id", ""),
                    title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    severity=sev,
                    pillar=pil,
                    scanner_name=fd.get("scanner_name", ""),
                    file_path=fd.get("file_path", ""),
                    line_number=fd.get("line_number"),
                    code_snippet=fd.get("code_snippet"),
                    remediation=fd.get("remediation"),
                    mitre_id=fd.get("mitre_id"),
                    mitre_tactic=fd.get("mitre_tactic"),
                    mitre_technique=fd.get("mitre_technique"),
                    cwe_id=fd.get("cwe_id"),
                    cve_id=fd.get("cve_id"),
                    stride_category=fd.get("stride_category"),
                    compliance_controls=fd.get("compliance_controls", {}),
                    confidence=fd.get("confidence", "HIGH"),
                    status=fd.get("status", "OPEN"),
                    status_comment=fd.get("status_comment"),
                    status_updated_at=fd.get("status_updated_at"),
                )
                reconstructed.append(f)

            report.findings = reconstructed
            dedup_stats = correlator.get_dedup_stats(raw_count, len(reconstructed))
            logger.info("Finding dedup: %d raw → %d unique (%.1f%% reduction)",
                       raw_count, len(reconstructed), dedup_stats["dedup_ratio"])
        except Exception as e:
            record_error(None, target_path, f"Deduplication: {e}")
            report.execution_status = "ERROR"

        self._apply_status_overrides(report, target_path)
        return report

    def _apply_status_overrides(self, report: ScanReport, target_path: str) -> None:
        """
        Applies persisted status overrides (OPEN, RESOLVED, AS_DESIGNED)
        from audit_status_overrides.json so triage decisions survive re-scans.
        """
        candidates = []
        if os.path.isdir(target_path):
            candidates.append(os.path.join(target_path, "audit_status_overrides.json"))
        else:
            candidates.append(os.path.join(os.path.dirname(target_path), "audit_status_overrides.json"))
        candidates.append(os.path.abspath("audit_status_overrides.json"))

        overrides_file = None
        for cand in candidates:
            if os.path.isfile(cand):
                overrides_file = cand
                break

        if not overrides_file:
            return

        try:
            with open(overrides_file, "r", encoding="utf-8") as f:
                overrides = json.load(f)
        except Exception as e:
            logger.debug("No se pudieron cargar overrides de %s: %s", overrides_file, e)
            return

        sec_manager = None
        try:
            from cyberaudit.core.override_security import OverrideSecurityManager
            sec_manager = OverrideSecurityManager()
        except Exception:
            pass

        for finding in report.findings:
            norm_path = os.path.normpath(finding.file_path).replace("\\", "/")
            keys = [
                f"{finding.id}|{norm_path}|{finding.line_number}",
                f"{finding.id}|{norm_path}",
                finding.id,
            ]
            override = None
            matched_key = None
            for k in keys:
                if k in overrides:
                    override = overrides[k]
                    matched_key = k
                    break

            if override:
                if sec_manager:
                    is_valid, reason = sec_manager.verify_override(matched_key, override)
                    if not is_valid:
                        logger.warning("Override rechazado por seguridad para %s: %s", matched_key, reason)
                        continue

                finding.status = override.get("status", finding.status)
                finding.status_comment = override.get("comment", finding.status_comment)
                finding.status_updated_at = override.get("updated_at", finding.status_updated_at)
