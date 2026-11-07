"""
cyberaudit/core/production_readiness_certifier.py
=================================================
Internal Production Readiness Evidence Evaluator.

Evaluates multi-dimensional audit data (SAST, SCA Reachability, Live Secrets,
Test Coverage, Mutation Score, Privacy/PII Taint, Container Hardening, and
Operational Observability) to emit a scoped internal readiness statement; this is not external certification.

Verdicts:
  - READY_FOR_PRODUCTION: All mandatory security, testing, and ops gates PASSED.
  - CONDITIONALLY_READY: Non-blocking advisories or signed waiver exceptions.
  - DEPLOYMENT_BLOCKED: One or more critical security, test, or compliance blockers.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import re
import uuid
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cyberaudit.core.models import Finding, Pillar, ScanReport, Severity


class ReadinessVerdict(str, Enum):
    READY_FOR_PRODUCTION = "READY_FOR_PRODUCTION"
    CONDITIONALLY_READY = "CONDITIONALLY_READY"
    DEPLOYMENT_BLOCKED = "DEPLOYMENT_BLOCKED"


class GateCategory(str, Enum):
    SECURITY_VULNERABILITIES = "SECURITY_VULNERABILITIES"
    ACTIVE_SECRETS_EXPOSURE = "ACTIVE_SECRETS_EXPOSURE"
    SCA_REACHABILITY = "SCA_REACHABILITY"
    TEST_AND_QUALITY = "TEST_AND_QUALITY"
    PRIVACY_AND_COMPLIANCE = "PRIVACY_AND_COMPLIANCE"
    CONTAINER_AND_INFRASTRUCTURE = "CONTAINER_AND_INFRASTRUCTURE"
    RESILIENCE_AND_OPS = "RESILIENCE_AND_OPS"


@dataclass
class GateCheckResult:
    gate_id: str
    title: str
    category: GateCategory
    passed: bool
    is_blocker: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    status: str = ""

    def __post_init__(self):
        if not self.status:
            self.status = "PASS" if self.passed else "FAIL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "title": self.title,
            "category": self.category.value,
            "passed": self.passed,
            "is_blocker": self.is_blocker,
            "message": self.message,
            "details": self.details,
            "remediation": self.remediation,
            "status": self.status,
        }


@dataclass
class ProductionPolicyConfig:
    max_critical_findings: int = 0
    max_high_findings: int = 0
    allow_active_secrets: bool = False
    allow_reachable_sca_cves: bool = False
    min_test_pass_rate: float = 100.0
    min_code_coverage_pct: float = 75.0
    min_mutation_score_pct: float = 85.0
    max_tautological_tests: int = 0
    min_assertion_density: float = 1.5
    require_healthcheck_endpoint: bool = True
    allow_unmasked_pii_logging: bool = False
    require_non_root_container: bool = True
    disallow_debug_mode: bool = True

    @classmethod
    def default_strict(cls) -> ProductionPolicyConfig:
        return cls()

    @classmethod
    def permissive_staging(cls) -> ProductionPolicyConfig:
        return cls(
            max_critical_findings=0,
            max_high_findings=3,
            min_code_coverage_pct=50.0,
            min_mutation_score_pct=70.0,
        )


@dataclass
class ProductionReleaseCertificate:
    certificate_id: str
    application_name: str
    target_environment: str
    timestamp: str
    verdict: ReadinessVerdict
    readiness_score: float
    total_checks: int
    passed_checks_count: int
    blockers_count: int
    warnings_count: int
    gate_results: List[GateCheckResult]
    tamper_proof_signature: str
    policy_name: str = "Enterprise Production Zero-Tolerance Policy"
    evidence_digest: str = ""
    policy: Dict[str, Any] = field(default_factory=dict)
    signature_algorithm: str = "HMAC-SHA256"

    def canonical_payload(self) -> bytes:
        data = self.to_dict()
        data.pop("tamper_proof_signature")
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

    def verify_signature(self, key: str) -> bool:
        if not key or not self.tamper_proof_signature:
            return False
        expected = hmac.new(key.encode("utf-8"), self.canonical_payload(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.tamper_proof_signature)

    @property
    def is_deployable(self) -> bool:
        return self.verdict in (ReadinessVerdict.READY_FOR_PRODUCTION, ReadinessVerdict.CONDITIONALLY_READY)

    def get_blockers(self) -> List[GateCheckResult]:
        return [g for g in self.gate_results if not g.passed and g.is_blocker]

    def get_warnings(self) -> List[GateCheckResult]:
        return [g for g in self.gate_results if not g.passed and not g.is_blocker]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "application_name": self.application_name,
            "target_environment": self.target_environment,
            "timestamp": self.timestamp,
            "verdict": self.verdict.value,
            "is_deployable": self.is_deployable,
            "readiness_score": self.readiness_score,
            "total_checks": self.total_checks,
            "passed_checks_count": self.passed_checks_count,
            "blockers_count": self.blockers_count,
            "warnings_count": self.warnings_count,
            "policy_name": self.policy_name,
            "tamper_proof_signature": self.tamper_proof_signature,
            "gate_results": [g.to_dict() for g in self.gate_results],
            "evidence_digest": self.evidence_digest,
            "policy": self.policy,
            "signature_algorithm": self.signature_algorithm,
        }

    def to_markdown(self) -> str:
        verdict_icon = "PASS / APROBADO PARA PRODUCCION" if self.verdict == ReadinessVerdict.READY_FOR_PRODUCTION else (
            "CONDICIONAL / REQUIERE APROBACION" if self.verdict == ReadinessVerdict.CONDITIONALLY_READY else "BLOQUEADO / DESPLIEGUE DENEGADO"
        )

        md = [
            f"# Dictamen Interno de Preparación para Producción y Despliegue",
            "Evaluación técnica según la política indicada. No sustituye una certificación externa ni demuestra controles fuera de su alcance.",
            f"",
            f"**ID de Certificado:** `{self.certificate_id}`  ",
            f"**Aplicación:** `{self.application_name}`  ",
            f"**Entorno Destino:** `{self.target_environment.upper()}`  ",
            f"**Fecha y Hora (UTC):** `{self.timestamp}`  ",
            f"**Política de Cumplimiento:** `{self.policy_name}`  ",
            f"",
            f"---",
            f"",
            f"## Veredicto de Despliegue: **{verdict_icon}**",
            f"",
            f"| Métrica Clave | Valor | Estado |",
            f"| :--- | :--- | :--- |",
            f"| **Puntuación de Preparación (Readiness Score)** | **{self.readiness_score:.1f} / 100.0** | {'CONFORME' if self.readiness_score >= 85 else 'ATENCION'} |",
            f"| **Comprobaciones Totales** | {self.total_checks} | - |",
            f"| **Comprobaciones Superadas** | {self.passed_checks_count} | - |",
            f"| **Bloqueadores Críticos (Blockers)** | **{self.blockers_count}** | {'0 (LIMPIO)' if self.blockers_count == 0 else 'BLOQUEANTE'} |",
            f"| **Advertencias No-Bloqueantes** | {self.warnings_count} | Informativo |",
            f"",
            f"---",
            f"",
            f"## Matriz Detallada de Controles de Despliegue",
            f"",
            f"| ID Control | Categoría | Nombre del Control | Veredicto | Impacto |",
            f"| :--- | :--- | :--- | :--- | :--- |",
        ]

        for g in self.gate_results:
            status_tag = "**APROBADO**" if g.passed else ("**BLOQUEANTE**" if g.is_blocker else "*ADVERTENCIA*")
            impact = "Bloquea Deploy" if g.is_blocker else "Advisory"
            md.append(f"| `{g.gate_id}` | `{g.category.value}` | {g.title} | {status_tag} | {impact} |")

        blockers = self.get_blockers()
        if blockers:
            md.extend([
                f"",
                f"---",
                f"",
                f"## Elementos Bloqueantes que Impiden el Despliegue ({len(blockers)})",
                f"",
            ])
            for b in blockers:
                md.append(f"### [X] {b.gate_id}: {b.title}")
                md.append(f"- **Mensaje:** {b.message}")
                if b.remediation:
                    md.append(f"- **Acción de Remediación Obligatoria:** {b.remediation}")
                md.append("")
        else:
            md.extend([
                f"",
                f"> [!NOTE]",
                f"> **CERO BLOQUEADORES IDENTIFICADOS:** El software cumple con todos los controles estrictos de seguridad, calidad de pruebas, privacidad de datos e infraestructura para su puesta en producción.",
                f"",
            ])

        md.extend([
            f"---",
            f"",
            f"## Integridad del dictamen (HMAC; clave compartida)",
            f"```",
            f"HMAC-SHA256: {self.tamper_proof_signature}",
            f"```",
            f"*Dictamen interno. Firma: {'presente' if self.tamper_proof_signature else 'ausente; no verificable'}.*",
        ])

        return "\n".join(md)


class ProductionReadinessCertifier:
    """
    Evaluates scan reports, test metrics, code files and configuration to determine
    whether an application meets enterprise standards to be released to production.
    """

    def __init__(
        self,
        policy_config: Optional[ProductionPolicyConfig] = None,
        signing_key: Optional[str] = None,
    ):
        self.policy = policy_config or ProductionPolicyConfig.default_strict()
        self._read_errors = []
        self.signing_key = (signing_key or os.getenv("CYBERAUDIT_SIGNING_KEY", "")).encode("utf-8")

    def certify(
        self,
        scan_report: Optional[ScanReport] = None,
        test_metrics: Optional[Dict[str, Any]] = None,
        target_path: Optional[str] = None,
        application_name: str = "Target Software",
        target_environment: str = "production",
    ) -> ProductionReleaseCertificate:
        self._read_errors = []
        gate_results: List[GateCheckResult] = []
        gate_results.append(GateCheckResult(
            "GATE-EVIDENCE-SIGNING", "Clave de firma externa configurada", GateCategory.SECURITY_VULNERABILITIES,
            len(self.signing_key) >= 32, True, "Se requiere una clave externa de al menos 32 bytes.",
        ))
        target_exists = bool(target_path and os.path.isdir(target_path))
        gate_results.append(GateCheckResult(
            "GATE-EVIDENCE-TARGET", "Código objetivo disponible", GateCategory.SECURITY_VULNERABILITIES,
            target_exists, True, "Las comprobaciones de código requieren un directorio objetivo existente.",
            status="PASS" if target_exists else "NOT_RUN",
        ))
        bound = bool(scan_report and scan_report.artifact_digest and test_metrics
                     and test_metrics.get("artifact_digest") == scan_report.artifact_digest)
        gate_results.append(GateCheckResult(
            "GATE-EVIDENCE-BINDING", "Métricas vinculadas al artefacto auditado", GateCategory.TEST_AND_QUALITY,
            bound, True, "artifact_digest de las métricas debe coincidir con el reporte del escaneo.",
            status="PASS" if bound else "INCONCLUSIVE",
        ))

        # 1. Evaluate Security Vulnerabilities Gate
        gate_results.extend(self._evaluate_security_vulnerabilities(scan_report))

        # 2. Evaluate Active Secrets & Credentials Gate
        gate_results.extend(self._evaluate_active_secrets(scan_report))

        # 3. Evaluate SCA Reachability Gate
        gate_results.extend(self._evaluate_sca_reachability(scan_report))

        # 4. Evaluate Test & Code Quality Gate
        gate_results.extend(self._evaluate_test_and_quality(test_metrics, target_path))

        # 5. Evaluate Privacy & Compliance (GDPR/HIPAA/PCI-DSS) Gate
        gate_results.extend(self._evaluate_privacy_compliance(scan_report, target_path))

        # 6. Evaluate Container & Infrastructure Gate
        gate_results.extend(self._evaluate_container_and_infra(scan_report, target_path))

        # 7. Evaluate Resilience, Health & Operational Observability Gate
        gate_results.extend(self._evaluate_resilience_and_ops(scan_report, target_path))

        # 8. Evaluate RSC-Harness Governance & Sello Gate (when .rsc.json is present)
        gate_results.extend(self._evaluate_rsc_harness_governance(target_path))

        if self._read_errors:
            gate_results.append(GateCheckResult(
                "GATE-EVIDENCE-READ", "Lectura completa de evidencia", GateCategory.SECURITY_VULNERABILITIES,
                False, True, "; ".join(self._read_errors), status="ERROR",
            ))
        # Compute counts and score
        total_checks = len(gate_results)
        passed_checks = [g for g in gate_results if g.passed]
        blockers = [g for g in gate_results if not g.passed and g.is_blocker]
        warnings = [g for g in gate_results if not g.passed and not g.is_blocker]

        # Score calculation: base 100, minus penalties for failures
        base_score = 100.0
        for g in gate_results:
            if not g.passed:
                penalty = 20.0 if g.is_blocker else 5.0
                base_score -= penalty
        readiness_score = max(0.0, min(100.0, round(base_score, 1)))

        # Determine overall verdict
        if blockers:
            verdict = ReadinessVerdict.DEPLOYMENT_BLOCKED
        elif warnings:
            verdict = ReadinessVerdict.CONDITIONALLY_READY
        else:
            verdict = ReadinessVerdict.READY_FOR_PRODUCTION

        cert_id = f"CERT-PROD-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        evidence = {"scan": scan_report.to_dict() if scan_report else None, "metrics": test_metrics}
        # Metrics validation below prevents malformed numbers from becoming approvals.
        evidence_digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        certificate = ProductionReleaseCertificate(
            certificate_id=cert_id,
            application_name=application_name,
            target_environment=target_environment,
            timestamp=timestamp,
            verdict=verdict,
            readiness_score=readiness_score,
            total_checks=total_checks,
            passed_checks_count=len(passed_checks),
            blockers_count=len(blockers),
            warnings_count=len(warnings),
            gate_results=gate_results,
            tamper_proof_signature="",
            evidence_digest=evidence_digest,
            policy=asdict(self.policy),
        )
        if len(self.signing_key) >= 32:
            certificate.tamper_proof_signature = hmac.new(self.signing_key, certificate.canonical_payload(), hashlib.sha256).hexdigest()
        return certificate

    def _walk_source(self, target_path):
        from cyberaudit.core.engine import AuditEngine
        excluded = AuditEngine.DEFAULT_EXCLUDES | {"tests", "test", "static"}
        for root, dirs, files in os.walk(target_path, onerror=lambda exc: self._read_errors.append(str(exc))):
            dirs[:] = [d for d in dirs if d not in excluded and not d.startswith(".")]
            yield root, dirs, files

    def _evaluate_security_vulnerabilities(self, scan_report: Optional[ScanReport]) -> List[GateCheckResult]:
        results = []
        if not scan_report:
            return [
                GateCheckResult(
                    gate_id="GATE-SEC-REPORT-01",
                    title="Reporte de Auditoría de Seguridad SAST Presente",
                    category=GateCategory.SECURITY_VULNERABILITIES,
                    passed=False,
                    is_blocker=True,
                    message="No se recibió evidencia de escaneo.",
                    status="NOT_RUN",
                )
            ]

        complete = scan_report.execution_status == "PASS" and not scan_report.execution_errors and bool(scan_report.artifact_digest)
        results.append(GateCheckResult(
            "GATE-SEC-COMPLETE", "Escaneo completado sin errores", GateCategory.SECURITY_VULNERABILITIES,
            complete, True, "Se requiere un escaneo completo con digest y sin errores.",
            status="PASS" if complete else "INCONCLUSIVE",
        ))
        criticals = [f for f in scan_report.findings if f.severity == Severity.CRITICAL]
        highs = [f for f in scan_report.findings if f.severity == Severity.HIGH]

        # Check Criticals
        passed_crit = len(criticals) <= self.policy.max_critical_findings
        results.append(GateCheckResult(
            gate_id="GATE-SEC-CRIT-01",
            title="Cero Vulnerabilidades de Severidad CRÍTICA (Zero Criticals)",
            category=GateCategory.SECURITY_VULNERABILITIES,
            passed=passed_crit,
            is_blocker=True,
            message=(
                f"Se detectaron {len(criticals)} vulnerabilidades CRÍTICAS sin resolver."
                if not passed_crit
                else "0 vulnerabilidades CRÍTICAS detectadas."
            ),
            details={"critical_findings": [f.title for f in criticals[:5]]},
            remediation="Remediar inmediatamente todas las fallas críticas (RCE, SQLi, Auth Bypass) antes de deploy.",
        ))

        # Check Highs
        passed_high = len(highs) <= self.policy.max_high_findings
        results.append(GateCheckResult(
            gate_id="GATE-SEC-HIGH-01",
            title="Umbral de Vulnerabilidades de Severidad ALTA (Zero Highs)",
            category=GateCategory.SECURITY_VULNERABILITIES,
            passed=passed_high,
            is_blocker=True,
            message=(
                f"Se detectaron {len(highs)} vulnerabilidades ALTAS (umbral permitido: {self.policy.max_high_findings})."
                if not passed_high
                else f"{len(highs)} vulnerabilidades ALTAS detectadas (dentro del límite)."
            ),
            details={"high_findings": [f.title for f in highs[:5]]},
            remediation="Aplicar parches o emitir excepción de seguridad firmada por CISO.",
        ))

        return results

    def _evaluate_active_secrets(self, scan_report: Optional[ScanReport]) -> List[GateCheckResult]:
        results = []
        if not scan_report:
            return results

        active_secrets = []
        for f in scan_report.findings:
            if "Secret Exposure" in f.title or f.pillar == Pillar.SECURITY_ENGINEER:
                live_status = f.compliance_controls.get("LiveVerification")
                if live_status == "ACTIVE_VERIFIED" or "[LIVE VERIFIED ACTIVE]" in f.title:
                    active_secrets.append(f)

        passed = len(active_secrets) == 0 or self.policy.allow_active_secrets
        results.append(GateCheckResult(
            gate_id="GATE-SEC-ACTIVE-KEYS-01",
            title="Ausencia de Credenciales y Claves Activas de Producción en Código",
            category=GateCategory.ACTIVE_SECRETS_EXPOSURE,
            passed=passed,
            is_blocker=True,
            message=(
                f"ALERTA CRÍTICA: Se detectaron {len(active_secrets)} credenciales confirmadas ACTIVAS en el código fuente."
                if not passed
                else "No se detectaron claves de producción activas en el repositorio."
            ),
            details={"active_secrets_found": [f.title for f in active_secrets]},
            remediation="Revocar inmediatamente las claves en el proveedor y migrar a Secret Manager / Vault.",
        ))

        return results

    def _evaluate_sca_reachability(self, scan_report: Optional[ScanReport]) -> List[GateCheckResult]:
        results = []
        if not scan_report:
            return results

        reachable_cves = []
        for f in scan_report.findings:
            if "SCA-REACHABLE" in f.id or "CONFIRMED_REACHABLE" in f.description:
                reachable_cves.append(f)

        passed = len(reachable_cves) == 0 or self.policy.allow_reachable_sca_cves
        results.append(GateCheckResult(
            gate_id="GATE-SCA-REACHABLE-01",
            title="Ausencia de CVEs Alcanzables en Cadena de Suministro (SCA Reachable)",
            category=GateCategory.SCA_REACHABILITY,
            passed=passed,
            is_blocker=True,
            message=(
                f"Se detectaron {len(reachable_cves)} CVEs con símbolos vulnerables invocados en el código fuente."
                if not passed
                else "No se detectaron dependencias vulnerables con rutas de ejecución alcanzables."
            ),
            details={"reachable_dependencies": [f.title for f in reachable_cves]},
            remediation="Actualizar las bibliotecas de terceros a versiones seguras o descontinuar símbolos afectados.",
        ))

        return results

    def _evaluate_test_and_quality(
        self,
        test_metrics: Optional[Dict[str, Any]],
        target_path: Optional[str] = None,
    ) -> List[GateCheckResult]:
        results = []
        metrics = test_metrics or {}
        required = {"pass_rate": (0, 100), "msi_percentage": (0, 100),
                    "coverage_pct": (0, 100), "tautological_tests_count": (0, float("inf")),
                    "assertion_density": (0, float("inf"))}
        invalid = [key for key, (low, high) in required.items()
                   if type(metrics.get(key)) not in (int, float)
                   or not math.isfinite(metrics[key]) or not low <= metrics[key] <= high]
        if invalid:
            return [GateCheckResult(
                "GATE-QA-EVIDENCE", "Métricas de pruebas completas y válidas", GateCategory.TEST_AND_QUALITY,
                False, True, "Métricas ausentes o inválidas: " + ", ".join(invalid), status="INCONCLUSIVE",
            )]
        results.append(GateCheckResult(
            "GATE-QA-COVERAGE", "Cobertura de código medida", GateCategory.TEST_AND_QUALITY,
            metrics["coverage_pct"] >= self.policy.min_code_coverage_pct, True,
            f"Cobertura: {metrics['coverage_pct']}%; mínimo: {self.policy.min_code_coverage_pct}%.",
        ))

        # 1. Test Pass Rate
        pass_rate = metrics["pass_rate"]
        passed_tests = pass_rate >= self.policy.min_test_pass_rate
        results.append(GateCheckResult(
            gate_id="GATE-QA-PASSRATE-01",
            title="Tasa de Aprobación de la Suite de Pruebas (Test Pass Rate = 100%)",
            category=GateCategory.TEST_AND_QUALITY,
            passed=passed_tests,
            is_blocker=True,
            message=f"Tasa de éxito de pruebas: {pass_rate:.1f}% (Requerido: {self.policy.min_test_pass_rate}%).",
            details={"pass_rate": pass_rate},
            remediation="Corregir todas las pruebas rotas antes de autorizar el despliegue.",
        ))

        # 2. Tautological / Hollow Tests Audit
        tautological_count = metrics.get("tautological_tests_count", 0)
        passed_tauto = tautological_count <= self.policy.max_tautological_tests
        results.append(GateCheckResult(
            gate_id="GATE-QA-ANTITAUTO-01",
            title="Ausencia de Pruebas Tautológicas o Vacías (Anti-Tautology AST)",
            category=GateCategory.TEST_AND_QUALITY,
            passed=passed_tauto,
            is_blocker=True,
            message=(
                f"Se detectaron {tautological_count} pruebas vacías o tautológicas (assert True / pass)."
                if not passed_tauto
                else "0 pruebas tautológicas detectadas; todas las pruebas contienen aserciones semánticas reales."
            ),
            details={"tautological_count": tautological_count},
            remediation="Reemplazar pruebas vacías con aserciones rigurosas que verifiquen lógica de negocio.",
        ))

        # 3. Mutation Score Indicator (MSI)
        msi = metrics["msi_percentage"]
        passed_msi = msi >= self.policy.min_mutation_score_pct
        results.append(GateCheckResult(
            gate_id="GATE-QA-MSI-01",
            title=f"Resistencia a Mutaciones de Código (MSI >= {self.policy.min_mutation_score_pct}%)",
            category=GateCategory.TEST_AND_QUALITY,
            passed=passed_msi,
            is_blocker=True,
            message=f"Mutation Score Indicator: {msi:.1f}% (Umbral requerido: {self.policy.min_mutation_score_pct}%).",
            details={"msi_percentage": msi},
            remediation="Agregar aserciones que exterminen los mutantes sobrevivientes en lógica central.",
        ))

        # 4. Semantic Assertion Density
        density = metrics.get("assertion_density", 2.5)
        passed_density = density >= self.policy.min_assertion_density
        results.append(GateCheckResult(
            gate_id="GATE-QA-DENSITY-01",
            title=f"Densidad Semántica de Aserciones (Densidad >= {self.policy.min_assertion_density} aserciones/test)",
            category=GateCategory.TEST_AND_QUALITY,
            passed=passed_density,
            is_blocker=False,
            message=f"Densidad media de aserciones: {density:.2f} aserciones por prueba.",
            details={"assertion_density": density},
            remediation="Enriquecer las pruebas existentes con verificaciones de estado y contratos defensivos.",
        ))

        return results

    def _evaluate_privacy_compliance(
        self,
        scan_report: Optional[ScanReport],
        target_path: Optional[str] = None,
    ) -> List[GateCheckResult]:
        results = []
        pii_leaks = []
        if scan_report:
            for f in scan_report.findings:
                if "PII" in f.id or "GDPR" in f.title or "PCI-DSS" in f.title:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        pii_leaks.append(f)

        passed = len(pii_leaks) == 0 or self.policy.allow_unmasked_pii_logging
        results.append(GateCheckResult(
            gate_id="GATE-PRIVACY-PII-01",
            title="Protección de Datos Personales y Privacidad (GDPR / HIPAA / PCI-DSS)",
            category=GateCategory.PRIVACY_AND_COMPLIANCE,
            passed=passed,
            is_blocker=True,
            message=(
                f"Se detectaron {len(pii_leaks)} fugas de datos sensibles (DNI, tarjetas, salud) en texto plano hacia logs o red."
                if not passed
                else "Conforme: No se detectaron fugas de datos PII sin enmascarar en sumideros públicos."
            ),
            details={"pii_violations": [f.title for f in pii_leaks]},
            remediation="Enmascarar datos personales antes de enviar a logging o servicios de terceros.",
        ))

        return results

    def _evaluate_container_and_infra(
        self,
        scan_report: Optional[ScanReport],
        target_path: Optional[str] = None,
    ) -> List[GateCheckResult]:
        results = []
        container_issues = []

        if target_path and os.path.exists(target_path):
            # Check Dockerfile for root user
            for root, _, files in self._walk_source(target_path):
                for f in files:
                    if f.lower() in ("dockerfile", "containerfile"):
                        df_path = os.path.join(root, f)
                        try:
                            content = Path(df_path).read_text(encoding="utf-8", errors="ignore")
                            user_lines = [l.strip() for l in content.splitlines() if l.strip().upper().startswith("USER")]
                            user = user_lines[-1].split(maxsplit=1)[-1].split(":", 1)[0].strip().lower() if user_lines else "root"
                            if user in ("root", "0"):
                                container_issues.append(f"{f}: Contenedor configurado para ejecutarse como ROOT.")
                        except Exception as exc:
                            self._read_errors.append(str(exc))

        if scan_report:
            for f in scan_report.findings:
                if "DOCKER" in f.id or "K8S" in f.id:
                    if f.severity in (Severity.CRITICAL, Severity.HIGH):
                        container_issues.append(f.title)

        passed = len(container_issues) == 0
        results.append(GateCheckResult(
            gate_id="GATE-INFRA-CONTAINER-01",
            title="Línea Base de Seguridad en Contenedores y Orquestación (Non-Root / Unprivileged)",
            category=GateCategory.CONTAINER_AND_INFRASTRUCTURE,
            passed=passed,
            is_blocker=self.policy.require_non_root_container,
            message=(
                f"Se detectaron {len(container_issues)} configuraciones inseguras en contenedores/IaC: {'; '.join(container_issues[:2])}"
                if not passed
                else "Configuraciones de contenedor cumplen con la línea base de privilegios mínimos (Non-Root)."
            ),
            details={"container_issues": container_issues},
            remediation="Especificar 'USER nonroot' en Dockerfile y deshabilitar privilegios de root en K8s PodSecurityContext.",
        ))

        return results

    def _evaluate_resilience_and_ops(
        self,
        scan_report: Optional[ScanReport],
        target_path: Optional[str] = None,
    ) -> List[GateCheckResult]:
        results = []
        has_healthcheck = False
        debug_active = False

        if target_path and os.path.exists(target_path):
            for root, _, files in self._walk_source(target_path):
                for f in files:
                    if f.endswith(".py"):
                        py_path = os.path.join(root, f)
                        try:
                            code = Path(py_path).read_text(encoding="utf-8", errors="ignore")
                            if any(endpoint in code for endpoint in ('"/health"', "'/health'", '"/ready"', "'/ready'", '"/live"', "'/live'")):
                                has_healthcheck = True
                            if re.search(r'DEBUG\s*=\s*True', code, re.IGNORECASE) and not "test" in f.lower():
                                debug_active = True
                        except Exception as exc:
                            self._read_errors.append(str(exc))

        # Check Healthcheck
        passed_health = has_healthcheck or not self.policy.require_healthcheck_endpoint
        results.append(GateCheckResult(
            gate_id="GATE-OPS-HEALTH-01",
            title="Sonda de Salud y Disponibilidad Operativa (/health o /ready)",
            category=GateCategory.RESILIENCE_AND_OPS,
            passed=passed_health,
            is_blocker=self.policy.require_healthcheck_endpoint,
            message=(
                "Ruta de healthcheck /health o /ready detectada para Kubernetes/ALB probes."
                if passed_health
                else "No se detectó endpoint de healthcheck (/health o /ready) en el código fuente."
            ),
            details={"has_healthcheck": has_healthcheck},
            remediation="Implementar endpoint GET /health para orquestadores de despliegue y balanceadores de carga.",
        ))

        # Check Debug Mode
        passed_debug = not debug_active or not self.policy.disallow_debug_mode
        results.append(GateCheckResult(
            gate_id="GATE-OPS-DEBUGMODE-01",
            title="Desactivación de Modo Depuración en Producción (DEBUG = False)",
            category=GateCategory.RESILIENCE_AND_OPS,
            passed=passed_debug,
            is_blocker=True,
            message=(
                "ALERTA: Se detectó DEBUG = True configurado en código de producción."
                if not passed_debug
                else "Modo depuración seguro (sin flags de debug activos en producción)."
            ),
            details={"debug_active": debug_active},
            remediation="Configurar DEBUG = False y cargar flags desde variables de entorno para producción.",
        ))

        return results


    def _evaluate_rsc_harness_governance(self, target_path: Optional[str] = None) -> List[GateCheckResult]:
        results: List[GateCheckResult] = []
        if not target_path or not os.path.isdir(target_path):
            return results

        rsc_config = os.path.join(target_path, ".rsc.json")
        if not os.path.isfile(rsc_config):
            return results

        constitution_path = os.path.join(target_path, "02-DOCS", "wiki", "sdd", "constitution.md")
        is_ratified = False
        if os.path.isfile(constitution_path):
            try:
                text = Path(constitution_path).read_text(encoding="utf-8", errors="ignore")
                is_ratified = not bool(re.search(r"^status:\s*draft\b", text, re.MULTILINE | re.IGNORECASE))
            except Exception as exc:
                self._read_errors.append(str(exc))

        results.append(GateCheckResult(
            gate_id="GATE-RSC-CONSTITUTION-01",
            title="Constitución SDD de RSC-Harness Ratificada (02-DOCS/wiki/sdd/constitution.md)",
            category=GateCategory.TEST_AND_QUALITY,
            passed=is_ratified,
            is_blocker=False,
            message=(
                "Constitución SDD de rsc-harness ratificada y activa."
                if is_ratified
                else "La constitución SDD en 02-DOCS/wiki/sdd/constitution.md está ausente o sigue en estado 'draft'."
            ),
            details={"constitution_ratified": is_ratified},
            remediation="Ratificar 02-DOCS/wiki/sdd/constitution.md eliminando 'status: draft' antes de cerrar cambios SDD.",
        ))

        sello_cfg = os.path.join(target_path, ".rsc", "sello-config.json")
        if os.path.isfile(sello_cfg):
            sello_log = os.path.join(target_path, ".rsc", "sello-log.jsonl")
            has_approved_sello = False
            if os.path.isfile(sello_log):
                try:
                    lines = [ln.strip() for ln in Path(sello_log).read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
                    if lines:
                        last_entry = json.loads(lines[-1])
                        has_approved_sello = last_entry.get("status") in ("approved", "APPROVE") or bool(last_entry.get("approved"))
                except Exception:
                    has_approved_sello = False

            results.append(GateCheckResult(
                gate_id="GATE-RSC-SELLO-01",
                title="Sello de Revisión Determinista RSC-Harness (.rsc/sello-log.jsonl)",
                category=GateCategory.TEST_AND_QUALITY,
                passed=has_approved_sello,
                is_blocker=True,
                message=(
                    "Sello de revisión rsc-harness aprobado para el candidato actual."
                    if has_approved_sello
                    else "El proyecto tiene 'rsc sello' activo pero no registra aprobación válida en .rsc/sello-log.jsonl."
                ),
                details={"sello_approved": has_approved_sello},
                remediation="Ejecutar 'npx @ericrisco/rsc sello freeze' y 'npx @ericrisco/rsc sello approve' tras pasar los lentes de revisión.",
            ))

        return results
