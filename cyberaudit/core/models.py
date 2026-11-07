"""
CyberAudit Core Models
Defines foundational data structures for findings, severity levels,
audit pillars, MITRE ATT&CK mapping, and aggregated reports.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime, timezone


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        colors = {
            "CRITICAL": "#ff3366",
            "HIGH": "#ff6600",
            "MEDIUM": "#ffcc00",
            "LOW": "#3399ff",
            "INFO": "#99aab5",
        }
        return colors.get(self.value, "#99aab5")

    @property
    def rank(self) -> int:
        ranks = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        return ranks.get(self.value, 0)


class StrideCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Pillar(str, Enum):
    SECURITY_ANALYST = "Security Analyst & SOC"
    DFIR_ENDPOINT = "DFIR & Endpoint Investigation"
    CLOUD_DEFENSE = "Cloud & Infrastructure Defense"
    PENETRATION_TESTER = "Penetration Tester & AppSec"
    SECURITY_ENGINEER = "Security Engineer & DevSecOps"
    AI_SECURITY = "AI Security & LLM Defenses"
    SOFTWARE_QA = "Software QA & Code Quality"
    UI_UX = "UI/UX & Accessibility (a11y)"
    ARCHITECTURE = "Software Architecture & Governance"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    pillar: Pillar
    scanner_name: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    mitre_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    stride_category: Optional[str] = None
    compliance_controls: Dict[str, str] = field(default_factory=dict)
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    status: str = "OPEN"  # OPEN, RESOLVED, AS_DESIGNED
    status_comment: Optional[str] = None
    status_updated_at: Optional[str] = None

    def __post_init__(self):
        if self.code_snippet and len(self.code_snippet) > 600:
            self.code_snippet = self.code_snippet[:600] + "... [TRUNCATED]"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "pillar": self.pillar.value,
            "scanner_name": self.scanner_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "mitre_id": self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "stride_category": self.stride_category,
            "compliance_controls": self.compliance_controls,
            "confidence": self.confidence,
            "status": self.status,
            "status_comment": self.status_comment,
            "status_updated_at": self.status_updated_at,
        }


@dataclass
class ScanReport:
    target_path: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    duration_seconds: float = 0.0
    files_scanned: int = 0
    scanners_executed: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    executive_summary: Optional[str] = None
    ai_verdict: Optional[str] = None
    ai_provider_used: Optional[str] = None
    execution_status: str = "NOT_RUN"
    execution_errors: List[dict] = field(default_factory=list)
    scanner_results: List[dict] = field(default_factory=list)
    files_discovered: int = 0
    artifact_digest: Optional[str] = None

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def active_findings(self) -> List[Finding]:
        return [f for f in self.findings if (getattr(f, "status", "OPEN") or "OPEN").upper() == "OPEN"]

    @property
    def resolved_findings(self) -> List[Finding]:
        return [f for f in self.findings if getattr(f, "status", "") == "RESOLVED"]

    @property
    def as_designed_findings(self) -> List[Finding]:
        return [f for f in self.findings if getattr(f, "status", "") == "AS_DESIGNED"]

    @property
    def status_counts(self) -> Dict[str, int]:
        counts = {"OPEN": 0, "RESOLVED": 0, "AS_DESIGNED": 0}
        for f in self.findings:
            st = getattr(f, "status", "OPEN") or "OPEN"
            counts[st] = counts.get(st, 0) + 1
        return counts

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def active_severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.active_findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def pillar_counts(self) -> Dict[str, int]:
        counts = {p.value: 0 for p in Pillar}
        for f in self.findings:
            counts[f.pillar.value] = counts.get(f.pillar.value, 0) + 1
        return counts

    @property
    def stride_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in StrideCategory}
        for f in self.findings:
            if f.stride_category:
                counts[f.stride_category] = counts.get(f.stride_category, 0) + 1
        return counts

    @property
    def mitre_matrix(self) -> Dict[str, List[Finding]]:
        matrix: Dict[str, List[Finding]] = {}
        for f in self.findings:
            tactic = f.mitre_tactic or "Uncategorized"
            if tactic not in matrix:
                matrix[tactic] = []
            matrix[tactic].append(f)
        return matrix

    def to_dict(self) -> dict:
        return {
            "target_path": self.target_path,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "scanners_executed": self.scanners_executed,
            "execution_status": self.execution_status,
            "execution_errors": self.execution_errors,
            "scanner_results": self.scanner_results,
            "files_discovered": self.files_discovered,
            "artifact_digest": self.artifact_digest,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "active_severity_counts": self.active_severity_counts,
            "status_counts": self.status_counts,
            "pillar_counts": self.pillar_counts,
            "stride_counts": self.stride_counts,
            "executive_summary": self.executive_summary,
            "ai_verdict": self.ai_verdict,
            "ai_provider_used": self.ai_provider_used,
            "findings": [f.to_dict() for f in self.findings],
        }

