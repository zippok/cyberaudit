"""
CyberAudit Kali Audit Orchestrator
Turns an authorized engagement scope plus a target into a deterministic, reproducible
sequence of Kali tool executions, and consolidates the parsed output into a platform
:class:`~cyberaudit.core.models.ScanReport`.

Responsibilities:
- Target classification (URL / host / CIDR) and scheme probing.
- Profile → tool-plan resolution with risk gating (INTRUSIVE tools need explicit opt-in).
- Sequential execution through :class:`~cyberaudit.kali.executor.KaliExecutor`.
- Artifact retrieval and parsing through :mod:`cyberaudit.kali.parsers`.
- Coverage accounting: every requested tool ends up as executed, skipped, failed or
  blocked, with an actionable reason and install hint. Nothing fails silently.

Two entry points exist:
- :meth:`KaliAuditOrchestrator.audit` — deterministic full-profile sweep.
- :class:`KaliSession` — step-by-step API used by the autonomous agent, which decides
  tool-by-tool what to run next while this module keeps enforcing scope and parsing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from cyberaudit.core.models import ScanReport
from cyberaudit.kali.executor import KaliExecutionDisabled, KaliExecutor, KaliRunResult
from cyberaudit.kali.findings import observations_to_findings
from cyberaudit.kali.parsers import ToolObservation, parse_tool_output
from cyberaudit.kali.scope import ScopeAuthorization, ScopeGuard, ScopeViolationError
from cyberaudit.kali.tool_registry import (
    BINARY_ARTIFACTS,
    KALI_TOOLS,
    TOOL_ARTIFACTS,
    KaliTool,
    KaliToolError,
    RiskLevel,
    ToolRequest,
    ToolStatus,
    build_command,
    resolve_default_wordlist,
)

logger = logging.getLogger("cyberaudit.kali.orchestrator")

MAX_ARTIFACT_READ_BYTES = 8 * 1024 * 1024


# ── Profiles ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KaliProfile:
    key: str
    title: str
    description: str
    tools: Tuple[str, ...]
    risk: RiskLevel
    audit_label: str


_RECON_TOOLS = ("nmap", "dnsrecon", "amass", "whatweb", "wafw00f", "httpx")
_WEB_TOOLS = ("testssl", "feroxbuster", "httpx", "whatweb", "wafw00f", "sslscan", "nikto", "nuclei", "gobuster", "ffuf", "dirb", "wpscan")
_INFRA_TOOLS = ("testssl", "nmap", "sslscan", "nbtscan", "enum4linux", "smbclient", "nxc", "snmpwalk", "onesixtyone", "smtp_user_enum", "nuclei")
_AD_TOOLS = ("nbtscan", "enum4linux", "smbclient", "nxc", "impacket_secretsdump", "responder")
_INTRUSIVE_TOOLS = ("sqlmap", "commix", "hydra", "john", "hashcat")
_FORENSIC_TOOLS = ("tcpdump", "tshark")
_WIRELESS_TOOLS = ("airodump_ng", "aircrack_ng")


def _dedupe(sequence: Sequence[str]) -> Tuple[str, ...]:
    seen: Dict[str, None] = {}
    for item in sequence:
        seen.setdefault(item, None)
    return tuple(seen.keys())


KALI_PROFILES: Dict[str, KaliProfile] = {
    "recon": KaliProfile(
        key="recon", title="Reconocimiento",
        description="Enumeración DNS/OSINT, fingerprinting de tecnologías y descubrimiento de superficie expuesta.",
        tools=_dedupe(_RECON_TOOLS), risk=RiskLevel.ACTIVE,
        audit_label="Auditoría de reconocimiento y superficie de exposición",
    ),
    "web": KaliProfile(
        key="web", title="Auditoría Web (DAST)",
        description="Escaneo de aplicaciones web: servidor, CMS, contenido oculto, plantillas CVE y TLS.",
        tools=_dedupe(_WEB_TOOLS), risk=RiskLevel.ACTIVE,
        audit_label="Auditoría de aplicación web (DAST)",
    ),
    "infra": KaliProfile(
        key="infra", title="Infraestructura y Servicios",
        description="Puertos, servicios, SMB/Samba, SNMP, SMTP y configuración criptográfica del perímetro.",
        tools=_dedupe(_INFRA_TOOLS), risk=RiskLevel.ACTIVE,
        audit_label="Auditoría de infraestructura y servicios de red",
    ),
    "ad": KaliProfile(
        key="ad", title="Active Directory & SMB",
        description="Enumeración SMB/NetBIOS/AD: usuarios, recursos, políticas y configuración de seguridad del dominio.",
        tools=_dedupe(_AD_TOOLS), risk=RiskLevel.ACTIVE,
        audit_label="Auditoría de Active Directory y SMB",
    ),
    "intrusive": KaliProfile(
        key="intrusive", title="Verificación Intrusiva (explotación)",
        description="Confirmación empírica de exploits y robustez de credenciales. Requiere autorización explícita.",
        tools=_dedupe(_INTRUSIVE_TOOLS), risk=RiskLevel.INTRUSIVE,
        audit_label="Verificación intrusiva de vulnerabilidades",
    ),
    "forensic": KaliProfile(
        key="forensic", title="Forense de Tráfico",
        description="Captura acotada de tráfico (PCAP) como evidencia forense del segmento auditado.",
        tools=_dedupe(_FORENSIC_TOOLS), risk=RiskLevel.INTRUSIVE,
        audit_label="Captura forense de tráfico de red",
    ),
    "wireless": KaliProfile(
        key="wireless", title="Redes Inalámbricas (802.11)",
        description="Captura 802.11 y auditoría offline de claves Wi-Fi sobre capturas autorizadas.",
        tools=_dedupe(_WIRELESS_TOOLS), risk=RiskLevel.INTRUSIVE,
        audit_label="Auditoría de red inalámbrica 802.11",
    ),
    "osint": KaliProfile(
        key="osint", title="OSINT & Exploit-DB",
        description="Descubrimiento pasivo de activos y correlación local con la base de datos de exploits.",
        tools=("amass", "dnsrecon", "searchsploit"), risk=RiskLevel.PASSIVE,
        audit_label="Auditoría OSINT y correlación de exploits",
    ),
    "full": KaliProfile(
        key="full", title="Auditoría Completa (no intrusiva)",
        description="Reconocimiento + servicios de infraestructura + auditoría web, sin acciones intrusivas.",
        tools=_dedupe(_RECON_TOOLS + _INFRA_TOOLS + _WEB_TOOLS), risk=RiskLevel.ACTIVE,
        audit_label="Auditoría integral externa (recon + infra + web)",
    ),
    "all": KaliProfile(
        key="all", title="Todas las herramientas registradas",
        description="Ejecuta el catálogo completo de herramientas compatibles con el objetivo (las intrusivas requieren autorización).",
        tools=tuple(KALI_TOOLS.keys()), risk=RiskLevel.INTRUSIVE,
        audit_label="Auditoría con catálogo completo de herramientas Kali",
    ),
}

WEB_TOOL_KEYS = {
    "feroxbuster",
    "whatweb", "wafw00f", "httpx", "nikto", "nuclei", "gobuster", "ffuf", "dirb", "wpscan", "sqlmap", "commix",
}
LOCAL_ONLY_TOOL_KEYS = {"john", "hashcat", "searchsploit"}


# ── Target classification ────────────────────────────────────────────────────

@dataclass
class TargetInfo:
    original: str
    host: str
    kind: str  # "web" | "host" | "cidr"
    url: Optional[str] = None
    scheme: str = "https"
    port: Optional[int] = None
    resolved_ips: List[str] = field(default_factory=list)

    @property
    def web_url(self) -> Optional[str]:
        if self.url:
            return self.url
        if self.kind in ("host", "web") and self.host:
            suffix = f":{self.port}" if self.port and self.port not in (80, 443) else ""
            return f"{self.scheme}://{self.host}{suffix}"
        return None

    def label(self) -> str:
        return self.url or (f"{self.host}/{self.port}" if self.port else self.host or self.original)


def _probe_scheme(host: str, port: Optional[int] = None, timeout: float = 2.0) -> str:
    """Detects whether the target speaks TLS on 443 or plain HTTP on 80 (bounded TCP connect)."""
    candidates: List[Tuple[str, int]] = []
    if port:
        candidates.append(("https" if port in (443, 8443) else "http", port))
    candidates.extend([("https", 443), ("http", 80)])
    for scheme, candidate_port in candidates:
        try:
            with socket.create_connection((host, candidate_port), timeout=timeout):
                return scheme
        except OSError:
            continue
    return "https"


def classify_target(target: str, probe: bool = True) -> TargetInfo:
    """Normalizes a raw CLI target into host/URL/CIDR coordinates."""
    from cyberaudit.core.target_verifier import TargetVerifier

    raw = (target or "").strip()
    if not raw:
        raise ScopeViolationError("El objetivo no puede estar vacío.")

    host, port = TargetVerifier.extract_host(raw)
    if "/" in host and "://" not in raw:
        return TargetInfo(original=raw, host=host, kind="cidr", port=port)

    if "://" in raw:
        from urllib.parse import urlparse

        parsed = urlparse(raw)
        return TargetInfo(
            original=raw,
            host=parsed.hostname or host,
            kind="web",
            url=raw,
            scheme=parsed.scheme or "https",
            port=parsed.port,
        )

    is_ip = host.count(".") == 3 and all(part.isdigit() for part in host.split("."))
    scheme = "https"
    if probe and not is_ip:
        scheme = _probe_scheme(host, port)
    return TargetInfo(original=raw, host=host, kind="host", scheme=scheme, port=port)


# ── Coverage & result containers ─────────────────────────────────────────────

@dataclass
class CoverageEntry:
    tool_key: str
    tool_title: str
    status: str  # executed | planned | skipped | failed | blocked
    risk: str = ""
    reason: str = ""
    install_hint: str = ""
    command: str = ""
    findings: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_key": self.tool_key,
            "tool_title": self.tool_title,
            "status": self.status,
            "risk": self.risk,
            "reason": self.reason,
            "install_hint": self.install_hint,
            "command": self.command,
            "findings": self.findings,
        }


def observation_to_dict(observation: ToolObservation) -> Dict[str, Any]:
    return {
        "tool": observation.tool_key,
        "title": observation.title,
        "severity": observation.severity.value,
        "host": observation.host,
        "port": observation.port,
        "cve": observation.cve_id,
        "cwe": observation.cwe_id,
        "evidence": observation.evidence,
    }


@dataclass
class KaliAuditResult:
    """Complete outcome of a Kali-driven engagement step."""

    target: str
    profile: str
    report: ScanReport
    observations: List[ToolObservation] = field(default_factory=list)
    runs: List[KaliRunResult] = field(default_factory=list)
    coverage: List[CoverageEntry] = field(default_factory=list)
    scope_authorization: Dict[str, Any] = field(default_factory=dict)
    artifacts_dir: str = ""
    audit_trail_path: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    dry_run: bool = False
    agent_trace: List[Dict[str, Any]] = field(default_factory=list)
    plan: List[Dict[str, Any]] = field(default_factory=list)
    ai_summary: Optional[str] = None

    @property
    def findings_count(self) -> int:
        return len(self.report.findings)

    def summary(self) -> Dict[str, Any]:
        executed = [entry for entry in self.coverage if entry.status == "executed"]
        return {
            "target": self.target,
            "profile": self.profile,
            "tools_executed": len(executed),
            "tools_total": len(self.coverage),
            "findings": self.findings_count,
            "severity_counts": self.report.severity_counts,
            "duration_seconds": self.duration_seconds,
            "artifacts_dir": self.artifacts_dir,
            "audit_trail_path": self.audit_trail_path,
            "dry_run": self.dry_run,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "dry_run": self.dry_run,
            "scope_authorization": self.scope_authorization,
            "artifacts_dir": self.artifacts_dir,
            "audit_trail_path": self.audit_trail_path,
            "summary": self.summary(),
            "plan": self.plan,
            "coverage": [entry.to_dict() for entry in self.coverage],
            "runs": [run.to_dict() for run in self.runs],
            "observations": [observation_to_dict(obs) for obs in self.observations],
            "agent_trace": self.agent_trace,
            "ai_summary": self.ai_summary,
            "report": self.report.to_dict(),
        }


# ── Session (step-by-step API used by the autonomous agent) ──────────────────

@dataclass
class KaliSession:
    """Mutable, scope-authorized execution context for one target."""

    target_info: TargetInfo
    authorization: ScopeAuthorization
    executor: KaliExecutor
    work_dir: str
    profile: str
    allow_intrusive: bool
    dry_run: bool
    wordlist: Optional[str] = None
    ports: Optional[str] = None
    extras: Dict[str, str] = field(default_factory=dict)
    coverage: List[CoverageEntry] = field(default_factory=list)
    runs: List[KaliRunResult] = field(default_factory=list)
    observations: List[ToolObservation] = field(default_factory=list)
    executed_tools: List[str] = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)
    started_at: str = field(default_factory=lambda: _now_utc())
    correlation_terms: List[str] = field(default_factory=list)

    @property
    def elapsed_seconds(self) -> float:
        return round(time.monotonic() - self.started, 2)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "target")).strip("_")[:60] or "target"


def _int_or(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


class KaliAuditOrchestrator:
    """Coordinates scope-validated Kali tool execution and result normalization."""

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        executor: Optional[KaliExecutor] = None,
        artifacts_root: Optional[str] = None,
        statuses: Optional[Dict[str, ToolStatus]] = None,
        progress: Optional[Callable[[str], None]] = None,
    ):
        self.scope_guard = scope_guard or ScopeGuard.from_file()
        self.artifacts_root = os.path.realpath(
            artifacts_root or os.getenv("CYBERAUDIT_KALI_ARTIFACTS", os.path.join(os.getcwd(), "reports", "kali"))
        )
        self._executor = executor
        self.progress = progress or (lambda message: logger.info("%s", message))
        self._statuses = statuses

    # ── Discovery helper ─────────────────────────────────────────────────────
    @property
    def statuses(self) -> Dict[str, ToolStatus]:
        if self._statuses is None:
            from cyberaudit.kali.tool_registry import tool_status_map

            self._statuses = tool_status_map()
        return self._statuses

    def available_tools(self, candidates: Sequence[str]) -> List[str]:
        """Filters a candidate list down to the binaries actually present in this system."""
        return [key for key in candidates if key in self.statuses and self.statuses[key].available]

    # ── Planning ─────────────────────────────────────────────────────────────
    def resolve_tools(self, profile: str, tools: Optional[Sequence[str]] = None) -> List[str]:
        if tools:
            resolved: List[str] = []
            for key in tools:
                normalized = str(key).strip().lower()
                if normalized not in KALI_TOOLS:
                    raise KaliToolError(
                        f"Herramienta desconocida: {key!r}. Disponibles: {', '.join(sorted(KALI_TOOLS))}"
                    )
                resolved.append(normalized)
            return resolved
        spec = KALI_PROFILES.get(profile)
        if spec is None:
            raise KaliToolError(
                f"Perfil desconocido: {profile!r}. Perfiles disponibles: {', '.join(sorted(KALI_PROFILES))}"
            )
        return list(spec.tools)

    def build_plan(
        self,
        target_info: TargetInfo,
        tool_keys: Sequence[str],
        allow_intrusive: bool,
        work_dir: str,
        wordlist: Optional[str] = None,
        ports: Optional[str] = None,
        extras: Optional[Dict[str, str]] = None,
        profile: str = "full",
    ) -> List[Dict[str, Any]]:
        """Builds the ordered execution plan without running anything."""
        plan: List[Dict[str, Any]] = []
        merged_extras: Dict[str, str] = dict(extras or {})
        if profile in ("infra", "full", "all") and "nmap_vuln" not in merged_extras:
            merged_extras["nmap_vuln"] = "true"

        for key in tool_keys:
            tool = KALI_TOOLS.get(key)
            if tool is None:
                continue
            status = self.statuses.get(key)
            if status is None or not status.available:
                plan.append({
                    "tool": key, "title": tool.title, "status": "skipped", "risk": tool.risk.value,
                    "reason": (status.notes if status else "Herramienta no registrada en el sistema."),
                    "install_hint": tool.install_hint, "command": "",
                })
                continue
            if tool.risk is RiskLevel.INTRUSIVE and not allow_intrusive:
                plan.append({
                    "tool": key, "title": tool.title, "status": "skipped", "risk": tool.risk.value,
                    "reason": "Herramienta intrusiva: requiere --allow-intrusive (y allow_intrusive en el alcance).",
                    "install_hint": "", "command": "",
                })
                continue
            if key in LOCAL_ONLY_TOOL_KEYS and not (
                merged_extras.get("hash_file") or merged_extras.get("term") or merged_extras.get("search_term")
            ):
                plan.append({
                    "tool": key, "title": tool.title, "status": "skipped", "risk": tool.risk.value,
                    "reason": "Requiere material de entrada (--hash-file para cracking, --search para Exploit-DB).",
                    "install_hint": "", "command": "",
                })
                continue
            if key in WEB_TOOL_KEYS and not target_info.web_url:
                plan.append({
                    "tool": key, "title": tool.title, "status": "skipped", "risk": tool.risk.value,
                    "reason": "Se requiere un objetivo HTTP(S) (--url o un target con esquema http/https).",
                    "install_hint": "", "command": "",
                })
                continue

            request = self._build_request(target_info, tool, work_dir, wordlist, ports, merged_extras)
            try:
                argv = build_command(key, request)
            except KaliToolError as exc:
                plan.append({
                    "tool": key, "title": tool.title, "status": "skipped", "risk": tool.risk.value,
                    "reason": str(exc), "install_hint": tool.install_hint, "command": "",
                })
                continue
            plan.append({
                "tool": key, "title": tool.title, "status": "planned", "risk": tool.risk.value,
                "reason": "", "install_hint": "", "command": " ".join(argv),
                "request": request, "argv": argv, "timeout": tool.default_timeout,
            })
        return plan

    def _build_request(
        self,
        target_info: TargetInfo,
        tool: KaliTool,
        work_dir: str,
        wordlist: Optional[str],
        ports: Optional[str],
        extras: Dict[str, str],
    ) -> ToolRequest:
        request = ToolRequest(
            target=target_info.original,
            host=target_info.host,
            work_dir=work_dir,
            url=target_info.web_url if tool.key in WEB_TOOL_KEYS else None,
            scheme=target_info.scheme,
            port=target_info.port,
            ports=ports,
            wordlist=wordlist or extras.get("wordlist") or None,
            userlist=extras.get("userlist") or None,
            passlist=extras.get("passlist") or None,
            hash_file=extras.get("hash_file") or None,
            capture_file=extras.get("capture_file") or None,
            community_file=extras.get("community_file") or None,
            service=extras.get("service") or "ssh",
            term=extras.get("term") or extras.get("search_term") or None,
            sudo=str(extras.get("sudo", "")).lower() in ("1", "true", "yes"),
            threads=_int_or(extras.get("threads"), 10),
            rate_limit=_int_or(extras.get("rate_limit"), 50),
            timeout_seconds=_int_or(extras.get("tool_timeout"), tool.default_timeout) or tool.default_timeout,
            duration_seconds=_int_or(extras.get("duration_seconds"), 30),
            severity_filter=extras.get("severity_filter") or "critical,high,medium",
            extras=dict(extras),
        )
        if tool.key in ("ffuf", "gobuster", "dirb") and not request.wordlist:
            request.wordlist = resolve_default_wordlist()
        return request

    # ── Session lifecycle ────────────────────────────────────────────────────
    def start_session(
        self,
        target: str,
        profile: str = "full",
        tools: Optional[Sequence[str]] = None,
        dry_run: bool = False,
        allow_intrusive: bool = False,
        wordlist: Optional[str] = None,
        ports: Optional[str] = None,
        extras: Optional[Dict[str, str]] = None,
        probe_scheme: bool = True,
        session_label: Optional[str] = None,
    ) -> KaliSession:
        """Validates scope and prepares the artifacts workspace for one target."""
        tool_keys = self.resolve_tools(profile, tools)
        target_info = classify_target(target, probe=False)

        risk_ceiling = max(
            (KALI_TOOLS[key].risk.rank for key in tool_keys if key in KALI_TOOLS),
            default=RiskLevel.ACTIVE.rank,
        )
        effective_risk = (
            RiskLevel.INTRUSIVE if (risk_ceiling >= RiskLevel.INTRUSIVE.rank and allow_intrusive) else RiskLevel.ACTIVE
        )

        authorization = self.scope_guard.authorize(target, effective_risk)
        self.scope_guard.authorize_local_floor(target)
        if probe_scheme and not dry_run:
            target_info = classify_target(target, probe=True)

        work_dir = os.path.join(
            self.artifacts_root,
            f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}_{_safe_slug(session_label or target_info.host)}_{uuid.uuid4().hex[:12]}",
        )
        os.makedirs(work_dir, exist_ok=True)

        executor = self._executor or KaliExecutor(
            work_dir=work_dir,
            dry_run=dry_run,
            require_authorization=authorization.to_dict(),
        )
        if dry_run:
            executor.dry_run = True

        return KaliSession(
            target_info=target_info,
            authorization=authorization,
            executor=executor,
            work_dir=work_dir,
            profile=profile,
            allow_intrusive=allow_intrusive,
            dry_run=dry_run,
            wordlist=wordlist,
            ports=ports,
            extras=dict(extras or {}),
        )

    def plan_for(
        self,
        session: KaliSession,
        tool_keys: Sequence[str],
    ) -> List[Dict[str, Any]]:
        return self.build_plan(
            target_info=session.target_info,
            tool_keys=tool_keys,
            allow_intrusive=session.allow_intrusive,
            work_dir=session.work_dir,
            wordlist=session.wordlist,
            ports=session.ports,
            extras=session.extras,
            profile=session.profile,
        )

    def execute_steps(self, session: KaliSession, plan: Sequence[Dict[str, Any]]) -> None:
        """Executes each planned step, mutating the session with runs and observations."""
        for step in plan:
            self.execute_step(session, step)

    def execute_step(self, session: KaliSession, step: Dict[str, Any]) -> Optional[CoverageEntry]:
        """Executes a single plan step (used by both the sweep and the autonomous agent)."""
        key = step["tool"]
        tool = KALI_TOOLS[key]

        if step.get("status") == "skipped":
            entry = CoverageEntry(
                tool_key=key, tool_title=step["title"], status="skipped", risk=step["risk"],
                reason=step.get("reason", ""), install_hint=step.get("install_hint", ""),
            )
            session.coverage.append(entry)
            session.runs.append(session.executor.skipped(tool, step.get("reason", "")))
            return entry

        argv: List[str] = step["argv"]
        self.scope_guard.authorize(session.target_info.original, tool.risk)
        step_dir = os.path.join(session.work_dir, f"{key}_{uuid.uuid4().hex}")
        os.makedirs(step_dir, exist_ok=True)
        if step.get("request") is not None:
            request = replace(step["request"], work_dir=step_dir)
            argv = build_command(key, request)
        if key == "onesixtyone":
            community_path = os.path.join(session.work_dir, "snmp_communities.txt")
            if not os.path.isfile(community_path):
                self._write_community_list(community_path)

        entry = CoverageEntry(
            tool_key=key, tool_title=tool.title, status="planned", risk=step["risk"],
            command=" ".join(argv),
        )
        try:
            run = session.executor.run(tool, argv, timeout=step["timeout"], artifact_paths=self._expected_artifacts(key, step_dir))
        except (KaliExecutionDisabled, OSError) as exc:
            entry.status = "blocked"
            entry.reason = str(exc)
            session.coverage.append(entry)
            return entry

        session.runs.append(run)
        session.executed_tools.append(key)

        if run.dry_run:
            session.coverage.append(entry)
            return entry

        if run.skip_reason:
            entry.status = "skipped"
            entry.reason = run.skip_reason
            session.coverage.append(entry)
            return entry

        try:
            content, artifact_path = self._read_tool_output(key, run, step_dir)
            if artifact_path and content:
                extension = os.path.splitext(artifact_path)[1]
                if extension == ".xml":
                    ET.fromstring(content)
                elif extension == ".json":
                    json.loads(content)
                elif extension == ".jsonl":
                    for line in content.splitlines():
                        if line.strip():
                            json.loads(line)
            tool_observations = parse_tool_output(
                key, content, session.target_info.label(),
                artifact_path=artifact_path,
                allow_plain_fallback=run.returncode in (0, None) and not run.timed_out,
                strict=True,
            )
        except Exception as exc:
            entry.status = "failed"
            entry.reason = f"Evidencia no interpretable: {exc}"
            session.coverage.append(entry)
            return entry
        session.observations.extend(tool_observations)
        entry.findings = len(tool_observations)

        if run.error:
            entry.status = "failed"
            entry.reason = run.error
        elif run.timed_out:
            entry.status = "failed"
            entry.reason = f"Timeout: se conservaron {len(tool_observations)} observaciones parciales."
        elif run.returncode not in (0, None):
            entry.status = "failed"
            entry.reason = (run.stderr or "").strip()[:400] or f"El proceso terminó con código {run.returncode}."
        else:
            entry.status = "executed"
        session.coverage.append(entry)
        return entry

    def correlate_exploits(self, session: KaliSession, terms: Optional[Sequence[str]] = None) -> List[ToolObservation]:
        """Correlates detected technologies with the local Exploit-DB mirror."""
        status = self.statuses.get("searchsploit")
        if status is None or not status.available:
            return []

        resolved_terms: List[str] = [term for term in (terms or []) if term]
        if not resolved_terms:
            explicit = session.extras.get("term") or session.extras.get("search_term")
            if explicit:
                resolved_terms.append(explicit)
            else:
                for observation in session.observations:
                    if observation.tool_key not in ("whatweb", "httpx", "nuclei", "wpscan", "nikto"):
                        continue
                    for token in _technology_terms(observation):
                        if token not in resolved_terms:
                            resolved_terms.append(token)
        resolved_terms = resolved_terms[:3]
        if not resolved_terms:
            return []

        tool = KALI_TOOLS["searchsploit"]
        collected: List[ToolObservation] = []
        for term in resolved_terms:
            step = {
                "tool": "searchsploit", "title": tool.title, "status": "planned",
                "risk": tool.risk.value, "reason": "", "install_hint": "",
            }
            request = ToolRequest(
                target=session.target_info.original, host=session.target_info.host,
                work_dir=session.work_dir, term=term, extras={"term": term},
            )
            try:
                argv = build_command("searchsploit", request)
            except KaliToolError as exc:
                session.coverage.append(CoverageEntry(
                    tool_key="searchsploit", tool_title=tool.title, status="skipped",
                    risk=tool.risk.value, reason=f"Correlación de exploits omitida: {exc}",
                ))
                continue
            step["argv"] = argv
            step["request"] = request
            step["timeout"] = tool.default_timeout
            step["command"] = " ".join(argv)
            entry = self.execute_step(session, step)
            if entry is not None and entry.status == "executed":
                entry.reason = f"Correlación con Exploit-DB para '{term}'"
                collected.extend([
                    obs for obs in session.observations if obs.tool_key == "searchsploit" and term in obs.title.lower()
                ])
        if resolved_terms:
            session.correlation_terms = resolved_terms
        return collected

    def finalize(
        self,
        session: KaliSession,
        dry_run: Optional[bool] = None,
        agent_trace: Optional[List[Dict[str, Any]]] = None,
        plan_snapshot: Optional[List[Dict[str, Any]]] = None,
        ai_summary: Optional[str] = None,
    ) -> KaliAuditResult:
        """Consolidates the session into a persisted :class:`KaliAuditResult`."""
        findings = observations_to_findings(session.observations)
        duration = session.elapsed_seconds
        report = ScanReport(
            target_path=session.target_info.label(),
            timestamp=_now_utc(),
            duration_seconds=duration,
            files_scanned=len([entry for entry in session.coverage if entry.status == "executed"]),
            scanners_executed=[entry.tool_key for entry in session.coverage if entry.status == "executed"],
            execution_status=("NOT_RUN" if session.dry_run else "PASS" if session.coverage and all(e.status == "executed" for e in session.coverage) else "INCONCLUSIVE"),
            scanner_results=[e.to_dict() for e in session.coverage],
            execution_errors=[e.to_dict() for e in session.coverage if e.status in ("failed", "blocked")],
            findings=findings,
        )
        if ai_summary:
            report.executive_summary = ai_summary
            report.ai_verdict = ai_summary

        result = KaliAuditResult(
            target=session.target_info.label(),
            profile=session.profile,
            report=report,
            observations=session.observations,
            runs=session.runs,
            coverage=session.coverage,
            scope_authorization=session.authorization.to_dict(),
            artifacts_dir=session.work_dir,
            audit_trail_path=session.executor.audit_trail_path,
            started_at=session.started_at,
            finished_at=_now_utc(),
            duration_seconds=duration,
            dry_run=session.dry_run if dry_run is None else dry_run,
            agent_trace=list(agent_trace or []),
            plan=list(plan_snapshot or []),
            ai_summary=ai_summary,
        )
        self._persist_result(result)
        return result

    # ── Deterministic sweep ──────────────────────────────────────────────────
    def audit(
        self,
        target: str,
        profile: str = "full",
        tools: Optional[Sequence[str]] = None,
        dry_run: bool = False,
        allow_intrusive: bool = False,
        wordlist: Optional[str] = None,
        ports: Optional[str] = None,
        extras: Optional[Dict[str, str]] = None,
        probe_scheme: bool = True,
        run_exploit_correlation: bool = True,
    ) -> KaliAuditResult:
        """Runs the resolved tool plan against a single authorized target."""
        session = self.start_session(
            target=target,
            profile=profile,
            tools=tools,
            dry_run=dry_run,
            allow_intrusive=allow_intrusive,
            wordlist=wordlist,
            ports=ports,
            extras=extras,
            probe_scheme=probe_scheme,
        )
        plan = self.plan_for(session, self.resolve_tools(profile, tools))
        for step in plan:
            if step.get("status") == "planned":
                self.progress(f"Ejecutando {step['title']} …")
            self.execute_step(session, step)

        if run_exploit_correlation and not dry_run:
            self.correlate_exploits(session)

        return self.finalize(session)

    # ── Helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _write_community_list(path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("public\nprivate\ncommunity\nmanager\nadmin\ncisco\nsnmp\n")

    @staticmethod
    def _expected_artifacts(tool_key: str, work_dir: str) -> List[str]:
        filename = TOOL_ARTIFACTS.get(tool_key)
        return [os.path.join(work_dir, filename)] if filename else []

    @staticmethod
    def _read_tool_output(tool_key: str, run: KaliRunResult, work_dir: str) -> Tuple[str, Optional[str]]:
        """Returns (text to parse, artifact path used)."""
        filename = TOOL_ARTIFACTS.get(tool_key)
        if filename:
            path = os.path.join(work_dir, filename)
            if filename in BINARY_ARTIFACTS:
                return (path if os.path.isfile(path) else ""), path
            if os.path.isfile(path):
                try:
                    if os.path.getsize(path) > MAX_ARTIFACT_READ_BYTES:
                        raise ValueError("El artefacto excede el límite de lectura del parser")
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        return handle.read(), path
                except OSError as exc:
                    raise OSError(f"No se pudo leer el artefacto {path}: {exc}") from exc
        if tool_key == "hashcat":
            return run.stdout, os.path.join(work_dir, "hashcat.potfile")
        return run.stdout, None

    @staticmethod
    def _persist_result(result: KaliAuditResult) -> None:
        try:
            os.makedirs(result.artifacts_dir, exist_ok=True)
            with open(os.path.join(result.artifacts_dir, "kali_result.json"), "w", encoding="utf-8") as handle:
                json.dump(result.to_dict(), handle, ensure_ascii=False, indent=2)
        except OSError as exc:  # pragma: no cover
            raise OSError(f"No se pudo persistir el resultado de la auditoría Kali: {exc}") from exc


_TECH_STOPWORDS = {
    "http", "https", "html", "the", "and", "with", "server", "title", "url", "index", "page",
    "welcome", "default", "untitled", "document", "openresty", "php",
}

_KNOWN_PRODUCTS = (
    "WordPress", "Joomla", "Drupal", "phpMyAdmin", "Tomcat", "Jenkins", "Grafana", "Elasticsearch",
    "Redis", "MongoDB", "MySQL", "PostgreSQL", "OpenSSH", "vsftpd", "ProFTPD", "Exim", "Postfix",
    "Log4j", "Struts", "Spring", "Citrix", "Fortinet", "PAN-OS", "Exchange", "SharePoint", "Nginx",
)


def _technology_terms(observation: ToolObservation) -> List[str]:
    """Extracts conservative product/version terms from a fingerprint observation."""
    terms: List[str] = []
    haystack = f"{observation.evidence} {observation.title}"
    for product, version in re.findall(r"\b([A-Za-z][A-Za-z0-9_.+-]{2,24})\s(\d+\.\d+(?:\.\d+)?)", haystack):
        lowered = product.lower()
        if lowered in _TECH_STOPWORDS:
            continue
        candidate = f"{lowered} {version}"
        if candidate not in terms:
            terms.append(candidate)
    for match in re.findall(r"\b(" + "|".join(_KNOWN_PRODUCTS) + r")\b", haystack, re.IGNORECASE):
        candidate = match.lower()
        if not any(candidate in term for term in terms) and len(terms) < 6:
            terms.append(candidate)
    return terms[:4]


__all__ = [
    "KALI_PROFILES",
    "KaliProfile",
    "KaliAuditOrchestrator",
    "KaliAuditResult",
    "KaliSession",
    "CoverageEntry",
    "TargetInfo",
    "classify_target",
    "WEB_TOOL_KEYS",
]
