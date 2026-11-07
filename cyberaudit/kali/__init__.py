"""
CyberAudit ↔ Kali Linux Integration
===================================

Bridges the CyberAudit platform with the offensive-security tooling installed on this
Kali Linux host so auditors can run real, evidence-backed tests instead of only static
analysis:

- :mod:`cyberaudit.kali.tool_registry` — declarative catalog of Kali tools, risk levels,
  validated ``argv`` builders and runtime availability discovery.
- :mod:`cyberaudit.kali.scope` — Rules of Engagement enforcement (deny-by-default).
- :mod:`cyberaudit.kali.executor` — hardened subprocess runner with evidence capture and
  an append-only JSONL audit trail.
- :mod:`cyberaudit.kali.parsers` — tool-output parsers producing normalized observations.
- :mod:`cyberaudit.kali.findings` — observation → platform Finding mapping.
- :mod:`cyberaudit.kali.orchestrator` — profiles, planning, execution and reporting.
- :mod:`cyberaudit.kali.agent` — local autonomous agent (LM Studio LLM plans, Kali runs).
"""

from cyberaudit.kali.executor import (
    KaliExecutionDisabled,
    KaliExecutor,
    KaliRunResult,
    kill_switch_engaged,
)
from cyberaudit.kali.findings import observations_to_findings, observation_to_finding
from cyberaudit.kali.orchestrator import (
    KALI_PROFILES,
    CoverageEntry,
    KaliAuditOrchestrator,
    KaliAuditResult,
    KaliProfile,
    KaliSession,
    TargetInfo,
    classify_target,
)
from cyberaudit.kali.parsers import ToolObservation, parse_tool_output
from cyberaudit.kali.scope import (
    DEFAULT_SCOPE_FILE,
    SCOPE_ENV_VAR,
    EngagementScope,
    ScopeAuthorization,
    ScopeGuard,
    ScopeViolationError,
    write_scope_template,
)
from cyberaudit.kali.tool_registry import (
    KALI_TOOLS,
    KaliCategory,
    KaliTool,
    KaliToolError,
    RiskLevel,
    ToolRequest,
    ToolStatus,
    build_command,
    discover_tools,
    resolve_binary,
    tool_status_map,
)

try:  # The agent pulls in the AI co-analyst; keep the import optional and cheap.
    from cyberaudit.kali.agent import (
        AgentAction,
        DeterministicPlanner,
        KaliAutonomousAgent,
        LocalLLMPlanner,
        MODEL_SAFE_PARAM_KEYS,
    )
except Exception as _agent_import_error:  # pragma: no cover - degraded environments
    KaliAutonomousAgent = None  # type: ignore[assignment]
    DeterministicPlanner = None  # type: ignore[assignment]
    LocalLLMPlanner = None  # type: ignore[assignment]
    AgentAction = None  # type: ignore[assignment]
    MODEL_SAFE_PARAM_KEYS = set()  # type: ignore[assignment]
    _AGENT_IMPORT_ERROR = _agent_import_error

__all__ = [
    "KALI_TOOLS",
    "KALI_PROFILES",
    "KaliTool",
    "KaliCategory",
    "KaliToolError",
    "KaliExecutor",
    "KaliRunResult",
    "KaliExecutionDisabled",
    "KaliAuditOrchestrator",
    "KaliAuditResult",
    "KaliProfile",
    "KaliSession",
    "KaliAutonomousAgent",
    "LocalLLMPlanner",
    "DeterministicPlanner",
    "AgentAction",
    "MODEL_SAFE_PARAM_KEYS",
    "CoverageEntry",
    "TargetInfo",
    "ToolObservation",
    "ToolRequest",
    "ToolStatus",
    "EngagementScope",
    "ScopeGuard",
    "ScopeAuthorization",
    "ScopeViolationError",
    "RiskLevel",
    "build_command",
    "classify_target",
    "discover_tools",
    "kill_switch_engaged",
    "observation_to_finding",
    "observations_to_findings",
    "parse_tool_output",
    "resolve_binary",
    "tool_status_map",
    "write_scope_template",
    "DEFAULT_SCOPE_FILE",
    "SCOPE_ENV_VAR",
]
