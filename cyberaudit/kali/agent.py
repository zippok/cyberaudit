"""
CyberAudit Kali Autonomous Agent
A local, offline-first agent that drives the Kali tool arsenal to completion:

    objetivo autorizado + meta del operador
        → planificador (LLM local en LM Studio) elige la siguiente herramienta
        → orquestador valida alcance, construye argv, ejecuta y parsea
        → observaciones normalizadas vuelven al contexto del planificador
        → resumen ejecutivo (LLM local, con respaldo heurístico determinista)

Safety contract (the LLM never gets to break these):
- The target is fixed by the operator and validated by the engagement scope; the model
  cannot introduce new hosts, URLs or file paths.
- The model may only pick tools from the available catalog and only set a whitelist of
  non-destructive options (ports, severity filter, extensions, service, rate limit…).
- INTRUSIVE tools stay disabled unless ``--allow-intrusive`` and the scope declares it.
- Every decision, command and refusal is recorded in ``KaliAuditResult.agent_trace``.
- If the local model is unavailable or returns malformed output, the agent degrades to
  the deterministic profile planner so an audit always completes.
"""

from __future__ import annotations

import abc
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cyberaudit.kali.orchestrator import (
    KALI_PROFILES,
    KaliAuditOrchestrator,
    KaliAuditResult,
    KaliSession,
)
from cyberaudit.kali.tool_registry import KALI_TOOLS, RiskLevel

logger = logging.getLogger("cyberaudit.kali.agent")

MAX_CONTEXT_OBSERVATIONS = 25
MAX_CONTEXT_CHARS = 14_000

#: Options the language model may set. Everything else is operator-controlled.
MODEL_SAFE_PARAM_KEYS = {
    "ports",
    "extensions",
    "base_path",
    "nmap_scripts",
    "nmap_vuln",
    "severity_filter",
    "rate_limit",
    "threads",
    "tool_timeout",
    "duration_seconds",
    "service",
    "snmp_community",
    "interface",
    "dns_zone_transfer",
    "insecure_tls",
    "hashcat_mode",
    "term",
    "search_term",
}

PLANNER_SYSTEM_PROMPT = (
    "Eres el planificador táctico de un agente de auditoría de seguridad ofensiva/defensiva. "
    "Decides qué herramienta de Kali Linux ejecutar a continuación sobre UN objetivo autorizado. "
    "Respondes SIEMPRE con un único objeto JSON válido, sin texto adicional, sin markdown. "
    "Nunca propones objetivos distintos al autorizado y nunca inventas nombres de herramientas."
)


@dataclass
class AgentAction:
    """A single decision produced by a planner."""

    action: str  # "run_tool" | "finish"
    tool: Optional[str] = None
    rationale: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "tool": self.tool,
            "rationale": self.rationale,
            "params": dict(self.params),
        }


@dataclass
class AgentContext:
    """Everything a planner is allowed to see when deciding the next step."""

    target: str
    goal: str
    profile: str
    candidate_tools: List[Dict[str, Any]]
    executed_tools: List[str]
    observations: List[Dict[str, Any]]
    coverage: List[Dict[str, Any]]
    steps_taken: int
    max_steps: int
    allow_intrusive: bool

    @property
    def remaining_steps(self) -> int:
        return max(0, self.max_steps - self.steps_taken)

    def prompt_payload(self) -> Dict[str, Any]:
        return {
            "objetivo_autorizado": self.target,
            "meta_del_operador": self.goal or "Auditoría de seguridad integral y automatizada del objetivo autorizado.",
            "perfil": self.profile,
            "herramientas_disponibles": self.candidate_tools,
            "herramientas_ya_ejecutadas": self.executed_tools,
            "hallazgos_y_observaciones": self.observations,
            "estado_de_cobertura": self.coverage,
            "pasos_restantes": self.remaining_steps,
            "acciones_intrusivas_autorizadas": self.allow_intrusive,
        }


# ── Planners ─────────────────────────────────────────────────────────────────

class KaliPlanner(abc.ABC):
    """Strategy that decides the next tool to run (or to stop)."""

    name = "planner"

    @abc.abstractmethod
    def next_action(self, context: AgentContext) -> AgentAction:
        ...

    def available(self) -> bool:
        return True


class DeterministicPlanner(KaliPlanner):
    """Walks the candidate list in order. Guarantees a complete, reproducible sweep."""

    name = "deterministico"

    def __init__(self, reason: str = ""):
        self.reason = reason

    def next_action(self, context: AgentContext) -> AgentAction:
        remaining = [tool["key"] for tool in context.candidate_tools if tool["key"] not in context.executed_tools]
        if context.remaining_steps <= 0:
            return AgentAction(action="finish", rationale="Se alcanzó el límite de pasos configurado.")
        if not remaining:
            return AgentAction(action="finish", rationale="Se completó la secuencia determinista de herramientas.")
        nxt = remaining[0]
        risk_note = ""
        if not context.allow_intrusive and KALI_TOOLS[nxt].risk is RiskLevel.INTRUSIVE:
            risk_note = " (intrusiva: se degradará a verificación no intrusiva)"
        return AgentAction(
            action="run_tool",
            tool=nxt,
            rationale=(self.reason or f"Siguiente herramienta de la secuencia del perfil '{context.profile}'{risk_note}."),
        )


def extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Tolerantly extracts the first complete JSON object from LLM output."""
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    decoder = json.JSONDecoder()
    for index, char in enumerate(cleaned):
        if char != "{":
            continue
        try:
            payload, _ = decoder.raw_decode(cleaned[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


class LocalLLMPlanner(KaliPlanner):
    """Uses the local LM Studio model (offline) to choose the next tool."""

    name = "llm-local"

    def __init__(
        self,
        analyst: Any = None,
        model: Optional[str] = None,
        timeout: float = 180.0,
        temperature: float = 0.1,
    ):
        self.analyst = analyst
        self.model_override = model or os.getenv("CYBERAUDIT_LOCAL_MODEL") or None
        self.timeout = timeout
        self.temperature = temperature
        self._model: Optional[str] = None
        self.last_error: Optional[str] = None

    # ── Availability ─────────────────────────────────────────────────────────
    def _analyst_client(self) -> Any:
        if self.analyst is None:
            from cyberaudit.ai.co_analyst import AICoAnalyst

            self.analyst = AICoAnalyst()
        return self.analyst

    def resolve_model(self) -> Optional[str]:
        if self._model:
            return self._model
        if self.model_override:
            self._model = self.model_override
            return self._model
        try:
            reachable, model = self._analyst_client().is_lm_studio_available(timeout=3.0)
        except Exception as exc:  # pragma: no cover - defensive
            self.last_error = f"Diagnóstico LM Studio fallido: {exc}"
            return None
        if reachable and model:
            self._model = model
        return self._model

    def available(self) -> bool:
        return bool(self.resolve_model())

    # ── Prompt ───────────────────────────────────────────────────────────────
    @staticmethod
    def build_prompt(context: AgentContext) -> str:
        payload = context.prompt_payload()
        tools_block = "\n".join(
            f"- {tool['key']} · {tool['title']} · categoria={tool['category']} · riesgo={tool['risk']}"
            f"{' · REQUIERE ROOT' if tool.get('requires_root') else ''}"
            f"\n    {tool.get('description', '')[:220]}"
            for tool in payload["herramientas_disponibles"]
        ) or "- (no hay herramientas disponibles en este sistema)"

        executed = ", ".join(payload["herramientas_ya_ejecutadas"]) or "(ninguna todavía)"
        coverage_block = "\n".join(
            f"- {entry['tool_key']}: {entry['status']}"
            + (f" — {entry['reason'][:140]}" if entry.get("reason") else "")
            for entry in payload["estado_de_cobertura"][-12:]
        ) or "- (sin ejecuciones previas)"

        observations_block = ""
        if payload["hallazgos_y_observaciones"]:
            observations_block = "\n".join(
                f"- [{obs['severity']}] ({obs['tool']}) {obs['title'][:150]}"
                + (f" → {obs['evidence'][:160]}" if obs.get("evidence") else "")
                for obs in payload["hallazgos_y_observaciones"]
            )
        else:
            observations_block = "(todavía no hay hallazgos normalizados)"

        return (
            "Contexto de la auditoría en curso (datos reales ya recolectados):\n"
            f"- Objetivo autorizado (ÚNICO permitido): {payload['objetivo_autorizado']}\n"
            f"- Meta del operador: {payload['meta_del_operador']}\n"
            f"- Perfil de auditoría: {payload['perfil']}\n"
            f"- Acciones intrusivas autorizadas: {payload['acciones_intrusivas_autorizadas']}\n"
            f"- Pasos restantes: {payload['pasos_restantes']}\n\n"
            f"HERRAMIENTAS DISPONIBLES (elige exactamente una clave de esta lista):\n{tools_block}\n\n"
            f"HERRAMIENTAS YA EJECUTADAS: {executed}\n\n"
            f"ESTADO DE COBERTURA:\n{coverage_block}\n\n"
            f"HALLAZGOS NORMALIZADOS HASTA AHORA:\n{observations_block}\n\n"
            "Decide el SIGUIENTE paso más valioso (máximo información nueva por ejecución; evita repetir "
            "herramientas ya ejecutadas; si el objetivo ya está caracterizado, responde finish).\n"
            "Responde EXCLUSIVAMENTE con un objeto JSON con uno de estos dos formatos:\n"
            '{"action": "run_tool", "tool": "<clave de la lista>", "rationale": "<por qué>", "params": {...}}\n'
            '{"action": "finish", "rationale": "<por qué ya no hace falta ejecutar más>"}\n'
            "Claves admitidas en 'params' (opcional): "
            + ", ".join(sorted(MODEL_SAFE_PARAM_KEYS))
            + ".\nNo incluyas texto fuera del JSON."
        )

    # ── Decision ─────────────────────────────────────────────────────────────
    def next_action(self, context: AgentContext) -> AgentAction:
        model = self.resolve_model()
        if not model:
            raise RuntimeError(self.last_error or "Modelo local de LM Studio no disponible.")

        prompt = self.build_prompt(context)
        client = self._analyst_client()
        try:
            raw = client.query_local_lm_studio(prompt, model, timeout=self.timeout)
        except TypeError:
            raw = client.query_local_lm_studio(prompt, model)
        except Exception as exc:
            self.last_error = f"Consulta al modelo local fallida: {exc}"
            raise RuntimeError(self.last_error)

        if not raw:
            self.last_error = "El modelo local no devolvió respuesta."
            raise RuntimeError(self.last_error)

        payload = extract_json_object(raw)
        if not payload:
            self.last_error = f"El modelo local no devolvió JSON válido: {raw[:200]}"
            raise RuntimeError(self.last_error)

        action = str(payload.get("action", "")).strip().lower()
        rationale = str(payload.get("rationale", "")).strip()
        if action in ("finish", "stop", "done", "end"):
            return AgentAction(action="finish", rationale=rationale or "El planificador local decidió finalizar.", raw=raw)

        tool = str(payload.get("tool", "")).strip().lower()
        raw_params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
        params = {
            key: value
            for key, value in raw_params.items()
            if key in MODEL_SAFE_PARAM_KEYS and isinstance(value, (str, int, float, bool))
        }
        return AgentAction(
            action="run_tool",
            tool=tool or None,
            rationale=rationale or "Selección del planificador local.",
            params=params,
            raw=raw,
        )


# ── Agent ────────────────────────────────────────────────────────────────────

class KaliAutonomousAgent:
    """Drives the Kali arsenal to completion, step by step, fully on-premise."""

    def __init__(
        self,
        orchestrator: Optional[KaliAuditOrchestrator] = None,
        planner: Optional[KaliPlanner] = None,
        analyst: Any = None,
        use_llm: bool = True,
        max_steps: int = 8,
        time_budget_seconds: int = 1800,
        verbose: bool = False,
    ):
        self.orchestrator = orchestrator or KaliAuditOrchestrator()
        self.analyst = analyst
        self.use_llm = use_llm
        self.max_steps = max_steps
        self.time_budget_seconds = time_budget_seconds
        self.verbose = verbose
        self._deterministic = DeterministicPlanner()
        self.planner: KaliPlanner = planner or (LocalLLMPlanner(analyst=analyst) if use_llm else self._deterministic)

    # ── Public API ───────────────────────────────────────────────────────────
    def run(
        self,
        target: str,
        goal: str = "",
        profile: str = "full",
        tools: Optional[Sequence[str]] = None,
        allow_intrusive: bool = False,
        dry_run: bool = False,
        max_steps: Optional[int] = None,
        extras: Optional[Dict[str, str]] = None,
        wordlist: Optional[str] = None,
        ports: Optional[str] = None,
        summarize: bool = True,
        run_exploit_correlation: bool = True,
        session_label: Optional[str] = None,
    ) -> KaliAuditResult:
        """Runs the autonomous loop until the planner finishes or the budget is exhausted."""
        steps_limit = int(max_steps or self.max_steps)
        merged_extras = dict(extras or {})
        if ports and "ports" not in merged_extras:
            merged_extras["ports"] = ports
        if wordlist:
            merged_extras["wordlist"] = wordlist

        session = self.orchestrator.start_session(
            target=target,
            profile=profile,
            tools=tools,
            dry_run=dry_run,
            allow_intrusive=allow_intrusive,
            wordlist=wordlist,
            ports=ports,
            extras=merged_extras,
            probe_scheme=True,
            session_label=session_label or "agent",
        )

        requested = self.orchestrator.resolve_tools(profile, tools)
        plan_pool = self.orchestrator.plan_for(session, requested)
        blocked_reasons: Dict[str, str] = {}
        candidates: List[Dict[str, Any]] = []
        for step in plan_pool:
            if step.get("status") != "planned":
                blocked_reasons[step["tool"]] = step.get("reason", "")
                continue
            tool = KALI_TOOLS[step["tool"]]
            candidates.append({
                "key": tool.key,
                "title": tool.title,
                "category": tool.category.value,
                "risk": tool.risk.value,
                "description": tool.description,
                "requires_root": tool.requires_root,
            })

        trace: List[Dict[str, Any]] = []
        for step in plan_pool:
            if step.get("status") != "planned":
                trace.append({
                    "step": 0,
                    "planner": "pre-flight",
                    "action": "skip",
                    "tool": step["tool"],
                    "rationale": step.get("reason", ""),
                    "status": "skipped",
                })

        if not candidates:
            trace.append({
                "step": 0, "planner": "pre-flight", "action": "finish",
                "rationale": "Ninguna herramienta del perfil es ejecutable contra este objetivo.", "status": "no-op",
            })
            return self._finish(session, trace, summarize=summarize)

        planner = self.planner
        planner_notes: List[str] = []
        if not planner.available():
            planner_notes.append(
                f"Planificador '{planner.name}' no disponible: se usa la secuencia determinista del perfil."
            )
            planner = self._deterministic
        failures = 0

        for step_index in range(1, steps_limit + 1):
            if session.elapsed_seconds >= self.time_budget_seconds:
                trace.append({
                    "step": step_index, "planner": planner.name, "action": "finish",
                    "rationale": f"Presupuesto de tiempo agotado ({self.time_budget_seconds}s).", "status": "budget",
                })
                break

            context = AgentContext(
                target=session.target_info.label(),
                goal=goal,
                profile=profile,
                candidate_tools=candidates,
                executed_tools=list(session.executed_tools),
                observations=self._observations_digest(session),
                coverage=[entry.to_dict() for entry in session.coverage],
                steps_taken=step_index - 1,
                max_steps=steps_limit,
                allow_intrusive=allow_intrusive,
            )

            action: Optional[AgentAction] = None
            try:
                action = planner.next_action(context)
                failures = 0
            except Exception as exc:
                failures += 1
                note = f"Planificador '{planner.name}' falló ({exc})."
                logger.warning(note)
                if failures >= 2 or planner is self._deterministic:
                    planner_notes.append(note + " Se continúa con la secuencia determinista del perfil.")
                    planner = self._deterministic
                try:
                    action = planner.next_action(context)
                except Exception as retry_exc:  # el reintento también falló: se degrada definitivamente
                    planner_notes.append(
                        f"Reintento del planificador fallido ({retry_exc}). Se usa la secuencia determinista del perfil."
                    )
                    planner = self._deterministic
                    try:
                        action = planner.next_action(context)
                    except Exception as deterministic_exc:  # pragma: no cover - no debería ocurrir
                        trace.append({
                            "step": step_index, "planner": planner.name, "action": "abort",
                            "rationale": f"Planificación imposible: {deterministic_exc}", "status": "error",
                        })
                        break

            if action.action == "finish":
                trace.append({
                    "step": step_index, "planner": planner.name, "action": "finish",
                    "rationale": action.rationale, "status": "finished",
                })
                break

            tool_key = (action.tool or "").strip().lower()
            candidate_keys = {tool["key"] for tool in candidates}
            if tool_key not in candidate_keys:
                note = (
                    f"El planificador propuso '{action.tool}', que no está en el catálogo ejecutable "
                    f"({', '.join(sorted(candidate_keys))}). Se descarta y se sigue con la secuencia determinista."
                )
                planner_notes.append(note)
                trace.append({
                    "step": step_index, "planner": planner.name, "action": "rejected",
                    "tool": action.tool, "rationale": action.rationale, "status": "rejected", "notes": note,
                })
                planner = self._deterministic
                continue

            if tool_key in session.executed_tools:
                trace.append({
                    "step": step_index, "planner": planner.name, "action": "skipped-duplicate",
                    "tool": tool_key, "rationale": action.rationale, "status": "skipped",
                    "notes": "Herramienta ya ejecutada en esta sesión.",
                })
                continue

            step_extras = dict(session.extras)
            applied_params: Dict[str, Any] = {}
            for key, value in action.params.items():
                if key in MODEL_SAFE_PARAM_KEYS:
                    step_extras[key] = str(value)
                    applied_params[key] = value
            if tool_key == "searchsploit" and "term" in step_extras:
                pass

            step_session = session
            step_session.extras = step_extras
            steps = self.orchestrator.plan_for(step_session, [tool_key])
            step_session.extras = dict(session.extras)
            planned = next((item for item in steps if item["tool"] == tool_key), None)
            if planned is None or planned.get("status") != "planned":
                reason = (planned or {}).get("reason", "No planificable con los parámetros propuestos.")
                trace.append({
                    "step": step_index, "planner": planner.name, "action": "skip",
                    "tool": tool_key, "rationale": action.rationale, "status": "skipped",
                    "params": applied_params, "notes": reason,
                })
                continue

            if self.verbose:
                self.orchestrator.progress(f"[agente] {planned['title']}: {planned['command']}")

            previous = len(session.observations)
            entry = self.orchestrator.execute_step(session, planned)
            new_observations = session.observations[previous:]
            status = entry.status if entry else "unknown"
            trace.append({
                "step": step_index,
                "planner": planner.name,
                "action": "run_tool",
                "tool": tool_key,
                "rationale": action.rationale,
                "params": applied_params,
                "command": planned.get("command", ""),
                "status": status,
                "findings": len(new_observations),
                "reason": (entry.reason if entry else ""),
            })

        if run_exploit_correlation and not dry_run:
            try:
                self.orchestrator.correlate_exploits(session)
            except Exception as exc:  # pragma: no cover - defensive
                planner_notes.append(f"Correlación de exploits omitida: {exc}")

        if planner_notes:
            trace.append({"step": 0, "planner": "notas", "action": "note", "rationale": " ".join(planner_notes), "status": "info"})

        plan_snapshot = [{k: v for k, v in step.items() if k not in ("request", "argv")} for step in plan_pool]
        return self._finish(session, trace, summarize=summarize, plan_snapshot=plan_snapshot)

    # ── Internals ────────────────────────────────────────────────────────────
    def _finish(
        self,
        session: KaliSession,
        trace: List[Dict[str, Any]],
        summarize: bool = True,
        plan_snapshot: Optional[List[Dict[str, Any]]] = None,
    ) -> KaliAuditResult:
        result = self.orchestrator.finalize(session, agent_trace=trace, plan_snapshot=plan_snapshot)
        if summarize:
            result.ai_summary = self._summarize(result)
            result.report.executive_summary = result.ai_summary
            result.report.ai_verdict = result.ai_summary
            self.orchestrator._persist_result(result)
        return result

    def _summarize(self, result: KaliAuditResult) -> str:
        """Executive synthesis: local LLM when reachable, deterministic heuristic otherwise."""
        try:
            if self.analyst is None:
                from cyberaudit.ai.co_analyst import AICoAnalyst

                self.analyst = AICoAnalyst()
            report = self.analyst.analyze(result.report, provider_mode="local")
            summary = report.executive_summary or report.ai_verdict
            if summary:
                return summary
        except Exception as exc:
            logger.warning("Síntesis con el modelo local fallida: %s", exc)
        return self._heuristic_summary(result)

    @staticmethod
    def _heuristic_summary(result: KaliAuditResult) -> str:
        counts = result.report.severity_counts
        top = sorted(result.report.findings, key=lambda finding: finding.severity.rank, reverse=True)[:8]
        lines = [
            "### Resumen de la auditoría Kali (síntesis local determinista)",
            f"- Objetivo: `{result.target}` (perfil `{result.profile}`)",
            f"- Herramientas ejecutadas: {result.summary()['tools_executed']} de {len(result.coverage)} planificadas",
            f"- Hallazgos: {result.findings_count} "
            f"(CRITICAL {counts.get('CRITICAL', 0)} · HIGH {counts.get('HIGH', 0)} · MEDIUM {counts.get('MEDIUM', 0)})",
            "",
            "**Hallazgos priorizados**",
        ]
        if top:
            lines.extend(f"- [{finding.severity.value}] {finding.title}" for finding in top)
        else:
            lines.append("- Sin hallazgos relevantes: la superficie analizada se comportó conforme a lo esperado.")
        skipped = [entry for entry in result.coverage if entry.status in ("skipped", "failed", "blocked")]
        if skipped:
            lines.append("")
            lines.append("**Cobertura incompleta (requiere revisión del auditor)**")
            lines.extend(
                f"- {entry.tool_key}: {entry.status} — {(entry.reason or '')[:160]}" for entry in skipped[:10]
            )
        return "\n".join(lines)

    @staticmethod
    def _observations_digest(session: KaliSession) -> List[Dict[str, Any]]:
        digest: List[Dict[str, Any]] = []
        for observation in session.observations[-MAX_CONTEXT_OBSERVATIONS:]:
            digest.append({
                "tool": observation.tool_key,
                "severity": observation.severity.value,
                "title": observation.title,
                "host": observation.host,
                "port": observation.port,
                "evidence": (observation.evidence or "")[:240],
            })
        return digest


__all__ = [
    "KaliAutonomousAgent",
    "KaliPlanner",
    "DeterministicPlanner",
    "LocalLLMPlanner",
    "AgentAction",
    "AgentContext",
    "MODEL_SAFE_PARAM_KEYS",
    "extract_json_object",
]
