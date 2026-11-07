"""
cyberaudit/core/telemetry_feedback.py
=======================================
Runtime Telemetry Feedback Engine — Frontier 3 of 3

Implements a Closed-Loop SAST+APM integration that:

1. PARSES runtime error payloads from Sentry and OpenTelemetry
2. CORRELATES each incident to an audit invariant rule (e.g.,
   AttributeError → INV-NULL-004, SQLAlchemyError → INV-SQL-001)
3. TRIGGERS the Sandbox Remediator autonomously to generate a hotfix
   + regression test before human intervention

Supported telemetry sources
----------------------------
- Sentry (JSON payload: exception, frames, stacktrace)
- OpenTelemetry / OTLP (spans with exception.type + exception.message attributes)
- DataDog (generic error event format)
- Generic JSON (best-effort extraction)

Correlation logic
-----------------
The engine maintains an EXCEPTION_RULE_MAP that maps exception types (and
their substrings) to invariant rule IDs. When a match is found the engine
returns the rule_id so the caller can look up the full rule and generate
remediation context.

Autonomous hotfix
-----------------
trigger_autonomous_hotfix() orchestrates the full loop:
  1. Parse incident
  2. Correlate to rule_id
  3. Locate the commit that introduced the regression (via git blame if available)
  4. Return a HotfixReport with rule_id, suggested_fix description, and metadata

This module is intentionally side-effect-free: the actual sandbox execution
is delegated to sandbox_runner.SandboxRemediator in the web layer.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Exception → invariant rule mapping
# ---------------------------------------------------------------------------

EXCEPTION_RULE_MAP: Dict[str, str] = {
    # Null / attribute errors → INV-NULL family
    "AttributeError":           "INV-NULL-004",
    "NoneType":                 "INV-NULL-004",
    "NullPointerException":     "INV-NULL-004",
    # SQL / DB errors → INV-SQL family
    "SQLAlchemyError":          "INV-SQL-001",
    "OperationalError":         "INV-SQL-001",
    "ProgrammingError":         "INV-SQL-001",
    "IntegrityError":           "INV-SQL-002",
    # Auth errors → INV-AUTH family
    "PermissionDenied":         "INV-AUTH-003",
    "Unauthorized":             "INV-AUTH-003",
    "AuthenticationError":      "INV-AUTH-003",
    "Forbidden":                "INV-AUTH-003",
    # Injection → INV-INJ family
    "InjectionError":           "INV-INJ-001",
    "CommandInjection":         "INV-INJ-002",
    "PathTraversalError":       "INV-INJ-003",
    # Deserialization
    "UnpicklingError":          "INV-DESER-001",
    "DeserializationError":     "INV-DESER-001",
    # Resource / rate limit
    "MemoryError":              "INV-RES-001",
    "TimeoutError":             "INV-RES-002",
    "ConnectionError":          "INV-RES-003",
    "RateLimitError":           "INV-RES-004",
    # Key / crypto
    "InvalidSignature":         "INV-CRYPTO-001",
    "CryptographyError":        "INV-CRYPTO-001",
    # Validation
    "ValidationError":          "INV-VAL-001",
    "ValueError":               "INV-VAL-002",
    "TypeError":                "INV-VAL-003",
    # File system
    "FileNotFoundError":        "INV-FS-001",
    "PermissionError":          "INV-FS-002",
    "IsADirectoryError":        "INV-FS-003",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TelemetryIncident:
    source: str             # "sentry" | "opentelemetry" | "datadog" | "generic"
    exception_type: str     # e.g. "AttributeError"
    file_path: str          # e.g. "services/billing.py"
    line_number: int        # e.g. 120
    message: str            # Human-readable error message
    timestamp: str          # ISO-8601 string
    # Optional enrichment
    function_name: str = ""
    transaction: str = ""
    environment: str = "production"
    occurrence_count: int = 1   # Number of occurrences in the reporting window
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source":           self.source,
            "exception_type":   self.exception_type,
            "file_path":        self.file_path,
            "line_number":      self.line_number,
            "message":          self.message,
            "timestamp":        self.timestamp,
            "function_name":    self.function_name,
            "transaction":      self.transaction,
            "environment":      self.environment,
            "occurrence_count": self.occurrence_count,
        }


@dataclass
class HotfixReport:
    incident: TelemetryIncident
    rule_id: Optional[str]
    suggested_fix: str
    blame_commit: Optional[str]       # Git commit SHA that introduced the regression
    blame_author: Optional[str]       # Author of the regressing commit
    regression_likely: bool           # True when a recent commit touched the file
    test_suggestion: str              # Suggested regression test description
    autonomous_trigger: bool = True   # Whether autonomous remediation was triggered

    def to_dict(self) -> dict:
        return {
            "rule_id":            self.rule_id,
            "incident":           self.incident.to_dict(),
            "suggested_fix":      self.suggested_fix,
            "blame_commit":       self.blame_commit,
            "blame_author":       self.blame_author,
            "regression_likely":  self.regression_likely,
            "test_suggestion":    self.test_suggestion,
            "autonomous_trigger": self.autonomous_trigger,
        }


# ---------------------------------------------------------------------------
# Payload parsers
# ---------------------------------------------------------------------------

def _safe_str(val: Any, default: str = "") -> str:
    return str(val) if val is not None else default


def _extract_sentry_frame(event: dict) -> tuple[str, int, str]:
    """Extract (file_path, line_number, function_name) from a Sentry event."""
    try:
        exceptions = event.get("exception", {}).get("values", [])
        if not exceptions:
            exceptions = [event.get("exception", {})]
        frames = exceptions[-1].get("stacktrace", {}).get("frames", [])
        if frames:
            frame = frames[-1]   # innermost frame
            return (
                _safe_str(frame.get("filename") or frame.get("abs_path")),
                int(frame.get("lineno", 0)),
                _safe_str(frame.get("function")),
            )
    except (KeyError, IndexError, TypeError, ValueError):
        pass
    return ("", 0, "")


def _extract_otel_frame(span: dict) -> tuple[str, int, str]:
    """Extract frame info from an OpenTelemetry span's attributes."""
    attrs = span.get("attributes", {})
    # Prefer explicit code.filepath attribute
    file_path = _safe_str(attrs.get("code.filepath", ""))
    if not file_path:
        # Fallback: try to parse from exception.stacktrace last line
        stacktrace = _safe_str(attrs.get("exception.stacktrace", ""))
        if stacktrace:
            lines = [ln for ln in stacktrace.splitlines() if ln.strip()]
            file_path = lines[-1] if lines else ""
    line_number = 0
    try:
        line_number = int(attrs.get("code.lineno", 0))
    except (ValueError, TypeError):
        pass
    function_name = _safe_str(attrs.get("code.function"))
    return file_path, line_number, function_name


# ---------------------------------------------------------------------------
# Main manager
# ---------------------------------------------------------------------------

class TelemetryFeedbackManager:
    """
    Parses, correlates, and acts on runtime telemetry incidents.

    Usage
    -----
    manager = TelemetryFeedbackManager(repo_path=".")
    incident = manager.parse_sentry_payload(sentry_event_dict)
    rule_id = manager.correlate_incident(incident)
    report = manager.trigger_autonomous_hotfix(incident, config_path=".audit-rules.yaml")
    """

    def __init__(
        self,
        repo_path: str = ".",
        extra_rule_map: Optional[Dict[str, str]] = None,
    ):
        self.repo_path = repo_path
        self._rule_map = {**EXCEPTION_RULE_MAP, **(extra_rule_map or {})}

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def parse_sentry_payload(self, payload: dict) -> TelemetryIncident:
        """
        Parse a Sentry error event payload.

        Sentry payload structure (simplified):
        {
          "event_id": "...",
          "timestamp": "2024-01-15T10:30:00Z",
          "level": "error",
          "exception": {
            "values": [{
              "type": "AttributeError",
              "value": "'NoneType' object has no attribute 'id'",
              "stacktrace": {"frames": [{"filename": ..., "lineno": ..., "function": ...}]}
            }]
          },
          "transaction": "/api/v1/billing",
          "environment": "production",
          "extra": {"occurrence_count": 4000}
        }
        """
        exc_type = ""
        exc_message = ""
        try:
            values = payload.get("exception", {}).get("values", [])
            if values:
                exc_type = _safe_str(values[-1].get("type"))
                exc_message = _safe_str(values[-1].get("value"))
        except (AttributeError, KeyError):
            pass

        file_path, line_number, function_name = _extract_sentry_frame(payload)

        return TelemetryIncident(
            source="sentry",
            exception_type=exc_type,
            file_path=file_path,
            line_number=line_number,
            message=exc_message,
            timestamp=_safe_str(payload.get("timestamp")),
            function_name=function_name,
            transaction=_safe_str(payload.get("transaction")),
            environment=_safe_str(payload.get("environment", "production")),
            occurrence_count=int(
                payload.get("extra", {}).get("occurrence_count", 1)
            ) if isinstance(payload.get("extra"), dict) else 1,
            raw_payload=payload,
        )

    def parse_opentelemetry_payload(self, payload: dict) -> TelemetryIncident:
        """
        Parse an OpenTelemetry (OTLP) span payload.

        Expected structure:
        {
          "name": "HTTP POST /api/billing",
          "start_time": "2024-01-15T10:30:00Z",
          "attributes": {
            "exception.type": "AttributeError",
            "exception.message": "...",
            "code.filepath": "services/billing.py",
            "code.lineno": 120,
            "code.function": "process_payment"
          },
          "resource": {"service.environment": "production"}
        }
        """
        attrs = payload.get("attributes", {})
        exc_type = _safe_str(attrs.get("exception.type"))
        exc_message = _safe_str(attrs.get("exception.message"))
        file_path, line_number, function_name = _extract_otel_frame(payload)

        resource = payload.get("resource", {})
        environment = _safe_str(resource.get("service.environment", "production"))

        return TelemetryIncident(
            source="opentelemetry",
            exception_type=exc_type,
            file_path=file_path,
            line_number=line_number,
            message=exc_message,
            timestamp=_safe_str(
                payload.get("start_time") or payload.get("end_time")
            ),
            function_name=function_name,
            transaction=_safe_str(payload.get("name")),
            environment=environment,
            occurrence_count=int(attrs.get("occurrence_count", 1)),
            raw_payload=payload,
        )

    def parse_generic_payload(self, payload: dict) -> TelemetryIncident:
        """
        Best-effort parser for generic/DataDog-style error payloads.
        Looks for common keys: error.type, error.message, file, line.
        """
        exc_type = _safe_str(
            payload.get("error.type") or
            payload.get("error_type") or
            payload.get("exception_type") or
            payload.get("type", "UnknownError")
        )
        exc_message = _safe_str(
            payload.get("error.message") or
            payload.get("message") or
            payload.get("error", {}).get("message", "") if isinstance(payload.get("error"), dict) else ""
        )
        file_path = _safe_str(
            payload.get("file") or
            payload.get("file_path") or
            payload.get("filename", "")
        )
        line_number = 0
        try:
            line_number = int(payload.get("line") or payload.get("line_number", 0))
        except (ValueError, TypeError):
            pass

        return TelemetryIncident(
            source="generic",
            exception_type=exc_type,
            file_path=file_path,
            line_number=line_number,
            message=exc_message,
            timestamp=_safe_str(payload.get("timestamp", "")),
            function_name=_safe_str(payload.get("function", "")),
            transaction=_safe_str(payload.get("transaction", "")),
            environment=_safe_str(payload.get("environment", "production")),
            occurrence_count=int(payload.get("count", payload.get("occurrence_count", 1))),
            raw_payload=payload,
        )

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate_incident(self, incident: TelemetryIncident) -> Optional[str]:
        """
        Correlate an incident to an invariant rule_id.

        Strategy:
        1. Exact match on exception_type
        2. Substring match (e.g., "MySQLdb.OperationalError" contains "OperationalError")
        3. Match on message content for additional clues

        Returns the matched rule_id, or None if no match found.
        """
        exc = incident.exception_type

        # 1. Exact match
        if exc in self._rule_map:
            return self._rule_map[exc]

        # 2. Substring match against known exception names
        for known_exc, rule_id in self._rule_map.items():
            if known_exc in exc or exc in known_exc:
                return rule_id

        # 3. Message-based heuristic
        msg_lower = incident.message.lower()
        if "null" in msg_lower or "none" in msg_lower or "attribute" in msg_lower:
            return "INV-NULL-004"
        if "sql" in msg_lower or "query" in msg_lower or "syntax" in msg_lower:
            return "INV-SQL-001"
        if "permission" in msg_lower or "denied" in msg_lower or "forbidden" in msg_lower:
            return "INV-AUTH-003"
        if "timeout" in msg_lower:
            return "INV-RES-002"

        return None

    # ------------------------------------------------------------------
    # Git blame (best-effort)
    # ------------------------------------------------------------------

    def _git_blame_line(
        self,
        file_path: str,
        line_number: int,
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Runs git blame on the given file:line_number.
        Returns (commit_sha, author_email) or (None, None) on failure.
        """
        if line_number <= 0:
            return None, None
        try:
            result = subprocess.run(
                [
                    "git", "-C", self.repo_path,
                    "blame", "--porcelain",
                    f"-L{line_number},{line_number}",
                    "--", file_path,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None, None

            lines = result.stdout.splitlines()
            commit_sha = lines[0].split()[0] if lines else None
            author = None
            for line in lines:
                if line.startswith("author-mail"):
                    author = line.split(" ", 1)[1].strip("<>")
                    break
            return commit_sha, author
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError, IndexError):
            return None, None

    # ------------------------------------------------------------------
    # Autonomous hotfix orchestration
    # ------------------------------------------------------------------

    def trigger_autonomous_hotfix(
        self,
        incident: TelemetryIncident,
        config_path: str = ".audit-rules.yaml",
    ) -> HotfixReport:
        """
        Orchestrate the closed-loop remediation cycle:

        1. Correlate incident to a rule_id
        2. Run git blame to find the regressing commit
        3. Build a HotfixReport with remediation suggestions

        The actual sandbox execution is performed by the web layer
        (POST /api/telemetry/webhook) to avoid blocking this module.

        Returns a HotfixReport regardless of git availability.
        """
        rule_id = self.correlate_incident(incident)

        # Git blame for the offending file:line
        blame_commit, blame_author = self._git_blame_line(
            incident.file_path, incident.line_number
        )
        regression_likely = blame_commit is not None

        # Build suggested fix based on rule family
        suggested_fix = self._build_fix_suggestion(rule_id, incident)
        test_suggestion = self._build_test_suggestion(rule_id, incident)

        return HotfixReport(
            incident=incident,
            rule_id=rule_id,
            suggested_fix=suggested_fix,
            blame_commit=blame_commit,
            blame_author=blame_author,
            regression_likely=regression_likely,
            test_suggestion=test_suggestion,
            autonomous_trigger=True,
        )

    # ------------------------------------------------------------------
    # Fix + test suggestion builders
    # ------------------------------------------------------------------

    def _build_fix_suggestion(
        self,
        rule_id: Optional[str],
        incident: TelemetryIncident,
    ) -> str:
        if not rule_id:
            return (
                f"Investigate {incident.exception_type} at "
                f"{incident.file_path}:{incident.line_number}. "
                "No invariant rule matched — consider adding a new rule."
            )

        family = rule_id.split("-")[1] if "-" in rule_id else ""

        suggestions: Dict[str, str] = {
            "NULL": (
                f"Add a null-guard before accessing the object at "
                f"{incident.file_path}:{incident.line_number}. "
                "Use `if obj is not None:` or the Optional pattern. "
                f"Rule: {rule_id}"
            ),
            "SQL": (
                f"Ensure all database queries at "
                f"{incident.file_path}:{incident.line_number} "
                "use parameterized statements. Never interpolate user input "
                f"into SQL strings. Rule: {rule_id}"
            ),
            "AUTH": (
                f"Verify authentication guards at "
                f"{incident.file_path}:{incident.line_number}. "
                "Ensure the endpoint checks permissions before processing the request. "
                f"Rule: {rule_id}"
            ),
            "INJ": (
                f"Sanitize all inputs before they reach the sink at "
                f"{incident.file_path}:{incident.line_number}. "
                "Apply input validation and output encoding. "
                f"Rule: {rule_id}"
            ),
            "RES": (
                f"Add timeout handling and circuit-breaker logic at "
                f"{incident.file_path}:{incident.line_number}. "
                f"Rule: {rule_id}"
            ),
            "VAL": (
                f"Add input validation / type coercion before the operation at "
                f"{incident.file_path}:{incident.line_number}. "
                f"Rule: {rule_id}"
            ),
            "CRYPTO": (
                f"Review cryptographic key handling at "
                f"{incident.file_path}:{incident.line_number}. "
                "Ensure keys are not expired and signatures are verified. "
                f"Rule: {rule_id}"
            ),
        }
        return suggestions.get(family, f"Apply fix for {rule_id} at {incident.file_path}:{incident.line_number}.")

    def _build_test_suggestion(
        self,
        rule_id: Optional[str],
        incident: TelemetryIncident,
    ) -> str:
        base = f"Add a regression test for {incident.exception_type}"
        if rule_id:
            base += f" (rule {rule_id})"
        base += (
            f" that reproduces the failure in {incident.file_path} "
            f"at line {incident.line_number} and asserts it does not raise."
        )
        return base
