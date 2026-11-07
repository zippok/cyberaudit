"""
CyberAudit Kali Process Executor
Runs offensive-security binaries with a hardened, auditable execution contract:

- ``argv`` lists only (never ``shell=True``), so shell metacharacters are inert.
- Process-group isolation with SIGTERM→SIGKILL escalation on timeout.
- Sanitized environment (whitelist), no stdin, no interactive pagers.
- Full stdout/stderr persisted as evidence artifacts; in-memory capture is bounded.
- JSONL execution log with SHA-256 of captured output (local integrity evidence).
- Global kill-switch (``CYBERAUDIT_KALI_DISABLED`` / ``CYBERAUDIT_OFFLINE``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import subprocess
import time
import uuid
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cyberaudit.kali.tool_registry import (
    BINARY_ARTIFACTS,
    KALI_TOOLS,
    KaliTool,
    KaliToolError,
    RiskLevel,
)

logger = logging.getLogger("cyberaudit.kali.executor")

KILL_SWITCH_ENV = "CYBERAUDIT_KALI_DISABLED"
OFFLINE_ENV = "CYBERAUDIT_OFFLINE"

_ENV_WHITELIST = ("PATH", "HOME", "LANG", "LC_ALL", "LANGUAGE", "TZ", "USER", "LOGNAME", "SHELL", "TMPDIR", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")


class KaliExecutionDisabled(Exception):
    """Raised when the global kill-switch or offline mode blocks execution."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def kill_switch_engaged() -> Optional[str]:
    """Returns a reason string when execution is globally disabled."""
    if os.getenv(KILL_SWITCH_ENV, "").strip().lower() in ("1", "true", "yes", "on"):
        return f"Kill-switch activo ({KILL_SWITCH_ENV}=1): toda ejecución de herramientas Kali está deshabilitada."
    if os.getenv(OFFLINE_ENV, "").strip().lower() in ("1", "true", "yes", "on"):
        return (
            f"Modo offline activo ({OFFLINE_ENV}=1): CyberAudit no ejecutará herramientas contra objetivos en red. "
            f"Desactívalo (unset {OFFLINE_ENV}) para auditorías en vivo."
        )
    return None


@dataclass
class KaliRunResult:
    """Immutable record of a single tool execution (or dry-run plan)."""

    tool_key: str
    tool_title: str
    risk: str
    argv: List[str]
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
    dry_run: bool = False
    started_at: str = ""
    finished_at: str = ""
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    artifact_paths: List[str] = field(default_factory=list)
    output_sha256: str = ""
    artifact_sha256: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    skip_reason: Optional[str] = None

    @property
    def command_line(self) -> str:
        import shlex

        return " ".join(shlex.quote(part) for part in self.argv)

    @property
    def executed(self) -> bool:
        return not self.dry_run and self.skip_reason is None and self.error is None

    @property
    def succeeded(self) -> bool:
        return self.executed and self.returncode == 0 and not self.timed_out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_key": self.tool_key,
            "tool_title": self.tool_title,
            "risk": self.risk,
            "argv": list(self.argv),
            "command_line": self.command_line,
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "dry_run": self.dry_run,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "artifact_paths": list(self.artifact_paths),
            "output_sha256": self.output_sha256,
            "artifact_sha256": self.artifact_sha256,
            "error": self.error,
            "skip_reason": self.skip_reason,
            "stdout_preview": self.stdout[:4000],
            "stderr_preview": self.stderr[:2000],
        }


class KaliExecutor:
    """Hardened subprocess runner for Kali tooling with evidence capture."""

    def __init__(
        self,
        work_dir: str,
        audit_trail_path: Optional[str] = None,
        dry_run: bool = False,
        max_capture_bytes: int = 262_144,
        require_authorization: Optional[Dict[str, Any]] = None,
        max_output_bytes: int = 64 * 1024 * 1024,
    ):
        self.work_dir = os.path.realpath(work_dir)
        os.makedirs(self.work_dir, exist_ok=True)
        self.audit_trail_path = audit_trail_path or os.path.join(self.work_dir, "kali_audit_trail.jsonl")
        self.dry_run = dry_run
        self.max_capture_bytes = max_capture_bytes
        self.authorization = require_authorization or {}
        self.max_output_bytes = max_output_bytes
        if max_capture_bytes < 1 or max_output_bytes < 1:
            raise ValueError("Los límites de salida deben ser positivos.")

    # ── Environment ──────────────────────────────────────────────────────────
    def _sanitized_env(self) -> Dict[str, str]:
        env: Dict[str, str] = {}
        for key in _ENV_WHITELIST:
            value = os.environ.get(key)
            if value:
                env[key] = value
        env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        env["TERM"] = "dumb"
        env["NO_COLOR"] = "1"
        env["CLICOLOR"] = "0"
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["CYBERAUDIT_KALI"] = "1"
        # Interactive/paging behaviour is always disabled
        env["PAGER"] = "cat"
        env["GIT_PAGER"] = "cat"
        env["DEBIAN_FRONTEND"] = "noninteractive"
        return env

    # ── Execution ────────────────────────────────────────────────────────────
    def plan(self, tool: KaliTool, argv: List[str], note: str = "") -> KaliRunResult:
        """Records an execution plan without running it (dry-run mode)."""
        result = KaliRunResult(
            tool_key=tool.key,
            tool_title=tool.title,
            risk=tool.risk.value,
            argv=list(argv),
            dry_run=True,
            started_at=_utc_now(),
            finished_at=_utc_now(),
            skip_reason=note or None,
        )
        self._record_audit(result, extra={"mode": "dry_run"})
        return result

    def skipped(self, tool: KaliTool, reason: str, argv: Optional[List[str]] = None) -> KaliRunResult:
        """Records a tool that was intentionally not executed (missing binary, missing auth...)."""
        result = KaliRunResult(
            tool_key=tool.key,
            tool_title=tool.title,
            risk=tool.risk.value,
            argv=list(argv or []),
            skip_reason=reason,
            started_at=_utc_now(),
            finished_at=_utc_now(),
        )
        self._record_audit(result, extra={"mode": "skipped"})
        return result

    def run(
        self,
        tool: KaliTool,
        argv: List[str],
        timeout: Optional[int] = None,
        artifact_paths: Optional[List[str]] = None,
    ) -> KaliRunResult:
        """Executes a validated argv, capturing bounded stdout/stderr and artifacts."""
        if not argv:
            raise KaliToolError(f"El argv para {tool.key} está vacío.")

        result = KaliRunResult(
            tool_key=tool.key,
            tool_title=tool.title,
            risk=tool.risk.value,
            argv=list(argv),
            artifact_paths=list(artifact_paths or []),
            started_at=_utc_now(),
        )

        if self.dry_run:
            result.dry_run = True
            result.finished_at = _utc_now()
            self._record_audit(result, extra={"mode": "dry_run"})
            return result

        engaged = kill_switch_engaged()
        if engaged:
            result.error = engaged
            result.finished_at = _utc_now()
            self._record_audit(result, extra={"mode": "blocked"})
            raise KaliExecutionDisabled(engaged)

        effective_timeout = int(timeout or tool.default_timeout)
        run_id = uuid.uuid4().hex
        stdout_path = os.path.join(self.work_dir, f"{tool.key}_{run_id}.stdout.txt")
        stderr_path = os.path.join(self.work_dir, f"{tool.key}_{run_id}.stderr.txt")
        result.stdout_path = stdout_path
        result.stderr_path = stderr_path

        start = time.monotonic()
        raw_out = b""
        raw_err = b""
        try:
            proc = subprocess.Popen(
                argv,
                cwd=self.work_dir,
                env=self._sanitized_env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            result.error = f"Binario no encontrado: {exc}"
            result.returncode = 127
            result.duration_ms = round((time.monotonic() - start) * 1000, 2)
            result.finished_at = _utc_now()
            self._record_audit(result, extra={"mode": "error"})
            return result
        except OSError as exc:
            result.error = f"Error al lanzar el proceso: {exc}"
            result.returncode = 126
            result.duration_ms = round((time.monotonic() - start) * 1000, 2)
            result.finished_at = _utc_now()
            self._record_audit(result, extra={"mode": "error"})
            return result

        errors = []
        limit_hit = threading.Event()
        previews = [bytearray(), bytearray()]

        def drain(stream, path, index):
            count = 0
            try:
                with open(path, "xb") as handle:
                    while True:
                        chunk = stream.read(65536)
                        if not chunk:
                            break
                        remaining = self.max_output_bytes - count
                        if len(chunk) > remaining:
                            limit_hit.set()
                        saved = chunk[:max(0, remaining)]
                        handle.write(saved)
                        count += len(saved)
                        previews[index].extend(saved[:max(0, self.max_capture_bytes - len(previews[index]))])
            except Exception as exc:
                errors.append(str(exc))
                limit_hit.set()
            finally:
                stream.close()

        threads = [threading.Thread(target=drain, args=(stream, path, index), daemon=True)
                   for index, (stream, path) in enumerate(((proc.stdout, stdout_path), (proc.stderr, stderr_path)))]
        for thread in threads:
            thread.start()
        while proc.poll() is None:
            if limit_hit.is_set() or time.monotonic() - start >= effective_timeout:
                result.timed_out = not limit_hit.is_set()
                result.error = (f"Timeout tras {effective_timeout}s" if result.timed_out
                                else "Límite de evidencia excedido o error de escritura")
                self._terminate_process_group(proc)
                break
            time.sleep(0.02)
        for thread in threads:
            thread.join(timeout=10)
        if any(t.is_alive() for t in threads):
            result.error = "Captura incompleta: subproceso mantiene abiertos los streams"
        if limit_hit.is_set():
            result.error = "Límite de evidencia excedido o error de escritura"
        if errors:
            result.error = "No se pudo preservar la evidencia: " + "; ".join(errors)
        result.duration_ms = round((time.monotonic() - start) * 1000, 2)
        result.returncode = proc.returncode if proc.returncode is not None else -1
        result.finished_at = _utc_now()
        result.stdout = bytes(previews[0]).decode("utf-8", errors="replace")
        result.stderr = bytes(previews[1]).decode("utf-8", errors="replace")
        digest = hashlib.sha256()
        try:
            for path in (stdout_path, stderr_path):
                with open(path, "rb") as handle:
                    for chunk in iter(lambda: handle.read(65536), b""):
                        digest.update(chunk)
                digest.update(b"\0")
            result.output_sha256 = digest.hexdigest()
        except OSError as exc:
            result.error = f"Evidencia no disponible: {exc}"

        for artifact in list(result.artifact_paths):
            if not os.path.isfile(artifact):
                continue
            try:
                artifact_hash = hashlib.sha256()
                with open(artifact, "rb") as handle:
                    for chunk in iter(lambda: handle.read(65536), b""):
                        artifact_hash.update(chunk)
                result.artifact_sha256[artifact] = artifact_hash.hexdigest()
            except OSError as exc:
                result.error = f"No se pudo verificar el artefacto: {exc}"

        self._record_audit(result, extra={"mode": "executed", "timeout_seconds": effective_timeout})
        return result

    @staticmethod
    def _terminate_process_group(proc: subprocess.Popen) -> None:
        if os.name == "nt":
            # terminate() alone leaves scanner grandchildren alive on Windows.
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            pgid = os.getpgid(proc.pid)
        except (AttributeError, ProcessLookupError, OSError):
            pgid = None
        try:
            if pgid:
                os.killpg(pgid, signal.SIGTERM)
            else:
                proc.terminate()
        except (ProcessLookupError, OSError):
            return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            if pgid:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass

    @staticmethod
    def _write_evidence(path: str, content: str) -> None:
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as handle:
                handle.write(content)
        except OSError as exc:  # pragma: no cover - disk level failure
            logger.warning("No se pudo escribir la evidencia %s: %s", path, exc)

    # ── Audit trail ──────────────────────────────────────────────────────────
    def _record_audit(self, result: KaliRunResult, extra: Optional[Dict[str, Any]] = None) -> None:
        entry: Dict[str, Any] = {
            "timestamp": result.finished_at or _utc_now(),
            "tool": result.tool_key,
            "tool_title": result.tool_title,
            "risk": result.risk,
            "argv": list(result.argv),
            "command_line": result.command_line,
            "returncode": result.returncode,
            "duration_ms": result.duration_ms,
            "timed_out": result.timed_out,
            "output_sha256": result.output_sha256,
            "artifact_sha256": result.artifact_sha256,
            "artifacts": list(result.artifact_paths),
            "error": result.error,
            "skip_reason": result.skip_reason,
        }
        entry.update(self.authorization or {})
        if extra:
            entry.update(extra)
        try:
            with open(self.audit_trail_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:  # pragma: no cover
            raise OSError(f"No se pudo preservar el audit trail: {exc}") from exc


def tool_for(key: str) -> Optional[KaliTool]:
    return KALI_TOOLS.get(key)


__all__ = [
    "KaliExecutor",
    "KaliRunResult",
    "KaliExecutionDisabled",
    "kill_switch_engaged",
    "RiskLevel",
]
