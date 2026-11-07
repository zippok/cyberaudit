"""One request per SSH/WSL invocation. Install this package in the Kali Python environment."""
from __future__ import annotations

import contextlib
import json
import sys

from cyberaudit.kali.executor import kill_switch_engaged
from cyberaudit.kali.scope import EngagementScope, ScopeGuard
from cyberaudit.kali.orchestrator import KaliAuditOrchestrator
from cyberaudit.kali.tool_registry import discover_tools


def handle_request(request: dict) -> dict:
    if not isinstance(request, dict) or request.get("protocol") != 1:
        raise ValueError("Protocolo no soportado")
    if kill_switch_engaged():
        raise ValueError(kill_switch_engaged())
    action = request.get("action")
    if action == "inventory":
        return {"protocol": 1, "ok": True, "tools": [tool.to_dict() for tool in discover_tools()]}
    if action != "scan":
        raise ValueError("Acción no soportada")
    scope = EngagementScope.from_dict(request.get("scope", {}))
    options = request.get("options", {})
    if not isinstance(options, dict):
        raise ValueError("Opciones inválidas")
    allowed = {"target", "profile", "tools", "dry_run", "allow_intrusive", "wordlist", "ports", "extras", "run_exploit_correlation"}
    if set(options) - allowed:
        raise ValueError("Opciones no permitidas")
    for key in ("dry_run", "allow_intrusive", "run_exploit_correlation"):
        if key in options and type(options[key]) is not bool:
            raise ValueError(f"{key} debe ser booleano")
    # Resolve targets and enforce scope on Kali, where the connections originate.
    result = KaliAuditOrchestrator(scope_guard=ScopeGuard(scope)).audit(**options)
    return {"protocol": 1, "ok": True, "result": result.to_dict(),
            "evidence_location": "worker", "note": "Los artefactos brutos permanecen en Kali; el resultado incluye sus rutas y hashes."}


def main():
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Solicitud demasiado grande")
        with contextlib.redirect_stdout(sys.stderr):
            response = handle_request(json.loads(raw))
        print(json.dumps(response, ensure_ascii=True, allow_nan=False))
    except Exception as exc:
        print(json.dumps({"protocol": 1, "ok": False, "error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
