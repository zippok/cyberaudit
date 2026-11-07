"""Optional shared-workspace RBAC and transactionally chained audit events."""
import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cyberaudit.web_auditor.business import canonical


AUDITOR_POSTS = {"/api/audit-web", "/api/audit-business", "/api/qa/run"}
REVIEWER_POSTS = {"/api/findings/status"}


def identify(authorization):
    config = json.loads(Path(os.environ["CYBERAUDIT_RBAC_FILE"]).read_text(encoding="utf-8"))
    if set(config) != {"version", "principals"} or config["version"] != 1 or not isinstance(config["principals"], list) or not config["principals"]:
        raise ValueError("Invalid RBAC configuration")
    identities, secrets, matched = set(), set(), None
    for principal in config["principals"]:
        if not isinstance(principal, dict) or not {"id", "role", "token_env"}.issubset(principal) or set(principal) - {"id", "role", "token_env", "organization"}:
            raise ValueError("Invalid principal")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", principal["id"]) or principal["id"] in identities:
            raise ValueError("Invalid or duplicate principal")
        if principal["role"] not in ("viewer", "reviewer", "auditor", "admin"):
            raise ValueError("Invalid role")
        token = os.environ.get(principal["token_env"], "")
        if len(token.encode()) < 32 or token in secrets:
            raise ValueError("Missing, weak or duplicate access token")
        identities.add(principal["id"])
        secrets.add(token)
        if hmac.compare_digest(authorization.encode(), ("Bearer " + token).encode()):
            organization = os.getenv("CYBERAUDIT_ORGANIZATION")
            if not organization or principal.get("organization") == organization:
                matched = {"id": principal["id"], "role": principal["role"], "organization": principal.get("organization")}
    return matched


def permitted(principal, method, path):
    role = principal["role"]
    if role == "admin" or method in ("GET", "HEAD", "OPTIONS"):
        return True
    return method == "POST" and ((role == "auditor" and path in AUDITOR_POSTS) or
                                  (role == "reviewer" and path in REVIEWER_POSTS))


def _verify_rows(rows, key):
    previous = "0" * 64
    for sequence, payload, signature in rows:
        data = json.loads(payload)
        if data["sequence"] != sequence or data["previous"] != previous:
            raise ValueError("Audit chain sequence mismatch")
        expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Audit chain signature mismatch")
        previous = signature
    return previous


def append_event(event):
    key = os.environ.get("CYBERAUDIT_AUDIT_KEY", "").encode()
    if len(key) < 32:
        raise ValueError("CYBERAUDIT_AUDIT_KEY must contain at least 32 bytes")
    path = Path(os.environ.get("CYBERAUDIT_AUDIT_DB", "reports/enterprise/events.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=10) as db:
        db.execute("CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, signature TEXT NOT NULL)")
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute("SELECT sequence,payload,signature FROM events ORDER BY sequence").fetchall()
        previous = _verify_rows(rows, key)
        sequence = len(rows) + 1
        data = {"event": event, "sequence": sequence, "previous": previous,
                "time": datetime.now(timezone.utc).isoformat()}
        payload = canonical(data).decode()
        signature = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        db.execute("INSERT INTO events VALUES (?,?,?)", (sequence, payload, signature))
    return signature


async def enterprise_request(request, call_next, lock):
    from fastapi.responses import JSONResponse
    try:
        principal = identify(request.headers.get("authorization", ""))
        allowed = principal is not None and permitted(principal, request.method, request.url.path)
        if allowed and os.getenv("CYBERAUDIT_ORGANIZATION"):
            from cyberaudit.web.organization import validate_request
            try:
                await validate_request(request)
            except (ValueError, OSError, TypeError):
                allowed = False
        # Never retain headers, queries, payloads or arbitrary URL components.
        event = {"request_id": uuid.uuid4().hex, "actor": principal["id"] if principal else "unknown",
                 "role": principal["role"] if principal else None, "method": request.method,
                 "path_sha256": hashlib.sha256(request.url.path.encode()).hexdigest(),
                 "decision": "ALLOW" if allowed else "DENY"}
        event["organization"] = os.getenv("CYBERAUDIT_ORGANIZATION")
        append_event({**event, "phase": "authorization"})
        if not allowed:
            return JSONResponse({"detail": "Permiso insuficiente" if principal else "Credencial requerida"}, status_code=403 if principal else 401)
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error):
        return JSONResponse({"detail": "Configuración empresarial o bitácora no disponible"}, status_code=503)
    mutation = request.method not in ("GET", "HEAD", "OPTIONS")
    acquired = not mutation or lock.acquire(blocking=False)
    status = 500
    try:
        if not acquired:
            response = JSONResponse({"detail": "Otra operación está en curso"}, status_code=409)
        else:
            response = await call_next(request)
        status = response.status_code
    finally:
        if mutation and acquired:
            lock.release()
        try:
            append_event({**event, "phase": "completion", "status": status})
        except (ValueError, OSError, KeyError, TypeError, sqlite3.Error):
            return JSONResponse({"detail": "Falló el registro final; la operación puede haberse ejecutado"}, status_code=503)
    return response
