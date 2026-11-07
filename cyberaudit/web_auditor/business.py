"""Scoped, authenticated browser workflows with role-isolated sessions."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

from playwright.sync_api import sync_playwright

from cyberaudit.kali.scope import ScopeGuard, ScopeViolationError
from cyberaudit.kali.tool_registry import RiskLevel
from cyberaudit.web_auditor.browser_probes import check_http_url, origin, load_journey, run_journey
from cyberaudit.web.organization import confined_path


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def load_business_plan(path):
    path = confined_path(path).resolve(strict=True)
    plan = json.loads(path.read_text(encoding="utf-8"))
    allowed = {"version", "url", "scope", "roles", "journeys", "access_checks", "browsers", "require_signature", "interactive"}
    if not isinstance(plan, dict) or set(plan) - allowed or plan.get("version") != 1:
        raise ValueError("Plan empresarial inválido")
    check_http_url(plan["url"])
    if type(plan.get("require_signature", False)) is not bool:
        raise ValueError("require_signature debe ser booleano")
    if type(plan.get("interactive", False)) is not bool:
        raise ValueError("interactive debe ser booleano")
    browsers = plan.get("browsers", ["chromium"])
    if not isinstance(browsers, list) or not browsers or len(set(browsers)) != len(browsers) or any(b not in ("chromium", "firefox", "webkit") for b in browsers):
        raise ValueError("Navegadores inválidos")
    plan["browsers"] = browsers
    scope = confined_path(path.parent / plan["scope"]).resolve(strict=True)
    guard = ScopeGuard.from_file(str(scope))
    try:
        guard.authorize(plan["url"], RiskLevel.INTRUSIVE)
    except ScopeViolationError as exc:
        raise ValueError("Alcance no autorizado para la auditoría de negocio") from exc
    roles = plan.get("roles")
    if not isinstance(roles, dict) or not 2 <= len(roles) <= 10 or roles.get("anonymous") != {}:
        raise ValueError("Se requieren 2–10 roles, incluido anonymous: {}")
    inputs = {"plan": hashlib.sha256(path.read_bytes()).hexdigest(), "scope": hashlib.sha256(scope.read_bytes()).hexdigest()}
    loaded = {}
    for role, auth in roles.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", role) or not isinstance(auth, dict):
            raise ValueError("Rol inválido")
        if role == "anonymous":
            continue
        if "login" not in auth or set(auth) - {"login", "identity_origins"}:
            raise ValueError("Cada rol autenticado requiere un recorrido login con aserciones")
        origins = auth.get("identity_origins", [])
        if not isinstance(origins, list) or len(origins) > 5:
            raise ValueError("identity_origins requiere una lista de hasta cinco orígenes")
        for identity_url in origins:
            check_http_url(identity_url)
            try:
                guard.authorize(identity_url, RiskLevel.INTRUSIVE)
            except ScopeViolationError as exc:
                raise ValueError("Proveedor de identidad fuera del alcance autorizado") from exc
        login = confined_path(path.parent / auth["login"]).resolve(strict=True)
        loaded[role] = load_journey(login)
        for step in loaded[role]["steps"]:
            if step["action"] == "fill" and ("value" in step or "value_env" not in step):
                raise ValueError("El login solo admite credenciales mediante value_env")
        inputs[f"login:{role}"] = hashlib.sha256(login.read_bytes()).hexdigest()
    journeys = plan.get("journeys")
    checks = plan.get("access_checks")
    if not isinstance(journeys, list) or not 1 <= len(journeys) <= 30:
        raise ValueError("Se requieren 1–30 recorridos de negocio")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 100:
        raise ValueError("Se requiere una matriz de acceso con 1–100 controles")
    names = set()
    for entry in journeys:
        if not isinstance(entry, dict) or set(entry) != {"id", "role", "file"} or entry["role"] not in roles:
            raise ValueError("Recorrido de negocio inválido")
        if not isinstance(entry["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", entry["id"]) or entry["id"] in names:
            raise ValueError("Identificador de recorrido inválido o duplicado")
        names.add(entry["id"])
        file = confined_path(path.parent / entry["file"]).resolve(strict=True)
        entry["definition"] = load_journey(file)
        inputs[f"journey:{entry['id']}"] = hashlib.sha256(file.read_bytes()).hexdigest()
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"id", "path", "expected"}:
            raise ValueError("Control de acceso inválido")
        if not isinstance(check["id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", check["id"]) or check["id"] in names:
            raise ValueError("Identificador de control inválido o duplicado")
        names.add(check["id"])
        url = check_http_url(urljoin(plan["url"], check["path"]))
        if origin(url) != origin(plan["url"]):
            raise ValueError("El control de acceso sale del origen autorizado")
        if not isinstance(check["expected"], dict) or set(check["expected"]) != set(roles):
            raise ValueError("Cada control debe declarar el resultado de todos los roles")
        for expected in check["expected"].values():
            if not isinstance(expected, dict) or set(expected) - {"status", "json_equals"}:
                raise ValueError("Resultado esperado inválido")
            if type(expected.get("status")) is not int or not 200 <= expected["status"] <= 599:
                raise ValueError("Estado HTTP esperado inválido")
            if expected["status"] < 300 and (not isinstance(expected.get("json_equals"), dict) or not expected["json_equals"]):
                raise ValueError("El acceso exitoso requiere json_equals para verificar el recurso o identidad")
        if check["expected"]["anonymous"]["status"] not in (401, 403):
            raise ValueError("El recurso protegido debe denegar acceso anónimo (401/403)")
    for role in roles:
        if role != "anonymous" and not any(c["expected"][role]["status"] < 300 for c in checks):
            raise ValueError("Cada rol autenticado necesita un control exitoso de identidad o recurso")
    return plan, guard, loaded, inputs


def run_business_audit(plan_path, output_root="reports/business"):
    if os.getenv("CYBERAUDIT_OFFLINE", "").lower() in ("1", "true", "yes", "on"):
        raise ValueError("CYBERAUDIT_OFFLINE activo")
    plan, guard, logins, inputs = load_business_plan(plan_path)
    key = os.getenv("CYBERAUDIT_SIGNING_KEY", "")
    if plan.get("require_signature") and len(key.encode()) < 32:
        raise ValueError("Se requiere CYBERAUDIT_SIGNING_KEY de al menos 32 bytes")
    # Fail before any interaction if a requested secret is missing.
    for journey in list(logins.values()) + [j["definition"] for j in plan["journeys"]]:
        for step in journey["steps"]:
            for field in ("value_env", "secret_env"):
                if field in step and not os.getenv(step[field]):
                    raise ValueError("Falta una variable de credencial o dato requerida por el recorrido")
    report = {"version": 1, "id": uuid.uuid4().hex, "started_at": datetime.now(timezone.utc).isoformat(),
              "input_sha256": inputs, "results": [], "limitations": [
                  "Los resultados cubren exclusivamente los recursos, roles y recorridos declarados.",
                  "La restricción de navegador no sustituye el aislamiento de red del sistema operativo.",
                  "No se persisten cookies, credenciales, cuerpos de respuesta ni capturas."]}
    results = report["results"]
    with sync_playwright() as pw:
        for name in plan["browsers"]:
            browser = None
            try:
                browser = getattr(pw, name).launch(headless=not plan.get("interactive", False))
                for role in plan["roles"]:
                    context = browser.new_context(service_workers="block", accept_downloads=False)
                    blocked = []
                    login_phase = [True]
                    identity_origins = {origin(u) for u in plan["roles"][role].get("identity_origins", [])}
                    login_origins = identity_origins | {origin(plan["url"])}
                    def route_request(route):
                        try:
                            url = check_http_url(route.request.url)
                            if origin(url) not in (login_origins if login_phase[0] else {origin(plan["url"])}):
                                raise ValueError("Fuera de origen")
                            guard.authorize(url, RiskLevel.INTRUSIVE)
                            route.continue_()
                        except Exception:
                            blocked.append(True)
                            route.abort()
                    context.route("**/*", route_request)
                    prefix = {"browser": name, "browser_version": browser.version, "role": role}
                    try:
                        page = context.new_page()
                        page.goto(plan["url"], wait_until="load", timeout=15000)
                        login = run_journey(page, plan["url"], logins[role], login_origins) if role != "anonymous" else {"status": "PASS", "steps": []}
                        login_phase[0] = False
                        if origin(page.url) != origin(plan["url"]):
                            login["status"] = "FAIL"
                        results.append({**prefix, "kind": "authentication", **login})
                        for check in plan["access_checks"]:
                            item = {**prefix, "kind": "access", "id": check["id"], "status": "NOT_RUN"}
                            if login["status"] == "PASS":
                                try:
                                    expected = check["expected"][role]
                                    # Browser fetch shares only this role's cookies and passes through route guards.
                                    measured = page.evaluate("""async ({url, expected}) => {
                                      const r = await fetch(url, {credentials:'same-origin', redirect:'error', signal:AbortSignal.timeout(10000), cache:'no-store'});
                                      let matched = true;
                                      if (expected.json_equals !== undefined) {
                                        const reader = r.body.getReader(); let size=0; const chunks=[];
                                        while(true) {const {value,done}=await reader.read(); if(done)break;
                                          size+=value.byteLength; if(size>1048576){await reader.cancel();throw Error('Response too large');} chunks.push(value);}
                                        const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
                                        const data=JSON.parse(new TextDecoder().decode(bytes));
                                        const stable=v=>Array.isArray(v)?v.map(stable):v!==null&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
                                        matched = data!==null && Object.entries(expected.json_equals).every(([k,v]) => JSON.stringify(stable(data[k])) === JSON.stringify(stable(v)));
                                      } else if (r.body) {
                                        await r.body.cancel();
                                      }
                                      return {http_status:r.status, assertion:matched};
                                    }""", {"url": urljoin(plan["url"], check["path"]), "expected": expected})
                                    item.update(measured)
                                    item["status"] = "PASS" if measured["http_status"] == expected["status"] and measured["assertion"] else "FAIL"
                                except Exception as exc:
                                    item.update(status="ERROR", error_type=type(exc).__name__)
                            results.append(item)
                        for journey in plan["journeys"]:
                            if journey["role"] == role:
                                result = run_journey(page, plan["url"], journey["definition"]) if login["status"] == "PASS" else {"status": "NOT_RUN"}
                                results.append({**prefix, "kind": "business", "id": journey["id"], **result})
                    except Exception as exc:
                        results.append({**prefix, "kind": "session", "status": "ERROR", "error_type": type(exc).__name__})
                    finally:
                        if blocked:
                            results.append({**prefix, "kind": "network_scope", "status": "ERROR", "blocked": len(blocked)})
                        context.close()
            except Exception as exc:
                results.append({"browser": name, "kind": "engine", "status": "ERROR", "error_type": type(exc).__name__})
            finally:
                if browser:
                    browser.close()
    report["status"] = "ERROR" if any(r["status"] == "ERROR" for r in results) else "FAIL" if any(r["status"] == "FAIL" for r in results) else "INCONCLUSIVE" if not results or any(r["status"] == "NOT_RUN" for r in results) else "PASS"
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    raw = canonical(report)
    envelope = {"report": report, "sha256": hashlib.sha256(raw).hexdigest(),
                "signature": hmac.new(key.encode(), raw, hashlib.sha256).hexdigest() if len(key.encode()) >= 32 else None,
                "signature_type": "HMAC-SHA256" if len(key.encode()) >= 32 else "UNSIGNED"}
    directory = Path(output_root).resolve() / report["id"]
    directory.mkdir(parents=True)
    (directory / "report.json").write_bytes(canonical(envelope))
    return envelope, directory


def verify_business_report(path, key=None):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw = canonical(data["report"])
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), data["sha256"]):
        return False
    key = key if key is not None else os.getenv("CYBERAUDIT_SIGNING_KEY", "")
    return len(key.encode()) >= 32 and data.get("signature_type") == "HMAC-SHA256" and hmac.compare_digest(hmac.new(key.encode(), raw, hashlib.sha256).hexdigest(), data.get("signature") or "")
