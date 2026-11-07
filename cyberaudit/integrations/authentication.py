"""Explicit, same-origin credential checks before and after external scans."""
import json
import os
import re
from urllib.parse import urljoin
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError

from cyberaudit.kali.scope import ScopeGuard
from cyberaudit.kali.tool_registry import RiskLevel
from cyberaudit.web_auditor.browser_probes import check_http_url, origin


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def auth_settings(step, resolve_secret=True):
    config = step.get("auth")
    if config is None:
        return None
    if step["tool"] not in ("zap", "schemathesis") or not isinstance(config, dict) or set(config) != {"header", "value_env", "verify_path", "identity"}:
        raise ValueError("Autenticación externa inválida")
    header = config["header"]
    if header not in ("Authorization", "Cookie", "X-API-Key") or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", config["value_env"]):
        raise ValueError("Cabecera o variable de autenticación inválida")
    url = check_http_url(urljoin(step["url"], config["verify_path"]))
    if origin(url) != origin(step["url"]) or not isinstance(config["identity"], dict) or not config["identity"]:
        raise ValueError("La identidad debe verificarse en el mismo origen")
    secret = os.getenv(config["value_env"], "") if resolve_secret else ""
    if resolve_secret and (not secret or len(secret) > 8192 or any(c in secret for c in "\r\n\0")):
        raise ValueError("Credencial ausente o inválida")
    return {"header": header, "url": url, "secret": secret, "identity": config["identity"]}


def verify_authentication(step):
    config = auth_settings(step)
    if config is None:
        return None
    guard = ScopeGuard.from_file(step["scope"])
    guard.authorize(config["url"], RiskLevel.INTRUSIVE)
    opener = build_opener(NoRedirect())
    observed = []
    for authenticated in (False, True):
        headers = {"Accept": "application/json", "Cache-Control": "no-store"}
        if authenticated:
            headers[config["header"]] = config["secret"]
        try:
            response = opener.open(Request(config["url"], headers=headers), timeout=10)
        except HTTPError as exc:
            response = exc
        with response:
            status = response.status
            raw = response.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("Respuesta de identidad demasiado grande")
        if authenticated:
            if status != 200:
                raise ValueError("La credencial no permite verificar la identidad")
            data = json.loads(raw)
            if not isinstance(data, dict) or any(data.get(k) != v for k, v in config["identity"].items()):
                raise ValueError("La identidad no coincide con el plan")
        elif status not in (401, 403):
            raise ValueError("El control anónimo no deniega acceso al recurso de identidad")
        observed.append(status)
    return {"status": "PASS", "anonymous_http": observed[0], "authenticated_http": observed[1], "identity_matched": True}
