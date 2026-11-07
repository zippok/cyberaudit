"""Real browser probes. Missing observations are null, never synthetic zeroes."""
from __future__ import annotations

import json
import os
import base64
import hashlib
import hmac
import struct
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import expect

VITALS_INIT = r"""(() => {
  const supported = PerformanceObserver.supportedEntryTypes || [];
  const data = window.__cyberAuditVitals = {
    lcp: null, fcp: null, cls: supported.includes('layout-shift') ? 0 : null,
    interaction_latency_max_ms: null, interactions: 0, supported,
    observer_errors: [], observation_started_ms: performance.now()
  };
  let first = 0, last = 0, session = 0;
  function observe(type, callback, options = {}) {
    if (!supported.includes(type)) return;
    try { new PerformanceObserver(list => callback(list.getEntries()))
      .observe({type, buffered: true, ...options}); }
    catch (e) { data.observer_errors.push(String(e)); }
  }
  observe('largest-contentful-paint', entries => {
    for (const entry of entries) data.lcp = entry.startTime;
  });
  observe('paint', entries => {
    for (const entry of entries) if (entry.name === 'first-contentful-paint') data.fcp = entry.startTime;
  });
  observe('layout-shift', entries => {
    for (const entry of entries) {
      if (entry.hadRecentInput) continue;
      if (session && entry.startTime - last < 1000 && entry.startTime - first < 5000) session += entry.value;
      else { session = entry.value; first = entry.startTime; }
      last = entry.startTime;
      data.cls = Math.max(data.cls, session);
    }
  });
  observe('event', entries => {
    for (const entry of entries) if (entry.interactionId) {
      data.interactions++;
      data.interaction_latency_max_ms = Math.max(data.interaction_latency_max_ms || 0, entry.duration);
    }
  }, {durationThreshold: 16});
})();"""


def origin(url):
    parts = urlsplit(url)
    return (parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))


def check_http_url(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("Se requiere URL HTTP(S) sin credenciales incrustadas")
    return url


def probe_pwa(page, context, timeout_ms=10000, expected=False, offline_selector=None, network_route=None):
    """Inspect actual manifest/worker and reload with browser networking disabled.

    Successful offline navigation alone does not prove business functionality;
    a project-specific selector supplies an explicit offline assertion.
    """
    url = page.url
    result = {"checks": [], "manifest": None, "worker": None, "offline": None}

    def check(name, passed, evidence):
        result["checks"].append({"name": name, "passed": bool(passed), "evidence": evidence})

    manifest_url = page.locator('link[rel~="manifest"]').first.get_attribute("href") if page.locator('link[rel~="manifest"]').count() else None
    if not manifest_url:
        result["status"] = "FAIL" if expected else "NOT_APPLICABLE"
        if expected:
            check("manifest_present", False, "No se declaró un manifest")
        return result
    manifest_url = urljoin(url, manifest_url)
    check_http_url(manifest_url)
    if origin(manifest_url) != origin(url):
        result.update(status="INCONCLUSIVE", reason="Manifest externo requiere alcance explícito")
        return result
    manifest = page.evaluate("""async ({url, timeout}) => {
      const response = await fetch(url, {signal: AbortSignal.timeout(timeout)});
      const body = await response.text();
      if (body.length > 1048576) throw new Error('Manifest excede 1 MiB');
      return {status: response.status, url: response.url, body};
    }""", {"url": manifest_url, "timeout": timeout_ms})
    check("manifest_http", manifest["status"] == 200, manifest["status"])
    if manifest["status"] != 200:
        result["status"] = "FAIL"
        return result
    data = json.loads(manifest["body"])
    if not isinstance(data, dict):
        raise ValueError("Manifest debe ser un objeto JSON")
    result["manifest"] = {"url": manifest_url, "data": data}
    check("manifest_name", bool(data.get("name") or data.get("short_name")), "name/short_name")
    start_url = urljoin(manifest_url, data.get("start_url", url))
    scope = urljoin(manifest_url, data.get("scope", urljoin(start_url, ".")))
    check("start_url_origin", origin(start_url) == origin(url), start_url)
    check("start_url_scope", origin(scope) == origin(start_url) and urlsplit(start_url).path.startswith(urlsplit(scope).path), scope)
    check("display_mode", data.get("display") in ("standalone", "fullscreen", "minimal-ui"), data.get("display"))
    icons = data.get("icons", [])
    if not isinstance(icons, list):
        raise ValueError("icons debe ser una lista")
    check("icons_declared", bool(icons), len(icons))
    for icon in icons[:20]:
        icon_url = urljoin(manifest_url, icon["src"])
        if origin(icon_url) != origin(url):
            check("icon_same_origin", False, icon_url)
            continue
        measured = page.evaluate("""({url, timeout}) => new Promise(resolve => {
          const image = new Image();
          const timer = setTimeout(() => {image.src=''; resolve({loaded:false, reason:'timeout'});}, timeout);
          image.onload = () => {clearTimeout(timer); resolve({loaded:true,width:image.naturalWidth,height:image.naturalHeight});};
          image.onerror = () => {clearTimeout(timer); resolve({loaded:false});};
          image.src = url;
        })""", {"url": icon_url, "timeout": timeout_ms})
        check("icon_load", measured.get("loaded"), {"url": icon_url, **measured})
    worker = page.evaluate("""async timeout => {
      if (!('serviceWorker' in navigator)) return {supported:false};
      const ready = await Promise.race([navigator.serviceWorker.ready.then(() => true),
        new Promise(resolve => setTimeout(() => resolve(false), timeout))]);
      const regs = await navigator.serviceWorker.getRegistrations();
      return {supported:true, ready, controlled:!!navigator.serviceWorker.controller,
        registrations:regs.map(r=>({scope:r.scope,active:r.active?.scriptURL || null,state:r.active?.state || null})),
        caches:('caches' in window) ? await caches.keys() : []};
    }""", timeout_ms)
    result["worker"] = worker
    check("worker_active", worker.get("ready"), worker)
    if worker.get("ready") and not worker.get("controlled"):
        page.reload(wait_until="load", timeout=timeout_ms)
    try:
        context.set_offline(True)
        # Routing can bypass service worker navigation in Firefox/WebKit. Remove
        # it only while networking is disabled; restore before reconnecting.
        if network_route:
            context.unroute("**/*", network_route)
        response = page.reload(wait_until="load", timeout=timeout_ms)
        usable = response is not None and response.ok and page.locator("body").inner_text().strip() != ""
        if offline_selector:
            expect(page.locator(offline_selector)).to_be_visible(timeout=timeout_ms)
        result["offline"] = {"loaded": usable, "http_status": response.status if response else None,
            "from_service_worker": response.from_service_worker if response else False,
            "navigator_online": page.evaluate("navigator.onLine"),
            "selector": offline_selector, "business_assertion": "PASS" if offline_selector else "NOT_RUN"}
        check("offline_reload", usable, result["offline"])
    except Exception as exc:
        result["offline"] = {"loaded": False, "error": str(exc)}
        if "internal error" in str(exc).lower():
            result["status"] = "INCONCLUSIVE"
            result["offline"]["status"] = "ERROR"
        else:
            check("offline_reload", False, str(exc))
    finally:
        if network_route:
            context.route("**/*", network_route)
        context.set_offline(False)
    response = page.goto(url, wait_until="load", timeout=timeout_ms)
    check("online_recovery", response is not None and response.ok, response.status if response else None)
    result.setdefault("status", "PASS" if all(c["passed"] for c in result["checks"]) else "FAIL")
    return result


def totp(secret, now=None):
    """RFC 6238 SHA-1, six digits, 30 seconds; only explicitly supplied test seeds."""
    seed = secret.replace(" ", "").upper()
    key = base64.b32decode(seed + "=" * ((-len(seed)) % 8))
    if len(key) < 16:
        raise ValueError("Semilla TOTP demasiado corta")
    counter = int(time.time() if now is None else now) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}"


def load_journey(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("Recorrido debe declarar version: 1")
    steps = data.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 100:
        raise ValueError("Se requieren 1–100 pasos")
    assertions = 0
    for step in steps:
        if not isinstance(step, dict) or step.get("action") not in ("goto", "click", "fill", "fill_totp", "check", "select", "expect_visible", "expect_text", "expect_url", "expect_hidden", "expect_enabled", "expect_disabled", "expect_checked", "expect_value", "expect_count"):
            raise ValueError("Acción desconocida")
        assertions += step["action"].startswith("expect_")
        action = step["action"]
        fields = {"action", "timeout_ms"}
        if action in ("goto", "expect_url"):
            fields.add("url")
            if not isinstance(step.get("url"), str) or not step["url"]:
                raise ValueError("Falta URL del paso")
        else:
            fields.add("selector")
            if not isinstance(step.get("selector"), str) or not step["selector"]:
                raise ValueError("Falta selector del paso")
        if action in ("fill", "expect_value"):
            fields.update(("value", "value_env"))
            if ("value" in step) == ("value_env" in step):
                raise ValueError("Declara value o value_env, no ambos")
            if not isinstance(step.get("value", step.get("value_env")), str):
                raise ValueError("Valor de paso inválido")
        if action == "select":
            fields.add("value")
            if not isinstance(step.get("value"), str):
                raise ValueError("Falta opción a seleccionar")
        if action == "fill_totp":
            fields.add("secret_env")
            if not isinstance(step.get("secret_env"), str) or not step["secret_env"]:
                raise ValueError("TOTP requiere secret_env")
        if action == "expect_text":
            fields.add("text")
            if not isinstance(step.get("text"), str):
                raise ValueError("Falta texto esperado")
        if action == "expect_count":
            fields.add("count")
            if type(step.get("count")) is not int or step["count"] < 0:
                raise ValueError("Cantidad esperada inválida")
        if set(step) - fields:
            raise ValueError("Campos desconocidos en el paso")
        timeout = step.get("timeout_ms", 10000)
        if type(timeout) is not int or not 1 <= timeout <= 60000:
            raise ValueError("timeout_ms debe estar entre 1 y 60000")
    if not assertions:
        raise ValueError("Un recorrido necesita al menos una aserción de resultado")
    return data


def run_journey(page, base_url, journey, allowed_origins=None):
    permitted_origins = set(allowed_origins or (origin(base_url),))
    logs = []
    for index, step in enumerate(journey["steps"]):
        action = step["action"]
        timeout = step.get("timeout_ms", 10000)
        # Never preserve fill values or environment secrets in the evidence.
        entry = {"step": index + 1, "action": action, "status": "PASS"}
        try:
            if action == "goto":
                url = check_http_url(urljoin(base_url, step["url"]))
                if origin(url) not in permitted_origins:
                    raise ValueError("Navegación fuera del origen autorizado")
                response = page.goto(url, wait_until="load", timeout=timeout)
                if response is None or not response.ok:
                    raise ValueError("Navegación sin respuesta HTTP exitosa")
            elif action == "expect_url":
                expect(page).to_have_url(urljoin(base_url, step["url"]), timeout=timeout)
            else:
                locator = page.locator(step["selector"])
                if action == "click":
                    locator.click(timeout=timeout)
                elif action == "fill":
                    value = os.environ[step["value_env"]] if "value_env" in step else step["value"]
                    locator.fill(value, timeout=timeout)
                elif action == "fill_totp":
                    locator.fill(totp(os.environ[step["secret_env"]]), timeout=timeout)
                elif action == "check":
                    locator.check(timeout=timeout)
                elif action == "select":
                    locator.select_option(step["value"], timeout=timeout)
                elif action == "expect_visible":
                    expect(locator).to_be_visible(timeout=timeout)
                elif action == "expect_text":
                    expect(locator).to_have_text(step["text"], timeout=timeout)
                elif action == "expect_hidden":
                    expect(locator).to_be_hidden(timeout=timeout)
                elif action == "expect_enabled":
                    expect(locator).to_be_enabled(timeout=timeout)
                elif action == "expect_disabled":
                    expect(locator).to_be_disabled(timeout=timeout)
                elif action == "expect_checked":
                    expect(locator).to_be_checked(timeout=timeout)
                elif action == "expect_value":
                    value = os.environ[step["value_env"]] if "value_env" in step else step["value"]
                    expect(locator).to_have_value(value, timeout=timeout)
                elif action == "expect_count":
                    expect(locator).to_have_count(step["count"], timeout=timeout)
            if origin(page.url) not in permitted_origins:
                raise ValueError("Recorrido salió del origen autorizado")
        except Exception as exc:
            # Playwright exception text may contain a filled password; store type only.
            entry.update(status="FAIL", error_type=type(exc).__name__)
            logs.append(entry)
            return {"status": "FAIL", "steps": logs, "not_run": len(journey["steps"]) - len(logs)}
        logs.append(entry)
    return {"status": "PASS", "steps": logs, "not_run": 0}
