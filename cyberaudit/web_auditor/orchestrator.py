"""Live browser audits with measured evidence and explicit incomplete states."""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from playwright.sync_api import sync_playwright
from cyberaudit.core.models import Finding, ScanReport, Severity, Pillar
from cyberaudit.core.target_verifier import TargetVerifier
from cyberaudit.web_auditor.headers_cookies import HeadersAndCookieAuditor
from cyberaudit.web_auditor.client_security import ClientSecurityAuditor
from cyberaudit.web_auditor.a11y_axe import A11yAndVitalsAuditor
from cyberaudit.web_auditor.passive_recon import PassiveWebReconAuditor
from cyberaudit.web_auditor.browser_probes import VITALS_INIT, check_http_url, origin, probe_pwa, load_journey, run_journey


class WebAuditorOrchestrator:
    def __init__(self, timeout_ms=30000):
        self.timeout_ms = timeout_ms
        self.headers_auditor = HeadersAndCookieAuditor()
        self.client_auditor = ClientSecurityAuditor()
        self.a11y_auditor = A11yAndVitalsAuditor()
        self.recon_auditor = PassiveWebReconAuditor()

    def audit(self, target_url, allow_local=False, run_a11y=True, run_passive_recon=True,
              browsers=("chromium",), expect_pwa=False, journey_path=None,
              offline_selector=None, evidence_root="reports/web", observation_ms=2000):
        if os.getenv("CYBERAUDIT_OFFLINE", "").strip().lower() in ("1", "true", "yes", "on"):
            return ScanReport(target_path=target_url, execution_status="NOT_RUN",
                scanner_results=[{"name": "web_audit", "status": "NOT_RUN", "reason": "CYBERAUDIT_OFFLINE activo"}])
        check_http_url(target_url)
        if not browsers or any(b not in ("chromium", "firefox", "webkit") for b in browsers):
            raise ValueError("Selecciona chromium, firefox o webkit")
        if type(observation_ms) is not int or not 250 <= observation_ms <= 30000:
            raise ValueError("observation_ms debe estar entre 250 y 30000")
        TargetVerifier.validate_safe_target(target_url, allow_local=allow_local)
        journey = load_journey(journey_path) if journey_path else None
        start = time.perf_counter()
        report = ScanReport(target_path=target_url)
        directory = Path(evidence_root).resolve() / uuid.uuid4().hex
        directory.mkdir(parents=True)
        evidence = {"target": target_url, "browsers": {}, "limitations": [
            "Medición de laboratorio durante una ventana limitada, no métricas de campo.",
            "El aislamiento de red de service workers requiere controles externos al navegador."]}

        def record(name, status, metrics=None, error=None):
            item = {"name": name, "status": status}
            if metrics is not None:
                item["metrics"] = metrics
            if error:
                item["error"] = str(error)
                report.execution_errors.append({"scanner": name, "error": str(error)})
            report.scanner_results.append(item)
            if status == "PASS":
                report.scanners_executed.append(name)

        def finding(key, title, details, browser_name, severity=Severity.MEDIUM):
            report.findings.append(Finding(id=f"WEB-{browser_name}-{key}", title=title,
                description=str(details), severity=severity, pillar=Pillar.SOFTWARE_QA,
                scanner_name=key, file_path=target_url))

        with sync_playwright() as playwright:
            for browser_name in dict.fromkeys(browsers):
                browser = None
                results = evidence["browsers"][browser_name] = {}
                blocked, errors = [], []
                try:
                    browser = getattr(playwright, browser_name).launch(headless=True)
                    results["version"] = browser.version
                    context = browser.new_context(ignore_https_errors=False, viewport={"width": 1280, "height": 800})
                    context.set_default_timeout(self.timeout_ms)
                    context.add_init_script(VITALS_INIT)

                    def route_request(route):
                        request = route.request
                        try:
                            check_http_url(request.url)
                            if request.is_navigation_request() and origin(request.url) != origin(target_url):
                                raise ValueError("Navegación fuera del origen del objetivo")
                            TargetVerifier.validate_safe_target(request.url, allow_local=allow_local)
                            route.continue_()
                        except Exception as exc:
                            blocked.append({"url": request.url, "reason": str(exc)})
                            route.abort()

                    context.route("**/*", route_request)
                    page = context.new_page()
                    page.bring_to_front()
                    page.on("pageerror", lambda exc: errors.append(str(exc)))
                    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
                    response = page.goto(target_url, wait_until="load", timeout=self.timeout_ms)
                    if response is None or not response.ok:
                        raise ValueError(f"Navegación falló: HTTP {response.status if response else 'sin respuesta'}")
                    page.wait_for_timeout(observation_ms)
                    report.files_scanned += 1
                    record(f"{browser_name}:navigation", "PASS", {"status": response.status, "url": page.url})
                    report.findings.extend(self.headers_auditor.audit_headers(response.headers, target_url))
                    report.findings.extend(self.headers_auditor.audit_cookies(context.cookies(), target_url))
                    record(f"{browser_name}:headers_cookies", "PASS")
                    try:
                        storage = page.evaluate("""() => {
                          const output = {};
                          for (const [label, store] of [['local',localStorage],['session',sessionStorage]])
                            for (let i=0;i<store.length;i++) {const key=store.key(i); output[label+':'+key]=store.getItem(key);}
                          return output;
                        }""")
                        report.findings.extend(self.client_auditor.audit_storage(storage, target_url))
                        report.findings.extend(self.client_auditor.audit_console_errors(errors, target_url))
                        record(f"{browser_name}:client_storage_console", "PASS", {"console_errors": len(errors)})
                    except Exception as exc:
                        record(f"{browser_name}:client_storage_console", "ERROR", error=exc)
                    try:
                        libraries = page.evaluate("""() => ({
                          ...(window.jQuery?.fn?.jquery ? {jQuery:window.jQuery.fn.jquery}:{}),
                          ...(window._?.VERSION ? {Lodash:window._.VERSION}:{}),
                          ...(window.React?.version ? {React:window.React.version}:{}),
                          ...(window.Vue?.version ? {Vue:window.Vue.version}:{})
                        })""")
                        report.findings.extend(self.client_auditor.audit_frontend_libraries(libraries, target_url))
                        record(f"{browser_name}:frontend_libraries", "PASS", {"observed": libraries,
                            "coverage": "Firmas locales limitadas; complementar con SCA/Trivy"})
                        maps = page.evaluate("""async () => {
                          const scripts = [...new Set([...document.scripts].map(s=>s.src))]
                            .filter(s=>s && new URL(s).origin===location.origin && s.endsWith('.js')).slice(0,15);
                          const results=[];
                          for (const script of scripts) {
                            const url=script+'.map';
                            try {
                              const response=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(3000)});
                              const reader=response.body?.getReader();
                              const chunk=reader ? await reader.read() : {value:new Uint8Array()};
                              if(reader) await reader.cancel();
                              const sample=new TextDecoder().decode((chunk.value || new Uint8Array()).slice(0,4096));
                              results.push({url,status:response.status,exposed:response.ok && /\"sources\"|\"mappings\"/.test(sample)});
                            } catch(e) {results.push({url,error:String(e)});}
                          } return results;
                        }""")
                        for index, item in enumerate(maps):
                            if item.get("exposed"):
                                finding(f"source-map-{index}", "Source map accesible", item["url"], browser_name)
                        record(f"{browser_name}:source_maps", "INCONCLUSIVE" if any(m.get("error") for m in maps) else "PASS", {"requests": maps})
                    except Exception as exc:
                        record(f"{browser_name}:frontend_source", "ERROR", error=exc)
                    try:
                        vitals = page.evaluate("() => ({...window.__cyberAuditVitals, observation_ended_ms:performance.now()})")
                        results["vitals"] = vitals
                        report.findings.extend(self.a11y_auditor.parse_web_vitals(vitals, target_url))
                        complete = all(vitals.get(k) is not None for k in ("lcp", "cls", "fcp")) and not vitals.get("observer_errors")
                        record(f"{browser_name}:web_vitals", "PASS" if complete else "INCONCLUSIVE", vitals)
                    except Exception as exc:
                        record(f"{browser_name}:web_vitals", "ERROR", error=exc)
                    if run_a11y:
                        try:
                            vendor = Path(__file__).parent / "vendor"
                            axe = vendor / "axe.min.js"
                            metadata = json.loads((vendor / "axe-integrity.json").read_text(encoding="utf-8"))
                            if hashlib.sha256(axe.read_bytes()).hexdigest() != metadata["sha256"]:
                                raise ValueError("Integridad de axe-core no válida")
                            page.add_script_tag(path=str(axe))
                            axe_results = page.evaluate("""async timeout => await Promise.race([
                              axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa']}}),
                              new Promise((_,reject)=>setTimeout(()=>reject(new Error('Timeout axe-core')),timeout))
                            ])""", self.timeout_ms)
                            results["axe"] = axe_results
                            report.findings.extend(self.a11y_auditor.parse_axe_violations(axe_results, target_url))
                            record(f"{browser_name}:a11y", "INCONCLUSIVE" if axe_results["incomplete"] else "PASS",
                                {"version": axe_results["testEngine"]["version"], "violations": len(axe_results["violations"]),
                                 "manual_review": len(axe_results["incomplete"])})
                        except Exception as exc:
                            record(f"{browser_name}:a11y", "ERROR", error=exc)
                    else:
                        record(f"{browser_name}:a11y", "NOT_RUN")
                    responsive = []
                    for width in (360, 768, 1280):
                        page.set_viewport_size({"width": width, "height": 800})
                        page.wait_for_timeout(100)
                        dimensions = page.evaluate("() => ({viewport:innerWidth, content:document.documentElement.scrollWidth})")
                        dimensions["overflow"] = dimensions["content"] > dimensions["viewport"] + 1
                        responsive.append(dimensions)
                        if dimensions["overflow"]:
                            finding(f"responsive-{width}", f"Desbordamiento horizontal a {width}px", dimensions, browser_name, Severity.LOW)
                    results["responsive"] = responsive
                    record(f"{browser_name}:responsive", "PASS", {"measurements": responsive})
                    page.set_viewport_size({"width": 1280, "height": 800})
                    if journey:
                        results["journey"] = run_journey(page, target_url, journey)
                        if results["journey"]["status"] == "FAIL":
                            finding("journey", "Recorrido funcional fallido", results["journey"], browser_name, Severity.HIGH)
                        record(f"{browser_name}:journey", results["journey"]["status"], results["journey"])
                    else:
                        record(f"{browser_name}:journey", "NOT_RUN", {"reason": "No se proporcionó un recorrido de negocio"})
                    try:
                        if page.url != target_url:
                            page.goto(target_url, wait_until="load")
                        pwa = probe_pwa(page, context, min(self.timeout_ms, 10000), expect_pwa, offline_selector, route_request)
                        results["pwa"] = pwa
                        for index, check in enumerate(pwa["checks"]):
                            if not check["passed"]:
                                finding(f"pwa-{index}", f"PWA: {check['name']}", check["evidence"], browser_name)
                        record(f"{browser_name}:pwa", pwa["status"], pwa)
                    except Exception as exc:
                        record(f"{browser_name}:pwa", "ERROR", error=exc)
                    results["blocked_requests"] = blocked
                    if blocked:
                        record(f"{browser_name}:network_scope", "INCONCLUSIVE", {"blocked": len(blocked)})
                    context.close()
                except Exception as exc:
                    record(f"{browser_name}:browser", "ERROR", error=exc)
                finally:
                    if browser:
                        browser.close()
        if run_passive_recon:
            try:
                report.findings.extend(self.recon_auditor.audit_target(target_url))
                record("passive_recon", "ERROR" if self.recon_auditor.errors else "PASS", {"errors": self.recon_auditor.errors})
            except Exception as exc:
                record("passive_recon", "ERROR", error=exc)
        else:
            record("passive_recon", "NOT_RUN")
        report.duration_seconds = round(time.perf_counter() - start, 3)
        states = [r["status"] for r in report.scanner_results]
        report.execution_status = ("ERROR" if "ERROR" in states else "INCONCLUSIVE"
            if any(s in ("NOT_RUN", "INCONCLUSIVE", "FAIL") for s in states) else "PASS")
        report.findings = list({(f.id, f.file_path): f for f in report.findings}.values())
        evidence["report"] = report.to_dict()
        raw = json.dumps(evidence, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8")
        (directory / "evidence.json").write_bytes(raw)
        (directory / "sha256.txt").write_text(hashlib.sha256(raw).hexdigest(), encoding="ascii")
        report.scanner_results.append({"name": "evidence", "status": "PASS", "path": str(directory / "evidence.json"),
                                       "sha256": hashlib.sha256(raw).hexdigest()})
        return report
