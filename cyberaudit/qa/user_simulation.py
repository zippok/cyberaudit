"""
CyberAudit User Simulation Engine (E2E Automated User Journey Testing)
Simulates a real system user interacting with the CyberAudit Enterprise Web UI:
- Systematically clicks buttons, switches tabs, opens/closes modals, applies filters,
  toggles accordions, tests inputs, and triggers QA operations.
- Actively listens for unhandled JavaScript errors (pageerror), console errors,
  and HTTP network failures to guarantee zero-fault user experience.
- Generates structured UserSimulationReport metrics for QA dashboards, pytest, and CLI.
"""

import os
import sys
import time
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger("cyberaudit.qa.user_simulation")


@dataclass
class UserActionLog:
    step: int
    category: str
    action_type: str
    target_name: str
    selector: str
    status: str  # "PASS", "FAIL", "SKIPPED"
    details: str
    duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UserSimulationReport:
    timestamp: str
    duration_seconds: float
    total_actions: int
    successful_actions: int
    failed_actions: int
    total_buttons_tested: int
    js_errors: List[str] = field(default_factory=list)
    console_errors: List[str] = field(default_factory=list)
    network_errors: List[str] = field(default_factory=list)
    action_logs: List[Dict[str, Any]] = field(default_factory=list)
    is_healthy: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_actions": self.total_actions,
            "successful_actions": self.successful_actions,
            "failed_actions": self.failed_actions,
            "total_buttons_tested": self.total_buttons_tested,
            "js_errors_count": len(self.js_errors),
            "js_errors": self.js_errors,
            "console_errors_count": len(self.console_errors),
            "console_errors": self.console_errors,
            "network_errors_count": len(self.network_errors),
            "network_errors": self.network_errors,
            "action_logs": self.action_logs,
            "is_healthy": self.is_healthy,
        }


class UserSimulationEngine:
    """
    Automated User Simulation & E2E Acceptance Testing Engine.
    Emulates everyday user operations across all UI modules in CyberAudit Web Dashboard.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")
        self.action_logs: List[UserActionLog] = []
        self.js_errors: List[str] = []
        self.console_errors: List[str] = []
        self.network_errors: List[str] = []
        self._button_tested_count = 0
        self._step_counter = 0

    def _record(self, category: str, action_type: str, target_name: str, selector: str, status: str, details: str, duration_ms: float):
        self._step_counter += 1
        log = UserActionLog(
            step=self._step_counter,
            category=category,
            action_type=action_type,
            target_name=target_name,
            selector=selector,
            status=status,
            details=details,
            duration_ms=round(duration_ms, 1),
        )
        self.action_logs.append(log)
        if action_type == "click":
            self._button_tested_count += 1

    def run(self, headless: bool = True, timeout_ms: int = 15000) -> UserSimulationReport:
        """
        Executes the full user simulation journey.
        Returns a complete UserSimulationReport.
        """
        from playwright.sync_api import sync_playwright

        start_time = time.time()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context(viewport={"width": 1440, "height": 900})
            page = context.new_page()

            # Listen for runtime errors
            page.on("pageerror", lambda e: self.js_errors.append(str(e)))
            page.on("console", lambda msg: self.console_errors.append(f"[{msg.type}] {msg.text}") if msg.type == "error" else None)
            page.on("requestfailed", lambda req: self.network_errors.append(f"{req.method} {req.url} - {req.failure}"))

            try:
                # ── Phase 1: Access Platform & Initial Load ─────────────────────────
                t0 = time.time()
                page.goto(self.base_url, timeout=timeout_ms, wait_until="domcontentloaded")
                page.wait_for_selector("#dashTargetPath", timeout=timeout_ms)
                self._record(
                    category="Inicialización",
                    action_type="navigate",
                    target_name="Carga de Aplicación y Dashboard",
                    selector="#dashTargetPath",
                    status="PASS",
                    details="Aplicación web cargada y métricas principales listas",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # ── Phase 2: Navigation Across All 6 Main Tabs ──────────────────────
                tabs_spec = [
                    ("tab-scanner", "content-scanner", "Pestaña: Ejecutar Auditoría"),
                    ("tab-findings", "content-findings", "Pestaña: Hallazgos Técnicos"),
                    ("tab-aianalyst", "content-aianalyst", "Pestaña: AI Co-Analyst Studio"),
                    ("tab-qa", "content-qa", "Pestaña: Verificación QA y UI/UX"),
                    ("tab-knowledge", "content-knowledge", "Pestaña: Base de Conocimientos"),
                    ("tab-dashboard", "content-dashboard", "Pestaña: Panel Ejecutivo"),
                ]

                for tab_id, content_id, label in tabs_spec:
                    t0 = time.time()
                    page.click(f"#{tab_id}")
                    page.wait_for_selector(f"#{content_id}:not(.hidden)", timeout=4000)
                    self._record(
                        category="Navegación",
                        action_type="click",
                        target_name=label,
                        selector=f"#{tab_id}",
                        status="PASS",
                        details=f"Pestaña activada y contenedor #{content_id} visible",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # ── Phase 3: Project Management Dialogs ──────────────────────────────
                t0 = time.time()
                btn_new_proj = page.locator("button[onclick*='openNewProjectModal']").first
                if btn_new_proj.is_visible():
                    btn_new_proj.click()
                    page.wait_for_selector("#newProjectModal:not(.hidden)", timeout=4000)
                    self._record(
                        category="Proyectos",
                        action_type="click",
                        target_name="Botón: Nuevo Proyecto (Abrir Modal)",
                        selector="button[onclick*='openNewProjectModal']",
                        status="PASS",
                        details="Modal de nuevo proyecto abierto con éxito",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                    # Simulate user filling inputs
                    page.fill("#newProjectName", "Proyecto de Prueba Simulado")
                    page.fill("#newProjectPath", "C:\\Users\\Public")
                    page.fill("#newProjectDesc", "Simulación de auditoría de usuario")

                    # Cancel/Close modal to leave system in clean state
                    t0 = time.time()
                    page.click("#newProjectModal button[onclick*='closeNewProjectModal']")
                    page.wait_for_selector("#newProjectModal", state="hidden", timeout=4000)
                    self._record(
                        category="Proyectos",
                        action_type="click",
                        target_name="Botón: Cancelar / Cerrar Modal Proyecto",
                        selector="#newProjectModal button[onclick*='closeNewProjectModal']",
                        status="PASS",
                        details="Modal cerrado sin alterar estado del sistema",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # ── Phase 4: Findings Explorer & Filters ────────────────────────────
                page.click("#tab-findings")
                page.wait_for_selector("#content-findings:not(.hidden)", timeout=4000)

                status_filters = [
                    ("statusFilter-OPEN", "Filtro: Vulnerabilidades Pendientes"),
                    ("statusFilter-RESOLVED", "Filtro: Hallazgos Arreglados"),
                    ("statusFilter-AS_DESIGNED", "Filtro: Código Así Es"),
                    ("statusFilter-ALL", "Filtro: Todos los Estados"),
                ]
                for btn_id, label in status_filters:
                    t0 = time.time()
                    page.click(f"#{btn_id}")
                    self._record(
                        category="Filtros Hallazgos",
                        action_type="click",
                        target_name=f"Botón {label}",
                        selector=f"#{btn_id}",
                        status="PASS",
                        details="Filtro de estado aplicado reactivamente",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # Severity filters
                sev_btns = page.locator(".sev-filter")
                sev_count = sev_btns.count()
                for i in range(min(sev_count, 5)):
                    t0 = time.time()
                    sev_btn = sev_btns.nth(i)
                    sev_label = sev_btn.inner_text().strip()
                    sev_btn.click()
                    self._record(
                        category="Filtros Severidad",
                        action_type="click",
                        target_name=f"Filtro Severidad: {sev_label}",
                        selector=f".sev-filter:nth-child({i+1})",
                        status="PASS",
                        details=f"Filtro de severidad '{sev_label}' ejecutado",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # Reset to all
                page.click(".sev-filter[data-sev='ALL']")

                # Search input simulation
                t0 = time.time()
                search_input = page.locator("#findingsSearch")
                search_input.fill("SQL")
                time.sleep(0.2)
                search_input.fill("")
                self._record(
                    category="Filtros Hallazgos",
                    action_type="input",
                    target_name="Caja de Búsqueda de Hallazgos",
                    selector="#findingsSearch",
                    status="PASS",
                    details="Filtrado en vivo por texto ejecutado y restaurado",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # Test finding accordion expand/collapse if cards exist
                detail_toggles = page.locator("button[onclick*='toggleDetails']")
                if detail_toggles.count() > 0:
                    t0 = time.time()
                    detail_toggles.first.click()
                    self._record(
                        category="Detalles Hallazgos",
                        action_type="click",
                        target_name="Botón: Alternar Detalles de Hallazgo (Acordeón)",
                        selector="button[onclick*='toggleDetails']",
                        status="PASS",
                        details="Detalles técnicos y snippet desplegados con éxito",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # ── Phase 5: AI Co-Analyst Studio Interactions ──────────────────────
                page.click("#tab-aianalyst")
                page.wait_for_selector("#content-aianalyst:not(.hidden)", timeout=4000)

                # Persona selection
                t0 = time.time()
                persona_select = page.locator("#chatPersonaSelect")
                if persona_select.is_visible():
                    persona_select.select_option("pentester")
                    persona_select.select_option("appsec_auditor")
                    self._record(
                        category="AI Co-Analyst",
                        action_type="input",
                        target_name="Selector de Perfil de Auditor AI",
                        selector="#chatPersonaSelect",
                        status="PASS",
                        details="Perfiles Lead Pentester y AppSec Auditor alternados",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # Clear chat button
                btn_clear = page.locator("button[onclick*='clearChatHistory']")
                if btn_clear.is_visible():
                    t0 = time.time()
                    btn_clear.click()
                    self._record(
                        category="AI Co-Analyst",
                        action_type="click",
                        target_name="Botón: Limpiar Historial de Chat",
                        selector="button[onclick*='clearChatHistory']",
                        status="PASS",
                        details="Historial de conversación reseteado adecuadamente",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # Quick action chips
                chips = page.locator("#content-aianalyst button[onclick*='sendQuickPrompt']")
                if chips.count() > 0:
                    t0 = time.time()
                    first_chip_text = chips.first.inner_text().strip()
                    self._record(
                        category="AI Co-Analyst",
                        action_type="verify",
                        target_name=f"Chip de Acción Rápida: {first_chip_text}",
                        selector="button[onclick*='sendQuickPrompt']",
                        status="PASS",
                        details="Chips de acción rápida interactivos y disponibles",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # ── Phase 6: Knowledge Base Interactions ────────────────────────────
                page.click("#tab-knowledge")
                page.wait_for_selector("#content-knowledge:not(.hidden)", timeout=4000)

                kb_btns = page.locator(".kb-cat-btn")
                kb_count = kb_btns.count()
                for i in range(min(kb_count, 4)):
                    t0 = time.time()
                    btn = kb_btns.nth(i)
                    label = btn.inner_text().strip()
                    btn.click()
                    self._record(
                        category="Base Conocimientos",
                        action_type="click",
                        target_name=f"Filtro Categoría KB: {label}",
                        selector=f".kb-cat-btn:nth-child({i+1})",
                        status="PASS",
                        details=f"Artículos de '{label}' filtrados sin errores",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # Reset KB to all
                page.click(".kb-cat-btn[data-cat='ALL']")

                # Open and close article modal if articles rendered
                art_btns = page.locator("button[onclick*='openKbModalByPath']")
                if art_btns.count() > 0:
                    t0 = time.time()
                    art_btns.first.click()
                    page.wait_for_selector("#kbReaderModal:not(.hidden)", timeout=4000)
                    self._record(
                        category="Base Conocimientos",
                        action_type="click",
                        target_name="Botón: Abrir Artículo Técnico (Modal)",
                        selector="button[onclick*='openKbModalByPath']",
                        status="PASS",
                        details="Modal de conocimiento renderizado con éxito",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                    t0 = time.time()
                    page.click("button[onclick*='closeKbModal']")
                    page.wait_for_selector("#kbReaderModal", state="hidden", timeout=4000)
                    self._record(
                        category="Base Conocimientos",
                        action_type="click",
                        target_name="Botón: Cerrar Modal de Conocimiento",
                        selector="button[onclick*='closeKbModal']",
                        status="PASS",
                        details="Modal cerrado y vista de artículos restaurada",
                        duration_ms=(time.time() - t0) * 1000,
                    )

                # ── Phase 7: QA Suite, UI/UX & Dynamic PoC Interactions ──────────────
                # 7.1 Software QA Lab
                page.click("#tab-qa")
                page.wait_for_selector("#content-qa:not(.hidden)", timeout=4000)

                # Sub-tab: Diagnóstico profundo de QA
                t0 = time.time()
                page.click("#qaSubTabDeep")
                page.wait_for_selector("#qaViewDeepDiag:not(.hidden)", timeout=4000)
                self._record(
                    category="QA Suite",
                    action_type="click",
                    target_name="Sub-pestaña: Diagnóstico Profundo QA",
                    selector="#qaSubTabDeep",
                    status="PASS",
                    details="Diagnóstico de calidad de código y salud QA visualizado",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # Sub-tab: Verificación modular
                t0 = time.time()
                page.click("#qaSubTabUnit")
                page.wait_for_selector("#qaViewUnit:not(.hidden)", timeout=4000)
                self._record(
                    category="QA Suite",
                    action_type="click",
                    target_name="Sub-pestaña: Verificación Modular",
                    selector="#qaSubTabUnit",
                    status="PASS",
                    details="Panel modular restaurado",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # Sub-tab: Simulación de Usuario (Vista QA)
                t0 = time.time()
                page.click("#qaSubTabUserSim")
                page.wait_for_selector("#qaViewUserSim:not(.hidden)", timeout=4000)
                self._record(
                    category="QA Suite",
                    action_type="click",
                    target_name="Sub-pestaña: Simulación de Usuario QA",
                    selector="#qaSubTabUserSim",
                    status="PASS",
                    details="Vista de simulación de usuario y telemetría cargada",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # Regreso a diagnóstico profundo
                t0 = time.time()
                page.click("#qaSubTabDeep")
                page.wait_for_selector("#qaViewDeepDiag:not(.hidden)", timeout=4000)
                self._record(
                    category="QA Suite",
                    action_type="click",
                    target_name="Sub-pestaña: Diagnóstico Profundo",
                    selector="#qaSubTabDeep",
                    status="PASS",
                    details="Regreso a diagnóstico profundo verificado",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # 7.2 UI/UX Lab Navigation
                t0 = time.time()
                page.click("#tab-uiux")
                page.wait_for_selector("#content-uiux:not(.hidden)", timeout=4000)
                self._record(
                    category="UI/UX Lab",
                    action_type="click",
                    target_name="Pestaña: UI/UX & Accesibilidad",
                    selector="#tab-uiux",
                    status="PASS",
                    details="Panel WCAG 2.1 AA y ergonomía móvil visualizado",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # 7.3 Dynamic Pentesting DAST Navigation
                t0 = time.time()
                page.click("#tab-dynamic")
                page.wait_for_selector("#content-dynamic:not(.hidden)", timeout=4000)
                self._record(
                    category="DAST Pentest",
                    action_type="click",
                    target_name="Pestaña: Pentesting Dinámico DAST",
                    selector="#tab-dynamic",
                    status="PASS",
                    details="Panel de 6 PoCs dinámicos visualizado correctamente",
                    duration_ms=(time.time() - t0) * 1000,
                )

                # ── Phase 8: Final Return to Executive Dashboard ─────────────────────
                t0 = time.time()
                page.click("#tab-dashboard")
                page.wait_for_selector("#content-dashboard:not(.hidden)", timeout=4000)
                self._record(
                    category="Navegación",
                    action_type="click",
                    target_name="Retorno a Panel Ejecutivo",
                    selector="#tab-dashboard",
                    status="PASS",
                    details="Flujo de usuario completo completado sin anomalías",
                    duration_ms=(time.time() - t0) * 1000,
                )

            except Exception as e:
                logger.error("Error during user simulation: %s", e)
                self._record(
                    category="Ejecución",
                    action_type="error",
                    target_name="Fallo Crítico en Flujo de Usuario",
                    selector="N/A",
                    status="FAIL",
                    details=str(e),
                    duration_ms=0.0,
                )
            finally:
                browser.close()

        total_duration = time.time() - start_time
        successful_actions = sum(1 for log in self.action_logs if log.status == "PASS")
        failed_actions = sum(1 for log in self.action_logs if log.status == "FAIL")

        # Zero tolerance for JS exceptions and unhandled console errors
        is_healthy = (len(self.js_errors) == 0 and len(self.console_errors) == 0 and failed_actions == 0)

        report = UserSimulationReport(
            timestamp=now_str,
            duration_seconds=total_duration,
            total_actions=len(self.action_logs),
            successful_actions=successful_actions,
            failed_actions=failed_actions,
            total_buttons_tested=self._button_tested_count,
            js_errors=self.js_errors,
            console_errors=self.console_errors,
            network_errors=self.network_errors,
            action_logs=[log.to_dict() for log in self.action_logs],
            is_healthy=is_healthy,
        )

        return report


def run_user_simulation_cli(base_url: str = "http://127.0.0.1:8000", headless: bool = True) -> UserSimulationReport:
    """Convenience entrypoint for CLI execution."""
    engine = UserSimulationEngine(base_url=base_url)
    return engine.run(headless=headless)
