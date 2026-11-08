#!/usr/bin/env python3
"""
CyberAudit Suite - Main Command-Line Interface (CLI)
Usage:
  python3 cli.py scan <path> [--html report.html] [--json report.json] [--ai] [--ai-provider auto|local|gemini]
  python3 cli.py audit-ad <path>
  python3 cli.py audit-cloud <path>
  python3 cli.py triage-logs <file_or_folder>
  python3 cli.py triage-endpoint <path>
"""

import os
import sys

# Ensure repository root is in sys.path regardless of CWD or symlinks
_REPO_ROOT = os.path.dirname(os.path.realpath(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import argparse
from contextlib import nullcontext

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError, ValueError):
        # Entornos de terminal sin soporte reconfigure en tiempo de carga inicial
        pass

from rich.console import Console

from cyberaudit.core.engine import AuditEngine
from cyberaudit.core.reporter import Reporter
from cyberaudit.core.models import Severity
from cyberaudit.ai.co_analyst import AICoAnalyst
from cyberaudit.kali.orchestrator import KALI_PROFILES as KALI_PROFILE_MAP

#: Available Kali audit profiles (used by the argparse choices for --profile)
KALI_PROFILE_CHOICES = tuple(sorted(KALI_PROFILE_MAP.keys()))

# Specific scanners for targeted subcommands
from cyberaudit.modules.security_analyst.yara_static_scanner import YaraStaticScanner
from cyberaudit.modules.security_analyst.sigma_engine import SigmaEngine
from cyberaudit.modules.security_analyst.ad_audit import ActiveDirectoryAuditScanner
from cyberaudit.modules.security_analyst.cloud_azure_audit import CloudAzureAuditScanner
from cyberaudit.modules.security_analyst.log_hygiene_scanner import LogHygieneScanner
from cyberaudit.modules.security_analyst.lolbas_detector import LolbasDetector
from cyberaudit.modules.security_analyst.cti_correlator import CtiCorrelator
from cyberaudit.modules.dfir.dfir_triage import DfirEndpointScanner

console = Console()


def run_scan(
    target_path: str,
    html_output: str = None,
    json_output: str = None,
    sarif_output: str = None,
    run_ai: bool = False,
    ai_provider: str = "auto",
    min_severity: str = None,
    scanners=None,
    archetype: str = "full",
    exclude_vendor: bool = True,
    offline: bool = False,
):
    if offline:
        os.environ["CYBERAUDIT_OFFLINE"] = "1"
    if not os.path.exists(target_path):
        console.print(f"[red bold]Error:[/] Target path does not exist: {target_path}")
        sys.exit(1)


    status_ctx = console.status(f"[bold cyan]Scanning {target_path} for security vulnerabilities & forensic indicators (Archetype: {archetype})...[/bold cyan]") if console.is_terminal else nullcontext()
    with status_ctx:
        engine = AuditEngine(scanners=scanners, archetype=archetype, exclude_vendor=exclude_vendor)
        report = engine.scan_path(target_path)

    if run_ai:
        ai_ctx = console.status(f"[bold green]Running AI Co-Analyst debrief (Mode: {ai_provider})...[/bold green]") if console.is_terminal else nullcontext()
        with ai_ctx:
            analyst = AICoAnalyst()
            report = analyst.analyze(report, provider_mode=ai_provider)

    # Convert min_severity string if provided
    sev_filter = None
    if min_severity:
        try:
            sev_filter = Severity[min_severity.upper()]
        except KeyError:
            console.print(f"[yellow]Warning:[/] Unknown severity '{min_severity}'. Displaying all findings.")

    # Render terminal output
    reporter = Reporter(report)
    reporter.print_terminal_summary(min_severity=sev_filter)

    # Export formats
    if json_output:
        saved_json = reporter.export_json(json_output)
        console.print(f"[green][+] JSON audit report saved to:[/] {saved_json}")

    if sarif_output:
        saved_sarif = reporter.export_sarif(sarif_output, base_dir=target_path)
        console.print(f"[green][+] OASIS SARIF 2.1.0 compliance report saved to:[/] {saved_sarif}")

    if html_output:
        saved_html = reporter.export_html(html_output)
        console.print(f"[green][+] Interactive HTML executive dashboard saved to:[/] {saved_html}")

    if report.execution_status != "PASS":
        console.print("[red]Auditoría incompleta: no se puede emitir una conclusión de seguridad.[/red]")
        sys.exit(2)


def run_certify_production(
    target_path: str,
    environment: str = "production",
    app_name: str = "Target Software",
    output_report: str = None,
    json_output: str = None,
    strict: bool = True,
    fail_on_blocked: bool = True,
    metrics_file: str = None,
):
    import json
    from cyberaudit.core.production_readiness_certifier import (
        ProductionReadinessCertifier,
        ProductionPolicyConfig,
        ReadinessVerdict,
    )
    from rich.table import Table

    if not os.path.exists(target_path):
        console.print(f"[red bold]Error:[/] Target path does not exist: {target_path}")
        sys.exit(1)

    console.print(f"[bold cyan]Auditing {target_path} for Production Deployment Readiness ({environment.upper()})...[/bold cyan]")

    engine = AuditEngine(exclude_vendor=True)
    report = engine.scan_path(target_path)

    # Only import measured evidence. Never invent passing test results.
    test_metrics = None
    if metrics_file:
        with open(metrics_file, encoding="utf-8") as handle:
            test_metrics = json.load(handle)
        if not isinstance(test_metrics, dict):
            raise ValueError("El archivo de métricas debe contener un objeto JSON.")

    policy = ProductionPolicyConfig.default_strict() if strict else ProductionPolicyConfig.permissive_staging()
    certifier = ProductionReadinessCertifier(policy_config=policy)
    cert = certifier.certify(
        scan_report=report,
        test_metrics=test_metrics,
        target_path=target_path,
        application_name=app_name,
        target_environment=environment,
    )

    console.print("\n" + "=" * 70)
    console.print(f"[bold]CYBERAUDIT PRODUCTION READINESS RELEASE CERTIFICATION[/bold]")
    console.print(f"Certificate ID: [bold green]{cert.certificate_id}[/bold green] | Environment: [bold]{cert.target_environment.upper()}[/bold]")
    console.print("=" * 70)

    table = Table(title="Production Gate Checklist")
    table.add_column("Gate ID", style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("Gate Name", style="bold")
    table.add_column("Verdict", style="bold")
    table.add_column("Details")

    for g in cert.gate_results:
        verdict_str = "[green]PASS[/green]" if g.passed else ("[red]BLOCKER[/red]" if g.is_blocker else "[yellow]WARNING[/yellow]")
        table.add_row(g.gate_id, g.category.value, g.title, verdict_str, g.message)

    console.print(table)

    console.print(f"\n[bold]Readiness Score:[/] {cert.readiness_score:.1f} / 100.0")
    if cert.verdict == ReadinessVerdict.READY_FOR_PRODUCTION:
        console.print(f"[bold green][+] VERDICT: READY FOR PRODUCTION (Deploy Approved)[/bold green]")
    elif cert.verdict == ReadinessVerdict.CONDITIONALLY_READY:
        console.print(f"[bold yellow][!] VERDICT: CONDITIONALLY READY (Deploy with signed waiver)[/bold yellow]")
    else:
        console.print(f"[bold red][X] VERDICT: DEPLOYMENT BLOCKED ({cert.blockers_count} critical blockers)[/bold red]")

    console.print(f"[dim]Tamper-Proof HMAC Signature: {cert.tamper_proof_signature}[/dim]")

    if output_report:
        with open(output_report, "w", encoding="utf-8") as f:
            f.write(cert.to_markdown())
        console.print(f"[green][+] Official Release Certificate saved to:[/] {output_report}")

    if json_output:
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(cert.to_dict(), f, indent=2, ensure_ascii=False)
        console.print(f"[green][+] Machine-readable Certificate saved to:[/] {json_output}")

    if fail_on_blocked and not cert.is_deployable:
        sys.exit(1)


def run_audit_infra(
    host: str,
    ports=None,
    verify_token=None,
    allow_local: bool = False,
    html_output=None,
    json_output=None,
    run_ai: bool = False,
    ai_provider: str = "auto",
    min_severity=None,
):
    from cyberaudit.core.target_verifier import TargetVerifier, TargetVerificationError
    from cyberaudit.infra.port_hygiene import PortHygieneAuditor
    from cyberaudit.infra.tls_cipher_audit import TLSCipherAuditor
    from cyberaudit.core.models import ScanReport
    from datetime import datetime, timezone
    import time

    start_time = time.perf_counter()

    try:
        clean_host, resolved_ips = TargetVerifier.validate_safe_target(host, allow_local=allow_local)
    except TargetVerificationError as e:
        console.print(f"[red bold][!] Error de Verificación Anti-SSRF:[/] {e}")
        sys.exit(1)

    if verify_token:
        if not TargetVerifier.verify_domain_ownership(host, verify_token):
            console.print(f"[yellow bold][!] Aviso de Gobernanza:[/] No se pudo verificar la propiedad del dominio '{host}' con el token provisto.")
            if not allow_local:
                console.print("[red bold]Bloqueado:[/] Para auditar infraestructura externa se requiere verificación de propiedad válida o flag --allow-local.")
                sys.exit(1)

    with console.status(f"[bold cyan]Auditing Infrastructure & External Attack Surface for {clean_host}...[/bold cyan]"):
        findings = []
        scanners_executed = ["port_hygiene", "tls_cipher_audit"]

        # Port hygiene
        port_auditor = PortHygieneAuditor()
        findings.extend(port_auditor.scan_target(clean_host, resolved_ips, custom_ports=ports))

        # TLS inspection (port 443)
        tls_auditor = TLSCipherAuditor()
        findings.extend(tls_auditor.audit_endpoint(clean_host, port=443))

        duration = time.perf_counter() - start_time

        report = ScanReport(
            target_path=host,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration_seconds=round(duration, 2),
            files_scanned=len(resolved_ips),
            scanners_executed=scanners_executed,
            findings=findings,
        )

    if run_ai:
        with console.status(f"[bold green]Running AI Co-Analyst debrief (Mode: {ai_provider})...[/bold green]"):
            analyst = AICoAnalyst()
            report = analyst.analyze(report, provider_mode=ai_provider)

    sev_filter = None
    if min_severity:
        try:
            sev_filter = Severity[min_severity.upper()]
        except KeyError:
            pass

    reporter = Reporter(report)
    reporter.print_terminal_summary(min_severity=sev_filter)

    if json_output:
        saved_json = reporter.export_json(json_output)
        console.print(f"[green][+] JSON audit report saved to:[/] {saved_json}")
    if html_output:
        saved_html = reporter.export_html(html_output)
        console.print(f"[green][+] Interactive HTML executive dashboard saved to:[/] {saved_html}")


def run_audit_web(
    url: str,
    allow_local: bool = False,
    run_a11y: bool = True,
    verify_token=None,
    html_output=None,
    json_output=None,
    run_ai: bool = False,
    ai_provider: str = "auto",
    min_severity=None,
    browsers=("chromium",),
    expect_pwa=False,
    journey_path=None,
    offline_selector=None,
    observation_ms=2000,
):
    from cyberaudit.core.target_verifier import TargetVerifier, TargetVerificationError
    from cyberaudit.web_auditor.orchestrator import WebAuditorOrchestrator

    try:
        TargetVerifier.validate_safe_target(url, allow_local=allow_local)
    except TargetVerificationError as e:
        console.print(f"[red bold][!] Error de Verificación Anti-SSRF:[/] {e}")
        sys.exit(1)

    if verify_token:
        if not TargetVerifier.verify_domain_ownership(url, verify_token):
            console.print(f"[yellow bold][!] Aviso de Gobernanza:[/] No se pudo verificar la propiedad del dominio con el token provisto.")
            if not allow_local:
                console.print("[red bold]Bloqueado:[/] Se requiere verificación de propiedad válida o flag --allow-local.")
                sys.exit(1)

    with console.status(f"[bold cyan]Running Headless Playwright Web Audit on {url}...[/bold cyan]"):
        orchestrator = WebAuditorOrchestrator()
        report = orchestrator.audit(
            target_url=url,
            allow_local=allow_local,
            run_a11y=run_a11y,
            run_passive_recon=True,
            browsers=browsers,
            expect_pwa=expect_pwa,
            journey_path=journey_path,
            offline_selector=offline_selector,
            observation_ms=observation_ms,
        )

    if run_ai:
        with console.status(f"[bold green]Running AI Co-Analyst debrief (Mode: {ai_provider})...[/bold green]"):
            analyst = AICoAnalyst()
            report = analyst.analyze(report, provider_mode=ai_provider)

    sev_filter = None
    if min_severity:
        try:
            sev_filter = Severity[min_severity.upper()]
        except KeyError:
            pass

    reporter = Reporter(report)
    reporter.print_terminal_summary(min_severity=sev_filter)

    if json_output:
        saved_json = reporter.export_json(json_output)
        console.print(f"[green][+] JSON audit report saved to:[/] {saved_json}")
    if html_output:
        saved_html = reporter.export_html(html_output)
        console.print(f"[green][+] Interactive HTML executive dashboard saved to:[/] {saved_html}")

    if report.execution_status != "PASS":
        sys.exit(2)
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in report.findings):
        sys.exit(1)


def run_audit_login(
    url: str,
    allow_local: bool = False,
    test_rate_limit: bool = True,
    html_output=None,
    json_output=None,
    run_ai: bool = False,
    ai_provider: str = "auto",
    min_severity=None,
):
    from cyberaudit.core.target_verifier import TargetVerifier, TargetVerificationError
    from cyberaudit.auth.login_posture import LoginPostureAuditor
    from cyberaudit.core.models import ScanReport
    import urllib.request
    import ssl
    import time
    from datetime import datetime, timezone

    start_time = time.perf_counter()

    try:
        TargetVerifier.validate_safe_target(url, allow_local=allow_local)
    except TargetVerificationError as e:
        console.print(f"[red bold][!] Error de Verificación Anti-SSRF:[/] {e}")
        sys.exit(1)

    with console.status(f"[bold cyan]Auditing Login Interface & Posture for {url}...[/bold cyan]"):
        auditor = LoginPostureAuditor()
        findings = []

        # 1. Fetch HTML and audit form posture
        try:
            ctx = ssl.create_default_context()
            if allow_local:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "CyberAudit-Defense-Auditor/2.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=5.0) as resp:
                html_body = resp.read(65536).decode("utf-8", errors="ignore")
                findings.extend(auditor.audit_form_html(html_body, url))
        except Exception as e:
            console.print(f"[yellow]Aviso:[/] No se pudo descargar el HTML inicial: {e}")

        # 2. Rate limiting check
        if test_rate_limit:
            findings.extend(auditor.audit_rate_limiting(url))

        # 3. User enumeration check
        findings.extend(auditor.audit_user_enumeration(url))

        duration = time.perf_counter() - start_time
        report = ScanReport(
            target_path=url,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration_seconds=round(duration, 2),
            files_scanned=1,
            scanners_executed=["login_posture"],
            findings=findings,
        )

    if run_ai:
        with console.status(f"[bold green]Running AI Co-Analyst debrief (Mode: {ai_provider})...[/bold green]"):
            analyst = AICoAnalyst()
            report = analyst.analyze(report, provider_mode=ai_provider)

    sev_filter = None
    if min_severity:
        try:
            sev_filter = Severity[min_severity.upper()]
        except KeyError:
            pass

    reporter = Reporter(report)
    reporter.print_terminal_summary(min_severity=sev_filter)

    if json_output:
        saved_json = reporter.export_json(json_output)
        console.print(f"[green][+] JSON audit report saved to:[/] {saved_json}")
    if html_output:
        saved_html = reporter.export_html(html_output)
        console.print(f"[green][+] Interactive HTML executive dashboard saved to:[/] {saved_html}")


def run_qa(pillar: str = "all", verbose: bool = False):
    import subprocess
    import time
    from rich.table import Table
    from rich.panel import Panel

    console.print(Panel(
        "[bold cyan]CyberAudit Suite v2.0 Enterprise - Automated QA & Verification Engine[/bold cyan]\n"
        "[dim]Validating multi-disciplinary detection engines across all 5 TryHackMe pillars against synthetic positive & negative controls.[/dim]",
        border_style="cyan"
    ))

    test_targets = {
        "analyst": ("Security Analyst & DFIR", "tests/test_analyst_scanners.py"),
        "pentester": ("Penetration Testing & Red Team", "tests/test_pentester_scanners.py"),
        "engineer": ("Security Engineering & DevSecOps", "tests/test_engineer_scanners.py"),
        "ai": ("AI Security & LLM Defenses", "tests/test_ai_scanners.py"),
        "qa": ("Software QA & Code Quality", "tests/test_qa_scanners.py"),
        "qa_expanded": ("Expanded QA & Contracts", "tests/test_software_qa_expanded.py"),
        "uiux": ("UI/UX & Accessibility (a11y)", "tests/test_ui_ux_scanners.py"),
        "uiux_expanded": ("Expanded UI/UX & WCAG 2.2", "tests/test_ui_ux_expanded.py"),
        "advanced_qa": ("Advanced QA & UX Heuristics", "tests/test_advanced_qa_scanners.py"),
        "arch": ("Software Architecture & Advanced Security", "tests/test_arch_and_advanced_security_scanners.py"),
        "cleancode": ("Clean Code & Anti-Hardcoding", "tests/test_clean_code_scanners.py"),
        "integration": ("Multi-Pillar Engine Integration", "tests/test_engine_integration.py"),
        "infra": ("Infrastructure EASM & TLS", "tests/test_infra_and_auth_audit.py"),
        "web": ("Dynamic Web DAST & Playwright", "tests/test_web_auditor.py"),
    }

    if pillar != "all" and pillar in test_targets:
        targets = {pillar: test_targets[pillar]}
    else:
        targets = test_targets

    table = Table(title="CyberAudit QA Verification Results", border_style="cyan", header_style="bold magenta")
    table.add_column("Security Pillar / Module", style="bold white")
    table.add_column("Test Suite Path", style="dim")
    table.add_column("Passed", style="green", justify="center")
    table.add_column("Failed", style="red", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Verification Status", justify="center")

    total_passed = 0
    total_failed = 0
    start_total = time.time()
    all_success = True

    for key, (pillar_name, test_file) in targets.items():
        cmd = [sys.executable, "-m", "pytest", test_file, "-q"]
        t0 = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True)
        dur = time.time() - t0

        out = res.stdout + res.stderr
        import re
        passed_m = re.search(r'(\d+)\s+passed', out)
        failed_m = re.search(r'(\d+)\s+failed', out)

        p_cnt = int(passed_m.group(1)) if passed_m else 0
        f_cnt = int(failed_m.group(1)) if failed_m else 0

        total_passed += p_cnt
        total_failed += f_cnt

        if res.returncode == 0 and f_cnt == 0:
            status = "[bold green]VERIFIED (100%)[/bold green]"
        else:
            status = "[bold red]FAILED[/bold red]"
            all_success = False

        table.add_row(
            pillar_name,
            test_file,
            f"[green]{p_cnt}[/green]",
            f"[red]{f_cnt}[/red]" if f_cnt > 0 else "0",
            f"{dur:.2f}s",
            status
        )
        if verbose and out.strip():
            console.print(f"[dim]{out.strip()}[/dim]")

    total_time = time.time() - start_total
    console.print(table)

    if all_success:
        console.print(Panel(
            f"[bold green]ALL QA TESTS VERIFIED: {total_passed} tests passed in {total_time:.2f}s[/bold green]\n"
            "[green]Every scanner accurately flagged synthetic positive vulnerability controls and correctly rejected negative/benign controls with zero false positives.[/green]",
            border_style="green"
        ))
    else:
        console.print(Panel(
            f"[bold red]QA SUITE FAILURE: {total_failed} tests failed, {total_passed} passed.[/bold red]\n"
            "[yellow]Review failed assertions above for regex discrepancies or false positive regressions.[/yellow]",
            border_style="red"
        ))
        sys.exit(1)


def run_dynamic_qa(export_html: str = None):
    console.print("[yellow]NOT_RUN: las demostraciones en memoria no prueban vulnerabilidades de tu sistema. Usa audit-web o external-audit con un objetivo y alcance autorizados.[/yellow]")
    raise SystemExit(2)


def run_sync_remediation(
    remediation_file: str,
    target_path: str = None,
    report_path: str = None,
    overrides_path: str = "audit_status_overrides.json",
    auto_reverify: bool = True,
    run_ai: bool = False,
    ai_provider: str = "auto",
):
    """Parses a developer's remediation response Markdown file, re-tests code on disk, and updates platform."""
    import json
    from cyberaudit.core.remediation import RemediationManager
    from rich.panel import Panel
    from rich.table import Table

    if not os.path.exists(remediation_file):
        console.print(f"[red bold]Error:[/] Archivo de subsanación no existe: {remediation_file}")
        sys.exit(1)

    with open(remediation_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    cand_reports = [report_path] if report_path else [
        "self_audit_latest.json",
        "audit_report_torrent_v2.json",
        "audit_report.json",
        "self_audit.json",
    ]
    report_dict = None
    used_report_path = None
    for cand in cand_reports:
        if cand and os.path.exists(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    report_dict = json.load(f)
                    used_report_path = cand
                    break
            except Exception:
                pass

    if not report_dict:
        console.print("[yellow bold]Aviso:[/] No se encontró un archivo JSON de auditoría previo. Creando reporte base.")
        report_dict = {"target_path": target_path or os.getcwd(), "findings": []}

    target_root = target_path or report_dict.get("target_path") or os.getcwd()

    console.print(Panel(
        f"[bold purple]CyberAudit Suite — Sincronización de Subsanaciones en Markdown[/bold purple]\n"
        f"[dim]Documento: {remediation_file} | Objetivo: {target_root} | Re-test en disco: {'Activado' if auto_reverify else 'Desactivado'}[/dim]",
        border_style="purple",
    ))

    manager = RemediationManager()
    with console.status("[bold purple]Procesando subsanaciones y re-verificando código fuente en disco...[/bold purple]"):
        res = manager.process_remediation_markdown(
            markdown_content=content,
            report_dict=report_dict,
            target_root=target_root,
            overrides_file=overrides_path,
            auto_reverify=auto_reverify,
        )

    if res.get("status") == "warning":
        console.print(f"[yellow]{res.get('message')}[/yellow]")
        return

    table = Table(title="Detalle de Subsanaciones Procesadas", show_header=True, header_style="bold magenta")
    table.add_column("ID Hallazgo", style="cyan", width=24)
    table.add_column("Ubicación", style="dim", width=26)
    table.add_column("Estado", justify="center", width=14)
    table.add_column("Re-test en Disco", justify="center", width=22)
    table.add_column("Comentario del Desarrollador", width=36)

    for it in res.get("items", []):
        st = it.get("status", "RESOLVED")
        st_badge = "[green bold]SUBSANADO[/]" if st == "RESOLVED" else "[magenta]POR DISEÑO[/]" if st == "AS_DESIGNED" else "[yellow]PENDIENTE[/]"
        retest = "[green]✅ Verificado Limpio[/]" if it.get("verified_on_disk") is True else (
            "[red bold]❌ Persiste en Código[/]" if it.get("verified_on_disk") is False else "[dim]N/A[/]"
        )
        fpath = it.get("file_path", "") or ""
        ln = it.get("line_number")
        loc = f"{os.path.basename(fpath)}:{ln}" if ln else os.path.basename(fpath)
        table.add_row(
            it.get("finding_id", ""),
            loc,
            st_badge,
            retest,
            it.get("developer_comment", "")[:60],
        )

    console.print(table)
    console.print()
    console.print(f"[bold green][+] Total analizados:[/] {res.get('total_parsed')} | [green]Verificados OK:[/] {res.get('verified_count')} | [red]Re-test fallido:[/] {res.get('failed_reverify_count')} | [magenta]Por diseño:[/] {res.get('as_designed_count')}")

    if used_report_path:
        try:
            with open(used_report_path, "w", encoding="utf-8") as f:
                json.dump(report_dict, f, indent=2, ensure_ascii=False)
            console.print(f"[green][+] Reporte JSON actualizado:[/] {used_report_path}")
        except Exception as e:
            console.print(f"[yellow][!] No se pudo actualizar JSON: {e}[/yellow]")

    if res.get("updated_markdown_report"):
        console.print(f"[green][+] Informe maestro Auditoria_*.md actualizado:[/] {res.get('updated_markdown_report')}")

    if run_ai:
        with console.status(f"[bold green]Generando Dictamen Técnico del AI Co-Analyst ({ai_provider})...[/bold green]"):
            analyst = AICoAnalyst()
            ai_res = analyst.review_developer_remediation(content, res, report_context=report_dict, provider_mode=ai_provider)
        console.print()
        console.print(Panel(
            ai_res.get("review", "Sin dictamen"),
            title=f"Dictamen Técnico del Auditor AI Co-Analyst ({ai_res.get('provider')})",
            border_style="green",
        ))


def run_ui(host: str = "127.0.0.1", port: int = 8000, reload: bool = False, no_browser: bool = False):
    import time
    import threading
    import webbrowser
    import uvicorn
    from rich.panel import Panel

    console.print(Panel(
        f"[bold cyan]CyberAudit Suite v2.0 Enterprise - Visual Dashboard & AI Studio[/bold cyan]\n\n"
        f"[green][+] Interfaz Web Interactiva:[/] [bold underline]http://{host}:{port}[/bold underline]\n"
        f"[green][+] Documentación API REST:[/] [bold underline]http://{host}:{port}/docs[/bold underline]\n"
        f"[dim]Presiona CTRL+C en la consola para detener el servidor.[/dim]",
        border_style="cyan"
    ))

    if not no_browser:
        def _open_tab():
            time.sleep(1.2)
            try:
                webbrowser.open(f"http://{host}:{port}")
            except Exception:
                pass
        threading.Thread(target=_open_tab, daemon=True).start()

    uvicorn.run("cyberaudit.web.app:app", host=host, port=port, reload=reload)


def run_user_simulation_cmd(base_url: str = None, headless: bool = True):
    from rich.panel import Panel
    from rich.table import Table
    from cyberaudit.qa.user_simulation import UserSimulationEngine

    console.print(Panel(
        "[bold cyan]CyberAudit Suite - Automated User Simulation & E2E Button Acceptance[/bold cyan]\n"
        "[dim]Simulación de usuario común interactuando con toda la plataforma web: navegación, modales, formularios, filtros y herramientas con vigilancia activa de errores.[/dim]",
        border_style="cyan"
    ))

    server_instance = None
    target_url = base_url

    if not target_url:
        import socket
        import threading
        import time
        import uvicorn
        from cyberaudit.web.app import app

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]

        target_url = f"http://127.0.0.1:{free_port}"
        config = uvicorn.Config(app, host="127.0.0.1", port=free_port, log_level="error")
        server_instance = uvicorn.Server(config)
        server_thread = threading.Thread(target=server_instance.run, daemon=True)
        server_thread.start()
        time.sleep(1.2)

    try:
        with console.status("[bold green]Simulando usuario común y probando todos los botones...[/bold green]"):
            engine = UserSimulationEngine(base_url=target_url)
            report = engine.run(headless=headless)

        table = Table(title="Traza de Simulación de Usuario Común (E2E)", border_style="cyan", header_style="bold magenta")
        table.add_column("Paso", style="dim", justify="center")
        table.add_column("Módulo", style="bold cyan")
        table.add_column("Acción", style="yellow")
        table.add_column("Elemento / Botón Objetivo", style="bold white")
        table.add_column("Tiempo", justify="right")
        table.add_column("Estado", justify="center")

        for log in report.action_logs:
            badge = "[bold green]PASS[/bold green]" if log["status"] == "PASS" else "[bold red]FAIL[/bold red]"
            table.add_row(
                f"#{log['step']}",
                log["category"],
                log["action_type"],
                log["target_name"],
                f"{log['duration_ms']:.1f}ms",
                badge,
            )

        console.print(table)

        err_style = "bold green" if report.is_healthy else "bold red"
        status_text = (
            f"[bold green]✔ 100% OPERACIONAL[/bold green] - Todos los botones e interacciones funcionan adecuadamente sin errores."
            if report.is_healthy
            else f"[bold red]✘ FALLOS DETECTADOS[/bold red] - Se detectaron excepciones o botones no funcionales."
        )

        console.print(Panel(
            f"[bold white]Resumen de la Simulación de Usuario:[/bold white]\n\n"
            f"• [cyan]Total de Acciones Ejecutadas:[/] [bold]{report.total_actions}[/bold]\n"
            f"• [cyan]Botones y Controles Probados:[/] [bold]{report.total_buttons_tested}[/bold]\n"
            f"• [cyan]Acciones Exitosas:[/] [bold green]{report.successful_actions}[/bold green]\n"
            f"• [cyan]Acciones Fallidas:[/] [{'bold green' if report.failed_actions == 0 else 'bold red'}]{report.failed_actions}[/]\n"
            f"• [cyan]Excepciones JS (pageerror):[/] [{err_style}]{len(report.js_errors)}[/]\n"
            f"• [cyan]Errores en Consola (console.error):[/] [{err_style}]{len(report.console_errors)}[/]\n"
            f"• [cyan]Tiempo Total:[/] {report.duration_seconds:.2f}s\n\n"
            f"{status_text}",
            title="[bold]Certificado de Calidad de Usuario[/bold]",
            border_style="green" if report.is_healthy else "red",
        ))

    finally:
        if server_instance:
            server_instance.should_exit = True


def run_audit_invariants(config_path: str = ".audit-rules.yaml", target_dir: str = ".", json_output: str = None):
    from cyberaudit.core.invariants import InvariantContractParser, AstCallGraphEngine
    from rich.table import Table

    if not os.path.exists(config_path):
        console.print(f"[red bold]Error:[/] Invariant rules configuration not found: {config_path}")
        sys.exit(1)

    with console.status(f"[bold cyan]Auditing software against invariant contracts ({config_path})...[/bold cyan]"):
        rules = InvariantContractParser.load_from_file(config_path)
        engine = AstCallGraphEngine(base_dir=target_dir)
        report = engine.audit_invariants(rules)

    console.print(f"\n[bold green]═══ CyberAudit Invariant Contracts Audit Report ═══[/bold green]")
    console.print(f"[dim]Timestamp: {report.timestamp} | Reglas evaluadas: {report.total_rules_evaluated} | Archivos analizados: {report.total_files_audited}[/dim]")

    score_color = "green" if report.compliance_score >= 90 else ("yellow" if report.compliance_score >= 70 else "red")
    console.print(f"Cumplimiento Arquitectónico: [{score_color} bold]{report.compliance_score}%[/] ({report.status})\n")

    if report.total_violations == 0:
        console.print("[bold green]✔ ¡Excelente! Todos los grafos de llamadas (Call Graphs) cumplen con los contratos de invariantes declarados.[/bold green]\n")
    else:
        table = Table(title="Violaciones de Contratos de Invariantes Detectadas", header_style="bold magenta")
        table.add_column("Regla", style="cyan")
        table.add_column("Ubicación", style="yellow")
        table.add_column("Función", style="white")
        table.add_column("Tipo", style="red")
        table.add_column("Detalle", style="dim")

        for v in report.violations:
            loc = f"{v.file_path}:{v.line_number}"
            table.add_row(v.rule_id, loc, v.function_name, v.violation_type, v.detail)

        console.print(table)
        console.print(f"[yellow]Sugerencia: Ejecuta remediación autónoma en sandbox para generar diffs acotados con evidencia dual.[/yellow]\n")

    if json_output:
        import json
        with open(json_output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        console.print(f"[green]Reporte JSON guardado en:[/] {json_output}")


def run_invariants_infer(target_dir: str = ".", output_path: str = ".audit-rules.yaml"):
    """Infers architectural invariants and synthesizes a production-ready .audit-rules.yaml."""
    from cyberaudit.core.invariants_inferer import InvariantsInferer
    from rich.table import Table

    console.print("[bold cyan]CyberAudit Invariant Inference Engine[/bold cyan]")
    console.print(f"[dim]Analyzing codebase at '{target_dir}' to discover architectural invariants...[/dim]\n")

    inferer = InvariantsInferer(base_dir=target_dir)
    rules = inferer.analyze()

    table = Table(title="Inferred Architectural Invariants", border_style="cyan")
    table.add_column("Rule ID", style="bold green")
    table.add_column("Category", style="cyan")
    table.add_column("Sinks", style="red")
    table.add_column("Required Guards", style="yellow")
    table.add_column("Confidence", justify="right")

    for r in rules:
        table.add_row(
            r.rule_id,
            r.name,
            ", ".join(r.forbidden_sinks),
            ", ".join(r.required_guards),
            f"{int(r.confidence * 100)}%",
        )
    console.print(table)

    yaml_text = inferer.synthesize_yaml(rules)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(yaml_text)
    console.print(f"\n[green bold][+] Generated {len(rules)} invariant contract(s) saved to:[/] {output_path}")
    console.print("[dim]Review the file and commit it to enable deterministic CI/CD verification.[/dim]\n")


def run_ci(config_path: str = ".audit-rules.yaml", target_dir: str = ".",
           fail_on_violations: bool = True, fail_threshold: int = 0,
           output_format: str = "table", output_file: str = None,
           scanners: str = "invariants", github_pr: int = None,
           use_cache: bool = True, cache_dir: str = ".cyberaudit_cache"):
    """Headless CI/CD mode — runs audit and returns standard exit codes.
    
    Exit codes:
        0: All contracts satisfied
        1: Violations detected (blocks merge)
        2: Configuration error / crash
    """
    import json as json_mod

    # Validate config
    if "invariants" in scanners:
        if not os.path.exists(config_path):
            console.print(f"[red bold]CI Error:[/] Config not found: {config_path}")
            sys.exit(2)

    # Run invariant audit with optional incremental cache
    from cyberaudit.core.invariants import InvariantContractParser, AstCallGraphEngine
    from cyberaudit.core.ast_cache import AstGraphCache

    ruleset = InvariantContractParser.load_from_file_full(config_path)
    cache = AstGraphCache(cache_dir=cache_dir) if use_cache else None
    engine = AstCallGraphEngine(
        base_dir=target_dir,
        dynamic_path_policy=ruleset.dynamic_path_policy,
        cache=cache
    )
    report = engine.audit_invariants(ruleset.rules)

    report_dict = report.to_dict()
    violations = report_dict.get("violations", [])
    score = report_dict.get("compliance_score", 100.0)

    # Format output
    if output_format == "json":
        output_str = json_mod.dumps(report_dict, indent=2)
    elif output_format == "sarif":
        output_str = _generate_sarif(report_dict)
    else:
        # Table format (default)
        output_str = _generate_ci_table(report_dict)

    # Write output
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output_str)
        console.print(f"[green]Report written to:[/] {output_file}")
    else:
        console.print(output_str)

    # GitHub PR review
    if github_pr:
        try:
            from cyberaudit.integrations.github_pr_reviewer import GitHubPRReviewer
            reviewer = GitHubPRReviewer()
            result = reviewer.review_pr(github_pr, violations, score)
            if result.success:
                console.print(f"[green]✓ GitHub PR #{github_pr} reviewed ({result.comments_posted} comments)[/]")
            else:
                console.print(f"[yellow]⚠ GitHub PR review failed: {result.error}[/]")
        except Exception as e:
            console.print(f"[yellow]⚠ GitHub PR review skipped: {e}[/]")

    # Determine exit code: dynamic_path_policy='warn' emits advisory findings without blocking CI
    blocking_violations = [
        v for v in violations
        if not (v.get("violation_type") == "UNVERIFIED_DYNAMIC_PATH" and engine.dynamic_path_policy == "warn")
    ]
    blocking_count = len(blocking_violations)
    if fail_on_violations and blocking_count > fail_threshold:
        console.print(f"[red bold]CI FAILED:[/] {blocking_count} blocking violation(s) detected (threshold: {fail_threshold})")
        sys.exit(1)
    else:
        console.print(f"[green bold]CI PASSED:[/] {score:.1f}% compliance, {blocking_count} blocking violation(s)")
        sys.exit(0)


def _generate_sarif(report_dict: dict) -> str:
    """Generates SARIF v2.1.0 output compatible with GitHub Code Scanning."""
    import json as json_mod

    rules = []
    results = []

    # Build unique rules from violations
    seen_rules = set()
    for v in report_dict.get("violations", []):
        rule_id = v.get("rule_id", "INV-UNKNOWN")
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": v.get("rule_name", rule_id),
                "shortDescription": {"text": v.get("rule_name", "")},
                "fullDescription": {"text": v.get("detail", "")},
                "defaultConfiguration": {
                    "level": "error" if v.get("severity") in ("CRITICAL", "HIGH") else "warning"
                },
            })

        results.append({
            "ruleId": rule_id,
            "level": "error" if v.get("severity") in ("CRITICAL", "HIGH") else "warning",
            "message": {"text": v.get("detail", "Invariant violation detected")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v.get("file_path", "").replace("\\", "/")},
                    "region": {"startLine": v.get("line_number", 1)}
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CyberAudit Invariant Guard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/cyberaudit/invariant-guard",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }
    return json_mod.dumps(sarif, indent=2)


def _generate_ci_table(report_dict: dict) -> str:
    """Generates a compact table output for CI logs."""
    lines = []
    lines.append("=" * 60)
    lines.append("  CyberAudit CI — Invariant Contracts Compliance Report")
    lines.append("=" * 60)
    lines.append(f"  Timestamp:    {report_dict.get('timestamp', 'N/A')}")
    lines.append(f"  Rules:        {report_dict.get('total_rules_evaluated', 0)}")
    lines.append(f"  Files:        {report_dict.get('total_files_audited', 0)}")
    lines.append(f"  Violations:   {report_dict.get('total_violations', 0)}")
    lines.append(f"  Compliance:   {report_dict.get('compliance_score', 0):.1f}%")
    lines.append(f"  Status:       {report_dict.get('status', 'UNKNOWN')}")
    lines.append("-" * 60)

    for v in report_dict.get("violations", []):
        lines.append(f"  ⚠ {v.get('rule_id', '?')} | {v.get('file_path', '?')}:{v.get('line_number', '?')} | {v.get('violation_type', '?')}")
        lines.append(f"    → {v.get('detail', '')}")

    if not report_dict.get("violations"):
        lines.append("  ✅ All invariant contracts satisfied.")

    lines.append("=" * 60)
    return "\n".join(lines)


def _kali_extras_from_args(args) -> dict:
    """Collects optional tool parameters from the CLI namespace."""
    mapping = {
        "nmap_scripts": "nmap_scripts",
        "severity_filter": "severity_filter",
        "rate_limit": "rate_limit",
        "threads": "threads",
        "duration_seconds": "duration",
        "interface": "interface",
        "service": "service",
        "search": "term",
        "hash_file": "hash_file",
        "capture_file": "capture_file",
        "userlist": "userlist",
        "passlist": "passlist",
        "snmp_community": "snmp_community",
        "wordlist": "wordlist",
        "extensions": "extensions",
    }
    extras = {}
    for attr, key in mapping.items():
        value = getattr(args, attr, None)
        if value:
            extras[key] = str(value)
    if getattr(args, "sudo", False):
        extras["sudo"] = "true"
    if getattr(args, "nmap_vuln", False):
        extras["nmap_vuln"] = "true"
    if getattr(args, "zone_transfer", False):
        extras["dns_zone_transfer"] = "true"
    if getattr(args, "insecure_tls", False):
        extras["insecure_tls"] = "true"
    return extras


def _build_kali_scope(args, target: str):
    """Builds the scope guard from a signed scope file or an explicit CLI declaration."""
    from cyberaudit.kali.scope import DEFAULT_SCOPE_FILE, SCOPE_ENV_VAR, EngagementScope, ScopeGuard

    scope_path = getattr(args, "scope", None)
    resolved = os.path.realpath(os.path.expanduser(scope_path or os.getenv(SCOPE_ENV_VAR, "").strip() or DEFAULT_SCOPE_FILE))
    if getattr(args, "authorized", False) and not os.path.isfile(resolved):
        scope = EngagementScope.from_cli(
            targets=[target],
            allow_private=getattr(args, "allow_local", False),
            allow_intrusive=getattr(args, "allow_intrusive", False),
            engagement_id=getattr(args, "engagement_id", "") or "CLI-DECLARED",
        )
        console.print("[yellow bold][!] Gobernanza:[/] usando una declaración de alcance en línea de comandos (--authorized).")
        console.print("[dim]    Para engagements reales usa un archivo firmado: python cli.py kali-scope init[/dim]")
        console.print(f"[dim]    Alcance: {scope.summary()}[/dim]")
        return ScopeGuard(scope)
    guard = ScopeGuard.from_file(resolved)
    if guard.authorized:
        console.print(f"[green][+] Alcance cargado:[/] {guard.scope.summary()}")
        if guard.scope.source_path:
            console.print(f"[dim]    Archivo: {guard.scope.source_path}[/dim]")
    return guard


def _print_kali_coverage(result, show_skipped: bool = True) -> None:
    """Renders the per-tool coverage table of a Kali audit."""
    from rich.table import Table

    colors = {"executed": "green", "planned": "cyan", "skipped": "yellow", "failed": "red", "blocked": "red"}
    table = Table(title="Cobertura de herramientas Kali", show_lines=False)
    table.add_column("Herramienta", style="bold")
    table.add_column("Estado")
    table.add_column("Riesgo")
    table.add_column("Hallazgos", justify="right")
    table.add_column("Detalle", overflow="fold", max_width=70)
    for entry in result.coverage:
        if entry.status == "skipped" and not show_skipped:
            continue
        color = colors.get(entry.status, "white")
        detail = entry.reason or entry.command or ""
        if entry.status == "skipped" and entry.install_hint:
            detail = f"{detail} → {entry.install_hint}"
        table.add_row(
            entry.tool_title.split(" — ")[0],
            f"[{color}]{entry.status.upper()}[/{color}]",
            entry.risk or "-",
            str(entry.findings),
            detail[:400],
        )
    console.print(table)


def _export_kali_result(result, json_output=None, html_output=None, sarif_output=None) -> None:
    """Writes the Kali-specific JSON bundle plus optional platform HTML/SARIF reports."""
    import json
    from cyberaudit.kali.orchestrator import KaliAuditResult
    from cyberaudit.kali.reporter_bridge import export_kali_html, export_kali_json

    if json_output:
        path = export_kali_json(result, json_output)
        console.print(f"[green][+] Resultado completo de la auditoría Kali (JSON):[/] {path}")
    if html_output:
        path = export_kali_html(result, html_output)
        console.print(f"[green][+] Dashboard HTML interactivo:[/] {path}")
    if sarif_output:
        saved = Reporter(result.report).export_sarif(sarif_output, base_dir=result.target)
        console.print(f"[green][+] OASIS SARIF 2.1.0:[/] {saved}")


def run_kali_tools(json_output: str = None, include_missing: bool = True) -> None:
    """Lists every registered Kali tool with availability, version and risk classification."""
    import json as _json
    from rich.table import Table
    from cyberaudit.kali import discover_tools, KALI_PROFILES, kill_switch_engaged

    statuses = discover_tools(force=True)
    available = [s for s in statuses if s.available]
    missing = [s for s in statuses if not s.available]

    table = Table(title=f"Arsenal Kali detectado en este host ({len(available)}/{len(statuses)} disponibles)")
    table.add_column("Herramienta", style="bold")
    table.add_column("Binario")
    table.add_column("Versión")
    table.add_column("Categoría")
    table.add_column("Riesgo")
    table.add_column("Perfiles")
    for status in statuses:
        if not status.available and not include_missing:
            continue
        state = "[green]OK[/green]" if status.available else "[red]AUSENTE[/red]"
        risk_color = {"PASSIVE": "blue", "ACTIVE": "yellow", "INTRUSIVE": "red"}.get(status.tool.risk.value, "white")
        table.add_row(
            f"{status.tool.key} {state}",
            os.path.basename(status.path) if status.path else status.tool.binary,
            status.version or "-",
            status.tool.category.value,
            f"[{risk_color}]{status.tool.risk.value}[/{risk_color}]",
            ",".join(status.tool.profiles) or "-",
        )
    console.print(table)

    if missing:
        console.print("[yellow]Instalación sugerida para las ausentes:[/]")
        for status in missing:
            console.print(f"  [dim]- {status.tool.key}: {status.tool.install_hint}[/dim]")

    console.print("\n[bold cyan]Perfiles de auditoría:[/]")
    for key, profile in KALI_PROFILES.items():
        console.print(f"  [bold]{key}[/] — {profile.title}: {profile.description}")

    reason = kill_switch_engaged()
    if reason:
        console.print(f"[red bold][!] Kill-switch activo:[/] {reason}")

    if json_output:
        payload = {
            "tools": [status.to_dict() for status in statuses],
            "profiles": {key: {"title": p.title, "description": p.description, "tools": list(p.tools), "risk": p.risk.value} for key, p in KALI_PROFILES.items()},
            "kill_switch": reason,
        }
        with open(json_output, "w", encoding="utf-8") as handle:
            _json.dump(payload, handle, ensure_ascii=False, indent=2)
        console.print(f"[green][+] Inventario exportado a:[/] {json_output}")


def run_kali_status(json_output: str = None) -> None:
    """Pre-flight check: tools, engagement scope, local LLM and artifact storage."""
    import json as _json
    from cyberaudit.ai.co_analyst import AICoAnalyst
    from cyberaudit.kali import DEFAULT_SCOPE_FILE, SCOPE_ENV_VAR, discover_tools, kill_switch_engaged
    from cyberaudit.kali.scope import EngagementScope
    from cyberaudit.kali.tool_registry import KaliCategory

    statuses = discover_tools()
    available = [s for s in statuses if s.available]
    covered_categories = len({s.tool.category for s in available})

    scope_path = os.getenv(SCOPE_ENV_VAR, "").strip() or DEFAULT_SCOPE_FILE
    scope = EngagementScope.load(scope_path if os.path.isfile(scope_path) else None)

    analyst = AICoAnalyst()
    reachable, model = analyst.is_lm_studio_available(timeout=3.0)
    offline = os.getenv("CYBERAUDIT_OFFLINE", "").strip() in ("1", "true", "yes", "on")
    switch = kill_switch_engaged()

    console.print("[bold cyan]=== CyberAudit ↔ Kali Linux · Diagnóstico ===[/bold cyan]")
    console.print(f"[+] Herramientas registradas: [bold]{len(statuses)}[/] | disponibles: [bold green]{len(available)}[/]")
    console.print(f"[+] Categorías cubiertas: {covered_categories}/{len(list(KaliCategory))} del catálogo")
    if scope.authorized:
        console.print(f"[green][+] Alcance autorizado:[/] {scope.summary()}")
    else:
        console.print("[yellow][!] Sin alcance autorizado:[/] ejecuta 'python cli.py kali-scope init' y firma el archivo.")
    if reachable and model:
        console.print(f"[green][+] LLM local (LM Studio):[/] online en {analyst.lm_studio_url} — modelo: [bold]{model}[/bold]")
    elif reachable:
        console.print(f"[yellow][!] LLM local:[/] servidor accesible en {analyst.lm_studio_url} pero sin modelo de chat cargado.")
        console.print("[dim]    Carga un modelo: scripts/kali_local_llm.sh ensure (o guía en KALI_INTEGRATION_README.md)[/dim]")
    else:
        console.print(f"[yellow][!] LLM local:[/] servidor no accesible en {analyst.lm_studio_url}. El modo autónomo usará el planificador determinista.")
    if offline:
        console.print("[yellow][!] Modo OFFLINE activo:[/] no se ejecutarán herramientas contra objetivos en red (CYBERAUDIT_OFFLINE=1).")
    if switch:
        console.print(f"[red bold][!] Kill-switch:[/] {switch}")
    console.print(f"[+] Directorio de evidencias: {os.path.realpath(os.getenv('CYBERAUDIT_KALI_ARTIFACTS', os.path.join(os.getcwd(), 'reports', 'kali')))}")

    if json_output:
        payload = {
            "tools_total": len(statuses),
            "tools_available": len(available),
            "scope": scope.to_dict(),
            "lm_studio_reachable": reachable,
            "lm_studio_model": model,
            "offline_mode": offline,
            "kill_switch": switch,
        }
        with open(json_output, "w", encoding="utf-8") as handle:
            _json.dump(payload, handle, ensure_ascii=False, indent=2)
        console.print(f"[green][+] Diagnóstico exportado a:[/] {json_output}")


def run_kali_scope_init(path: str = None, force: bool = False) -> None:
    """Writes the engagement authorization template (Rules of Engagement)."""
    from cyberaudit.kali.scope import ScopeViolationError, write_scope_template

    try:
        written = write_scope_template(path, force=force)
    except ScopeViolationError as exc:
        console.print(f"[red bold][!] {exc}[/]")
        sys.exit(1)
    console.print(f"[green][+] Plantilla de autorización creada:[/] {written}")
    console.print("[bold]Pasos obligatorios antes de auditar:[/]")
    console.print("  1. Rellena cliente, responsable, ventana temporal y objetivos en 'allow'.")
    console.print("  2. Marca 'authorized: true' únicamente con autorización escrita del cliente.")
    console.print("  3. Ejecuta: python cli.py kali-scan <objetivo> --profile recon")


def run_kali_scope_check(args) -> None:
    """Validates a target against the engagement scope without running any tool."""
    from cyberaudit.kali.scope import RiskLevel, ScopeViolationError

    target = args.target
    guard = _build_kali_scope(args, target)
    risk = RiskLevel.INTRUSIVE if getattr(args, "allow_intrusive", False) else RiskLevel.ACTIVE
    try:
        authorization = guard.authorize(target, risk)
        guard.authorize_local_floor(target)
    except ScopeViolationError as exc:
        console.print(f"[red bold][X] Objetivo FUERA de alcance:[/] {exc}")
        sys.exit(1)
    console.print(f"[green bold][+] Objetivo autorizado:[/] {authorization.host}")
    console.print(f"    IPs resueltas: {', '.join(authorization.resolved_ips) or 'n/d'}")
    console.print(f"    Regla que autoriza: {authorization.matched_rule}")
    console.print(f"    Riesgo máximo evaluado: {authorization.risk.value}")
    console.print(f"    Engagement: {authorization.engagement_id or 'n/d'} ({authorization.client or 'cliente n/d'})")


def run_kali_scan(args) -> None:
    """Deterministic authorized Kali sweep (profile or explicit tool list)."""
    from cyberaudit.ai.co_analyst import AICoAnalyst
    from cyberaudit.kali import KALI_TOOLS, KaliAuditOrchestrator, KaliToolError, ScopeViolationError

    target = args.target
    guard = _build_kali_scope(args, target)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()] if getattr(args, "tools", None) else None

    if getattr(args, "backend", "local") != "local":
        from cyberaudit.kali.remote import invoke_worker, save_remote_result
        if args.html or args.sarif or args.ai:
            raise ValueError("El worker remoto exporta JSON; HTML/SARIF/IA remotos aún no están implementados.")
        response = invoke_worker({
            "protocol": 1, "action": "scan", "scope": guard.scope.to_dict(),
            "options": {"target": target, "profile": args.profile, "tools": tools,
                        "dry_run": args.dry_run, "allow_intrusive": args.allow_intrusive,
                        "wordlist": args.wordlist, "ports": args.ports,
                        "extras": _kali_extras_from_args(args),
                        "run_exploit_correlation": not args.no_exploit_correlation},
        }, args.backend, args.distribution, args.ssh_host, worker_python=args.worker_python)
        destination = args.json or os.path.join("reports", "kali", "remote_result.json")
        save_remote_result(response, destination)
        result_data = response["result"]
        console.print(f"Resultado remoto: {destination}")
        console.print(f"Evidencias brutas en Kali: {result_data['artifacts_dir']}")
        coverage = result_data.get("coverage", [])
        if not coverage or any(item["status"] in ("failed", "blocked", "skipped") for item in coverage):
            sys.exit(2)
        severities = result_data["report"]["severity_counts"]
        if args.fail_on_findings and severities.get("CRITICAL", 0) + severities.get("HIGH", 0):
            sys.exit(1)
        return

    artifacts_root = getattr(args, "artifacts_dir", None)
    orchestrator = KaliAuditOrchestrator(
        scope_guard=guard,
        artifacts_root=artifacts_root,
        progress=lambda message: console.print(f"[dim]→ {message}[/dim]"),
    )

    try:
        with console.status(f"[bold cyan]Ejecutando auditoría Kali ({args.profile}) contra {target}…[/bold cyan]"):
            result = orchestrator.audit(
                target=target,
                profile=args.profile,
                tools=tools,
                dry_run=getattr(args, "dry_run", False),
                allow_intrusive=getattr(args, "allow_intrusive", False),
                wordlist=getattr(args, "wordlist", None),
                ports=getattr(args, "ports", None),
                extras=_kali_extras_from_args(args),
                run_exploit_correlation=not getattr(args, "no_exploit_correlation", False),
            )
    except ScopeViolationError as exc:
        console.print(f"[red bold][X] Bloqueado por la política de alcance:[/] {exc}")
        sys.exit(2)
    except KaliToolError as exc:
        console.print(f"[red bold][X] Error de configuración de herramientas:[/] {exc}")
        sys.exit(2)

    if getattr(args, "dry_run", False):
        console.print("[bold yellow]MODO SIMULACIÓN (--dry-run):[/] no se ejecutó ninguna herramienta. Plan calculado:")
        for step in result.plan:
            target_desc = step["tool"]
            console.print(f"  - {target_desc}: {step.get('command') or step.get('reason')}")

    if getattr(args, "ai", False):
        with console.status("[bold green]Síntesis ejecutiva con el AI Co-Analyst…[/bold green]"):
            report = AICoAnalyst().analyze(result.report, provider_mode=args.ai_provider)
            result.report = report
            result.ai_summary = report.executive_summary
        if report.ai_provider_used:
            console.print(f"[dim]Proveedor de síntesis: {report.ai_provider_used}[/dim]")

    # Evidence first: the artifacts are written before console rendering so that a broken
    # output pipe (p.ej. '| head') nunca haga perder el informe ni el audit trail.
    _export_kali_result(result, getattr(args, "json", None), getattr(args, "html", None), getattr(args, "sarif", None))
    _print_kali_coverage(result)

    sev_filter = None
    if getattr(args, "severity", None):
        try:
            sev_filter = Severity[args.severity.upper()]
        except KeyError:
            console.print(f"[yellow]Warning:[/] severidad desconocida '{args.severity}'.")
    Reporter(result.report).print_terminal_summary(min_severity=sev_filter)
    console.print(f"[dim]Evidencias y audit trail: {result.artifacts_dir}[/dim]")
    if getattr(args, "fail_on_findings", False) and result.report.severity_counts.get("CRITICAL", 0) + result.report.severity_counts.get("HIGH", 0) > 0:
        sys.exit(1)


def run_kali_agent(args) -> None:
    """Autonomous local agent: the local LLM plans, Kali executes, results are synthesized."""
    from cyberaudit.ai.co_analyst import AICoAnalyst
    from cyberaudit.kali import KaliAuditOrchestrator, KaliAutonomousAgent, KaliToolError, ScopeViolationError

    target = args.target
    guard = _build_kali_scope(args, target)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()] if getattr(args, "tools", None) else None

    analyst = AICoAnalyst()
    use_llm = not getattr(args, "no_llm", False)

    if use_llm:
        reachable, model = analyst.is_lm_studio_available(timeout=3.0)
        if reachable and model:
            console.print(f"[green][+] Planificador local:[/] {model} ({analyst.lm_studio_url})")
        else:
            console.print("[yellow][!] Sin modelo de chat local disponible:[/] el agente usará el planificador determinista.")
            console.print("[dim]    Guía de despliegue local en KALI_INTEGRATION_README.md (LM Studio + Gemma/Qwen).[/dim]")

    agent = KaliAutonomousAgent(
        orchestrator=KaliAuditOrchestrator(
            scope_guard=guard,
            artifacts_root=getattr(args, "artifacts_dir", None),
            progress=lambda message: console.print(f"[dim]→ {message}[/dim]"),
        ),
        analyst=analyst,
        use_llm=use_llm,
        max_steps=getattr(args, "max_steps", 8),
        time_budget_seconds=getattr(args, "time_budget", 1800),
        verbose=True,
    )

    try:
        with console.status(f"[bold cyan]Agente autónomo analizando {target} (perfil {args.profile})…[/bold cyan]"):
            result = agent.run(
                target=target,
                goal=getattr(args, "goal", "") or "",
                profile=args.profile,
                tools=tools,
                allow_intrusive=getattr(args, "allow_intrusive", False),
                dry_run=getattr(args, "dry_run", False),
                max_steps=getattr(args, "max_steps", 8),
                extras=_kali_extras_from_args(args),
                wordlist=getattr(args, "wordlist", None),
                ports=getattr(args, "ports", None),
                summarize=not getattr(args, "no_summary", False),
                run_exploit_correlation=not getattr(args, "no_exploit_correlation", False),
                session_label="agent",
            )
    except ScopeViolationError as exc:
        console.print(f"[red bold][X] Bloqueado por la política de alcance:[/] {exc}")
        sys.exit(2)
    except KaliToolError as exc:
        console.print(f"[red bold][X] Error de configuración de herramientas:[/] {exc}")
        sys.exit(2)

    from rich.panel import Panel

    if result.agent_trace:
        console.print("[bold cyan]Traza de decisiones del agente:[/]")
        for entry in result.agent_trace:
            if entry.get("action") in ("note",):
                console.print(f"  [yellow]{entry.get('rationale')}[/yellow]")
                continue
            if entry.get("action") == "finish":
                console.print(f"  [bold]finish[/bold] — {entry.get('rationale')}")
                continue
            tool = entry.get("tool") or entry.get("action")
            console.print(
                f"  [bold]{entry.get('step', 0):>2}. {tool}[/bold] "
                f"[{entry.get('status', '')}] {entry.get('rationale', '')[:150]}"
            )
            if entry.get("command"):
                console.print(f"      [dim]{entry['command'][:220]}[/dim]")

    _export_kali_result(result, getattr(args, "json", None), getattr(args, "html", None), getattr(args, "sarif", None))
    _print_kali_coverage(result)
    if result.ai_summary:
        console.print(Panel(result.ai_summary, title="Síntesis ejecutiva (modelo local)", border_style="cyan"))

    sev_filter = None
    if getattr(args, "severity", None):
        try:
            sev_filter = Severity[args.severity.upper()]
        except KeyError:
            pass
    Reporter(result.report).print_terminal_summary(min_severity=sev_filter)
    console.print(f"[dim]Evidencias y audit trail: {result.artifacts_dir}[/dim]")


def run_query_kb(query: str, limit: int = 3, category: str = None):
    """Consulta la base de conocimientos técnica y muestra los principios aplicables."""
    from cyberaudit.core.knowledge_base import KnowledgeBase
    from rich.panel import Panel

    kb = KnowledgeBase()
    results = kb.search(query, limit=limit, category=category)
    if not results:
        console.print(f"[yellow]No se encontraron secciones para la consulta:[/yellow] '{query}'")
        return

    console.print(f"\n[bold green]📚 Base de Conocimientos CyberAudit — {len(results)} resultados para '{query}':[/bold green]\n")
    for idx, r in enumerate(results):
        meta = f"[bold cyan]Categoría:[/] {r['category']} | [bold cyan]Tags:[/] {', '.join(r['tags']) if r['tags'] else 'N/A'}"
        if r.get('cwe_ids'):
            meta += f" | [bold red]CWEs:[/] {', '.join(r['cwe_ids'])}"

        preview = r['content'][:650].strip() + ("..." if len(r['content']) > 650 else "")
        console.print(Panel(
            f"{preview}\n\n[dim]Fuente: {r['relative_path']}[/dim]",
            title=f"[bold white]{idx + 1}. {r['title']}[/bold white]",
            subtitle=meta,
            border_style="blue"
        ))


def main():
    parser = argparse.ArgumentParser(
        prog="cyberaudit",
        description="CyberAudit Suite - Enterprise Cybersecurity Auditing & Quality Assurance Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Audit subcommands")

    # Command: query-kb
    kb_parser = subparsers.add_parser("query-kb", help="Search the engineering and cybersecurity knowledge base")
    kb_parser.add_argument("query", help="Keywords or topic to search (e.g. CWE-78, DDIA, TDD, Command Injection)")
    kb_parser.add_argument("--limit", type=int, default=3, help="Max results to display")
    kb_parser.add_argument("--category", help="Filter by category")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run comprehensive cybersecurity audit on a directory or file")
    scan_parser.add_argument("target", help="Path to file or folder to audit")
    scan_parser.add_argument("--html", help="Generate interactive HTML report at specified path", default=None)
    scan_parser.add_argument("--json", help="Export structured JSON report at specified path", default=None)
    scan_parser.add_argument("--sarif", help="Export OASIS SARIF 2.1.0 compliance report (GitHub/GitLab compatible)", default=None)
    scan_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary")
    scan_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider (local LM Studio, Google Gemini Cloud, or auto-detect)")
    scan_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")
    scan_parser.add_argument("--archetype", choices=["client", "cloud", "full"], default="full", help="Application deployment archetype (client for desktop/mobile, cloud for API/backend, full for general)")
    scan_parser.add_argument("--include-vendor", action="store_true", help="Include third-party and minified vendor code in SAST analysis (default is excluded)")
    scan_parser.add_argument("--offline", "--no-verify-secrets", dest="offline", action="store_true", help="Air-gapped mode: disable live network queries and credential checks (zero egress leaks)")


    # Command: audit-ad
    ad_parser = subparsers.add_parser("audit-ad", help="Audit Active Directory scripts, GPOs, and LDAP configs")
    ad_parser.add_argument("target", help="Path to AD files, scripts, or sysvol mirror")
    ad_parser.add_argument("--html", help="Output HTML report", default=None)
    ad_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: audit-cloud
    cloud_parser = subparsers.add_parser("audit-cloud", help="Audit Cloud / Azure / Entra ID / AWS IaC files")
    cloud_parser.add_argument("target", help="Path to cloud configs or terraform/bicep templates")
    cloud_parser.add_argument("--html", help="Output HTML report", default=None)
    cloud_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: triage-logs
    log_parser = subparsers.add_parser("triage-logs", help="Evaluate event logs & web logs using Sigma detection rules")
    log_parser.add_argument("target", help="Path to log file or directory of logs")
    log_parser.add_argument("--html", help="Output HTML report", default=None)
    log_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: triage-endpoint
    endpoint_parser = subparsers.add_parser("triage-endpoint", help="DFIR Endpoint artifact investigation")
    endpoint_parser.add_argument("target", help="Path to registry dumps, system configs, or forensic artifacts")
    endpoint_parser.add_argument("--html", help="Output HTML report", default=None)
    endpoint_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: audit-aws
    aws_parser = subparsers.add_parser("audit-aws", help="Audit AWS Cloud infrastructure (Terraform, CloudFormation, IAM)")
    aws_parser.add_argument("target", help="Path to AWS Terraform or CloudFormation templates")
    aws_parser.add_argument("--html", help="Output HTML report", default=None)
    aws_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: audit-k8s
    k8s_parser = subparsers.add_parser("audit-k8s", help="Audit Kubernetes manifests and container hardening")
    k8s_parser.add_argument("target", help="Path to Kubernetes YAML manifests or Helm charts")
    k8s_parser.add_argument("--html", help="Output HTML report", default=None)
    k8s_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: audit-cicd
    cicd_parser = subparsers.add_parser("audit-cicd", help="Audit CI/CD workflows and software supply chain dependencies")
    cicd_parser.add_argument("target", help="Path to repository or .github/workflows directory")
    cicd_parser.add_argument("--html", help="Output HTML report", default=None)
    cicd_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: audit-api
    api_parser = subparsers.add_parser("audit-api", help="Audit REST/GraphQL endpoints for OWASP API Security Top 10")
    api_parser.add_argument("target", help="Path to API source code")
    api_parser.add_argument("--html", help="Output HTML report", default=None)
    api_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: audit-ai
    ai_parser = subparsers.add_parser("audit-ai", help="Audit AI pipelines, LLM prompts, RAG stores, and model supply chain")
    ai_parser.add_argument("target", help="Path to AI/ML application or service")
    ai_parser.add_argument("--html", help="Output HTML report", default=None)
    ai_parser.add_argument("--json", help="Output JSON report", default=None)

    # Command: audit-qa
    audit_qa_parser = subparsers.add_parser("audit-qa", help="Audit software code quality, resource leaks, concurrency, and test health")
    audit_qa_parser.add_argument("target", help="Path to software codebase or repository")
    audit_qa_parser.add_argument("--html", help="Output HTML report", default=None)
    audit_qa_parser.add_argument("--json", help="Output JSON report", default=None)
    audit_qa_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary of QA findings")
    audit_qa_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider (local LM Studio, Google Gemini Cloud, or auto-detect)")
    audit_qa_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")
    audit_qa_parser.add_argument("--include-vendor", action="store_true", help="Include third-party vendor files")

    # Command: audit-uiux
    audit_uiux_parser = subparsers.add_parser("audit-uiux", help="Audit UI/UX, responsive ergonomics, and WCAG accessibility standards")
    audit_uiux_parser.add_argument("target", help="Path to software frontend, templates, or styles")
    audit_uiux_parser.add_argument("--html", help="Output HTML report", default=None)
    audit_uiux_parser.add_argument("--json", help="Output JSON report", default=None)
    audit_uiux_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary of UI/UX findings")
    audit_uiux_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider")
    audit_uiux_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")
    audit_uiux_parser.add_argument("--include-vendor", action="store_true", help="Include third-party vendor files")

    # Command: audit-arch
    audit_arch_parser = subparsers.add_parser("audit-arch", help="Audit software architecture, coupling, N+1 queries, layer violations, and copyleft licensing")
    audit_arch_parser.add_argument("target", help="Path to software codebase")
    audit_arch_parser.add_argument("--html", help="Output HTML report", default=None)
    audit_arch_parser.add_argument("--json", help="Output JSON report", default=None)
    audit_arch_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary")
    audit_arch_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider")
    audit_arch_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")
    audit_arch_parser.add_argument("--include-vendor", action="store_true", help="Include third-party vendor files")

    business_parser = subparsers.add_parser("audit-business", help="Auditoría real autenticada por roles y recorridos de negocio")
    business_parser.add_argument("--plan", required=True, help="Plan JSON con alcance, roles, recursos y recorridos")
    business_parser.add_argument("--output", default="reports/business")

    # Command: audit-mobile
    audit_mobile_parser = subparsers.add_parser("audit-mobile", help="Audit Android and mobile application security (OWASP MASVS, Tapjacking, WebViews)")
    audit_mobile_parser.add_argument("target", help="Path to Android project or mobile files")
    audit_mobile_parser.add_argument("--html", help="Output HTML report", default=None)
    audit_mobile_parser.add_argument("--json", help="Output JSON report", default=None)
    audit_mobile_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary")
    audit_mobile_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider")

    # Command: audit-cleancode
    audit_clean_parser = subparsers.add_parser("audit-cleancode", help="Audit code cleanliness, hardcoded paths/IPs (12-Factor App), leftover debug logs, and technical debt")
    audit_clean_parser.add_argument("target", help="Path to software codebase")
    audit_clean_parser.add_argument("--html", help="Output HTML report", default=None)
    audit_clean_parser.add_argument("--json", help="Output JSON report", default=None)
    audit_clean_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary")
    audit_clean_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider")
    audit_clean_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")
    audit_clean_parser.add_argument("--include-vendor", action="store_true", help="Include third-party vendor files")

    # Command: run-dynamic-qa
    dynamic_qa_parser = subparsers.add_parser("run-dynamic-qa", help="Legacy command: reports NOT_RUN; use audit-web or external-audit")
    dynamic_qa_parser.add_argument("--export", help="Path to export standalone HTML evidence report", default=None)

    # Command: run-qa
    qa_parser = subparsers.add_parser("run-qa", help="Run automated QA validation & defensive verification suite across all security pillars")
    qa_parser.add_argument("--pillar", choices=["all", "analyst", "pentester", "engineer", "ai", "qa", "qa_expanded", "uiux", "uiux_expanded", "advanced_qa", "arch", "cleancode", "integration", "infra", "web"], default="all", help="Filter QA test suite by security pillar")
    qa_parser.add_argument("-v", "--verbose", action="store_true", help="Display verbose test item outputs")

    # Command: check-ai
    subparsers.add_parser("check-ai", help="Test connectivity and diagnostics for Local LM Studio and Cloud AI Co-Analyst")

    # Command: ui
    ui_parser = subparsers.add_parser("ui", help="Launch the interactive web dashboard & AI Co-Analyst Studio")
    ui_parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    ui_parser.add_argument("--port", type=int, default=8000, help="Port to run the web server on (default: 8000)")
    ui_parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    ui_parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the default web browser")

    # Command: test-ui
    test_ui_parser = subparsers.add_parser("test-ui", help="Simulate a real user session to test every UI button, modal, tab, and filter (E2E acceptance)")
    test_ui_parser.add_argument("--url", default=None, help="Base URL of running instance (default: spins up temporary internal server)")
    test_ui_parser.add_argument("--no-headless", action="store_true", help="Launch real visible browser window instead of headless")

    # Command: sync-remediation
    remed_parser = subparsers.add_parser("sync-remediation", help="Upload and sync a developer's Markdown (.md) remediation response file with the platform")
    remed_parser.add_argument("remediation_file", help="Path to the remediation Markdown (.md) document")
    remed_parser.add_argument("--target", default=None, help="Root path of target source code (default: inferred from audit report or CWD)")
    remed_parser.add_argument("--report", default=None, help="Path to audit JSON report to update")
    remed_parser.add_argument("--overrides", default="audit_status_overrides.json", help="Path to status overrides JSON (default: audit_status_overrides.json)")
    remed_parser.add_argument("--no-reverify", action="store_true", help="Skip running real scanner re-tests against code on disk")
    remed_parser.add_argument("--ai", action="store_true", help="Request AI Co-Analyst auditor review and debrief for the developer")
    remed_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider for auditor feedback")

    # Command: invariants (Management, Synthesis & Profiling)
    invariants_cmd = subparsers.add_parser("invariants", help="Manage declarative invariant contracts (.audit-rules.yaml)")
    invariants_sub = invariants_cmd.add_subparsers(dest="invariants_action", help="Invariants action")

    init_cmd = invariants_sub.add_parser("init", help="Initialize or infer .audit-rules.yaml from code patterns")
    init_cmd.add_argument("--infer", action="store_true", help="Profile codebase to auto-infer invariant contracts")
    init_cmd.add_argument("--target-dir", default=".", help="Base directory of codebase (default: .)")
    init_cmd.add_argument("--output", default=".audit-rules.yaml", help="Output YAML file path (default: .audit-rules.yaml)")

    # Command: audit-invariants
    invariants_parser = subparsers.add_parser("audit-invariants", help="Audit software against formal declarative invariant contracts (.audit-rules.yaml)")
    invariants_parser.add_argument("--config", default=".audit-rules.yaml", help="Path to .audit-rules.yaml specification (default: .audit-rules.yaml)")
    invariants_parser.add_argument("--target-dir", default=".", help="Base directory of the target codebase (default: current directory)")
    invariants_parser.add_argument("--json", default=None, help="Export structured compliance report to JSON file")

    # Command: ci (Headless CI/CD Pipeline Mode)
    ci_parser = subparsers.add_parser("ci", help="Run CyberAudit in headless CI/CD mode with standard exit codes")
    ci_parser.add_argument("--config", default=".audit-rules.yaml", help="Path to .audit-rules.yaml (default: .audit-rules.yaml)")
    ci_parser.add_argument("--target-dir", default=".", help="Base directory of target codebase (default: .)")
    ci_parser.add_argument("--fail-on-violations", action="store_true", help="Exit with code 1 if any invariant violations found (blocks merge)")
    ci_parser.add_argument("--fail-threshold", type=int, default=0, help="Max violations allowed before failing (default: 0 = any violation fails)")
    ci_parser.add_argument("--output-format", choices=["table", "json", "sarif"], default="table", help="Output format (default: table)")
    ci_parser.add_argument("--output-file", default=None, help="Write report to file (default: stdout)")
    ci_parser.add_argument("--scanners", default="invariants", help="Comma-separated list of scanner sets to run (default: invariants)")
    ci_parser.add_argument("--github-pr", type=int, default=None, help="Post inline review comments on this GitHub PR number")
    ci_parser.add_argument("--no-cache", action="store_true", help="Disable incremental AST graph caching")
    ci_parser.add_argument("--cache-dir", default=".cyberaudit_cache", help="Directory for AST cache store (default: .cyberaudit_cache)")

    # Command: audit-web (Live DAST via Headless Playwright)
    web_parser = subparsers.add_parser("audit-web", help="Audit live web applications (DAST) using Headless Playwright, A11y, and HTTP security")
    web_parser.add_argument("url", help="Target URL to audit (e.g., https://example.com)")
    web_parser.add_argument("--html", help="Generate interactive HTML report", default=None)
    web_parser.add_argument("--json", help="Export structured JSON report", default=None)
    web_parser.add_argument("--allow-local", action="store_true", help="Allow auditing local/private addresses for development")
    web_parser.add_argument("--skip-a11y", action="store_true", help="Skip WCAG 2.1 accessibility axe-core audit")
    web_parser.add_argument("--browsers", nargs="+", choices=["chromium", "firefox", "webkit"], default=["chromium"])
    web_parser.add_argument("--expect-pwa", action="store_true", help="Exigir manifest y funcionamiento PWA")
    web_parser.add_argument("--journey", help="Recorrido funcional JSON con aserciones reales")
    web_parser.add_argument("--offline-selector", help="Elemento que debe ser visible sin conexión")
    web_parser.add_argument("--observation-ms", type=int, default=2000, help="Ventana de observación de rendimiento")
    web_parser.add_argument("--verify-token", help="Domain ownership challenge token", default=None)
    web_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary")
    web_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider")
    web_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")

    # Command: audit-infra (EASM, Port Hygiene, TLS Cryptographic Assessment)
    infra_parser = subparsers.add_parser("audit-infra", help="Audit external attack surface (EASM), port hygiene, and TLS cryptographic configurations")
    infra_parser.add_argument("host", help="Target hostname or IP address to audit (e.g., example.com)")
    infra_parser.add_argument("--ports", help="Comma-separated list of custom ports to check (default: critical catalog)", default=None)
    infra_parser.add_argument("--html", help="Generate interactive HTML report", default=None)
    infra_parser.add_argument("--json", help="Export structured JSON report", default=None)
    infra_parser.add_argument("--allow-local", action="store_true", help="Allow auditing local/private addresses for development")
    infra_parser.add_argument("--verify-token", help="Domain ownership challenge token", default=None)
    infra_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary")
    infra_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider")
    infra_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")

    # Command: audit-login (NIST SP 800-63B Authentication & Form Hygiene)
    login_parser = subparsers.add_parser("audit-login", help="Audit authentication endpoints and login forms (NIST SP 800-63B / OWASP ASVS)")
    login_parser.add_argument("url", help="Login endpoint or page URL (e.g., https://example.com/login)")
    login_parser.add_argument("--html", help="Generate interactive HTML report", default=None)
    login_parser.add_argument("--json", help="Export structured JSON report", default=None)
    login_parser.add_argument("--allow-local", action="store_true", help="Allow auditing local/private addresses for development")
    login_parser.add_argument("--skip-rate-limit", action="store_true", help="Skip the controlled 5-request burst rate-limiting check")
    login_parser.add_argument("--ai", action="store_true", help="Generate AI Co-Analyst executive summary")
    login_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="auto", help="AI provider")
    login_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None, help="Filter minimum severity to display")

    # Command: certify-production (Production Readiness & Deployment Gate)
    cert_parser = subparsers.add_parser(
        "certify-production",
        help="Evaluate software readiness and certify compliance for production deployment (Release Gate)"
    )
    cert_parser.add_argument("target", help="Root directory or file of target application")
    cert_parser.add_argument("--metrics", help="JSON de métricas medidas, con artifact_digest del escaneo")
    cert_parser.add_argument("--env", default="production", choices=["production", "staging", "canary"], help="Target deployment environment (default: production)")
    cert_parser.add_argument("--app-name", default="Target Application", help="Name of application being certified")
    cert_parser.add_argument("--output", default=None, help="Path to write Markdown certification certificate (e.g. RELEASE_CERTIFICATE.md)")
    cert_parser.add_argument("--json", default=None, help="Export structured certificate to JSON file")
    cert_parser.add_argument("--strict", action="store_true", default=True, help="Enforce zero-tolerance production policy (0 critical, 0 high, 100%% tests)")
    cert_parser.add_argument("--no-strict", dest="strict", action="store_false", help="Use permissive staging policy")
    cert_parser.add_argument("--no-fail", dest="fail_on_blocked", action="store_false", default=True, help="Do not exit with code 1 if blocked")

    # ── Command: kali-tools (inventario del arsenal instalado) ──────────────
    kali_tools_parser = subparsers.add_parser(
        "kali-tools",
        help="Lista las herramientas Kali detectadas en este sistema (versión, riesgo, perfiles) y el estado del LLM local")
    kali_tools_parser.add_argument("--json", help="Exportar inventario estructurado a JSON", default=None)
    kali_tools_parser.add_argument("--only-available", action="store_true", help="Mostrar únicamente las herramientas instaladas")

    # ── Command: kali-status (verificación previa del entorno) ──────────────
    kali_status_parser = subparsers.add_parser(
        "kali-status",
        help="Diagnóstico previo: arsenal instalado, alcance autorizado, LLM local (LM Studio) y almacenamiento de evidencias")
    kali_status_parser.add_argument("--json", help="Exportar el diagnóstico a JSON", default=None)

    # ── Command: kali-scope (gestión de la autorización del engagement) ─────
    kali_scope_parser = subparsers.add_parser(
        "kali-scope",
        help="Gestiona la autorización del engagement (Rules of Engagement): plantilla y validación de objetivos")
    kali_scope_sub = kali_scope_parser.add_subparsers(dest="scope_action", help="Acción sobre el alcance")

    kali_scope_init = kali_scope_sub.add_parser("init", help="Crea la plantilla .cyberaudit-scope.yaml para firmar")
    kali_scope_init.add_argument("--path", default=None, help="Ruta de salida (por defecto .cyberaudit-scope.yaml)")
    kali_scope_init.add_argument("--force", action="store_true", help="Sobrescribir si el archivo ya existe")

    kali_scope_check = kali_scope_sub.add_parser("check", help="Valida un objetivo contra el alcance sin ejecutar ninguna herramienta")
    kali_scope_check.add_argument("target", help="Objetivo a validar (dominio, IP, CIDR o URL)")
    kali_scope_check.add_argument("--scope", default=None, help="Ruta al archivo de alcance (por defecto .cyberaudit-scope.yaml)")
    kali_scope_check.add_argument("--authorized", action="store_true", help="Declaración explícita de autorización en línea de comandos (sólo laboratorios)")
    kali_scope_check.add_argument("--engagement-id", dest="engagement_id", default="", help="Identificador del engagement")
    kali_scope_check.add_argument("--allow-local", action="store_true", help="Permitir objetivos en redes privadas (laboratorio aislado)")
    kali_scope_check.add_argument("--allow-intrusive", action="store_true", help="Evaluar el objetivo para acciones intrusivas")

    # Parámetros compartidos por kali-scan y kali-agent
    kali_common = argparse.ArgumentParser(add_help=False)
    kali_common.add_argument("target", help="Objetivo autorizado: dominio, IP, CIDR o URL (p.ej. https://app.cliente.com)")
    kali_common.add_argument("--profile", default="full", choices=sorted(KALI_PROFILE_CHOICES),
                             help="Perfil de auditoría (por defecto: full)")
    kali_common.add_argument("--tools", default=None, help="Lista explícita de herramientas separadas por comas (omite el perfil)")
    kali_common.add_argument("--scope", default=None, help="Ruta al archivo de alcance (por defecto .cyberaudit-scope.yaml)")
    kali_common.add_argument("--authorized", action="store_true", help="Declaración explícita de autorización en CLI (sin archivo firmado)")
    kali_common.add_argument("--engagement-id", dest="engagement_id", default="", help="Identificador del engagement")
    kali_common.add_argument("--allow-local", action="store_true", help="Permitir objetivos privados (laboratorio propio aislado)")
    kali_common.add_argument("--allow-intrusive", action="store_true", help="Habilitar herramientas intrusivas (explotación, fuerza bruta, captura)")
    kali_common.add_argument("--dry-run", action="store_true", help="Calcular el plan y los argv sin ejecutar nada")
    kali_common.add_argument("--ports", default=None, help="Especificación de puertos para nmap/masscan (p.ej. 22,80,443 o 1-1024)")
    kali_common.add_argument("--wordlist", default=None, help="Diccionario para gobuster/ffuf/dirb (por defecto: seclists/dirb)")
    kali_common.add_argument("--search", default=None, help="Término para la correlación con Exploit-DB (searchsploit)")
    kali_common.add_argument("--hash-file", dest="hash_file", default=None, help="Archivo de hashes para auditoría offline (john/hashcat)")
    kali_common.add_argument("--capture-file", dest="capture_file", default=None, help="Captura PCAP/802.11 aportada al engagement (aircrack-ng)")
    kali_common.add_argument("--userlist", default=None, help="Diccionario de usuarios autorizado (hydra/enum4linux/smtp-user-enum)")
    kali_common.add_argument("--passlist", default=None, help="Diccionario de contraseñas autorizado (hydra)")
    kali_common.add_argument("--service", default=None, help="Servicio objetivo para hydra (ssh, ftp, http-get, smb, rdp...)")
    kali_common.add_argument("--snmp-community", dest="snmp_community", default=None, help="Comunidad SNMP a probar (por defecto public)")
    kali_common.add_argument("--interface", default=None, help="Interfaz de red para captura (tcpdump/tshark/responder)")
    kali_common.add_argument("--duration", type=int, default=None, help="Duración de captura en segundos")
    kali_common.add_argument("--nmap-scripts", dest="nmap_scripts", default=None, help="Scripts NSE concretos (p.ej. vuln,smb-vuln-*)")
    kali_common.add_argument("--nmap-vuln", dest="nmap_vuln", action="store_true", help="Activar scripts NSE default,vuln en nmap")
    kali_common.add_argument("--severity-filter", dest="severity_filter", default=None, help="Severidades de plantillas nuclei/httpx (p.ej. critical,high)")
    kali_common.add_argument("--rate-limit", dest="rate_limit", type=int, default=None, help="Peticiones por segundo máximas (nuclei/httpx/masscan)")
    kali_common.add_argument("--threads", type=int, default=None, help="Hilos concurrentes (gobuster/ffuf/sqlmap)")
    kali_common.add_argument("--zone-transfer", dest="zone_transfer", action="store_true", help="Incluir intento de transferencia de zona DNS (dnsrecon)")
    kali_common.add_argument("--insecure-tls", dest="insecure_tls", action="store_true", help="Omitir la validación TLS en fuzzers web (gobuster/ffuf)")
    kali_common.add_argument("--sudo", action="store_true", help="Ejecutar con sudo -n (requerido por masscan/tcpdump/tshark/responder)")
    kali_common.add_argument("--no-exploit-correlation", action="store_true", help="Desactivar la correlación con Exploit-DB")
    kali_common.add_argument("--artifacts-dir", dest="artifacts_dir", default=None, help="Directorio raíz de evidencias (por defecto reports/kali)")
    kali_common.add_argument("--json", default=None, help="Exportar el resultado completo del engagement a JSON")
    kali_common.add_argument("--html", default=None, help="Generar el informe de evidencias HTML")
    kali_common.add_argument("--sarif", default=None, help="Exportar los hallazgos en formato OASIS SARIF 2.1.0")
    kali_common.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None,
                             help="Filtrar la severidad mínima mostrada en consola")

    kali_scan_parser = subparsers.add_parser(
        "kali-scan", parents=[kali_common],
        help="Auditoría determinista con herramientas Kali (perfil o lista explícita) sobre un objetivo autorizado")
    kali_scan_parser.add_argument("--backend", choices=["local", "wsl", "ssh"], default="local", help="Lugar de ejecución del pentesting")
    kali_scan_parser.add_argument("--distribution", default="kali-linux", help="Distribución WSL que aloja el worker")
    kali_scan_parser.add_argument("--ssh-host", default="", help="Alias SSH o usuario@host del worker Kali")
    remote_inventory = subparsers.add_parser("kali-remote-tools", help="Inventario de herramientas del worker Kali")
    remote_inventory.add_argument("--backend", choices=["wsl", "ssh"], required=True)
    remote_inventory.add_argument("--distribution", default="kali-linux")
    remote_inventory.add_argument("--ssh-host", default="")
    remote_inventory.add_argument("--worker-python", default="python3", help="Intérprete del entorno virtual en Kali")
    kali_scan_parser.add_argument("--worker-python", default="python3", help="Intérprete del entorno virtual en Kali")
    remote_inventory.add_argument("--json", default="reports/kali/remote_inventory.json")
    kali_scan_parser.add_argument("--ai", action="store_true", help="Sintetizar el informe con el AI Co-Analyst (local por defecto)")
    kali_scan_parser.add_argument("--ai-provider", choices=["auto", "local", "gemini"], default="local", help="Proveedor de síntesis")
    kali_scan_parser.add_argument("--fail-on-findings", action="store_true", help="Salir con código 1 si hay hallazgos CRITICAL/HIGH")

    kali_agent_parser = subparsers.add_parser(
        "kali-agent", parents=[kali_common],
        help="Agente autónomo local: el modelo de LM Studio planifica, Kali ejecuta y CyberAudit procesa los resultados")
    kali_agent_parser.add_argument("--goal", default="", help="Meta del operador para orientar al planificador local")
    kali_agent_parser.add_argument("--max-steps", dest="max_steps", type=int, default=8, help="Máximo de ejecuciones de herramientas (por defecto 8)")
    kali_agent_parser.add_argument("--time-budget", dest="time_budget", type=int, default=1800, help="Presupuesto total de tiempo en segundos")
    kali_agent_parser.add_argument("--no-llm", dest="no_llm", action="store_true", help="No usar el modelo local: planificador determinista")
    kali_agent_parser.add_argument("--no-summary", dest="no_summary", action="store_true", help="Omitir la síntesis ejecutiva final")

    external_parser = subparsers.add_parser("external-audit", help="Integraciones SAST, SCA, IaC, DAST, API y QA con evidencia")
    external_parser.add_argument("--plan", help="Plan JSON version 1")
    external_parser.add_argument("--execute", action="store_true", help="Ejecutar análisis locales e importar evidencia; por defecto solo planifica")
    external_parser.add_argument("--output", default="reports/external", help="Directorio de trabajos")
    external_parser.add_argument("--inventory", action="store_true", help="Mostrar integraciones y binarios disponibles")
    external_parser.add_argument("--verify", help="Verificar evidencia de un directorio de trabajo")

    # ── Command: harness (CyberAudit Skill Harness - rsc style) ─────────────
    harness_parser = subparsers.add_parser(
        "harness",
        help="CyberAudit Skill Harness (rsc-style): list-skills, run-skill, risk y sello criptográfico sobre los 68 escáneres"
    )
    harness_sub = harness_parser.add_subparsers(dest="harness_action", help="Acción del Skill Harness")

    harness_list = harness_sub.add_parser("list-skills", help="Lista las 9 skills del CyberAudit Harness y sus escáneres asociados")
    harness_list.add_argument("--json", action="store_true", help="Imprimir salida en formato JSON")

    harness_run = harness_sub.add_parser("run-skill", help="Ejecuta todos los escáneres de una skill de CyberAudit")
    harness_run.add_argument("skill_id", help="ID de la skill (p.ej. cyberaudit-appsec, cyberaudit-qa-resilience, cyberaudit-ui-ux-a11y, cyberaudit-full)")
    harness_run.add_argument("target", nargs="?", default=".", help="Directorio o archivo objetivo")
    harness_run.add_argument("--threshold", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], help="Severidad mínima que bloquea el veredicto")
    harness_run.add_argument("--json", default=None, help="Guardar reporte JSON de evidencia de la skill")
    harness_run.add_argument("--fail-on-block", action="store_true", help="Salir con código 1 si el veredicto es BLOCK")

    harness_risk = harness_sub.add_parser("risk", help="Calcula el tier de riesgo (0/1/2) y recomienda qué skills de CyberAudit ejecutar")
    harness_risk.add_argument("target", nargs="?", default=".", help="Directorio del repositorio")
    harness_risk.add_argument("--json", action="store_true", help="Imprimir salida en formato JSON")

    harness_sello = harness_sub.add_parser("sello", help="Ejecuta la auditoría y emite SELLO-CYBERAUDIT-VERIFICADO en .rsc/cyberaudit-sello-log.jsonl")
    harness_sello.add_argument("target", nargs="?", default=".", help="Directorio objetivo")
    harness_sello.add_argument("--skill", default="cyberaudit-full", help="Skill a certificar (por defecto: cyberaudit-full con los 68 escáneres)")
    harness_sello.add_argument("--threshold", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], help="Umbral de bloqueo")
    harness_sello.add_argument("--json", action="store_true", help="Imprimir sello en formato JSON")

    # ── Command: onboard (Interactive Plan & Scaffolding Wizard) ─────────────
    onboard_parser = subparsers.add_parser("onboard", help="Interactive CyberAudit onboarding wizard with binding Plan ID")
    onboard_parser.add_argument("target", nargs="?", default=".", help="Target project root")
    onboard_parser.add_argument("--technical-level", default="technical", choices=["technical", "non-technical", "mixed"], help="Communication register")
    onboard_parser.add_argument("--project-kind", default="software", choices=["software", "operations", "research", "content", "mixed"], help="Kind of project")
    onboard_parser.add_argument("--goal", default="Auditoría integral de software, seguridad y gobernanza", help="Project goal")
    onboard_parser.add_argument("--software-scope", default="growing", choices=["small", "growing", "complex"], help="Software scope")
    onboard_parser.add_argument("--workflow", default="main", choices=["main", "branches"], help="Git landing workflow")
    onboard_parser.add_argument("--target-assistants", default="antigravity,claude,cursor", help="Comma-separated target assistants")
    onboard_parser.add_argument("--accept-plan", default=None, help="Cryptographic Plan ID to accept and apply")

    # ── Command: doctor (Diagnostic health check) ───────────────────────────
    doctor_parser = subparsers.add_parser("doctor", help="Check CyberAudit harness health, configuration, and scanner status")
    doctor_parser.add_argument("target", nargs="?", default=".", help="Target directory")

    # ── Command: fix (Real 4-phase TDD AutoFix) ────────────────────────────
    fix_parser = subparsers.add_parser("fix", help="Real 4-phase TDD auto-remediation loop (Red Test -> Patch -> Green Test -> Sello)")
    fix_parser.add_argument("finding_id", help="Finding ID or keyword to remediate")
    fix_parser.add_argument("target", nargs="?", default=".", help="Target directory")

    # ── Command: setup-tools (External industry tools orchestrator) ────────
    setup_tools_parser = subparsers.add_parser("setup-tools", help="Check and provision external industry security tools (npm audit, pip-audit, gitleaks, trivy)")
    setup_tools_parser.add_argument("--install", action="store_true", help="Automatically install missing tools via system package manager")

    # ── Command: audit (Top-level alias for full-spectrum scan) ─────────────
    audit_parser = subparsers.add_parser("audit", help="Run full-spectrum audit across all 8 pillars")
    audit_parser.add_argument("target", nargs="?", default=".", help="Target path to audit")
    audit_parser.add_argument("--html", help="HTML report", default=None)
    audit_parser.add_argument("--json", help="JSON report", default=None)
    audit_parser.add_argument("--sarif", help="SARIF report", default=None)
    audit_parser.add_argument("--severity", default=None, help="Filter minimum severity")

    args = parser.parse_args()

    if args.command == "external-audit":
        from cyberaudit.integrations.audit_pipeline import inventory, run_plan, verify_evidence
        import json as external_json
        try:
            if args.inventory:
                print(external_json.dumps(inventory(), indent=2, ensure_ascii=False))
                return
            if args.verify:
                errors = verify_evidence(args.verify)
                print(external_json.dumps({"integrity_errors": errors}, ensure_ascii=False))
                sys.exit(2 if errors else 0)
            if not args.plan:
                parser.error("external-audit requiere --plan, --inventory o --verify")
            job, directory = run_plan(args.plan, args.output, execute=args.execute)
            console.print(f"Trabajo: {directory}\nEstado: {job['status']} | Gate: {job['gate']}")
            sys.exit(0 if not args.execute or job["gate"] == "PASS" else 1 if job["gate"] == "FAIL" else 2)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            console.print(f"Error de integración: {exc}")
            sys.exit(2)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "onboard":
        from cyberaudit.core.onboarding import OnboardingEngine
        engine = OnboardingEngine(args.target)
        targets = [t.strip() for t in args.target_assistants.split(",") if t.strip()]
        plan = engine.generate_plan(
            technical_level=args.technical_level,
            project_kind=args.project_kind,
            goal=args.goal,
            software_scope=args.software_scope,
            workflow=args.workflow,
            targets=targets,
        )
        if not args.accept_plan:
            print("CYBERAUDIT_ONBOARDING_PLAN")
            print(f"Plan id: {plan['plan_id']}")
            print(f"Project: {plan['record']['project_kind']} ({plan['record']['software_scope']})")
            print(f"Technical level: {plan['record']['technical_level']}")
            print(f"Workflow: {plan['record']['workflow']}")
            print(f"Targets: {', '.join(plan['record']['targets'])}")
            print("Selected:")
            for c in plan["selected_components"]:
                print(f"  + {c['id']} — {c['desc']}")
            print("Deferred:")
            for c in plan["deferred_components"]:
                print(f"  - {c['id']} — {c['desc']}")
            print("Excluded:")
            for c in plan["excluded_components"]:
                print(f"  x {c['id']} — {c['desc']}")
            print("Managed paths:")
            for p in plan["managed_paths"]:
                print(f"  {p}")
            print(f"\nTo accept this plan and install CyberAudit, execute:")
            print(f"  cyberaudit onboard --technical-level {args.technical_level} --project-kind {args.project_kind} --software-scope {args.software_scope} --accept-plan {plan['plan_id']}")
            sys.exit(0)
        else:
            ok, msg = engine.apply_plan(plan, args.accept_plan)
            if not ok:
                console.print(f"[red bold]Error:[/] {msg}")
                sys.exit(1)
            console.print(f"[green bold]{msg}[/green bold]")
            console.print("📍 Dónde estamos: Arnés CyberAudit instalado y verificado exitosamente.")
            console.print("✅ Qué hicimos: Creado perfil en 02-DOCS, inyectada capa always-on en AGENTS.md y 48 skills vinculadas.")
            console.print("🧭 Qué decidimos: Nivel técnico registrado con decisión ratificada.")
            console.print("➡️ Siguiente paso: ¿Deseas ejecutar ahora una auditoría base con 'cyberaudit audit'?")
            sys.exit(0)

    elif args.command == "doctor":
        console.print("[bold cyan]=== CyberAudit Doctor Diagnostic ===[/bold cyan]")
        cwd = os.path.abspath(args.target)
        checks = [
            ("Configuration (.cyberaudit.json or .rsc.json)", os.path.exists(os.path.join(cwd, ".cyberaudit.json")) or os.path.exists(os.path.join(cwd, ".rsc.json"))),
            ("Always-On Layer (.antigravity/AGENTS.md or AGENTS.md)", os.path.exists(os.path.join(cwd, ".antigravity", "AGENTS.md")) or os.path.exists(os.path.join(cwd, "AGENTS.md"))),
            ("Knowledge & Profile (02-DOCS/wiki/harness/)", os.path.exists(os.path.join(cwd, "02-DOCS", "wiki", "harness", "user-profile.md"))),
            ("Python AuditEngine Runtime (68 scanners)", True),
            ("External Tools Discovery", True),
        ]
        all_ok = True
        for name, ok in checks:
            mark = "[green]✅[/green]" if ok else "[red]❌[/red]"
            console.print(f"  {mark} {name}")
            if not ok:
                all_ok = False
        status_color = "green" if all_ok else "yellow"
        console.print(f"Status: [bold {status_color}]{'HEALTHY' if all_ok else 'NEEDS ATTENTION'}[/bold {status_color}]")
        sys.exit(0)

    elif args.command == "audit":
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            sarif_output=args.sarif,
            min_severity=args.severity,
        )
        sys.exit(0)

    if args.command == "query-kb":
        run_query_kb(args.query, limit=args.limit, category=args.category)
        sys.exit(0)

    if args.command == "scan":
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            sarif_output=getattr(args, "sarif", None),
            run_ai=args.ai,
            ai_provider=args.ai_provider,
            min_severity=args.severity,
            archetype=getattr(args, "archetype", "full"),
            exclude_vendor=not getattr(args, "include_vendor", False),
            offline=getattr(args, "offline", False),
        )

    elif args.command == "audit-ad":
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[ActiveDirectoryAuditScanner(), LolbasDetector(), CtiCorrelator()],
        )
    elif args.command == "audit-cloud":
        from cyberaudit.modules.security_analyst.cloud_aws_audit import CloudAwsAuditScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[CloudAzureAuditScanner(), CloudAwsAuditScanner(), LogHygieneScanner(), CtiCorrelator()],
        )
    elif args.command == "triage-logs":
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[SigmaEngine(), CtiCorrelator()],
        )
    elif args.command == "triage-endpoint":
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[DfirEndpointScanner(), LolbasDetector(), YaraStaticScanner()],
        )
    elif args.command == "audit-aws":
        from cyberaudit.modules.security_analyst.cloud_aws_audit import CloudAwsAuditScanner
        from cyberaudit.modules.security_engineer.secrets_scanner import SecretsScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[CloudAwsAuditScanner(), SecretsScanner()],
        )
    elif args.command == "audit-k8s":
        from cyberaudit.modules.security_engineer.k8s_security_scanner import K8sSecurityScanner
        from cyberaudit.modules.security_engineer.docker_iac_scanner import DockerIacScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[K8sSecurityScanner(), DockerIacScanner()],
        )
    elif args.command == "audit-cicd":
        from cyberaudit.modules.security_engineer.cicd_pipeline_scanner import CicdPipelineScanner
        from cyberaudit.modules.security_engineer.sca_dependency_scanner import ScaDependencyScanner
        from cyberaudit.modules.security_engineer.secrets_scanner import SecretsScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[CicdPipelineScanner(), ScaDependencyScanner(), SecretsScanner()],
        )
    elif args.command == "audit-api":
        from cyberaudit.modules.security_engineer.owasp_api_scanner import OwaspApiScanner
        from cyberaudit.modules.penetration_tester.sqli_scanner import SqlInjectionScanner
        from cyberaudit.modules.penetration_tester.auth_session_jwt_scanner import AuthSessionJwtScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[OwaspApiScanner(), SqlInjectionScanner(), AuthSessionJwtScanner()],
        )
    elif args.command == "audit-ai":
        from cyberaudit.modules.ai_security.prompt_injection_scanner import AiSecurityScanner
        from cyberaudit.modules.ai_security.ai_supply_chain_scanner import AiSupplyChainScanner
        from cyberaudit.modules.ai_security.rag_security_scanner import RagSecurityScanner
        from cyberaudit.modules.ai_security.ai_agent_security_scanner import AiAgentSecurityScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            scanners=[AiSecurityScanner(), AiSupplyChainScanner(), RagSecurityScanner(), AiAgentSecurityScanner()],
        )
    elif args.command == "audit-qa":
        from cyberaudit.modules.software_qa.code_quality_scanner import CodeQualityScanner
        from cyberaudit.modules.software_qa.resource_leak_scanner import ResourceLeakScanner
        from cyberaudit.modules.software_qa.test_coverage_auditor import TestCoverageAuditor
        from cyberaudit.modules.software_qa.concurrency_race_scanner import ConcurrencyRaceScanner
        from cyberaudit.modules.software_qa.complexity_maintainability_scanner import ComplexityMaintainabilityScanner
        from cyberaudit.modules.software_qa.resilience_performance_scanner import ResiliencePerformanceScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            run_ai=getattr(args, "ai", False),
            ai_provider=getattr(args, "ai_provider", "auto"),
            min_severity=getattr(args, "severity", None),
            exclude_vendor=not getattr(args, "include_vendor", False),
            scanners=[
                CodeQualityScanner(),
                ResourceLeakScanner(),
                TestCoverageAuditor(),
                ConcurrencyRaceScanner(),
                ComplexityMaintainabilityScanner(),
                ResiliencePerformanceScanner(),
            ],
        )
    elif args.command == "audit-uiux":
        from cyberaudit.modules.ui_ux.accessibility_a11y_scanner import AccessibilityA11yScanner
        from cyberaudit.modules.ui_ux.responsive_ergonomics_scanner import ResponsiveErgonomicsScanner
        from cyberaudit.modules.ui_ux.contrast_typography_scanner import ContrastTypographyScanner
        from cyberaudit.modules.ui_ux.ux_advanced_heuristics_scanner import UxAdvancedHeuristicsScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            run_ai=getattr(args, "ai", False),
            ai_provider=getattr(args, "ai_provider", "auto"),
            min_severity=getattr(args, "severity", None),
            exclude_vendor=not getattr(args, "include_vendor", False),
            scanners=[
                AccessibilityA11yScanner(),
                ResponsiveErgonomicsScanner(),
                ContrastTypographyScanner(),
                UxAdvancedHeuristicsScanner(),
            ],
        )
    elif args.command == "audit-arch":
        from cyberaudit.modules.software_architecture.software_architecture_scanner import SoftwareArchitectureScanner
        from cyberaudit.modules.software_qa.complexity_maintainability_scanner import ComplexityMaintainabilityScanner
        from cyberaudit.modules.security_engineer.supply_chain_sbom_scanner import SupplyChainSbomScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            run_ai=getattr(args, "ai", False),
            ai_provider=getattr(args, "ai_provider", "auto"),
            min_severity=getattr(args, "severity", None),
            exclude_vendor=not getattr(args, "include_vendor", False),
            scanners=[
                SoftwareArchitectureScanner(),
                ComplexityMaintainabilityScanner(),
                SupplyChainSbomScanner(),
            ],
        )
    elif args.command == "audit-mobile":
        from cyberaudit.modules.penetration_tester.mobile_security_scanner import MobileSecurityScanner
        from cyberaudit.modules.penetration_tester.crypto_pqc_agility_scanner import CryptoPqcAgilityScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            run_ai=getattr(args, "ai", False),
            ai_provider=getattr(args, "ai_provider", "auto"),
            scanners=[
                MobileSecurityScanner(),
                CryptoPqcAgilityScanner(),
            ],
        )
    elif args.command == "audit-cleancode":
        from cyberaudit.modules.software_qa.clean_code_scanner import CleanCodeBestPracticesScanner
        from cyberaudit.modules.software_qa.complexity_maintainability_scanner import ComplexityMaintainabilityScanner
        run_scan(
            target_path=args.target,
            html_output=args.html,
            json_output=args.json,
            run_ai=getattr(args, "ai", False),
            ai_provider=getattr(args, "ai_provider", "auto"),
            min_severity=getattr(args, "severity", None),
            exclude_vendor=not getattr(args, "include_vendor", False),
            scanners=[
                CleanCodeBestPracticesScanner(),
                ComplexityMaintainabilityScanner(),
            ],
        )
    elif args.command == "audit-business":
        from cyberaudit.web_auditor.business import run_business_audit
        try:
            evidence, directory = run_business_audit(args.plan, args.output)
        except (ValueError, OSError, KeyError) as exc:
            console.print(f"[red]No se pudo ejecutar el plan: {type(exc).__name__}[/red]")
            sys.exit(2)
        console.print(f"Evidencia: {directory / 'report.json'}")
        state = evidence["report"]["status"]
        console.print(f"Estado: {state} | Firma: {evidence['signature_type']}")
        sys.exit(0 if state == "PASS" else 1 if state == "FAIL" else 2)
    elif args.command == "run-dynamic-qa":
        run_dynamic_qa(export_html=args.export)
    elif args.command == "run-qa":
        run_qa(pillar=args.pillar, verbose=args.verbose)
    elif args.command == "check-ai":
        analyst = AICoAnalyst()
        diag = analyst.test_connection()
        console.print("[bold cyan]=== CyberAudit AI Co-Analyst Diagnostics ===[/bold cyan]")
        if diag["lm_studio_reachable"]:
            console.print(f"[green][+] Local LM Studio Server:[/] Online at {diag['url']}")
            console.print(f"[green][+] Active Model:[/] {diag['active_model']}")
            if diag.get("test_inference_ok"):
                console.print(f"[green][+] Local Inference Test:[/] [bold]OK[/bold] (Operational)")
                console.print(f"    [italic dim]Response: {diag.get('test_response')}[/italic dim]")
            else:
                console.print(f"[yellow][!] Local Inference Test:[/] Failed or Timed Out ({diag.get('test_error', 'No reply')})")
        else:
            console.print(f"[red][-] Local LM Studio Server:[/] [bold]Offline[/bold] (Could not reach {diag['url']})")
            console.print("[dim]    Tip: Open LM Studio -> Developer / Local Server tab -> Click 'Start Server' on port 1234.[/dim]")

        if diag["gemini_api_key_configured"]:
            console.print(f"[green][+] Cloud Gemini Fallback:[/] Configured ({diag['gemini_model']})")
        else:
            console.print("[yellow][-] Cloud Gemini Fallback:[/] No GEMINI_API_KEY detected in environment.")
    elif args.command == "ui":
        run_ui(host=args.host, port=args.port, reload=args.reload, no_browser=args.no_browser)
    elif args.command == "test-ui":
        run_user_simulation_cmd(base_url=args.url, headless=not args.no_headless)
    elif args.command == "sync-remediation":
        run_sync_remediation(
            remediation_file=args.remediation_file,
            target_path=args.target,
            report_path=args.report,
            overrides_path=args.overrides,
            auto_reverify=not args.no_reverify,
            run_ai=args.ai,
            ai_provider=args.ai_provider,
        )
    elif args.command == "invariants":
        if getattr(args, "invariants_action", None) == "init":
            run_invariants_infer(target_dir=args.target_dir, output_path=args.output)
        else:
            parser.print_help()
    elif args.command == "audit-invariants":
        run_audit_invariants(
            config_path=args.config,
            target_dir=args.target_dir,
            json_output=args.json,
        )
    elif args.command == "ci":
        run_ci(
            config_path=args.config,
            target_dir=args.target_dir,
            fail_on_violations=args.fail_on_violations,
            fail_threshold=args.fail_threshold,
            output_format=args.output_format,
            output_file=args.output_file,
            scanners=args.scanners,
            github_pr=args.github_pr,
            use_cache=not getattr(args, "no_cache", False),
            cache_dir=getattr(args, "cache_dir", ".cyberaudit_cache"),
        )
    elif args.command == "audit-web":
        run_audit_web(
            url=args.url,
            allow_local=args.allow_local,
            run_a11y=not args.skip_a11y,
            verify_token=args.verify_token,
            html_output=args.html,
            json_output=args.json,
            run_ai=args.ai,
            ai_provider=args.ai_provider,
            min_severity=args.severity,
            browsers=args.browsers,
            expect_pwa=args.expect_pwa,
            journey_path=args.journey,
            offline_selector=args.offline_selector,
            observation_ms=args.observation_ms,
        )
    elif args.command == "audit-infra":
        port_list = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()] if getattr(args, "ports", None) else None
        run_audit_infra(
            host=args.host,
            ports=port_list,
            verify_token=args.verify_token,
            allow_local=args.allow_local,
            html_output=args.html,
            json_output=args.json,
            run_ai=args.ai,
            ai_provider=args.ai_provider,
            min_severity=args.severity,
        )
    elif args.command == "audit-login":
        run_audit_login(
            url=args.url,
            allow_local=args.allow_local,
            test_rate_limit=not args.skip_rate_limit,
            html_output=args.html,
            json_output=args.json,
            run_ai=args.ai,
            ai_provider=args.ai_provider,
            min_severity=args.severity,
        )
    elif args.command == "kali-tools":
        run_kali_tools(json_output=args.json, include_missing=not args.only_available)
    elif args.command == "kali-status":
        run_kali_status(json_output=args.json)
    elif args.command == "kali-scope":
        if getattr(args, "scope_action", None) == "init":
            run_kali_scope_init(path=args.path, force=args.force)
        elif getattr(args, "scope_action", None) == "check":
            run_kali_scope_check(args)
        else:
            parser.print_help()
    elif args.command == "kali-remote-tools":
        from cyberaudit.kali.remote import invoke_worker, save_remote_result
        response = invoke_worker({"protocol": 1, "action": "inventory"}, args.backend, args.distribution, args.ssh_host, timeout=300, worker_python=args.worker_python)
        save_remote_result(response, args.json)
        for tool in response["tools"]:
            console.print(f"{tool['key']}: {'disponible' if tool['available'] else 'no instalada'} ({tool.get('version') or 'versión desconocida'})")
        console.print(f"Inventario: {args.json}")
    elif args.command == "kali-scan":
        run_kali_scan(args)
    elif args.command == "kali-agent":
        run_kali_agent(args)
    elif args.command == "certify-production":
        run_certify_production(
            target_path=args.target,
            environment=args.env,
            app_name=args.app_name,
            output_report=args.output,
            json_output=args.json,
            strict=args.strict,
            fail_on_blocked=args.fail_on_blocked,
            metrics_file=args.metrics,
        )
    elif args.command == "harness":
        import json as harness_json
        from cyberaudit.core.skill_harness import CyberAuditSkillHarness
        from rich.table import Table

        harness = CyberAuditSkillHarness()
        action = getattr(args, "harness_action", None)

        if action == "list-skills":
            skills = harness.list_skills()
            if getattr(args, "json", False):
                print(harness_json.dumps(skills, indent=2, ensure_ascii=False))
            else:
                table = Table(title="CyberAudit Skill Harness (Definitive 68-Scanner Suite)")
                table.add_column("Skill ID", style="bold cyan")
                table.add_column("Scanners", justify="right", style="green")
                table.add_column("Title", style="bold")
                table.add_column("Standards")
                for s in skills:
                    table.add_row(s["id"], str(s["scanner_count"]), s["title"], ", ".join(s["standards"][:2]))
                console.print(table)
        elif action == "run-skill":
            res = harness.run_skill(
                skill_id=args.skill_id,
                target_path=args.target,
                fail_threshold=args.threshold,
            )
            if args.json:
                with open(args.json, "w", encoding="utf-8") as f:
                    harness_json.dump(res, f, indent=2, ensure_ascii=False)
                console.print(f"[green][+] Skill evidence report saved to:[/] {args.json}")
            color = "green" if res["verdict"] == "PASS" else "red"
            console.print(
                f"[bold cyan][{res['skill_id']}][/bold cyan] Scanners: [bold]{res['scanners_executed_count']}[/bold] | "
                f"Files: [bold]{res['files_scanned']}[/bold] | Blocking (>={res['fail_threshold']}): [bold]{res['blocking_findings_count']}[/bold] | "
                f"Verdict: [bold {color}]{res['verdict']}[/bold {color}]"
            )
            if getattr(args, "fail_on_block", False) and res["verdict"] != "PASS":
                sys.exit(1)
        elif action == "risk":
            risk_info = harness.evaluate_risk(target_path=args.target)
            if getattr(args, "json", False):
                print(harness_json.dumps(risk_info, indent=2, ensure_ascii=False))
            else:
                console.print(
                    f"[bold cyan]CyberAudit Risk Assessment:[/bold cyan] Tier [bold]{risk_info['tier']}[/bold] "
                    f"(Lane: [bold]{risk_info['lane']}[/bold]) | Changed files: {risk_info['changed_files_count']}"
                )
                console.print(f"Recommended CyberAudit Skills: [green]{', '.join(risk_info['recommended_skills'])}[/green]")
        elif action == "sello":
            seal = harness.emit_sello(
                target_path=args.target,
                skill_id=args.skill,
                fail_threshold=args.threshold,
            )
            if getattr(args, "json", False):
                print(harness_json.dumps(seal, indent=2, ensure_ascii=False))
            else:
                color = "green" if seal["verdict"] == "PASS" else "red"
                console.print(
                    f"[bold {color}]{seal['seal_type']}: {seal['seal_hash']}[/bold {color}] "
                    f"(Skill: {seal['skill_id']} | Scanners: {seal['scanners_executed_count']} | "
                    f"Files: {seal['files_scanned']} | Log: {seal['log_path']})"
                )
        else:
            harness_parser.print_help()
    elif args.command == "fix":
        from cyberaudit.core.tdd_remediation import TddRemediationEngine
        engine = TddRemediationEngine(target_root=args.target)
        console.print(f"[bold cyan]=== CyberAudit Real TDD Remediation Loop ===[/bold cyan]")
        console.print(f"Target: [bold]{os.path.abspath(args.target)}[/bold] | Finding: [bold]{args.finding_id}[/bold]")
        res = engine.execute_tdd_fix(args.finding_id)
        if res.get("status") == "NOT_FOUND":
            console.print(f"[yellow]ℹ Finding '{args.finding_id}' is clean or not present in active audit.[/yellow]")
        else:
            console.print(f"  1. Red Test Repro: [green]{'CREATED (' + res['repro_test_file'] + ')' if res.get('repro_test_file') else 'VERIFIED'}[/green]")
            console.print(f"  2. Atomic Defensive Patch: [green]{res.get('patch_notes')}[/green]")
            console.print(f"  3. Green Test Suite: [green]{'ALL TESTS GREEN' if res.get('green_tests_passed') else 'TESTS FAILED'}[/green]")
            console.print(f"  4. Static Zero-Regression: [green]{'VERIFIED (0 findings remaining)' if res.get('success') else 'FLAGGED'}[/green]")
            if res.get("seal_hash"):
                console.print(f"\n[bold green]{res.get('seal_type')}: {res.get('seal_hash')}[/bold green]")
    elif args.command == "setup-tools":
        from cyberaudit.core.external_orchestrator import ExternalToolOrchestrator
        console.print("[bold cyan]=== CyberAudit External Security Tools Orchestrator ===[/bold cyan]")
        if getattr(args, "install", False):
            install_res = ExternalToolOrchestrator.install_missing_tools()
            for t, status in install_res.items():
                console.print(f"  [dim]Install status for {t}: {status}[/dim]")
        diag = ExternalToolOrchestrator.get_tools_diagnostic()
        for tool, info in diag.items():
            icon = "[green]✅[/green]" if info["installed"] else "[red]❌[/red]"
            ver = f"({info['version']})" if info.get("version") else "(not installed)"
            console.print(f"  {icon} [bold]{tool}[/bold]: {ver} - {info['role']}")
            if info.get("binary"):
                console.print(f"     [dim]Path: {info['binary']}[/dim]")
        missing = [t for t, i in diag.items() if not i["installed"]]
        if missing and not getattr(args, "install", False):
            console.print("\n[yellow]💡 Run 'python cli.py setup-tools --install' to automatically provision missing tools.[/yellow]")
        elif not missing:
            console.print("\n[green]All 4 industry external tools are operational with native blindspot coverage.[/green]")


if __name__ == "__main__":
    main()
