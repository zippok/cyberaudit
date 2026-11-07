"""
CyberAudit Reporting Engine
Generates:
1. Terminal Summary (Rich tables, colored severity badges, MITRE matrix summary)
2. JSON Output (Structured machine-readable report)
3. Interactive Executive HTML Dashboard (Client-facing, modern responsive dark UI)
"""

import json
import os
import html
import glob
import re
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from cyberaudit.core.models import ScanReport, Severity, Finding


class Reporter:
    def __init__(self, report: ScanReport):
        self.report = report
        self.console = Console()

    def print_terminal_summary(self, min_severity: Optional[Severity] = None):
        """Prints a comprehensive, visually stunning report to the terminal using Rich."""
        console = self.console

        # Banner
        console.print(
            Panel(
                Text(
                    f"CYBERAUDIT SUITE - SECURITY AUDIT REPORT\nTarget: {self.report.target_path}",
                    justify="center",
                    style="bold cyan",
                ),
                subtitle=f"Scanned {self.report.files_scanned} files in {self.report.duration_seconds}s | {self.report.timestamp}",
                border_style="cyan",
            )
        )

        # Overview Table
        summary_table = Table(title="Audit Metrics Overview", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="dim", width=24)
        summary_table.add_column("Value", style="bold")

        summary_table.add_row("Total Files Scanned", str(self.report.files_scanned))
        summary_table.add_row("Execution status", self.report.execution_status)
        summary_table.add_row("Execution errors", str(len(self.report.execution_errors)))
        summary_table.add_row("Total Findings", str(self.report.total_findings))
        summary_table.add_row("Critical Findings", f"[red bold]{self.report.severity_counts.get('CRITICAL', 0)}[/]")
        summary_table.add_row("High Findings", f"[bright_red]{self.report.severity_counts.get('HIGH', 0)}[/]")
        summary_table.add_row("Medium Findings", f"[yellow]{self.report.severity_counts.get('MEDIUM', 0)}[/]")
        summary_table.add_row("Low Findings", f"[blue]{self.report.severity_counts.get('LOW', 0)}[/]")
        summary_table.add_row("Informational", f"[dim]{self.report.severity_counts.get('INFO', 0)}[/]")

        if self.report.ai_provider_used:
            summary_table.add_row("AI Co-Analyst Engine", f"[green]{self.report.ai_provider_used}[/]")

        console.print(summary_table)
        console.print()

        # Findings Detail Table
        findings_table = Table(title="Detected Security Vulnerabilities & Indicators", show_header=True, header_style="bold blue")
        findings_table.add_column("Severity", justify="center", width=10)
        findings_table.add_column("ID / Rule", style="dim", width=22)
        findings_table.add_column("Title & Description", width=38)
        findings_table.add_column("File & Line", style="cyan", width=26)
        findings_table.add_column("MITRE Tactic", style="magenta", width=18)

        min_rank = min_severity.rank if min_severity else 0

        filtered_findings = [f for f in self.report.findings if f.severity.rank >= min_rank]
        sorted_findings = sorted(filtered_findings, key=lambda x: x.severity.rank, reverse=True)

        for f in sorted_findings:
            sev_color = {
                "CRITICAL": "red bold",
                "HIGH": "bright_red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "dim",
            }.get(f.severity.value, "white")

            file_loc = os.path.basename(f.file_path)
            if f.line_number:
                file_loc += f":{f.line_number}"

            findings_table.add_row(
                f"[{sev_color}]{f.severity.value}[/]",
                f.id,
                f"[bold]{f.title}[/]\n[dim]{f.description[:100]}...[/dim]" if len(f.description) > 100 else f"[bold]{f.title}[/]\n[dim]{f.description}[/dim]",
                file_loc,
                f"{f.mitre_tactic or 'N/A'}\n[dim]({f.mitre_id or ''})[/dim]",
            )

        console.print(findings_table)
        console.print()

        # AI Co-Analyst Executive Summary
        if self.report.ai_verdict:
            console.print(
                Panel(
                    self.report.ai_verdict,
                    title=f"[bold green]AI Co-Analyst Debrief ({self.report.ai_provider_used})[/bold green]",
                    border_style="green",
                )
            )

    def export_json(self, output_file: str) -> str:
        """Exports full report data as formatted JSON."""
        output_file = os.path.abspath(output_file)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.report.to_dict(), f, indent=2)
        return output_file

    def export_sarif(self, output_file: str, base_dir: Optional[str] = None) -> str:
        """Exports full report data conforming to OASIS SARIF 2.1.0 standard (GitHub/GitLab compliant)."""
        from cyberaudit.core.sarif_exporter import export_sarif_file
        return export_sarif_file(self.report, output_file, base_dir=base_dir)

    def generate_html_content(self) -> str:
        """Render the report without filesystem side effects."""

        counts = self.report.severity_counts
        crit_count = counts.get("CRITICAL", 0)
        high_count = counts.get("HIGH", 0)
        med_count = counts.get("MEDIUM", 0)
        low_count = counts.get("LOW", 0)
        info_count = counts.get("INFO", 0)

        # Build Finding cards
        finding_cards = []
        for f in sorted(self.report.findings, key=lambda x: x.severity.rank, reverse=True):
            sev_badge_color = {
                "CRITICAL": "bg-red-500/20 text-red-400 border-red-500/30",
                "HIGH": "bg-orange-500/20 text-orange-400 border-orange-500/30",
                "MEDIUM": "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
                "LOW": "bg-blue-500/20 text-blue-400 border-blue-500/30",
                "INFO": "bg-slate-500/20 text-slate-400 border-slate-500/30",
            }.get(f.severity.value, "bg-gray-500/20 text-gray-400 border-gray-500/30")

            snippet_html = ""
            if f.code_snippet:
                snippet_html = f"""
                <div class="mt-3 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto">
                    <code>{html.escape(f.code_snippet)}</code>
                </div>
                """

            mitre_badge = ""
            if f.mitre_id:
                mitre_badge = f'<span class="px-2 py-0.5 text-xs rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">MITRE {html.escape(f.mitre_id)}: {html.escape(f.mitre_technique or "")}</span>'

            cve_badge = ""
            if f.cve_id:
                cve_badge = f'<span class="px-2 py-0.5 text-xs rounded bg-red-500/20 text-red-300 border border-red-500/30">{html.escape(f.cve_id)}</span>'

            stride_badge = ""
            if f.stride_category:
                stride_badge = f'<span class="px-2 py-0.5 text-xs rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">STRIDE: {html.escape(f.stride_category)}</span>'

            compliance_badges = ""
            if f.compliance_controls:
                for framework, control in f.compliance_controls.items():
                    compliance_badges += f'<span class="px-2 py-0.5 text-xs rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">{html.escape(framework)}: {html.escape(control)}</span> '

            card = f"""
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition duration-150 shadow-md">
                <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="px-2.5 py-1 text-xs font-bold rounded-full border {sev_badge_color}">{f.severity.value}</span>
                        <span class="font-mono text-xs text-slate-400">{html.escape(f.id)}</span>
                        {stride_badge}
                        {mitre_badge}
                        {cve_badge}
                    </div>
                    <span class="text-xs text-slate-400 font-mono">{html.escape(os.path.basename(f.file_path))}{f':{f.line_number}' if f.line_number else ''}</span>
                </div>
                <h4 class="text-lg font-semibold text-white mb-1">{html.escape(f.title)}</h4>
                <p class="text-sm text-slate-300 mb-3">{html.escape(f.description)}</p>
                {snippet_html}
                {f'<div class="mt-3 flex flex-wrap gap-1.5 items-center"><span class="text-xs text-slate-400">Compliance Mappings:</span> {compliance_badges}</div>' if compliance_badges else ''}
                <div class="mt-3 pt-3 border-t border-slate-800/80 flex items-start gap-2">
                    <span class="text-xs font-bold text-emerald-400 shrink-0">Remediation:</span>
                    <span class="text-xs text-slate-300">{html.escape(f.remediation or "Follow organizational security policy.")}</span>
                </div>
            </div>
            """
            finding_cards.append(card)

        # Build STRIDE breakdown pills
        stride_counts = self.report.stride_counts
        stride_pills = []
        stride_colors = {
            "Spoofing": "border-red-500/30 text-red-300 bg-red-950/30",
            "Tampering": "border-orange-500/30 text-orange-300 bg-orange-950/30",
            "Repudiation": "border-yellow-500/30 text-yellow-300 bg-yellow-950/30",
            "Information Disclosure": "border-blue-500/30 text-blue-300 bg-blue-950/30",
            "Denial of Service": "border-purple-500/30 text-purple-300 bg-purple-950/30",
            "Elevation of Privilege": "border-pink-500/30 text-pink-300 bg-pink-950/30",
        }
        for cat, cnt in stride_counts.items():
            if cnt > 0:
                col = stride_colors.get(cat, "border-slate-500/30 text-slate-300 bg-slate-900")
                stride_pills.append(f"""
                <div class="border rounded-xl p-3 {col}">
                    <div class="text-xs uppercase tracking-wider font-semibold opacity-80">{html.escape(cat)}</div>
                    <div class="text-2xl font-bold mt-1">{cnt}</div>
                </div>
                """)

        # AI Verdict HTML rendering
        ai_html_content = "<p class='text-slate-400 italic'>No AI debrief generated. Run scan with --ai to generate an executive synthesis.</p>"
        if self.report.ai_verdict:
            formatted_ai = html.escape(self.report.ai_verdict)
            formatted_ai = formatted_ai.replace("\n\n", "<br><br>").replace("\n", "<br>")
            formatted_ai = formatted_ai.replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>")
            ai_html_content = f"""
            <div class="prose prose-invert max-w-none text-sm text-slate-200 leading-relaxed font-sans">
                {formatted_ai}
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberAudit Suite - Enterprise Security Audit Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; }}
        code, pre {{ font-family: 'Fira Code', monospace; }}
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
    <aside role="status">Estado de ejecución: {html.escape(self.report.execution_status)}. Errores: {len(self.report.execution_errors)}. Un resultado incompleto no demuestra ausencia de vulnerabilidades.</aside>
    <!-- Header -->
    <header class="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
            <div class="flex items-center gap-3">
                <div class="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-cyan-500/20">
                    🛡️
                </div>
                <div>
                    <h1 class="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                        CyberAudit Suite <span class="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">v2.0 Enterprise</span>
                    </h1>
                    <p class="text-xs text-slate-400">Enterprise Cybersecurity, DevSecOps & AI Defenses Platform</p>
                </div>
            </div>
            <div class="flex items-center gap-4 text-xs font-mono text-slate-400">
                <div>Target: <span class="text-slate-200">{html.escape(self.report.target_path)}</span></div>
                <div>|</div>
                <div>{self.report.timestamp}</div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-8 space-y-8">
        <!-- Key Metrics Cards -->
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div class="bg-slate-900/80 border border-red-500/20 rounded-2xl p-5 shadow-lg">
                <div class="text-xs font-medium text-red-400 uppercase tracking-wider">Critical</div>
                <div class="text-3xl font-extrabold text-red-500 mt-1">{crit_count}</div>
                <div class="text-xs text-slate-400 mt-1">Requires instant response</div>
            </div>
            <div class="bg-slate-900/80 border border-orange-500/20 rounded-2xl p-5 shadow-lg">
                <div class="text-xs font-medium text-orange-400 uppercase tracking-wider">High</div>
                <div class="text-3xl font-extrabold text-orange-400 mt-1">{high_count}</div>
                <div class="text-xs text-slate-400 mt-1">Direct exploit exposure</div>
            </div>
            <div class="bg-slate-900/80 border border-yellow-500/20 rounded-2xl p-5 shadow-lg">
                <div class="text-xs font-medium text-yellow-400 uppercase tracking-wider">Medium</div>
                <div class="text-3xl font-extrabold text-yellow-400 mt-1">{med_count}</div>
                <div class="text-xs text-slate-400 mt-1">Hardening required</div>
            </div>
            <div class="bg-slate-900/80 border border-blue-500/20 rounded-2xl p-5 shadow-lg">
                <div class="text-xs font-medium text-blue-400 uppercase tracking-wider">Low & Info</div>
                <div class="text-3xl font-extrabold text-blue-400 mt-1">{low_count + info_count}</div>
                <div class="text-xs text-slate-400 mt-1">Best practices & hygiene</div>
            </div>
            <div class="bg-slate-900/80 border border-indigo-500/20 rounded-2xl p-5 shadow-lg col-span-2 md:col-span-1">
                <div class="text-xs font-medium text-indigo-400 uppercase tracking-wider">Files Scanned</div>
                <div class="text-3xl font-extrabold text-white mt-1">{self.report.files_scanned}</div>
                <div class="text-xs text-slate-400 mt-1">{self.report.duration_seconds}s execution</div>
            </div>
        </div>

        <!-- STRIDE Threat Modeling Overview -->
        {f'''
        <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <h3 class="text-base font-bold text-white mb-3 flex items-center gap-2">
                <span>🎯</span> STRIDE Threat Modeling Breakdown
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-6 gap-3">
                {"".join(stride_pills)}
            </div>
        </div>
        ''' if stride_pills else ''}

        <!-- AI Executive Briefing -->
        <div class="bg-gradient-to-br from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-500/30 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center gap-2">
                    <span class="text-lg">🤖</span>
                    <h3 class="text-base font-bold text-indigo-200">AI Co-Analyst Executive Advisory</h3>
                    <span class="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">
                        {html.escape(self.report.ai_provider_used or "Local Heuristic Mode")}
                    </span>
                </div>
            </div>
            {ai_html_content}
        </div>

        <!-- Findings List -->
        <div>
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold text-white flex items-center gap-2">
                    Security Findings <span class="text-sm font-normal text-slate-400">({self.report.total_findings} items)</span>
                </h3>
            </div>
            <div class="space-y-4">
                {''.join(finding_cards) if finding_cards else '<div class="p-8 text-center bg-slate-900 rounded-xl border border-slate-800 text-slate-400">No vulnerabilities detected matching current criteria.</div>'}
            </div>
        </div>
    </main>

    <footer class="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        Generated by CyberAudit Suite &bull; Confidential Client Security Assessment &bull; All Rights Reserved
    </footer>
</body>
</html>
"""
        return html_template

    def export_html(self, output_file: str) -> str:
        output_file = os.path.abspath(output_file)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(self.generate_html_content())
        return output_file

    def export_markdown(self, output_file: str, audit_number: int = 1) -> str:
        """Exports full comprehensive audit report as structured Markdown."""
        output_file = os.path.abspath(output_file)
        md_content = generate_markdown_audit_report(self.report, audit_number=audit_number)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        return output_file


def generate_markdown_audit_report(report: ScanReport, audit_number: int = 1) -> str:
    """
    Generates a comprehensive, professional Markdown report covering all audit pillars:
    Security (AppSec, DevSecOps, Cloud, DFIR, AI), Software QA, Code Quality, UI/UX, and Architecture.
    """
    target = report.target_path
    timestamp = report.timestamp
    duration = f"{report.duration_seconds:.2f}s"
    files_scanned = report.files_scanned
    total_findings = report.total_findings

    # Status counts
    status_counts = report.status_counts if hasattr(report, "status_counts") else {}
    open_cnt = status_counts.get("OPEN", 0)
    resolved_cnt = status_counts.get("RESOLVED", 0)
    as_designed_cnt = status_counts.get("AS_DESIGNED", 0)

    # Active severities
    active_sev = report.active_severity_counts if hasattr(report, "active_severity_counts") else report.severity_counts
    crit_cnt = active_sev.get("CRITICAL", 0)
    high_cnt = active_sev.get("HIGH", 0)
    med_cnt = active_sev.get("MEDIUM", 0)
    low_cnt = active_sev.get("LOW", 0)
    info_cnt = active_sev.get("INFO", 0)

    # Risk Score: Critical (25 pts) & High (10 pts) drive severe risk.
    # Medium (QA/clean code) is capped when there are no Critical or High vulnerabilities.
    crit_contrib = crit_cnt * 25
    high_contrib = high_cnt * 10
    med_contrib = min(35, med_cnt * 1) if (crit_cnt == 0 and high_cnt == 0) else min(35, med_cnt * 2)
    risk_score = min(100, crit_contrib + high_contrib + med_contrib)
    if crit_cnt > 0:
        posture = "CRÍTICO (Acción Inmediata Requerida)"
    elif high_cnt > 0 or risk_score >= 60:
        posture = "ELEVADO (Atención en Sprint Activo)"
    elif risk_score >= 20:
        posture = "MODERADO (Deuda Técnica Controlada / QA)"
    else:
        posture = "BAJO / SALUDABLE"

    lines = []
    lines.append(f"# 🛡️ Informe Integral de Auditoría de Software — CyberAudit Suite Enterprise")
    lines.append(f"**Auditoría N.º:** #{audit_number:03d} | **Fecha:** {timestamp} | **Objetivo:** `{target}`\n")
    lines.append("---")
    lines.append("## 1. Resumen Ejecutivo y Métricas Globales\n")
    lines.append(f"- **Estado de ejecución:** {report.execution_status}; errores: {len(report.execution_errors)}")
    if report.execution_status != "PASS":
        lines.append("- **Auditoría incompleta o sin estado verificado: no permite concluir que el software sea seguro.**")
    lines.append(f"- **Indicador heurístico de hallazgos (no es CVSS ni certificación):** **{risk_score}/100** — *{posture}*")
    lines.append(f"- **Archivos Auditados:** {files_scanned} archivos en {duration}")
    lines.append(f"- **Herramientas y Módulos Ejecutados:** {len(report.scanners_executed)} scanners automatizados")
    lines.append(f"- **Total de Hallazgos Históricos:** {total_findings}\n")

    lines.append("### Estado de Triage y Subsanación")
    lines.append("| Estado | Cantidad | Significado |")
    lines.append("|---|---|---|")
    lines.append(f"| 🔴 **Pendientes (OPEN)** | **{open_cnt}** | Vulnerabilidades y observaciones activas que requieren corrección |")
    lines.append(f"| 🟢 **Subsanados (RESOLVED)** | **{resolved_cnt}** | Hallazgos corregidos en el código y validados mediante re-test |")
    lines.append(f"| 🟣 **Por Diseño (AS_DESIGNED)** | **{as_designed_cnt}** | Comportamientos aceptados formalmente por el equipo |")
    lines.append("")

    lines.append("### Severidades Activas (Solo Pendientes)")
    lines.append(f"| Crítico | Alto | Medio | Bajo | Info |")
    lines.append(f"|---|---|---|---|---|")
    lines.append(f"| 🔴 {crit_cnt} | 🟠 {high_cnt} | 🟡 {med_cnt} | 🔵 {low_cnt} | ⚪ {info_cnt} |")
    lines.append("")

    # Pillars table
    lines.append("### Desglose por Pilares y Áreas de Evaluación")
    lines.append("| Pilar de Evaluación | Hallazgos Registrados |")
    lines.append("|---|---|")
    for pillar_name, count in (report.pillar_counts or {}).items():
        lines.append(f"| {pillar_name} | {count} |")
    lines.append("")

    # AI Co-Analyst verdict
    if report.executive_summary or report.ai_verdict:
        lines.append("## 2. Dictamen del AI Co-Analyst Studio\n")
        provider = report.ai_provider_used or "Motor Heurístico Local"
        lines.append(f"> **Proveedor de Análisis:** {provider}\n")
        lines.append(report.executive_summary or report.ai_verdict or "")
        lines.append("\n---\n")

    # Detailed Findings by Pillar
    lines.append("## 3. Catálogo Exhaustivo de Hallazgos por Herramienta y Pilar\n")

    if not report.findings:
        lines.append("*No se detectaron vulnerabilidades ni observaciones en el software auditado.*")
    else:
        # Group by pillar
        findings_by_pillar: Dict[str, List[Finding]] = {}
        for f in report.findings:
            p_val = f.pillar.value if hasattr(f.pillar, "value") else str(f.pillar)
            if p_val not in findings_by_pillar:
                findings_by_pillar[p_val] = []
            findings_by_pillar[p_val].append(f)

        for pillar_name, p_findings in findings_by_pillar.items():
            lines.append(f"### 📌 Pilar: {pillar_name} ({len(p_findings)} hallazgos)\n")

            # Sort by rank desc
            sorted_f = sorted(p_findings, key=lambda x: x.severity.rank if hasattr(x.severity, "rank") else 0, reverse=True)
            for f in sorted_f:
                st = getattr(f, "status", "OPEN") or "OPEN"
                status_badge = "🔴 [PENDIENTE]" if st == "OPEN" else "🟢 [SUBSANADO / VERIFICADO]" if st == "RESOLVED" else "🟣 [POR DISEÑO]"
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)

                lines.append(f"#### {status_badge} [{sev_val}] {f.title}")
                lines.append(f"- **ID:** `{f.id}` | **Herramienta:** `{f.scanner_name}`")
                loc = f"`{f.file_path}`"
                if f.line_number:
                    loc += f" (Línea {f.line_number})"
                lines.append(f"- **Ubicación:** {loc}")
                if f.cwe_id:
                    lines.append(f"- **CWE:** `{f.cwe_id}`")
                if f.mitre_id:
                    lines.append(f"- **MITRE ATT&CK:** `{f.mitre_id}` — *{f.mitre_technique or 'Técnica General'}* ({f.mitre_tactic or 'Táctica'})")
                if f.stride_category:
                    lines.append(f"- **STRIDE:** `{f.stride_category}`")

                lines.append(f"\n**Descripción:**\n{f.description}\n")

                if f.code_snippet:
                    lines.append("**Fragmento de Código Detectado:**")
                    lines.append("```")
                    lines.append(f.code_snippet.strip())
                    lines.append("```\n")

                if f.remediation:
                    lines.append(f"**Remediación Sugerida:**\n{f.remediation}\n")

                if getattr(f, "status_comment", None):
                    lines.append(f"> 📝 **Nota de Triage / Re-test:** {f.status_comment} *(Fecha: {getattr(f, 'status_updated_at', '') or 'N/A'})*\n")

                lines.append("---\n")

    lines.append("## 4. Herramientas y Scanners Ejecutados en Esta Auditoría\n")
    for s_name in (report.scanners_executed or []):
        lines.append(f"- [x] {s_name}")
    lines.append("\n---\n")
    lines.append(f"*Informe generado automáticamente por CyberAudit Suite v2.0 Enterprise. Confidencial.*")

    return "\n".join(lines)


def save_markdown_audit_report(
    report: ScanReport,
    target_dir: str,
    audit_number: Optional[int] = None,
) -> Tuple[str, int]:
    """
    Saves a comprehensive Markdown audit report directly into the root of the audited software.
    File format: Auditoria_<numero>_<YYYY-MM-DD>.md (e.g. Auditoria_001_2026-09-18.md).
    If audit_number is not supplied, auto-increments based on existing files in target_dir.
    """
    target_dir = os.path.abspath(target_dir)
    if os.path.isfile(target_dir):
        target_dir = os.path.dirname(target_dir)

    os.makedirs(target_dir, exist_ok=True)

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if audit_number is None:
        # Find existing Auditoria_*_*.md in target_dir to find next sequential number
        existing_files = glob.glob(os.path.join(target_dir, "Auditoria_*_*.md"))
        max_num = 0
        for f in existing_files:
            fname = os.path.basename(f)
            m = re.match(r"^Auditoria_(\d+)_\d{4}-\d{2}-\d{2}\.md$", fname, re.IGNORECASE)
            if m:
                try:
                    num = int(m.group(1))
                    if num > max_num:
                        max_num = num
                except ValueError:
                    pass
        audit_number = max_num + 1 if max_num > 0 else 1

    filename = f"Auditoria_{audit_number:03d}_{today_str}.md"
    file_path = os.path.join(target_dir, filename)

    content = generate_markdown_audit_report(report, audit_number=audit_number)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    return file_path, audit_number
