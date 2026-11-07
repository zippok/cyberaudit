"""
CyberAudit Kali Evidence Reporter
Renders the outcome of a Kali engagement as auditor-facing artifacts:

- ``export_kali_json``     → complete machine-readable bundle (plan, coverage, runs,
  observations, findings, agent trace, scope authorization).
- ``export_kali_html``     → self-contained evidence report (coverage, executed commands,
  findings with raw evidence, agent decision trace).
- ``export_kali_markdown`` → Markdown dossier for the engagement file.

The interactive platform dashboard (``Reporter.export_html``) remains the canonical view
for the findings themselves; this module adds the offensive-tooling evidence that the
dashboard does not carry (commands, tool versions, coverage, authorizations).
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cyberaudit.core.models import Severity
from cyberaudit.kali.orchestrator import KaliAuditResult

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_STATUS_BADGE = {
    "executed": ("#16a34a", "EJECUTADA"),
    "planned": ("#0891b2", "PLANIFICADA"),
    "skipped": ("#ca8a04", "OMITIDA"),
    "failed": ("#dc2626", "FALLIDA"),
    "blocked": ("#9333ea", "BLOQUEADA"),
}


def _write(path: str, content: str) -> str:
    resolved = os.path.realpath(os.path.expanduser(path))
    parent = os.path.dirname(resolved)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(resolved, "w", encoding="utf-8") as handle:
        handle.write(content)
    return resolved


def export_kali_json(result: KaliAuditResult, path: str) -> str:
    """Writes the full engagement bundle (plan, coverage, evidence, findings)."""
    return _write(path, json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


def _severity_summary(result: KaliAuditResult) -> Dict[str, int]:
    counts = {severity.value: 0 for severity in _SEVERITY_ORDER}
    for finding in result.report.findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def render_kali_markdown(result: KaliAuditResult) -> str:
    """Markdown dossier: scope, coverage, findings with evidence and agent trace."""
    counts = _severity_summary(result)
    authorization = result.scope_authorization or {}
    lines: List[str] = [
        f"# Auditoría Kali · {result.target}",
        "",
        f"- **Perfil:** `{result.profile}`",
        f"- **Inicio:** {result.started_at}",
        f"- **Fin:** {result.finished_at} ({result.duration_seconds}s)",
        f"- **Modo:** {'SIMULACIÓN (sin ejecución)' if result.dry_run else 'ejecución real'}",
        f"- **Engagement:** {authorization.get('engagement_id') or 'n/d'} · Cliente: {authorization.get('client') or 'n/d'}",
        f"- **Autorización:** regla `{authorization.get('matched_rule') or 'n/d'}` · riesgo máximo `{authorization.get('risk') or 'n/d'}`",
        f"- **Evidencias:** `{result.artifacts_dir}`",
        f"- **Audit trail (JSONL):** `{result.audit_trail_path}`",
        "",
        "## Resumen de hallazgos",
        "",
        "| Severidad | Cantidad |",
        "| --- | --- |",
    ]
    lines.extend(f"| {severity} | {counts.get(severity, 0)} |" for severity in [s.value for s in _SEVERITY_ORDER])
    lines.extend(["", "## Cobertura de herramientas", "", "| Herramienta | Estado | Riesgo | Hallazgos | Comando / motivo |", "| --- | --- | --- | --- | --- |"])
    for entry in result.coverage:
        detail = (entry.reason or entry.command or "").replace("|", "\\|")
        lines.append(f"| {entry.tool_key} | {entry.status} | {entry.risk} | {entry.findings} | {detail[:220]} |")

    if result.agent_trace:
        lines.extend(["", "## Traza de decisiones del agente autónomo", "", "| Paso | Planificador | Acción | Herramienta | Estado | Motivo |", "| --- | --- | --- | --- | --- | --- |"])
        for entry in result.agent_trace:
            lines.append(
                f"| {entry.get('step', '')} | {entry.get('planner', '')} | {entry.get('action', '')} | "
                f"{entry.get('tool', '')} | {entry.get('status', '')} | "
                f"{str(entry.get('rationale', '')).replace('|', chr(92) + '|')[:200]} |"
            )

    if result.report.findings:
        lines.extend(["", "## Hallazgos detallados"])
        for index, finding in enumerate(
            sorted(result.report.findings, key=lambda f: f.severity.rank, reverse=True), start=1
        ):
            lines.extend([
                "",
                f"### {index}. [{finding.severity.value}] {finding.title}",
                "",
                f"- **ID:** `{finding.id}`",
                f"- **Herramienta:** `{finding.scanner_name}`",
                f"- **Ubicación:** `{finding.file_path}`",
                f"- **STRIDE:** {finding.stride_category or 'n/d'}",
                f"- **CWE:** {finding.cwe_id or 'n/d'} · **CVE:** {finding.cve_id or 'n/d'}",
                f"- **MITRE ATT&CK:** {finding.mitre_id or 'n/d'} ({finding.mitre_tactic or 'n/d'} — {finding.mitre_technique or 'n/d'})",
                "",
                f"**Descripción.** {finding.description}",
                "",
                "**Evidencia recogida:**",
                "",
                "```",
                (finding.code_snippet or "sin evidencia adjunta").strip(),
                "```",
                "",
                f"**Remediación recomendada.** {finding.remediation or 'n/d'}",
            ])
            if finding.compliance_controls:
                controls = "; ".join(f"{key}: {value}" for key, value in finding.compliance_controls.items())
                lines.append(f"\n**Cumplimiento.** {controls}")
    else:
        lines.extend(["", "## Hallazgos detallados", "", "Sin hallazgos: la superficie evaluada no presentó evidencias de vulnerabilidad en las comprobaciones ejecutadas."])

    if result.ai_summary:
        lines.extend(["", "## Síntesis ejecutiva (modelo local)", "", result.ai_summary])

    lines.extend(["", "---", f"_Generado por CyberAudit Suite · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_", ""])
    return "\n".join(lines)


def export_kali_markdown(result: KaliAuditResult, path: str) -> str:
    return _write(path, render_kali_markdown(result))


def _badge(status: str) -> str:
    color, label = _STATUS_BADGE.get(status, ("#6b7280", status.upper()))
    return f'<span class="badge" style="background:{color}">{html.escape(label)}</span>'


def export_kali_html(result: KaliAuditResult, path: str) -> str:
    """Writes a self-contained evidence report (HTML) for the engagement."""
    counts = _severity_summary(result)
    authorization = result.scope_authorization or {}
    severity_color = {severity.value: severity.color for severity in _SEVERITY_ORDER}

    coverage_rows = []
    for entry in result.coverage:
        detail = entry.reason or entry.command or ""
        if entry.status == "skipped" and entry.install_hint:
            detail = f"{detail} — {entry.install_hint}"
        coverage_rows.append(
            "<tr>"
            f"<td><strong>{html.escape(entry.tool_key)}</strong><div class='muted'>{html.escape(entry.tool_title)}</div></td>"
            f"<td>{_badge(entry.status)}</td>"
            f"<td>{html.escape(entry.risk or '-')}</td>"
            f"<td class='num'>{entry.findings}</td>"
            f"<td class='mono small'>{html.escape(detail[:600])}</td>"
            "</tr>"
        )

    command_rows = []
    for run in result.runs:
        if not run.argv:
            continue
        output_path = run.stdout_path or ""
        command_rows.append(
            "<tr>"
            f"<td>{html.escape(run.tool_key)}</td>"
            f"<td class='mono small'>{html.escape(run.command_line)[:900]}</td>"
            f"<td class='num'>{run.returncode}</td>"
            f"<td class='num'>{run.duration_ms / 1000:.1f}s</td>"
            f"<td class='mono small'>{html.escape(os.path.basename(output_path)) if output_path else '-'}</td>"
            "</tr>"
        )

    trace_rows = []
    for entry in result.agent_trace:
        trace_rows.append(
            "<tr>"
            f"<td class='num'>{entry.get('step', '')}</td>"
            f"<td>{html.escape(str(entry.get('planner', '')))}</td>"
            f"<td>{html.escape(str(entry.get('action', '')))}</td>"
            f"<td>{html.escape(str(entry.get('tool') or '-'))}</td>"
            f"<td>{html.escape(str(entry.get('status', '')))}</td>"
            f"<td class='small'>{html.escape(str(entry.get('rationale', ''))[:400])}</td>"
            "</tr>"
        )

    finding_cards = []
    for finding in sorted(result.report.findings, key=lambda f: f.severity.rank, reverse=True):
        color = severity_color.get(finding.severity.value, "#999")
        controls = " · ".join(f"{k}: {v}" for k, v in (finding.compliance_controls or {}).items())
        finding_cards.append(
            f"""
            <article class="finding" style="border-left:4px solid {color}">
              <header>
                <span class="sev" style="background:{color}">{html.escape(finding.severity.value)}</span>
                <h3>{html.escape(finding.title)}</h3>
              </header>
              <p class="muted mono small">
                {html.escape(finding.id)} · {html.escape(finding.scanner_name)} · {html.escape(finding.file_path)}
                {'· CVE ' + html.escape(finding.cve_id) if finding.cve_id else ''}
                {'· CWE ' + html.escape(finding.cwe_id) if finding.cwe_id else ''}
              </p>
              <p>{html.escape(finding.description)}</p>
              <details><summary>Evidencia</summary><pre>{html.escape((finding.code_snippet or 'sin evidencia').strip())}</pre></details>
              <p><strong>Remediación:</strong> {html.escape(finding.remediation or 'n/d')}</p>
              {'<p class="muted small">' + html.escape(controls) + '</p>' if controls else ''}
            </article>
            """
        )

    summary_cards = "".join(
        f'<div class="kpi" style="border-color:{severity_color[s.value]}">'
        f'<span class="kpi-value" style="color:{severity_color[s.value]}">{counts.get(s.value, 0)}</span>'
        f'<span class="kpi-label">{s.value}</span></div>'
        for s in _SEVERITY_ORDER
    )
    executed = len([entry for entry in result.coverage if entry.status == "executed"])

    document = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Auditoría Kali · {html.escape(result.target)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:32px; background:#0b1220; color:#e5e7eb;
         font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }}
  h1,h2,h3 {{ margin:0 0 12px; line-height:1.25; }}
  h1 {{ font-size:26px; }}
  h2 {{ font-size:19px; margin-top:36px; border-bottom:1px solid #1f2937; padding-bottom:8px; }}
  a {{ color:#22d3ee; }}
  .muted {{ color:#94a3b8; }}
  .small {{ font-size:12px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin:20px 0; }}
  .meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:8px 24px;
           background:#111a2e; border:1px solid #1f2937; border-radius:12px; padding:16px 20px; }}
  .kpi {{ background:#111a2e; border:1px solid #1f2937; border-left-width:4px; border-radius:12px; padding:14px 18px; }}
  .kpi-value {{ display:block; font-size:26px; font-weight:700; }}
  .kpi-label {{ font-size:12px; letter-spacing:.08em; color:#94a3b8; }}
  table {{ width:100%; border-collapse:collapse; background:#111a2e; border-radius:12px; overflow:hidden; }}
  th,td {{ padding:9px 12px; border-bottom:1px solid #1f2937; text-align:left; vertical-align:top; font-size:13px; }}
  th {{ background:#16213a; font-size:11px; letter-spacing:.06em; text-transform:uppercase; color:#cbd5e1; }}
  td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .badge {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:10.5px;
            font-weight:700; letter-spacing:.05em; color:#0b1220; }}
  .finding {{ background:#111a2e; border-radius:12px; padding:16px 18px; margin:12px 0; }}
  .finding header {{ display:flex; align-items:center; gap:10px; }}
  .finding h3 {{ font-size:15px; margin:0; }}
  .sev {{ padding:2px 8px; border-radius:6px; font-size:10.5px; font-weight:700; color:#0b1220; }}
  pre {{ background:#0b1220; border:1px solid #1f2937; border-radius:8px; padding:10px;
         white-space:pre-wrap; word-break:break-word; font-size:12px; max-height:340px; overflow:auto; }}
  details summary {{ cursor:pointer; color:#22d3ee; font-size:12.5px; }}
  footer {{ margin-top:40px; color:#64748b; font-size:12px; }}
</style>
</head>
<body>
  <h1>Auditoría de seguridad con herramientas Kali</h1>
  <p class="muted">Objetivo: <strong>{html.escape(result.target)}</strong> · perfil <strong>{html.escape(result.profile)}</strong>
     · {'simulación (dry-run)' if result.dry_run else 'ejecución real'}</p>

  <div class="grid">{summary_cards}</div>

  <div class="meta">
    <div><span class="muted">Inicio:</span> {html.escape(result.started_at)}</div>
    <div><span class="muted">Duración:</span> {result.duration_seconds}s</div>
    <div><span class="muted">Herramientas ejecutadas:</span> {executed} / {len(result.coverage)}</div>
    <div><span class="muted">Engagement:</span> {html.escape(str(authorization.get('engagement_id') or 'n/d'))}</div>
    <div><span class="muted">Cliente:</span> {html.escape(str(authorization.get('client') or 'n/d'))}</div>
    <div><span class="muted">Regla de autorización:</span> <span class="mono">{html.escape(str(authorization.get('matched_rule') or 'n/d'))}</span></div>
    <div><span class="muted">Evidencias:</span> <span class="mono small">{html.escape(result.artifacts_dir)}</span></div>
    <div><span class="muted">Audit trail:</span> <span class="mono small">{html.escape(result.audit_trail_path)}</span></div>
  </div>

  <h2>Cobertura de herramientas</h2>
  <table><thead><tr><th>Herramienta</th><th>Estado</th><th>Riesgo</th><th>Hallazgos</th><th>Comando / motivo</th></tr></thead>
  <tbody>{''.join(coverage_rows) or '<tr><td colspan="5" class="muted">Sin entradas de cobertura.</td></tr>'}</tbody></table>

  <h2>Comandos ejecutados (evidencia)</h2>
  <table><thead><tr><th>Herramienta</th><th>Comando</th><th>RC</th><th>Duración</th><th>Salida</th></tr></thead>
  <tbody>{''.join(command_rows) or '<tr><td colspan="5" class="muted">Ninguna herramienta llegó a ejecutarse.</td></tr>'}</tbody></table>

  {('<h2>Traza de decisiones del agente autónomo</h2><table><thead><tr><th>Paso</th><th>Planificador</th><th>Acción</th><th>Herramienta</th><th>Estado</th><th>Motivo</th></tr></thead><tbody>' + ''.join(trace_rows) + '</tbody></table>') if trace_rows else ''}

  <h2>Hallazgos</h2>
  {''.join(finding_cards) or '<p class="muted">Sin hallazgos en las comprobaciones ejecutadas.</p>'}

  {('<h2>Síntesis ejecutiva (modelo local)</h2><pre>' + html.escape(result.ai_summary) + '</pre>') if result.ai_summary else ''}

  <footer>Generado por CyberAudit Suite · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} ·
  auditoría sujeta al alcance autorizado del engagement.</footer>
</body>
</html>
"""
    return _write(path, document)


__all__ = [
    "export_kali_json",
    "export_kali_html",
    "export_kali_markdown",
    "render_kali_markdown",
]
