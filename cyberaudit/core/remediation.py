"""
CyberAudit Core Remediation Engine
Bridges the communication gap between Security Auditors and Software Developers.
Parses remediation response Markdown files (.md), matches declared fixes against
active audit findings, executes targeted automated re-verification on disk,
updates platform triage states/overrides, and generates auditor feedback debriefs.
"""

import os
import re
import glob
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from cyberaudit.core.models import ScanReport, Finding, Severity, Pillar
from cyberaudit.core.reverifier import AuditReverifier
from cyberaudit.core.reporter import generate_markdown_audit_report, save_markdown_audit_report

logger = logging.getLogger("cyberaudit.core.remediation")


@dataclass
class RemediationItem:
    """Represents an individual remediation item reported by the developer or auditor."""
    finding_id: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    status: str = "RESOLVED"  # RESOLVED, AS_DESIGNED, OPEN
    developer_comment: str = ""
    verified_on_disk: Optional[bool] = None
    verification_message: Optional[str] = None
    original_finding_title: Optional[str] = None
    severity: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "status": self.status,
            "developer_comment": self.developer_comment,
            "verified_on_disk": self.verified_on_disk,
            "verification_message": self.verification_message,
            "original_finding_title": self.original_finding_title,
            "severity": self.severity,
        }


class MarkdownRemediationParser:
    """
    Parses developer remediation response documents in various standard Markdown formats:
    1. Annotated/Modified Auditoria_*.md reports (with [SUBSANADO] or [POR DISEÑO] badges and notes)
    2. Structured Markdown Tables (| ID | Archivo | Estado | Explicación |)
    3. Markdown Checklist items (- [x] `ID`: Subsanado / Comentario)
    4. Markdown Section Headers (### [SUBSANADO] ID ...)
    """

    STATUS_MAP = {
        "subsanado": "RESOLVED",
        "subsanada": "RESOLVED",
        "resuelto": "RESOLVED",
        "resuelta": "RESOLVED",
        "solucionado": "RESOLVED",
        "solucionada": "RESOLVED",
        "corregido": "RESOLVED",
        "corregida": "RESOLVED",
        "resolved": "RESOLVED",
        "fixed": "RESOLVED",
        "por diseño": "AS_DESIGNED",
        "por diseno": "AS_DESIGNED",
        "as designed": "AS_DESIGNED",
        "as_designed": "AS_DESIGNED",
        "aceptado": "AS_DESIGNED",
        "aceptada": "AS_DESIGNED",
        "falso positivo": "AS_DESIGNED",
        "false positive": "AS_DESIGNED",
        "pendiente": "OPEN",
        "abierto": "OPEN",
        "open": "OPEN",
        "reabierto": "OPEN",
        "reopened": "OPEN",
    }

    @classmethod
    def normalize_status(cls, raw_status: str) -> str:
        s = raw_status.strip().lower()
        if s in cls.STATUS_MAP:
            return cls.STATUS_MAP[s]
        for k, v in cls.STATUS_MAP.items():
            if k in s:
                return v
        return "RESOLVED"

    def parse_markdown(self, content: str) -> List[RemediationItem]:
        """Parses markdown content and extracts a list of RemediationItem objects."""
        items: List[RemediationItem] = []
        seen_keys = set()

        def _add_item(item: RemediationItem):
            norm_p = (item.file_path or "").replace("\\", "/").lower()
            key = f"{item.finding_id}|{norm_p}|{item.line_number or ''}"
            if key not in seen_keys:
                seen_keys.add(key)
                items.append(item)

        # 1. Format: Annotated Auditoria_*.md report
        annotated_items = self._parse_annotated_audit_report(content)
        for it in annotated_items:
            _add_item(it)

        # 2. Format: Markdown Tables
        table_items = self._parse_markdown_tables(content)
        for it in table_items:
            _add_item(it)

        # 3. Format: Section Headers (### [SUBSANADO] ...)
        section_items = self._parse_section_headers(content)
        for it in section_items:
            _add_item(it)

        # 4. Format: Checklists (- [x] `ID`: ...)
        checklist_items = self._parse_checklists(content)
        for it in checklist_items:
            _add_item(it)

        return items

    def _parse_annotated_audit_report(self, content: str) -> List[RemediationItem]:
        """
        Parses findings from an edited Auditoria_*.md where status headers or notes have been modified:
        e.g.:
        #### 🟢 [SUBSANADO / VERIFICADO] [HIGH] SQL Injection in auth/login.py
        - **ID:** `SAST-SQLI-001` | **Herramienta:** `SQL Injection Scanner`
        - **Ubicación:** `src/database.py` (Línea 42)
        ...
        > 📝 **Nota de Triage / Re-test:** Corregido usando consultas parametrizadas.
        """
        items: List[RemediationItem] = []
        header_pattern = re.compile(
            r"####\s+([🔴🟢🟣][^\[\n]*)?\[(PENDIENTE|SUBSANADO(?:\s*/\s*VERIFICADO)?|POR DISEÑO|RESOLVED|AS_DESIGNED|OPEN)\]\s*\[([A-Z]+)\]\s*(.*?)\n(.*?)(?=\n####|\n## |\Z)",
            re.DOTALL | re.IGNORECASE,
        )

        for match in header_pattern.finditer(content):
            raw_status = match.group(2)
            title = match.group(4).strip()
            block = match.group(5)

            status = self.normalize_status(raw_status)

            id_match = re.search(r"\*\*ID:\*\*\s*`?([A-Za-z0-9_\-\.:]+)`?", block)
            if not id_match:
                continue
            finding_id = id_match.group(1).strip()

            file_path = None
            line_number = None
            loc_match = re.search(r"\*\*Ubicación:\*\*\s*`?([^`\(\n]+)`?(?:\s*\(Línea\s*(\d+)\))?", block)
            if loc_match:
                file_path = loc_match.group(1).strip()
                if loc_match.group(2):
                    try:
                        line_number = int(loc_match.group(2))
                    except ValueError:
                        pass

            comment = ""
            note_match = re.search(r">\s*📝\s*\*\*[^:]+:\*\*\s*(.*?)(?:\*\(Fecha:.*?\)\*|\n|$)", block, re.DOTALL)
            if note_match:
                comment = note_match.group(1).strip()
            else:
                dev_match = re.search(r"(?:Subsanaci[oó]n|Soluci[oó]n|Acci[oó]n|Comentario):\s*([^\n]+)", block, re.IGNORECASE)
                if dev_match:
                    comment = dev_match.group(1).strip()

            if status in ("RESOLVED", "AS_DESIGNED") or comment:
                items.append(RemediationItem(
                    finding_id=finding_id,
                    file_path=file_path,
                    line_number=line_number,
                    status=status,
                    developer_comment=comment or (
                        "Subsanado por el equipo de desarrollo" if status == "RESOLVED"
                        else "Comportamiento por diseño justificado"
                    ),
                    original_finding_title=title,
                ))

        return items

    def _parse_markdown_tables(self, content: str) -> List[RemediationItem]:
        """
        Parses tables like:
        | ID | Archivo | Estado | Explicación / Subsanación |
        | QA-COGNITIVE-NESTING-DEPTH | app.py | SUBSANADO | Refactorizado con early returns |
        """
        items: List[RemediationItem] = []
        lines = content.splitlines()
        table_rows = []
        in_table = False
        header_indices = {}

        for line in lines:
            line_str = line.strip()
            if line_str.startswith("|") and line_str.endswith("|"):
                cells = [c.strip() for c in line_str.strip("|").split("|")]
                if not in_table:
                    lower_cells = [c.lower() for c in cells]
                    id_idx = next((i for i, c in enumerate(lower_cells) if "id" in c or "hallazgo" in c or "regla" in c), -1)
                    if id_idx != -1:
                        in_table = True
                        header_indices["id"] = id_idx
                        header_indices["file"] = next((i for i, c in enumerate(lower_cells) if "archivo" in c or "ubicaci" in c or "file" in c or "path" in c), -1)
                        header_indices["status"] = next((i for i, c in enumerate(lower_cells) if "estado" in c or "status" in c or "triage" in c), -1)
                        header_indices["notes"] = next((i for i, c in enumerate(lower_cells) if "explicaci" in c or "subsanaci" in c or "nota" in c or "comentario" in c or "acci" in c or "soluci" in c), -1)
                        continue
                else:
                    if all(set(c).issubset({"-", ":", " "}) for c in cells):
                        continue
                    table_rows.append(cells)
            else:
                in_table = False

        for row in table_rows:
            if "id" not in header_indices or header_indices["id"] >= len(row):
                continue
            raw_id = row[header_indices["id"]].strip("`* ")
            if not raw_id:
                continue

            file_path = None
            line_number = None
            if header_indices.get("file", -1) != -1 and header_indices["file"] < len(row):
                raw_file = row[header_indices["file"]].strip("`* ")
                loc_m = re.search(r"^(.*?)(?::(\d+)|\s*\(Línea\s*(\d+)\))?$", raw_file)
                if loc_m:
                    file_path = loc_m.group(1).strip()
                    ln_str = loc_m.group(2) or loc_m.group(3)
                    if ln_str:
                        try:
                            line_number = int(ln_str)
                        except ValueError:
                            pass

            status = "RESOLVED"
            if header_indices.get("status", -1) != -1 and header_indices["status"] < len(row):
                status = self.normalize_status(row[header_indices["status"]])

            notes = ""
            if header_indices.get("notes", -1) != -1 and header_indices["notes"] < len(row):
                notes = row[header_indices["notes"]].strip()

            items.append(RemediationItem(
                finding_id=raw_id,
                file_path=file_path,
                line_number=line_number,
                status=status,
                developer_comment=notes or "Subsanación registrada vía tabla",
            ))

        return items

    def _parse_section_headers(self, content: str) -> List[RemediationItem]:
        """
        Parses section header blocks:
        ### [SUBSANADO] SEC-SQLI-01: Inyección SQL en database.py
        - **Archivo:** src/database.py (Línea 42)
        - **Comentario:** Se usaron queries parametrizadas.
        """
        items: List[RemediationItem] = []
        pattern = re.compile(
            r"(?:^|\n)###\s*(?:\[(SUBSANADO|RESOLVED|POR DISEÑO|AS_DESIGNED|OPEN|PENDIENTE)\]\s*)?`?([A-Za-z0-9_\-\.:]+)`?(?::\s*([^\n]+))?\n(.*?)(?=\n###|\n## |\Z)",
            re.DOTALL | re.IGNORECASE,
        )

        for match in pattern.finditer(content):
            raw_status = match.group(1) or "RESOLVED"
            finding_id = match.group(2).strip()
            title = match.group(3) or ""
            body = match.group(4)

            if finding_id.lower() in ("resumen", "métricas", "metricas", "dictamen", "estado", "pilar", "1", "2", "3", "4", "instrucciones", "tabla"):
                continue

            status = self.normalize_status(raw_status)
            file_path = None
            line_number = None
            file_match = re.search(r"(?:\*\*Archivo:\*\*|\*\*Ubicaci[oó]n:\*\*|Archivo:|Ubicaci[oó]n:)\s*`?([^`\(\n]+)`?(?::(\d+)|\s*\(Línea\s*(\d+)\))?", body, re.IGNORECASE)
            if file_match:
                file_path = file_match.group(1).strip()
                ln_str = file_match.group(2) or file_match.group(3)
                if ln_str:
                    try:
                        line_number = int(ln_str)
                    except ValueError:
                        pass

            comment_match = re.search(r"(?:\*\*Comentario:\*\*|\*\*Acci[oó]n:\*\*|\*\*Subsanaci[oó]n:\*\*|Comentario:|Subsanaci[oó]n:|Soluci[oó]n:)\s*([^\n]+(?:\n\s+[^\n]+)*)", body, re.IGNORECASE)
            comment = comment_match.group(1).strip() if comment_match else body.strip()

            items.append(RemediationItem(
                finding_id=finding_id,
                file_path=file_path,
                line_number=line_number,
                status=status,
                developer_comment=comment or "Subsanación detallada en sección",
                original_finding_title=title.strip() if title else None,
            ))

        return items

    def _parse_checklists(self, content: str) -> List[RemediationItem]:
        """
        Parses checklists like:
        - [x] `SEC-SQLI-01` (src/db.py:42): Subsanado - Se implementó cursor.execute con tupla
        - [x] `QA-EMPTY-EXCEPT`: Por diseño - Manejo de excepción intencional
        - [ ] `ENG-SECRET-001`: Pendiente
        """
        items: List[RemediationItem] = []
        pattern = re.compile(
            r"^\s*-\s*\[([ xX])\]\s*`?([A-Za-z0-9_\-\.:]+)`?(?:\s*\(([^)]+)\))?:\s*(.+)$",
            re.MULTILINE,
        )

        for match in pattern.finditer(content):
            checked = match.group(1).lower() == "x"
            finding_id = match.group(2).strip()
            loc_str = match.group(3)
            rest = match.group(4).strip()

            file_path = None
            line_number = None
            if loc_str:
                loc_m = re.search(r"^(.*?)(?::(\d+)|\s*Línea\s*(\d+))?$", loc_str.strip())
                if loc_m:
                    file_path = loc_m.group(1).strip()
                    ln_str = loc_m.group(2) or loc_m.group(3)
                    if ln_str:
                        try:
                            line_number = int(ln_str)
                        except ValueError:
                            pass

            if not checked:
                status = "OPEN"
                comment = rest or "Pendiente de subsanar"
            else:
                lower_rest = rest.lower()
                if "por dise" in lower_rest or "as_designed" in lower_rest or "aceptado" in lower_rest:
                    status = "AS_DESIGNED"
                else:
                    status = "RESOLVED"
                comment = rest

            items.append(RemediationItem(
                finding_id=finding_id,
                file_path=file_path,
                line_number=line_number,
                status=status,
                developer_comment=comment,
            ))

        return items


class RemediationManager:
    """
    Coordinates the ingestion of remediation Markdown documents, runs targeted
    scanner re-verifications against source code, applies status overrides,
    updates report metrics, and generates synchronized reports and developer feedback.
    """

    def __init__(self, parser: Optional[MarkdownRemediationParser] = None, reverifier: Optional[AuditReverifier] = None):
        self.parser = parser or MarkdownRemediationParser()
        self.reverifier = reverifier or AuditReverifier()

    def process_remediation_markdown(
        self,
        markdown_content: str,
        report_dict: Dict[str, Any],
        target_root: Optional[str] = None,
        overrides_file: Optional[str] = None,
        auto_reverify: bool = True,
        audit_number: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Main pipeline to process an uploaded remediation markdown file:
        1. Parses Markdown content to find declared remediations.
        2. Matches items against findings in report_dict.
        3. If auto_reverify is True and status is RESOLVED, re-runs the specific scanner on disk.
        4. Applies updates to in-memory report and persists to overrides_file.
        5. Recalculates metrics and risk score.
        6. Re-generates Auditoria_<num>_<fecha>.md.
        """
        parsed_items = self.parser.parse_markdown(markdown_content)
        if not parsed_items:
            return {
                "status": "warning",
                "message": "No se detectaron hallazgos ni subsanaciones estructuradas en el archivo Markdown.",
                "total_parsed": 0,
                "items": [],
                "report": report_dict,
            }

        effective_target = target_root or report_dict.get("target_path") or os.getcwd()
        findings_list = report_dict.get("findings", [])
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        overrides = {}
        if overrides_file and os.path.exists(overrides_file):
            try:
                with open(overrides_file, "r", encoding="utf-8") as f:
                    overrides = json.load(f)
            except Exception as e:
                logger.debug("Failed reading existing overrides: %s", e)

        processed_items: List[RemediationItem] = []
        verified_count = 0
        failed_reverify_count = 0
        as_designed_count = 0
        open_count = 0

        for item in parsed_items:
            matched_findings = self._find_matching_findings(item, findings_list)
            if not matched_findings:
                item.verification_message = "Hallazgo no encontrado en el informe activo de la plataforma."
                processed_items.append(item)
                continue

            for target_finding in matched_findings:
                f_id = target_finding.get("id")
                f_path = target_finding.get("file_path", "")
                f_line = target_finding.get("line_number")
                f_scanner = target_finding.get("scanner_name")
                f_sev = target_finding.get("severity")

                item.original_finding_title = target_finding.get("title")
                item.severity = f_sev

                if item.status == "RESOLVED":
                    if auto_reverify:
                        reverify_res = self.reverifier.reverify_finding(
                            finding_id=f_id,
                            file_path=f_path,
                            line_number=f_line,
                            scanner_name=f_scanner,
                            target_root=effective_target,
                            write_markdown=False,
                            persist_overrides=False,
                        )

                        if reverify_res.get("is_resolved", False):
                            item.verified_on_disk = True
                            item.verification_message = "✅ Verificado en código: el scanner confirmó que la vulnerabilidad fue eliminada."
                            verified_count += 1
                            effective_status = "RESOLVED"
                            full_comment = f"Subsanado por desarrollador: {item.developer_comment}. [Re-test: Código limpio]"
                        else:
                            item.verified_on_disk = False
                            item.verification_message = f"⚠️ Persiste en código: el scanner aún detectó la falla en línea {reverify_res.get('remaining_findings', [{}])[0].get('line_number') or f_line or 'N/A'}."
                            failed_reverify_count += 1
                            effective_status = "OPEN"
                            full_comment = f"El desarrollador reportó subsanación ('{item.developer_comment}'), pero la vulnerabilidad aún persiste en el código fuente."
                    else:
                        item.verified_on_disk = None
                        item.verification_message = "Subsanación registrada por el desarrollador (sin re-test en disco)."
                        verified_count += 1
                        effective_status = "RESOLVED"
                        full_comment = f"Subsanado por desarrollador: {item.developer_comment}"

                elif item.status == "AS_DESIGNED":
                    item.verified_on_disk = True
                    item.verification_message = "🟣 Aceptado como comportamiento por diseño."
                    as_designed_count += 1
                    effective_status = "AS_DESIGNED"
                    full_comment = f"Aceptado por diseño: {item.developer_comment}"

                else:
                    item.verified_on_disk = None
                    item.verification_message = "Marcado como pendiente de revisión."
                    open_count += 1
                    effective_status = "OPEN"
                    full_comment = item.developer_comment or "Reabierto o pendiente"

                target_finding["status"] = effective_status
                target_finding["status_comment"] = full_comment
                target_finding["status_updated_at"] = now_str

                norm_p = os.path.normpath(f_path).replace("\\", "/")
                key = f"{f_id}|{norm_p}|{f_line}" if f_line is not None else f"{f_id}|{norm_p}"
                overrides[key] = {
                    "finding_id": f_id,
                    "file_path": f_path,
                    "line_number": f_line,
                    "status": effective_status,
                    "comment": full_comment,
                    "updated_at": now_str,
                    "verified_on_disk": item.verified_on_disk,
                }

                processed_items.append(item)

        if overrides_file:
            try:
                with open(overrides_file, "w", encoding="utf-8") as f:
                    json.dump(overrides, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error("Failed persisting remediation overrides to %s: %s", overrides_file, e)

        status_counts = {"OPEN": 0, "RESOLVED": 0, "AS_DESIGNED": 0}
        active_sev_counts = {s.value: 0 for s in Severity}
        for f in findings_list:
            st = (f.get("status") or "OPEN").upper()
            status_counts[st] = status_counts.get(st, 0) + 1
            if st == "OPEN":
                sev = f.get("severity", "MEDIUM")
                if sev in active_sev_counts:
                    active_sev_counts[sev] += 1

        report_dict["status_counts"] = status_counts
        report_dict["active_severity_counts"] = active_sev_counts

        updated_md_path = None
        try:
            findings_objs = []
            for f in findings_list:
                raw_p = f.get("pillar", Pillar.PENETRATION_TESTER.value)
                p_val = Pillar.PENETRATION_TESTER
                for p in Pillar:
                    if p.value == raw_p or p.name == raw_p:
                        p_val = p
                        break
                raw_s = f.get("severity", "MEDIUM")
                s_val = Severity.MEDIUM
                for s in Severity:
                    if s.value == raw_s or s.name == raw_s:
                        s_val = s
                        break
                findings_objs.append(Finding(
                    id=f.get("id", ""),
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    severity=s_val,
                    pillar=p_val,
                    scanner_name=f.get("scanner_name", ""),
                    file_path=f.get("file_path", ""),
                    line_number=f.get("line_number"),
                    code_snippet=f.get("code_snippet"),
                    remediation=f.get("remediation"),
                    cwe_id=f.get("cwe_id"),
                    mitre_id=f.get("mitre_id"),
                    status=f.get("status", "OPEN"),
                    status_comment=f.get("status_comment"),
                    status_updated_at=f.get("status_updated_at"),
                ))

            scan_rep = ScanReport(
                target_path=report_dict.get("target_path", effective_target),
                timestamp=report_dict.get("timestamp", now_str),
                duration_seconds=report_dict.get("duration_seconds", 0.0),
                files_scanned=report_dict.get("files_scanned", 0),
                scanners_executed=report_dict.get("scanners_executed", []),
                findings=findings_objs,
                executive_summary=report_dict.get("executive_summary"),
                ai_verdict=report_dict.get("ai_verdict"),
                ai_provider_used=report_dict.get("ai_provider_used"),
            )
            updated_md_path, num = save_markdown_audit_report(scan_rep, effective_target, audit_number=audit_number)
            report_dict["audit_md_path"] = updated_md_path
            report_dict["audit_number"] = num
        except Exception as e:
            logger.warning("Could not refresh Auditoria_*.md after remediation: %s", e)

        return {
            "status": "ok",
            "message": f"Se procesaron {len(processed_items)} subsanaciones. {verified_count} verificadas/resueltas, {as_designed_count} por diseño, {failed_reverify_count} fallaron re-test en disco.",
            "total_parsed": len(parsed_items),
            "verified_count": verified_count,
            "failed_reverify_count": failed_reverify_count,
            "as_designed_count": as_designed_count,
            "open_count": open_count,
            "items": [it.to_dict() for it in processed_items],
            "status_counts": status_counts,
            "active_severity_counts": active_sev_counts,
            "updated_markdown_report": updated_md_path,
            "report": report_dict,
        }

    def _find_matching_findings(self, item: RemediationItem, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Matches a parsed item against active findings using ID, file path, and line number."""
        matches = []
        target_id = item.finding_id.strip().lower()
        norm_item_path = item.file_path.replace("\\", "/").lower() if item.file_path else None

        for f in findings:
            f_id = (f.get("id") or "").strip().lower()
            if f_id != target_id:
                continue

            if norm_item_path:
                f_path = (f.get("file_path") or "").replace("\\", "/").lower()
                if not (f_path == norm_item_path or f_path.endswith(norm_item_path) or norm_item_path.endswith(f_path)):
                    continue

            if item.line_number is not None and f.get("line_number") is not None:
                if f.get("line_number") != item.line_number:
                    continue

            matches.append(f)

        if not matches and not norm_item_path:
            id_only = [f for f in findings if (f.get("id") or "").strip().lower() == target_id]
            if len(id_only) == 1:
                matches = id_only

        return matches

    @classmethod
    def generate_developer_response_template(cls, report_dict: Dict[str, Any]) -> str:
        """
        Generates a clean Markdown response template pre-filled with open findings
        so the developer can easily document their remediations and reply back.
        """
        target = report_dict.get("target_path", "Software Target")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        findings = report_dict.get("findings", [])
        open_findings = [f for f in findings if (f.get("status") or "OPEN").upper() == "OPEN"]

        lines = [
            f"# 📝 Informe de Respuesta y Subsanación de Hallazgos — Equipo de Desarrollo",
            f"**Objetivo:** `{target}` | **Fecha:** {today} | **Hallazgos a Subsanar:** {len(open_findings)}",
            "",
            "---",
            "## Instrucciones para el Desarrollador",
            "1. Revisa cada hallazgo identificado en la auditoría técnica.",
            "2. En el campo `Estado`, selecciona una opción: **SUBSANADO** (corregido en código), **POR DISEÑO** (comportamiento previsto justificado), o **PENDIENTE**.",
            "3. En `Acción Realizada / Justificación`, describe la solución técnica, archivo/línea modificado o commit de Git.",
            "4. Guarda este archivo (`.md`) y súbelo a la plataforma en la pestaña **AI Co-Analyst Studio** o vía CLI para sincronizar y re-verificar automáticamente.",
            "",
            "---",
            "## Tabla Resumen de Subsanaciones",
            "",
            "| ID Hallazgo | Severidad | Ubicación | Estado Propuesto | Acción Realizada / Justificación Técnica |",
            "|---|---|---|---|---|",
        ]

        for f in open_findings:
            f_id = f.get("id", "N/A")
            sev = f.get("severity", "MEDIUM")
            f_path = f.get("file_path", "")
            ln = f.get("line_number")
            loc = f"{f_path}:{ln}" if ln else f_path
            lines.append(f"| `{f_id}` | **{sev}** | `{loc}` | SUBSANADO | *Describe aquí la corrección aplicada* |")

        lines.append("")
        lines.append("---")
        lines.append("## Detalle Extendido por Hallazgo (Opcional)")
        lines.append("")

        for f in open_findings[:15]:
            f_id = f.get("id", "N/A")
            title = f.get("title", "")
            sev = f.get("severity", "MEDIUM")
            f_path = f.get("file_path", "")
            ln = f.get("line_number")
            loc = f"`{f_path}`" + (f" (Línea {ln})" if ln else "")

            lines.append(f"### [SUBSANADO] `{f_id}`: {title}")
            lines.append(f"- **Severidad:** {sev} | **Ubicación:** {loc}")
            lines.append(f"- **Herramienta:** {f.get('scanner_name', 'N/A')}")
            if f.get("code_snippet"):
                lines.append(f"**Código Reportado:**")
                lines.append("```")
                lines.append(f.get("code_snippet", "").strip()[:200])
                lines.append("```")
            lines.append(f"- **Comentario del Desarrollador:** *Escribe aquí el detalle de la solución implementada en código*")
            lines.append("")

        lines.append("---")
        lines.append("*Plantilla generada por CyberAudit Suite v2.0 Enterprise. Listo para ser subido al AI Co-Analyst Studio.*")
        return "\n".join(lines)
