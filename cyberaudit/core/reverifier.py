"""
CyberAudit Core Re-verifier
Executes targeted re-tests of specific scanners and code files to verify
whether identified findings/vulnerabilities have been genuinely resolved,
and updates the audit status and markdown reports accordingly.
"""

import os
import re
import glob
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from cyberaudit.core.engine import AuditEngine
from cyberaudit.core.models import ScanReport, Finding, Severity, Pillar
from cyberaudit.core.reporter import generate_markdown_audit_report, save_markdown_audit_report

logger = logging.getLogger("cyberaudit.core.reverifier")


def _dict_to_finding(f: Dict[str, Any]) -> Finding:
    """Converts a finding dictionary to a Finding model object."""
    raw_pillar = f.get("pillar", Pillar.PENETRATION_TESTER.value)
    pillar_val = Pillar.PENETRATION_TESTER
    for p in Pillar:
        if p.value == raw_pillar or p.name == raw_pillar:
            pillar_val = p
            break

    raw_sev = f.get("severity", "MEDIUM")
    sev_val = Severity.MEDIUM
    for s in Severity:
        if s.value == raw_sev or s.name == raw_sev:
            sev_val = s
            break

    return Finding(
        id=f.get("id", ""),
        title=f.get("title", ""),
        description=f.get("description", ""),
        severity=sev_val,
        pillar=pillar_val,
        scanner_name=f.get("scanner_name", ""),
        file_path=f.get("file_path", ""),
        line_number=f.get("line_number"),
        code_snippet=f.get("code_snippet"),
        remediation=f.get("remediation"),
        cwe_id=f.get("cwe_id"),
        status=f.get("status", "OPEN"),
        status_comment=f.get("status_comment"),
        status_updated_at=f.get("status_updated_at"),
    )


class AuditReverifier:
    """
    Orchestrates targeted re-verification of specific findings by executing
    the exact scanner against the current source code on disk.
    """

    def __init__(self, engine: Optional[AuditEngine] = None):
        self.engine = engine or AuditEngine(archetype="full")
        self.scanners_by_name = {s.name: s for s in self.engine.scanners}

    def _resolve_file_path(self, file_path: str, target_root: Optional[str] = None) -> Tuple[str, bool]:
        """Resolves file path to an absolute path, checking target_root and CWD."""
        norm_input = file_path.replace("/", os.sep).replace("\\", os.sep)

        if os.path.isabs(norm_input) and os.path.exists(norm_input):
            return norm_input, True

        if target_root:
            cand = os.path.normpath(os.path.join(target_root, norm_input))
            if os.path.exists(cand):
                return cand, True

        cand = os.path.normpath(os.path.join(os.getcwd(), norm_input))
        if os.path.exists(cand):
            return cand, True

        fallback = os.path.abspath(cand if target_root is None else os.path.join(target_root, norm_input))
        return fallback, os.path.exists(fallback)

    def _find_scanner(self, scanner_name: Optional[str]) -> Optional[Any]:
        """Finds scanner instance by exact name, case-insensitive, or substring match."""
        if not scanner_name:
            return None

        if scanner_name in self.scanners_by_name:
            return self.scanners_by_name[scanner_name]

        lower = scanner_name.lower().strip()
        for name, scanner in self.scanners_by_name.items():
            if name.lower() == lower:
                return scanner

        for name, scanner in self.scanners_by_name.items():
            if lower in name.lower() or name.lower() in lower:
                return scanner

        return None

    def reverify_finding(
        self,
        finding_id: str,
        file_path: str,
        line_number: Optional[int] = None,
        scanner_name: Optional[str] = None,
        target_root: Optional[str] = None,
        report: Optional[ScanReport] = None,
        report_dict: Optional[Dict[str, Any]] = None,
        overrides_file: Optional[str] = None,
        md_report_path: Optional[str] = None,
        audit_number: Optional[int] = None,
        write_markdown: bool = True,
        persist_overrides: bool = True,
        scan_cache: Optional[Dict[str, List[Finding]]] = None,
    ) -> Dict[str, Any]:
        """
        Re-tests a specific finding on disk.
        Returns whether the issue is resolved, remaining findings (if any),
        and updates the report and Markdown documentation.
        """
        abs_path, exists = self._resolve_file_path(file_path, target_root)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Case 1: Target file was deleted (e.g. temporary vulnerable script removed)
        if not exists:
            comment = f"Subsanación verificada: el archivo fue eliminado o movido ({now_str})."
            updated_md = self._apply_resolution(
                finding_id=finding_id,
                file_path=file_path,
                line_number=line_number,
                comment=comment,
                report=report,
                report_dict=report_dict,
                overrides_file=overrides_file,
                md_report_path=md_report_path,
                target_root=target_root,
                audit_number=audit_number,
                write_markdown=write_markdown,
                persist_overrides=persist_overrides,
            )
            return {
                "finding_id": finding_id,
                "file_path": abs_path,
                "is_resolved": True,
                "status": "RESOLVED",
                "message": comment,
                "remaining_findings": [],
                "updated_markdown_report": updated_md,
            }

        # Case 2: Read updated file content
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return {
                "finding_id": finding_id,
                "file_path": abs_path,
                "is_resolved": False,
                "status": "ERROR",
                "message": f"No se pudo leer el archivo para re-test: {e}",
                "remaining_findings": [],
            }

        # Case 3: Execute target scanner(s) with caching support
        scanner = self._find_scanner(scanner_name)
        scanners_to_run = [scanner] if scanner else self.engine.scanners

        cache_key = f"{abs_path}|{scanner_name or 'all'}"
        if scan_cache is not None and cache_key in scan_cache:
            active_findings = scan_cache[cache_key]
        else:
            active_findings = []
            for sc in scanners_to_run:
                try:
                    results = sc.scan_file(abs_path, content)
                    active_findings.extend(results)
                except Exception as e:
                    logger.debug("Error running scanner %s during reverify: %s", getattr(sc, "name", "unknown"), e)
            if scan_cache is not None:
                scan_cache[cache_key] = active_findings

        # Check if the specific finding still exists in active_findings
        matching_findings: List[Finding] = []
        for f in active_findings:
            if f.id == finding_id:
                matching_findings.append(f)
            elif line_number and f.line_number and abs(f.line_number - line_number) <= 2:
                if scanner_name and (scanner and scanner.name.lower() in f.scanner_name.lower()):
                    matching_findings.append(f)

        if not matching_findings:
            # Finding has been resolved!
            comment = f"Subsanación verificada exitosamente: el re-test con '{scanner_name or 'SAST'}' no detectó la vulnerabilidad ({now_str})."
            updated_md = self._apply_resolution(
                finding_id=finding_id,
                file_path=file_path,
                line_number=line_number,
                comment=comment,
                report=report,
                report_dict=report_dict,
                overrides_file=overrides_file,
                md_report_path=md_report_path,
                target_root=target_root,
                audit_number=audit_number,
                write_markdown=write_markdown,
                persist_overrides=persist_overrides,
            )
            return {
                "finding_id": finding_id,
                "file_path": abs_path,
                "is_resolved": True,
                "status": "RESOLVED",
                "message": comment,
                "remaining_findings": [],
                "updated_markdown_report": updated_md,
            }
        else:
            return {
                "finding_id": finding_id,
                "file_path": abs_path,
                "is_resolved": False,
                "status": "OPEN",
                "message": f"La vulnerabilidad aún persiste en el código fuente. Hallazgo detectado en línea {matching_findings[0].line_number or 'N/A'}.",
                "remaining_findings": [f.to_dict() for f in matching_findings],
            }

    def _apply_resolution(
        self,
        finding_id: str,
        file_path: str,
        line_number: Optional[int],
        comment: str,
        report: Optional[ScanReport],
        report_dict: Optional[Dict[str, Any]],
        overrides_file: Optional[str],
        md_report_path: Optional[str],
        target_root: Optional[str],
        audit_number: Optional[int],
        write_markdown: bool = True,
        persist_overrides: bool = True,
    ) -> Optional[str]:
        """Updates in-memory report, persists override, and updates markdown report."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        norm_target = file_path.replace("\\", "/").lower()

        # 1. Update in-memory report object if provided
        if report:
            for f in report.findings:
                f_norm = f.file_path.replace("\\", "/").lower()
                if f.id == finding_id and (f_norm == norm_target or f_norm.endswith(norm_target) or norm_target.endswith(f_norm)):
                    f.status = "RESOLVED"
                    f.status_comment = comment
                    f.status_updated_at = now_str
                    break

        # 2. Update report dict if provided
        if report_dict and "findings" in report_dict:
            status_counts = {"OPEN": 0, "RESOLVED": 0, "AS_DESIGNED": 0}
            active_sev_counts = {s.value: 0 for s in Severity}
            for fd in report_dict["findings"]:
                fd_norm = fd.get("file_path", "").replace("\\", "/").lower()
                if fd.get("id") == finding_id and (fd_norm == norm_target or fd_norm.endswith(norm_target) or norm_target.endswith(fd_norm)):
                    fd["status"] = "RESOLVED"
                    fd["status_comment"] = comment
                    fd["status_updated_at"] = now_str

                st = (fd.get("status") or "OPEN").upper()
                status_counts[st] = status_counts.get(st, 0) + 1
                if st == "OPEN":
                    sev = fd.get("severity", "MEDIUM")
                    if sev in active_sev_counts:
                        active_sev_counts[sev] += 1
            report_dict["status_counts"] = status_counts
            report_dict["active_severity_counts"] = active_sev_counts

        # 3. Persist override to disk
        if persist_overrides and overrides_file:
            try:
                overrides = {}
                if os.path.exists(overrides_file):
                    with open(overrides_file, "r", encoding="utf-8") as f:
                        overrides = json.load(f)
                norm_p = os.path.normpath(file_path).replace("\\", "/")
                key = f"{finding_id}|{norm_p}|{line_number}" if line_number is not None else f"{finding_id}|{norm_p}"
                overrides[key] = {
                    "finding_id": finding_id,
                    "file_path": file_path,
                    "line_number": line_number,
                    "status": "RESOLVED",
                    "comment": comment,
                    "updated_at": now_str,
                }
                with open(overrides_file, "w", encoding="utf-8") as f:
                    json.dump(overrides, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error("Could not persist override in reverifier: %s", e)

        # 4. Update Markdown audit report file
        if not write_markdown:
            return None

        return self._update_markdown_report(
            report=report,
            report_dict=report_dict,
            target_dir=target_root or (report.target_path if report else None) or (report_dict.get("target_path") if report_dict else None),
            md_report_path=md_report_path,
            audit_number=audit_number,
        )

    def _update_markdown_report(
        self,
        report: Optional[ScanReport] = None,
        report_dict: Optional[Dict[str, Any]] = None,
        target_dir: Optional[str] = None,
        md_report_path: Optional[str] = None,
        audit_number: Optional[int] = None,
    ) -> Optional[str]:
        """Generates and writes the updated Markdown audit report."""
        target = target_dir or (report.target_path if report else None) or (report_dict.get("target_path") if report_dict else None) or os.getcwd()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        report_to_export = report
        if not report_to_export and report_dict:
            rep_findings = [_dict_to_finding(f) for f in report_dict.get("findings", [])]
            report_to_export = ScanReport(
                target_path=report_dict.get("target_path", target),
                timestamp=report_dict.get("timestamp", now_str),
                duration_seconds=report_dict.get("duration_seconds", 0.0),
                files_scanned=report_dict.get("files_scanned", 0),
                scanners_executed=report_dict.get("scanners_executed", []),
                findings=rep_findings,
                executive_summary=report_dict.get("executive_summary"),
                ai_verdict=report_dict.get("ai_verdict"),
                ai_provider_used=report_dict.get("ai_provider_used"),
            )

        if not report_to_export:
            return None

        try:
            if md_report_path and os.path.exists(md_report_path):
                content = generate_markdown_audit_report(report_to_export, audit_number=audit_number or 1)
                with open(md_report_path, "w", encoding="utf-8") as f:
                    f.write(content)
                return md_report_path

            dir_path = target if os.path.isdir(target) else os.path.dirname(target)
            existing_reports = sorted(glob.glob(os.path.join(dir_path, "Auditoria_*_*.md")))
            if existing_reports:
                latest = existing_reports[-1]
                m = re.match(r"^Auditoria_(\d+)_\d{4}-\d{2}-\d{2}\.md$", os.path.basename(latest), re.IGNORECASE)
                num = int(m.group(1)) if m else (audit_number or 1)
                content = generate_markdown_audit_report(report_to_export, audit_number=num)
                with open(latest, "w", encoding="utf-8") as f:
                    f.write(content)
                return latest
            else:
                updated_file, _ = save_markdown_audit_report(report_to_export, dir_path, audit_number=audit_number)
                return updated_file
        except Exception as e:
            logger.error("Could not update markdown audit report: %s", e)
            return None

    def reverify_all_in_report(
        self,
        report: Optional[ScanReport] = None,
        report_dict: Optional[Dict[str, Any]] = None,
        target_root: Optional[str] = None,
        overrides_file: Optional[str] = None,
        md_report_path: Optional[str] = None,
        audit_number: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Re-verifies all findings currently in report, skipping accepted AS_DESIGNED items."""
        findings_list = report.findings if report else report_dict.get("findings", []) if report_dict else []
        resolved_count = 0
        still_open_count = 0
        as_designed_count = 0
        details = []
        scan_cache: Dict[str, List[Finding]] = {}
        batch_overrides: Dict[str, Any] = {}
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        effective_target = target_root or (report.target_path if report else report_dict.get("target_path") if report_dict else None) or os.getcwd()

        for f in findings_list:
            fid = f.id if hasattr(f, "id") else f.get("id")
            fpath = f.file_path if hasattr(f, "file_path") else f.get("file_path")
            fline = f.line_number if hasattr(f, "line_number") else f.get("line_number")
            fscanner = f.scanner_name if hasattr(f, "scanner_name") else f.get("scanner_name")
            fstatus = (f.status if hasattr(f, "status") else f.get("status") or "OPEN").upper()

            if fstatus == "AS_DESIGNED":
                as_designed_count += 1
                details.append({
                    "finding_id": fid,
                    "file_path": fpath,
                    "is_resolved": False,
                    "status": "AS_DESIGNED",
                    "message": "Diseño previsto aceptado (triage)",
                })
                continue

            res = self.reverify_finding(
                finding_id=fid,
                file_path=fpath,
                line_number=fline,
                scanner_name=fscanner,
                target_root=effective_target,
                report=report,
                report_dict=report_dict,
                overrides_file=None,
                md_report_path=md_report_path,
                audit_number=audit_number,
                write_markdown=False,
                persist_overrides=False,
                scan_cache=scan_cache,
            )

            if res["is_resolved"]:
                resolved_count += 1
                norm_p = os.path.normpath(fpath or "").replace("\\", "/")
                key = f"{fid}|{norm_p}|{fline}" if fline is not None else f"{fid}|{norm_p}"
                batch_overrides[key] = {
                    "finding_id": fid,
                    "file_path": fpath,
                    "line_number": fline,
                    "status": "RESOLVED",
                    "comment": res["message"],
                    "updated_at": now_str,
                }
            else:
                still_open_count += 1

            details.append({
                "finding_id": fid,
                "file_path": fpath,
                "is_resolved": res["is_resolved"],
                "status": res.get("status"),
                "message": res.get("message"),
            })

        # 1. Batch persist overrides once if any finding was resolved
        if batch_overrides and overrides_file:
            try:
                overrides = {}
                if os.path.exists(overrides_file):
                    with open(overrides_file, "r", encoding="utf-8") as f_ov:
                        overrides = json.load(f_ov)
                overrides.update(batch_overrides)
                with open(overrides_file, "w", encoding="utf-8") as f_ov:
                    json.dump(overrides, f_ov, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error("Could not persist batch overrides: %s", e)

        # 2. Update markdown report once if any finding was resolved
        updated_md = None
        if resolved_count > 0:
            updated_md = self._update_markdown_report(
                report=report,
                report_dict=report_dict,
                target_dir=effective_target,
                md_report_path=md_report_path,
                audit_number=audit_number,
            )

        return {
            "total_checked": len(findings_list),
            "resolved_count": resolved_count,
            "still_open_count": still_open_count,
            "as_designed_count": as_designed_count,
            "updated_markdown_report": updated_md,
            "results": details,
        }

