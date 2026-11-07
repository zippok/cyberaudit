"""
CyberAudit Suite - Enterprise Web API & Interactive Application
FastAPI server powering the visual cybersecurity dashboard, real-time audit runner,
STRIDE threat modeling analytics, QA verification test suite, and AI Co-Analyst Studio.
"""

import os
import sys
import json
import time
import asyncio
import subprocess
import logging
import hmac
import ipaddress
import threading
import hashlib
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, StrictBool

from cyberaudit.core.engine import AuditEngine
from cyberaudit.core.reporter import Reporter, save_markdown_audit_report, generate_markdown_audit_report
from cyberaudit.core.reverifier import AuditReverifier
from cyberaudit.core.remediation import RemediationManager, MarkdownRemediationParser
from cyberaudit.core.models import ScanReport, Finding, Severity, Pillar, StrideCategory
from cyberaudit.ai.co_analyst import AICoAnalyst

logger = logging.getLogger("cyberaudit.web")
from cyberaudit.web.organization import validate_runtime
validate_runtime()

app = FastAPI(
    title="CyberAudit Suite Enterprise API",
    description="Enterprise Cybersecurity Auditing, QA Verification & AI Co-Analyst Platform",
    version="2.0.0",
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.getenv("CYBERAUDIT_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(","))
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

allowed_origins_env = os.getenv("CYBERAUDIT_CORS_ORIGINS", "")
if allowed_origins_env.strip():
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
else:
    allowed_origins = [
        f"http://{h}:{p}"
        for h in ("localhost", "127.0.0.1")
        for p in (8000, 3000, 5173)
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=4)
scan_lock = threading.Lock()


@app.middleware("http")
async def protect_api(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin and origin not in allowed_origins and origin != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "Origen no autorizado"}, status_code=403)
        if os.getenv("CYBERAUDIT_RBAC_FILE"):
            from cyberaudit.web.enterprise import enterprise_request
            return await enterprise_request(request, call_next, scan_lock)
        token = os.getenv("CYBERAUDIT_API_TOKEN", "")
        peer = request.client.host if request.client else ""
        try:
            local = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            # Starlette's in-process test transport does not expose a network socket.
            local = peer == "testclient"
        if token:
            supplied = request.headers.get("authorization", "")
            if not hmac.compare_digest(supplied, "Bearer " + token):
                return JSONResponse({"detail": "Se requiere token de acceso"}, status_code=401)
        elif not local:
            return JSONResponse({"detail": "Configure CYBERAUDIT_API_TOKEN para acceso remoto"}, status_code=403)
        # Current project storage is single-operator. Serialize conflicting mutations.
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not scan_lock.acquire(blocking=False):
                return JSONResponse({"detail": "Hay otra operación en curso; reintente al finalizar"}, status_code=409)
            try:
                return await call_next(request)
            finally:
                scan_lock.release()
    return await call_next(request)

# Global in-memory state (legacy / single-project mode)
current_report_data: Optional[Dict[str, Any]] = None
is_scanning: bool = False
scan_status: str = "Idle"
co_analyst = AICoAnalyst()
remediation_manager = RemediationManager()

# Multi-project state
PROJECTS_FILE = "cyberaudit_projects.json"
projects: Dict[str, Dict[str, Any]] = {}   # {project_id: project_dict}
active_project_id: Optional[str] = None


def _load_projects() -> None:
    """Loads persisted projects from PROJECTS_FILE on startup."""
    global projects
    path = os.path.join(os.getcwd(), PROJECTS_FILE)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                projects = json.load(f)
            for pid, project in projects.items():
                report_path = _project_report_path(pid)
                if report_path.is_file():
                    project["report_data"] = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug("Failed loading projects file: %s", e)
            projects = {}


def _project_report_path(project_id: str) -> Path:
    return Path(os.getcwd()) / "reports" / "projects" / (hashlib.sha256(project_id.encode()).hexdigest() + ".json")


def _atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _save_projects() -> None:
    """Persists current projects dict to PROJECTS_FILE."""
    path = os.path.join(os.getcwd(), PROJECTS_FILE)
    try:
        # Don't serialize full report_data to disk (can be huge); save metadata only
        slim = {}
        for pid, proj in projects.items():
            if proj.get("report_data") is not None:
                _atomic_json(_project_report_path(pid), proj["report_data"])
            slim[pid] = {k: v for k, v in proj.items() if k != "report_data"}
        _atomic_json(Path(path), slim)
    except Exception as e:
        raise OSError(f"No se pudo guardar el proyecto: {e}") from e


def _get_project_overrides_path(project_id: str) -> str:
    """Returns the overrides file path for a given project (isolated per project)."""
    safe_id = project_id.replace("/", "_").replace("\\", "_")
    return os.path.join(os.getcwd(), f"{safe_id}_overrides.json")


def _get_active_report() -> Optional[Dict[str, Any]]:
    """Returns the currently active report: from active project or legacy global."""
    global active_project_id, projects, current_report_data
    if active_project_id and active_project_id in projects:
        return projects[active_project_id].get("report_data")
    return current_report_data


def _set_active_report(report_data: Dict[str, Any]) -> None:
    """Sets report on active project or legacy global."""
    global active_project_id, projects, current_report_data
    if active_project_id and active_project_id in projects:
        projects[active_project_id]["report_data"] = report_data
    else:
        current_report_data = report_data


def _dict_to_finding(f: Dict[str, Any]) -> Finding:
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
        mitre_id=f.get("mitre_id"),
        mitre_tactic=f.get("mitre_tactic"),
        mitre_technique=f.get("mitre_technique"),
        cwe_id=f.get("cwe_id"),
        cve_id=f.get("cve_id"),
        stride_category=f.get("stride_category"),
        compliance_controls=f.get("compliance_controls", {}),
        status=f.get("status", "OPEN"),
        status_comment=f.get("status_comment"),
        status_updated_at=f.get("status_updated_at"),
    )


def clean_filename(name: str) -> str:
    """Sanitizes user input to prevent path traversal in file operations."""
    return os.path.basename(name).replace("..", "").strip()


def _apply_overrides_to_dict(
    report_data: Dict[str, Any],
    overrides_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Applies persisted overrides to in-memory report dict and recalculates status counts.

    Args:
        report_data: The report dict to patch in-place.
        overrides_path: Path to the overrides JSON file. If None, uses the legacy
            ``audit_status_overrides.json`` in the current working directory.
    """
    if not report_data or "findings" not in report_data:
        return report_data

    overrides_file = overrides_path or os.path.join(os.getcwd(), "audit_status_overrides.json")
    overrides = {}
    global_file = os.path.join(os.getcwd(), "audit_status_overrides.json")
    if os.path.exists(global_file):
        try:
            with open(global_file, "r", encoding="utf-8") as f:
                overrides.update(json.load(f))
        except Exception as e:
            logger.debug("Failed reading global overrides: %s", e)

    if overrides_file and os.path.exists(overrides_file) and os.path.abspath(overrides_file) != os.path.abspath(global_file):
        try:
            with open(overrides_file, "r", encoding="utf-8") as f:
                overrides.update(json.load(f))
        except Exception as e:
            logger.debug("Failed reading project overrides in web app: %s", e)

    status_counts = {"OPEN": 0, "RESOLVED": 0, "AS_DESIGNED": 0}
    active_sev_counts = {s.value: 0 for s in Severity}

    for finding in report_data.get("findings", []):
        norm_path = os.path.normpath(finding.get("file_path", "")).replace("\\", "/")
        fid = finding.get("id", "")
        ln = finding.get("line_number")
        keys = [
            f"{fid}|{norm_path}|{ln}",
            f"{fid}|{norm_path}",
            fid,
        ]
        override = None
        for k in keys:
            if k in overrides:
                override = overrides[k]
                break

        if override:
            finding["status"] = override.get("status", finding.get("status", "OPEN"))
            finding["status_comment"] = override.get("comment", finding.get("status_comment"))
            finding["status_updated_at"] = override.get("updated_at", finding.get("status_updated_at"))
        else:
            if "status" not in finding:
                finding["status"] = "OPEN"

        st = (finding.get("status") or "OPEN").upper()
        status_counts[st] = status_counts.get(st, 0) + 1
        if st == "OPEN":
            sev = finding.get("severity", "MEDIUM")
            if sev in active_sev_counts:
                active_sev_counts[sev] += 1

    report_data["status_counts"] = status_counts
    report_data["active_severity_counts"] = active_sev_counts
    return report_data


def load_initial_report():
    """Attempts to load the most recent report on startup so dashboard is pre-populated."""
    global current_report_data, active_project_id
    if os.getenv("CYBERAUDIT_ORGANIZATION"):
        active_project_id = next(iter(projects), None)
        current_report_data = None
        return
    if "proj_vigiacad" in projects:
        active_project_id = "proj_vigiacad"
    elif projects:
        active_project_id = next(iter(projects))

    candidates = [
        "reports/audit_report_vigiacad.json",
        "/home/psypp0/Documentos/VigiaCAD-app-main/audit_report.json",
        "audit_report.json",
        "self_audit_latest.json",
    ]
    for c in candidates:
        try:
            with open(c, "r", encoding="utf-8") as f:
                current_report_data = json.load(f)
                _apply_overrides_to_dict(current_report_data)
                if active_project_id and active_project_id in projects:
                    projects[active_project_id]["report_data"] = current_report_data
                return
        except FileNotFoundError:
            continue
        except Exception as e:
            logger.debug("Failed loading initial report candidate %s: %s", c, e)


# Startup: load persisted projects and legacy report
_load_projects()
load_initial_report()



# Pydantic Request Models
class ScanRequest(BaseModel):
    path: str
    archetype: str = "full"
    exclude_vendor: bool = True
    run_ai: bool = False
    ai_provider: str = "auto"


class ChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = None
    provider: str = "auto"
    persona: str = "appsec_auditor"


class QaRequest(BaseModel):
    pillar: str = "all"


class UpdateFindingStatusRequest(BaseModel):
    finding_id: str
    file_path: str
    line_number: Optional[int] = None
    status: str  # OPEN, RESOLVED, AS_DESIGNED
    comment: Optional[str] = None


class CreateProjectRequest(BaseModel):
    name: str
    path: str
    archetype: str = "full"
    description: str = ""


class ReverifyFindingRequest(BaseModel):
    finding_id: str
    file_path: str
    line_number: Optional[int] = None
    scanner_name: Optional[str] = None
    project_id: Optional[str] = None


class MarkdownReportRequest(BaseModel):
    target_dir: Optional[str] = None
    audit_number: Optional[int] = None


class UploadRemediationRequest(BaseModel):
    content: Optional[str] = None
    filename: Optional[str] = "subsanacion.md"
    auto_reverify: bool = True
    provider: str = "auto"
    project_id: Optional[str] = None


# ─── Project Management Endpoints ────────────────────────────────────────────

@app.get("/api/projects")
def list_projects():
    """Lists all known projects and the currently active project."""
    proj_list = []
    for pid, proj in projects.items():
        report = proj.get("report_data")
        proj_list.append({
            "id": pid,
            "name": proj.get("name", pid),
            "path": proj.get("path", ""),
            "archetype": proj.get("archetype", "full"),
            "description": proj.get("description", ""),
            "created_at": proj.get("created_at", ""),
            "last_scanned": proj.get("last_scanned"),
            "total_findings": len(report.get("findings", [])) if report else 0,
            "status_counts": report.get("status_counts", {}) if report else {},
            "is_active": pid == active_project_id,
        })
    return {
        "status": "ok",
        "active_project_id": active_project_id,
        "projects": proj_list,
    }


@app.post("/api/projects")
def create_project(req: CreateProjectRequest):
    """Creates a new project. Optionally activates it immediately."""
    global active_project_id
    if not os.path.exists(req.path):
        raise HTTPException(status_code=400, detail=f"Path does not exist: {req.path}")

    import uuid
    project_id = f"proj_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    projects[project_id] = {
        "id": project_id,
        "name": req.name,
        "path": req.path,
        "archetype": req.archetype,
        "description": req.description,
        "created_at": now,
        "last_scanned": None,
        "report_data": None,
    }
    _save_projects()
    # Auto-activate if it's the first project
    if active_project_id is None:
        active_project_id = project_id
    return {
        "status": "ok",
        "project": {k: v for k, v in projects[project_id].items() if k != "report_data"},
        "active_project_id": active_project_id,
    }


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str):
    """Deletes a project and its overrides file. Deactivates if it was active."""
    global active_project_id
    if project_id not in projects:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")

    proj_name = projects[project_id].get("name", project_id)
    del projects[project_id]

    # Clean up overrides file with validated filename guard
    clean_id = clean_filename(project_id)
    overrides_path = _get_project_overrides_path(clean_id)
    if os.path.exists(overrides_path):
        try:
            os.remove(overrides_path)
        except Exception:
            pass

    if active_project_id == project_id:
        active_project_id = next(iter(projects), None)

    _save_projects()
    return {
        "status": "ok",
        "message": f"Proyecto '{proj_name}' eliminado.",
        "active_project_id": active_project_id,
    }


@app.post("/api/projects/{project_id}/activate")
def activate_project(project_id: str):
    """Sets the active project. All subsequent operations use this project's report."""
    global active_project_id
    if project_id not in projects:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")
    active_project_id = project_id
    proj = projects[project_id]
    report = proj.get("report_data")
    return {
        "status": "ok",
        "active_project_id": active_project_id,
        "project_name": proj.get("name"),
        "has_report": report is not None,
        "total_findings": len(report.get("findings", [])) if report else 0,
        "status_counts": report.get("status_counts", {}) if report else {},
        "report": report,
    }


@app.get("/api/projects/{project_id}/report")
def get_project_report(project_id: str):
    """Returns the current audit report for a specific project."""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")
    report = projects[project_id].get("report_data")
    if not report:
        return {"status": "empty", "message": "Proyecto sin escaneo. Ejecuta una auditoría primero."}
    return {"status": "ok", "report": report}


@app.post("/api/projects/{project_id}/scan")
async def scan_project(project_id: str, req: ScanRequest):
    """Scans the target path for a specific project and stores results in that project."""
    global active_project_id
    if project_id not in projects:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")

    proj = projects[project_id]
    target_path = req.path or proj.get("path", "")
    if not os.path.exists(target_path):
        raise HTTPException(status_code=400, detail=f"Path does not exist: {target_path}")

    def _do_scan():
        engine = AuditEngine(archetype=req.archetype, exclude_vendor=req.exclude_vendor)
        report = engine.scan_path(target_path)
        if req.run_ai:
            report = co_analyst.analyze(report, provider_mode=req.ai_provider)
        report_dict = report.to_dict()
        _apply_overrides_to_dict(report_dict, overrides_path=_get_project_overrides_path(project_id))
        try:
            md_path, audit_num = save_markdown_audit_report(report, target_path)
            report_dict["audit_md_path"] = md_path
            report_dict["audit_number"] = audit_num
            logger.info("Project %s: Generated markdown audit report: %s (#%d)", project_id, md_path, audit_num)
        except Exception as e:
            logger.warning("Could not auto-generate markdown audit report in project: %s", e)
        return report_dict

    loop = asyncio.get_event_loop()
    report_dict = await loop.run_in_executor(executor, _do_scan)

    projects[project_id]["report_data"] = report_dict
    projects[project_id]["last_scanned"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    projects[project_id]["path"] = target_path
    projects[project_id]["archetype"] = req.archetype
    projects[project_id]["audit_md_path"] = report_dict.get("audit_md_path")
    _save_projects()

    # Auto-activate this project
    active_project_id = project_id
    return {"status": "ok", "report": report_dict}


@app.post("/api/projects/{project_id}/findings/status")
def update_project_finding_status(project_id: str, req: UpdateFindingStatusRequest):
    """Updates the triage status of a finding within a specific project."""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail=f"Project not found: {project_id}")
    if req.status not in ("OPEN", "RESOLVED", "AS_DESIGNED"):
        raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")

    overrides_file = _get_project_overrides_path(project_id)
    overrides = {}
    if os.path.exists(overrides_file):
        try:
            with open(overrides_file, "r", encoding="utf-8") as f:
                overrides = json.load(f)
        except Exception as e:
            logger.debug("Error loading project overrides: %s", e)

    norm_path = os.path.normpath(req.file_path).replace("\\", "/")
    override_key = f"{req.finding_id}|{norm_path}|{req.line_number}" if req.line_number is not None else f"{req.finding_id}|{norm_path}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    default_comment = (
        "Marcado como solucionado" if req.status == "RESOLVED"
        else "Comportamiento por diseño verificado" if req.status == "AS_DESIGNED"
        else "Reabierto"
    )
    overrides[override_key] = {
        "finding_id": req.finding_id,
        "file_path": req.file_path,
        "line_number": req.line_number,
        "status": req.status,
        "comment": req.comment.strip() if req.comment and req.comment.strip() else default_comment,
        "updated_at": timestamp,
    }

    try:
        with open(overrides_file, "w", encoding="utf-8") as f:
            json.dump(overrides, f, indent=2, ensure_ascii=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not persist override: {e}")

    report = projects[project_id].get("report_data")
    if report:
        _apply_overrides_to_dict(report, overrides_path=overrides_file)
        projects[project_id]["report_data"] = report

    return {
        "status": "ok",
        "message": f"Estado del hallazgo actualizado a {req.status}",
        "override_key": override_key,
        "finding_status": req.status,
        "status_counts": report.get("status_counts") if report else None,
        "active_severity_counts": report.get("active_severity_counts") if report else None,
    }


@app.get("/api/presets")
def get_presets():
    """Returns quick preset paths for one-click auditing."""
    cwd = os.getcwd()
    torrent_env = os.getenv("TARGET_PRESET_PATH")
    torrent_path = torrent_env if torrent_env else os.path.join(cwd, "torrent-streamer-pro-main")
    presets = []
    if os.path.exists(torrent_path):
        presets.append({
            "name": "Target: Torrent Streamer Pro (Recalibrado)",
            "path": torrent_path,
            "archetype": "client",
            "desc": "Aplicación de streaming P2P nativa de escritorio (Electron / C++).",
        })
    presets.append({
        "name": "Target: Repositorio CyberAudit Suite",
        "path": cwd,
        "archetype": "full",
        "desc": "Auditoría interna de seguridad del propio motor y sus módulos.",
    })
    tests_dir = os.path.join(cwd, "tests")
    if os.path.exists(tests_dir):
        presets.append({
            "name": "Target: Batería de Pruebas QA (Synthetic Fixtures)",
            "path": tests_dir,
            "archetype": "full",
            "desc": "Validación contra vectores sintéticos de prueba y controles de seguridad.",
        })
    return presets


@app.get("/api/report/latest")
def get_latest_report():
    """Returns the current loaded audit report (active project or legacy global)."""
    report = _get_active_report()
    if not report:
        return {"status": "empty", "message": "No audit report currently loaded. Run a scan or select a preset."}
    active_proj = projects.get(active_project_id) if active_project_id else None
    return {
        "status": "ok",
        "report": report,
        "active_project_id": active_project_id,
        "active_project_name": active_proj.get("name") if active_proj else None,
    }


def _execute_scan(req: ScanRequest, project_id: Optional[str] = None) -> Dict[str, Any]:
    global current_report_data, is_scanning, scan_status
    try:
        is_scanning = True
        scan_status = f"Escaneando directorio {req.path} (Arquetipo: {req.archetype})..."
        engine = AuditEngine(archetype=req.archetype, exclude_vendor=req.exclude_vendor)
        report = engine.scan_path(req.path)

        if req.run_ai:
            scan_status = f"Ejecutando síntesis ejecutiva con IA Co-Analyst ({req.ai_provider})..."
            report = co_analyst.analyze(report, provider_mode=req.ai_provider)

        report_dict = report.to_dict()
        # Use project-specific overrides file when a project is active
        overrides_path = _get_project_overrides_path(project_id) if project_id else None
        _apply_overrides_to_dict(report_dict, overrides_path=overrides_path)

        # Automatically generate Auditoria_<num>_<fecha>.md directly in the target software's root directory
        try:
            md_path, audit_num = save_markdown_audit_report(report, req.path)
            report_dict["audit_md_path"] = md_path
            report_dict["audit_number"] = audit_num
            logger.info("Generated markdown audit report: %s (#%d)", md_path, audit_num)
        except Exception as e:
            logger.warning("Could not auto-generate markdown audit report: %s", e)

        if project_id and project_id in projects:
            projects[project_id]["report_data"] = report_dict
        else:
            current_report_data = report_dict
        # Also update project metadata
        if project_id and project_id in projects:
            projects[project_id]["last_scanned"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            projects[project_id]["path"] = req.path
            projects[project_id]["audit_md_path"] = report_dict.get("audit_md_path")
            _save_projects()
        scan_status = "Auditoría completada." if report.execution_status == "PASS" else "Auditoría incompleta: consulte los errores de ejecución."
        return report_dict
    finally:
        is_scanning = False


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    """Triggers an audit scan synchronously via threadpool."""
    if not os.path.exists(req.path):
        raise HTTPException(status_code=400, detail=f"Target path does not exist: {req.path}")

    loop = asyncio.get_event_loop()
    report_dict = await loop.run_in_executor(executor, _execute_scan, req, active_project_id)
    return {"status": "ok", "report": report_dict}


@app.get("/api/scan/status")
def get_scan_status():
    """Returns current scanner execution state."""
    return {"is_scanning": is_scanning, "status": scan_status}


class LiveWebAuditRequest(BaseModel):
    model_config = {"extra": "forbid"}
    url: str
    scope_path: str
    browsers: List[str] = Field(default_factory=lambda: ["chromium"])
    expect_pwa: StrictBool = False
    journey_path: Optional[str] = None
    offline_selector: Optional[str] = None
    observation_ms: int = Field(default=2000, ge=250, le=30000)


@app.get("/api/audit-tools")
def audit_tool_inventory():
    from cyberaudit.integrations.audit_pipeline import inventory
    return {"tools": inventory()}


@app.post("/api/audit-web")
async def run_live_web_audit(req: LiveWebAuditRequest):
    from functools import partial
    from cyberaudit.kali.scope import ScopeGuard, ScopeViolationError
    from cyberaudit.kali.tool_registry import RiskLevel
    from cyberaudit.web_auditor.orchestrator import WebAuditorOrchestrator
    from cyberaudit.core.target_verifier import TargetVerificationError
    try:
        guard = ScopeGuard.from_file(req.scope_path)
        guard.authorize(req.url, RiskLevel.ACTIVE)
        project_id = active_project_id
        call = partial(WebAuditorOrchestrator().audit, req.url,
            allow_local=guard.scope.allow_private, browsers=req.browsers,
            expect_pwa=req.expect_pwa, journey_path=req.journey_path,
            offline_selector=req.offline_selector, observation_ms=req.observation_ms)
        report = await asyncio.get_running_loop().run_in_executor(executor, call)
        report_data = report.to_dict()
        if project_id and project_id in projects:
            projects[project_id]["report_data"] = report_data
            _save_projects()
        return {"status": report.execution_status, "report": report_data}
    except (ValueError, OSError, ScopeViolationError, TargetVerificationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class BusinessAuditRequest(BaseModel):
    model_config = {"extra": "forbid"}
    plan_path: str


@app.post("/api/audit-business")
async def run_business_endpoint(req: BusinessAuditRequest):
    from cyberaudit.web_auditor.business import run_business_audit
    try:
        evidence, directory = await asyncio.get_running_loop().run_in_executor(executor, run_business_audit, req.plan_path)
        return {"status": evidence["report"]["status"], "evidence": evidence, "path": str(directory / "report.json")}
    except (ValueError, OSError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=f"Plan rechazado: {type(exc).__name__}") from exc


@app.post("/api/findings/status")
def update_finding_status(req: UpdateFindingStatusRequest):
    """
    Updates the triage status of a finding (OPEN, RESOLVED, AS_DESIGNED).
    When a project is active, uses the project's isolated overrides file.
    Otherwise, uses the legacy audit_status_overrides.json in CWD.
    """
    if req.status not in ("OPEN", "RESOLVED", "AS_DESIGNED"):
        raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")

    # Route to project-specific or legacy overrides file
    if active_project_id and active_project_id in projects:
        overrides_file = _get_project_overrides_path(active_project_id)
    else:
        overrides_file = os.path.join(os.getcwd(), "audit_status_overrides.json")

    overrides = {}
    if os.path.exists(overrides_file):
        try:
            with open(overrides_file, "r", encoding="utf-8") as f:
                overrides = json.load(f)
        except Exception as e:
            logger.debug("Error loading existing overrides: %s", e)

    norm_path = os.path.normpath(req.file_path).replace("\\", "/")
    override_key = f"{req.finding_id}|{norm_path}|{req.line_number}" if req.line_number is not None else f"{req.finding_id}|{norm_path}"

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    default_comment = "Marcado como solucionado" if req.status == "RESOLVED" else "Comportamiento por diseño verificado" if req.status == "AS_DESIGNED" else "Reabierto"
    overrides[override_key] = {
        "finding_id": req.finding_id,
        "file_path": req.file_path,
        "line_number": req.line_number,
        "status": req.status,
        "comment": req.comment.strip() if req.comment and req.comment.strip() else default_comment,
        "updated_at": timestamp,
    }

    try:
        with open(overrides_file, "w", encoding="utf-8") as f:
            json.dump(overrides, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error("Failed saving overrides to %s: %s", overrides_file, e)
        raise HTTPException(status_code=500, detail=f"Could not persist override: {e}")

    report = _get_active_report()
    if report:
        _apply_overrides_to_dict(report, overrides_path=overrides_file)
        _set_active_report(report)

    return {
        "status": "ok",
        "message": f"Estado del hallazgo actualizado a {req.status}",
        "override_key": override_key,
        "finding_status": req.status,
        "status_counts": report.get("status_counts") if report else None,
        "active_severity_counts": report.get("active_severity_counts") if report else None,
    }


@app.post("/api/findings/reverify")
def reverify_finding_endpoint(req: ReverifyFindingRequest):
    """
    Re-tests code against the specific scanner on disk to verify if a finding was genuinely resolved.
    Automatically updates the in-memory report, persistence overrides, and the Auditoria_*.md report.
    """
    proj_id = req.project_id or active_project_id
    overrides_file = _get_project_overrides_path(proj_id) if proj_id and proj_id in projects else os.path.join(os.getcwd(), "audit_status_overrides.json")

    report_dict = None
    if proj_id and proj_id in projects:
        report_dict = projects[proj_id].get("report_data")
    if not report_dict:
        report_dict = current_report_data

    target_root = None
    if report_dict:
        target_root = report_dict.get("target_path")
    if not target_root and proj_id and proj_id in projects:
        target_root = projects[proj_id].get("path")
    if not target_root:
        target_root = os.getcwd()

    reverifier = AuditReverifier()
    result = reverifier.reverify_finding(
        finding_id=req.finding_id,
        file_path=req.file_path,
        line_number=req.line_number,
        scanner_name=req.scanner_name,
        target_root=target_root,
        report_dict=report_dict,
        overrides_file=overrides_file,
    )

    if report_dict:
        _apply_overrides_to_dict(report_dict, overrides_path=overrides_file)
        _set_active_report(report_dict)

    return {
        "status": "ok",
        "result": result,
        "is_resolved": result.get("is_resolved", False),
        "message": result.get("message"),
        "status_counts": report_dict.get("status_counts") if report_dict else {},
        "active_severity_counts": report_dict.get("active_severity_counts") if report_dict else {},
        "updated_markdown_report": result.get("updated_markdown_report"),
    }


@app.post("/api/projects/{project_id}/findings/reverify")
def reverify_project_finding_endpoint(project_id: str, req: ReverifyFindingRequest):
    req.project_id = project_id
    return reverify_finding_endpoint(req)


@app.post("/api/projects/{project_id}/findings/reverify-all")
def reverify_project_all_findings_endpoint(project_id: str):
    return reverify_all_findings_endpoint(project_id=project_id)


@app.post("/api/findings/reverify-all")
def reverify_all_findings_endpoint(project_id: Optional[str] = None):
    """Re-verifies all findings currently in report by executing scans across all files."""
    proj_id = project_id or active_project_id
    overrides_file = _get_project_overrides_path(proj_id) if proj_id and proj_id in projects else os.path.join(os.getcwd(), "audit_status_overrides.json")

    report_dict = None
    if proj_id and proj_id in projects:
        report_dict = projects[proj_id].get("report_data")
    if not report_dict:
        report_dict = current_report_data

    if not report_dict:
        raise HTTPException(status_code=400, detail="No audit report currently loaded.")

    target_root = report_dict.get("target_path") or os.getcwd()
    reverifier = AuditReverifier()
    summary = reverifier.reverify_all_in_report(
        report_dict=report_dict,
        target_root=target_root,
        overrides_file=overrides_file,
    )
    _apply_overrides_to_dict(report_dict, overrides_path=overrides_file)
    _set_active_report(report_dict)

    return {
        "status": "ok",
        "summary": summary,
        "status_counts": report_dict.get("status_counts"),
        "active_severity_counts": report_dict.get("active_severity_counts"),
    }


@app.post("/api/report/generate-markdown")
def generate_markdown_endpoint(req: MarkdownReportRequest):
    """Generates or refreshes the Auditoria_<num>_<fecha>.md report file directly in target dir."""
    report_dict = _get_active_report()
    if not report_dict:
        raise HTTPException(status_code=400, detail="No audit report loaded.")

    findings = [_dict_to_finding(f) for f in report_dict.get("findings", [])]
    report = ScanReport(
        target_path=report_dict.get("target_path", os.getcwd()),
        timestamp=report_dict.get("timestamp", ""),
        duration_seconds=report_dict.get("duration_seconds", 0.0),
        files_scanned=report_dict.get("files_scanned", 0),
        scanners_executed=report_dict.get("scanners_executed", []),
        execution_status=report_dict.get("execution_status", "NOT_RUN"),
        execution_errors=report_dict.get("execution_errors", []),
        scanner_results=report_dict.get("scanner_results", []),
        artifact_digest=report_dict.get("artifact_digest"),
        findings=findings,
        executive_summary=report_dict.get("executive_summary"),
        ai_verdict=report_dict.get("ai_verdict"),
        ai_provider_used=report_dict.get("ai_provider_used"),
    )

    target_dir = req.target_dir or report_dict.get("target_path") or os.getcwd()
    md_path, num = save_markdown_audit_report(report, target_dir, audit_number=req.audit_number)
    report_dict["audit_md_path"] = md_path
    report_dict["audit_number"] = num
    _set_active_report(report_dict)

    return {
        "status": "ok",
        "audit_md_path": md_path,
        "audit_number": num,
        "filename": os.path.basename(md_path),
    }


# ─── Remediation & Auditor-Developer Collaboration Endpoints ────────────────

def _execute_remediation_pipeline(
    markdown_content: str,
    filename: str = "subsanacion.md",
    auto_reverify: bool = True,
    provider: str = "auto",
    project_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Helper that runs the remediation parser, reverifier, persistence, and AI Co-Analyst debrief."""
    proj_id = project_id or active_project_id
    overrides_file = (
        _get_project_overrides_path(proj_id)
        if proj_id and proj_id in projects
        else os.path.join(os.getcwd(), "audit_status_overrides.json")
    )

    report_dict = None
    if proj_id and proj_id in projects:
        report_dict = projects[proj_id].get("report_data")
    if not report_dict:
        report_dict = current_report_data

    if not report_dict:
        raise HTTPException(
            status_code=400,
            detail="No hay ningún informe de auditoría cargado en la plataforma. Ejecuta un escaneo primero.",
        )

    target_root = report_dict.get("target_path")
    if not target_root and proj_id and proj_id in projects:
        target_root = projects[proj_id].get("path")
    if not target_root:
        target_root = os.getcwd()

    res = remediation_manager.process_remediation_markdown(
        markdown_content=markdown_content,
        report_dict=report_dict,
        target_root=target_root,
        overrides_file=overrides_file,
        auto_reverify=auto_reverify,
    )

    if res.get("status") == "warning":
        return res

    # Generate AI Co-Analyst review and debrief for developer
    ai_feedback = co_analyst.review_developer_remediation(
        remediation_markdown=markdown_content,
        remediation_summary=res,
        report_context=report_dict,
        provider_mode=provider,
    )
    res["ai_review"] = ai_feedback.get("review")
    res["ai_provider"] = ai_feedback.get("provider")
    res["report"] = report_dict

    # Update active report and projects metadata
    _set_active_report(report_dict)
    if proj_id and proj_id in projects:
        projects[proj_id]["report_data"] = report_dict
        _save_projects()

    return res


@app.post("/api/remediation/upload-md")
async def upload_remediation_md(req: UploadRemediationRequest):
    """
    Ingests a developer's Markdown (.md) remediation response.
    Parses remediated findings, optionally re-verifies against code on disk,
    updates platform triage states/overrides, and triggers an AI Co-Analyst review.
    """
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="El contenido Markdown de subsanación no puede estar vacío.")

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        _execute_remediation_pipeline,
        req.content,
        req.filename or "subsanacion.md",
        req.auto_reverify,
        req.provider,
        req.project_id,
    )
    return result


@app.post("/api/remediation/upload-file")
async def upload_remediation_file(
    file: UploadFile = File(...),
    auto_reverify: bool = Form(True),
    provider: str = Form("auto"),
    project_id: Optional[str] = Form(None),
):
    """
    Multipart file upload endpoint for developer's .md remediation document.
    """
    if not file.filename.lower().endswith((".md", ".markdown", ".txt")):
        raise HTTPException(status_code=400, detail="El archivo debe tener extensión .md o .markdown.")

    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content = raw_bytes.decode("latin-1", errors="replace")

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        _execute_remediation_pipeline,
        content,
        file.filename,
        auto_reverify,
        provider,
        project_id,
    )
    return result


@app.get("/api/remediation/template")
def get_remediation_template(project_id: Optional[str] = None):
    """
    Generates a pre-filled Markdown remediation response template for the active project
    so developers can directly fill in their fixes and justifications.
    """
    proj_id = project_id or active_project_id
    report_dict = None
    if proj_id and proj_id in projects:
        report_dict = projects[proj_id].get("report_data")
    if not report_dict:
        report_dict = current_report_data

    if not report_dict:
        report_dict = {"target_path": os.getcwd(), "findings": []}

    template_md = RemediationManager.generate_developer_response_template(report_dict)
    return {
        "status": "ok",
        "template": template_md,
        "filename": "Plantilla_Respuesta_Subsanacion.md",
        "total_open_findings": len([f for f in report_dict.get("findings", []) if (f.get("status") or "OPEN").upper() == "OPEN"]),
    }


@app.get("/api/report/export/html")
def export_html_report():
    """Exports current report to standalone HTML."""
    report_data = _get_active_report()
    if not report_data:
        raise HTTPException(status_code=404, detail="No report available to export.")

    # Reconstruct ScanReport object
    findings = [_dict_to_finding(f) for f in report_data.get("findings", [])]
    report = ScanReport(
        target_path=report_data.get("target_path", ""),
        timestamp=report_data.get("timestamp", ""),
        duration_seconds=report_data.get("duration_seconds", 0.0),
        files_scanned=report_data.get("files_scanned", 0),
        scanners_executed=report_data.get("scanners_executed", []),
        execution_status=report_data.get("execution_status", "NOT_RUN"),
        execution_errors=report_data.get("execution_errors", []),
        scanner_results=report_data.get("scanner_results", []),
        artifact_digest=report_data.get("artifact_digest"),
        findings=findings,
        executive_summary=report_data.get("executive_summary"),
        ai_verdict=report_data.get("ai_verdict"),
        ai_provider_used=report_data.get("ai_provider_used"),
    )
    reporter = Reporter(report)
    html_content = reporter.generate_html_content()
    return HTMLResponse(content=html_content, media_type="text/html")


# ─── Specialized Pillar Diagnostics (QA, UI/UX, Architecture) ───────────────

@app.get("/api/qa/diagnostics")
def get_qa_diagnostics(project_id: Optional[str] = None):
    """
    Extracts deep, actionable Software QA & Code Quality telemetry from the active audit report:
    - Resource leaks (unclosed files, sockets, dangling intervals)
    - Swallowed exceptions & silent try/catch blocks
    - Concurrency risks & TOCTOU conditions
    - Test coverage smells & placebo test suites
    - Complexity hotspots & maintainability
    """
    proj_id = project_id or active_project_id
    report = projects[proj_id].get("report_data") if (proj_id and proj_id in projects) else current_report_data
    if not report:
        return {
            "has_report": False,
            "health_score": None,
            "total_qa": 0,
            "open_qa": 0,
            "resolved_qa": 0,
            "categories": {
                "swallowed_exceptions": [],
                "resource_leaks": [],
                "concurrency_risks": [],
                "test_coverage_smells": [],
                "complexity_hotspots": [],
                "clean_code_violations": [],
            }
        }

    findings = report.get("findings", [])
    qa_findings = [f for f in findings if (f.get("pillar") == Pillar.SOFTWARE_QA.value or f.get("pillar") == Pillar.SOFTWARE_QA.name or "QA-" in (f.get("id") or "") or "CLEAN-" in (f.get("id") or ""))]

    categories = {
        "swallowed_exceptions": [],
        "resource_leaks": [],
        "concurrency_risks": [],
        "test_coverage_smells": [],
        "complexity_hotspots": [],
        "clean_code_violations": [],
    }

    for f in qa_findings:
        fid = (f.get("id") or "").upper()
        title = (f.get("title") or "").upper()
        if "SWALLOWED" in fid or "CATCH" in fid or "EXCEPTION" in title:
            categories["swallowed_exceptions"].append(f)
        elif "LEAK" in fid or "RESOURCE" in fid or "TIMER" in fid or "SOCKET" in fid or "UNCLOSED" in title:
            categories["resource_leaks"].append(f)
        elif "CONCURRENCY" in fid or "RACE" in fid or "TOCTOU" in fid or "ASYNC" in title:
            categories["concurrency_risks"].append(f)
        elif "COVERAGE" in fid or "TEST" in fid or "ASSERTION" in title or "MOCK" in title:
            categories["test_coverage_smells"].append(f)
        elif "COMPLEXITY" in fid or "CYCLOMATIC" in title or "MAINTAINABILITY" in fid:
            categories["complexity_hotspots"].append(f)
        else:
            categories["clean_code_violations"].append(f)

    open_qa = [f for f in qa_findings if (f.get("status") or "OPEN").upper() == "OPEN"]
    resolved_qa = [f for f in qa_findings if (f.get("status") or "").upper() in ("RESOLVED", "AS_DESIGNED")]

    penalty = sum(15 if f.get("severity") in ("CRITICAL", "HIGH") else 5 for f in open_qa)
    health_score = max(10, min(100, 100 - penalty)) if qa_findings else None

    return {
        "has_report": True,
        "target_path": report.get("target_path", ""),
        "health_score": health_score,
        "score_method": "finding_severity_heuristic",
        "certification_status": "NOT_EVALUATED",
        "total_qa": len(qa_findings),
        "open_qa": len(open_qa),
        "resolved_qa": len(resolved_qa),
        "categories": categories,
    }


@app.get("/api/uiux/diagnostics")
def get_uiux_diagnostics(project_id: Optional[str] = None):
    """
    Extracts deep, actionable UI/UX & Accessibility telemetry from the active audit report:
    - WCAG 2.1 / 2.2 violations (alt text, aria labels, tabindexes)
    - Responsive ergonomics & touch targets (<48px)
    - Color contrast & typography readability
    - Jakob Nielsen usability heuristics (focus outlines, form autocompletes, motion)
    """
    proj_id = project_id or active_project_id
    report = projects[proj_id].get("report_data") if (proj_id and proj_id in projects) else current_report_data
    if not report:
        return {
            "has_report": False,
            "health_score": None,
            "wcag_compliance_level": "N/A",
            "total_uiux": 0,
            "open_uiux": 0,
            "resolved_uiux": 0,
            "categories": {
                "wcag_violations": [],
                "responsive_ergonomics": [],
                "contrast_typography": [],
                "nielsen_heuristics": [],
            }
        }

    findings = report.get("findings", [])
    uiux_findings = [f for f in findings if (f.get("pillar") == Pillar.UI_UX.value or f.get("pillar") == Pillar.UI_UX.name or "UIUX-" in (f.get("id") or "") or "A11Y" in (f.get("id") or ""))]

    categories = {
        "wcag_violations": [],
        "responsive_ergonomics": [],
        "contrast_typography": [],
        "nielsen_heuristics": [],
    }

    for f in uiux_findings:
        fid = (f.get("id") or "").upper()
        title = (f.get("title") or "").upper()
        if "A11Y" in fid or "WCAG" in title or "ALT" in fid or "LABEL" in fid or "TABINDEX" in fid:
            categories["wcag_violations"].append(f)
        elif "RESPONSIVE" in fid or "TOUCH" in fid or "VIEWPORT" in fid or "ERGONOMIC" in title:
            categories["responsive_ergonomics"].append(f)
        elif "CONTRAST" in fid or "TYPOGRAPHY" in fid or "FONT" in fid or "COLOR" in title:
            categories["contrast_typography"].append(f)
        else:
            categories["nielsen_heuristics"].append(f)

    open_uiux = [f for f in uiux_findings if (f.get("status") or "OPEN").upper() == "OPEN"]
    resolved_uiux = [f for f in uiux_findings if (f.get("status") or "").upper() in ("RESOLVED", "AS_DESIGNED")]

    penalty = sum(15 if f.get("severity") in ("CRITICAL", "HIGH") else 6 for f in open_uiux)
    health_score = max(10, min(100, 100 - penalty)) if uiux_findings else None

    compliance = "No evaluada: requiere cobertura completa y revisión manual"

    return {
        "has_report": True,
        "target_path": report.get("target_path", ""),
        "health_score": health_score,
        "score_method": "finding_severity_heuristic",
        "certification_status": "NOT_EVALUATED",
        "wcag_compliance_level": compliance,
        "total_uiux": len(uiux_findings),
        "open_uiux": len(open_uiux),
        "resolved_uiux": len(resolved_uiux),
        "categories": categories,
    }


@app.get("/api/architecture/diagnostics")
def get_architecture_diagnostics(project_id: Optional[str] = None):
    """
    Extracts Software Architecture, Technical Debt and Structural Health telemetry:
    - Modular coupling & cohesion
    - Circular dependencies
    - Anti-patterns & Layer bypasses
    """
    proj_id = project_id or active_project_id
    report = projects[proj_id].get("report_data") if (proj_id and proj_id in projects) else current_report_data
    if not report:
        return {
            "has_report": False,
            "health_score": None,
            "total_arch": 0,
            "open_arch": 0,
            "resolved_arch": 0,
            "findings": [],
        }

    findings = report.get("findings", [])
    arch_findings = [f for f in findings if (f.get("pillar") == Pillar.ARCHITECTURE.value or f.get("pillar") == Pillar.ARCHITECTURE.name or "ARCH-" in (f.get("id") or ""))]

    open_arch = [f for f in arch_findings if (f.get("status") or "OPEN").upper() == "OPEN"]
    resolved_arch = [f for f in arch_findings if (f.get("status") or "").upper() in ("RESOLVED", "AS_DESIGNED")]

    penalty = sum(15 if f.get("severity") in ("CRITICAL", "HIGH") else 8 for f in open_arch)
    health_score = max(15, min(100, 100 - penalty)) if arch_findings else None

    return {
        "has_report": True,
        "target_path": report.get("target_path", ""),
        "health_score": health_score,
        "score_method": "finding_severity_heuristic",
        "certification_status": "NOT_EVALUATED",
        "total_arch": len(arch_findings),
        "open_arch": len(open_arch),
        "resolved_arch": len(resolved_arch),
        "findings": arch_findings,
    }


@app.post("/api/qa/run")
async def run_qa_tests(req: QaRequest):
    """Executes the automated QA verification suite and returns structured results."""
    test_targets = {
        "analyst": ("Security Analyst & DFIR", "tests/test_analyst_scanners.py"),
        "pentester": ("Penetration Testing & Red Team", "tests/test_pentester_scanners.py"),
        "engineer": ("Security Engineering & DevSecOps", "tests/test_engineer_scanners.py"),
        "ai": ("AI Security & LLM Defenses", "tests/test_ai_scanners.py"),
        "qa": ("Software QA & Code Quality", "tests/test_qa_scanners.py"),
        "uiux": ("UI/UX & Accessibility (a11y)", "tests/test_ui_ux_scanners.py"),
        "advanced_qa": ("Advanced QA & UX Heuristics", "tests/test_advanced_qa_scanners.py"),
        "arch": ("Software Architecture & Advanced Security", "tests/test_arch_and_advanced_security_scanners.py"),
        "cleancode": ("Clean Code & Anti-Hardcoding", "tests/test_clean_code_scanners.py"),
        "integration": ("Multi-Pillar Engine Integration", "tests/test_engine_integration.py"),
    }

    if req.pillar != "all" and req.pillar in test_targets:
        targets = {req.pillar: test_targets[req.pillar]}
    else:
        targets = test_targets

    results = []
    total_passed = 0
    total_failed = 0
    start_total = time.time()

    loop = asyncio.get_event_loop()

    def _run_single_test(key, name, path):
        cmd = [sys.executable, "-m", "pytest", path, "-q"]
        t0 = time.time()
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                                 cwd=Path(__file__).resolve().parents[2])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"pillar_key": key, "name": name, "file": path,
                    "passed": 0, "failed": 0, "duration": round(time.time() - t0, 2),
                    "verified": False, "exit_code": None, "execution_status": "ERROR",
                    "output": f"{type(exc).__name__}: {exc}"}
        dur = round(time.time() - t0, 2)
        out = res.stdout + res.stderr
        import re
        passed_m = re.search(r'(\d+)\s+passed', out)
        failed_m = re.search(r'(\d+)\s+failed', out)
        p_cnt = int(passed_m.group(1)) if passed_m else 0
        f_cnt = int(failed_m.group(1)) if failed_m else 0
        return {
            "pillar_key": key,
            "name": name,
            "file": path,
            "passed": p_cnt,
            "failed": f_cnt,
            "duration": dur,
            "verified": (res.returncode == 0 and f_cnt == 0 and p_cnt > 0),
            "exit_code": res.returncode,
            "execution_status": "PASS" if res.returncode == 0 and p_cnt > 0 else "ERROR",
            "output": out.strip() if res.returncode != 0 or p_cnt == 0 else "",
        }

    for key, (name, path) in targets.items():
        res = await loop.run_in_executor(executor, _run_single_test, key, name, path)
        total_passed += res["passed"]
        total_failed += res["failed"]
        results.append(res)

    total_time = round(time.time() - start_total, 2)
    return {
        "req_pillar": req.pillar,
        "all_passed": bool(results) and all(r["verified"] for r in results),
        "evidence_origin": "auditor_self_tests",
        "target_validation": "NOT_RUN",
        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_duration": total_time,
        "suites": results,
    }


@app.post("/api/qa/dynamic/run")
async def run_dynamic_pocs():
    """Legacy demonstrations cannot establish findings on an audited target."""
    return {
        "status": "NOT_RUN", "total_pocs": 0,
        "all_mitigated": False, "all_exploited": False, "results": [],
        "reason": "Las demostraciones en memoria no auditan tu sistema. Usa audit-web o external-audit con un objetivo y alcance autorizados.",
    }


@app.get("/api/qa/dynamic/report/html", response_class=HTMLResponse)
def get_dynamic_qa_report_html():
    return HTMLResponse(content="<h1>NOT_RUN</h1><p>No hay evidencia de pentesting sobre un objetivo. Las demostraciones internas no constituyen una auditoría.</p>", status_code=409)


@app.post("/api/qa/user-simulation")
async def run_user_simulation_endpoint(request: Request):
    """
    Executes automated end-to-end user simulation testing.
    Simulates real browser user clicking buttons, switching tabs, and testing interactions,
    guaranteeing zero JavaScript errors and complete UI responsiveness.
    """
    from cyberaudit.qa.user_simulation import UserSimulationEngine
    base_url = str(request.base_url).rstrip("/")

    def _do_sim():
        engine = UserSimulationEngine(base_url=base_url)
        return engine.run(headless=True)

    loop = asyncio.get_event_loop()
    report = await loop.run_in_executor(executor, _do_sim)
    return {
        "status": "ok",
        "report": report.to_dict(),
    }


@app.get("/api/ai/status")
def get_ai_status():
    """Checks LM Studio and Gemini AI connectivity."""
    diag = co_analyst.test_connection()
    return diag


@app.post("/api/ai/chat")
async def chat_ai(req: ChatRequest):
    """Interactive chat with the AI Co-Analyst, using the active project report as context."""
    loop = asyncio.get_event_loop()
    active_report = _get_active_report()

    def _do_chat():
        return co_analyst.chat(
            user_message=req.message,
            history=req.history,
            report_context=active_report,
            provider_mode=req.provider,
            persona=req.persona,
        )

    res = await loop.run_in_executor(executor, _do_chat)
    return res


@app.post("/api/ai/analyze")
async def analyze_current_report(req: BaseModel):
    """Re-analyzes current report with AI Co-Analyst and updates executive summary."""
    active_report = _get_active_report()
    if not active_report:
        raise HTTPException(status_code=400, detail="No audit report loaded.")

    findings = [_dict_to_finding(f) for f in active_report.get("findings", [])]
    report = ScanReport(
        target_path=active_report.get("target_path", ""),
        timestamp=active_report.get("timestamp", ""),
        duration_seconds=active_report.get("duration_seconds", 0.0),
        files_scanned=active_report.get("files_scanned", 0),
        scanners_executed=active_report.get("scanners_executed", []),
        execution_status=active_report.get("execution_status", "NOT_RUN"),
        execution_errors=active_report.get("execution_errors", []),
        scanner_results=active_report.get("scanner_results", []),
        artifact_digest=active_report.get("artifact_digest"),
        findings=findings,
    )

    loop = asyncio.get_event_loop()
    updated_report = await loop.run_in_executor(executor, co_analyst.analyze, report, "auto")
    active_report["executive_summary"] = updated_report.executive_summary
    active_report["ai_verdict"] = updated_report.ai_verdict
    active_report["ai_provider_used"] = updated_report.ai_provider_used
    _set_active_report(active_report)
    return {"status": "ok", "executive_summary": updated_report.executive_summary, "provider": updated_report.ai_provider_used}


@app.get("/api/knowledge/list")
def list_knowledge_articles():
    """Lists all knowledge base articles."""
    from cyberaudit.core.knowledge_base import KnowledgeBase
    kb = KnowledgeBase()
    return {"status": "ok", "total": len(kb.articles), "articles": [a.to_dict() for a in kb.articles]}


@app.get("/api/knowledge/search")
def search_knowledge_base(q: str = ""):
    """Searches the knowledge base with query string."""
    from cyberaudit.core.knowledge_base import KnowledgeBase
    kb = KnowledgeBase()
    results = kb.search(q, limit=10)
    return {"status": "ok", "query": q, "results": results}


@app.get("/api/invariants/audit")
def audit_invariants_endpoint(config: str = ".audit-rules.yaml"):
    """Audits active codebase against declarative invariant contracts."""
    from cyberaudit.core.invariants import InvariantContractParser, AstCallGraphEngine
    config_path = os.path.abspath(config)
    if not os.path.exists(config_path):
        return {"status": "error", "message": f"Config not found: {config_path}", "compliance_score": 0.0, "violations": []}

    rules = InvariantContractParser.load_from_file(config_path)
    engine = AstCallGraphEngine(base_dir=".")
    report = engine.audit_invariants(rules)
    return {
        "status": "ok",
        "data": report.to_dict()
    }


@app.post("/api/invariants/remediate")
def remediate_invariant_endpoint(req: Dict[str, Any]):
    """Runs ephemeral sandbox verification on a candidate patch."""
    from cyberaudit.core.sandbox_runner import AutonomousRemediationRunner, RemediationPatch, RemediationCategory
    runner = AutonomousRemediationRunner(base_dir=".")
    category_str = req.get("category", "input_guard")
    try:
        category = RemediationCategory(category_str)
    except ValueError:
        category = RemediationCategory.INPUT_SANITIZATION_GUARD

    patch = RemediationPatch(
        patch_id=req.get("patch_id", "PATCH-AUTO"),
        rule_id=req.get("rule_id", "INV-UNKNOWN"),
        target_file=req.get("target_file", ""),
        category=category,
        diff=req.get("diff", ""),
        repro_test_code=req.get("repro_test_code", ""),
        explanation=req.get("explanation", "")
    )
    verified_patch = runner.verify_and_close_loop(patch)
    pr_markdown = runner.generate_pull_request_markdown(verified_patch)
    return {
        "status": "ok",
        "patch": verified_patch.to_dict(),
        "pr_markdown": pr_markdown
    }


@app.post("/api/telemetry/webhook")
def telemetry_webhook(payload: Dict[str, Any]):
    """
    Closed-Loop SAST+APM webhook.
    Receives runtime error payloads from Sentry, OpenTelemetry, or generic APMs,
    correlates incidents to invariant contract rules, determines the regressing commit,
    and returns an autonomous hotfix recommendation with remediation context.
    """
    from cyberaudit.core.telemetry_feedback import TelemetryFeedbackManager
    manager = TelemetryFeedbackManager(repo_path=".")

    if "exception" in payload:
        incident = manager.parse_sentry_payload(payload)
    elif "attributes" in payload:
        incident = manager.parse_opentelemetry_payload(payload)
    else:
        incident = manager.parse_generic_payload(payload)

    report = manager.trigger_autonomous_hotfix(incident)
    return {
        "status": "ok",
        "data": report.to_dict()
    }


@app.get("/", response_class=HTMLResponse)
def serve_index():
    """Serves the interactive web dashboard."""
    template_path = Path(__file__).parent / "templates" / "index.html"
    if template_path.exists():
        with open(template_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>CyberAudit Suite API is running. Template not found.</h1>")
