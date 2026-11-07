"""One organization per server process; confined application data paths."""
import os
import re
from pathlib import Path


def validate_runtime():
    organization = os.getenv("CYBERAUDIT_ORGANIZATION")
    if not organization:
        return
    root = Path(os.environ["CYBERAUDIT_ORGANIZATION_ROOT"]).resolve(strict=True)
    marker = root / ".cyberaudit-organization"
    if Path.cwd().resolve() != root or marker.read_text(encoding="utf-8") != organization or not os.getenv("CYBERAUDIT_RBAC_FILE"):
        raise ValueError("Arranque de organización inválido; utiliza serve_organization.py")


def confined_path(value):
    path = Path(value).resolve()
    root = os.getenv("CYBERAUDIT_ORGANIZATION_ROOT")
    if root and not path.is_relative_to(Path(root).resolve()):
        raise ValueError("Ruta fuera del espacio de la organización")
    return path


def configure_organization(identifier, root, rbac):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", identifier):
        raise ValueError("Identificador de organización inválido")
    root = Path(root).resolve()
    if any((parent / ".cyberaudit-organization").exists() for parent in root.parents):
        raise ValueError("No se permiten organizaciones anidadas")
    rbac = Path(rbac).resolve(strict=True)
    root.mkdir(parents=True, exist_ok=True)
    marker = root / ".cyberaudit-organization"
    if marker.exists():
        if marker.read_text(encoding="utf-8") != identifier:
            raise ValueError("El directorio pertenece a otra organización")
    else:
        if any(root.iterdir()):
            raise ValueError("Utiliza un directorio vacío para una organización nueva")
        with marker.open("x", encoding="utf-8") as handle:
            handle.write(identifier)
    os.environ["CYBERAUDIT_ORGANIZATION"] = identifier
    os.environ["CYBERAUDIT_ORGANIZATION_ROOT"] = str(root)
    os.environ["CYBERAUDIT_RBAC_FILE"] = str(rbac)
    os.environ["CYBERAUDIT_AUDIT_DB"] = str(root / "events.sqlite3")
    os.chdir(root)


async def validate_request(request):
    """Unported legacy routes fail closed in organization deployments."""
    path, method = request.url.path, request.method
    read = {"/api/projects", "/api/report/latest", "/api/audit-tools", "/api/scan/status", "/api/presets",
            "/api/qa/diagnostics", "/api/uiux/diagnostics", "/api/architecture/diagnostics", "/api/report/export/html"}
    write = {"/api/projects", "/api/audit-web", "/api/audit-business", "/api/scan", "/api/findings/status"}
    project_route = bool(re.fullmatch(r"/api/projects/[A-Za-z0-9_-]+/(report|activate|scan|findings/status)", path))
    if not ((method in ("GET", "HEAD") and path in read) or (method == "POST" and path in write) or project_route):
        raise ValueError("Ruta no habilitada para organizaciones")
    def inspect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key == "path" or key.endswith("_path")) and isinstance(item, str) and item:
                    confined_path(item)
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)
    inspect(dict(request.query_params))
    if method in ("POST", "PUT", "PATCH"):
        if request.headers.get("content-type", "").split(";")[0] == "application/json":
            inspect(await request.json())
