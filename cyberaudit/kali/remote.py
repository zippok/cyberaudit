"""Windows controller for the Linux pentesting worker; no target text in shell commands."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from cyberaudit.kali.executor import kill_switch_engaged, KaliExecutionDisabled


def worker_command(backend: str, distribution: str = "kali-linux", ssh_host: str = "", worker_python: str = "python3") -> list[str]:
    if not re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)+|python3", worker_python):
        raise ValueError("Intérprete remoto inválido; use python3 o una ruta Linux absoluta sin espacios")
    worker = [worker_python, "-m", "cyberaudit.kali.worker"]
    if backend == "wsl":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", distribution):
            raise ValueError("Distribución WSL inválida")
        return ["wsl.exe", "--distribution", distribution, "--exec", *worker]
    if backend == "ssh":
        if not re.fullmatch(r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]*", ssh_host):
            raise ValueError("Host SSH inválido; use un alias de ~/.ssh/config o usuario@host")
        return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10", ssh_host, *worker]
    raise ValueError("El backend remoto debe ser wsl o ssh")


def invoke_worker(request: dict, backend: str, distribution: str = "kali-linux",
                  ssh_host: str = "", timeout: int = 3600, worker_python: str = "python3") -> dict:
    blocked = kill_switch_engaged()
    if blocked:
        raise KaliExecutionDisabled(blocked)
    payload = json.dumps(request, allow_nan=False).encode("utf-8")
    if len(payload) > 1024 * 1024:
        raise ValueError("Solicitud demasiado grande")
    command = worker_command(backend, distribution, ssh_host, worker_python)
    # Spool responses to disk; never buffer unbounded subprocess output in RAM.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err)
        try:
            process.communicate(payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError("Timeout del transporte. El estado remoto es desconocido; revise el worker y sus evidencias.")
        out.seek(0)
        raw = out.read(32 * 1024 * 1024 + 1)
        err.seek(0)
        diagnostic = err.read(4096).decode("utf-8", errors="replace")
        if process.returncode or len(raw) > 32 * 1024 * 1024:
            raise RuntimeError(f"Worker falló o respuesta excedida (código {process.returncode}): {diagnostic}")
        response = json.loads(raw)
        if response.get("protocol") != 1 or not response.get("ok"):
            raise RuntimeError(response.get("error", "Respuesta de worker inválida"))
        return response


def save_remote_result(response: dict, destination: str) -> None:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(response, ensure_ascii=False, indent=2), encoding="utf-8")
