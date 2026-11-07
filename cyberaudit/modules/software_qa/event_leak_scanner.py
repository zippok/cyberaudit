"""
cyberaudit/modules/software_qa/event_leak_scanner.py
====================================================
Frontend & Node.js Event Listener Memory Leak Scanner.

Audits frontend and serverless JavaScript/TypeScript code for uncollected event subscriptions:
- `socket.on(...)` / `io.on(...)` without corresponding `.off(...)` or `.removeListener(...)`.
- `EventEmitter.on(...)` subscriptions in classes or request handlers causing heap bloat.
- React `useEffect(...)` blocks attaching DOM or socket listeners without returning cleanup handlers.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Pillar, Severity


class EventListenerLeakScanner(BaseScanner):
    """
    Scanner de fugas de memoria por suscripciones a eventos no liberadas
    (EventEmitters, WebSockets, Socket.io y Listeners del DOM en React/Node).
    """

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "QA-SOCKET-LISTENER-LEAK",
                "title": "Software QA: Socket.io / WebSocket Listener Without Cleanup (.off / removeListener)",
                "pattern": re.compile(
                    r"(?:^|\s+)(?:socket|io|ws|client)\.on\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:function|\([^)]*\)\s*=>)"
                    r"(?![\s\S]{0,350}?(?:\.off\(|\.removeListener\(|\.removeAllListeners\(|return\s*\(\s*\)\s*=>))",
                    re.MULTILINE,
                ),
                "severity": Severity.HIGH,
                "description": (
                    "Suscripción a evento de socket (`socket.on(...)`) registrada sin desuscripción correspondiente "
                    "(`.off(...)` o `.removeListener(...)`). Cada reconexión o re-renderizado acumula closures en el heap, "
                    "duplicando el procesamiento de eventos y provocando fugas de memoria continuas en el navegador o servidor."
                ),
                "remediation": (
                    "Desuscriba el listener cuando el ciclo de vida del componente o conexión finalice: "
                    "`socket.off('eventName', handler)` o devuelva una función de limpieza en `useEffect`."
                ),
                "file_types": [".js", ".ts", ".jsx", ".tsx"],
            },
            {
                "id": "QA-EVENT-EMITTER-LEAK-NODE",
                "title": "Software QA: Node.js EventEmitter Listener Without Disposal Guard",
                "pattern": re.compile(
                    r"(?:^|\s+)([a-zA-Z0-9_]+)\.addListener\s*\(\s*['\"][^'\"]+['\"]"
                    r"(?![\s\S]{0,300}?(?:\.removeListener\(|\.off\(|\.removeAllListeners\())",
                    re.MULTILINE,
                ),
                "severity": Severity.MEDIUM,
                "description": (
                    "Uso de `addListener` en un EventEmitter sin mecanismo observable de liberación. "
                    "Provoca la advertencia `MaxListenersExceededWarning` de Node.js y fugas de memoria en procesos de larga duración."
                ),
                "remediation": (
                    "Utilice `emitter.once()` si el evento solo debe capturarse una vez, o elimine el listener con `emitter.removeListener()`."
                ),
                "file_types": [".js", ".ts"],
            },
            {
                "id": "QA-REACT-USEEFFECT-EVENT-LEAK",
                "title": "Software QA: React useEffect Event Listener Without Cleanup Return",
                "pattern": re.compile(
                    r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[\s\S]{1,250}?(?:window|document)\.addEventListener\s*\([^)]*\)"
                    r"(?![\s\S]{0,300}?return\s*\(\s*\)\s*=>[\s\S]{0,100}?removeEventListener)",
                    re.MULTILINE,
                ),
                "severity": Severity.HIGH,
                "description": (
                    "Llamada a `addEventListener` dentro del hook `useEffect` sin retornar una función de limpieza "
                    "que invoque `removeEventListener`. Cada desmontaje o re-renderizado dejará listeners fantasmas en el DOM."
                ),
                "remediation": (
                    "Retorne una función de limpieza en el `useEffect`: `return () => window.removeEventListener('event', handler);`."
                ),
                "file_types": [".jsx", ".tsx", ".js", ".ts"],
            },
        ]

    @property
    def name(self) -> str:
        return "EventListenerLeakScanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Detecta fugas de memoria por suscripciones a sockets, EventEmitter y DOM listeners no desuscritos."

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".jsx", ".tsx"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            if not any(file_path.endswith(ext) for ext in rule["file_types"]):
                continue

            for match in rule["pattern"].finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                lines = content.splitlines()
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)[:120]

                findings.append(
                    Finding(
                        id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        remediation=rule["remediation"],
                        cwe_id="CWE-401",
                        confidence="HIGH",
                    )
                )

        return findings

    def scan(self, file_path: str, content: str) -> List[Finding]:
        return self.scan_file(file_path, content)
