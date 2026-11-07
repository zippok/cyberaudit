"""
cyberaudit/modules/software_qa/db_pool_scanner.py
=================================================
Database Connection Pool & Cursor Exhaustion Scanner.

Audits codebase for resource starvation, socket depletion, and connection pool leaks:
- Database connections or cursors opened without context managers (`with`) or `try...finally` disposal.
- Connection pooling checkouts (`pool.getconn()`, `pool.connect()`) lacking deterministic `putconn()` / `client.release()`.
- Unhandled transaction scopes lacking atomic rollback on exception.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Pillar, Severity


class DatabasePoolExhaustionScanner(BaseScanner):
    """
    Scanner que audita el manejo seguro de conexiones y pools a bases de datos.
    Detecta fugas de descriptores de sockets y agotamiento de pools (Pool Starvation).
    """

    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "QA-DB-POOL-EXHAUSTION-PY",
                "title": "Software QA: Database Connection Checkout Without Guaranteed Disposal",
                "pattern": re.compile(
                    r"(?:^|\s+)([a-zA-Z0-9_]+)\s*=\s*(?:[a-zA-Z0-9_]+\.getconn|psycopg2\.connect|mysql\.connector\.connect|sqlite3\.connect|asyncpg\.connect)\s*\([^)]*\)"
                    r"(?![\s\S]{0,350}?(?:with\s+|\.close\(\)|\.putconn\(\1\)|finally:))",
                    re.MULTILINE,
                ),
                "severity": Severity.HIGH,
                "description": (
                    "Conexión a base de datos obtenida mediante asignación directa sin bloque 'with' "
                    "ni bloque 'try...finally'. Si ocurre una excepción antes de cerrar la conexión o devolverla al pool, "
                    "el socket queda huérfano causando agotamiento del pool (Connection Pool Starvation)."
                ),
                "remediation": (
                    "Utilice un context manager (`with pool.getconn() as conn:`) o asegure la devolución "
                    "en un bloque `finally`: `finally: pool.putconn(conn)`."
                ),
                "file_types": [".py"],
            },
            {
                "id": "QA-DB-CURSOR-LEAK-PY",
                "title": "Software QA: Database Cursor Leak Without Context Manager",
                "pattern": re.compile(
                    r"(?:^|\s+)([a-zA-Z0-9_]+)\s*=\s*[a-zA-Z0-9_]+\.cursor\s*\([^)]*\)"
                    r"(?![\s\S]{0,250}?(?:with\s+|\1\.close\(\)|finally:))",
                    re.MULTILINE,
                ),
                "severity": Severity.MEDIUM,
                "description": (
                    "Cursor de base de datos instanciado sin sentencia 'with' ni cierre explícito en 'finally'. "
                    "Los cursores no cerrados retienen bloqueos de memoria en el cliente y servidor DB."
                ),
                "remediation": (
                    "Envuelva el cursor en un context manager: `with conn.cursor() as cur:` para garantizar su liberación."
                ),
                "file_types": [".py"],
            },
            {
                "id": "QA-DB-POOL-LEAK-NODE",
                "title": "Software QA: Node.js/TypeScript Database Client Checkout Without Release",
                "pattern": re.compile(
                    r"(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*await\s+[a-zA-Z0-9_]+\.connect\s*\([^)]*\)"
                    r"(?![\s\S]{0,400}?(?:\1\.release\(\)|\1\.end\(\)|finally\s*\{))",
                    re.MULTILINE,
                ),
                "severity": Severity.HIGH,
                "description": (
                    "Cliente de pool (pg, mysql2, etc.) reservado con `await pool.connect()` sin invocación garantizada "
                    "de `client.release()` en un bloque `finally`. Provoca que el pool alcance el límite de clientes (`max`), "
                    "bloqueando indefinidamente las peticiones HTTP entrantes."
                ),
                "remediation": (
                    "Asegure la liberación del cliente en el bloque finally: `try { ... } finally { client.release(); }`."
                ),
                "file_types": [".js", ".ts", ".jsx", ".tsx"],
            },
            {
                "id": "QA-DB-DANGLING-TRANSACTION-PY",
                "title": "Software QA: Unhandled DB Transaction Without Atomic Rollback Guard",
                "pattern": re.compile(
                    r"(?:^|\s+)([a-zA-Z0-9_]+)\.begin\s*\(\s*\)"
                    r"(?![\s\S]{0,300}?(?:\1\.rollback\(\)|except|finally:))",
                    re.MULTILINE,
                ),
                "severity": Severity.HIGH,
                "description": (
                    "Inicio manual de transacción (`conn.begin()`) sin bloque `try...except...rollback()`. "
                    "Si una sentencia SQL falla, la transacción permanece abierta reteniendo locks a nivel de fila o tabla."
                ),
                "remediation": (
                    "Use un bloque `try/except` que ejecute `conn.rollback()` ante cualquier error, o `with conn.begin():`."
                ),
                "file_types": [".py"],
            },
        ]

    @property
    def name(self) -> str:
        return "DatabasePoolExhaustionScanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Detecta fugas de descriptores de sockets, transacciones huérfanas y agotamiento de pools de base de datos."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx"]

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
                        cwe_id="CWE-772",
                        confidence="HIGH",
                    )
                )

        return findings

    def scan(self, file_path: str, content: str) -> List[Finding]:
        return self.scan_file(file_path, content)
