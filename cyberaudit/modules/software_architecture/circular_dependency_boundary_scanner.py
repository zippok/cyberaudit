"""
Circular Dependency & Clean Architecture Boundary Scanner
Audits source files and project import graphs for:
1. Direct UI/Presentation layer imports of database/ORM internals (Layer Violation).
2. Circular module dependencies (A -> B -> A) across local files.
"""

import os
import re
from typing import Dict, List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class CircularDependencyAndBoundaryScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Circular Dependency & Clean Architecture Boundary Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.ARCHITECTURE

    @property
    def description(self) -> str:
        return (
            "Detects circular module dependencies (A -> B -> A) and Clean Architecture layer violations "
            "(e.g., frontend UI components importing database/ORM repositories directly)."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".jsx", ".tsx", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        norm = file_path.replace("\\", "/").lower()
        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. ARCH-BOUNDARY-UI-IMPORTS-DB (Clean Architecture Layer Violation)
        # ------------------------------------------------------------------
        is_ui_file = any(
            seg in norm
            for seg in ["/components/", "/views/", "/pages/", "/ui/", ".jsx", ".tsx", ".vue"]
        ) and not any(seg in norm for seg in ["/api/", "/server/", "/pages/api/"])

        if is_ui_file:
            db_import_re = re.compile(
                r"""(?:import\s+.*?\s+from\s+|require\s*\(\s*)['"`](?:@prisma/client|pg|mysql2|sqlite3|typeorm|sequelize|mongoose|.*?/repositories/|.*?/models/db)['"`]"""
            )
            for match in db_import_re.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                findings.append(
                    Finding(
                        id="ARCH-BOUNDARY-UI-IMPORTS-DB",
                        title="Clean Architecture: UI/Presentation Component Directly Imports Database Layer",
                        description=(
                            f"UI component `{os.path.basename(file_path)}` directly imports database/ORM module (`{match.group(0)}`). "
                            f"This violates the Dependency Rule (Clean Architecture / Hexagonal Architecture), coupling presentation directly to persistence."
                        ),
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Route UI interactions through an application service, API client, or use-case port rather than importing database drivers in UI code.",
                        cwe_id="CWE-1047",
                    )
                )

        return findings

    def scan_directory(self, dir_path: str) -> List[Finding]:
        findings: List[Finding] = []
        import_graph: Dict[str, Set[str]] = {}
        rel_to_abs: Dict[str, str] = {}

        import_re = re.compile(
            r"""(?:import\s+[^'"]*?\s+from\s+|require\s*\(\s*)['"](\.[^'"]+)['"]"""
        )

        exclude = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".antigravity"}
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in exclude and not d.startswith(".")]
            for fname in files:
                if not fname.endswith((".js", ".ts", ".jsx", ".tsx")):
                    continue
                abs_p = os.path.join(root, fname)
                rel_p = os.path.relpath(abs_p, dir_path).replace("\\", "/")
                base_no_ext = os.path.splitext(rel_p)[0]
                rel_to_abs[base_no_ext] = abs_p
                import_graph.setdefault(base_no_ext, set())

                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                except Exception:
                    continue

                cur_dir = os.path.dirname(rel_p)
                for m in import_re.finditer(text):
                    raw_target = m.group(1)
                    resolved = os.path.normpath(os.path.join(cur_dir, raw_target)).replace("\\", "/")
                    resolved_no_ext = os.path.splitext(resolved)[0]
                    import_graph[base_no_ext].add(resolved_no_ext)

        visited_pairs: Set[tuple] = set()
        for node_a, targets in import_graph.items():
            for node_b in targets:
                if node_b != node_a and node_b in import_graph and node_a in import_graph[node_b]:
                    pair = tuple(sorted((node_a, node_b)))
                    if pair not in visited_pairs:
                        visited_pairs.add(pair)
                        findings.append(
                            Finding(
                                id="ARCH-CIRCULAR-DEPENDENCY",
                                title="Software Architecture: Circular Module Dependency Detected (A <-> B)",
                                description=(
                                    f"Mutual import cycle detected between `{pair[0]}` and `{pair[1]}`. "
                                    f"Circular dependencies break modular reasoning, cause undefined initialization states at runtime, and prevent clean tree-shaking."
                                ),
                                severity=Severity.MEDIUM,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=rel_to_abs.get(pair[0], dir_path),
                                line_number=1,
                                code_snippet=f"{pair[0]} <-> {pair[1]}",
                                remediation="Extract shared types/utilities into a third lower-level module or invert the dependency using interfaces.",
                                cwe_id="CWE-1047",
                            )
                        )

        return findings
