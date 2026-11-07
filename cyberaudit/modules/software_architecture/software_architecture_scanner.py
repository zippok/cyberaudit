"""
Software Architecture, Performance & Governance Scanner
Audits software architecture integrity:
1. N+1 ORM Database Query Antipatterns (disproportionate DB roundtrips)
2. Architectural Layer Boundary Violations (UI/Presentation layer directly invoking SQL/database engines)
3. Open-Source License Compliance & Viral Copyleft Contamination (GPL/AGPL in proprietary workflows)
4. Monolithic Architectural Modules (God Files exceeding 2,500 lines)
"""

import json
import os
import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class SoftwareArchitectureScanner(BaseScanner):
    __test__ = False  # Prevent pytest collector from discovering this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Software Architecture, Performance & Governance Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.ARCHITECTURE

    @property
    def description(self) -> str:
        return "Audits software architecture quality, N+1 ORM queries, architectural layer leaks (UI directly accessing DB), and viral copyleft open-source license contamination."

    @property
    def supported_extensions(self) -> Set[str]:
        return {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".html",
            ".java", ".kt", ".cs", ".go", ".php", ".json", ".txt"
        }

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        basename = os.path.basename(file_path).lower()
        norm_path = file_path.replace("\\", "/").lower()

        # 1. License Compliance & Viral Copyleft Audit
        if basename == "package.json":
            findings.extend(self._scan_package_license(file_path, content))
        else:
            findings.extend(self._scan_file_license_headers(file_path, content))

        # 2. Architectural Layer Boundary Leakage (UI accessing DB directly)
        findings.extend(self._scan_layer_boundaries(file_path, norm_path, content))

        # 3. N+1 Database Query Antipattern in loops
        findings.extend(self._scan_n_plus_one(file_path, content))

        # 4. God File Architecture Anti-Pattern
        findings.extend(self._scan_god_file(file_path, content))

        return findings

    def _scan_package_license(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(content)
        except Exception:
            return findings

        # Check declared license
        license_str = data.get("license", "")
        if isinstance(license_str, str):
            copyleft_matches = re.search(r'\b(AGPL|GPL(?:-2\.0|-3\.0|-1\.0)?|SSPL)\b', license_str, re.IGNORECASE)
            if copyleft_matches:
                findings.append(Finding(
                    id="ARCH-LICENSE-COPYLEFT-VIRAL",
                    title=f"Viral Copyleft License Contamination Risk: '{license_str}'",
                    description=f"The package declares a strong copyleft license ('{license_str}'). If this project incorporates proprietary components or is distributed/hosted without intention of open-sourcing the entire software stack, this creates severe intellectual property and legal compliance exposure.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    code_snippet=f'"license": "{license_str}"',
                    remediation="Consult legal counsel regarding copyleft licensing. Consider migrating to permissive licenses (MIT, Apache-2.0, BSD-3-Clause) or obtaining commercial dual-licensing agreements.",
                    mitre_id="T1195",
                    mitre_tactic="Initial Access",
                    mitre_technique="Supply Chain Compromise",
                    cwe_id="CWE-1104",
                    stride_category=StrideCategory.REPUDIATION.value,
                    compliance_controls={"OpenSSF": "License-Compliance", "SPDX": license_str, "ISO 27001": "A.5.32"},
                ))

        # Check known viral copyleft packages in dependencies
        copyleft_packages = {
            "gpl": "GPL licensed library",
            "canvas": "Cairo/GPL bindings",
        }
        for dep_key in ["dependencies", "devDependencies"]:
            deps = data.get(dep_key, {})
            if isinstance(deps, dict):
                for dep, ver in deps.items():
                    if "agpl" in dep.lower() or dep.lower().startswith("gpl-"):
                        findings.append(Finding(
                            id="ARCH-DEPENDENCY-COPYLEFT-VIRAL",
                            title=f"Copyleft Viral Dependency '{dep}' in {dep_key}",
                            description=f"Dependency '{dep}' carries viral copyleft obligations. Linking this library can legally infect the consuming application under reciprocal licensing mandates.",
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            code_snippet=f'"{dep}": "{ver}"',
                            remediation="Audit dependency licensing tree with 'license-checker' or 'pip-licenses' to ensure all transitive dependencies conform to organization licensing policy.",
                            mitre_id="T1195",
                            mitre_tactic="Initial Access",
                            mitre_technique="Supply Chain Compromise",
                            cwe_id="CWE-1104",
                            stride_category=StrideCategory.REPUDIATION.value,
                            compliance_controls={"OpenSSF": "License-Review", "ISO 27001": "A.5.32"},
                        ))

        return findings

    def _scan_file_license_headers(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        head = content[:2000]
        if re.search(r'\b(GNU (?:General|Affero) Public License|AGPL-3\.0|GPLv3)\b', head, re.IGNORECASE):
            findings.append(Finding(
                id="ARCH-SOURCE-COPYLEFT-HEADER",
                title="Source Code File Header Contains Strong Copyleft (GPL/AGPL) Notice",
                description="This source file explicitly contains a GNU GPL or AGPL copyright header, legally classifying this compilation as a derivative work under reciprocal open-source licensing.",
                severity=Severity.MEDIUM,
                pillar=self.pillar,
                scanner_name=self.name,
                file_path=file_path,
                line_number=1,
                code_snippet=head[:150].strip(),
                remediation="Ensure this module complies with corporate open-source governance and IP distribution policies.",
                mitre_id="T1195",
                mitre_tactic="Initial Access",
                mitre_technique="Supply Chain Compromise",
                cwe_id="CWE-1104",
                stride_category=StrideCategory.REPUDIATION.value,
                compliance_controls={"SPDX": "GPL-3.0", "ISO 27001": "A.5.32"},
            ))
        return findings

    def _scan_layer_boundaries(self, file_path: str, norm_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        # Indicators that a file belongs to UI / Presentation Layer
        is_ui_layer = (
            any(ui_dir in norm_path for ui_dir in ["/components/", "/views/", "/pages/", "/ui/", "/renderer/", "/templates/", "/frontend/"])
            or norm_path.endswith(".jsx")
            or norm_path.endswith(".tsx")
            or norm_path.endswith(".vue")
        )

        if not is_ui_layer:
            return findings

        lines = content.splitlines()

        # Check for direct database engine imports in UI files
        db_import_patterns = [
            (re.compile(r'\b(import|require)\s*\(?[\'"](sqlite3|pg|mysql|mysql2|typeorm|sequelize|mongoose|prisma|psycopg2|sqlalchemy)[\'"]', re.IGNORECASE), "Direct database client imported in UI component"),
            (re.compile(r'from\s+[\'"](sqlite3|pg|mysql|mysql2|typeorm|sequelize|mongoose|prisma|psycopg2|sqlalchemy)[\'"]', re.IGNORECASE), "Direct database module imported in UI component"),
        ]

        for idx, line in enumerate(lines, 1):
            for pattern, desc in db_import_patterns:
                if pattern.search(line):
                    findings.append(Finding(
                        id="ARCH-LAYER-LEAKAGE-UI-DB",
                        title=f"Architectural Layer Violation: UI Component Directly Imports Database Engine ({desc})",
                        description="A presentation/UI component directly imports a database persistence library. This violates Clean Architecture and Hexagonal Architecture principles by tightly coupling user interface logic directly with persistence storage, creating security bypasses, connection leaks, and testability failure.",
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        remediation="Decouple UI from database persistence. The UI should only invoke Backend REST/GraphQL/IPC API endpoints or use Domain Services/Repositories via Data Transfer Objects (DTOs).",
                        mitre_id="T1190",
                        mitre_tactic="Initial Access",
                        mitre_technique="Exploit Public-Facing Application: Architectural Flaw",
                        cwe_id="CWE-1068",
                        stride_category=StrideCategory.TAMPERING.value,
                        compliance_controls={"Clean Architecture": "Dependency Rule", "TOGAF": "Separation of Concerns"},
                    ))

        return findings

    def _scan_n_plus_one(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        if any(t in file_path.lower().replace("\\", "/") for t in ["/test/", "/tests/", "test_", "_test."]):
            return findings

        lines = content.splitlines()

        # Heuristic for loop start
        loop_start_patterns = [
            re.compile(r'^\s*for\s+.*\s+in\s+.*:\s*$'),  # Python for loop
            re.compile(r'^\s*while\s+.*:\s*$'),          # Python while loop
            re.compile(r'\bfor\s*\([^;]+;[^;]+;[^)]*\)'), # JS/C/Java for loop
            re.compile(r'\bfor\s*\(\s*(const|let|var)?\s+\w+\s+(of|in)\s+'), # JS for..of/in
            re.compile(r'\.(forEach|map)\s*\(\s*(async\s*)?\('), # JS .forEach / .map
        ]

        # Database execution call within loop
        db_call_patterns = [
            re.compile(r'\b(cursor\.execute|db\.query|db\.execute|db\.run|db\.all|db\.get)\s*\('),
            re.compile(r'\b(SELECT\s+.*\s+FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM)\b', re.IGNORECASE),
            re.compile(r'\b(await\s+\w+\.(findById|findOne|findUnique|findFirst))\s*\('),
        ]

        in_loop = False
        loop_line = 0
        loop_indent = 0

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            current_indent = len(line) - len(line.lstrip())

            # Detect loop start
            for lp in loop_start_patterns:
                if lp.search(line):
                    # Check if loop is a single-line expression that immediately concludes
                    if stripped.endswith(");") or stripped.endswith("});") or (stripped.endswith(";") and not stripped.endswith("{")):
                        in_loop = False
                        break
                    in_loop = True
                    loop_line = idx
                    loop_indent = current_indent
                    break

            # If inside a loop block, check for db query executions
            if in_loop and idx > loop_line:
                # If Python indent drops to or below loop indent, we exited the loop
                if file_path.endswith(".py") and current_indent <= loop_indent and not line.startswith(" ") and not line.startswith("\t"):
                    in_loop = False
                    continue

                # In JS/TS/PHP/Java, check for closing braces or block exit
                if not file_path.endswith(".py"):
                    if (stripped.startswith("}") or stripped.endswith("}") or stripped == "}") and current_indent <= loop_indent:
                        in_loop = False
                        continue
                    if idx - loop_line > 30:
                        in_loop = False
                        continue

                for dp in db_call_patterns:
                    match_db = dp.search(line)
                    if match_db:
                        findings.append(Finding(
                            id="ARCH-DB-N-PLUS-1-QUERY",
                            title=f"Database Query Dispatched Inside Iterative Loop (N+1 Query Antipattern)",
                            description=f"A database query or ORM record lookup is executed at line {idx} inside a loop initiated at line {loop_line}. For N items in the collection, this triggers N separate network round-trips to the database engine rather than 1 batch query, causing severe latency spikes, connection pool exhaustion, and CPU throttling under load.",
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=idx,
                            code_snippet=line.strip(),
                            remediation="Refactor to batch retrieval: Use SQL 'WHERE id IN (...)', SQL JOINs, or ORM eager loading strategies (.include(), joinedload(), .prefetch_related()).",
                            mitre_id="T1499",
                            mitre_tactic="Impact",
                            mitre_technique="Endpoint Denial of Service: Resource Exhaustion",
                            cwe_id="CWE-400",
                            stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                            compliance_controls={"Performance Engineering": "ISO/IEC 25010 Efficiency", "ACID": "Connection Pool Governance"},
                        ))
                        # Avoid duplicate flags for the same loop
                        in_loop = False
                        break

        return findings

    def _scan_god_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower().replace("\\", "/")
        if any(lower_path.endswith(ext) for ext in [".lock", "package-lock.json", "composer.lock"]):
            return findings

        line_count = len(content.splitlines())

        if line_count > 2500:
            findings.append(Finding(
                id="ARCH-MONOLITHIC-GOD-FILE",
                title=f"Monolithic God File Anti-Pattern: {line_count:,} Lines of Code",
                description=f"The file contains {line_count:,} lines of code, exceeding the architectural maintainability threshold of 2,500 lines. Excessive size indicates low cohesion, tight coupling, and violation of the Single Responsibility Principle (SRP).",
                severity=Severity.MEDIUM,
                pillar=self.pillar,
                scanner_name=self.name,
                file_path=file_path,
                line_number=1,
                code_snippet=f"File length: {line_count:,} lines",
                remediation="Refactor into cohesive, single-responsibility modules, services, and utility classes following Domain-Driven Design (DDD) bounded contexts.",
                cwe_id="CWE-1068",
                stride_category=StrideCategory.TAMPERING.value,
                compliance_controls={"Clean Architecture": "Single Responsibility Principle (SRP)", "ISO/IEC 25010": "Maintainability"},
            ))

        return findings
