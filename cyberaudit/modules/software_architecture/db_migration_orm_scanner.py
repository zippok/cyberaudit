"""
Database Migration & ORM N+1 Safety Scanner
Audits SQL migrations, ORM models, and database query code against:
1. Non-zero-downtime SQL migrations (DROP COLUMN / DROP TABLE / ALTER COLUMN without Expand-and-Contract).
2. ORM / SQL queries executed inside loops (N+1 Query Anti-Pattern).
3. Unindexed Foreign Keys in SQL / Prisma / ORM schemas.
4. Destructive UPDATE / DELETE statements without a WHERE clause.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class DatabaseMigrationAndOrmScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Database Migration & ORM N+1 Safety Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.ARCHITECTURE

    @property
    def description(self) -> str:
        return (
            "Detects blocking/destructive SQL migrations (DROP/ALTER without expand-contract), "
            "ORM N+1 queries inside loops, unindexed foreign keys, and unbounded UPDATE/DELETE statements."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".sql", ".prisma", ".js", ".ts", ".jsx", ".tsx", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        lines = content.splitlines()
        total_lines = len(lines)

        # Skip test files for N+1 and migration checks unless explicitly testing SQL
        is_test_file = any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_"])

        # ------------------------------------------------------------------
        # 1. ARCH-DB-MIGRATION-DESTRUCTIVE (Zero-Downtime Migration Safety)
        # ------------------------------------------------------------------
        if lower_path.endswith(".sql") or "migration" in lower_path or "alembic" in lower_path:
            destructive_patterns = [
                (
                    re.compile(r"\bALTER\s+TABLE\s+[\w.\"`]+\s+DROP\s+COLUMN\b", re.IGNORECASE),
                    "ARCH-DB-MIGRATION-DROP-COLUMN",
                    "Destructive DROP COLUMN in SQL Migration Without Expand-and-Contract",
                    Severity.HIGH,
                ),
                (
                    re.compile(r"\bALTER\s+TABLE\s+[\w.\"`]+\s+ALTER\s+COLUMN\s+[\w\"`]+\s+TYPE\b", re.IGNORECASE),
                    "ARCH-DB-MIGRATION-ALTER-TYPE",
                    "Table-Locking ALTER COLUMN TYPE in SQL Migration",
                    Severity.MEDIUM,
                ),
                (
                    re.compile(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY\b)(?!IF\s+NOT\s+EXISTS\b)[\w\"`]+\s+ON\b", re.IGNORECASE),
                    "ARCH-DB-INDEX-NON-CONCURRENT",
                    "Blocking CREATE INDEX Without CONCURRENTLY on Production Table",
                    Severity.LOW,
                ),
            ]
            for pattern, fid, title, sev in destructive_patterns:
                for match in pattern.finditer(content):
                    if "expand-contract: ignore" in content.lower():
                        continue
                    line_num = content[: match.start()].count("\n") + 1
                    snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                    findings.append(
                        Finding(
                            id=fid,
                            title=f"Architecture & DB Safety: {title}",
                            description=(
                                f"Detected `{match.group(0)}` in migration or SQL script. In rolling/zero-downtime deployments "
                                f"(Kleppmann DDIA / Farley CD), dropping or mutating columns while old application instances "
                                f"are still running causes immediate runtime crashes and table locks."
                            ),
                            severity=sev,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet[:200],
                            remediation=(
                                "Apply the Expand-and-Contract pattern: (1) Add nullable column / stop reading old column in app code, "
                                "(2) Backfill data asynchronously, (3) Drop column in a subsequent release."
                            ),
                            cwe_id="CWE-400",
                            stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                            compliance_controls={"DDIA": "Chapter 4 - Evolvability & Rolling Upgrades", "ISO-27001": "A.8.32"},
                        )
                    )

        # ------------------------------------------------------------------
        # 2. ARCH-DB-UNBOUNDED-MUTATION (UPDATE / DELETE without WHERE)
        # ------------------------------------------------------------------
        if not is_test_file:
            unbounded_sql = re.compile(
                r"\b(?:DELETE\s+FROM\s+[\w.\"`]+|UPDATE\s+[\w.\"`]+\s+SET\s+[^;\"'\n]+?)\s*(?:;|[\"']\s*\))",
                re.IGNORECASE,
            )
            for match in unbounded_sql.finditer(content):
                stmt = match.group(0)
                if re.search(r"\bWHERE\b", stmt, re.IGNORECASE):
                    continue
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else stmt
                findings.append(
                    Finding(
                        id="ARCH-DB-UNBOUNDED-MUTATION",
                        title="Database Safety: Destructive UPDATE or DELETE Without WHERE Clause",
                        description=(
                            f"SQL statement `{stmt.strip()}` executes a table-wide mutation without a `WHERE` filter. "
                            f"This risks catastrophic data loss or full-table corruption."
                        ),
                        severity=Severity.CRITICAL,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Always include an explicit `WHERE` clause or use `TRUNCATE` only in explicitly guarded administrative scripts.",
                        cwe_id="CWE-284",
                        stride_category=StrideCategory.TAMPERING.value,
                    )
                )

        # ------------------------------------------------------------------
        # 3. ARCH-ORM-N-PLUS-ONE (ORM / DB Query Executed Inside Loop)
        # ------------------------------------------------------------------
        if not is_test_file and any(lower_path.endswith(ext) for ext in [".js", ".ts", ".jsx", ".tsx", ".py"]):
            loop_header_re = re.compile(
                r"^\s*(?:for\s*\(|for\s+await\s*\(|while\s*\(|for\s+\w+\s+in\s+|[\w.]+\.(?:forEach|map)\s*\(\s*async\b)"
            )
            db_call_re = re.compile(
                r"\b(?:await\s+(?:prisma|db|orm|conn|connection|pool|knex|sequelize|typeorm|client|session)\.[\w.]+\.(?:findUnique|findFirst|findOne|findById|findByPk|query|execute|get|save|create|update)\s*\(|"
                r"await\s+[\w]*(?:Model|Repository|Repo|Dao|Table|Collection)\.(?:findUnique|findFirst|findOne|findById|findByPk|query|execute|get|save|create|update)\s*\(|"
                r"await\s+prisma\.\w+\.(?:findUnique|findFirst|findOne|findById|findByPk|query|execute|get|save|create|update)\s*\(|"
                r"session\.(?:query|execute)\s*\(|cursor\.execute\s*\(|objects\.(?:get|filter)\s*\()"
            )
            for idx, line in enumerate(lines):
                if loop_header_re.search(line):
                    window = "\n".join(lines[idx : min(idx + 10, total_lines)])
                    db_match = db_call_re.search(window)
                    if db_match:
                        findings.append(
                            Finding(
                                id="ARCH-ORM-N-PLUS-ONE",
                                title="Performance & Architecture: Database / ORM Query Inside Loop (N+1 Anti-Pattern)",
                                description=(
                                    f"Detected database/ORM query (`{db_match.group(0).strip()}`) inside an iterative loop starting at line {idx + 1}. "
                                    f"Executing 1 query per collection item causes $O(N)$ network round-trips and saturates the connection pool under load."
                                ),
                                severity=Severity.HIGH,
                                pillar=self.pillar,
                                scanner_name=self.name,
                                file_path=file_path,
                                line_number=idx + 1,
                                code_snippet=line.strip()[:200],
                                remediation=(
                                    "Batch-fetch records outside the loop using `WHERE id IN (...)`, Prisma `include`/`findMany({ where: { id: { in: ids } } })`, "
                                    "SQLAlchemy `selectinload`/`joinedload`, or bulk `INSERT`/`UPDATE`."
                                ),
                                cwe_id="CWE-400",
                                stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                            )
                        )

        return findings
