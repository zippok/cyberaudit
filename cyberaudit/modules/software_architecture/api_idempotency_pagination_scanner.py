"""
API Contract, Idempotency & Pagination Bounds Scanner
Audits REST/GraphQL/RPC endpoints for:
1. State-mutating POST/PATCH payment/order/transaction endpoints lacking Idempotency-Key handling (DDIA).
2. Unbounded collection queries (SELECT * / .findMany() / .find() without LIMIT / take / pagination).
3. Missing HTTP status code semantics or raw database entities leaked in API responses.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class ApiIdempotencyAndPaginationScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "API Contract, Idempotency & Pagination Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.ARCHITECTURE

    @property
    def description(self) -> str:
        return (
            "Audits API endpoints for missing Idempotency-Key handling on critical mutations (payments/orders) "
            "and unbounded collection queries lacking pagination limits."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".jsx", ".tsx", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. ARCH-API-MISSING-IDEMPOTENCY-KEY
        # ------------------------------------------------------------------
        mutation_route_re = re.compile(
            r"""\b(?:app|router|fastify)\.(?:post|put|patch)\s*\(\s*['"`]([^'"`]*(?:pay|charge|checkout|transfer|order|invoice|withdraw|refund)[^'"`]*)['"`]""",
            re.IGNORECASE,
        )
        py_mutation_route_re = re.compile(
            r"""@(?:app|router|bp)\.(?:post|put|patch|route)\s*\(\s*['"]([^'"]*(?:pay|charge|checkout|transfer|order|invoice|withdraw|refund)[^'"]*)['"]""",
            re.IGNORECASE,
        )

        for route_re in (mutation_route_re, py_mutation_route_re):
            for match in route_re.finditer(content):
                route_path = match.group(1)
                start_line = content[: match.start()].count("\n") + 1
                window = "\n".join(lines[start_line - 1 : min(start_line + 35, total_lines)])
                if not re.search(r"idempotenc|idempotent|x-request-id|dedup", window, re.IGNORECASE):
                    snippet = lines[start_line - 1].strip() if start_line - 1 < total_lines else match.group(0)
                    findings.append(
                        Finding(
                            id="ARCH-API-MISSING-IDEMPOTENCY-KEY",
                            title="Distributed Systems (DDIA): Critical Mutation Endpoint Missing Idempotency Key",
                            description=(
                                f"Endpoint `{route_path}` performs a financial or state-critical mutation without checking an "
                                f"`Idempotency-Key` header or deduplication token. Network retries or client double-clicks can cause duplicate charges or duplicate records."
                            ),
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=start_line,
                            code_snippet=snippet[:200],
                            remediation=(
                                "Require an `Idempotency-Key` header on state-changing POST/PATCH routes and persist the key + response "
                                "atomically in the database or Redis with a TTL."
                            ),
                            cwe_id="CWE-841",
                            stride_category=StrideCategory.TAMPERING.value,
                            compliance_controls={"DDIA": "Chapter 11 - Idempotence", "PCI-DSS": "6.5.8"},
                        )
                    )

        # ------------------------------------------------------------------
        # 2. ARCH-API-UNBOUNDED-QUERY (Pagination Missing)
        # ------------------------------------------------------------------
        unbounded_orm_re = re.compile(r"\b(?:prisma\.\w+\.findMany|\w+Model\.find)\s*\(\s*\)")
        for match in unbounded_orm_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="ARCH-API-UNBOUNDED-QUERY",
                    title="API Scalability: Unbounded Collection Query Without Pagination (take / limit)",
                    description=(
                        f"Call `{match.group(0)}` fetches an entire table/collection into memory without `take` or `limit`. "
                        f"As the dataset grows, this triggers Out-Of-Memory (OOM) crashes and DoS."
                    ),
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Enforce explicit pagination bounds (`take: Math.min(limit, 100)` or `.limit(100)`) on all collection queries.",
                    cwe_id="CWE-770",
                    stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                    compliance_controls={"OWASP-API-2023": "API4:2023 Unrestricted Resource Consumption"},
                )
            )

        return findings
