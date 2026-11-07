"""
Type Safety & Schema Boundary Validation Scanner
Audits TypeScript/JavaScript/Python code for:
1. Type safety suppression (@ts-ignore, @ts-nocheck, explicit `: any` abuse).
2. Unvalidated API input boundaries (reading req.body / req.query without schema validation).
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class TypeSafetyAndSchemaBoundaryScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Type Safety & Schema Boundary Validation Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return (
            "Detects TypeScript type-safety bypasses (@ts-ignore, @ts-nocheck, excessive `any`) "
            "and HTTP route handlers consuming req.body without schema validation."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".ts", ".tsx", ".js", ".jsx", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_", ".d.ts"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. QA-TS-SAFETY-SUPPRESSION (@ts-ignore / @ts-nocheck / as any)
        # ------------------------------------------------------------------
        if lower_path.endswith((".ts", ".tsx")):
            ts_ignore_re = re.compile(r"//\s*@ts-(?:ignore|nocheck)\b")
            for match in ts_ignore_re.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
                findings.append(
                    Finding(
                        id="QA-TS-SAFETY-SUPPRESSION",
                        title="Type Safety: Unconditional @ts-ignore / @ts-nocheck Suppresses Compiler Verification",
                        description=(
                            f"Directive `{snippet}` silences the TypeScript compiler entirely on the target line or file, "
                            f"hiding type mismatches and null-dereference bugs."
                        ),
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Fix the underlying type mismatch or replace `@ts-ignore` with `@ts-expect-error: <justification>`.",
                        cwe_id="CWE-704",
                    )
                )

            any_matches = list(re.finditer(r"(?::\s*any\b|\bas\s+any\b)", content))
            if len(any_matches) >= 3:
                first_line = content[: any_matches[0].start()].count("\n") + 1
                snippet = lines[first_line - 1].strip() if first_line - 1 < total_lines else ": any"
                findings.append(
                    Finding(
                        id="QA-TS-EXCESSIVE-ANY",
                        title="Type Safety: Excessive `any` Type Escape Hatches Degrade Static Guarantees",
                        description=(
                            f"Detected {len(any_matches)} occurrences of `: any` or `as any` in `{file_path}`. "
                            f"Using `any` disables static type checking and propagates untyped values across module boundaries."
                        ),
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=first_line,
                        code_snippet=snippet[:200],
                        remediation="Use `unknown` with type narrowing (type guards or Zod schemas) or define explicit interfaces/generics.",
                        cwe_id="CWE-704",
                    )
                )

        # ------------------------------------------------------------------
        # 2. QA-SCHEMA-UNVALIDATED-BODY (Unvalidated req.body destructuring)
        # ------------------------------------------------------------------
        route_body_re = re.compile(
            r"""\b(?:app|router)\.(?:post|put|patch)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{"""
        )
        for match in route_body_re.finditer(content):
            route_path = match.group(1)
            start_line = content[: match.start()].count("\n") + 1
            window = "\n".join(lines[start_line - 1 : min(start_line + 25, total_lines)])
            if "req.body" in window and not re.search(
                r"\b(?:safeParse|parse|validate|Joi|zod|z\.|ajv|typeof\s+|sanitize|assert)\b",
                window,
                re.IGNORECASE,
            ):
                snippet = lines[start_line - 1].strip() if start_line - 1 < total_lines else match.group(0)
                findings.append(
                    Finding(
                        id="QA-SCHEMA-UNVALIDATED-BODY",
                        title="Boundary Safety: HTTP Mutation Route Consumes req.body Without Schema Validation",
                        description=(
                            f"Route `{route_path}` reads `req.body` directly without visible schema or type validation (Zod/Joi/AJV/type checks). "
                            f"Unvalidated payloads allow type confusion (e.g., arrays/objects instead of strings) and mass assignment."
                        ),
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=start_line,
                        code_snippet=snippet[:200],
                        remediation="Validate `req.body` at the route boundary using a strict schema validator (`schema.safeParse(req.body)`) or explicit allowlist.",
                        cwe_id="CWE-20",
                        stride_category=StrideCategory.TAMPERING.value,
                    )
                )

        return findings
