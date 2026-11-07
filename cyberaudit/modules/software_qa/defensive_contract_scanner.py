"""
Defensive Programming, Error Handling & API Contract Scanner (Software QA)
Audits source code for:
- Stack trace loss during exception re-raising (QA-ERROR-STACK-TRACE-LOSS)
- Ingesting raw unvalidated JSON at API boundary controllers (QA-API-UNVALIDATED-BOUNDARY-PAYLOAD)
- Silenced exception context in application logging (QA-SILENCED-EXCEPTION-LOGGER)
"""

import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class DefensiveContractScanner(BaseScanner):
    __test__ = False  # Prevent pytest from collecting this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Defensive Programming & API Contract Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Audits exception hygiene (stack trace preservation), API boundary contract schemas, and defensive logging diagnostics."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".php", ".cs"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()

        # Skip non-code, docs, tests, and minified assets
        if any(lower_path.endswith(ext) for ext in [".min.js", ".min.css", ".md", ".json", ".lock", ".svg"]):
            return []

        # Skip test files for contract checks
        if "test" in lower_path or "spec" in lower_path:
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ----------------------------------------------------------------------
        # 1. QA-ERROR-STACK-TRACE-LOSS
        # ----------------------------------------------------------------------
        if lower_path.endswith(".py"):
            # Detect Python: except X as e: ... raise Y(...) without "from e" or "from None"
            for idx, line in enumerate(lines):
                except_m = re.match(r"^\s*except\s+([A-Za-z0-9_.]+)\s+as\s+(\w+)\s*:", line)
                if except_m:
                    err_var = except_m.group(2)
                    for j in range(idx + 1, min(idx + 10, total_lines)):
                        sub_line = lines[j]
                        if sub_line.strip() and not sub_line.startswith((" ", "\t")):
                            break
                        if re.search(r"\braise\s+[A-Za-z0-9_.]+\s*\(", sub_line):
                            if f"from {err_var}" not in sub_line and "from None" not in sub_line:
                                findings.append(
                                    Finding(
                                        id="QA-ERROR-STACK-TRACE-LOSS",
                                        title=f"Software QA: Exception Re-raised Without Preserving Root Cause Chain (from {err_var})",
                                        description=(
                                            f"Exception block catches `{err_var}` and raises a new exception without chaining `from {err_var}`. "
                                            f"In Python 3, unchained exception re-raising breaks the exception context chain and causes Sentry/APM "
                                            f"telemetry tools to lose the underlying root-cause stack trace."
                                        ),
                                        severity=Severity.MEDIUM,
                                        pillar=self.pillar,
                                        scanner_name=self.name,
                                        file_path=file_path,
                                        line_number=j + 1,
                                        code_snippet=sub_line.strip()[:180],
                                        remediation=f"Preserve root cause exception chaining: append `from {err_var}` to the raise statement.",
                                        cwe_id="CWE-398",
                                        compliance_controls={"PEP-3134": "Exception-Chaining", "ISO-25010": "Maintainability"},
                                    )
                                )
                                break

        if any(lower_path.endswith(ext) for ext in [".js", ".ts", ".mjs"]):
            # Detect JS/TS: catch (err) { throw new Error(...) } without { cause: err }
            catch_throw_pattern = re.compile(
                r'catch\s*\(\s*(\w+)\s*\)\s*\{([^}]{1,400}?)\bthrow\s+new\s+(?:Error|\w+Error)\s*\(([^)\n]*)\)\s*;?\s*\}'
            )
            for match in catch_throw_pattern.finditer(content):
                err_var = match.group(1)
                args = match.group(3)
                if f"cause:" not in args:
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="QA-ERROR-STACK-TRACE-LOSS",
                            title="Software QA: JavaScript Error Re-thrown Without Preserving Error Cause ({ cause })",
                            description=(
                                f"A `catch ({err_var})` block constructs and throws a new `Error` without attaching `{err_var}` as `{'{ cause: ' + err_var + ' }'}`. "
                                f"This completely discards the inner exception stack trace, obscuring the root failure in production logs."
                            ),
                            severity=Severity.MEDIUM,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation=f"Chain the original error using ES2022 Error cause: `throw new Error('...', {{ cause: {err_var} }});`.",
                            cwe_id="CWE-398",
                            compliance_controls={"ECMA-402": "Error-Cause", "ISO-25010": "Reliability"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 2. QA-API-UNVALIDATED-BOUNDARY-PAYLOAD
        # ----------------------------------------------------------------------
        if lower_path.endswith(".py"):
            # Check for Flask/Bottle/Django parsing request.json or request.get_json() without Pydantic/Marshmallow
            has_schema_validator = any(k in content for k in ["BaseModel", "pydantic", "marshmallow", "Schema", "serializer", "validate"])
            raw_json_pattern = re.compile(r'\brequest\.(?:get_json\s*\(\s*\)|json\b)')
            if not has_schema_validator:
                for match in raw_json_pattern.finditer(content):
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="QA-API-UNVALIDATED-BOUNDARY-PAYLOAD",
                            title="Software QA & Robustness: Boundary API Route Ingests Raw Unvalidated JSON Payload",
                            description=(
                                f"Endpoint processes incoming client body directly via `{match.group(0)}` without schema validation. "
                                f"Consuming untyped dictionary payloads at the boundary layer exposes downstream logic to "
                                f"unexpected KeyErrors, TypeErrors, null-pointer crashes, and internal 500 exceptions under malformed inputs."
                            ),
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Validate request payloads against a typed schema using Pydantic `BaseModel` or Marshmallow schemas.",
                            cwe_id="CWE-20",
                            stride_category=StrideCategory.TAMPERING.value,
                            compliance_controls={"OWASP-API": "API3:2023", "ISO-25010": "Robustness"},
                        )
                    )

        if any(lower_path.endswith(ext) for ext in [".js", ".ts"]):
            # Express / Koa / Fastify route handlers using req.body without zod, joi, or yup
            has_ts_validator = any(k in content for k in ["zod", "joi", "yup", "class-validator", "typebox", "valibot"])
            req_body_pattern = re.compile(r'\b(?:const|let|var)\s*\{[^}]+\}\s*=\s*req\.body\b')
            if not has_ts_validator:
                for match in req_body_pattern.finditer(content):
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                    findings.append(
                        Finding(
                            id="QA-API-UNVALIDATED-BOUNDARY-PAYLOAD",
                            title="Software QA & Robustness: Express/Node Route Destructures Raw req.body Without Schema",
                            description=(
                                f"Controller destructures `{match.group(0)}` without prior schema or runtime validation. "
                                f"Missing boundary schemas allow unexpected types or missing keys to propagate into core services, "
                                f"causing uncaught exceptions and corrupted database transactions."
                            ),
                            severity=Severity.HIGH,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=matched_line[:180],
                            remediation="Validate `req.body` using a runtime schema library like Zod (`schema.parse(req.body)`) or Joi.",
                            cwe_id="CWE-20",
                            stride_category=StrideCategory.TAMPERING.value,
                            compliance_controls={"OWASP-API": "API3:2023", "ISO-25010": "Robustness"},
                        )
                    )

        # ----------------------------------------------------------------------
        # 3. QA-SILENCED-EXCEPTION-LOGGER
        # ----------------------------------------------------------------------
        if lower_path.endswith(".py"):
            # Except block with logger.error without exc_info=True
            silenced_log_pattern = re.compile(
                r'except\s+(?:Exception|[A-Za-z0-9_\.]+)(?:\s+as\s+\w+)?:\s*\n[ \t]+(?:logger|logging)\.(?:error|critical|warning)\s*\(\s*["\'][^"\']+["\']\s*\)',
                re.MULTILINE
            )
            for match in silenced_log_pattern.finditer(content):
                start_pos = match.start()
                line_num = content[:start_pos].count("\n") + 1
                matched_line = lines[line_num - 1].strip() if line_num - 1 < total_lines else ""
                findings.append(
                    Finding(
                        id="QA-SILENCED-EXCEPTION-LOGGER",
                        title="Software QA: Exception Logged Without Diagnostic Traceback Context (Missing exc_info)",
                        description=(
                            "Exception handler records an error log string without passing `exc_info=True` or the exception object. "
                            "While an error message is recorded, the full traceback, originating file, and code line are omitted, "
                            "crippling post-incident debugging."
                        ),
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=matched_line[:180],
                        remediation="Add `exc_info=True` to the logger call: `logger.error('...', exc_info=True)`.",
                        cwe_id="CWE-778",
                        compliance_controls={"ISO-25010": "Maintainability", "SOC2": "CC7.2"},
                    )
                )

        return findings
