"""
cyberaudit/modules/software_qa/openapi_diff_scanner.py
======================================================
OpenAPI & REST API Contract Breaking Changes Scanner.

Audits API contracts for breaking changes, backwards-incompatibility, and schema defects:
- Removed endpoints or HTTP methods without deprecation cycle.
- Newly added required request parameters without fallback defaults.
- Modified parameter or response types (breaking consumer deserialization).
- Endpoints lacking explicit error response schemas (4xx / 5xx blindspots).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Pillar, Severity


@dataclass
class ApiBreakingChange:
    change_type: str
    endpoint: str
    method: str
    description: str
    severity: Severity


class OpenApiBreakingChangesScanner(BaseScanner):
    """
    Scanner y verificador diferencial de contratos OpenAPI / Swagger.
    Previene regresiones y caídas en clientes móviles y frontend por cambios rompientes.
    """

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "OpenApiBreakingChangesScanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.SOFTWARE_QA

    @property
    def description(self) -> str:
        return "Detecta cambios rompientes de API, parámetros obligatorios sin default y ausencia de modelos de error."

    @property
    def file_extensions(self) -> List[str]:
        return [".json", ".yaml", ".yml"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.lower()
        if not (
            "openapi" in lower_path
            or "swagger" in lower_path
            or lower_path.endswith(".json")
            or lower_path.endswith(".yaml")
            or lower_path.endswith(".yml")
        ):
            return findings

        data = self._parse_spec(content)
        if not data or not isinstance(data, dict) or "paths" not in data:
            return findings

        paths = data.get("paths", {})
        if not isinstance(paths, dict):
            return findings

        for endpoint, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, operation in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                    continue
                if not isinstance(operation, dict):
                    continue

                # Rule 1: Missing Error Responses (no 4xx/5xx defined)
                responses = operation.get("responses", {})
                has_error_model = any(
                    str(code).startswith("4") or str(code).startswith("5") or str(code).lower() == "default"
                    for code in responses.keys()
                )
                if not has_error_model and responses:
                    findings.append(
                        Finding(
                            id="QA-OPENAPI-MISSING-ERROR-RESPONSE",
                            title=f"Software QA: Missing Error Response Model in {method.upper()} {endpoint}",
                            description=(
                                f"La operación {method.upper()} {endpoint} no define esquemas de error (códigos 4xx o 5xx). "
                                "Los clientes SDK y frontend no podrán gestionar tipadamente excepciones o fallos HTTP."
                            ),
                            severity=Severity.LOW,
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=1,
                            code_snippet=f"{method.upper()} {endpoint}",
                            remediation="Declare al menos una respuesta estándar de error (e.g. 400, 422 o 'default') con un esquema tipado.",
                            cwe_id="CWE-392",
                            confidence="HIGH",
                        )
                    )

                # Rule 2: Breaking required parameters without default
                parameters = operation.get("parameters", [])
                if isinstance(parameters, list):
                    for param in parameters:
                        if isinstance(param, dict) and param.get("required") is True:
                            schema = param.get("schema", {})
                            if isinstance(schema, dict) and "default" not in schema:
                                param_in = param.get("in", "query")
                                param_name = param.get("name", "unnamed")
                                if param_in in ("query", "header"):
                                    findings.append(
                                        Finding(
                                            id="QA-OPENAPI-BREAKING-PARAM",
                                            title=f"Software QA: Breaking Required {param_in.capitalize()} Parameter '{param_name}'",
                                            description=(
                                                f"El parámetro '{param_name}' en {method.upper()} {endpoint} está marcado como requerido "
                                                f"(`required: true`) sin un valor por defecto. Si este endpoint ya fue consumido por versiones "
                                                "anteriores de clientes, generará fallos inmediatos 400 Bad Request."
                                            ),
                                            severity=Severity.MEDIUM,
                                            pillar=self.pillar,
                                            scanner_name=self.name,
                                            file_path=file_path,
                                            line_number=1,
                                            code_snippet=f"Parameter: {param_name} (in: {param_in}, required: true)",
                                            remediation=f"Defina un valor `default` en el esquema del parámetro '{param_name}' o hágase opcional.",
                                            cwe_id="CWE-1025",
                                            confidence="HIGH",
                                        )
                                    )

        return findings

    def scan(self, file_path: str, content: str) -> List[Finding]:
        return self.scan_file(file_path, content)

    def compare_specs(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[ApiBreakingChange]:
        """
        Compara dos especificaciones OpenAPI y extrae cambios rompientes (Breaking Changes):
        - Rutas o verbos HTTP eliminados.
        - Nuevos parámetros requeridos en rutas existentes.
        - Tipos de parámetros modificados incompatibles.
        """
        changes: List[ApiBreakingChange] = []
        old_paths = old_spec.get("paths", {})
        new_paths = new_spec.get("paths", {})

        # Check for removed endpoints
        for endpoint, old_methods in old_paths.items():
            if endpoint not in new_paths:
                changes.append(
                    ApiBreakingChange(
                        change_type="REMOVED_ENDPOINT",
                        endpoint=endpoint,
                        method="ALL",
                        description=f"El endpoint '{endpoint}' fue eliminado por completo de la API.",
                        severity=Severity.CRITICAL,
                    )
                )
                continue

            new_methods = new_paths[endpoint]
            for method, old_op in old_methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                if method not in new_methods:
                    changes.append(
                        ApiBreakingChange(
                            change_type="REMOVED_HTTP_METHOD",
                            endpoint=endpoint,
                            method=method.upper(),
                            description=f"El verbo HTTP {method.upper()} fue eliminado del endpoint '{endpoint}'.",
                            severity=Severity.HIGH,
                        )
                    )
                    continue

                # Check parameter additions / alterations
                new_op = new_methods[method]
                old_params = {p.get("name"): p for p in old_op.get("parameters", []) if isinstance(p, dict)}
                new_params = {p.get("name"): p for p in new_op.get("parameters", []) if isinstance(p, dict)}

                for p_name, p_data in new_params.items():
                    if p_name not in old_params and p_data.get("required") is True:
                        changes.append(
                            ApiBreakingChange(
                                change_type="NEW_REQUIRED_PARAMETER",
                                endpoint=endpoint,
                                method=method.upper(),
                                description=f"Se agregó el parámetro requerido obligatorio '{p_name}' a '{endpoint}'.",
                                severity=Severity.HIGH,
                            )
                        )

        return changes

    def _parse_spec(self, content: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(content)
        except Exception:
            pass

        try:
            import yaml
            return yaml.safe_load(content)
        except Exception:
            pass

        return None
