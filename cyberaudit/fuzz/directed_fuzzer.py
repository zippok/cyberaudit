"""Hybrid IAST, AST-Directed Fuzzer & Attack Surface Management.

Combines static route extraction from source code ASTs (FastAPI, Flask, Django)
with taint analysis metadata to synthesize targeted, non-destructive canary payloads.
Performs external attack surface analysis (dangling DNS subdomain takeover and TLS cipher posture).
"""
from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cyberaudit.fuzz.directed_fuzzer")


@dataclass
class RouteParam:
    """Represents an HTTP request parameter."""
    name: str
    param_type: str = "str"
    in_location: str = "query"  # query, path, body, header
    is_tainted: bool = False
    taint_sink: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "param_type": self.param_type,
            "in_location": self.in_location,
            "is_tainted": self.is_tainted,
            "taint_sink": self.taint_sink,
        }


@dataclass
class EndpointRoute:
    """Represents a discovered web application endpoint route."""
    path: str
    method: str
    handler_function: str
    parameters: List[RouteParam] = field(default_factory=list)
    source_file: str = "app.py"
    line_number: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "handler_function": self.handler_function,
            "parameters": [p.to_dict() for p in self.parameters],
            "source_file": self.source_file,
            "line_number": self.line_number,
        }


class ASTRouteHarvester:
    """Extracts REST routes and parameters from Python web frameworks (FastAPI, Flask, Django)."""

    FASTAPI_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

    def harvest_from_source(self, code: str, filename: str = "app.py") -> List[EndpointRoute]:
        """Parse source code AST to harvest web routes and parameters."""
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            logger.warning("Failed to parse AST for %s: %s", filename, e)
            return []

        routes: List[EndpointRoute] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    # FastAPI style: @app.get("/items/{item_id}") or @router.post(...)
                    if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                        attr_name = decorator.func.attr.lower()
                        if attr_name in self.FASTAPI_METHODS:
                            route_path = self._extract_first_arg_str(decorator)
                            if route_path:
                                params = self._extract_parameters(node, route_path)
                                routes.append(EndpointRoute(
                                    path=route_path,
                                    method=attr_name.upper(),
                                    handler_function=node.name,
                                    parameters=params,
                                    source_file=filename,
                                    line_number=node.lineno,
                                ))
                        # Flask style: @app.route("/path", methods=["GET", "POST"])
                        elif attr_name == "route":
                            route_path = self._extract_first_arg_str(decorator)
                            methods = self._extract_flask_methods(decorator)
                            if route_path:
                                params = self._extract_parameters(node, route_path)
                                for m in methods:
                                    routes.append(EndpointRoute(
                                        path=route_path,
                                        method=m.upper(),
                                        handler_function=node.name,
                                        parameters=params,
                                        source_file=filename,
                                        line_number=node.lineno,
                                    ))

        return routes

    def _extract_first_arg_str(self, call_node: ast.Call) -> Optional[str]:
        if call_node.args and isinstance(call_node.args[0], ast.Constant) and isinstance(call_node.args[0].value, str):
            return call_node.args[0].value
        return None

    def _extract_flask_methods(self, call_node: ast.Call) -> List[str]:
        for kw in call_node.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                extracted = []
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        extracted.append(elt.value)
                return extracted or ["GET"]
        return ["GET"]

    def _extract_parameters(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, route_path: str) -> List[RouteParam]:
        params: List[RouteParam] = []
        path_vars = set(re.findall(r"\{([a-zA-Z0-9_]+)\}", route_path))

        for arg in func_node.args.args:
            name = arg.arg
            if name in ("self", "cls", "request"):
                continue

            ptype = "str"
            if arg.annotation and isinstance(arg.annotation, ast.Name):
                ptype = arg.annotation.id

            in_loc = "path" if name in path_vars else "query"
            params.append(RouteParam(name=name, param_type=ptype, in_location=in_loc))

        return params


class TaintGuidedMutator:
    """Synthesizes benign, surgical canary payloads specifically adapted to the taint sink."""

    CANARY_TOKEN = "cybercanary_9182"
    MATH_PRODUCT = 102947  # 7919 * 13

    def generate_probes_for_sink(self, sink_type: str, base_value: str = "test") -> List[Dict[str, Any]]:
        """Generate targeted non-destructive probe payloads."""
        st = sink_type.lower()

        if "sql" in st:
            return [
                {
                    "type": "SQL_CANARY_ARITHMETIC",
                    "payload": f"{base_value}' OR 7919*13={self.MATH_PRODUCT} -- ",
                    "expected_oracle": str(self.MATH_PRODUCT),
                    "is_destructive": False,
                },
                {
                    "type": "SQL_QUOTE_BREAK",
                    "payload": f"{base_value}'\"",
                    "expected_oracle": "SQL syntax error",
                    "is_destructive": False,
                },
            ]
        elif "cmd" in st or "command" in st or "shell" in st or "exec" in st:
            return [
                {
                    "type": "CMD_CANARY_ECHO",
                    "payload": f"; echo {self.CANARY_TOKEN} ;",
                    "expected_oracle": self.CANARY_TOKEN,
                    "is_destructive": False,
                },
                {
                    "type": "CMD_SUBSTITUTION_ECHO",
                    "payload": f"$(echo {self.CANARY_TOKEN})",
                    "expected_oracle": self.CANARY_TOKEN,
                    "is_destructive": False,
                },
            ]
        elif "path" in st or "file" in st:
            return [
                {
                    "type": "PATH_TRAVERSAL_CANARY",
                    "payload": f"../../../../etc/passwd",
                    "expected_oracle": "root:x:0:0:",
                    "is_destructive": False,
                },
                {
                    "type": "PATH_TRAVERSAL_BYPASS",
                    "payload": f"....//....//....//etc/passwd",
                    "expected_oracle": "root:x:0:0:",
                    "is_destructive": False,
                },
            ]
        elif "xss" in st or "html" in st:
            return [
                {
                    "type": "XSS_BENIGN_CANARY_TAG",
                    "payload": f"<probe-canary id='{self.CANARY_TOKEN}' />",
                    "expected_oracle": f"<probe-canary id='{self.CANARY_TOKEN}' />",
                    "is_destructive": False,
                }
            ]

        # Generic boundary check
        return [
            {
                "type": "GENERIC_CANARY",
                "payload": f"{base_value}_{self.CANARY_TOKEN}",
                "expected_oracle": self.CANARY_TOKEN,
                "is_destructive": False,
            }
        ]


class AttackSurfaceScanner:
    """Audits external exposure: Dangling DNS CNAMEs and TLS/Cipher deprecation."""

    TAKEOVER_PATTERNS = [
        (r"\.s3\.amazonaws\.com$", "AWS S3 Bucket", "NoSuchBucket"),
        (r"\.s3-website-.*\.amazonaws\.com$", "AWS S3 Website", "NoSuchBucket"),
        (r"\.github\.io$", "GitHub Pages", "There isn't a GitHub Pages site here"),
        (r"\.azurewebsites\.net$", "Azure App Service", "404 Web Site not found"),
        (r"\.herokuapp\.com$", "Heroku", "No such app"),
    ]

    DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
    WEAK_CIPHER_SUBSTRINGS = {"RC4", "3DES", "DES", "MD5", "NULL", "EXPORT"}

    def audit_cname_record(self, subdomain: str, cname_target: str, resolved_nxdomain: bool = False, response_body: str = "") -> Optional[Dict[str, Any]]:
        """Check if a CNAME record points to a dangling vulnerable cloud resource."""
        for pattern, provider, error_fingerprint in self.TAKEOVER_PATTERNS:
            if re.search(pattern, cname_target, re.IGNORECASE):
                # If target is NXDOMAIN or response contains error fingerprint
                if resolved_nxdomain or (error_fingerprint and error_fingerprint in response_body):
                    return {
                        "id": "ASM-DNS-001",
                        "severity": "CRITICAL",
                        "title": f"Dangling DNS CNAME Subdomain Takeover ({provider})",
                        "subdomain": subdomain,
                        "cname_target": cname_target,
                        "provider": provider,
                        "evidence": "Target returned NXDOMAIN or provider 404 unallocated fingerprint.",
                        "remediation": f"Delete the CNAME record for '{subdomain}' or re-register the target in {provider}.",
                    }
        return None

    def audit_tls_posture(
        self, supported_protocols: List[str], cipher_suites: List[str]
    ) -> Dict[str, Any]:
        """Audit TLS protocols and cipher suites for weak crypto and missing PFS."""
        issues: List[Dict[str, Any]] = []

        # 1. Deprecated TLS protocol versions
        for proto in supported_protocols:
            if proto in self.DEPRECATED_TLS_VERSIONS:
                issues.append({
                    "id": "ASM-TLS-001",
                    "severity": "HIGH",
                    "title": f"Deprecated TLS Protocol Enabled: {proto}",
                    "description": f"Protocol {proto} is insecure and deprecated by RFC 8996.",
                    "remediation": "Disable TLS 1.0/1.1 and enforce TLS 1.2 or TLS 1.3.",
                })

        # 2. Weak ciphers
        for cipher in cipher_suites:
            for weak in self.WEAK_CIPHER_SUBSTRINGS:
                if weak in cipher.upper():
                    issues.append({
                        "id": "ASM-TLS-002",
                        "severity": "HIGH",
                        "title": f"Insecure Cipher Suite: {cipher}",
                        "description": f"Cipher suite relies on broken primitive ({weak}).",
                        "remediation": "Remove weak cipher suite and enable AEAD ciphers (AES-GCM / CHACHA20-POLY1305).",
                    })
                    break

        # 3. Forward Secrecy check
        has_pfs = any("ECDHE" in c or "DHE" in c for c in cipher_suites)
        if not has_pfs and len(cipher_suites) > 0:
            issues.append({
                "id": "ASM-TLS-003",
                "severity": "MEDIUM",
                "title": "Absence of Perfect Forward Secrecy (PFS)",
                "description": "None of the configured ciphers support ephemeral Diffie-Hellman key exchange (ECDHE/DHE).",
                "remediation": "Prioritize ECDHE-ECDSA or ECDHE-RSA cipher suites.",
            })

        return {
            "secure": len(issues) == 0,
            "total_issues": len(issues),
            "issues": issues,
        }


class HybridIASTEngine:
    """Coordinates AST route extraction, taint parameter mapping, and probe synthesis."""

    def __init__(self) -> None:
        self.harvester = ASTRouteHarvester()
        self.mutator = TaintGuidedMutator()
        self.asm_scanner = AttackSurfaceScanner()

    def generate_targeted_fuzz_plan(
        self,
        source_code: str,
        filename: str = "routes.py",
        taint_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Harvest routes and align with taint findings to create targeted test probes."""
        routes = self.harvester.harvest_from_source(source_code, filename)
        taint_map = {tf.get("param_name", ""): tf.get("sink_type", "sql") for tf in (taint_findings or [])}

        planned_tests: List[Dict[str, Any]] = []

        for r in routes:
            for p in r.parameters:
                if p.name in taint_map:
                    p.is_tainted = True
                    p.taint_sink = taint_map[p.name]
                    probes = self.mutator.generate_probes_for_sink(p.taint_sink, base_value="testval")
                    planned_tests.append({
                        "route": r.path,
                        "method": r.method,
                        "parameter": p.name,
                        "in_location": p.in_location,
                        "taint_sink": p.taint_sink,
                        "probes": probes,
                    })

        return {
            "total_routes_discovered": len(routes),
            "targeted_fuzz_targets": len(planned_tests),
            "routes": [r.to_dict() for r in routes],
            "fuzz_plan": planned_tests,
        }
