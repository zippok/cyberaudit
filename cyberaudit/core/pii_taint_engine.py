"""
cyberaudit/core/pii_taint_engine.py
===================================
Automated PII Data Flow Tracking & Privacy Governance Engine (GDPR / HIPAA / PCI-DSS).

Solves the gap between technical code auditing and data protection compliance.
Identifies sensitive Personal Identifiable Information (PII) defined in ORM models,
schemas, or variables, and tracks their propagation to non-compliant sinks (unencrypted
logging, external egress, plain file storage).

Outputs:
- Structured PII compliance violations mapped to specific legal articles:
  * GDPR: Art. 5(1)(f) (Confidentiality), Art. 32 (Security of Processing).
  * HIPAA: 45 CFR § 164.312 (Technical Safeguards for ePHI).
  * PCI-DSS: Req 3.4 (Cardholder Data Protection), Req 4.1 (Transmission Protection).
- Automatic visual data lineage diagram (Mermaid graph).
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class PiiCategory(str, Enum):
    GDPR_IDENTIFIER = "GDPR_IDENTIFIER"
    PCI_DSS_FINANCIAL = "PCI_DSS_FINANCIAL"
    HIPAA_HEALTH = "HIPAA_HEALTH"
    SECURITY_CREDENTIAL = "SECURITY_CREDENTIAL"


@dataclass
class PiiDefinition:
    field_name: str
    category: PiiCategory
    regulatory_frameworks: Dict[str, str]
    severity: str = "HIGH"


# Standard dictionary of sensitive PII field keywords
PII_CATALOG: Dict[str, PiiDefinition] = {
    # GDPR Personal Identifiers
    "dni": PiiDefinition("dni", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 5(1)(f), Art. 32"}, "HIGH"),
    "nif": PiiDefinition("nif", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 5(1)(f), Art. 32"}, "HIGH"),
    "ssn": PiiDefinition("ssn", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 5(1)(f), Art. 32", "NIST": "SP 800-122"}, "CRITICAL"),
    "passport": PiiDefinition("passport", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 5(1)(f)"}, "HIGH"),
    "email": PiiDefinition("email", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 5(1)(f)"}, "MEDIUM"),
    "phone": PiiDefinition("phone", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 5(1)(f)"}, "MEDIUM"),
    "birth_date": PiiDefinition("birth_date", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 9 (Special Category)"}, "HIGH"),
    "national_id": PiiDefinition("national_id", PiiCategory.GDPR_IDENTIFIER, {"GDPR": "Art. 5(1)(f)"}, "HIGH"),

    # PCI-DSS Cardholder Data
    "credit_card": PiiDefinition("credit_card", PiiCategory.PCI_DSS_FINANCIAL, {"PCI_DSS": "Req 3.4, Req 4.1"}, "CRITICAL"),
    "card_number": PiiDefinition("card_number", PiiCategory.PCI_DSS_FINANCIAL, {"PCI_DSS": "Req 3.4, Req 4.1"}, "CRITICAL"),
    "cvv": PiiDefinition("cvv", PiiCategory.PCI_DSS_FINANCIAL, {"PCI_DSS": "Req 3.2 (Do Not Store SAD)"}, "CRITICAL"),
    "pan": PiiDefinition("pan", PiiCategory.PCI_DSS_FINANCIAL, {"PCI_DSS": "Req 3.4"}, "CRITICAL"),
    "iban": PiiDefinition("iban", PiiCategory.PCI_DSS_FINANCIAL, {"PCI_DSS": "Req 3.4", "GDPR": "Art. 32"}, "HIGH"),
    "bank_account": PiiDefinition("bank_account", PiiCategory.PCI_DSS_FINANCIAL, {"PCI_DSS": "Req 3.4"}, "HIGH"),

    # HIPAA Protected Health Information (ePHI)
    "medical_record": PiiDefinition("medical_record", PiiCategory.HIPAA_HEALTH, {"HIPAA": "45 CFR § 164.312"}, "CRITICAL"),
    "diagnosis": PiiDefinition("diagnosis", PiiCategory.HIPAA_HEALTH, {"HIPAA": "45 CFR § 164.312", "GDPR": "Art. 9"}, "CRITICAL"),
    "prescription": PiiDefinition("prescription", PiiCategory.HIPAA_HEALTH, {"HIPAA": "45 CFR § 164.312"}, "CRITICAL"),
    "patient_id": PiiDefinition("patient_id", PiiCategory.HIPAA_HEALTH, {"HIPAA": "45 CFR § 164.514"}, "HIGH"),
    "health_data": PiiDefinition("health_data", PiiCategory.HIPAA_HEALTH, {"HIPAA": "45 CFR § 164.312"}, "CRITICAL"),

    # Security Credentials
    "password": PiiDefinition("password", PiiCategory.SECURITY_CREDENTIAL, {"ISO_27001": "A.9.4.3", "PCI_DSS": "Req 8.2"}, "CRITICAL"),
    "password_hash": PiiDefinition("password_hash", PiiCategory.SECURITY_CREDENTIAL, {"NIST": "SP 800-63B"}, "HIGH"),
    "pin": PiiDefinition("pin", PiiCategory.SECURITY_CREDENTIAL, {"PCI_DSS": "Req 3.2"}, "CRITICAL"),
    "api_secret": PiiDefinition("api_secret", PiiCategory.SECURITY_CREDENTIAL, {"SOC2": "CC6.1"}, "CRITICAL"),
}


@dataclass
class PiiSourceNode:
    field_name: str
    model_or_class: str
    category: PiiCategory
    file_path: str
    line_number: int


@dataclass
class PiiSinkNode:
    sink_type: str  # "LOGGING", "NETWORK_EGRESS", "UNENCRYPTED_STORAGE"
    callee_name: str  # e.g. "logger.info", "print", "requests.post"
    file_path: str
    line_number: int
    code_snippet: str


@dataclass
class PiiViolation:
    source: PiiSourceNode
    sink: PiiSinkNode
    regulatory_frameworks: Dict[str, str]
    severity: str
    recommendation: str

    def to_dict(self) -> Dict:
        return {
            "pii_field": self.source.field_name,
            "category": self.source.category.value,
            "model_or_class": self.source.model_or_class,
            "source_location": f"{self.source.file_path}:{self.source.line_number}",
            "sink_type": self.sink.sink_type,
            "sink_callee": self.sink.callee_name,
            "sink_location": f"{self.sink.file_path}:{self.sink.line_number}",
            "code_snippet": self.sink.code_snippet,
            "compliance_controls": self.regulatory_frameworks,
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


class PiiDataFlowEngine:
    """
    Rastrea el flujo de datos sensibles desde modelos hasta sumideros de fuga.
    """

    LOG_SINKS = {
        "logger.info", "logger.debug", "logger.warn", "logger.warning",
        "logger.error", "logger.critical", "logging.info", "logging.debug",
        "logging.warning", "logging.error", "print", "sys.stderr.write", "sys.stdout.write"
    }

    NETWORK_SINKS = {
        "requests.post", "requests.get", "requests.put", "httpx.post", "httpx.get",
        "urllib.request.urlopen", "http.client.HTTPConnection"
    }

    def __init__(self, project_root: str):
        self.project_root = os.path.abspath(project_root)

    def scan_code(self, file_path: str, content: str) -> List[PiiViolation]:
        """Scans a single file's content for PII model declarations and leaky sinks."""
        try:
            tree = ast.parse(content, filename=file_path)
        except Exception:
            return []

        lines = content.splitlines()

        # Step 1: Detect PII fields in classes / dataclasses / ORM models
        sources = self._detect_pii_sources(tree, file_path)

        # Step 2: Detect leaks in functions where PII variables/attributes are used in sinks
        violations = self._trace_pii_leaks(tree, file_path, lines, sources)
        return violations

    def _detect_pii_sources(self, tree: ast.AST, file_path: str) -> List[PiiSourceNode]:
        sources: List[PiiSourceNode] = []

        for node in ast.walk(tree):
            # Class definitions (ORM / Pydantic / Dataclasses)
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    field_name = None
                    lineno = getattr(item, "lineno", node.lineno)

                    # e.g. dni = Column(String) or dni: str
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name):
                                field_name = target.id
                    elif isinstance(item, ast.AnnAssign):
                        if isinstance(item.target, ast.Name):
                            field_name = item.target.id

                    if field_name:
                        matched = self._match_pii_catalog(field_name)
                        if matched:
                            sources.append(PiiSourceNode(
                                field_name=field_name,
                                model_or_class=node.name,
                                category=matched.category,
                                file_path=file_path,
                                line_number=lineno,
                            ))

            # Standalone function arguments or dictionary keys
            elif isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    matched = self._match_pii_catalog(arg.arg)
                    if matched:
                        sources.append(PiiSourceNode(
                            field_name=arg.arg,
                            model_or_class=f"{node.name}() argument",
                            category=matched.category,
                            file_path=file_path,
                            line_number=node.lineno,
                        ))

        return sources

    def _match_pii_catalog(self, name: str) -> Optional[PiiDefinition]:
        lower = name.lower()
        # Direct match
        if lower in PII_CATALOG:
            return PII_CATALOG[lower]
        # Substring / pattern match e.g. user_dni, customer_credit_card, patient_medical_record
        for key, pii_def in PII_CATALOG.items():
            if f"_{key}" in lower or f"{key}_" in lower or lower.startswith(key) or lower.endswith(key):
                return pii_def
        return None

    def _trace_pii_leaks(
        self,
        tree: ast.AST,
        file_path: str,
        lines: List[str],
        known_sources: List[PiiSourceNode]
    ) -> List[PiiViolation]:
        violations: List[PiiViolation] = []
        source_field_names = {s.field_name.lower(): s for s in known_sources}

        # Step 1: Propagate local assignments (e.g. payload = {"card": credit_card})
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                refs = self._find_pii_references(node.value, source_field_names)
                if refs:
                    first_ref = next(iter(refs.values()))
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            source_field_names[target.id.lower()] = first_ref

        # Step 2: Trace calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee_str = self._resolve_call_str(node.func)
                sink_type = None
                if callee_str in self.LOG_SINKS:
                    sink_type = "LOGGING"
                elif callee_str in self.NETWORK_SINKS:
                    sink_type = "NETWORK_EGRESS"

                if sink_type:
                    # Check both positional args and keyword arguments (e.g. json=payload)
                    all_call_args = list(node.args) + [kw.value for kw in getattr(node, "keywords", [])]
                    for arg in all_call_args:
                        referenced_pii = self._find_pii_references(arg, source_field_names)
                        for var_ident, pii_src in referenced_pii.items():
                            pii_meta = PII_CATALOG.get(pii_src.field_name) or self._match_pii_catalog(pii_src.field_name)
                            if not pii_meta:
                                continue

                            line_no = getattr(node, "lineno", 1)
                            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
                            sink_node = PiiSinkNode(
                                sink_type=sink_type,
                                callee_name=callee_str,
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                            )

                            regs = pii_meta.regulatory_frameworks
                            reg_str = ", ".join(f"{k} {v}" for k, v in regs.items())
                            rec = (
                                f"Enmascarar o eliminar la variable sensible '{pii_src.field_name}' antes de enviarla a {callee_str}. "
                                f"La exposición de datos personales sin cifrar o anonimizar incumple {reg_str}."
                            )

                            violations.append(PiiViolation(
                                source=pii_src,
                                sink=sink_node,
                                regulatory_frameworks=regs,
                                severity=pii_meta.severity,
                                recommendation=rec,
                            ))

        return violations

    def _find_pii_references(self, node: ast.AST, source_fields: Dict[str, PiiSourceNode]) -> Dict[str, PiiSourceNode]:
        """Finds any identifiers or attributes in an expression that match PII fields."""
        refs: Dict[str, PiiSourceNode] = {}
        for sub in ast.walk(node):
            name = None
            if isinstance(sub, ast.Name):
                name = sub.id.lower()
            elif isinstance(sub, ast.Attribute):
                name = sub.attr.lower()

            if name:
                # Match against known sources or general catalog
                if name in source_fields:
                    refs[name] = source_fields[name]
                else:
                    matched = self._match_pii_catalog(name)
                    if matched:
                        # Synthetic source
                        refs[matched.field_name] = PiiSourceNode(
                            field_name=matched.field_name,
                            model_or_class="Local variable",
                            category=matched.category,
                            file_path="",
                            line_number=getattr(sub, "lineno", 1),
                        )
        return refs

    def _resolve_call_str(self, func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            val = self._resolve_call_str(func_node.value)
            return f"{val}.{func_node.attr}" if val else func_node.attr
        return ""

    @staticmethod
    def generate_mermaid_lineage(violations: List[PiiViolation]) -> str:
        """Generates a Mermaid graph illustrating PII data flows into sensitive sinks."""
        if not violations:
            return "```mermaid\ngraph LR\n    OK[No PII Leaks Detected]\n```"

        lines = ["```mermaid", "graph TD"]
        for idx, v in enumerate(violations, start=1):
            src_id = f"SRC_{idx}"
            sink_id = f"SINK_{idx}"
            reg_label = "/".join(v.regulatory_frameworks.keys())
            lines.append(f'    {src_id}["{v.source.model_or_class}: {v.source.field_name}"]')
            lines.append(f'    {sink_id}["{v.sink.callee_name} ({v.sink.sink_type})\\nLine {v.sink.line_number}"]')
            lines.append(f'    {src_id} -->|"VIOLATION: {reg_label}"| {sink_id}')
            lines.append(f'    style {sink_id} fill:#ffdddd,stroke:#ff0000,stroke-width:2px')
        lines.append("```")
        return "\n".join(lines)
