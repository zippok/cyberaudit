"""
CyberAudit Invariant Contracts & AST Call Graph Engine
Deterministic verification of declarative software invariants (.audit-rules.yaml)
without normative hallucinations or unnecessary token expenditure.
"""

import ast
import os
import glob
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("cyberaudit.core.invariants")


@dataclass
class InvariantRule:
    """Represents an architectural or business invariant contract."""
    id: str
    name: str
    description: str
    target: str
    entrypoints: List[str] = field(default_factory=list)
    required_guards: List[str] = field(default_factory=list)
    forbidden_sinks: List[str] = field(default_factory=list)
    exemptions: List[str] = field(default_factory=list)
    severity: str = "HIGH"
    remediation_category: str = "input_guard"


@dataclass
class InvariantViolation:
    """Formal finding when a control path violates a declared invariant contract."""
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    function_name: str
    violation_type: str
    detail: str
    ast_slice: str
    severity: str
    remediation_category: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvariantAuditReport:
    """Aggregated compliance result for all declared invariants."""
    timestamp: str
    total_rules_evaluated: int
    total_files_audited: int
    total_violations: int
    compliance_score: float
    violations: List[InvariantViolation] = field(default_factory=list)
    status: str = "PASS"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["violations"] = [v.to_dict() if isinstance(v, InvariantViolation) else v for v in self.violations]
        return data


class InvariantContractParser:
    """Parses .audit-rules.yaml specifications into strongly-typed InvariantRule instances."""

    @staticmethod
    def load_from_file(file_path: str) -> List[InvariantRule]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Invariant rules config not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        return InvariantContractParser.load_from_string(content)

    @staticmethod
    def load_from_string(yaml_content: str) -> List[InvariantRule]:
        if yaml:
            data = yaml.safe_load(yaml_content) or {}
        else:
            data = InvariantContractParser._simple_yaml_parse(yaml_content)

        rules: List[InvariantRule] = []
        raw_invariants = data.get("invariants", [])

        for inv in raw_invariants:
            contract = inv.get("contract", {})
            rule = InvariantRule(
                id=inv.get("id", "INV-UNKNOWN"),
                name=inv.get("name", "Unnamed Invariant"),
                description=inv.get("description", ""),
                target=inv.get("target", "**/*.py"),
                entrypoints=inv.get("entrypoints", []),
                required_guards=contract.get("required_guards", []),
                forbidden_sinks=contract.get("forbidden_sinks", []),
                exemptions=inv.get("exemptions", []),
                severity=inv.get("severity", "HIGH"),
                remediation_category=inv.get("remediation_category", "input_guard")
            )
            rules.append(rule)

        return rules

    @staticmethod
    def load_from_file_full(file_path: str) -> "InvariantRuleSet":
        """Returns the full rule-set including the dynamic_path_policy directive.
        Preferred over load_from_file for CLI / CI consumers that need the policy.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Invariant rules config not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        if yaml:
            data = yaml.safe_load(content) or {}
        else:
            data = {}
        policy = data.get("dynamic_path_policy", "warn")
        rules = InvariantContractParser.load_from_string(content)
        return InvariantRuleSet(rules=rules, dynamic_path_policy=policy)

    @staticmethod
    def _simple_yaml_parse(content: str) -> Dict[str, Any]:
        # Minimal fallback parser if pyyaml is missing
        return {"invariants": []}


@dataclass
class InvariantRuleSet:
    """Full rule set including top-level policy directives from .audit-rules.yaml."""
    rules: List[InvariantRule] = field(default_factory=list)
    dynamic_path_policy: str = "warn"  # strict | warn | require_annotation


class AstCallGraphEngine:
    """
    Constructs an AST-level Call Graph for target Python files and checks
    if function control paths strictly respect the declared Invariant Contracts.

    dynamic_path_policy controls UNVERIFIED_DYNAMIC_PATH emission:
      - strict             → severity mirrors the rule; exit 1 in CI
      - warn               → severity clamped to LOW (INFO in SARIF); exit 0
      - require_annotation → violation only when no 'cyberaudit:trust-dynamic'
                             annotation exists in the function docstring
    """

    # Patterns that indicate dynamic dispatch (non-static callees)
    DYNAMIC_DISPATCH_PATTERNS = [
        "getattr(",
        "eval(",
        "exec(",
        "__import__(",
        "importlib.import_module(",
        "operator.methodcaller(",
    ]

    def __init__(self, base_dir: str = ".", dynamic_path_policy: str = "warn", cache: Optional[Any] = None):
        self.base_dir = os.path.abspath(base_dir)
        self.dynamic_path_policy = dynamic_path_policy
        self.cache = cache

    def audit_invariants(self, rules: List[InvariantRule]) -> InvariantAuditReport:
        import datetime
        all_violations: List[InvariantViolation] = []
        audited_files: Set[str] = set()

        for rule in rules:
            target_pattern = os.path.join(self.base_dir, rule.target.replace("/", os.sep))
            matched_files = glob.glob(target_pattern, recursive=True)

            for fpath in matched_files:
                if not fpath.endswith(".py") or not os.path.isfile(fpath):
                    continue
                audited_files.add(fpath)
                violations = self._audit_file_against_rule(fpath, rule)
                all_violations.extend(violations)

        if self.cache:
            try:
                self.cache.save()
            except Exception as e:
                logger.debug("Failed to persist AST cache: %s", e)

        total_rules = len(rules)
        total_files = len(audited_files)
        total_violations = len(all_violations)

        blocking_violations = [
            v for v in all_violations
            if not (v.violation_type == "UNVERIFIED_DYNAMIC_PATH" and self.dynamic_path_policy == "warn")
        ]

        score = 100.0
        if total_files > 0:
            score = max(0.0, 100.0 - (len(blocking_violations) * 15.0))

        report = InvariantAuditReport(
            timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_rules_evaluated=total_rules,
            total_files_audited=total_files,
            total_violations=total_violations,
            compliance_score=round(score, 1),
            violations=all_violations,
            status="PASS" if len(blocking_violations) == 0 else "FAIL"
        )
        return report

    def _audit_file_against_rule(self, file_path: str, rule: InvariantRule) -> List[InvariantViolation]:
        violations: List[InvariantViolation] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
            tree = ast.parse(source, filename=file_path)
        except Exception as e:
            logger.warning("Could not parse AST for %s: %s", file_path, e)
            return violations

        source_lines = source.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_name = node.name

                # Check if function matches any entrypoint pattern
                matches_entrypoint = self._matches_entrypoint(node, rule.entrypoints)
                if not matches_entrypoint:
                    continue

                # Check exemptions
                if self._is_exempt(fn_name, file_path, rule.exemptions):
                    continue

                # Analyze Call Graph & AST within function body
                fn_calls = self._extract_calls(node)
                context_managers = self._extract_with_contexts(node)

                # Check Rule Type: Context Managers (e.g. INV-IO-002)
                if "open(" in rule.forbidden_sinks or "open" in rule.forbidden_sinks:
                    bare_opens = self._find_bare_opens(node)
                    for call_node in bare_opens:
                        ast_slice = self._get_ast_slice(source_lines, call_node.lineno)
                        violations.append(InvariantViolation(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            file_path=os.path.relpath(file_path, self.base_dir),
                            line_number=call_node.lineno,
                            function_name=fn_name,
                            violation_type="MISSING_CONTEXT_MANAGER",
                            detail=f"Llamada a open() sin context manager 'with open(...)' detectada en {fn_name}",
                            ast_slice=ast_slice,
                            severity=rule.severity,
                            remediation_category=rule.remediation_category
                        ))

                # Check Rule Type: Required Guards before Forbidden Sinks (e.g. INV-AUTH-001)
                if rule.forbidden_sinks:
                    for sink in rule.forbidden_sinks:
                        for call_node, call_str in fn_calls:
                            if sink in call_str:
                                # Check if any required guard is called anywhere in the function
                                has_guard = any(guard in c_str for _, c_str in fn_calls for guard in rule.required_guards)
                                if not has_guard:
                                    ast_slice = self._get_ast_slice(source_lines, call_node.lineno)
                                    violations.append(InvariantViolation(
                                        rule_id=rule.id,
                                        rule_name=rule.name,
                                        file_path=os.path.relpath(file_path, self.base_dir),
                                        line_number=call_node.lineno,
                                        function_name=fn_name,
                                        violation_type="UNGUARDED_MUTATION_SINK",
                                        detail=f"Sink de mutación '{sink}' ejecutado en {fn_name} sin la guarda requerida: {rule.required_guards}",
                                        ast_slice=ast_slice,
                                        severity=rule.severity,
                                        remediation_category=rule.remediation_category
                                    ))
                # ----------------------------------------------------------------
                # Check Rule Type: Dynamic Dispatch Patterns
                # Detects getattr(), eval(), exec(), __import__() inside guarded
                # entrypoints that target forbidden sinks. Behavior governed by self.dynamic_path_policy.
                # ----------------------------------------------------------------
                if rule.forbidden_sinks:
                    dynamic_hits = self._find_dynamic_dispatch(node, source_lines)
                    for call_node, dispatch_pattern, ast_slice in dynamic_hits:
                        # require_annotation: skip if docstring contains trust marker
                        if self.dynamic_path_policy == "require_annotation":
                            fn_docstring = ast.get_docstring(node) or ""
                            if "cyberaudit:trust-dynamic" in fn_docstring:
                                continue

                        # strict → full rule severity; warn → clamped to LOW
                        eff_severity = (
                            rule.severity
                            if self.dynamic_path_policy == "strict"
                            else "LOW"
                        )
                        violations.append(InvariantViolation(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            file_path=os.path.relpath(file_path, self.base_dir),
                            line_number=call_node.lineno,
                            function_name=fn_name,
                            violation_type="UNVERIFIED_DYNAMIC_PATH",
                            detail=(
                                f"Despacho dinámico '{dispatch_pattern}' detectado en "
                                f"{fn_name} — el análisis estático no puede trazar el callee "
                                f"completo. Política: {self.dynamic_path_policy}."
                            ),
                            ast_slice=ast_slice,
                            severity=eff_severity,
                            remediation_category="dynamic_dispatch_review"
                        ))

        return violations

    def _find_dynamic_dispatch(
        self, fn_node: ast.AST, source_lines: List[str]
    ) -> List[tuple]:
        """Returns (call_node, pattern_str, ast_slice) tuples for dynamic calls."""
        hits = []
        for child in ast.walk(fn_node):
            if isinstance(child, ast.Call):
                call_str = ast.unparse(child.func) if hasattr(ast, "unparse") else ""
                # Match patterns like getattr(, eval(, exec(
                for pat in self.DYNAMIC_DISPATCH_PATTERNS:
                    # Strip trailing '(' to compare against ast.unparse result
                    fn_token = pat.rstrip("(")
                    if call_str == fn_token or call_str.endswith("." + fn_token):
                        ast_slice = self._get_ast_slice(source_lines, child.lineno)
                        hits.append((child, pat, ast_slice))
                        break  # one match per call node
        return hits

    def _matches_entrypoint(self, fn_node: ast.AST, entrypoints: List[str]) -> bool:
        if not entrypoints or "def *" in entrypoints:
            return True

        fn_name = getattr(fn_node, "name", "")
        decorators: List[str] = []
        for dec in getattr(fn_node, "decorator_list", []):
            dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
            decorators.append(dec_src)

        for ep in entrypoints:
            if ep.startswith("@"):
                dec_target = ep[1:]
                if any(dec_target in d for d in decorators):
                    return True
            elif ep.startswith("def "):
                prefix = ep[4:].replace("*", "")
                if fn_name.startswith(prefix):
                    return True
            elif ep in fn_name:
                return True

        return False

    def _is_exempt(self, fn_name: str, file_path: str, exemptions: List[str]) -> bool:
        rel_path = os.path.relpath(file_path, self.base_dir).replace("\\", "/")
        for ex in exemptions:
            if ex in fn_name or ex in rel_path:
                return True
        return False

    def _extract_calls(self, node: ast.AST) -> List[tuple]:
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_str = ast.unparse(child.func) if hasattr(ast, "unparse") else ""
                calls.append((child, call_str))
        return calls

    def _extract_with_contexts(self, node: ast.AST) -> List[ast.With]:
        return [child for child in ast.walk(node) if isinstance(child, (ast.With, ast.AsyncWith))]

    def _find_bare_opens(self, fn_node: ast.AST) -> List[ast.Call]:
        """Detects calls to open() that are NOT used inside a with/async with context manager."""
        with_open_lines: Set[int] = set()
        for w in ast.walk(fn_node):
            if isinstance(w, (ast.With, ast.AsyncWith)):
                for item in w.items:
                    if isinstance(item.context_expr, ast.Call):
                        fn_name = ast.unparse(item.context_expr.func) if hasattr(ast, "unparse") else ""
                        if fn_name == "open":
                            with_open_lines.add(item.context_expr.lineno)

        bare_opens = []
        for child in ast.walk(fn_node):
            if isinstance(child, ast.Call):
                name = ast.unparse(child.func) if hasattr(ast, "unparse") else ""
                if name == "open" and child.lineno not in with_open_lines:
                    bare_opens.append(child)
        return bare_opens

    def _get_ast_slice(self, source_lines: List[str], lineno: int, window: int = 4) -> str:
        start = max(0, lineno - window - 1)
        end = min(len(source_lines), lineno + window)
        snippet = source_lines[start:end]
        return "\n".join(snippet)
