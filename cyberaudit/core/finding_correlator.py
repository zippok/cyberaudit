"""
CyberAudit Finding Correlation Engine — Deduplication & Exposure Scoring.

Three-layer pipeline:
  Layer 1: Fingerprinting   → Deterministic hash per (file, line_range, category)
  Layer 2: Cluster Merging  → Groups findings from same component/file
  Layer 3: Exposure Scoring → Prioritizes public routes vs. internal utilities
"""

import hashlib
import os
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger("cyberaudit.core.finding_correlator")

# Category normalization mapping: scanner-specific IDs → canonical buckets
CATEGORY_BUCKETS = {
    # Security
    "Penetration Tester & AppSec": "security",
    "Security Engineer & DevSecOps": "security",
    "Security Analyst & SOC": "security",
    "Cloud & Infrastructure Defense": "security",
    "DFIR & Endpoint Investigation": "security",
    "AI Security & LLM Defenses": "security",
    # Quality
    "Software QA & Code Quality": "quality",
    # Architecture
    "Software Architecture & Governance": "architecture",
    # UI/UX
    "UI/UX & Accessibility (a11y)": "accessibility",
}

# Exposure classification paths
PUBLIC_INDICATORS = [
    "web/app.py", "api/", "routes/", "views/", "endpoints/",
    "handlers/", "controllers/", "server.py", "main.py",
]
TEST_INDICATORS = [
    "tests/", "test_", "_test.py", "conftest.py",
    "demo_environment/", "fixtures/", "mocks/",
]
INTERNAL_INDICATORS = [
    "scripts/", "utils/", "internal/", "tools/",
    "migrations/", "config/", "setup.py",
]


@dataclass
class CorrelationMetadata:
    """Additional metadata added by the correlation engine."""
    fingerprint: str = ""
    related_findings: List[str] = field(default_factory=list)
    source_scanners: List[str] = field(default_factory=list)
    exposure_score: float = 0.5
    exposure_label: str = "INTERNAL"  # PUBLIC, TRANSITIVE, INTERNAL, TEST
    component_path: str = ""
    correlation_confidence: str = "HIGH"


class FindingFingerprinter:
    """Generates deterministic fingerprints for deduplication.
    
    Fingerprint = hash(normalized_file + line_bucket + category_bucket)
    This groups findings that refer to the same code location and category,
    even if discovered by different scanners.
    """

    LINE_BUCKET_SIZE = 5  # Lines within 5 of each other → same bucket

    @staticmethod
    def fingerprint(finding_dict: Dict) -> str:
        """Generate a stable fingerprint for a finding dictionary.

        Uses AST-node semantic anchoring (class::method::kind) when the
        finding includes ast_class / ast_method metadata, falling back to the
        legacy line-bucket approach for scanner findings that don't carry AST
        context.

        Stability contract:
          - Inserting comment lines or blank lines → fingerprint UNCHANGED (ast mode)
          - Renaming a function or moving it to another class → new fingerprint (correct)
          - Two distinct vulnerability types in the same method → distinct if id_prefix differs

        Closure/Lambda Disambiguation:
          Anonymous functions (``<lambda>``) and same-named closures (``wrapper``,
          ``inner``, …) within a single file share the same ``ast_method`` token,
          which would produce colliding fingerprints.  Callers must populate
          ``ast_closure_index`` (0-based ordinal among sibling closures at the
          same scope) to disambiguate.  The canonical key then becomes:
              ast:{file}:{class}:{method}[{index}]:{category}:{id_prefix}
        """
        # --- Structural / AST semantic anchor (preferred, rename-stable, immune to line shifts) ---
        repo = finding_dict.get("repo", "")
        qualified_path = finding_dict.get("qualified_path", "")
        ast_class = finding_dict.get("ast_class", "")    # e.g. "PaymentService"
        ast_method = finding_dict.get("ast_method", "")  # e.g. "process_payment"
        node_sig = (
            finding_dict.get("node_ast_signature")
            or finding_dict.get("node_signature")
            or finding_dict.get("ast_node_signature")
            or ""
        )

        if qualified_path or ast_class or ast_method or node_sig or repo:
            file_path = FindingFingerprinter._normalize_path(finding_dict.get("file_path", ""))
            pillar = finding_dict.get("pillar", "")
            category = CATEGORY_BUCKETS.get(pillar, "other")
            finding_id = finding_dict.get("id", "")
            rule_id = finding_dict.get("rule_id") or finding_id
            id_prefix = rule_id.rsplit("-", 1)[0] if "-" in rule_id else rule_id

            # ── Closure / Lambda Disambiguation ──────────────────────────────
            _AMBIGUOUS = frozenset({
                "<lambda>", "wrapper", "inner", "decorator",
                "handler", "closure", "callback", "__call__",
            })
            is_ambiguous = (
                ast_method == "<lambda>"
                or ast_method in _AMBIGUOUS
                or ".<locals>." in ast_method   # qualname-style nested closure
            )
            if is_ambiguous:
                closure_index = finding_dict.get("ast_closure_index", 0)
                method_anchor = f"{ast_method}[{closure_index}]"
            else:
                method_anchor = ast_method

            # Resolve qualified scope path
            if qualified_path:
                effective_qualified = qualified_path
            elif ast_class and method_anchor:
                effective_qualified = f"{ast_class}::{method_anchor}"
            elif ast_class:
                effective_qualified = ast_class
            else:
                effective_qualified = method_anchor

            # Structural formula: Hash(Repo + Archivo + QualifiedPath + RuleID + NodeASTSignature)
            if repo or qualified_path or node_sig:
                raw = f"struct:{repo}:{file_path}:{effective_qualified}:{id_prefix}:{node_sig}"
            else:
                # Retains ast: format for backward compatibility with canonical AST tests
                raw = f"ast:{file_path}:{ast_class}:{method_anchor}:{category}:{id_prefix}"

            return "ast_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

        # --- Legacy line-bucket fallback ---
        file_path = FindingFingerprinter._normalize_path(finding_dict.get("file_path", ""))
        line = finding_dict.get("line_number") or 0
        line_bucket = (line // FindingFingerprinter.LINE_BUCKET_SIZE) * FindingFingerprinter.LINE_BUCKET_SIZE
        pillar = finding_dict.get("pillar", "")
        category = CATEGORY_BUCKETS.get(pillar, "other")
        finding_id = finding_dict.get("id", "")
        id_prefix = finding_id.rsplit("-", 1)[0] if "-" in finding_id else finding_id
        raw = f"{file_path}:{line_bucket}:{category}:{id_prefix}"
        return "ln_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:13]

    @staticmethod
    def structural_fingerprint(
        repo: str,
        file_path: str,
        qualified_path: str,
        rule_id: str,
        node_ast_signature: str = "",
    ) -> str:
        """Computes deterministic structural fingerprint:
        Hash(Repo + Archivo + QualifiedPath + RuleID + NodeASTSignature)
        Completely immune to physical line shifts, reformatting, or comment insertions.
        """
        norm_path = FindingFingerprinter._normalize_path(file_path)
        rule_prefix = rule_id.rsplit("-", 1)[0] if "-" in rule_id else rule_id
        raw = f"struct:{repo.strip()}:{norm_path}:{qualified_path.strip()}:{rule_prefix}:{node_ast_signature.strip()}"
        return "ast_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize file paths for consistent comparison."""
        return os.path.normpath(path).replace("\\", "/").lower().strip()

    @staticmethod
    def _canonical_for_test(finding_dict: Dict) -> str:
        """Return the raw canonical key string (before hashing) for test inspection.

        Mirrors the logic in ``fingerprint()`` exactly — useful for asserting
        that closure indices or method anchors are embedded correctly without
        duplicating the disambiguation logic in test code.
        """
        ast_class = finding_dict.get("ast_class", "")
        ast_method = finding_dict.get("ast_method", "")
        if not (ast_class or ast_method):
            return ""  # Not in AST mode
        file_path = FindingFingerprinter._normalize_path(finding_dict.get("file_path", ""))
        pillar = finding_dict.get("pillar", "")
        category = CATEGORY_BUCKETS.get(pillar, "other")
        finding_id = finding_dict.get("id", "")
        id_prefix = finding_id.rsplit("-", 1)[0] if "-" in finding_id else finding_id
        _AMBIGUOUS = frozenset({
            "<lambda>", "wrapper", "inner", "decorator",
            "handler", "closure", "callback", "__call__",
        })
        is_ambiguous = (
            ast_method == "<lambda>"
            or ast_method in _AMBIGUOUS
            or ".<locals>." in ast_method
        )
        if is_ambiguous:
            closure_index = finding_dict.get("ast_closure_index", 0)
            method_anchor = f"{ast_method}[{closure_index}]"
        else:
            method_anchor = ast_method
        return f"ast:{file_path}:{ast_class}:{method_anchor}:{category}:{id_prefix}"


class ExposureScorer:
    """Evaluates architectural exposure based on entrypoints and transitive reachability.
    
    Scoring:
      PUBLIC     = 1.0  (Direct HTTP/API/Web handlers or Celery entrypoints)
      TRANSITIVE = 0.85 (Modules imported directly or transitively by public entrypoints)
      INTERNAL   = 0.4  (Isolated scripts, developer tooling)
      TEST       = 0.1  (Test suites, fixtures, demo environments)
    """

    SCORES = {
        "PUBLIC": 1.0,
        "TRANSITIVE": 0.85,
        "INTERNAL": 0.4,
        "TEST": 0.1,
    }

    @staticmethod
    def score(file_path: str, reachable_from_entrypoint: bool = False) -> Tuple[float, str]:
        """Returns (score, label) for a file path.
        
        Args:
            file_path: Relative or absolute path to the file.
            reachable_from_entrypoint: Whether the module is imported by an active entrypoint.
        """
        norm = file_path.replace("\\", "/").lower()

        # Test files → lowest exposure
        for indicator in TEST_INDICATORS:
            if indicator in norm:
                return (ExposureScorer.SCORES["TEST"], "TEST")

        # Public entrypoint indicators (including background workers and services)
        extended_public = PUBLIC_INDICATORS + ["celery.py", "worker.py", "tasks.py", "service.py", "billing/"]
        for indicator in extended_public:
            if indicator in norm:
                return (ExposureScorer.SCORES["PUBLIC"], "PUBLIC")

        # Transitive exposure: imported by a public entrypoint
        if reachable_from_entrypoint:
            return (ExposureScorer.SCORES["TRANSITIVE"], "TRANSITIVE")

        # Internal utilities → medium-low priority
        for indicator in INTERNAL_INDICATORS:
            if indicator in norm:
                return (ExposureScorer.SCORES["INTERNAL"], "INTERNAL")

        # Default: internal
        return (ExposureScorer.SCORES["INTERNAL"], "INTERNAL")


class FindingClusterEngine:
    """Deduplicates and correlates findings from multiple scanners.
    
    For each cluster of findings sharing the same fingerprint:
    - Keeps the finding with highest severity as PRIMARY
    - Attaches others as related_findings
    - Merges CWE, MITRE, compliance metadata
    - Tracks all source scanner names
    """

    SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    def deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicates a list of finding dictionaries.
        
        Returns the deduplicated list with correlation metadata injected.
        """
        if not findings:
            return findings

        # Phase 1: Fingerprint all findings
        fingerprinter = FindingFingerprinter()
        clusters: Dict[str, List[Dict]] = defaultdict(list)

        for f in findings:
            fp = fingerprinter.fingerprint(f)
            f["_fingerprint"] = fp
            clusters[fp].append(f)

        # Phase 2: Merge clusters
        deduplicated: List[Dict] = []
        total_raw = len(findings)
        total_merged = 0

        for fp, cluster in clusters.items():
            if len(cluster) == 1:
                # Singleton: just add correlation metadata
                primary = cluster[0]
                self._inject_correlation_metadata(primary, [], fp)
                deduplicated.append(primary)
            else:
                # Multi-finding cluster: merge
                total_merged += len(cluster) - 1
                primary = self._select_primary(cluster)
                related = [f for f in cluster if f is not primary]
                self._merge_into_primary(primary, related, fp)
                deduplicated.append(primary)

        logger.info(
            "Deduplication: %d raw → %d unique (%d merged across %d clusters)",
            total_raw, len(deduplicated), total_merged, len(clusters)
        )

        # Phase 3: Exposure scoring with transitive reachability
        for f in deduplicated:
            f_path = f.get("file_path", "").replace("\\", "/").lower()
            score, label = ExposureScorer.score(f.get("file_path", ""))
            f["exposure_score"] = score
            f["exposure_label"] = label

        # Sort by effective priority:
        # INVARIANT SECURITY FLOOR: CRITICAL findings can NEVER drop below 4.5
        # and HIGH findings can NEVER drop below 3.2, regardless of whether they
        # reside in internal utils, preventing dangerous demotion of root vulnerabilities.
        def _effective_priority(f: Dict) -> float:
            sev_rank = self.SEVERITY_RANK.get(f.get("severity", "MEDIUM"), 3)
            exp_score = f.get("exposure_score", 0.5)
            raw_priority = sev_rank * exp_score
            if sev_rank >= 5:  # CRITICAL (e.g. hardcoded secrets, RCE)
                return max(4.5, raw_priority)
            elif sev_rank >= 4:  # HIGH
                return max(3.2, raw_priority)
            return raw_priority

        deduplicated.sort(key=_effective_priority, reverse=True)

        return deduplicated

    def get_dedup_stats(self, raw_count: int, deduped_count: int) -> Dict:
        """Returns statistics about the deduplication process."""
        return {
            "total_raw": raw_count,
            "after_dedup": deduped_count,
            "duplicates_removed": raw_count - deduped_count,
            "dedup_ratio": round(
                (1 - deduped_count / raw_count) * 100, 1
            ) if raw_count > 0 else 0.0,
        }

    def _select_primary(self, cluster: List[Dict]) -> Dict:
        """Selects the finding with highest severity as the primary."""
        return max(
            cluster,
            key=lambda f: self.SEVERITY_RANK.get(f.get("severity", "MEDIUM"), 3)
        )

    def _merge_into_primary(self, primary: Dict, related: List[Dict], fingerprint: str):
        """Merges metadata from related findings into the primary."""
        all_scanners = {primary.get("scanner_name", "")}
        all_related_ids = []
        merged_compliance = dict(primary.get("compliance_controls", {}))
        merged_cwe = set()
        merged_mitre = set()

        if primary.get("cwe_id"):
            merged_cwe.add(primary["cwe_id"])
        if primary.get("mitre_id"):
            merged_mitre.add(primary["mitre_id"])

        for r in related:
            all_scanners.add(r.get("scanner_name", ""))
            all_related_ids.append(r.get("id", ""))

            # Merge compliance controls
            for k, v in r.get("compliance_controls", {}).items():
                if k not in merged_compliance:
                    merged_compliance[k] = v

            # Merge CWE/MITRE
            if r.get("cwe_id"):
                merged_cwe.add(r["cwe_id"])
            if r.get("mitre_id"):
                merged_mitre.add(r["mitre_id"])

            # If related has better remediation, use it
            if r.get("remediation") and not primary.get("remediation"):
                primary["remediation"] = r["remediation"]

        # Inject correlation metadata
        self._inject_correlation_metadata(primary, all_related_ids, fingerprint)
        primary["source_scanners"] = sorted(all_scanners - {""})
        primary["compliance_controls"] = merged_compliance

        # Merge CWE/MITRE as comma-separated if multiple
        if len(merged_cwe) > 1:
            primary["cwe_id"] = ", ".join(sorted(merged_cwe))
        if len(merged_mitre) > 1:
            primary["mitre_id"] = ", ".join(sorted(merged_mitre))

    def _inject_correlation_metadata(self, finding: Dict, related_ids: List[str],
                                      fingerprint: str):
        """Adds correlation fields to a finding dictionary."""
        finding["fingerprint"] = fingerprint
        finding["related_findings"] = related_ids
        if "source_scanners" not in finding:
            finding["source_scanners"] = [finding.get("scanner_name", "")]
        finding["component_path"] = self._extract_component(finding.get("file_path", ""))
        # Remove internal working field
        finding.pop("_fingerprint", None)

    @staticmethod
    def _extract_component(file_path: str) -> str:
        """Extracts the component/package path from a file path."""
        norm = file_path.replace("\\", "/")
        parts = norm.split("/")
        if len(parts) >= 2:
            return "/".join(parts[:2])
        return parts[0] if parts else ""
