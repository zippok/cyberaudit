"""
Test Impact Analysis (TIA) — Smart test selection based on module import graphs.
Given a set of modified files, determines the minimal subset of tests that
need to run to verify no regressions were introduced.
"""
import ast
import os
import glob
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple

logger = logging.getLogger("cyberaudit.core.test_impact_analyzer")


@dataclass
class ImportEdge:
    """Represents a module-level import dependency."""
    source_file: str      # File that contains the import statement
    target_module: str    # Module being imported
    import_type: str      # 'import' or 'from_import'
    line_number: int


@dataclass 
class ImportGraph:
    """Directed graph of module dependencies."""
    edges: List[ImportEdge] = field(default_factory=list)
    # Maps: normalized module path -> set of files that import it
    reverse_index: Dict[str, Set[str]] = field(default_factory=dict)
    # Maps: file path -> set of modules it imports
    forward_index: Dict[str, Set[str]] = field(default_factory=dict)
    # All discovered Python files
    all_files: Set[str] = field(default_factory=set)


class ImportGraphBuilder:
    """Builds a project-wide import dependency graph using AST analysis."""
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = os.path.abspath(base_dir)
    
    def build(self, exclude_patterns: Optional[List[str]] = None) -> ImportGraph:
        """Scans all .py files and builds the import dependency graph."""
        exclude = exclude_patterns or ["__pycache__", ".git", "node_modules", ".venv", "venv"]
        graph = ImportGraph()
        
        for root, dirs, files in os.walk(self.base_dir):
            # Filter excluded directories
            dirs[:] = [d for d in dirs if d not in exclude]
            
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                filepath = os.path.join(root, fname)
                rel_path = os.path.relpath(filepath, self.base_dir).replace("\\", "/")
                graph.all_files.add(rel_path)
                
                try:
                    imports = self._extract_imports(filepath)
                    for edge in imports:
                        edge.source_file = rel_path
                        graph.edges.append(edge)
                        
                        # Build forward index
                        if rel_path not in graph.forward_index:
                            graph.forward_index[rel_path] = set()
                        graph.forward_index[rel_path].add(edge.target_module)
                        
                        # Build reverse index: resolve module to file path(s)
                        resolved_paths = self._resolve_module_to_files(edge.target_module)
                        for rp in resolved_paths:
                            if rp not in graph.reverse_index:
                                graph.reverse_index[rp] = set()
                            graph.reverse_index[rp].add(rel_path)
                except Exception as e:
                    logger.debug("Could not parse imports for %s: %s", filepath, e)
        
        return graph
    
    def _extract_imports(self, filepath: str) -> List[ImportEdge]:
        """Extracts all import statements from a Python file."""
        edges = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
        except (SyntaxError, Exception):
            return edges
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    edges.append(ImportEdge(
                        source_file="",  # filled by caller
                        target_module=alias.name,
                        import_type="import",
                        line_number=node.lineno
                    ))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    edges.append(ImportEdge(
                        source_file="",
                        target_module=node.module,
                        import_type="from_import",
                        line_number=node.lineno
                    ))
        
        return edges
    
    def _resolve_module_to_files(self, module_name: str) -> List[str]:
        """Resolves a Python module name to possible file paths relative to base_dir."""
        parts = module_name.replace(".", os.sep)
        candidates = [
            parts + ".py",
            os.path.join(parts, "__init__.py"),
        ]
        resolved = []
        for candidate in candidates:
            norm = candidate.replace("\\", "/")
            full = os.path.join(self.base_dir, candidate)
            if os.path.isfile(full):
                resolved.append(norm)
        return resolved


class TestImpactAnalyzer:
    """Determines which test files are impacted by changes to specific source files."""
    __test__ = False
    
    def __init__(self, graph: ImportGraph, max_depth: int = 3,
                 full_suite_threshold: float = 0.5):
        self.graph = graph
        self.max_depth = max_depth
        self.full_suite_threshold = full_suite_threshold
        # Identify test files
        self.test_files = {f for f in graph.all_files
                         if self._is_test_file(f)}
        self.non_test_files = graph.all_files - self.test_files
    
    @staticmethod
    def _is_test_file(path: str) -> bool:
        """Determines if a file is a test file."""
        basename = os.path.basename(path)
        return (basename.startswith("test_") or basename.endswith("_test.py")
                or "/tests/" in path or path.startswith("tests/"))
    
    def get_impacted_tests(self, modified_files: List[str]) -> List[str]:
        """Returns the minimal set of test files impacted by the given modified files."""
        # Normalize modified file paths
        normalized = []
        for f in modified_files:
            rel = os.path.relpath(os.path.abspath(f), os.path.abspath(".")).replace("\\", "/") if os.path.isabs(f) else f.replace("\\", "/")
            normalized.append(rel)
        
        # Find all transitively impacted files
        impacted: Set[str] = set()
        for mod_file in normalized:
            self._find_impacted_transitive(mod_file, impacted, depth=0)
        
        # Filter to only test files
        impacted_tests = impacted & self.test_files
        
        # Also include any test file that directly names any modified module
        for tf in self.test_files:
            forward = self.graph.forward_index.get(tf, set())
            for mod_file in normalized:
                mod_module = mod_file.replace("/", ".").replace(".py", "")
                if any(mod_module in imp or mod_file.replace(".py", "").replace("/", ".") in imp
                       for imp in forward):
                    impacted_tests.add(tf)
        
        # Threshold check: if too many tests selected, run all
        if len(self.test_files) > 0:
            ratio = len(impacted_tests) / len(self.test_files)
            if ratio > self.full_suite_threshold:
                logger.info("TIA: %.0f%% of tests impacted (>%.0f%% threshold). Running full suite.",
                           ratio * 100, self.full_suite_threshold * 100)
                return sorted(self.test_files)
        
        logger.info("TIA: %d/%d tests selected for regression.", 
                   len(impacted_tests), len(self.test_files))
        return sorted(impacted_tests)
    
    def _find_impacted_transitive(self, file_path: str, impacted: Set[str], depth: int):
        """Recursively finds all files that depend on the given file."""
        if depth >= self.max_depth:
            return
        if file_path in impacted:
            return
        impacted.add(file_path)
        
        # Find who imports this file
        dependents = self.graph.reverse_index.get(file_path, set())
        for dep in dependents:
            self._find_impacted_transitive(dep, impacted, depth + 1)
