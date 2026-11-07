"""
cyberaudit/core/taint_engine.py
================================
Interprocedural Taint Analysis Engine — Frontier 1 of 3

Traces untrusted data from *sources* (HTTP inputs, CLI args, env vars) through
multi-hop call graphs across module boundaries to *sinks* (SQL queries, shell
commands, file operations, eval), emitting full forensic TaintTrace reports
when no sanitizer exists in the data flow path.

Architecture
------------
- TaintSource / TaintSink / TaintHop / TaintTrace  — data model
- _FnKey / _FnInfo                                 — inter-module call graph nodes
- InterproceduralTaintEngine                        — main orchestrator
  1. _index_all_files()         → build _FnInfo for each function in each .py
  2. _build_caller_map()        → map function_name → list of functions that call it
  3. _collect_sources_sinks()   → detect source/sink call-sites per fn (including subscripts)
  4. analyze()                  → for each (source_fn, sink_fn) pair, BFS via caller map

Algorithm
---------
Direction: BACKWARD from each sink function up through callers to find source functions.
This is correct because taint flows source→callee→callee→sink, which means
to verify reachability from source to sink we invert: find all ancestors of the
sink function, then check if any ancestor contains a source call.

Sanitizer detection: any function in the ancestor chain containing a sanitizer
call marks the trace as sanitized=True.
"""

from __future__ import annotations

import ast
import os
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Taint vocabulary — sources & sinks
# ---------------------------------------------------------------------------

TAINT_SOURCES: Dict[str, str] = {
    # HTTP / WSGI inputs
    "request.args":          "http_input",
    "request.form":          "http_input",
    "request.data":          "http_input",
    "request.json":          "http_input",
    "request.get_json":      "http_input",
    "request.values":        "http_input",
    "req.query":             "http_input",
    "req.body":              "http_input",
    # FastAPI / Starlette
    "Query":                 "http_input",
    "Body":                  "http_input",
    "Form":                  "http_input",
    # Django
    "request.POST":          "http_input",
    "request.GET":           "http_input",
    # CLI / env
    "sys.argv":              "cli_input",
    "os.environ":            "env_input",
    "os.getenv":             "env_input",
    # Socket / raw I/O
    "socket.recv":           "network_input",
    "socket.recvfrom":       "network_input",
    "sys.stdin.read":        "stdin_input",
    "input":                 "stdin_input",
}

TAINT_SINKS: Dict[str, str] = {
    # SQL injection
    "cursor.execute":        "sql_injection",
    "cursor.executemany":    "sql_injection",
    "connection.execute":    "sql_injection",
    "db.execute":            "sql_injection",
    "session.execute":       "sql_injection",
    "engine.execute":        "sql_injection",
    # Command injection
    "os.system":             "command_injection",
    "os.popen":              "command_injection",
    "subprocess.run":        "command_injection",
    "subprocess.call":       "command_injection",
    "subprocess.Popen":      "command_injection",
    "subprocess.check_output": "command_injection",
    # Code eval
    "eval":                  "code_injection",
    "exec":                  "code_injection",
    # Path traversal
    "os.remove":             "path_traversal",
    "os.unlink":             "path_traversal",
    "os.rmdir":              "path_traversal",
    "shutil.rmtree":         "path_traversal",
    "shutil.move":           "path_traversal",
    # SSRF / HTTP egress
    "requests.get":          "ssrf",
    "requests.post":         "ssrf",
    "requests.put":          "ssrf",
    "urllib.request.urlopen": "ssrf",
    "httpx.get":             "ssrf",
    # Deserialization
    "pickle.loads":          "deserialization",
    "pickle.load":           "deserialization",
    "yaml.load":             "deserialization",
}

SANITIZER_PREFIXES: Tuple[str, ...] = (
    "escape", "sanitize", "clean", "validate", "encode",
    "strip", "quote", "parameterize", "secure", "bleach",
    "html.escape", "markupsafe", "urlencode", "re.escape",
)


# ---------------------------------------------------------------------------
# Matching helper
# ---------------------------------------------------------------------------

def _taint_matches(call_name: str, pattern: str) -> bool:
    """
    Determines if a call name matches a taint source/sink pattern.

    Rules (in order):
    1. Exact match:         "cursor.execute" == "cursor.execute"  → True
    2. Prefix + dot/[      "request.args.get" starts with "request.args." → True
    3. Strict suffix match: only when pattern last segment is ≥ 7 chars to avoid
                             .get / .run / .read false positives.
    """
    if call_name == pattern:
        return True
    if call_name.startswith(pattern + ".") or call_name.startswith(pattern + "["):
        return True
    parts = pattern.split(".")
    last = parts[-1]
    if len(last) >= 7 and call_name.endswith("." + last):
        return True
    return False


def _subscript_matches(subscript_name: str, pattern: str) -> bool:
    """Check if a subscript access like request.form["key"] matches a source pattern."""
    # subscript_name is like "request.form", pattern is like "request.form"
    return subscript_name == pattern or subscript_name.startswith(pattern + ".")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    name: str
    category: str


@dataclass
class TaintSink:
    name: str
    category: str


@dataclass
class TaintHop:
    file_path: str
    line_number: int
    function_name: str
    variable_in: str
    variable_out: str


@dataclass
class TaintTrace:
    source: TaintSource
    sink: TaintSink
    hops: List[TaintHop]
    sanitized: bool = False
    sanitizer_name: Optional[str] = None

    def hop_count(self) -> int:
        return len(self.hops)

    def entry_point(self) -> Optional[str]:
        return self.hops[0].function_name if self.hops else None

    def to_dict(self) -> dict:
        return {
            "source": {"name": self.source.name, "category": self.source.category},
            "sink":   {"name": self.sink.name,   "category": self.sink.category},
            "hops": [
                {
                    "file_path":     h.file_path,
                    "line_number":   h.line_number,
                    "function_name": h.function_name,
                    "variable_in":   h.variable_in,
                    "variable_out":  h.variable_out,
                }
                for h in self.hops
            ],
            "sanitized":      self.sanitized,
            "sanitizer_name": self.sanitizer_name,
        }


# ---------------------------------------------------------------------------
# Internal function node
# ---------------------------------------------------------------------------

@dataclass
class _FnKey:
    file_path: str
    fn_name: str

    def __hash__(self) -> int:
        return hash((self.file_path, self.fn_name))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _FnKey):
            return False
        return self.file_path == other.file_path and self.fn_name == other.fn_name


@dataclass
class _FnInfo:
    key: _FnKey
    line_start: int
    line_end: int
    source_sites: List[Tuple[str, int]]       # (source_name, lineno)
    sink_sites:   List[Tuple[str, int]]       # (sink_name, lineno)
    sanitizer_sites: List[Tuple[str, int]]    # (sanitizer_name, lineno)
    callees: List[Tuple[str, int]]            # (callee_name, lineno)


# ---------------------------------------------------------------------------
# Python AST visitor
# ---------------------------------------------------------------------------

class _PythonModuleVisitor(ast.NodeVisitor):
    """Walks a Python AST and produces _FnInfo records for each function."""

    def __init__(
        self,
        file_path: str,
        sources: Dict[str, str],
        sinks: Dict[str, str],
    ):
        self.file_path = file_path
        self._sources = sources
        self._sinks = sinks
        self.functions: List[_FnInfo] = []
        self._fn_stack: List[_FnInfo] = []

    def _current_fn(self) -> Optional[_FnInfo]:
        return self._fn_stack[-1] if self._fn_stack else None

    def _make_fn(self, node: ast.FunctionDef) -> _FnInfo:
        return _FnInfo(
            key=_FnKey(self.file_path, node.name),
            line_start=node.lineno,
            line_end=getattr(node, "end_lineno", node.lineno),
            source_sites=[],
            sink_sites=[],
            sanitizer_sites=[],
            callees=[],
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        fn = self._make_fn(node)
        self._fn_stack.append(fn)
        self.generic_visit(node)
        self._fn_stack.pop()
        self.functions.append(fn)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _extract_call_name(self, node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Attribute):
            val = func.value
            if isinstance(val, ast.Name):
                return f"{val.id}.{func.attr}"
            if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
                return f"{val.value.id}.{val.attr}.{func.attr}"
            return func.attr
        if isinstance(func, ast.Name):
            return func.id
        return "<dynamic>"

    def _extract_subscript_obj(self, node: ast.Subscript) -> str:
        """Return the dotted name of the subscripted object, e.g. request.form"""
        val = node.value
        if isinstance(val, ast.Name):
            return val.id
        if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
            return f"{val.value.id}.{val.attr}"
        return "<dynamic>"

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect taint sources accessed via subscript, e.g. request.form['key']."""
        fn = self._current_fn()
        if fn is not None:
            obj_name = self._extract_subscript_obj(node)
            for src_name in self._sources:
                if _subscript_matches(obj_name, src_name):
                    fn.source_sites.append((src_name, node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fn = self._current_fn()
        if fn is None:
            self.generic_visit(node)
            return

        name = self._extract_call_name(node)
        lineno = node.lineno

        for src_name in self._sources:
            if _taint_matches(name, src_name):
                fn.source_sites.append((src_name, lineno))

        for sink_name in self._sinks:
            if _taint_matches(name, sink_name):
                fn.sink_sites.append((sink_name, lineno))

        for prefix in SANITIZER_PREFIXES:
            if name.startswith(prefix) or name == prefix:
                fn.sanitizer_sites.append((name, lineno))

        fn.callees.append((name, lineno))

        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class InterproceduralTaintEngine:
    """
    Performs interprocedural taint analysis across a Python codebase.

    Algorithm: backward BFS from sink functions through caller graph to find
    source functions. This correctly handles multi-hop chains where source
    is in a callee and sink is in an ancestor caller.
    """

    MAX_BFS_DEPTH = 15

    def __init__(
        self,
        base_dir: str,
        registry=None,
        cache=None,
        extra_sources: Optional[Dict[str, str]] = None,
        extra_sinks:   Optional[Dict[str, str]] = None,
    ):
        self.base_dir = str(base_dir)
        self.cache = cache
        self._sources = {**TAINT_SOURCES, **(extra_sources or {})}
        self._sinks   = {**TAINT_SINKS,   **(extra_sinks   or {})}

        # fn_name → list of _FnInfo (may have multiple defs across files)
        self._fn_map: Dict[str, List[_FnInfo]] = {}
        # _FnKey → _FnInfo
        self._fn_key_map: Dict[_FnKey, _FnInfo] = {}

    # ------------------------------------------------------------------
    # Phase 1 — Index all Python files
    # ------------------------------------------------------------------

    def _index_all_files(self) -> None:
        for root, dirs, files in os.walk(self.base_dir):
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d not in {"__pycache__", "node_modules", ".venv", "venv",
                               "site-packages", "dist", "build", ".git"}
            ]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                self._index_file(os.path.join(root, fname))

    def _index_file(self, file_path: str) -> None:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
            tree = ast.parse(source, filename=file_path)
        except (SyntaxError, OSError):
            return

        visitor = _PythonModuleVisitor(file_path, self._sources, self._sinks)
        visitor.visit(tree)

        for fn_info in visitor.functions:
            self._fn_key_map[fn_info.key] = fn_info
            self._fn_map.setdefault(fn_info.key.fn_name, []).append(fn_info)

    def _build_caller_map(self) -> None:
        """Build inverse call graph: callee_short_name → [_FnInfo that call it]."""
        self._caller_map: Dict[str, List[_FnInfo]] = {}
        for fn_info in self._fn_key_map.values():
            for callee_name, _lineno in fn_info.callees:
                short = callee_name.split(".")[-1]
                # Register both full name and short name
                self._caller_map.setdefault(callee_name, []).append(fn_info)
                if short != callee_name:
                    self._caller_map.setdefault(short, []).append(fn_info)

    # ------------------------------------------------------------------
    # Phase 2 — Build forward callee resolution map
    # ------------------------------------------------------------------

    def _resolve_callees(self, caller: _FnInfo, callee_name: str) -> List[_FnInfo]:
        """
        Resolve a callee name string to actual _FnInfo objects.
        Tries: exact fn_name, then last-segment (short) name.
        Prefers same-file, then any file. Caps at 4 to avoid explosion.
        """
        short = callee_name.split(".")[-1]
        candidates: List[_FnInfo] = []

        # Exact name
        for fn in self._fn_map.get(callee_name, []):
            candidates.append(fn)
        # Short name (e.g., "get_input" from "module.get_input")
        if not candidates and short != callee_name:
            for fn in self._fn_map.get(short, []):
                candidates.append(fn)

        if not candidates:
            return []

        # Prefer same-file
        same_file = [c for c in candidates if c.key.file_path == caller.key.file_path]
        return (same_file or candidates)[:4]

    # ------------------------------------------------------------------
    # Phase 3 — Forward BFS from source function through call graph to sinks
    # ------------------------------------------------------------------

    def _forward_bfs(
        self,
        source_fn: _FnInfo,
        source_site: Tuple[str, int],
    ) -> List[TaintTrace]:
        """
        Forward BFS from a function containing a taint source.
        Follows the call graph (caller → callee) until reaching functions
        that contain sink calls. Sanitizers along the path mark traces sanitized.
        """
        src_obj = TaintSource(
            name=source_site[0],
            category=self._sources.get(source_site[0], "unknown"),
        )

        traces: List[TaintTrace] = []

        # BFS state: (current_fn, hops_so_far, sanitized, sanitizer_name)
        queue: deque = deque()
        initial_hop = TaintHop(
            file_path=source_fn.key.file_path,
            line_number=source_site[1],
            function_name=source_fn.key.fn_name,
            variable_in=source_site[0],
            variable_out=source_site[0],
        )
        queue.append((source_fn, [initial_hop], False, None))

        # Visited: (file_path, fn_name) to avoid infinite recursion
        visited: Set[Tuple[str, str]] = set()

        while queue:
            current, hops, is_sanitized, san_name = queue.popleft()

            visit_key = (current.key.file_path, current.key.fn_name)
            if visit_key in visited:
                continue
            visited.add(visit_key)

            if len(hops) > self.MAX_BFS_DEPTH:
                continue

            # Detect sanitizers in this function
            if current.sanitizer_sites and not is_sanitized:
                is_sanitized = True
                san_name = current.sanitizer_sites[0][0]

            # Check if this function reaches a sink
            for sink_name, sink_lineno in current.sink_sites:
                sink_obj = TaintSink(
                    name=sink_name,
                    category=self._sinks.get(
                        sink_name,
                        self._sinks.get(sink_name.split(".")[-1], "unknown")
                    ),
                )
                sink_hop = TaintHop(
                    file_path=current.key.file_path,
                    line_number=sink_lineno,
                    function_name=current.key.fn_name,
                    variable_in=hops[-1].variable_out,
                    variable_out=sink_name,
                )
                traces.append(TaintTrace(
                    source=src_obj,
                    sink=sink_obj,
                    hops=hops + [sink_hop],
                    sanitized=is_sanitized,
                    sanitizer_name=san_name,
                ))

            # Enqueue callees of the current function (taint flows into callees)
            for callee_name, callee_lineno in current.callees:
                for callee_fn in self._resolve_callees(current, callee_name):
                    callee_key = (callee_fn.key.file_path, callee_fn.key.fn_name)
                    if callee_key not in visited:
                        next_hop = TaintHop(
                            file_path=callee_fn.key.file_path,
                            line_number=callee_lineno,
                            function_name=callee_name,
                            variable_in=hops[-1].variable_out,
                            variable_out=callee_name,
                        )
                        queue.append((
                            callee_fn,
                            hops + [next_hop],
                            is_sanitized,
                            san_name,
                        ))

            # Also enqueue callers (taint propagates upward when source fn returns tainted data)
            fn_name = current.key.fn_name
            for caller in self._caller_map.get(fn_name, []):
                caller_key = (caller.key.file_path, caller.key.fn_name)
                if caller_key not in visited:
                    next_hop = TaintHop(
                        file_path=caller.key.file_path,
                        line_number=caller.line_start,
                        function_name=caller.key.fn_name,
                        variable_in=hops[-1].variable_out,
                        variable_out=caller.key.fn_name,
                    )
                    queue.append((
                        caller,
                        hops + [next_hop],
                        is_sanitized,
                        san_name,
                    ))

        return traces

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        entrypoints: Optional[List[str]] = None,
    ) -> List[TaintTrace]:
        """
        Run full interprocedural taint analysis.

        Returns all TaintTrace objects (sanitized + unsanitized).
        Filter with ``analyze_unsanitized()`` for exploitable paths only.
        """
        self._fn_map.clear()
        self._fn_key_map.clear()

        self._index_all_files()
        self._build_caller_map()

        all_traces: List[TaintTrace] = []

        for fn_key, fn_info in self._fn_key_map.items():
            if not fn_info.source_sites:
                continue
            if entrypoints and fn_info.key.fn_name not in entrypoints:
                continue
            for src_site in fn_info.source_sites:
                traces = self._forward_bfs(fn_info, src_site)
                all_traces.extend(traces)

        # Deduplicate by (source_name, sink_name, entry_point)
        seen: Set[Tuple[str, str, str]] = set()
        unique: List[TaintTrace] = []
        for t in all_traces:
            key = (t.source.name, t.sink.name, t.entry_point() or "")
            if key not in seen:
                seen.add(key)
                unique.append(t)

        return unique

    def analyze_unsanitized(
        self,
        entrypoints: Optional[List[str]] = None,
    ) -> List[TaintTrace]:
        """Convenience: returns only unsanitized (exploitable) traces."""
        return [t for t in self.analyze(entrypoints) if not t.sanitized]
