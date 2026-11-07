"""
CyberAudit Polyglot AST Engine — Agnostic multi-language parsing & call-graph extraction.

Provides a unified representation (FileAstSummary, FunctionSummary, CallSummary)
across Python, TypeScript/JavaScript, Go, and Java.

Uses native `ast` for Python and extensible drivers (Tree-sitter or structural lexers)
for polyglot microservice architectures.
"""

import abc
import ast
import os
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any

logger = logging.getLogger("cyberaudit.core.polyglot_ast")


@dataclass
class CallSummary:
    """Represents a function or method invocation inside a block of code."""
    callee_name: str
    line_number: int
    is_dynamic: bool = False
    arguments: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "callee_name": self.callee_name,
            "line_number": self.line_number,
            "is_dynamic": self.is_dynamic,
            "arguments": self.arguments,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CallSummary":
        return cls(
            callee_name=data["callee_name"],
            line_number=data["line_number"],
            is_dynamic=data.get("is_dynamic", False),
            arguments=data.get("arguments", []),
        )


@dataclass
class FunctionSummary:
    """Represents a function, method, or closure in any supported language."""
    name: str
    line_start: int
    line_end: int
    class_name: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    calls: List[CallSummary] = field(default_factory=list)
    closure_index: int = 0
    docstring: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "class_name": self.class_name,
            "decorators": self.decorators,
            "calls": [c.to_dict() for c in self.calls],
            "closure_index": self.closure_index,
            "docstring": self.docstring,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FunctionSummary":
        return cls(
            name=data["name"],
            line_start=data["line_start"],
            line_end=data["line_end"],
            class_name=data.get("class_name"),
            decorators=data.get("decorators", []),
            calls=[CallSummary.from_dict(c) for c in data.get("calls", [])],
            closure_index=data.get("closure_index", 0),
            docstring=data.get("docstring"),
        )


@dataclass
class FileAstSummary:
    """Agnostic summary of an entire source file."""
    file_path: str
    language: str
    functions: List[FunctionSummary] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "functions": [f.to_dict() for f in self.functions],
            "imports": self.imports,
            "parse_errors": self.parse_errors,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileAstSummary":
        return cls(
            file_path=data["file_path"],
            language=data["language"],
            functions=[FunctionSummary.from_dict(f) for f in data.get("functions", [])],
            imports=data.get("imports", []),
            parse_errors=data.get("parse_errors", []),
        )


class LanguageAstParser(abc.ABC):
    """Abstract Base Class for language-specific AST parsers."""

    @property
    @abc.abstractmethod
    def language_id(self) -> str:
        """Returns the canonical language identifier (e.g. 'python', 'typescript', 'go', 'java')."""
        ...

    @property
    @abc.abstractmethod
    def supported_extensions(self) -> Set[str]:
        """Set of file extensions handled by this parser (e.g. {'.py'})."""
        ...

    @abc.abstractmethod
    def parse_code(self, code: str, file_path: str = "") -> FileAstSummary:
        """Parse source code string and return agnostic AST summary."""
        ...


class PythonAstParser(LanguageAstParser):
    """Native Python AST parser using the standard library `ast` module."""

    @property
    def language_id(self) -> str:
        return "python"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".py", ".pyw"}

    def parse_code(self, code: str, file_path: str = "") -> FileAstSummary:
        summary = FileAstSummary(file_path=file_path, language="python")
        try:
            tree = ast.parse(code, filename=file_path or "<string>")
        except SyntaxError as e:
            summary.parse_errors.append(f"SyntaxError: {e}")
            return summary

        # 1. Extract imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    summary.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    summary.imports.append(node.module)

        # 2. Extract classes and functions
        class NodeVisitor(ast.NodeVisitor):
            def __init__(self):
                self.current_class: Optional[str] = None
                self.functions: List[FunctionSummary] = []
                self.closure_counters: Dict[str, int] = {}

            def visit_ClassDef(self, node: ast.ClassDef):
                prev_class = self.current_class
                self.current_class = node.name
                self.generic_visit(node)
                self.current_class = prev_class

            def _extract_calls(self, fn_node: ast.AST) -> List[CallSummary]:
                calls = []
                for node in ast.walk(fn_node):
                    if isinstance(node, ast.Call):
                        callee_str = ""
                        is_dyn = False
                        if isinstance(node.func, ast.Name):
                            callee_str = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            try:
                                callee_str = ast.unparse(node.func)
                            except Exception:
                                callee_str = node.func.attr
                        else:
                            is_dyn = True
                            callee_str = "<dynamic_call>"
                        
                        args_repr = []
                        for a in node.args:
                            try:
                                args_repr.append(ast.unparse(a))
                            except Exception:
                                args_repr.append("?")

                        calls.append(CallSummary(
                            callee_name=callee_str,
                            line_number=getattr(node, "lineno", 0),
                            is_dynamic=is_dyn,
                            arguments=args_repr,
                        ))
                return calls

            def _extract_decorators(self, node: Any) -> List[str]:
                decorators = []
                for dec in getattr(node, "decorator_list", []):
                    try:
                        decorators.append(ast.unparse(dec))
                    except Exception:
                        if isinstance(dec, ast.Name):
                            decorators.append(dec.id)
                        elif isinstance(dec, ast.Attribute):
                            decorators.append(dec.attr)
                        elif isinstance(dec, ast.Call):
                            try:
                                decorators.append(ast.unparse(dec.func))
                            except Exception:
                                pass
                return decorators

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self._handle_fn(node)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self._handle_fn(node)
                self.generic_visit(node)

            def visit_Lambda(self, node: ast.Lambda):
                # Closure disambiguation
                c_key = f"{self.current_class or ''}::<lambda>"
                c_idx = self.closure_counters.get(c_key, 0)
                self.closure_counters[c_key] = c_idx + 1

                calls = self._extract_calls(node)
                self.functions.append(FunctionSummary(
                    name="<lambda>",
                    line_start=getattr(node, "lineno", 0),
                    line_end=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                    class_name=self.current_class,
                    decorators=[],
                    calls=calls,
                    closure_index=c_idx,
                    docstring=None,
                ))
                self.generic_visit(node)

            def _handle_fn(self, node: Any):
                name = node.name
                c_key = f"{self.current_class or ''}::{name}"
                c_idx = self.closure_counters.get(c_key, 0)
                self.closure_counters[c_key] = c_idx + 1

                doc = ast.get_docstring(node)
                decorators = self._extract_decorators(node)
                calls = self._extract_calls(node)

                self.functions.append(FunctionSummary(
                    name=name,
                    line_start=getattr(node, "lineno", 0),
                    line_end=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
                    class_name=self.current_class,
                    decorators=decorators,
                    calls=calls,
                    closure_index=c_idx,
                    docstring=doc,
                ))

        visitor = NodeVisitor()
        visitor.visit(tree)
        summary.functions = visitor.functions
        return summary


class TreeSitterPolyglotDriver(LanguageAstParser):
    """Polyglot parser for TypeScript/JavaScript, Go, and Java.
    
    Compatibility name: this driver currently uses structural regular expressions,
    not Tree-sitter. Results are heuristic and do not constitute a complete AST.
    Nested constructs and language-specific syntax can require manual validation.
    """

    SUPPORTED_MAP = {
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".go": "go",
        ".java": "java",
    }

    def __init__(self, target_lang: str = "generic"):
        self._target_lang = target_lang

    @property
    def language_id(self) -> str:
        return self._target_lang

    @property
    def supported_extensions(self) -> Set[str]:
        return set(self.SUPPORTED_MAP.keys())

    def parse_code(self, code: str, file_path: str = "") -> FileAstSummary:
        ext = os.path.splitext(file_path)[1].lower() if file_path else ".ts"
        lang = self.SUPPORTED_MAP.get(ext, "typescript")
        summary = FileAstSummary(file_path=file_path, language=lang)

        lines = code.splitlines()
        
        # 1. Structural Imports Extraction
        if lang in ("typescript", "javascript"):
            for line in lines:
                m = re.search(r'''(?:import\s+.*?from\s+['"]([^'"]+)['"]|require\(['"]([^'"]+)['"]\))''', line)
                if m:
                    summary.imports.append(m.group(1) or m.group(2))
        elif lang == "go":
            in_import_block = False
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("import ("):
                    in_import_block = True
                    continue
                if in_import_block:
                    if stripped == ")":
                        in_import_block = False
                        continue
                    m = re.search(r'''"([^"]+)"''', stripped)
                    if m:
                        summary.imports.append(m.group(1))
                else:
                    m = re.search(r'''import\s+"([^"]+)"''', stripped)
                    if m:
                        summary.imports.append(m.group(1))
        elif lang == "java":
            for line in lines:
                m = re.search(r'''import\s+([a-zA-Z0-9_.*]+);''', line)
                if m:
                    summary.imports.append(m.group(1))

        # 2. Structural Function / Method Extraction
        if lang in ("typescript", "javascript"):
            fn_regex = re.compile(
                r'''(?:(@[a-zA-Z0-9_().]+)\s+)*(?:(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)|(?:public|private|protected)?\s*(?:async\s+)?([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*[{:])'''
            )
        elif lang == "go":
            fn_regex = re.compile(
                r'''func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)\s*\([^)]*\)'''
            )
        elif lang == "java":
            fn_regex = re.compile(
                r'''(?:(@[a-zA-Z0-9_().]+)\s+)*(?:public|protected|private)?\s*(?:static\s+)?(?:final\s+)?[\w<>,\[\]]+\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'''
            )
        else:
            fn_regex = re.compile(r'''function\s+([a-zA-Z0-9_]+)''')

        call_regex = re.compile(r'''([a-zA-Z0-9_$.]+)\s*\(''')

        current_decorators: List[str] = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("@"):
                current_decorators.append(stripped)
                continue

            m = fn_regex.search(stripped)
            if m:
                groups = [g for g in m.groups() if g and not g.startswith("@")]
                fn_name = groups[-1] if groups else "anonymous"
                
                sub_lines = lines[idx: min(len(lines), idx + 35)]
                fn_calls: List[CallSummary] = []
                for sub_idx, sub_l in enumerate(sub_lines, start=idx + 1):
                    for call_match in call_regex.finditer(sub_l):
                        callee = call_match.group(1)
                        if callee not in ("if", "for", "while", "switch", "catch", "function", "return"):
                            fn_calls.append(CallSummary(
                                callee_name=callee,
                                line_number=sub_idx,
                                is_dynamic=False,
                            ))

                summary.functions.append(FunctionSummary(
                    name=fn_name,
                    line_start=idx,
                    line_end=idx + len(sub_lines),
                    decorators=list(current_decorators),
                    calls=fn_calls,
                ))
                current_decorators = []
            elif not stripped:
                if current_decorators and not stripped.startswith("@"):
                    current_decorators = []

        return summary


class PolyglotParserRegistry:
    """Registry coordinating language-specific parsers."""

    def __init__(self):
        self._parsers: Dict[str, LanguageAstParser] = {}
        self._register_defaults()

    def _register_defaults(self):
        py_parser = PythonAstParser()
        for ext in py_parser.supported_extensions:
            self._parsers[ext] = py_parser

        ts_driver = TreeSitterPolyglotDriver("polyglot")
        for ext in ts_driver.supported_extensions:
            self._parsers[ext] = ts_driver

    def register_parser(self, parser: LanguageAstParser):
        for ext in parser.supported_extensions:
            self._parsers[ext.lower()] = parser

    def get_parser_for_file(self, file_path: str) -> Optional[LanguageAstParser]:
        ext = os.path.splitext(file_path)[1].lower()
        return self._parsers.get(ext)

    def parse_file(self, file_path: str) -> FileAstSummary:
        parser = self.get_parser_for_file(file_path)
        if not parser:
            return FileAstSummary(
                file_path=file_path,
                language="unknown",
                parse_errors=[f"Unsupported extension for file: {file_path}"]
            )
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            return parser.parse_code(code, file_path=file_path)
        except Exception as e:
            return FileAstSummary(
                file_path=file_path,
                language=parser.language_id,
                parse_errors=[str(e)]
            )
