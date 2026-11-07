"""
CyberAudit Knowledge Base Engine (RAG & Semantic Retrieval)
Arquitectura Enterprise RAG conforme a "AI Engineering" (Chip Huyen, Cap. 7 & 8):

1. Ingestión Recursiva Dinámica: Recorre todo conocimientos/ (.md, .txt, subdirectorios).
2. Segmentación Jerárquica Consciente de la Estructura (Structure-Aware Chunking).
3. Enriquecimiento con Metadatos y Contexto Padre-Hijo (Parent-Child Hierarchy).
4. Expansión Semántica de Consultas Técnicas (Technical Query Expansion).
5. Motor de Ranking Probabilístico Okapi BM25 con Boosting de Metadatos.
"""

import os
import re
import math
import logging
import unicodedata
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

logger = logging.getLogger("cyberaudit.kb")


def normalize_text(text: str) -> str:
    """Normaliza texto eliminando acentos y convirtiendo a minúsculas para búsqueda tolerante."""
    if not text:
        return ""
    nfkd = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def tokenize_text(text: str) -> List[str]:
    """Tokeniza texto normalizado conservando tokens técnicos alfanuméricos y CWEs."""
    norm = normalize_text(text)
    return [t for t in re.split(r"[^a-z0-9_-]+", norm) if len(t) >= 2]


DOMAIN_EXPANSIONS = [
    (re.compile(r"congel|bloque|hang|freeze|cuelgu", re.I), ["event loop", "non-blocking", "asyncio", "sync io", "cwe-400"]),
    (re.compile(r"fuga|leak|memoria|recurso", re.I), ["memory leak", "resource lifecycle", "event loop", "cwe-400", "connections"]),
    (re.compile(r"inyecci|inject|comando|shell|cmd|terminal", re.I), ["cwe-78", "cwe-89", "command injection", "allow-list", "sanitization"]),
    (re.compile(r"caida|corte|crash|apagon|corromp|apagado", re.I), ["crash-safe", "atomic write", "ddia", "durability", "wal"]),
    (re.compile(r"concurren|carrera|race|simultan|hilo", re.I), ["cwe-362", "concurrency", "race condition", "idempotencia", "atomic"]),
    (re.compile(r"pago|tarjeta|dinero|transacc|saldo|balance", re.I), ["idempotencia", "transactions", "ddia", "isolation", "acid"]),
    (re.compile(r"secret|credencial|token|api.?key|password|clave", re.I), ["cwe-798", "env isolation", "secrets", "least privilege"]),
    (re.compile(r"prueb|test|testing|tdd|asercion", re.I), ["tdd", "hermetic tests", "small cls", "unit testing"]),
    (re.compile(r"refactor|limpio|deuda|smell|acopla", re.I), ["refactoring", "code smells", "extract method", "code complete"]),
    (re.compile(r"prompt|llm|ia|modelo|agente|hallucina", re.I), ["prompt injection", "owasp llm01", "guardrails", "output handling"]),
    (re.compile(r"async|promesa|await|futuro", re.I), ["asyncio", "promises", "event loop", "non-blocking"]),
    (re.compile(r"servidor|endpoint|api|rest|ruta", re.I), ["http", "headers", "cors", "network headers"]),
]


def expand_query(query: str) -> Tuple[List[str], List[str]]:
    norm = normalize_text(query)
    primary = set(tokenize_text(norm))
    expansions = set()

    for pattern, tags in DOMAIN_EXPANSIONS:
        if pattern.search(norm):
            for t in tags:
                for token in tokenize_text(t):
                    if token not in primary:
                        expansions.add(token)

    return list(primary), list(expansions)


class KnowledgeArticle:
    def __init__(
        self,
        file_path: str,
        title: str,
        category: str,
        content: str,
        tags: List[str],
        parent_title: str = "",
        parent_context: str = "",
        references: Optional[List[Dict[str, str]]] = None,
        cwe_ids: Optional[List[str]] = None,
    ):
        self.file_path = file_path
        self.title = title
        self.category = category
        self.content = content
        self.tags = tags
        self.parent_title = parent_title
        self.parent_context = parent_context
        self.references = references or []
        self.cwe_ids = cwe_ids or []
        self.normalized_title = normalize_text(title)
        self.normalized_tags = [normalize_text(t) for t in tags]
        self.normalized_cwes = [normalize_text(c) for c in self.cwe_ids]
        self.normalized_category = normalize_text(category)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "relative_path": os.path.relpath(self.file_path, os.getcwd()).replace("\\", "/"),
            "title": self.title,
            "parent_title": self.parent_title,
            "parent_context": self.parent_context,
            "category": self.category,
            "tags": self.tags,
            "cwe_ids": self.cwe_ids,
            "summary": self.content[:280].replace("\r", "").replace("\n", " ").strip() + "...",
            "content": self.content,
            "references": self.references,
            "urls": [r["url"] for r in self.references if "url" in r],
        }


class KnowledgeBase:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(KnowledgeBase, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, base_dir: Optional[str] = None):
        if self._initialized:
            return

        if base_dir is None:
            # Workspace root conocimientos folder
            self.base_dir = Path(__file__).resolve().parent.parent.parent.parent / "conocimientos"
            if not self.base_dir.exists():
                self.base_dir = Path(__file__).resolve().parent.parent.parent / "conocimientos"
        else:
            self.base_dir = Path(base_dir)

        self.articles: List[KnowledgeArticle] = []

        # Parámetros Okapi BM25
        self.k1 = 1.2
        self.b = 0.75
        self.doc_lengths: List[int] = []
        self.avgdl: float = 0.0
        self.doc_term_freqs: List[Dict[str, int]] = []
        self.doc_freqs: Dict[str, int] = {}
        self.idf_cache: Dict[str, float] = {}

        self.load_documents()
        self._initialized = True

    def _extract_cwe_ids(self, text: str) -> List[str]:
        return list(set(re.findall(r"\bCWE-\d+\b", text, re.IGNORECASE)))

    def _extract_tags(self, text: str) -> List[str]:
        tags = set()
        keywords = [
            "OWASP", "MITRE", "ATT&CK", "CWE", "CWE-78", "CWE-89", "CWE-362", "CWE-400", "CWE-798",
            "PCI-DSS", "ISO 27001", "CIS", "Zero Trust", "Taint Analysis", "Command Injection",
            "SQL Injection", "Allow-list", "Event Loop", "Crash-Safe", "Atomic Write", "DDIA",
            "TDD", "Small CLs", "Hermetic Tests", "Hyrum Law", "Refactoring", "Code Smells",
            "Node.js", "TypeScript", "TailwindCSS", "Python", "Java", "Docker", "SARIF"
        ]
        for kw in keywords:
            if re.search(rf"\b{re.escape(kw)}\b", text, re.IGNORECASE):
                tags.add(kw)
        return list(tags)

    def _extract_references(self, text: str) -> List[Dict[str, str]]:
        refs = []
        md_links = re.findall(r"\[([^\]]+)\]\((https?://[^\)]+)\)", text)
        for link_title, link_url in md_links:
            refs.append({"title": link_title, "url": link_url})
        raw_urls = re.findall(r"(?<!\()(https?://[^\s\)\>\]\"]+)", text)
        for r_url in raw_urls:
            if not any(r["url"] == r_url for r in refs):
                refs.append({"title": "Referencia Técnica", "url": r_url})
        return refs

    def load_documents(self):
        """Carga y segmenta documentos Markdown y de texto en artículos atómicos."""
        self.articles = []
        if not self.base_dir.exists():
            return

        for root, dirs, files in os.walk(self.base_dir):
            # Omitir binarios y changelogs viejos
            dirs[:] = [d for d in dirs if d not in ["c-api", "whatsnew", "__pycache__", ".git", "node_modules"]]

            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, self.base_dir).replace("\\", "/")

                # Procesar Markdown con particionamiento por encabezados
                if file.endswith(".md") and file.lower() != "readme.md":
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            raw_text = f.read()

                        text = raw_text.replace("\r\n", "\n")
                        sections = re.split(r"\n(?=#{2,3}\s+)", text)
                        
                        if len(sections) > 1:
                            main_title_match = re.search(r"^#\s+(.+)$", sections[0], re.MULTILINE)
                            doc_title = main_title_match.group(1).strip() if main_title_match else file.replace(".md", "")
                            parent_category = "General"
                            parent_h2 = ""
                            parent_context = ""

                            for sec in sections:
                                sec_lines = sec.strip().split("\n")
                                first_line = sec_lines[0].strip()
                                sec_body = "\n".join(sec_lines[1:]).strip()

                                if first_line.startswith("## "):
                                    parent_h2 = first_line.replace("##", "").strip()
                                    sec_header = parent_h2
                                    parent_context = sec_body[:280].replace("\n", " ").strip()
                                    if any(k in parent_h2.lower() for k in ["google", "farley", "tdd", "trunk"]):
                                        parent_category = "Google SE & Farley CD"
                                    elif any(k in parent_h2.lower() for k in ["ddia", "kleppmann", "datos", "concurrencia"]):
                                        parent_category = "DDIA & Arquitectura"
                                    elif any(k in parent_h2.lower() for k in ["appsec", "janca", "seguridad", "vulnerabilidades", "cwe"]):
                                        parent_category = "AppSec & Ciberseguridad"
                                    elif any(k in parent_h2.lower() for k in ["refactoring", "fowler", "deuda"]):
                                        parent_category = "Clean Code & Refactorización"
                                    elif any(k in parent_h2.lower() for k in ["ai", "huyen", "inferencia"]):
                                        parent_category = "AI Engineering"
                                elif first_line.startswith("### "):
                                    sub_h3 = first_line.replace("###", "").strip()
                                    sec_header = f"{parent_h2} > {sub_h3}" if parent_h2 else sub_h3
                                else:
                                    continue

                                if len(sec_body) < 25:
                                    continue

                                full_sec_text = f"{sec_header}\n{sec_body}"
                                self.articles.append(
                                    KnowledgeArticle(
                                        file_path=full_path,
                                        title=f"{doc_title} > {sec_header}",
                                        category=parent_category,
                                        parent_title=parent_h2,
                                        parent_context=parent_context,
                                        content=sec_body,
                                        tags=self._extract_tags(full_sec_text),
                                        references=self._extract_references(full_sec_text),
                                        cwe_ids=self._extract_cwe_ids(full_sec_text),
                                    )
                                )
                        else:
                            # Documento simple
                            title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
                            title = title_match.group(1).strip() if title_match else file.replace(".md", "").replace("_", " ").title()
                            self.articles.append(
                                KnowledgeArticle(
                                    file_path=full_path,
                                    title=title,
                                    category="General",
                                    content=text,
                                    tags=self._extract_tags(text),
                                    references=self._extract_references(text),
                                    cwe_ids=self._extract_cwe_ids(text),
                                )
                            )
                    except Exception as e:
                        logger.debug("Failed loading markdown article %s: %s", full_path, e)

                # Procesar archivos de texto (.txt) de tecnologías y documentación estándar
                elif file.endswith(".txt"):
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            text = f.read().replace("\r\n", "\n")

                        cat_map = {
                            "nodeJS.txt": ("Node.js Backend & Runtime", "Backend & Runtime"),
                            "typescript.txt": ("TypeScript Type Safety", "Lenguajes & Tipado"),
                            "tailwind.txt": ("TailwindCSS Design System", "Frontend & UI"),
                            "java.txt": ("Java Enterprise Patterns", "Arquitectura Enterprise"),
                        }

                        if file in cat_map:
                            title_prefix, cat = cat_map[file]
                            blocks = re.split(r"\n\s*(?:={3,}|-{3,})\s*\n", text)
                        else:
                            base_name = os.path.splitext(file)[0]
                            title_prefix = f"Python Docs > {base_name}"
                            if "library" in rel_path:
                                cat = "Python Standard Library"
                            elif "howto" in rel_path:
                                cat = "Python How-To Guides"
                            elif "tutorial" in rel_path:
                                cat = "Python Tutorial"
                            else:
                                cat = "Python Documentation"
                            blocks = re.split(r"\n\s*(?:={3,}|-{3,}|\*{3,})\s*\n|\n\n(?=[A-Z0-9_().]+(?:\s+--|\s*:|\n[-=]+))", text)

                        for b in blocks:
                            b_text = b.strip()
                            if len(b_text) > 60:
                                first_line = b_text.split("\n")[0][:80].strip()
                                self.articles.append(
                                    KnowledgeArticle(
                                        file_path=full_path,
                                        title=f"{title_prefix} > {first_line}",
                                        category=cat,
                                        parent_title=title_prefix,
                                        parent_context=f"Documentación técnica de {title_prefix}",
                                        content=b_text,
                                        tags=self._extract_tags(b_text),
                                        references=self._extract_references(b_text),
                                        cwe_ids=self._extract_cwe_ids(b_text),
                                    )
                                )
                    except Exception as e:
                        logger.debug("Failed loading text article %s: %s", full_path, e)

        # Ingestar skills y protocolos de rsc-harness (.rsc/skills/) si existen en el workspace
        self._load_rsc_skills()

        # Construir índice Okapi BM25
        self.build_bm25_index()

    def _load_rsc_skills(self):
        """Carga las skills instaladas de rsc-harness (.rsc/skills/ o .antigravity/rsc/) en el índice RAG."""
        candidate_dirs = [
            self.base_dir.parent / ".rsc" / "skills",
            self.base_dir.parent / ".antigravity" / "rsc",
        ]
        rsc_skills_dir = next((d for d in candidate_dirs if d.is_dir()), None)
        if rsc_skills_dir is None:
            return

        for root, _, files in os.walk(rsc_skills_dir):
            for file in files:
                if not file.endswith(".md"):
                    continue
                full_path = os.path.join(root, file)
                rel_skill = os.path.relpath(full_path, rsc_skills_dir).replace("\\", "/")
                skill_name = rel_skill.split("/")[0]
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        raw_text = f.read().replace("\r\n", "\n")

                    sections = re.split(r"\n(?=#{2,3}\s+)", raw_text)
                    for sec in sections:
                        sec_lines = sec.strip().split("\n")
                        first_line = sec_lines[0].strip() if sec_lines else ""
                        sec_body = "\n".join(sec_lines[1:]).strip()
                        if len(sec_body) < 35:
                            continue
                        sec_header = re.sub(r"^#{1,3}\s+", "", first_line).strip() or skill_name
                        full_sec_text = f"{skill_name} {sec_header}\n{sec_body}"
                        tags = list(set(self._extract_tags(full_sec_text) + ["rsc-harness", skill_name]))
                        self.articles.append(
                            KnowledgeArticle(
                                file_path=full_path,
                                title=f"RSC Skill [{skill_name}] > {sec_header}",
                                category="RSC Harness & Agent Skills",
                                parent_title=f"RSC Skill: {skill_name}",
                                parent_context=f"rsc-harness skill protocol ({rel_skill})",
                                content=sec_body,
                                tags=tags,
                                references=self._extract_references(full_sec_text),
                                cwe_ids=self._extract_cwe_ids(full_sec_text),
                            )
                        )
                except Exception as e:
                    logger.debug("Failed loading rsc skill %s: %s", full_path, e)

    def build_bm25_index(self):
        N = len(self.articles)
        self.doc_lengths = []
        self.doc_term_freqs = []
        self.doc_freqs.clear()
        self.idf_cache.clear()

        if N == 0:
            return

        total_length = 0
        for article in self.articles:
            full_text = f"{article.title} {article.category} {' '.join(article.tags)} {' '.join(article.cwe_ids)} {article.content}"
            tokens = tokenize_text(full_text)
            t_len = len(tokens)
            total_length += t_len
            self.doc_lengths.append(t_len)

            tf: Dict[str, int] = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1
            self.doc_term_freqs.append(tf)

            for term in tf.keys():
                self.doc_freqs[term] = self.doc_freqs.get(term, 0) + 1

        self.avgdl = total_length / N

        for term, n in self.doc_freqs.items():
            idf = math.log(1.0 + (N - n + 0.5) / (n + 0.5))
            self.idf_cache[term] = max(idf, 0.15)

    def search(self, query: str, limit: int = 4, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Búsqueda probabilística Okapi BM25 con Expansión Semántica y Boosting de Metadatos.
        """
        if not self.articles:
            self.load_documents()

        N = len(self.articles)
        if N == 0:
            return []

        primary_terms, expansion_terms = expand_query(query)
        if not primary_terms and not expansion_terms:
            return [a.to_dict() for a in self.articles[:limit]]

        scored_articles: List[Tuple[float, KnowledgeArticle]] = []

        for i, article in enumerate(self.articles):
            if category and normalize_text(category) not in article.normalized_category:
                continue

            tf_map = self.doc_term_freqs[i]
            doc_len = self.doc_lengths[i]
            score = 0.0

            # 1. Términos primarios (peso 1.0)
            for term in primary_terms:
                idf = self.idf_cache.get(term, math.log(1.0 + N))
                f = tf_map.get(term, 0)
                if f > 0:
                    num = f * (self.k1 + 1.0)
                    den = f + self.k1 * (1.0 - self.b + self.b * (doc_len / self.avgdl))
                    score += idf * (num / den)

                # Boosting de metadatos (Cap. 7 AI Engineering)
                if term in article.normalized_title:
                    score += idf * 3.0
                if any(term in tag for tag in article.normalized_tags):
                    score += idf * 2.2
                if any(term in cwe for cwe in article.normalized_cwes):
                    score += idf * 4.5
                if term in article.normalized_category:
                    score += idf * 1.5

                if "COMPREHENSIVE_SOFTWARE_FACTORY_KNOWLEDGE" in article.file_path or "AI_ENGINEERING_SYNTHESIS" in article.file_path:
                    score *= 1.25

            # 2. Términos de expansión semántica (peso 0.55)
            for term in expansion_terms:
                idf = self.idf_cache.get(term, 0.6)
                f = tf_map.get(term, 0)
                if f > 0:
                    num = f * (self.k1 + 1.0)
                    den = f + self.k1 * (1.0 - self.b + self.b * (doc_len / self.avgdl))
                    score += 0.55 * idf * (num / den)

                if term in article.normalized_title:
                    score += 0.55 * idf * 2.2
                if any(term in tag for tag in article.normalized_tags):
                    score += 0.55 * idf * 1.8
                if any(term in cwe for cwe in article.normalized_cwes):
                    score += 0.55 * idf * 3.5

            if score > 0.5:
                scored_articles.append((score, article))

        scored_articles.sort(key=lambda x: x[0], reverse=True)
        return [item[1].to_dict() for item in scored_articles[:limit]]

    def get_context_for_prompt(self, query: str, max_chars: int = 2200) -> str:
        """
        Construye un bloque de contexto complementario para enriquecer el análisis del AI Co-Analyst.
        """
        results = self.search(query, limit=2)
        if not results:
            return ""

        context_parts = [
            "=== REFERENCIAS TÉCNICAS CONSULTADAS (GUÍA COMPLEMENTARIA RAG - BM25) ===",
            "> NOTA: Utiliza estos principios y patrones (Google SE, Farley, DDIA, AppSec, Fowler, McConnell, Chip Huyen) como referencia técnica de alta prioridad para estructurar el diagnóstico y remediación, complementándolas con tu conocimiento de seguridad general.\n"
        ]
        accumulated_chars = 0

        for r in results:
            content = r["content"].strip()
            part = f"#### [{r['category']}] {r['title']}\n"
            if r.get("parent_context") and r.get("parent_title") != r.get("title"):
                part += f"> Contexto del Capítulo: {r['parent_context']}\n"
            part += f"{content}\n"

            if accumulated_chars + len(part) > max_chars:
                remaining = max_chars - accumulated_chars
                if remaining > 180:
                    part = part[:remaining] + "\n[... fragmento truncado ...]\n"
                    context_parts.append(part)
                break
            context_parts.append(part)
            accumulated_chars += len(part)

        context_parts.append("=========================================================================")
        return "\n".join(context_parts)
