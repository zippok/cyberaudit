"""
RAG Security & Data Poisoning Scanner (AI Security Pillar)
Audits Retrieval-Augmented Generation (RAG) pipelines:
- Indirect Prompt Injection via unvalidated document ingestion into vector databases (Chroma, FAISS, Pinecone, Qdrant)
- Multi-Tenant Data Leakage: Vector similarity searches lacking tenant/user metadata filters
- Unsandboxed document parsing for vector embeddings
Mapped to MITRE ATLAS: AML.T0054 (LLM Prompt Injection), AML.T0048
"""

import re
from typing import List, Dict, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class RagSecurityScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rules: List[Dict[str, Any]] = [
            {
                "id": "AISEC-RAG-INDIRECT-INJECTION-01",
                "title": "RAG Security: Indirect Prompt Injection via External Document Ingestion",
                "pattern": re.compile(
                    r'(?:vector_store|vectorstore|chroma|pinecone|qdrant|faiss)\.add_(?:documents|texts)\s*\(\s*(?:web_scrape|user_upload|external_docs|untrusted_text|request\.)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.TAMPERING.value,
                "compliance": {
                    "OWASP_LLM": "LLM01:2025",
                    "MITRE_ATLAS": "AML.T0054",
                },
                "description": "Untrusted external text or user-uploaded documents ingested directly into vector database without prompt boundary sanitization, enabling Indirect Prompt Injection when context is retrieved by LLM.",
                "remediation": "Enclose retrieved vector context in strict XML/Markdown delimiters (e.g. `<context>...</context>`) and instruct the model never to follow commands found within retrieved context.",
                "mitre_id": "AML.T0054",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "LLM Prompt Injection",
                "cwe_id": "CWE-20",
            },
            {
                "id": "AISEC-RAG-CROSS-TENANT-LEAK-01",
                "title": "RAG Security: Vector Search Lacks Tenant / User Metadata Isolation Filter",
                "pattern": re.compile(
                    r'(?:similarity_search|similarity_search_by_vector|vector_search|hybrid_search|(?:vector_store|vectorstore|collection|index)\.(?:search|query))\s*\(\s*[\s\S]{0,60}?(?!\bfilter\s*=)[^)]*\)',
                    re.IGNORECASE,
                ),
                "severity": Severity.HIGH,
                "stride": StrideCategory.INFORMATION_DISCLOSURE.value,
                "compliance": {
                    "OWASP_LLM": "LLM06:2025",
                    "GDPR": "Art. 32",
                    "SOC2": "CC6.3",
                },
                "description": "Vector database similarity search executed without metadata filtering (`filter={'tenant_id': current_tenant}`), permitting cross-tenant document exfiltration in multi-user applications.",
                "remediation": "Mandate tenant and user-level metadata filters in all vector similarity queries: `vector_store.similarity_search(query, filter={'tenant_id': user.tenant_id})`.",
                "mitre_id": "T1005",
                "mitre_tactic": "Collection",
                "mitre_technique": "Data from Local System",
                "cwe_id": "CWE-200",
            },
        ]

    @property
    def name(self) -> str:
        return "RAG Security & Data Poisoning Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.AI_SECURITY

    @property
    def description(self) -> str:
        return "Audits RAG pipelines for indirect prompt injection, vector data poisoning, and cross-tenant data leaks."

    @property
    def file_extensions(self) -> List[str]:
        return [".py", ".ts", ".js", ".ipynb"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_content = content.lower()

        # Only scan files that reference genuine vector stores or RAG libraries
        is_rag = any(
            marker in lower_content
            for marker in ["chromadb", "pinecone", "qdrant", "weaviate", "milvus", "vectorstore", "faiss.index", "langchain", "llama_index", "openai.embeddings"]
        )
        if not is_rag:
            return []

        lines = content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            for rule in self.rules:
                if rule["pattern"].search(line):
                    findings.append(
                        Finding(
                            id=rule["id"],
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            pillar=self.pillar,
                            scanner_name=self.name,
                            file_path=file_path,
                            line_number=line_idx,
                            code_snippet=line.strip()[:180],
                            remediation=rule["remediation"],
                            mitre_id=rule["mitre_id"],
                            mitre_tactic=rule["mitre_tactic"],
                            mitre_technique=rule["mitre_technique"],
                            cwe_id=rule.get("cwe_id"),
                            stride_category=rule.get("stride"),
                            compliance_controls=rule.get("compliance", {}),
                        )
                    )

        return findings
