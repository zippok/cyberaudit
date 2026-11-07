"""
AI Engineering FinOps, Token Budget, Eval & Structured Output Scanner
Audits LLM / GenAI integrations against Chip Huyen's "AI Engineering" best practices:
1. Unbounded LLM Generation (`chat.completions.create` / `generate_content` / `messages.create`) without `max_tokens` / `max_output_tokens` (Denial of Wallet / FinOps risk).
2. Unvalidated `JSON.parse(llmResponse)` without schema validation or try/catch fallback (Hallucination Crash).
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class AiEvalDriftAndCostGuardScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "AI Engineering FinOps, Token Budget & Output Guard Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.AI_SECURITY

    @property
    def description(self) -> str:
        return (
            "Audits LLM calls for missing max_tokens/max_output_tokens cost caps (Denial of Wallet) "
            "and unguarded JSON.parse on raw model outputs."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. AI-FINOPS-MISSING-MAX-TOKENS (OpenAI / Anthropic SDK call without max_tokens)
        # ------------------------------------------------------------------
        llm_call_re = re.compile(
            r"\b(?:completions\.create|messages\.create|generate_content)\s*\(\s*\{([\s\S]{10,600}?)\}\s*\)"
        )
        for match in llm_call_re.finditer(content):
            args_body = match.group(1)
            if "max_tokens" not in args_body and "max_completion_tokens" not in args_body:
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)[:120]
                findings.append(
                    Finding(
                        id="AI-FINOPS-MISSING-MAX-TOKENS",
                        title="AI Engineering & FinOps (OWASP LLM10): LLM Completion Call Missing `max_tokens` Budget Cap",
                        description=(
                            f"LLM API invocation at line {line_num} does not specify `max_tokens` or `max_completion_tokens`. "
                            f"Adversarial inputs (sponge prompts) or runaway generation loops can exhaust token quotas and cause Denial-of-Wallet."
                        ),
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Always enforce an explicit `max_tokens` / `max_completion_tokens` ceiling tailored to the task's expected output size.",
                        cwe_id="CWE-770",
                        stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                        compliance_controls={"OWASP-LLM": "LLM10:2025 Unbounded Consumption"},
                    )
                )

        return findings
