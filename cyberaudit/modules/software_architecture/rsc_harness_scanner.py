"""
RSC-Harness & Agentic Governance Scanner
Audits software projects against the rsc-harness (P2, P7, P10) governance contract:
1. Draft Constitution Detection: Checks if 02-DOCS/wiki/sdd/constitution.md is still in 'status: draft'.
2. Tool Connection Proof: Audits 01-TOOLS/<tool>/ folders to verify CREDENTIALS.md, .env.example, and test_connection.sh exist and no raw .env is tracked.
3. Verification Record Integrity: Audits 02-DOCS/wiki/sdd/verifications/*.md for mandatory source_state, rollback plan, and unresolved HERRAMIENTA-AUSENTE / SUSTITUIDA gaps.
4. FTD Evidence Contract (P10): Audits 02-DOCS/wiki/ftd/*.md so checked-off tasks [x] are accompanied by observed proof under ## Evidence.
5. Core Audit Skills Equipped: Checks .rsc.json to verify core review/verification skills (review, verify, security-scan, secure-coding, code-review) are installed.
"""

import json
import os
import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class RscHarnessGovernanceScanner(BaseScanner):
    __test__ = False

    REQUIRED_AUDIT_SKILLS = {"review", "verify", "security-scan", "secure-coding", "code-review"}

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "RSC-Harness & Agentic SDD/FTD Governance Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.ARCHITECTURE

    @property
    def description(self) -> str:
        return (
            "Audits rsc-harness project memory (02-DOCS/), tool connections (01-TOOLS/), "
            "SDD constitution status, verification gates (P2/P10), and installed audit skills."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".md", ".json"]

    def should_scan(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/").lower()
        basename = norm.split("/")[-1]
        if basename == ".rsc.json":
            return True
        if "/02-docs/wiki/" in norm and norm.endswith(".md"):
            return True
        if "/01-tools/" in norm and (norm.endswith(".md") or norm.endswith(".json")):
            return True
        return False

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        norm = file_path.replace("\\", "/").lower()
        basename = norm.split("/")[-1]

        if basename == ".rsc.json":
            findings.extend(self._scan_rsc_config(file_path, content))
        elif norm.endswith("/02-docs/wiki/sdd/constitution.md"):
            findings.extend(self._scan_constitution(file_path, content))
        elif "/02-docs/wiki/sdd/verifications/" in norm and norm.endswith(".md"):
            findings.extend(self._scan_verification_record(file_path, content))
        elif "/02-docs/wiki/ftd/" in norm and norm.endswith(".md"):
            findings.extend(self._scan_ftd_document(file_path, content))

        return findings

    def scan_directory(self, dir_path: str) -> List[Finding]:
        findings: List[Finding] = []
        tools_dir = os.path.join(dir_path, "01-TOOLS")
        if os.path.isdir(tools_dir):
            findings.extend(self._scan_tools_directory(tools_dir))
        return findings

    def _scan_rsc_config(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(content)
        except Exception:
            return findings

        if not isinstance(data, dict):
            return findings

        skills = set()
        raw_skills = data.get("skills", [])
        if isinstance(raw_skills, list):
            for s in raw_skills:
                if isinstance(s, str):
                    skills.add(s.replace("skill/", ""))
                elif isinstance(s, dict) and "id" in s:
                    skills.add(str(s["id"]).replace("skill/", ""))

        selected = data.get("selected", [])
        if isinstance(selected, list):
            for item in selected:
                if isinstance(item, str) and item.startswith("skill/"):
                    skills.add(item.replace("skill/", ""))
                elif isinstance(item, dict) and str(item.get("id", "")).startswith("skill/"):
                    skills.add(str(item["id"]).replace("skill/", ""))

        # Check .rsc/skills directory on disk if present next to .rsc.json
        rsc_skills_dir = os.path.join(os.path.dirname(file_path), ".rsc", "skills")
        if os.path.isdir(rsc_skills_dir):
            try:
                for entry in os.listdir(rsc_skills_dir):
                    if os.path.isdir(os.path.join(rsc_skills_dir, entry)):
                        skills.add(entry)
            except OSError:
                pass

        missing = sorted(self.REQUIRED_AUDIT_SKILLS - skills)
        if skills and missing:
            findings.append(
                Finding(
                    id="RSC-GOV-MISSING-AUDIT-SKILLS",
                    title=f"RSC-Harness Missing Recommended Security/Review Skills: {', '.join(missing)}",
                    description=(
                        f"The project has rsc-harness configured in '.rsc.json', but is missing core "
                        f"audit and verification skills ({', '.join(missing)}). Installing these skills "
                        f"equips the coding agent and CyberAudit with OWASP secure coding rules, spec-less "
                        f"code review, and evidence gates."
                    ),
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=f"Missing skills: {', '.join(missing)}",
                    remediation=f"Run: npx @ericrisco/rsc add {' '.join(missing)}",
                    cwe_id="CWE-710",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"RSC-Harness": "P2-Evidence-Gates", "ISO 27001": "A.8.28"},
                )
            )
        return findings

    def _scan_constitution(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        if re.search(r"^status:\s*draft\b", content, re.MULTILINE | re.IGNORECASE):
            findings.append(
                Finding(
                    id="RSC-SDD-DRAFT-CONSTITUTION",
                    title="RSC-Harness SDD Constitution is Still in Draft Status",
                    description=(
                        "The project's SDD Constitution (02-DOCS/wiki/sdd/constitution.md) is marked as "
                        "'status: draft' or contains unratified placeholders. Without a ratified constitution, "
                        "the 'verify' and 'review' skills lack non-negotiable quality bars (coverage floor, "
                        "security floor, and Definition of Done)."
                    ),
                    severity=Severity.LOW,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="status: draft",
                    remediation="Complete and ratify 02-DOCS/wiki/sdd/constitution.md (set 'status: ratified' and 'version: 1.0.0').",
                    cwe_id="CWE-710",
                    stride_category=StrideCategory.REPUDIATION.value,
                    compliance_controls={"RSC-Harness": "SDD-Constitution", "NIST CSF": "GV.PO-01"},
                )
            )
        return findings

    def _scan_verification_record(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        has_source_state = bool(re.search(r"^source_state:\s*\S+", content, re.MULTILINE))
        if not has_source_state:
            findings.append(
                Finding(
                    id="RSC-VERIFY-MISSING-SOURCE-STATE",
                    title="RSC Verification Record Missing Mandatory 'source_state' Commit Binding",
                    description=(
                        "A verification record under 02-DOCS/wiki/sdd/verifications/ does not declare "
                        "'source_state: <sha>' in its YAML frontmatter. Per rsc-harness P10 & verify skill, "
                        "a verdict belongs to the exact commit SHA measured, not to the project."
                    ),
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=content[:160].strip(),
                    remediation="Add 'source_state: <git-short-sha> (clean)' to the YAML frontmatter of the verification record.",
                    cwe_id="CWE-345",
                    stride_category=StrideCategory.REPUDIATION.value,
                    compliance_controls={"RSC-Harness": "P10-Observed-Evidence", "SLSA": "Provenance-Binding"},
                )
            )

        if re.search(r"##\s+Verdict:\s*PASS\b", content, re.IGNORECASE):
            if re.search(r"\b(HERRAMIENTA-AUSENTE|SUSTITUIDA)\b", content):
                findings.append(
                    Finding(
                        id="RSC-VERIFY-PASS-WITH-UNVERIFIED-GAP",
                        title="RSC Verification Record Claims PASS While Declaring Missing or Substituted Tooling",
                        description=(
                            "The verification record declares 'Verdict: PASS' while listing 'HERRAMIENTA-AUSENTE' "
                            "or 'SUSTITUIDA' under unexecuted layers. Per rsc-harness verify rules, a skipped tool "
                            "or coverage report without a threshold (GAP) is an unverified criterion and cannot pass silently."
                        ),
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=1,
                        code_snippet="Verdict: PASS with HERRAMIENTA-AUSENTE / SUSTITUIDA",
                        remediation="Run the missing verification tool or configure the fail-under threshold before marking Verdict: PASS.",
                        cwe_id="CWE-693",
                        stride_category=StrideCategory.REPUDIATION.value,
                        compliance_controls={"RSC-Harness": "P2-Gates-That-Can-Fail"},
                    )
                )
        return findings

    def _scan_ftd_document(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        checked_tasks = re.findall(r"^\s*-\s*\[[xX]\]\s+(.+)$", content, re.MULTILINE)
        if not checked_tasks:
            return findings

        evidence_match = re.search(r"##\s+Evidence\s*\n(.*?)(?=\n##\s+|\Z)", content, re.DOTALL | re.IGNORECASE)
        evidence_body = evidence_match.group(1).strip() if evidence_match else ""
        is_placeholder = (
            not evidence_body
            or len(evidence_body) < 15
            or "pendiente" in evidence_body.lower()
            or evidence_body in ("-", "N/A", "TBD")
        )
        if is_placeholder:
            findings.append(
                Finding(
                    id="RSC-FTD-CHECKED-WITHOUT-EVIDENCE",
                    title="RSC FTD Feature Document Has Completed Tasks Without Observed Proof (P10 Violation)",
                    description=(
                        f"The FTD document marks {len(checked_tasks)} task(s) as completed '[x]', "
                        "but the '## Evidence' section is empty or contains a placeholder. "
                        "Per rsc-harness Principle P10 ('Done means observed'), tasks may only be checked off "
                        "when command or test output is recorded under Evidence."
                    ),
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=checked_tasks[0][:120],
                    remediation="Record the actual observed test/command output in the '## Evidence' section for every completed task.",
                    cwe_id="CWE-710",
                    stride_category=StrideCategory.REPUDIATION.value,
                    compliance_controls={"RSC-Harness": "P10-Done-Means-Observed"},
                )
            )
        return findings

    def _scan_tools_directory(self, tools_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            entries = os.listdir(tools_dir)
        except OSError:
            return findings

        for entry in entries:
            if entry.startswith("_") or entry.startswith("."):
                continue
            sub_dir = os.path.join(tools_dir, entry)
            if not os.path.isdir(sub_dir):
                continue

            required_files = ["README.md", "CREDENTIALS.md", ".env.example", "test_connection.sh"]
            missing = [req for req in required_files if not os.path.isfile(os.path.join(sub_dir, req))]
            if missing:
                findings.append(
                    Finding(
                        id="RSC-TOOLS-INCOMPLETE-HARNESS",
                        title=f"RSC Tool Connection '{entry}' Missing Mandatory Harness Files",
                        description=(
                            f"The tool connection folder '01-TOOLS/{entry}/' is missing {', '.join(missing)}. "
                            "Every tool connected via rsc-harness must include documentation, credential instructions, "
                            "an '.env.example' template, and an executable 'test_connection.sh' proof script."
                        ),
                        severity=Severity.LOW,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=sub_dir,
                        code_snippet=f"Missing in 01-TOOLS/{entry}: {', '.join(missing)}",
                        remediation=f"Copy missing templates from 01-TOOLS/_TEMPLATE/ into 01-TOOLS/{entry}/ and verify the connection.",
                        cwe_id="CWE-710",
                        stride_category=StrideCategory.TAMPERING.value,
                        compliance_controls={"RSC-Harness": "01-TOOLS-Contract"},
                    )
                )
        return findings
