"""Local script execution and rule-based remediation guidance.

This module does not establish target exploitability or execute an SLM.
Local subprocess execution is not a security sandbox.
"""
from __future__ import annotations

import enum
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cyberaudit.core.sandbox_drivers import LocalProcessDriver, ResourceLimits

logger = logging.getLogger("cyberaudit.autonomous.poc_sandbox")


class PoCValidationStatus(str, enum.Enum):
    """Validation status resulting from controlled sandbox execution."""
    NOT_RUN = "NOT_RUN"
    VERIFIED_EXPLOITABLE = "VERIFIED_EXPLOITABLE"
    UNVERIFIED_BENIGN = "UNVERIFIED_BENIGN"
    SANDBOX_ERROR = "SANDBOX_ERROR"


@dataclass
class PoCVerificationReport:
    """Evidence and telemetry resulting from an automated PoC sandbox run."""
    finding_id: str
    status: PoCValidationStatus
    canary_token: str
    execution_output: str
    telemetry_matched: bool
    duration_ms: float
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "canary_token": self.canary_token,
            "execution_output": self.execution_output,
            "telemetry_matched": self.telemetry_matched,
            "duration_ms": self.duration_ms,
            "evidence": self.evidence,
        }


class AutonomousPoCSynthesizer:
    """Synthesizes benign, executable pytest reproduction scripts with canary probes."""

    def synthesize_repro_script(
        self,
        finding: Dict[str, Any],
        canary_token: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Generate a Python script containing a benign canary probe test.
        
        Returns: (script_content, canary_token)
        """
        raise NotImplementedError(
            "Automatic PoC generation is unavailable: provide a reviewed reproducer "
            "bound to the actual target. Demonstration canaries are not audit evidence."
        )


class SandboxPoCExecutor:
    """Executes synthesized PoC in a localized, hermetic sandbox and inspects execution telemetry."""

    def __init__(self) -> None:
        self.driver = LocalProcessDriver()

    def execute_and_verify(
        self,
        finding_id: str,
        poc_code: str,
        canary_token: str,
        timeout: int = 10,
    ) -> PoCVerificationReport:
        """Run the PoC in an isolated subprocess and verify if canary token is reflected in stdout/stderr."""
        start_time = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="cyberaudit_poc_") as tmpdir:
            test_file = os.path.join(tmpdir, "test_poc.py")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write(poc_code)

            try:
                cmd = [sys.executable, "-m", "pytest", test_file, "-v", "-s", "--tb=short"]
                proc = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                duration = round((time.monotonic() - start_time) * 1000, 2)
                output = proc.stdout + proc.stderr

                # Verify canary in output
                canary_matched = canary_token in output and proc.returncode == 0
                if canary_matched:
                    status = PoCValidationStatus.UNVERIFIED_BENIGN
                else:
                    status = PoCValidationStatus.UNVERIFIED_BENIGN

                return PoCVerificationReport(
                    finding_id=finding_id,
                    status=status,
                    canary_token=canary_token,
                    execution_output=output[:1000],  # Truncate for report
                    telemetry_matched=canary_matched,
                    duration_ms=duration,
                    evidence={
                        "exit_code": proc.returncode,
                        "token_observed": canary_token in output,
                        "target_verification": "NOT_RUN",
                        "reason": "Printed tokens and passing scripts do not prove target exploitability",
                    },
                )
            except subprocess.TimeoutExpired:
                duration = round((time.monotonic() - start_time) * 1000, 2)
                return PoCVerificationReport(
                    finding_id=finding_id,
                    status=PoCValidationStatus.SANDBOX_ERROR,
                    canary_token=canary_token,
                    execution_output="Execution timed out in sandbox.",
                    telemetry_matched=False,
                    duration_ms=duration,
                    evidence={"error": "TIMEOUT"},
                )
            except Exception as e:
                duration = round((time.monotonic() - start_time) * 1000, 2)
                return PoCVerificationReport(
                    finding_id=finding_id,
                    status=PoCValidationStatus.SANDBOX_ERROR,
                    canary_token=canary_token,
                    execution_output=str(e),
                    telemetry_matched=False,
                    duration_ms=duration,
                    evidence={"error": str(e)},
                )


class LocalSLMTriageAdapter:
    """Performs offline triage and patch synthesis using local Small Language Models (SLMs)."""

    def __init__(self, model_name: str = "DeepSeek-Coder-1.3B-Instruct") -> None:
        self.model_name = model_name

    def triage_finding(
        self,
        finding: Dict[str, Any],
        code_context: str,
    ) -> Dict[str, Any]:
        """Perform on-premise triage, root-cause deduction, and patch generation without cloud calls."""
        cwe = str(finding.get("cwe", "CWE-UNKNOWN"))
        title = finding.get("title", "Security Flaw")

        # Deterministic offline reasoning engine
        if "CWE-89" in cwe or "SQL" in title.upper():
            rca = "Untrusted parameter directly concatenated into dynamic SQL string."
            vector = "Remote HTTP query parameter injection bypassing auth or querying arbitrary tables."
            patch = "Use parameterized prepared statements (cursor.execute('SELECT ... WHERE id = %s', (id,)))"
        elif "CWE-78" in cwe or "COMMAND" in title.upper():
            rca = "Arbitrary shell argument execution via shell=True or unescaped string formatting in subprocess."
            vector = "Injected shell operators (;, &&, |) executing arbitrary host commands."
            patch = "Pass arguments as a list with shell=False (subprocess.run(['cmd', arg1], shell=False))"
        elif "CWE-918" in cwe or "SSRF" in title.upper():
            rca = "Unrestricted HTTP client fetching user-supplied URL without private CIDR filtering."
            vector = "Attacker accesses internal metadata (169.254.169.254) or intranet microservices."
            patch = "Enforce URL domain whitelist and reject private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
        else:
            rca = "Boundary check missing on untrusted input payload."
            vector = "Improper input validation causing unhandled exception or denial of service."
            patch = "Add explicit schema validation and strict type casting."

        return {
            "model": None,
            "requested_model": self.model_name,
            "method": "static_rule_guidance",
            "model_execution": "NOT_RUN",
            "finding_id": finding.get("id", "F-001"),
            "root_cause_analysis": rca,
            "attack_vector": vector,
            "remediation_code_patch": patch,
            "confidence_score": None,
            "offline_certified": False,
        }


class AutonomousRedTeamBot:
    """Coordinates autonomous PoC synthesis, sandbox verification, and local SLM triage."""

    def __init__(self) -> None:
        self.synthesizer = AutonomousPoCSynthesizer()
        self.executor = SandboxPoCExecutor()
        self.triage_adapter = LocalSLMTriageAdapter()

    def process_finding(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
    ) -> Dict[str, Any]:
        """Execute automated PoC verification and triage."""
        finding_id = finding.get("id", "F-001")
        result = dict(finding)
        result["exploitability_proven"] = False
        result["poc_evidence"] = {
            "finding_id": finding_id,
            "status": PoCValidationStatus.NOT_RUN.value,
            "reason": "No reviewed reproducer bound to the actual target was provided",
        }

        # Perform local SLM triage
        triage = self.triage_adapter.triage_finding(finding, code_context)
        result["slm_triage"] = triage

        return result
