"""
CyberAudit External-First Orchestrator
Implements the 'External-First with Graceful Fallback & Blindspot Coverage' doctrine:
1. Stage 1 (External-First): Discovers and executes available industry-standard tools
   (npm audit, pip-audit, gitleaks, trivy) against project manifests.
2. Stage 2 (Graceful Fallback): If external tools fail or are absent, flags the domain
   for native scanner fallback so the audit never halts or misses vulnerabilities.
3. Stage 3 (Normalization): Parses external tool JSON/SARIF output into uniform Finding objects.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple, Any

from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory

logger = logging.getLogger("cyberaudit.core.external_orchestrator")


class ExternalToolOrchestrator:
    """
    Orquestador de herramientas externas de industria con fallback a escáneres nativos.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.status: Dict[str, Any] = {
            "attempted": [],
            "succeeded": [],
            "failed": [],
            "fallback_needed": set(),
        }

    def is_tool_available(self, tool_name: str) -> bool:
        """Determines if a command line binary is accessible on system PATH."""
        return shutil.which(tool_name) is not None

    def run_external_first(self, target_path: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Executes external tools first where applicable.
        Returns (findings, status_summary).
        """
        findings: List[Finding] = []
        target_path = os.path.abspath(target_path)

        if not os.path.exists(target_path):
            return findings, self.status

        # ── 1. Node.js Dependency Audit (npm audit) ──────────────────────────
        pkg_json = os.path.join(target_path, "package.json")
        pkg_lock = os.path.join(target_path, "package-lock.json")
        if os.path.isfile(pkg_json) or os.path.isfile(pkg_lock):
            self.status["attempted"].append("npm_audit")
            if self.is_tool_available("npm"):
                npm_findings = self._run_npm_audit(target_path)
                if npm_findings is not None:
                    findings.extend(npm_findings)
                    self.status["succeeded"].append("npm_audit")
                else:
                    self.status["failed"].append("npm_audit")
                    self.status["fallback_needed"].add("sca_dependency")
            else:
                self.status["failed"].append("npm_audit (not in PATH)")
                self.status["fallback_needed"].add("sca_dependency")

        # ── 2. Python Dependency Audit (pip-audit) ────────────────────────────
        req_txt = os.path.join(target_path, "requirements.txt")
        pyproject = os.path.join(target_path, "pyproject.toml")
        if os.path.isfile(req_txt) or os.path.isfile(pyproject):
            self.status["attempted"].append("pip_audit")
            if self.is_tool_available("pip-audit"):
                py_findings = self._run_pip_audit(target_path)
                if py_findings is not None:
                    findings.extend(py_findings)
                    self.status["succeeded"].append("pip_audit")
                else:
                    self.status["failed"].append("pip_audit")
                    self.status["fallback_needed"].add("sca_dependency")
            else:
                self.status["failed"].append("pip_audit (not in PATH)")
                self.status["fallback_needed"].add("sca_dependency")

        # ── 3. Secrets Scanning (gitleaks) ───────────────────────────────────
        if self.is_tool_available("gitleaks"):
            self.status["attempted"].append("gitleaks")
            gl_findings = self._run_gitleaks(target_path)
            if gl_findings is not None:
                findings.extend(gl_findings)
                self.status["succeeded"].append("gitleaks")
            else:
                self.status["failed"].append("gitleaks")
                self.status["fallback_needed"].add("secrets")
        else:
            self.status["fallback_needed"].add("secrets")

        # ── 4. Container & IaC Scanning (trivy) ──────────────────────────────
        dockerfile = os.path.join(target_path, "Dockerfile")
        if os.path.isfile(dockerfile) and self.is_tool_available("trivy"):
            self.status["attempted"].append("trivy")
            trivy_findings = self._run_trivy(target_path)
            if trivy_findings is not None:
                findings.extend(trivy_findings)
                self.status["succeeded"].append("trivy")
            else:
                self.status["failed"].append("trivy")
                self.status["fallback_needed"].add("docker_iac")
        elif os.path.isfile(dockerfile):
            self.status["fallback_needed"].add("docker_iac")

        self.status["fallback_needed"] = list(self.status["fallback_needed"])
        return findings, self.status

    def _run_npm_audit(self, target_dir: str) -> Optional[List[Finding]]:
        """Runs npm audit --json in target directory and normalizes vulnerabilities."""
        try:
            # Use shell=False with explicit argv list
            cmd = ["npm", "audit", "--json"]
            proc = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=(os.name == "nt")  # Windows requires shell for npm.cmd in some shells
            )
            raw = proc.stdout.strip()
            if not raw:
                return None
            data = json.loads(raw)
            findings: List[Finding] = []

            # npm audit v7+ format
            vulnerabilities = data.get("vulnerabilities", {})
            for pkg_name, v_info in vulnerabilities.items():
                severity_str = v_info.get("severity", "moderate").upper()
                sev = Severity.MEDIUM
                if severity_str in ("CRITICAL", "HIGH", "LOW", "INFO"):
                    sev = Severity[severity_str]

                via_list = v_info.get("via", [])
                cve_list = []
                for item in via_list:
                    if isinstance(item, dict):
                        cve = item.get("url", "").split("/")[-1] or item.get("title", "")
                        cve_list.append(cve)

                title = f"SCA External: {pkg_name} ({', '.join(cve_list[:2]) or severity_str}) via npm audit"
                desc = (
                    f"External industry tool 'npm audit' flagged dependency '{pkg_name}' with severity {severity_str}. "
                    f"Range: {v_info.get('range', 'unknown')} | Fix: {v_info.get('fixAvailable', False)}"
                )

                findings.append(
                    Finding(
                        id=f"EXT-NPM-AUDIT-{pkg_name.upper()}",
                        title=title,
                        description=desc,
                        severity=sev,
                        pillar=Pillar.SECURITY_ENGINEER,
                        scanner_name="External npm audit (Industry Standard)",
                        file_path=os.path.join(target_dir, "package.json"),
                        line_number=1,
                        code_snippet=f'"{pkg_name}": "{v_info.get("range", "*")}"',
                        remediation="Run 'npm audit fix' or upgrade package to non-vulnerable version.",
                        cwe_id="CWE-1357",
                        mitre_id="T1195.001",
                        stride_category=StrideCategory.TAMPERING.value,
                        compliance_controls={"NPM": "Audit Security Gate", "SLSA": "Build Level 2"},
                    )
                )
            return findings
        except Exception as e:
            logger.debug("npm audit execution skipped or failed: %s", e)
            return None

    def _run_pip_audit(self, target_dir: str) -> Optional[List[Finding]]:
        """Runs pip-audit --format json and normalizes vulnerabilities."""
        try:
            cmd = ["pip-audit", "--format", "json"]
            proc = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            raw = proc.stdout.strip()
            if not raw:
                return None
            data = json.loads(raw)
            findings: List[Finding] = []

            for dep in data.get("dependencies", []):
                vulns = dep.get("vulns", [])
                pkg_name = dep.get("name", "unknown")
                pkg_ver = dep.get("version", "unknown")
                for v in vulns:
                    v_id = v.get("id", "VULN")
                    findings.append(
                        Finding(
                            id=f"EXT-PIP-AUDIT-{v_id}",
                            title=f"SCA External: {pkg_name}=={pkg_ver} ({v_id}) via pip-audit",
                            description=v.get("description", f"Known vulnerability in {pkg_name}."),
                            severity=Severity.HIGH,
                            pillar=Pillar.SECURITY_ENGINEER,
                            scanner_name="External pip-audit (Industry Standard)",
                            file_path=os.path.join(target_dir, "requirements.txt"),
                            line_number=1,
                            code_snippet=f"{pkg_name}=={pkg_ver}",
                            remediation=f"Upgrade {pkg_name} to >= {', '.join(v.get('fix_versions', ['latest']))}",
                            cwe_id="CWE-1357",
                            mitre_id="T1195.001",
                            stride_category=StrideCategory.TAMPERING.value,
                        )
                    )
            return findings
        except Exception as e:
            logger.debug("pip-audit execution failed: %s", e)
            return None

    def _run_gitleaks(self, target_dir: str) -> Optional[List[Finding]]:
        """Runs gitleaks detect and normalizes detected credentials."""
        try:
            cmd = ["gitleaks", "detect", "--no-git", "--report-format", "json", "-s", target_dir]
            proc = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            raw = proc.stdout.strip()
            if not raw:
                return []
            items = json.loads(raw)
            findings: List[Finding] = []
            for item in items:
                findings.append(
                    Finding(
                        id=f"EXT-GITLEAKS-{item.get('RuleID', 'SECRET')}",
                        title=f"Secrets External: {item.get('Description', 'Exposed credential')} via Gitleaks",
                        description=f"Gitleaks detected secret matching rule '{item.get('RuleID')}'.",
                        severity=Severity.CRITICAL,
                        pillar=Pillar.SECURITY_ENGINEER,
                        scanner_name="External Gitleaks (Industry Standard)",
                        file_path=item.get("File", target_dir),
                        line_number=item.get("StartLine", 1),
                        code_snippet="[REDACTED SECRET VALUE]",
                        remediation="Rotate exposed credential immediately and add file to .gitignore.",
                        cwe_id="CWE-798",
                        mitre_id="T1552.001",
                        stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    )
                )
            return findings
        except Exception as e:
            logger.debug("gitleaks execution failed: %s", e)
            return None

    def _run_trivy(self, target_dir: str) -> Optional[List[Finding]]:
        """Runs trivy fs --scanners misconfig and normalizes results."""
        try:
            cmd = ["trivy", "fs", "--scanners", "misconfig", "--format", "json", target_dir]
            proc = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            raw = proc.stdout.strip()
            if not raw:
                return []
            data = json.loads(raw)
            findings: List[Finding] = []
            results = data.get("Results", [])
            for res in results:
                target_f = res.get("Target", target_dir)
                for mis in res.get("Misconfigurations", []):
                    sev_str = mis.get("Severity", "MEDIUM").upper()
                    sev = getattr(Severity, sev_str, Severity.MEDIUM)
                    findings.append(
                        Finding(
                            id=f"EXT-TRIVY-{mis.get('ID', 'MISCONFIG')}",
                            title=f"IaC External: {mis.get('Title', 'Misconfiguration')} via Trivy",
                            description=mis.get("Description", ""),
                            severity=sev,
                            pillar=Pillar.SECURITY_ENGINEER,
                            scanner_name="External Trivy (Industry Standard)",
                            file_path=target_f,
                            line_number=mis.get("Resolution", {}).get("StartLine", 1),
                            code_snippet=mis.get("Message", ""),
                            remediation=mis.get("Resolution", "Review IaC hardening directives."),
                            cwe_id="CWE-16",
                            stride_category=StrideCategory.TAMPERING.value,
                        )
                    )
            return findings
        except Exception as e:
            logger.debug("trivy execution failed: %s", e)
            return None
