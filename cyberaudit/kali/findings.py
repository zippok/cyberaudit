"""
CyberAudit Kali Finding Mapper
Translates normalized :class:`ToolObservation` records into platform
:class:`~cyberaudit.core.models.Finding` objects, enriching them with pillar,
STRIDE category, MITRE context and normative compliance mappings.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional, Sequence

from cyberaudit.core.models import Finding, Pillar, Severity, StrideCategory
from cyberaudit.kali.parsers import ToolObservation
from cyberaudit.kali.tool_registry import KALI_TOOLS, KaliCategory

PILLAR_BY_CATEGORY: Dict[KaliCategory, Pillar] = {
    KaliCategory.RECON: Pillar.PENETRATION_TESTER,
    KaliCategory.WEB: Pillar.PENETRATION_TESTER,
    KaliCategory.NETWORK: Pillar.CLOUD_DEFENSE,
    KaliCategory.AD: Pillar.SECURITY_ANALYST,
    KaliCategory.CREDENTIAL: Pillar.PENETRATION_TESTER,
    KaliCategory.EXPLOIT: Pillar.PENETRATION_TESTER,
    KaliCategory.FORENSIC: Pillar.DFIR_ENDPOINT,
    KaliCategory.WIRELESS: Pillar.PENETRATION_TESTER,
}

STRIDE_BY_CATEGORY: Dict[KaliCategory, StrideCategory] = {
    KaliCategory.RECON: StrideCategory.INFORMATION_DISCLOSURE,
    KaliCategory.WEB: StrideCategory.TAMPERING,
    KaliCategory.NETWORK: StrideCategory.INFORMATION_DISCLOSURE,
    KaliCategory.AD: StrideCategory.SPOOFING,
    KaliCategory.CREDENTIAL: StrideCategory.SPOOFING,
    KaliCategory.EXPLOIT: StrideCategory.ELEVATION_OF_PRIVILEGE,
    KaliCategory.FORENSIC: StrideCategory.REPUDIATION,
    KaliCategory.WIRELESS: StrideCategory.INFORMATION_DISCLOSURE,
}

MITRE_BY_TOOL: Dict[str, Dict[str, str]] = {
    "nmap": {"id": "T1046", "tactic": "Discovery", "technique": "Network Service Discovery"},
    "masscan": {"id": "T1046", "tactic": "Discovery", "technique": "Network Service Discovery"},
    "nikto": {"id": "T1595.002", "tactic": "Reconnaissance", "technique": "Vulnerability Scanning"},
    "nuclei": {"id": "T1595.002", "tactic": "Reconnaissance", "technique": "Vulnerability Scanning"},
    "gobuster": {"id": "T1083", "tactic": "Discovery", "technique": "File and Directory Discovery"},
    "ffuf": {"id": "T1083", "tactic": "Discovery", "technique": "File and Directory Discovery"},
    "dirb": {"id": "T1083", "tactic": "Discovery", "technique": "File and Directory Discovery"},
    "whatweb": {"id": "T1592.002", "tactic": "Reconnaissance", "technique": "Software Discovery"},
    "wafw00f": {"id": "T1590.005", "tactic": "Reconnaissance", "technique": "IP Addresses"},
    "httpx": {"id": "T1595.001", "tactic": "Reconnaissance", "technique": "Scanning IP Blocks"},
    "dnsrecon": {"id": "T1590.002", "tactic": "Reconnaissance", "technique": "DNS Lookups"},
    "amass": {"id": "T1590.002", "tactic": "Reconnaissance", "technique": "DNS Lookups"},
    "enum4linux": {"id": "T1087.002", "tactic": "Discovery", "technique": "Account Discovery: Domain Account"},
    "smbclient": {"id": "T1135", "tactic": "Discovery", "technique": "Network Share Discovery"},
    "nxc": {"id": "T1021.002", "tactic": "Lateral Movement", "technique": "SMB/Windows Admin Shares"},
    "snmpwalk": {"id": "T1602.001", "tactic": "Collection", "technique": "SNMP (MIB Dump)"},
    "onesixtyone": {"id": "T1046", "tactic": "Discovery", "technique": "Network Service Discovery"},
    "smtp_user_enum": {"id": "T1087.003", "tactic": "Discovery", "technique": "Account Discovery: Email Account"},
    "nbtscan": {"id": "T1018", "tactic": "Discovery", "technique": "Remote System Discovery"},
    "sslscan": {"id": "T1595.002", "tactic": "Reconnaissance", "technique": "Vulnerability Scanning"},
    "sqlmap": {"id": "T1190", "tactic": "Initial Access", "technique": "Exploit Public-Facing Application"},
    "commix": {"id": "T1190", "tactic": "Initial Access", "technique": "Exploit Public-Facing Application"},
    "hydra": {"id": "T1110.001", "tactic": "Credential Access", "technique": "Brute Force: Password Guessing"},
    "john": {"id": "T1110.002", "tactic": "Credential Access", "technique": "Brute Force: Password Cracking"},
    "hashcat": {"id": "T1110.002", "tactic": "Credential Access", "technique": "Brute Force: Password Cracking"},
    "impacket_secretsdump": {"id": "T1003.003", "tactic": "Credential Access", "technique": "OS Credential Dumping: NTDS"},
    "responder": {"id": "T1557.001", "tactic": "Credential Access", "technique": "LLMNR/NBT-NS Poisoning"},
    "tcpdump": {"id": "T1040", "tactic": "Credential Access", "technique": "Network Sniffing"},
    "tshark": {"id": "T1040", "tactic": "Credential Access", "technique": "Network Sniffing"},
    "searchsploit": {"id": "T1588.005", "tactic": "Resource Development", "technique": "Obtain Capabilities: Exploits"},
}

COMPLIANCE_BY_CATEGORY: Dict[KaliCategory, Dict[str, str]] = {
    KaliCategory.NETWORK: {
        "PCI_DSS": "PCI-DSS 4.0 Req 1.3 (perímetro de red)",
        "ISO_27001": "A.8.20 (seguridad de redes) / A.8.21",
        "CIS": "CIS Controls v8 — 4.1 (configuración segura)",
        "NIST_CSF": "PR.PS-01 / ID.AM-03",
    },
    KaliCategory.WEB: {
        "PCI_DSS": "PCI-DSS 4.0 Req 6.2.4 (defectos de software)",
        "ISO_27001": "A.8.28 (codificación segura)",
        "OWASP": "OWASP Top 10 — A05:2021 / A03:2021",
        "NIST_CSF": "PR.PS-02",
    },
    KaliCategory.AD: {
        "PCI_DSS": "PCI-DSS 4.0 Req 8.2 (autenticación)",
        "ISO_27001": "A.5.15 / A.5.17 (control de acceso)",
        "CIS": "CIS Controls v8 — 5.3 / 6.5",
        "NIST_CSF": "PR.AA-01",
    },
    KaliCategory.CREDENTIAL: {
        "PCI_DSS": "PCI-DSS 4.0 Req 8.3.6 (complejidad de contraseñas)",
        "ISO_27001": "A.5.17 (información de autenticación)",
        "NIST": "NIST SP 800-63B",
    },
    KaliCategory.EXPLOIT: {
        "PCI_DSS": "PCI-DSS 4.0 Req 6.3.3 (parches críticos)",
        "ISO_27001": "A.8.8 (gestión de vulnerabilidades técnicas)",
        "NIST_CSF": "ID.RA-01",
    },
    KaliCategory.RECON: {
        "ISO_27001": "A.5.7 (inteligencia de amenazas)",
        "NIST_CSF": "ID.RA-02",
    },
    KaliCategory.FORENSIC: {
        "NIST": "NIST SP 800-61 Rev.2 (manejo de incidentes)",
        "ISO_27001": "A.8.15 (registro de eventos)",
    },
    KaliCategory.WIRELESS: {
        "PCI_DSS": "PCI-DSS 4.0 Req 11.1",
        "ISO_27001": "A.8.20",
    },
}


def _tool_key_to_id_token(tool_key: str) -> str:
    return tool_key.upper().replace("_", "-")


def _stable_suffix(observation: ToolObservation) -> str:
    basis = f"{observation.title}|{observation.host}|{observation.port}|{observation.cve_id}"
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:8]


def build_finding_id(observation: ToolObservation) -> str:
    token = _tool_key_to_id_token(observation.tool_key)
    slug = observation.slug or ""
    slug = re.sub(r"[^A-Za-z0-9\-]+", "-", str(slug)).strip("-").upper()
    if not slug:
        slug = _stable_suffix(observation).upper()
    return f"KALI-{token}-{slug}"[:150]


def observation_to_finding(observation: ToolObservation) -> Finding:
    """Converts a single normalized observation into a platform Finding."""
    tool = KALI_TOOLS.get(observation.tool_key)
    category = tool.category if tool else KaliCategory.RECON

    stride = observation.stride_category or STRIDE_BY_CATEGORY.get(category, StrideCategory.INFORMATION_DISCLOSURE).value
    compliance = dict(COMPLIANCE_BY_CATEGORY.get(category, {}))
    compliance.update(observation.compliance_controls or {})
    mitre = MITRE_BY_TOOL.get(observation.tool_key, {})

    location = observation.host or ""
    if observation.port:
        location = f"{location}:{observation.port}"
    if tool is not None:
        location = f"{location} [{tool.binary}]" if location else f"[{tool.binary}]"

    return Finding(
        id=build_finding_id(observation),
        title=observation.title,
        description=observation.description,
        severity=observation.severity,
        pillar=PILLAR_BY_CATEGORY.get(category, Pillar.PENETRATION_TESTER),
        scanner_name=f"kali:{observation.tool_key}",
        file_path=location or "kali-target",
        line_number=None,
        code_snippet=observation.evidence or None,
        remediation=observation.remediation,
        mitre_id=mitre.get("id"),
        mitre_tactic=mitre.get("tactic"),
        mitre_technique=mitre.get("technique"),
        cwe_id=observation.cwe_id,
        cve_id=observation.cve_id,
        stride_category=stride,
        compliance_controls=compliance,
        confidence=observation.confidence,
    )


def observations_to_findings(observations: Sequence[ToolObservation]) -> List[Finding]:
    """Maps observations to findings, merging duplicates deterministically.

    When two observations collapse into the same finding id, the highest severity
    wins and the duplicate evidence is appended (so no data is silently lost).
    """
    merged: Dict[str, Finding] = {}
    for observation in observations:
        finding = observation_to_finding(observation)
        existing = merged.get(finding.id)
        if existing is None:
            merged[finding.id] = finding
            continue
        if finding.severity.rank > existing.severity.rank:
            new_snippet = existing.code_snippet or ""
            merged[finding.id] = finding
            if new_snippet and new_snippet not in (finding.code_snippet or ""):
                finding.code_snippet = ((finding.code_snippet or "") + "\n---\n" + new_snippet)[:600]
            existing = finding
        elif finding.code_snippet and finding.code_snippet not in (existing.code_snippet or ""):
            existing.code_snippet = ((existing.code_snippet or "") + "\n---\n" + finding.code_snippet)[:600]
    return list(merged.values())


__all__ = [
    "observation_to_finding",
    "observations_to_findings",
    "build_finding_id",
    "PILLAR_BY_CATEGORY",
    "COMPLIANCE_BY_CATEGORY",
    "MITRE_BY_TOOL",
]
