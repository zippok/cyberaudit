"""
Cyber Threat Intelligence (CTI) & MISP Correlator
Extracts Indicators of Compromise (IOCs: IPs, domains, hashes),
defangs them for safe reporting, and correlates them with known
threat actor infrastructure (Volt Typhoon, Conti, LockBit, Lazarus).
Mapped to MITRE ATT&CK: T1071.001, T1583
"""

import re
import json
import os
from pathlib import Path
from datetime import datetime
import ipaddress
from typing import List, Dict, Set, Any
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar


class CtiCorrelator(BaseScanner):
    def __init__(self, feed_path=None):
        super().__init__()
        # Regex extractors
        self.ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        self.sha256_regex = re.compile(r"\b[a-fA-F0-9]{64}\b")
        self.md5_regex = re.compile(r"\b[a-fA-F0-9]{32}\b")
        # Domain extractor requires http/https to prevent false positives on C++ files (.cc), GLSL shaders (.xyz), or Roku (.top)
        self.domain_regex = re.compile(r"\bhttps?://([a-zA-Z0-9.-]+\.(?:ru|su|xyz|top|pw|onion))\b", re.IGNORECASE)

        # No built-in actor attribution: only explicitly supplied, dated evidence.
        self.known_threat_db: Dict[str, Dict[str, Any]] = {}
        configured = feed_path or os.getenv("CYBERAUDIT_CTI_FEED")
        if configured:
            feed = json.loads(Path(configured).read_text(encoding="utf-8"))
            if not feed.get("source") or not feed.get("retrieved_at"):
                raise ValueError("CTI feed requires source and retrieved_at")
            datetime.fromisoformat(feed["retrieved_at"].replace("Z", "+00:00"))
            for indicator in feed["indicators"]:
                entry = dict(indicator)
                entry["severity"] = Severity[entry.get("severity", "MEDIUM")]
                entry["source"] = feed["source"]
                entry["retrieved_at"] = feed["retrieved_at"]
                for key in ("actor", "campaign", "threat"):
                    if not entry.get(key):
                        raise ValueError(f"CTI indicator requires {key}")
                self.known_threat_db[entry["value"].lower()] = entry

    @property
    def name(self) -> str:
        return "CTI & Threat Intel Correlator"

    @property
    def evidence_coverage(self) -> dict:
        return {"threat_feed": "LOADED" if self.known_threat_db else "NOT_RUN",
                "indicator_count": len(self.known_threat_db),
                "live_threat_intelligence_query": "NOT_RUN",
                "domain_heuristics": "STATIC_RULES"}

    @property
    def pillar(self) -> Pillar:
        return Pillar.SECURITY_ANALYST

    @property
    def description(self) -> str:
        return "Extracts and defangs IOCs (IPs, hashes, domains) and correlates with an explicitly configured, dated local threat feed."

    @staticmethod
    def defang_ioc(ioc: str) -> str:
        """Safely defangs an IOC for non-executable reporting."""
        defanged = ioc.replace("http://", "hxxp://").replace("https://", "hxxps://")
        defanged = defanged.replace(".", "[.]")
        return defanged

    @staticmethod
    def is_public_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
        except ValueError:
            return False

    def should_scan(self, file_path: str) -> bool:
        import os
        ext = os.path.splitext(file_path)[1].lower()
        if ext in {
            ".exe", ".dll", ".so", ".dylib", ".bin", ".sys", ".node",
            ".pak", ".o", ".obj", ".class", ".pyc", ".pyd", ".png",
            ".jpg", ".jpeg", ".zip", ".tar", ".gz", ".7z",
        }:
            return False
        return True

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        found_iocs: Set[str] = set()

        # 1. Check IP addresses
        for match in self.ip_regex.finditer(content):
            ip = match.group(0)
            if self.is_public_ip(ip) and ip not in found_iocs:
                found_iocs.add(ip)
                defanged = self.defang_ioc(ip)
                threat_info = self.known_threat_db.get(ip)

                if threat_info:
                    finding = Finding(
                        id=f"CTI-IOC-IP-KNOWN-{ip.replace('.', '-')}",
                        title=f"CTI Match: Known Threat Actor IP Detected ({defanged})",
                        description=f"IP matches threat feed for {threat_info['actor']} ({threat_info['threat']}). Campaign: {threat_info['campaign']}. Source: {threat_info['source']} ({threat_info['retrieved_at']}).",
                        severity=threat_info.get("severity", Severity.HIGH),
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        code_snippet=f"Matched IOC: {defanged}",
                        remediation=f"Block {defanged} at perimeter firewalls/EDR. Check SIEM logs for any past connections to this address.",
                        mitre_id="T1071.001",
                        mitre_tactic="Command and Control",
                        mitre_technique="Application Layer Protocol: Web Protocols",
                    )
                    findings.append(finding)

        # 2. Check Hashes (MD5 and SHA256)
        for h in list(self.sha256_regex.findall(content)) + list(self.md5_regex.findall(content)):
            h_lower = h.lower()
            if h_lower in self.known_threat_db and h_lower not in found_iocs:
                found_iocs.add(h_lower)
                threat_info = self.known_threat_db[h_lower]
                if threat_info["actor"] == "Known Null Hash":
                    continue

                finding = Finding(
                    id=f"CTI-IOC-HASH-{h_lower[:12]}",
                    title=f"CTI Match: Malicious File Hash Detected ({threat_info['actor']})",
                    description=f"Hash matches malicious artifact linked to {threat_info['actor']} - {threat_info['threat']}.",
                    severity=threat_info.get("severity", Severity.CRITICAL),
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    code_snippet=f"Hash: {h_lower}",
                    remediation="Quarantine the file and run an incident investigation across endpoints sharing this checksum.",
                    mitre_id="T1204.002",
                    mitre_tactic="Execution",
                    mitre_technique="User Execution: Malicious File",
                )
                findings.append(finding)

        # 3. Check Suspicious TLD Domains
        for match in self.domain_regex.finditer(content):
            dom = match.group(1).lower()
            if dom not in found_iocs:
                found_iocs.add(dom)
                defanged = self.defang_ioc(dom)
                threat_info = self.known_threat_db.get(dom)

                severity = threat_info.get("severity", Severity.MEDIUM) if threat_info else Severity.LOW
                desc = (
                    f"Domain matches known threat actor: {threat_info['actor']} ({threat_info['threat']})"
                    if threat_info
                    else f"Observed reference to high-risk or commonly abused TLD domain: {defanged}"
                )

                finding = Finding(
                    id=f"CTI-IOC-DOM-{dom.replace('.', '-')[:20]}",
                    title=f"CTI Notice: Suspicious Domain Reference ({defanged})",
                    description=desc,
                    severity=severity,
                    confidence="MEDIUM" if threat_info else "LOW",
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    code_snippet=f"Extracted Domain: {defanged}",
                    remediation=f"Verify business necessity for communicating with {defanged}. Consider sinkholing or DNS blocklisting.",
                    mitre_id="T1583",
                    mitre_tactic="Resource Development",
                    mitre_technique="Acquire Infrastructure: Domains",
                )
                findings.append(finding)

        return findings
