"""Mobile Application Security & Binary Decompilation Engine.

Audits Android APK/AAB and iOS IPA artifacts across:
1. AndroidManifest.xml & Info.plist security flags
2. Dalvik / Smali disassembled bytecode (TrustManager bypasses, weak PRNG, hardcoded keys)
3. Android Keystore / Apple Keychain storage taint tracking
4. Native JNI (.so / Mach-O) buffer overflow risk and stack canary verification
5. Certificate Pinning and Anti-Root / Anti-Jailbreak resilience (OWASP MASVS)
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("cyberaudit.mobile.binary_engine")


@dataclass
class MobileFinding:
    """Represents a security or compliance flaw identified in a mobile package."""
    id: str
    category: str
    cwe: str
    masvs_req: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    location: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "cwe": self.cwe,
            "masvs_req": self.masvs_req,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "remediation": self.remediation,
        }


class ManifestScanner:
    """Audits AndroidManifest.xml and iOS Info.plist configurations."""

    def scan_android_manifest_xml(self, xml_content: str) -> List[MobileFinding]:
        """Audit AndroidManifest XML content for dangerous permissions and attributes."""
        findings: List[MobileFinding] = []
        try:
            root = ET.fromstring(xml_content)
        except Exception as e:
            # Fallback regex search if XML is malformed
            logger.warning("Manifest XML parse error: %s. Using regex fallback.", e)
            return self._scan_android_manifest_regex(xml_content)

        # Android namespace
        ns = {"android": "http://schemas.android.com/apk/res/android"}

        app = root.find("application")
        if app is not None:
            # 1. Debuggable flag
            debuggable = app.attrib.get("{http://schemas.android.com/apk/res/android}debuggable")
            if debuggable == "true":
                findings.append(MobileFinding(
                    id="MOB-MAN-001",
                    category="MANIFEST_SECURITY",
                    cwe="CWE-215",
                    masvs_req="MASVS-RESILIENCE-1",
                    severity="CRITICAL",
                    title="Application is Debuggable in Manifest",
                    description="android:debuggable='true' allows any local user to attach a debugger via ADB.",
                    location="AndroidManifest.xml:<application>",
                    remediation="Set android:debuggable='false' in release builds.",
                ))

            # 2. AllowBackup flag
            backup = app.attrib.get("{http://schemas.android.com/apk/res/android}allowBackup")
            if backup == "true" or backup is None:
                findings.append(MobileFinding(
                    id="MOB-MAN-002",
                    category="MANIFEST_SECURITY",
                    cwe="CWE-921",
                    masvs_req="MASVS-STORAGE-1",
                    severity="HIGH",
                    title="Application Data Backup Enabled",
                    description="android:allowBackup='true' enables adb backup of application sandbox data.",
                    location="AndroidManifest.xml:<application>",
                    remediation="Set android:allowBackup='false' to prevent unauthorized backup extraction.",
                ))

            # 3. UsesCleartextTraffic
            cleartext = app.attrib.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
            if cleartext == "true":
                findings.append(MobileFinding(
                    id="MOB-MAN-003",
                    category="MANIFEST_SECURITY",
                    cwe="CWE-319",
                    masvs_req="MASVS-NETWORK-1",
                    severity="HIGH",
                    title="Cleartext HTTP Traffic Permitted",
                    description="android:usesCleartextTraffic='true' allows unencrypted HTTP network communication.",
                    location="AndroidManifest.xml:<application>",
                    remediation="Set android:usesCleartextTraffic='false' and enforce TLS 1.3 via network_security_config.",
                ))

            # 4. Unprotected Exported Components
            for comp_tag in ("activity", "service", "receiver", "provider"):
                for elem in app.findall(comp_tag):
                    exported = elem.attrib.get("{http://schemas.android.com/apk/res/android}exported")
                    permission = elem.attrib.get("{http://schemas.android.com/apk/res/android}permission")
                    name = elem.attrib.get("{http://schemas.android.com/apk/res/android}name", "unknown")
                    if exported == "true" and not permission:
                        findings.append(MobileFinding(
                            id="MOB-MAN-004",
                            category="MANIFEST_SECURITY",
                            cwe="CWE-926",
                            masvs_req="MASVS-PLATFORM-1",
                            severity="HIGH",
                            title=f"Exported {comp_tag.capitalize()} without Permission Protection",
                            description=f"Component '{name}' is exported to third-party apps without android:permission restriction.",
                            location=f"AndroidManifest.xml:<{comp_tag} name='{name}'>",
                            remediation="Set android:exported='false' or require a signature-level permission.",
                        ))

        return findings

    def _scan_android_manifest_regex(self, content: str) -> List[MobileFinding]:
        findings: List[MobileFinding] = []
        if 'android:debuggable="true"' in content:
            findings.append(MobileFinding(
                id="MOB-MAN-001",
                category="MANIFEST_SECURITY",
                cwe="CWE-215",
                masvs_req="MASVS-RESILIENCE-1",
                severity="CRITICAL",
                title="Application is Debuggable in Manifest",
                description="android:debuggable='true' detected via pattern matching.",
                location="AndroidManifest.xml",
                remediation="Set android:debuggable='false' in release builds.",
            ))
        if 'android:usesCleartextTraffic="true"' in content:
            findings.append(MobileFinding(
                id="MOB-MAN-003",
                category="MANIFEST_SECURITY",
                cwe="CWE-319",
                masvs_req="MASVS-NETWORK-1",
                severity="HIGH",
                title="Cleartext HTTP Traffic Permitted",
                description="android:usesCleartextTraffic='true' detected.",
                location="AndroidManifest.xml",
                remediation="Enforce HTTPS across all application endpoints.",
            ))
        return findings

    def scan_ios_info_plist(self, plist_content: str) -> List[MobileFinding]:
        """Audit iOS Info.plist for App Transport Security (ATS) exceptions."""
        findings: List[MobileFinding] = []
        if "<key>NSAllowsArbitraryLoads</key>" in plist_content and "<true/>" in plist_content:
            findings.append(MobileFinding(
                id="MOB-PLIST-001",
                category="MANIFEST_SECURITY",
                cwe="CWE-319",
                masvs_req="MASVS-NETWORK-1",
                severity="HIGH",
                title="iOS App Transport Security (ATS) Arbitrary Loads Allowed",
                description="NSAllowsArbitraryLoads set to true completely disables TLS enforcement in iOS.",
                location="Info.plist:NSAppTransportSecurity",
                remediation="Remove NSAllowsArbitraryLoads and configure granular domain exceptions if required.",
            ))
        return findings


class SmaliBytecodeScanner:
    """Parses Dalvik / Smali disassembled bytecode for insecure patterns."""

    def scan_smali_content(self, smali_text: str, filename: str = "Unknown.smali") -> List[MobileFinding]:
        findings: List[MobileFinding] = []

        # 1. Empty / Insecure TrustManager
        if "Ljavax/net/ssl/X509TrustManager;" in smali_text or "implements Ljavax/net/ssl/X509TrustManager;" in smali_text:
            # Check if checkServerTrusted has no throw or exception
            check_server_pattern = r"\.method public checkServerTrusted\([^\)]*\)V[\s\S]*?\.end method"
            matches = re.findall(check_server_pattern, smali_text)
            for m in matches:
                # If method simply returns void without throwing CertificateException
                if "throw" not in m and "return-void" in m:
                    findings.append(MobileFinding(
                        id="MOB-SMALI-001",
                        category="SMALI_BYTECODE",
                        cwe="CWE-295",
                        masvs_req="MASVS-NETWORK-1",
                        severity="CRITICAL",
                        title="Empty X509TrustManager Allows All SSL Certificates",
                        description="Method checkServerTrusted() contains empty implementation (return-void without validation), disabling MITM protections.",
                        location=f"{filename}::checkServerTrusted",
                        remediation="Implement standard certificate chain validation or use default Android system TrustManager.",
                    ))

        # 2. Insecure PRNG (java.util.Random)
        if "Ljava/util/Random;-><init>" in smali_text or "Ljava/util/Random;->nextInt" in smali_text:
            findings.append(MobileFinding(
                id="MOB-SMALI-002",
                category="SMALI_BYTECODE",
                cwe="CWE-330",
                masvs_req="MASVS-CRYPTO-1",
                severity="MEDIUM",
                title="Insecure Pseudo-Random Number Generator (java.util.Random)",
                description="Use of java.util.Random instead of java.security.SecureRandom in cryptographic or token generation context.",
                location=filename,
                remediation="Replace java.util.Random with java.security.SecureRandom.",
            ))

        # 3. Weak Symmetric Cryptography (DES, DESede, RC4, MD5)
        cipher_pattern = r'const-string\s+[vp]\d+,\s*"(DES|DESede|RC4|Blowfish|AES/ECB)'
        for match in re.finditer(cipher_pattern, smali_text, re.IGNORECASE):
            cipher_mode = match.group(1)
            findings.append(MobileFinding(
                id="MOB-SMALI-003",
                category="SMALI_BYTECODE",
                cwe="CWE-327",
                masvs_req="MASVS-CRYPTO-1",
                severity="HIGH",
                title=f"Weak Cryptographic Algorithm Detected ({cipher_mode})",
                description=f"Instantiating cipher with deprecated/insecure algorithm or mode '{cipher_mode}'.",
                location=f"{filename}:{match.start()}",
                remediation="Use AES-GCM (AES/GCM/NoPadding) with 256-bit keys.",
            ))

        # 4. Hardcoded Secrets in Dalvik Strings
        secret_pattern = r'const-string\s+[vp]\d+,\s*"(AIza[0-9A-Za-z-_]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{20,})"'
        for match in re.finditer(secret_pattern, smali_text):
            findings.append(MobileFinding(
                id="MOB-SMALI-004",
                category="SMALI_BYTECODE",
                cwe="CWE-798",
                masvs_req="MASVS-STORAGE-1",
                severity="CRITICAL",
                title="Hardcoded API Credential in Smali Bytecode",
                description="Hardcoded credential pattern detected in constant string pool.",
                location=filename,
                remediation="Store secrets in Android Keystore or retrieve via backend auth session.",
            ))

        return findings


class KeystoreTaintTracker:
    """Tracks insecure handling of secrets retrieved from Android KeyStore or stored in plain XML."""

    def scan_storage_flows(self, code_snippet: str, filename: str = "App.java") -> List[MobileFinding]:
        findings: List[MobileFinding] = []

        # Detect plain SharedPreferences storing sensitive data
        if "getSharedPreferences" in code_snippet or "PreferenceManager.getDefaultSharedPreferences" in code_snippet:
            # Check if putting token, password, or key into editor without EncryptedSharedPreferences
            if "EncryptedSharedPreferences" not in code_snippet:
                sensitive_keys = re.findall(r'\.putString\s*\(\s*["\'](password|token|secret|private_key|auth)["\']', code_snippet, re.IGNORECASE)
                if sensitive_keys:
                    findings.append(MobileFinding(
                        id="MOB-STORE-001",
                        category="KEYSTORE_TAINT",
                        cwe="CWE-312",
                        masvs_req="MASVS-STORAGE-1",
                        severity="HIGH",
                        title="Sensitive Data Stored in Unencrypted SharedPreferences",
                        description=f"Key(s) {sensitive_keys} stored in standard SharedPreferences XML without encryption.",
                        location=filename,
                        remediation="Migrate to EncryptedSharedPreferences (AndroidX Security library).",
                    ))

        return findings


class JNIBinaryAuditor:
    """Inspects native C/C++ libraries (.so, Mach-O) for unsafe libc calls and stack canary symbols."""

    UNSAFE_SYMBOLS = {
        "strcpy": "CWE-120: Buffer copy without bounds check",
        "strcat": "CWE-120: Buffer concatenation without bounds check",
        "sprintf": "CWE-134: Unbounded formatted string copy",
        "gets": "CWE-242: Inherently dangerous unbounded stdin read",
    }

    def scan_symbols(self, symbols: List[str], library_name: str = "libnative.so") -> List[MobileFinding]:
        findings: List[MobileFinding] = []

        for sym in symbols:
            clean_sym = sym.strip().lstrip("_")
            if clean_sym in self.UNSAFE_SYMBOLS:
                findings.append(MobileFinding(
                    id="MOB-JNI-001",
                    category="JNI_NATIVE_OVERFLOW",
                    cwe="CWE-120",
                    masvs_req="MASVS-CODE-1",
                    severity="HIGH",
                    title=f"Unsafe C Function in Native Library: {clean_sym}",
                    description=f"Native library '{library_name}' imports '{clean_sym}' ({self.UNSAFE_SYMBOLS[clean_sym]}).",
                    location=f"{library_name}:{clean_sym}",
                    remediation="Replace with bounded alternatives (strncpy, snprintf, fgets) and compile with -fstack-protector-strong.",
                ))

        # Check for stack canary symbol
        has_canary = any("__stack_chk_fail" in s for s in symbols)
        if not has_canary and len(symbols) > 5:
            findings.append(MobileFinding(
                id="MOB-JNI-002",
                category="JNI_NATIVE_OVERFLOW",
                cwe="CWE-693",
                masvs_req="MASVS-CODE-1",
                severity="HIGH",
                title="Missing Stack Canary Protection in JNI Library",
                description=f"Native binary '{library_name}' was compiled without stack canary symbol (__stack_chk_fail).",
                location=library_name,
                remediation="Compile with -fstack-protector-all or -fstack-protector-strong.",
            ))

        return findings


class AntiRootPinningAuditor:
    """Verifies existence and resilience of certificate pinning and anti-tamper protections."""

    ROOT_INDICATORS = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "com.noshufou.android.su",
        "com.topjohnwu.magisk",
        "CydiaSubstrate",
        "/Library/MobileSubstrate",
    ]

    def audit_resilience(self, code_base_strings: Set[str]) -> Dict[str, Any]:
        """Audit whether anti-root indicators and certificate pinning rules are present."""
        found_root_checks = [ind for ind in self.ROOT_INDICATORS if ind in code_base_strings]
        has_pinning = any("CertificatePinner" in s or "pin-set" in s or "hpkp" in s.lower() for s in code_base_strings)

        findings: List[MobileFinding] = []

        if not has_pinning:
            findings.append(MobileFinding(
                id="MOB-PIN-001",
                category="ANTI_TAMPER_PINNING",
                cwe="CWE-295",
                masvs_req="MASVS-NETWORK-2",
                severity="MEDIUM",
                title="Missing SSL/TLS Certificate Pinning",
                description="No OkHttp CertificatePinner or network_security_config pin-set detected.",
                location="NetworkConfiguration",
                remediation="Implement CertificatePinner or Android Network Security Config <pin-set>.",
            ))

        if not found_root_checks:
            findings.append(MobileFinding(
                id="MOB-ROOT-001",
                category="ANTI_TAMPER_PINNING",
                cwe="CWE-693",
                masvs_req="MASVS-RESILIENCE-1",
                severity="LOW",
                title="Absence of Anti-Root / Jailbreak Detection Checks",
                description="Application does not verify integrity of runtime environment against rooted/jailbroken devices.",
                location="SecurityEnforcement",
                remediation="Add root/jailbreak detection and Play Integrity / App Attest verification.",
            ))

        return {
            "has_certificate_pinning": has_pinning,
            "has_root_detection": len(found_root_checks) > 0,
            "detected_root_indicators": found_root_checks,
            "findings": [f.to_dict() for f in findings],
        }


class MobileSecurityEngine:
    """Unified coordinator for mobile package security auditing."""

    def __init__(self) -> None:
        self.manifest_scanner = ManifestScanner()
        self.smali_scanner = SmaliBytecodeScanner()
        self.keystore_tracker = KeystoreTaintTracker()
        self.jni_auditor = JNIBinaryAuditor()
        self.resilience_auditor = AntiRootPinningAuditor()

    def audit_mobile_project(
        self,
        manifest_xml: Optional[str] = None,
        info_plist: Optional[str] = None,
        smali_files: Optional[Dict[str, str]] = None,
        java_sources: Optional[Dict[str, str]] = None,
        jni_symbols: Optional[Dict[str, List[str]]] = None,
        all_strings: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Execute full OWASP MASVS compliance and security assessment."""
        all_findings: List[MobileFinding] = []

        if manifest_xml:
            all_findings.extend(self.manifest_scanner.scan_android_manifest_xml(manifest_xml))

        if info_plist:
            all_findings.extend(self.manifest_scanner.scan_ios_info_plist(info_plist))

        if smali_files:
            for fname, content in smali_files.items():
                all_findings.extend(self.smali_scanner.scan_smali_content(content, fname))

        if java_sources:
            for fname, content in java_sources.items():
                all_findings.extend(self.keystore_tracker.scan_storage_flows(content, fname))

        if jni_symbols:
            for lib_name, symbols in jni_symbols.items():
                all_findings.extend(self.jni_auditor.scan_symbols(symbols, lib_name))

        resilience = self.resilience_auditor.audit_resilience(all_strings or set())
        for f_dict in resilience.get("findings", []):
            all_findings.append(MobileFinding(**f_dict))

        # Aggregate metrics
        severities: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            severities[f.severity] = severities.get(f.severity, 0) + 1

        return {
            "total_findings": len(all_findings),
            "severity_summary": severities,
            "resilience_summary": {
                "has_certificate_pinning": resilience["has_certificate_pinning"],
                "has_root_detection": resilience["has_root_detection"],
            },
            "findings": [f.to_dict() for f in all_findings],
        }
