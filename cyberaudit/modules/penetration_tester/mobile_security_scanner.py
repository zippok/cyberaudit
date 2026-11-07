"""
Mobile Application Security & OWASP MASVS Scanner
Audits mobile and hybrid apps (Android / Capacitor / Cordova / React Native / Electron mobile)
for security weaknesses based on OWASP Mobile Application Security Verification Standard (MASVS v2)
and MASTG.
"""

import os
import re
from typing import List, Set
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class MobileSecurityScanner(BaseScanner):
    __test__ = False  # Avoid pytest collector discovering this as a test class

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Mobile Application Security & OWASP MASVS Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return "Detects Android/mobile vulnerabilities including tapjacking, insecure WebViews, exported components without permissions, cleartext storage, and network cleartext traffic according to OWASP MASVS."

    @property
    def supported_extensions(self) -> Set[str]:
        return {".xml", ".java", ".kt", ".js", ".ts", ".jsx", ".tsx", ".html", ".gradle"}

    def should_scan(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        basename = os.path.basename(file_path).lower()
        if basename == "androidmanifest.xml":
            return True
        return ext in self.supported_extensions

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        basename = os.path.basename(file_path).lower()

        # 1. AndroidManifest.xml specific checks
        if basename == "androidmanifest.xml" or file_path.endswith(".xml"):
            findings.extend(self._scan_manifest(file_path, content))

        # 2. Tapjacking / Screen Overlay vulnerability (code or layout XML)
        findings.extend(self._scan_tapjacking(file_path, content))

        # 3. Insecure WebView configurations
        findings.extend(self._scan_webviews(file_path, content))

        # 4. Insecure Local Storage & Cleartext Secrets
        findings.extend(self._scan_storage(file_path, content))

        # 5. Dangerous World Readable/Writable Modes
        findings.extend(self._scan_file_modes(file_path, content))

        return findings

    def _scan_manifest(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Check usesCleartextTraffic="true"
        for idx, line in enumerate(lines, 1):
            if re.search(r'android:usesCleartextTraffic\s*=\s*["\']true["\']', line, re.IGNORECASE):
                findings.append(Finding(
                    id="MASVS-NETWORK-CLEARTEXT",
                    title="Android Cleartext HTTP Traffic Permitted (usesCleartextTraffic=true)",
                    description="The application explicitly enables cleartext HTTP transmission in its AndroidManifest.xml, allowing network adversaries to intercept sensitive communications, sessions, or credentials via Man-in-the-Middle (MitM) attacks.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Set android:usesCleartextTraffic='false' and enforce a strict Network Security Configuration XML with TLS 1.3/1.2 and certificate pinning where applicable.",
                    mitre_id="T1439",
                    mitre_tactic="Collection",
                    mitre_technique="Network Traffic Capture",
                    cwe_id="CWE-319",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"OWASP MASVS": "MASVS-NETWORK-1", "PCI-DSS": "Requirement 4.1", "NIST SP 800-53": "SC-8"},
                ))

            # Check debuggable="true" in manifest
            if re.search(r'android:debuggable\s*=\s*["\']true["\']', line, re.IGNORECASE):
                findings.append(Finding(
                    id="MASVS-RESILIENCE-DEBUGGABLE",
                    title="Production Android Package Marked as Debuggable (android:debuggable=true)",
                    description="The application manifest marks the build as debuggable, allowing arbitrary remote debugging, memory dumping, and code injection via JDWP / ADB without root privileges.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Ensure android:debuggable is false or omitted in release builds via Gradle build variants (debuggable false).",
                    mitre_id="T1414",
                    mitre_tactic="Discovery",
                    mitre_technique="Software Discovery: Debugger Attached",
                    cwe_id="CWE-215",
                    stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                    compliance_controls={"OWASP MASVS": "MASVS-RESILIENCE-1"},
                ))

        # Check exported components without permissions
        component_pattern = re.compile(r'<(activity|service|receiver|provider)\b([^>]*?)>', re.IGNORECASE | re.DOTALL)
        for match in component_pattern.finditer(content):
            comp_type = match.group(1).lower()
            tag_body = match.group(2)
            if re.search(r'android:exported\s*=\s*["\']true["\']', tag_body, re.IGNORECASE):
                if not re.search(r'android:permission\s*=', tag_body, re.IGNORECASE):
                    # Check if it's the main launcher activity (which must be exported)
                    if 'android.intent.action.MAIN' in tag_body and 'android.intent.category.LAUNCHER' in tag_body:
                        continue
                    start_char = match.start()
                    line_num = content.count("\n", 0, start_char) + 1
                    findings.append(Finding(
                        id=f"MASVS-PLATFORM-EXPORTED-{comp_type.upper()}",
                        title=f"Android {comp_type.capitalize()} Component Exported Without Permission Protection",
                        description=f"An Android <{comp_type}> is exported (android:exported='true') to all applications on the device without requiring an android:permission. Any malicious third-party app installed on the same device can invoke or send intents to this component.",
                        severity=Severity.HIGH,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=match.group(0)[:200],
                        remediation=f"If third-party access is not required, set android:exported='false'. If cross-app communication is needed, protect the component with a custom signature permission (android:protectionLevel='signature').",
                        mitre_id="T1626",
                        mitre_tactic="Lateral Movement",
                        mitre_technique="Use Alternate Authentication Material: Application Component Hijacking",
                        cwe_id="CWE-926",
                        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                        compliance_controls={"OWASP MASVS": "MASVS-PLATFORM-1"},
                    ))

        return findings

    def _scan_tapjacking(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            # XML check
            if re.search(r'android:filterTouchesWhenObscured\s*=\s*["\']false["\']', line, re.IGNORECASE):
                findings.append(Finding(
                    id="MASVS-PLATFORM-TAPJACKING-DISABLED",
                    title="Tapjacking / Screen Overlay Protection Explicitly Disabled",
                    description="The UI element or activity explicitly sets android:filterTouchesWhenObscured='false', allowing malicious overlay applications (e.g. accessibility service overlays, toast windows, TYPE_APPLICATION_OVERLAY) to hijack user touches or trick users into clicking authorization buttons blindly.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Set android:filterTouchesWhenObscured='true' or call setFilterTouchesWhenObscured(true) on sensitive click targets, confirmation dialogs, and credential inputs.",
                    mitre_id="T1411",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="Input Injection: Tapjacking / Screen Overlay",
                    cwe_id="CWE-1021",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"OWASP MASVS": "MASVS-PLATFORM-2"},
                ))
            # Code check
            if re.search(r'\.setFilterTouchesWhenObscured\s*\(\s*false\s*\)', line):
                findings.append(Finding(
                    id="MASVS-PLATFORM-TAPJACKING-DISABLED",
                    title="Tapjacking / Overlay Filtering Explicitly Disabled via API",
                    description="The code calls setFilterTouchesWhenObscured(false), leaving the component vulnerable to clickjacking and overlay abuse.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Enable touch filtering with setFilterTouchesWhenObscured(true) for all security-sensitive operations.",
                    mitre_id="T1411",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="Input Injection: Tapjacking",
                    cwe_id="CWE-1021",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"OWASP MASVS": "MASVS-PLATFORM-2"},
                ))

        return findings

    def _scan_webviews(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        has_js_enabled = False
        has_file_access = False
        js_line = 0
        file_line = 0

        for idx, line in enumerate(lines, 1):
            if re.search(r'\.setJavaScriptEnabled\s*\(\s*true\s*\)', line):
                has_js_enabled = True
                js_line = idx

            if re.search(r'\.(setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs)\s*\(\s*true\s*\)', line):
                has_file_access = True
                file_line = idx
                findings.append(Finding(
                    id="MASVS-PLATFORM-WEBVIEW-FILE-ACCESS",
                    title="Insecure WebView Local File Access Enabled",
                    description="The WebView explicitly enables local file scheme access (setAllowFileAccess / setAllowUniversalAccessFromFileURLs). If the WebView loads external content or untrusted URLs, an attacker can read private app data, databases, and keystores via file:// schemes or XSS.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Disable local file scheme access with setAllowFileAccess(false) and setAllowUniversalAccessFromFileURLs(false). Use androidx.webkit.WebViewAssetLoader to serve local assets safely over virtual https:// domains.",
                    mitre_id="T1203",
                    mitre_tactic="Execution",
                    mitre_technique="Exploitation for Client Execution",
                    cwe_id="CWE-749",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"OWASP MASVS": "MASVS-CODE-4"},
                ))

        if has_js_enabled and has_file_access:
            findings.append(Finding(
                id="MASVS-PLATFORM-WEBVIEW-XSS-EXPLOITABLE",
                title="Critical WebView Configuration: JavaScript Combined with File Access",
                description="The WebView enables both JavaScript execution and local file access simultaneously. Any Cross-Site Scripting (XSS) in loaded pages or Man-in-the-Middle injection can immediately escalate to local arbitrary file exfiltration from the app sandbox.",
                severity=Severity.CRITICAL,
                pillar=self.pillar,
                scanner_name=self.name,
                file_path=file_path,
                line_number=js_line or file_line,
                code_snippet=f"JavaScript enabled (L{js_line}) + Local file access enabled (L{file_line})",
                remediation="Disable file access entirely. If external content must be rendered, isolate it in a sandboxed iframe or separate restricted WebView process.",
                mitre_id="T1059",
                mitre_tactic="Execution",
                mitre_technique="Command and Scripting Interpreter: JavaScript",
                cwe_id="CWE-79",
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE.value,
                compliance_controls={"OWASP MASVS": "MASVS-CODE-4"},
            ))

        return findings

    def _scan_storage(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Cleartext sensitive keys stored in SharedPreferences
        pref_pattern = re.compile(r'(\.putString|\.putLong|\.putInt|\.encode)\s*\(\s*["\'](password|token|secret|auth|apikey|api_key|access_token|refresh_token|private_key|pin|credential)["\']', re.IGNORECASE)
        ext_storage_pattern = re.compile(r'(Environment\.getExternalStorageDirectory|getExternalFilesDir|getExternalStoragePublicDirectory)\s*\(', re.IGNORECASE)

        for idx, line in enumerate(lines, 1):
            match_pref = pref_pattern.search(line)
            if match_pref:
                key_name = match_pref.group(2)
                findings.append(Finding(
                    id="MASVS-STORAGE-CLEARTEXT-PREFS",
                    title=f"Sensitive Credential '{key_name}' Stored in Unencrypted Shared Preferences",
                    description=f"The application stores sensitive authentication material ('{key_name}') in standard SharedPreferences. In rooted devices, physical backups, or via local vulnerabilities, this data can be read in plain text.",
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Migrate to EncryptedSharedPreferences (from AndroidX Security Crypto library) backed by the hardware-backed Android KeyStore (MasterKey), or use Secure Keystore encryption.",
                    mitre_id="T1409",
                    mitre_tactic="Credential Access",
                    mitre_technique="Access Stored Application Data: Unencrypted Credentials",
                    cwe_id="CWE-312",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={"OWASP MASVS": "MASVS-STORAGE-1", "PCI-DSS": "Requirement 3.4", "ISO 27001": "A.8.24"},
                ))

            if ext_storage_pattern.search(line):
                findings.append(Finding(
                    id="MASVS-STORAGE-EXTERNAL-STORAGE",
                    title="Storage of Application Data in Insecure External Storage Directory",
                    description="The application writes or accesses files in external shared storage (SD card / ExternalStorageDirectory). Files in shared storage can be read, tampered with, or infected by any other app holding external storage permissions.",
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Store private app data in internal app storage (context.getFilesDir() or context.getCacheDir()). Use Android Scoped Storage and MediaStore APIs if sharing files with the user.",
                    mitre_id="T1409",
                    mitre_tactic="Collection",
                    mitre_technique="Data from Local System: External Storage",
                    cwe_id="CWE-921",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"OWASP MASVS": "MASVS-STORAGE-2"},
                ))

        return findings

    def _scan_file_modes(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            if re.search(r'\b(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\b', line):
                findings.append(Finding(
                    id="MASVS-STORAGE-WORLD-READABLE",
                    title="Use of Insecure MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE Flag",
                    description="The application creates or opens files with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE. These modes are deprecated by Google and expose the app's private sandbox files to read and write tampering from any third-party app on the device.",
                    severity=Severity.CRITICAL,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=idx,
                    code_snippet=line.strip(),
                    remediation="Use MODE_PRIVATE (default) for local app files and employ Android Keystore / EncryptedFile if encryption at rest is needed.",
                    mitre_id="T1409",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="File and Directory Permissions Modification",
                    cwe_id="CWE-732",
                    stride_category=StrideCategory.TAMPERING.value,
                    compliance_controls={"OWASP MASVS": "MASVS-STORAGE-1"},
                ))

        return findings
