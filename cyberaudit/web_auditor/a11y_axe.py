"""
CyberAudit Accessibility (A11y) & Core Web Vitals Auditor
Injects axe-core into the live DOM and captures WCAG 2.1 AA/AAA compliance,
as well as browser performance metrics via PerformanceObserver.
"""

from typing import List, Dict, Any, Optional
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


AXE_CORE_CDN_URL = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.9.0/axe.min.js"


class A11yAndVitalsAuditor:
    """Audits DOM accessibility and UX ergonomics."""

    def parse_axe_violations(self, axe_results: Dict[str, Any], url: str) -> List[Finding]:
        """
        Translates raw axe-core violation JSON into canonical CyberAudit Finding models.
        """
        findings: List[Finding] = []
        violations = axe_results.get("violations", [])

        for v in violations:
            rule_id = v.get("id", "generic-a11y")
            impact = v.get("impact", "minor")
            help_text = v.get("help", "Problema de accesibilidad detectado")
            desc = v.get("description", "")
            help_url = v.get("helpUrl", "https://dequeuniversity.com/rules/axe/")
            nodes = v.get("nodes", [])
            node_count = len(nodes)

            # Sample CSS selectors
            selectors = [n.get("target", [""])[0] for n in nodes[:3] if n.get("target")]
            sel_str = f" Elementos afectados ({node_count}): {', '.join(selectors)}" if selectors else ""

            # Map axe impact to Severity
            if impact in ("critical", "serious"):
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Extract tags (e.g. wcag2aa, wcag143)
            tags = v.get("tags", [])
            wcag_tags = [t for t in tags if "wcag" in t]
            wcag_label = f" [{', '.join(wcag_tags)}]" if wcag_tags else ""

            findings.append(Finding(
                id=f"A11Y-{rule_id.upper()}",
                title=f"Accesibilidad (WCAG): {help_text}{wcag_label}",
                description=f"{desc}.{sel_str}",
                severity=severity,
                pillar=Pillar.UI_UX,
                scanner_name="a11y_axe",
                file_path=url,
                cwe_id="CWE-1375",
                remediation=f"Ajustar el marcado HTML/CSS según las directivas WCAG 2.1: {help_url}",
                confidence="HIGH",
            ))

        return findings

    def parse_web_vitals(self, vitals: Dict[str, Any], url: str) -> List[Finding]:
        """
        Audits measured Core Web Vitals (LCP, CLS, FCP).
        """
        findings: List[Finding] = []
        cls_val = vitals.get("cls")
        lcp_val = vitals.get("lcp")  # Missing observations are not zeroes.

        # Cumulative Layout Shift (CLS) > 0.25 is Poor, > 0.1 Needs Improvement
        if cls_val is not None and cls_val > 0.25:
            findings.append(Finding(
                id="UX-CLS-POOR",
                title=f"Cumulative Layout Shift Crítico (CLS: {cls_val:.3f})",
                description=f"La página sufre desplazamientos acumulados severos de diseño (CLS > 0.25), degradando la experiencia de usuario y accesibilidad motora.",
                severity=Severity.LOW,
                pillar=Pillar.UI_UX,
                scanner_name="web_vitals",
                file_path=url,
                cwe_id="CWE-1375",
                remediation="Definir dimensiones fijas (width/height o aspect-ratio) para imágenes, banners y componentes asíncronos.",
                confidence="HIGH",
            ))

        # Largest Contentful Paint (LCP) > 4000ms is Poor
        if lcp_val is not None and lcp_val > 4000:
            findings.append(Finding(
                id="UX-LCP-SLOW",
                title=f"Velocidad de Carga Crítica (LCP: {lcp_val/1000:.2f}s)",
                description=f"El Largest Contentful Paint excede 4.0 segundos, indicando recursos bloqueantes o imágenes sin optimizar.",
                severity=Severity.INFO,
                pillar=Pillar.SOFTWARE_QA,
                scanner_name="web_vitals",
                file_path=url,
                remediation="Optimizar imágenes con formatos modernos (WebP/AVIF) y utilizar compresión gzip/brotli.",
                confidence="HIGH",
            ))

        return findings
