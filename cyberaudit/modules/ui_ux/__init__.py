"""
CyberAudit UI/UX & Accessibility (a11y) Module
Provides automated audits for usability, responsive ergonomics,
color contrast, and international accessibility standards (WCAG 2.1 / 2.2).
"""

from cyberaudit.modules.ui_ux.accessibility_a11y_scanner import AccessibilityA11yScanner
from cyberaudit.modules.ui_ux.responsive_ergonomics_scanner import ResponsiveErgonomicsScanner
from cyberaudit.modules.ui_ux.contrast_typography_scanner import ContrastTypographyScanner
from cyberaudit.modules.ui_ux.ux_advanced_heuristics_scanner import UxAdvancedHeuristicsScanner
from cyberaudit.modules.ui_ux.wcag22_modern_compliance_scanner import Wcag22ModernComplianceScanner
from cyberaudit.modules.ui_ux.cognitive_ergonomics_scanner import CognitiveErgonomicsScanner

__all__ = [
    "AccessibilityA11yScanner",
    "ResponsiveErgonomicsScanner",
    "ContrastTypographyScanner",
    "UxAdvancedHeuristicsScanner",
    "Wcag22ModernComplianceScanner",
    "CognitiveErgonomicsScanner",
]
