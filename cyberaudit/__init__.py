"""
CyberAudit Suite - Enterprise Cybersecurity Auditing & Quality Assurance Platform
"""
import os
from pathlib import Path

__version__ = "1.0.0"

# Ensure local Playwright browsers are found if available
_root_dir = Path(__file__).resolve().parent.parent
_local_playwright = _root_dir / ".playwright"
if _local_playwright.is_dir() and not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(_local_playwright)

