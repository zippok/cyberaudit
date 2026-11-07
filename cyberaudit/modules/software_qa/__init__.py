"""
Software QA & Code Quality Audit Module
Contains specialized static analysis engines for:
- Code Quality, exception hygiene, and maintainability (CodeQualityScanner)
- OS resource and memory leak detection (ResourceLeakScanner)
- Test suite existence, health, and coverage auditing (TestCoverageAuditor)
- Concurrency, async race conditions, and thread safety (ConcurrencyRaceScanner)
"""

from cyberaudit.modules.software_qa.code_quality_scanner import CodeQualityScanner
from cyberaudit.modules.software_qa.resource_leak_scanner import ResourceLeakScanner
from cyberaudit.modules.software_qa.test_coverage_auditor import TestCoverageAuditor
from cyberaudit.modules.software_qa.concurrency_race_scanner import ConcurrencyRaceScanner
from cyberaudit.modules.software_qa.complexity_maintainability_scanner import ComplexityMaintainabilityScanner
from cyberaudit.modules.software_qa.resilience_performance_scanner import ResiliencePerformanceScanner
from cyberaudit.modules.software_qa.clean_code_scanner import CleanCodeBestPracticesScanner
from cyberaudit.modules.software_qa.flaky_test_lifecycle_scanner import FlakyTestLifecycleScanner
from cyberaudit.modules.software_qa.defensive_contract_scanner import DefensiveContractScanner
from cyberaudit.modules.software_qa.db_pool_scanner import DatabasePoolExhaustionScanner
from cyberaudit.modules.software_qa.openapi_diff_scanner import OpenApiBreakingChangesScanner
from cyberaudit.modules.software_qa.event_leak_scanner import EventListenerLeakScanner

__all__ = [
    "CodeQualityScanner",
    "ResourceLeakScanner",
    "TestCoverageAuditor",
    "ConcurrencyRaceScanner",
    "ComplexityMaintainabilityScanner",
    "ResiliencePerformanceScanner",
    "CleanCodeBestPracticesScanner",
    "FlakyTestLifecycleScanner",
    "DefensiveContractScanner",
    "DatabasePoolExhaustionScanner",
    "OpenApiBreakingChangesScanner",
    "EventListenerLeakScanner",
]

