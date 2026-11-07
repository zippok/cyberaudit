"""
Base Scanner Interface
All audit and detection modules inherit from this class to ensure
modularity, plug-and-play architecture, and uniform reporting.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
import fnmatch
from cyberaudit.core.models import Finding, Pillar


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners in CyberAudit Suite.
    """

    def __init__(self):
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this scanner."""
        pass

    @property
    @abstractmethod
    def pillar(self) -> Pillar:
        """The cybersecurity pillar this scanner belongs to."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief summary of what this scanner checks."""
        pass

    @property
    def file_extensions(self) -> List[str]:
        """
        List of file extensions to target, e.g. ['.py', '.ps1', '.json'].
        If empty, scanner receives all non-binary text files.
        """
        return []

    @property
    def file_patterns(self) -> List[str]:
        """
        Glob patterns to match, e.g. ['Dockerfile*', '*.conf', '*access*.log'].
        """
        return []

    def should_scan(self, file_path: str) -> bool:
        """
        Determines whether the given file should be scanned by this module.
        """
        # If no filters provided, scan all text files
        if not self.file_extensions and not self.file_patterns:
            return True

        normalized_path = file_path.replace("\\", "/").lower()
        file_name = normalized_path.split("/")[-1]

        # Check extensions
        for ext in self.file_extensions:
            if file_name.endswith(ext.lower()):
                return True

        # Check glob patterns
        for pattern in self.file_patterns:
            if fnmatch.fnmatch(file_name, pattern.lower()) or fnmatch.fnmatch(normalized_path, pattern.lower()):
                return True

        return False

    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Scans a single file's content and returns a list of Findings.
        """
        pass

    def scan_directory(self, dir_path: str) -> List[Finding]:
        """
        Optional directory-level scan (e.g. cross-file analysis, missing files, structure checks).
        Default returns empty list.
        """
        return []
