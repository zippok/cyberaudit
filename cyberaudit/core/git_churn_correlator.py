"""
cyberaudit/core/git_churn_correlator.py
=========================================
Behavioral Code Analysis & Git Churn Hotspot Engine — Frontier 2 of 3

Implements CodeScene-style hotspot analysis that crosses:
- Cyclomatic complexity (structural code complexity)
- Git commit churn (frequency of changes over time)
- Author count (bus-factor risk)

into a single HotspotScore metric that identifies the files most likely to
harbour defects and warrant the most security scrutiny.

Formula
-------
    HotspotScore = Complexity × ln(1 + TotalChurn) × √(AuthorCount)

Categories
----------
    CRITICAL_HOTSPOT  — HotspotScore ≥ HIGH_THRESHOLD  (default 30.0)
    MODERATE_HOTSPOT  — HotspotScore ≥ MOD_THRESHOLD   (default 10.0)
    STABLE_LEGACY     — everything else (low churn or low complexity)

Integration
-----------
    GitChurnAnalyzer.adjust_finding_priorities(findings, metrics) escalates
    severity labels for findings in CRITICAL_HOTSPOT files and decorates
    finding dicts with the hotspot metadata.

Safe Fallback
-------------
    If git is not available (no git binary, no .git repo, permission error),
    the engine returns an empty dict and logs a warning — callers always get
    a usable, empty result rather than an exception.
"""

from __future__ import annotations

import math
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Thresholds (tunable)
# ---------------------------------------------------------------------------

CRITICAL_THRESHOLD = 30.0
MODERATE_THRESHOLD = 10.0

# Cyclomatic complexity proxy: count decision keywords per file
_DECISION_PATTERN = re.compile(
    r"\b(if|elif|else|for|while|and|or|except|case|assert|return)\b"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class GitFileMetrics:
    file_path: str
    commit_count: int           # Number of commits touching this file
    author_count: int           # Distinct authors who committed to this file
    churn_additions: int        # Total lines added across all commits
    churn_deletions: int        # Total lines deleted across all commits
    complexity_proxy: int       # Cyclomatic complexity proxy (decision keywords)
    hotspot_score: float        # HotspotScore formula result
    category: str               # CRITICAL_HOTSPOT | MODERATE_HOTSPOT | STABLE_LEGACY

    @property
    def total_churn(self) -> int:
        return self.churn_additions + self.churn_deletions

    def to_dict(self) -> dict:
        return {
            "file_path":         self.file_path,
            "commit_count":      self.commit_count,
            "author_count":      self.author_count,
            "churn_additions":   self.churn_additions,
            "churn_deletions":   self.churn_deletions,
            "total_churn":       self.total_churn,
            "complexity_proxy":  self.complexity_proxy,
            "hotspot_score":     round(self.hotspot_score, 3),
            "category":          self.category,
        }


# ---------------------------------------------------------------------------
# Hotspot scoring
# ---------------------------------------------------------------------------

def _compute_hotspot_score(
    complexity: int,
    total_churn: int,
    author_count: int,
) -> float:
    """
    HotspotScore = Complexity × ln(1 + TotalChurn) × √(AuthorCount)
    """
    return complexity * math.log1p(total_churn) * math.sqrt(max(author_count, 1))


def _categorize(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL_HOTSPOT"
    if score >= MODERATE_THRESHOLD:
        return "MODERATE_HOTSPOT"
    return "STABLE_LEGACY"


# ---------------------------------------------------------------------------
# Complexity proxy (AST-based for Python, keyword-count fallback for others)
# ---------------------------------------------------------------------------

def _measure_complexity(file_path: str) -> int:
    """
    Returns a cyclomatic complexity proxy for a file.
    For Python, counts AST branch nodes (If, For, While, ExceptHandler, Assert).
    For other file types, counts decision keywords.
    """
    try:
        import ast as _ast
        if file_path.endswith(".py"):
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
            try:
                tree = _ast.parse(source)
                count = 0
                for node in _ast.walk(tree):
                    if isinstance(node, (
                        _ast.If, _ast.For, _ast.While, _ast.AsyncFor,
                        _ast.ExceptHandler, _ast.Assert, _ast.With,
                        _ast.AsyncWith, _ast.comprehension,
                    )):
                        count += 1
                    elif isinstance(node, _ast.BoolOp):
                        count += len(node.values) - 1
                return max(count, 1)
            except SyntaxError:
                pass  # Fall through to keyword count
    except ImportError:
        pass

    # Generic keyword count for non-Python or unparseable files
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        return max(len(_DECISION_PATTERN.findall(source)), 1)
    except OSError:
        return 1


# ---------------------------------------------------------------------------
# Git log parsing
# ---------------------------------------------------------------------------

def _run_git_log(repo_path: str, since_days: int) -> Optional[str]:
    """
    Runs git log --numstat and returns raw output string.
    Returns None if git is unavailable or repo has no commits.

    Output format per commit:
        <hash>|<author_email>|<subject>
        <additions>\t<deletions>\t<file_path>
        ...
        (blank line)
    """
    since_arg = f"--since={since_days} days ago"
    cmd = [
        "git", "-C", repo_path,
        "log",
        "--numstat",
        "--pretty=format:%H|%ae|%s",
        since_arg,
        "--",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _parse_git_log(raw: str) -> Dict[str, dict]:
    """
    Parses the output of git log --numstat --pretty=format:%H|%ae|%s.
    Returns a dict: file_path → {commit_hashes, authors, additions, deletions}
    """
    file_stats: Dict[str, dict] = {}
    current_hash: Optional[str] = None
    current_author: Optional[str] = None

    for line in raw.splitlines():
        line = line.rstrip()
        if not line:
            current_hash = None
            current_author = None
            continue

        # Commit header line: hash|email|subject
        if "|" in line and len(line.split("|")) >= 2:
            parts = line.split("|", 2)
            if len(parts[0]) == 40 or len(parts[0]) == 64:  # SHA-1 or SHA-256
                current_hash = parts[0]
                current_author = parts[1]
                continue

        # numstat line: additions\tdeletions\tfilepath
        if "\t" in line and current_hash is not None:
            cols = line.split("\t", 2)
            if len(cols) == 3:
                add_str, del_str, fpath = cols
                try:
                    adds = int(add_str)
                    dels = int(del_str)
                except ValueError:
                    # Binary files show "-" instead of numbers
                    adds, dels = 0, 0

                if fpath not in file_stats:
                    file_stats[fpath] = {
                        "commits": set(),
                        "authors": set(),
                        "additions": 0,
                        "deletions": 0,
                    }
                file_stats[fpath]["commits"].add(current_hash)
                if current_author:
                    file_stats[fpath]["authors"].add(current_author)
                file_stats[fpath]["additions"] += adds
                file_stats[fpath]["deletions"] += dels

    return file_stats


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class GitChurnAnalyzer:
    """
    Analyzes git churn and code complexity to produce hotspot scores.

    Usage
    -----
    analyzer = GitChurnAnalyzer(repo_path=".")
    metrics = analyzer.analyze(since_days=180)
    for path, m in sorted(metrics.items(), key=lambda x: -x[1].hotspot_score):
        print(m.to_dict())
    """

    def __init__(self, repo_path: str = "."):
        self.repo_path = os.path.abspath(repo_path)

    def analyze(self, since_days: int = 180) -> Dict[str, GitFileMetrics]:
        """
        Analyze git history and return a dict of file_path → GitFileMetrics.
        Returns an empty dict if git is not available.

        Parameters
        ----------
        since_days : int
            How many days of git history to consider.
        """
        raw = _run_git_log(self.repo_path, since_days)
        if not raw:
            return {}

        file_stats = _parse_git_log(raw)
        metrics: Dict[str, GitFileMetrics] = {}

        for rel_path, stats in file_stats.items():
            # Resolve to absolute path
            abs_path = os.path.join(self.repo_path, rel_path)
            commit_count = len(stats["commits"])
            author_count = len(stats["authors"])
            additions = stats["additions"]
            deletions = stats["deletions"]
            total_churn = additions + deletions

            # Measure complexity (only if file exists on disk)
            if os.path.isfile(abs_path):
                complexity = _measure_complexity(abs_path)
            else:
                # File was renamed/deleted — use a minimum proxy
                complexity = 1

            score = _compute_hotspot_score(complexity, total_churn, author_count)
            category = _categorize(score)

            metrics[rel_path] = GitFileMetrics(
                file_path=rel_path,
                commit_count=commit_count,
                author_count=author_count,
                churn_additions=additions,
                churn_deletions=deletions,
                complexity_proxy=complexity,
                hotspot_score=score,
                category=category,
            )

        return metrics

    def adjust_finding_priorities(
        self,
        findings: List[Dict],
        metrics: Dict[str, GitFileMetrics],
    ) -> List[Dict]:
        """
        Escalate or annotate findings based on hotspot category.

        Rules:
        - CRITICAL_HOTSPOT: severity HIGH → CRITICAL, add hotspot badge
        - MODERATE_HOTSPOT: add hotspot badge, no severity change
        - STABLE_LEGACY:    no change

        Parameters
        ----------
        findings : list of finding dicts (must have 'file_path' and 'severity' keys)
        metrics  : output of analyze()

        Returns
        -------
        Modified findings list (in-place + returned for convenience).
        """
        SEVERITY_ESCALATION = {
            "LOW":    "MEDIUM",
            "MEDIUM": "HIGH",
            "HIGH":   "CRITICAL",
        }

        for finding in findings:
            fpath = finding.get("file_path", "")
            # Try both the full path and just the relative portion
            m = metrics.get(fpath) or metrics.get(os.path.basename(fpath))
            if m is None:
                continue

            finding["hotspot_category"] = m.category
            finding["hotspot_score"] = round(m.hotspot_score, 3)

            if m.category == "CRITICAL_HOTSPOT":
                old_sev = finding.get("severity", "")
                finding["severity"] = SEVERITY_ESCALATION.get(old_sev, old_sev)
                finding["hotspot_escalated"] = True
            elif m.category == "MODERATE_HOTSPOT":
                finding["hotspot_escalated"] = False

        return findings

    @staticmethod
    def compute_score(
        complexity: int,
        total_churn: int,
        author_count: int,
    ) -> float:
        """Expose the scoring formula for external use and tests."""
        return _compute_hotspot_score(complexity, total_churn, author_count)
