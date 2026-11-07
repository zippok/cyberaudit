"""
GitHub PR Review Bot & Branch Manager.

Provides automated inline PR review comments for invariant violations
and autonomous fix branch creation via the GitHub REST API.

Authentication: Uses GITHUB_TOKEN environment variable (available
natively in GitHub Actions) or CYBERAUDIT_GITHUB_TOKEN.
"""

import os
import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger("cyberaudit.integrations.github_pr_reviewer")


@dataclass
class PRReviewComment:
    """An inline review comment on a specific file and line in a PR diff."""
    path: str
    line: int
    body: str
    side: str = "RIGHT"  # RIGHT = new code side


@dataclass
class PRReviewResult:
    """Result of submitting a PR review."""
    success: bool
    review_id: Optional[int] = None
    pr_number: Optional[int] = None
    comments_posted: int = 0
    error: Optional[str] = None


class GitHubPRReviewer:
    """Posts inline review comments on GitHub Pull Requests.
    
    For each invariant violation found in changed files, posts a
    REQUEST_CHANGES review with inline comments at the exact diff line.
    If no violations: posts APPROVE with a compliance badge.
    """

    API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None):
        """
        Args:
            token: GitHub API token. Falls back to GITHUB_TOKEN or CYBERAUDIT_GITHUB_TOKEN env.
            repo: Repository in 'owner/repo' format. Falls back to GITHUB_REPOSITORY env.
        """
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("CYBERAUDIT_GITHUB_TOKEN", "")
        self.repo = repo or os.environ.get("GITHUB_REPOSITORY", "")

    def _api_request(self, method: str, endpoint: str,
                     data: Optional[Dict] = None) -> Tuple[int, Dict]:
        """Makes an authenticated request to the GitHub API."""
        url = f"{self.API_BASE}{endpoint}"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "CyberAudit-PRReviewer/1.0"
        }

        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))
                return resp.status, response_data
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            logger.error("GitHub API error %d: %s", e.code, error_body)
            return e.code, {"error": error_body}
        except Exception as e:
            logger.error("GitHub API request failed: %s", e)
            return 0, {"error": str(e)}

    def review_pr(self, pr_number: int, violations: List[Dict],
                  compliance_score: float = 100.0) -> PRReviewResult:
        """Posts a review on a Pull Request with inline violation comments.
        
        Args:
            pr_number: The PR number to review.
            violations: List of InvariantViolation dicts.
            compliance_score: Overall compliance percentage.
            
        Returns:
            PRReviewResult with success status and posted comment count.
        """
        if not self.token or not self.repo:
            return PRReviewResult(
                success=False,
                error="Missing GITHUB_TOKEN or GITHUB_REPOSITORY. "
                      "Set these environment variables or pass them to the constructor."
            )

        # Build inline comments for violations in PR diff
        comments = []
        for v in violations:
            comment_body = (
                f"⚠️ **{v.get('rule_id', 'INV-???')}** — {v.get('rule_name', 'Invariant Violation')}\n\n"
                f"**Tipo:** `{v.get('violation_type', 'UNKNOWN')}`\n"
                f"**Severidad:** `{v.get('severity', 'HIGH')}`\n\n"
                f"{v.get('detail', '')}\n\n"
                f"```python\n{v.get('ast_slice', '')}\n```\n\n"
                f"📋 Definido en `.audit-rules.yaml` — Categoría de remediación: "
                f"`{v.get('remediation_category', 'manual_review')}`"
            )
            comments.append(PRReviewComment(
                path=v.get("file_path", ""),
                line=v.get("line_number", 1),
                body=comment_body,
            ))

        # Determine review event type
        if violations:
            event = "REQUEST_CHANGES"
            summary = (
                f"## ⚠️ CyberAudit Invariant Guard — {len(violations)} violación(es)\n\n"
                f"**Compliance Score:** `{compliance_score:.1f}%`\n\n"
                f"| Regla | Archivo | Línea | Tipo |\n"
                f"|-------|---------|-------|------|\n"
            )
            for v in violations:
                summary += (
                    f"| `{v.get('rule_id', '')}` | `{v.get('file_path', '')}` | "
                    f"{v.get('line_number', '')} | `{v.get('violation_type', '')}` |\n"
                )
            summary += (
                f"\n> Resuelve las violaciones y re-ejecuta la auditoría. "
                f"Consulta `.audit-rules.yaml` para detalles de cada contrato."
            )
        else:
            event = "APPROVE"
            summary = (
                f"## ✅ CyberAudit Invariant Guard — Compliance 100%\n\n"
                f"Todos los contratos de invariantes satisfechos. "
                f"Call Graphs verificados deterministamente via AST."
            )

        # Build review payload
        review_data: Dict[str, Any] = {
            "event": event,
            "body": summary,
        }
        if comments:
            review_data["comments"] = [
                {"path": c.path, "line": c.line, "body": c.body, "side": c.side}
                for c in comments
            ]

        endpoint = f"/repos/{self.repo}/pulls/{pr_number}/reviews"
        status_code, response = self._api_request("POST", endpoint, review_data)

        if 200 <= status_code < 300:
            return PRReviewResult(
                success=True,
                review_id=response.get("id"),
                pr_number=pr_number,
                comments_posted=len(comments),
            )
        else:
            return PRReviewResult(
                success=False,
                pr_number=pr_number,
                error=f"HTTP {status_code}: {response.get('error', 'Unknown error')}"
            )


class GitHubBranchManager:
    """Creates fix branches and opens Pull Requests via the GitHub API.
    
    Used by the Autonomous Remediation Runner (Phase 5) to push
    verified patches as real PRs instead of just generating markdown.
    """

    API_BASE = "https://api.github.com"

    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("CYBERAUDIT_GITHUB_TOKEN", "")
        self.repo = repo or os.environ.get("GITHUB_REPOSITORY", "")

    def _api_request(self, method: str, endpoint: str,
                     data: Optional[Dict] = None) -> Tuple[int, Dict]:
        """Makes an authenticated request to the GitHub API."""
        url = f"{self.API_BASE}{endpoint}"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "CyberAudit-BranchManager/1.0"
        }
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return e.code, {"error": error_body}
        except Exception as e:
            return 0, {"error": str(e)}

    def create_fix_branch(self, rule_id: str, base_branch: str = "main") -> Optional[str]:
        """Creates a fix branch named fix/cyberaudit-{rule_id}-{timestamp}.
        
        Returns the branch name if successful, None otherwise.
        """
        if not self.token or not self.repo:
            logger.warning("Cannot create branch: missing GITHUB_TOKEN or GITHUB_REPOSITORY")
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        branch_name = f"fix/cyberaudit-{rule_id.lower()}-{timestamp}"

        # Get base branch SHA
        status, data = self._api_request(
            "GET", f"/repos/{self.repo}/git/refs/heads/{base_branch}"
        )
        if status != 200:
            logger.error("Failed to get base branch SHA: %s", data)
            return None

        base_sha = data.get("object", {}).get("sha", "")
        if not base_sha:
            return None

        # Create new branch
        status, data = self._api_request(
            "POST", f"/repos/{self.repo}/git/refs",
            {"ref": f"refs/heads/{branch_name}", "sha": base_sha}
        )
        if 200 <= status < 300:
            logger.info("Created fix branch: %s", branch_name)
            return branch_name

        logger.error("Failed to create branch: %s", data)
        return None

    def open_pull_request(self, branch: str, title: str,
                          body: str, base: str = "main") -> Optional[int]:
        """Opens a Pull Request from the fix branch to the base branch.
        
        Returns PR number if successful, None otherwise.
        """
        if not self.token or not self.repo:
            return None

        status, data = self._api_request(
            "POST", f"/repos/{self.repo}/pulls",
            {
                "title": title,
                "body": body,
                "head": branch,
                "base": base,
                "maintainer_can_modify": True,
            }
        )
        if 200 <= status < 300:
            pr_number = data.get("number")
            logger.info("Opened PR #%d: %s", pr_number, title)
            return pr_number

        logger.error("Failed to open PR: %s", data)
        return None
