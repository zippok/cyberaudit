"""Unified Attack Graph & Cloud Infrastructure Topology Engine.

Correlates application-layer SAST findings with container runtime specs,
Kubernetes NetworkPolicies, cloud IAM permissions, and critical assets.
Evaluates supplied configuration and telemetry. Does not collect live eBPF events
or establish network reachability by itself.
"""
from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cyberaudit.infra.cloud_graph")


class NodeType(str, enum.Enum):
    """Types of nodes in the unified infrastructure and code attack graph."""
    CODE_VULN = "code_vuln"
    CONTAINER = "container"
    NETWORK_POLICY = "network_policy"
    IAM_ROLE = "iam_role"
    CRITICAL_ASSET = "critical_asset"
    HOST_CONFIG = "host_config"


class AttackPathStatus(str, enum.Enum):
    """Status of an analyzed attack path."""
    VIABLE_ATTACK_PATH = "VIABLE_ATTACK_PATH"
    MITIGATED_BY_TOPOLOGY = "MITIGATED_BY_TOPOLOGY"
    BLOCKED_BY_IAM = "BLOCKED_BY_IAM"
    ISOLATED_BY_NETWORK = "ISOLATED_BY_NETWORK"


@dataclass
class GraphNode:
    """Represents a node in the attack graph."""
    id: str
    name: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "node_type": self.node_type.value,
            "properties": self.properties,
        }


@dataclass
class GraphEdge:
    """Represents a directional relationship between two nodes."""
    source_id: str
    target_id: str
    relation: str  # e.g., 'RUNS_IN', 'BOUND_TO', 'CAN_CONNECT_TO', 'ASSUMES_ROLE', 'TARGETS'
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "properties": self.properties,
        }


@dataclass
class AttackPath:
    """Represents a path from an entrypoint / vulnerability to a critical asset."""
    path_nodes: List[str]
    description: str
    severity: str
    status: AttackPathStatus
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_nodes": self.path_nodes,
            "description": self.description,
            "severity": self.severity,
            "status": self.status.value,
            "remediation_steps": self.remediation_steps,
        }


class UnifiedAttackGraph:
    """Synthesizes code-level security findings with infrastructure topology."""

    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}
        self.adjacency: Dict[str, List[GraphEdge]] = {}

    def add_node(self, node: GraphNode) -> None:
        """Register a node in the graph."""
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge between nodes."""
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            raise ValueError(f"Both nodes ({edge.source_id}, {edge.target_id}) must exist in the graph.")
        self.adjacency[edge.source_id].append(edge)

    def find_all_paths(
        self, start_id: str, target_id: str, visited: Optional[Set[str]] = None
    ) -> List[List[str]]:
        """Find all acyclic directed paths between start and target."""
        if visited is None:
            visited = set()
        if start_id == target_id:
            return [[start_id]]
        if start_id not in self.nodes or target_id not in self.nodes:
            return []

        paths: List[List[str]] = []
        visited.add(start_id)

        for edge in self.adjacency.get(start_id, []):
            nxt = edge.target_id
            if nxt not in visited:
                subpaths = self.find_all_paths(nxt, target_id, visited.copy())
                for sp in subpaths:
                    paths.append([start_id] + sp)

        return paths

    def correlate_code_with_infra(
        self, code_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Correlate SAST code findings with infrastructure nodes and adjust severity.
        
        Example: SSRF vulnerability correlated with IMDSv2 and Kubernetes NetworkPolicy.
        """
        correlated: List[Dict[str, Any]] = []

        # Find if there are network policies restricting egress
        net_policies = [n for n in self.nodes.values() if n.node_type == NodeType.NETWORK_POLICY]
        container_nodes = [n for n in self.nodes.values() if n.node_type == NodeType.CONTAINER]
        iam_roles = [n for n in self.nodes.values() if n.node_type == NodeType.IAM_ROLE]

        for finding in code_findings:
            cwe = str(finding.get("cwe", ""))
            original_sev = finding.get("severity", "HIGH")
            finding_id = finding.get("id", "finding-unknown")
            finding_title = finding.get("title", "Finding")

            result = dict(finding)
            result["assessment_kind"] = "configuration_hypothesis"
            result["live_exploitability_verified"] = False

            if "CWE-918" in cwe or "SSRF" in finding_title.upper():
                # Check for egress controls / IMDSv2
                has_egress_block = any(
                    np.properties.get("block_metadata_egress", False) or
                    "169.254.169.254" in np.properties.get("blocked_cidrs", [])
                    for np in net_policies
                )
                imdsv2_enforced = any(
                    c.properties.get("http_tokens", "") == "required" or
                    c.properties.get("imdsv2_enforced", False)
                    for c in container_nodes
                )

                if has_egress_block or imdsv2_enforced:
                    result["original_severity"] = original_sev
                    result["severity"] = "INFO"
                    result["topology_status"] = AttackPathStatus.MITIGATED_BY_TOPOLOGY.value
                    result["mitigation_reason"] = (
                        "SSRF mitigated by infrastructure: "
                        + ("Egress NetworkPolicy blocks metadata service (169.254.169.254). " if has_egress_block else "")
                        + ("AWS IMDSv2 token enforcement active." if imdsv2_enforced else "")
                    )
                else:
                    # Check IAM permissions
                    privileged_iam = any(
                        "*" in role.properties.get("permissions", []) or
                        any("s3:GetObject" in p or "iam:" in p for p in role.properties.get("permissions", []))
                        for role in iam_roles
                    )
                    result["severity"] = "CRITICAL"
                    result["topology_status"] = AttackPathStatus.VIABLE_ATTACK_PATH.value
                    result["exploit_chain"] = (
                        "Viable attack chain: Code SSRF -> Cloud Metadata Service unblocked -> "
                        + ("High-privilege IAM Role credentials extracted." if privileged_iam else "Instance identity token stolen.")
                    )
            elif "CWE-89" in cwe or "SQL" in finding_title.upper():
                # Check if DB asset is isolated
                db_assets = [n for n in self.nodes.values() if n.node_type == NodeType.CRITICAL_ASSET and n.properties.get("asset_type") == "database"]
                is_isolated = any(db.properties.get("network_isolated", False) for db in db_assets)
                is_read_only = any(db.properties.get("read_only", False) for db in db_assets)

                if is_isolated and is_read_only:
                    result["original_severity"] = original_sev
                    result["severity"] = "MEDIUM"
                    result["topology_status"] = AttackPathStatus.ISOLATED_BY_NETWORK.value
                    result["mitigation_reason"] = "Database connection restricted to isolated read-only replica."
                else:
                    result["topology_status"] = AttackPathStatus.VIABLE_ATTACK_PATH.value

            correlated.append(result)

        return correlated

    def evaluate_target_attack_surface(self, start_node_id: str, target_asset_id: str) -> AttackPath:
        """Evaluate whether a path from a vulnerability or ingress container can compromise an asset."""
        paths = self.find_all_paths(start_node_id, target_asset_id)
        if not paths:
            return AttackPath(
                path_nodes=[start_node_id, target_asset_id],
                description=f"No viable directed path from {start_node_id} to {target_asset_id}.",
                severity="INFO",
                status=AttackPathStatus.ISOLATED_BY_NETWORK,
                remediation_steps=["Maintain current network segmentation."],
            )

        # Examine nodes in the shortest path
        primary_path = paths[0]
        remediations: List[str] = []
        is_blocked = False
        blocked_reason = ""

        for nid in primary_path:
            node = self.nodes[nid]
            if node.node_type == NodeType.NETWORK_POLICY:
                if node.properties.get("default_deny_egress", False):
                    is_blocked = True
                    blocked_reason = f"Blocked by default-deny egress in NetworkPolicy {node.name}"
            elif node.node_type == NodeType.IAM_ROLE:
                if not node.properties.get("permissions"):
                    is_blocked = True
                    blocked_reason = f"Blocked by least-privilege IAM Role {node.name}"

        if is_blocked:
            return AttackPath(
                path_nodes=primary_path,
                description=f"Attack path mitigated: {blocked_reason}",
                severity="LOW",
                status=AttackPathStatus.MITIGATED_BY_TOPOLOGY,
                remediation_steps=["Preserve policy integrity in CI/CD."],
            )

        return AttackPath(
            path_nodes=primary_path,
            description=f"Direct viable lateral movement chain from {start_node_id} to {target_asset_id}.",
            severity="CRITICAL",
            status=AttackPathStatus.VIABLE_ATTACK_PATH,
            remediation_steps=[
                "Implement Kubernetes NetworkPolicy to restrict egress to private subnets.",
                "Enforce IMDSv2 on EC2/EKS nodes (Set HttpTokens=required).",
                "Apply least-privilege IAM policy attached to container service account.",
            ],
        )


class CISBenchmarkScanner:
    """Validates Linux host system configurations against CIS security baselines."""

    BENCHMARKS: List[Dict[str, Any]] = [
        {
            "id": "CIS-1.1",
            "title": "SSH Root Login Disabled",
            "key": "PermitRootLogin",
            "expected": "no",
            "category": "ssh",
            "severity": "HIGH",
        },
        {
            "id": "CIS-1.2",
            "title": "SSH Password Authentication Disabled",
            "key": "PasswordAuthentication",
            "expected": "no",
            "category": "ssh",
            "severity": "MEDIUM",
        },
        {
            "id": "CIS-2.1",
            "title": "IP Forwarding Disabled",
            "key": "net.ipv4.ip_forward",
            "expected": "0",
            "category": "sysctl",
            "severity": "MEDIUM",
        },
        {
            "id": "CIS-2.2",
            "title": "TCP SYN Cookies Enabled",
            "key": "net.ipv4.tcp_syncookies",
            "expected": "1",
            "category": "sysctl",
            "severity": "HIGH",
        },
        {
            "id": "CIS-3.1",
            "title": "Shadow File Permissions Restrictive",
            "key": "etc_shadow_perm",
            "expected": "0600",
            "category": "filesystem",
            "severity": "CRITICAL",
        },
    ]

    def scan_config(self, host_config: Dict[str, Any]) -> Dict[str, Any]:
        """Audit host parameters and return compliance scorecard."""
        passed_checks = []
        failed_checks = []

        for bm in self.BENCHMARKS:
            actual = str(host_config.get(bm["key"], "")).strip()
            expected = bm["expected"]
            if actual.lower() == expected.lower():
                passed_checks.append({
                    "id": bm["id"],
                    "title": bm["title"],
                    "actual": actual,
                    "expected": expected,
                })
            else:
                failed_checks.append({
                    "id": bm["id"],
                    "title": bm["title"],
                    "actual": actual or "MISSING",
                    "expected": expected,
                    "severity": bm["severity"],
                })

        total = len(self.BENCHMARKS)
        score = (len(passed_checks) / total) * 100.0 if total > 0 else 0.0

        return {
            "total_checks": total,
            "passed_count": len(passed_checks),
            "failed_count": len(failed_checks),
            "compliance_score": round(score, 2),
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "compliant": total > 0 and len(failed_checks) == 0,
            "evidence_origin": "supplied_configuration",
            "live_host_verification": "NOT_RUN",
        }


class KernelTelemetryProbe:
    """Analyzes runtime execution logs / eBPF traces for anomalous process activities."""

    FORBIDDEN_SPAWN_PARENTS = {"nginx", "httpd", "python", "gunicorn", "uwsgi", "node", "apache2"}
    SENSITIVE_BINARIES = {"/bin/sh", "/bin/bash", "/bin/zsh", "cmd.exe", "powershell.exe", "/usr/bin/python"}

    def analyze_event(self, event: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Evaluate an eBPF syscall or exec trace event.
        
        Returns: (is_anomalous: bool, reason: Optional[str])
        """
        event_type = event.get("type", "execve")
        parent = event.get("parent_process", "").lower()
        child = event.get("child_process", "").lower()
        network_dest = event.get("remote_addr", "")
        dest_port = event.get("remote_port", 0)

        # 1. Reverse shell detection (web worker spawning interactive shell)
        if any(p in parent for p in self.FORBIDDEN_SPAWN_PARENTS):
            if any(b in child for b in self.SENSITIVE_BINARIES):
                return (
                    True,
                    f"CRITICAL ANOMALY: Web runtime '{parent}' spawned shell process '{child}' (Potential RCE / Reverse Shell).",
                )

        # 2. Suspicious outbound connection from worker to unexpected port
        if event_type == "connect" and any(p in parent for p in self.FORBIDDEN_SPAWN_PARENTS):
            if dest_port in {4444, 1337, 6666, 9001}:
                return (
                    True,
                    f"CRITICAL ANOMALY: Worker '{parent}' connected to known backdoor port {dest_port} at {network_dest}.",
                )

        # 3. Unauthorized write to binary directory
        if event_type in {"open_write", "unlink"}:
            path = event.get("target_path", "")
            if path.startswith("/bin/") or path.startswith("/usr/bin/") or path.startswith("/sbin/"):
                return (
                    True,
                    f"TAMPERING DETECTED: Process '{parent}' attempted modification to system binary '{path}'.",
                )

        return (False, None)
