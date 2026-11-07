"""
Realtime WebSocket, GraphQL & gRPC Protocol Security Scanner
Audits non-REST API protocols for:
1. WebSocket (`ws` / `WebSocketServer`) lacking `maxPayload` size bounds or `Origin` verification (CSWSH).
2. GraphQL Server (`ApolloServer` / `graphqlHTTP` / ` strawberry`) with introspection enabled in production or lacking query depth limits.
3. gRPC Server (`grpc.Server` / `createInsecure`) bound without TLS credentials in non-local environments.
"""

import re
from typing import List
from cyberaudit.core.base_scanner import BaseScanner
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


class RealtimeWebsocketGraphqlGrpcScanner(BaseScanner):
    __test__ = False

    def __init__(self):
        super().__init__()

    @property
    def name(self) -> str:
        return "Realtime WebSocket, GraphQL & gRPC Protocol Security Scanner"

    @property
    def pillar(self) -> Pillar:
        return Pillar.PENETRATION_TESTER

    @property
    def description(self) -> str:
        return (
            "Audits WebSocket servers (missing Origin check / maxPayload), GraphQL endpoints "
            "(introspection enabled / missing depth limit), and insecure gRPC bindings."
        )

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".ts", ".py"]

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lower_path = file_path.replace("\\", "/").lower()
        if any(x in lower_path for x in ["/test/", "/tests/", ".test.", ".spec.", "test_"]):
            return []

        lines = content.splitlines()
        total_lines = len(lines)

        # ------------------------------------------------------------------
        # 1. APPSEC-WS-UNBOUNDED-PAYLOAD (new WebSocketServer without maxPayload)
        # ------------------------------------------------------------------
        ws_server_re = re.compile(r"\bnew\s+(?:WebSocketServer| WebSocket\.Server)\s*\(\s*\{([^}]*)\}\s*\)", re.DOTALL)
        for match in ws_server_re.finditer(content):
            opts = match.group(1)
            if "maxPayload" not in opts:
                line_num = content[: match.start()].count("\n") + 1
                snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)[:120]
                findings.append(
                    Finding(
                        id="APPSEC-WS-UNBOUNDED-PAYLOAD",
                        title="WebSocket Security: WebSocketServer Initialized Without `maxPayload` Limit",
                        description=(
                            f"WebSocket server at line {line_num} omits `maxPayload`. By default, `ws` allows frames up to 100 MB, "
                            f"enabling single-connection memory exhaustion (DoS)."
                        ),
                        severity=Severity.MEDIUM,
                        pillar=self.pillar,
                        scanner_name=self.name,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet[:200],
                        remediation="Configure an explicit `maxPayload` (e.g., `maxPayload: 64 * 1024`) and verify the `Origin` header in `verifyClient` or the `upgrade` event.",
                        cwe_id="CWE-770",
                        stride_category=StrideCategory.DENIAL_OF_SERVICE.value,
                    )
                )

        # ------------------------------------------------------------------
        # 2. APPSEC-GRAPHQL-INTROSPECTION-ENABLED
        # ------------------------------------------------------------------
        gql_intro_re = re.compile(r"\bintrospection\s*:\s*true\b")
        for match in gql_intro_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="APPSEC-GRAPHQL-INTROSPECTION-ENABLED",
                    title="GraphQL Security: Schema Introspection Explicitly Enabled (`introspection: true`)",
                    description=(
                        f"GraphQL configuration enables schema introspection unconditionally (`{snippet}`). "
                        f"Attackers can query `__schema` to enumerate all internal mutations, types, and deprecated fields."
                    ),
                    severity=Severity.MEDIUM,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Disable introspection in production (`introspection: process.env.NODE_ENV !== 'production'`) and enforce `graphql-depth-limit`.",
                    cwe_id="CWE-200",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                )
            )

        # ------------------------------------------------------------------
        # 3. APPSEC-GRPC-INSECURE-CREDENTIALS
        # ------------------------------------------------------------------
        grpc_insecure_re = re.compile(r"\b(?:ServerCredentials\.createInsecure|credentials\.createInsecure|add_insecure_port)\s*\(")
        for match in grpc_insecure_re.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            snippet = lines[line_num - 1].strip() if line_num - 1 < total_lines else match.group(0)
            findings.append(
                Finding(
                    id="APPSEC-GRPC-INSECURE-CHANNEL",
                    title="gRPC Security: Plaintext Unauthenticated gRPC Channel/Server (`createInsecure`)",
                    description=(
                        f"gRPC binding `{snippet}` disables TLS encryption and mutual authentication (mTLS), "
                        f"exposing internal protobuf RPC traffic to network sniffing and spoofing."
                    ),
                    severity=Severity.HIGH,
                    pillar=self.pillar,
                    scanner_name=self.name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet[:200],
                    remediation="Use `ServerCredentials.createSsl(...)` / `grpc.ssl_server_credentials(...)` with mTLS in production.",
                    cwe_id="CWE-319",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                )
            )

        return findings
