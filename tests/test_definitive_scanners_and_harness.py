"""
Unit & Integration Tests for the 14 New Definitive Scanners and the CyberAudit Skill Harness.
Verifies both negative controls (vulnerable / anti-pattern snippets trigger the exact Finding IDs)
and positive controls (clean code passes with 0 findings), plus skill harness orchestration and sello emission.
"""

import os
import sys
import tempfile
import unittest

_CYBERAUDIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _CYBERAUDIT_ROOT not in sys.path:
    sys.path.insert(0, _CYBERAUDIT_ROOT)

from cyberaudit.core.engine import AuditEngine
from cyberaudit.core.skill_harness import CyberAuditSkillHarness, CYBERAUDIT_SKILL_DOMAINS
from cyberaudit.modules.software_architecture.db_migration_orm_scanner import DatabaseMigrationAndOrmScanner
from cyberaudit.modules.software_architecture.api_idempotency_pagination_scanner import ApiIdempotencyAndPaginationScanner
from cyberaudit.modules.software_architecture.circular_dependency_boundary_scanner import CircularDependencyAndBoundaryScanner
from cyberaudit.modules.software_qa.type_safety_schema_scanner import TypeSafetyAndSchemaBoundaryScanner
from cyberaudit.modules.software_qa.test_quality_assertion_auditor import TestQualityAndAssertionAuditor
from cyberaudit.modules.software_qa.crash_safety_durability_scanner import CrashSafetyAndDurabilityScanner
from cyberaudit.modules.software_qa.algorithmic_complexity_redos_scanner import AlgorithmicComplexityAndRedosScanner
from cyberaudit.modules.software_qa.observability_structured_logging_scanner import ObservabilityAndStructuredLoggingScanner
from cyberaudit.modules.ui_ux.async_ui_states_scanner import AsyncUiStatesCompletenessScanner
from cyberaudit.modules.ui_ux.core_web_vitals_perf_scanner import CoreWebVitalsAndFrontendPerfScanner
from cyberaudit.modules.ui_ux.design_system_token_i18n_scanner import DesignSystemTokenAndI18nScanner
from cyberaudit.modules.ui_ux.client_storage_hydration_scanner import ClientStorageAndHydrationSafetyScanner
from cyberaudit.modules.security_engineer.gdpr_privacy_pii_scanner import GdprPrivacyAndPiiDataFlowScanner
from cyberaudit.modules.penetration_tester.realtime_ws_graphql_grpc_scanner import RealtimeWebsocketGraphqlGrpcScanner
from cyberaudit.modules.security_analyst.cloud_gcp_terraform_audit import MultiCloudGcpAndTerraformScanner
from cyberaudit.modules.ai_security.ai_eval_drift_cost_scanner import AiEvalDriftAndCostGuardScanner


class TestDefinitiveScannersAndHarness(unittest.TestCase):
    def test_engine_registers_all_68_scanners(self):
        engine = AuditEngine()
        self.assertEqual(len(engine.scanners), 68)

    def test_db_migration_and_orm_scanner(self):
        scanner = DatabaseMigrationAndOrmScanner()
        sql_findings = scanner.scan_file(
            "migrations/002_drop.sql",
            "ALTER TABLE users DROP COLUMN legacy_email;\nDELETE FROM audit_logs;",
        )
        ids = {f.id for f in sql_findings}
        self.assertIn("ARCH-DB-MIGRATION-DROP-COLUMN", ids)
        self.assertIn("ARCH-DB-UNBOUNDED-MUTATION", ids)

        orm_findings = scanner.scan_file(
            "src/orderService.ts",
            "for (const id of orderIds) {\n  const item = await prisma.order.findUnique({ where: { id } });\n}",
        )
        self.assertTrue(any(f.id == "ARCH-ORM-N-PLUS-ONE" for f in orm_findings))

    def test_api_idempotency_and_pagination_scanner(self):
        scanner = ApiIdempotencyAndPaginationScanner()
        findings = scanner.scan_file(
            "src/routes/payments.js",
            "app.post('/api/v1/checkout/pay', async (req, res) => {\n  const all = await prisma.invoice.findMany();\n  return res.json(all);\n});",
        )
        ids = {f.id for f in findings}
        self.assertIn("ARCH-API-MISSING-IDEMPOTENCY-KEY", ids)
        self.assertIn("ARCH-API-UNBOUNDED-QUERY", ids)

    def test_circular_dependency_and_layer_boundary_scanner(self):
        scanner = CircularDependencyAndBoundaryScanner()
        findings = scanner.scan_file(
            "src/components/UserProfile.tsx",
            "import { PrismaClient } from '@prisma/client';\nexport const UserProfile = () => null;",
        )
        self.assertTrue(any(f.id == "ARCH-BOUNDARY-UI-IMPORTS-DB" for f in findings))

    def test_type_safety_and_schema_boundary_scanner(self):
        scanner = TypeSafetyAndSchemaBoundaryScanner()
        findings = scanner.scan_file(
            "src/controllers/user.ts",
            "// @ts-ignore\nconst a: any = 1;\nconst b: any = 2;\nconst c: any = 3;\napp.post('/users', (req, res) => { const x = req.body.name; });",
        )
        ids = {f.id for f in findings}
        self.assertIn("QA-TS-SAFETY-SUPPRESSION", ids)
        self.assertIn("QA-TS-EXCESSIVE-ANY", ids)
        self.assertIn("QA-SCHEMA-UNVALIDATED-BODY", ids)

    def test_test_quality_assertion_auditor(self):
        scanner = TestQualityAndAssertionAuditor()
        findings = scanner.scan_file(
            "test/auth.test.js",
            "it.only('checks math', () => {\n  expect(true).toBe(true);\n});\nit('does nothing', () => {\n  const x = 1 + 2;\n});",
        )
        ids = {f.id for f in findings}
        self.assertIn("QA-TEST-TAUTOLOGICAL-ASSERTION", ids)
        self.assertIn("QA-TEST-EXCLUSIVE-ONLY", ids)
        self.assertIn("QA-TEST-MISSING-ASSERTION", ids)

    def test_crash_safety_and_durability_scanner(self):
        scanner = CrashSafetyAndDurabilityScanner()
        js_findings = scanner.scan_file(
            "src/stateStore.js",
            "fs.writeFileSync(configFilePath, JSON.stringify(data));",
        )
        self.assertTrue(any(f.id == "QA-DDIA-NON-ATOMIC-STATE-WRITE" for f in js_findings))

        py_findings = scanner.scan_file(
            "src/webhook.py",
            "resp = requests.post('https://example.com/hook', json=payload)",
        )
        self.assertTrue(any(f.id == "QA-DDIA-OUTBOUND-HTTP-NO-TIMEOUT" for f in py_findings))

    def test_algorithmic_complexity_and_redos_scanner(self):
        scanner = AlgorithmicComplexityAndRedosScanner()
        findings = scanner.scan_file(
            "src/matcher.js",
            "const badRe = /^(a+)+$/;\nconst res = items.map(x => allowedList.includes(x.id));",
        )
        ids = {f.id for f in findings}
        self.assertIn("QA-PERF-REDOS-QUANTIFIER", ids)
        self.assertIn("QA-PERF-QUADRATIC-LOOKUP", ids)

    def test_observability_structured_logging_scanner(self):
        scanner = ObservabilityAndStructuredLoggingScanner()
        findings = scanner.scan_file(
            "src/service.js",
            "try { work(); } catch (err) { throw new Error(err.message); }",
        )
        self.assertTrue(any(f.id == "QA-SRE-LOST-ERROR-CAUSE" for f in findings))

    def test_ui_ux_modern_scanners(self):
        async_scanner = AsyncUiStatesCompletenessScanner()
        f1 = async_scanner.scan_file(
            "src/CheckoutForm.tsx",
            "<form onSubmit={handlePay}><button type=\"submit\">Pay</button></form>\nfetch('/pay');\nwindow.alert('Error');",
        )
        ids1 = {f.id for f in f1}
        self.assertIn("UIUX-ASYNC-DOUBLE-SUBMIT", ids1)
        self.assertIn("UIUX-BLOCKING-WINDOW-ALERT", ids1)

        cwv_scanner = CoreWebVitalsAndFrontendPerfScanner()
        f2 = cwv_scanner.scan_file(
            "src/Hero.tsx",
            "<img src=\"/hero.png\" alt=\"Hero\" />\nwindow.addEventListener('scroll', onScroll);",
        )
        ids2 = {f.id for f in f2}
        self.assertIn("UIUX-CWV-CLS-IMAGE-DIMENSIONS", ids2)
        self.assertIn("UIUX-CWV-INP-NON-PASSIVE-LISTENER", ids2)

        token_scanner = DesignSystemTokenAndI18nScanner()
        f3 = token_scanner.scan_file(
            "src/Modal.tsx",
            "<div style={{ color: '#ff0055', zIndex: 99999 }}>Hi</div>",
        )
        ids3 = {f.id for f in f3}
        self.assertIn("UIUX-TOKEN-ZINDEX-ESCALATION", ids3)
        self.assertIn("UIUX-TOKEN-INLINE-HEX-COLOR", ids3)

        storage_scanner = ClientStorageAndHydrationSafetyScanner()
        f4 = storage_scanner.scan_file(
            "src/authClient.ts",
            "localStorage.setItem('jwt_access_token', token);",
        )
        self.assertTrue(any(f.id == "UIUX-STORAGE-SENSITIVE-TOKEN" for f in f4))

    def test_security_privacy_cloud_protocol_ai_scanners(self):
        gdpr_scanner = GdprPrivacyAndPiiDataFlowScanner()
        f_gdpr = gdpr_scanner.scan_file(
            "src/auth.js",
            "console.log('User logged in:', user.email, req.body.credit_card);",
        )
        self.assertTrue(any(f.id == "PRIVACY-GDPR-PLAINTEXT-PII-LOG" for f in f_gdpr))

        proto_scanner = RealtimeWebsocketGraphqlGrpcScanner()
        f_proto = proto_scanner.scan_file(
            "src/realtime.js",
            "const wss = new WebSocketServer({ port: 8080 });\nconst gql = new ApolloServer({ introspection: true });\ngrpc.ServerCredentials.createInsecure();",
        )
        proto_ids = {f.id for f in f_proto}
        self.assertIn("APPSEC-WS-UNBOUNDED-PAYLOAD", proto_ids)
        self.assertIn("APPSEC-GRAPHQL-INTROSPECTION-ENABLED", proto_ids)
        self.assertIn("APPSEC-GRPC-INSECURE-CHANNEL", proto_ids)

        gcp_scanner = MultiCloudGcpAndTerraformScanner()
        f_gcp = gcp_scanner.scan_file(
            "infra/main.tf",
            'resource "google_service_account_key" "k" {}\nmember = "allUsers"\nrole = "roles/owner"',
        )
        gcp_ids = {f.id for f in f_gcp}
        self.assertIn("CLOUD-GCP-PUBLIC-IAM-BINDING", gcp_ids)
        self.assertIn("CLOUD-GCP-PRIMITIVE-ROLE", gcp_ids)
        self.assertIn("CLOUD-GCP-STATIC-SA-KEY", gcp_ids)

        ai_scanner = AiEvalDriftAndCostGuardScanner()
        f_ai = ai_scanner.scan_file(
            "src/llm.js",
            "await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: prompt }] });",
        )
        self.assertTrue(any(f.id == "AI-FINOPS-MISSING-MAX-TOKENS" for f in f_ai))

    def test_skill_harness_orchestration_and_sello(self):
        harness = CyberAuditSkillHarness()
        skills = harness.list_skills()
        self.assertEqual(len(skills), 9)
        self.assertEqual(len(harness.get_scanners_for_skill("cyberaudit-full")), 68)

        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = os.path.join(tmpdir, "clean.py")
            with open(sample_file, "w", encoding="utf-8") as f:
                f.write("def add(a: int, b: int) -> int:\n    return a + b\n")

            res = harness.run_skill("cyberaudit-appsec", tmpdir)
            self.assertEqual(res["verdict"], "PASS")
            self.assertEqual(res["scanners_executed_count"], 12)

            sello_log = os.path.join(tmpdir, "cyberaudit-sello-log.jsonl")
            seal = harness.emit_sello(tmpdir, skill_id="cyberaudit-appsec", log_path=sello_log)
            self.assertEqual(seal["seal_type"], "SELLO-CYBERAUDIT-VERIFICADO")
            self.assertTrue(os.path.exists(sello_log))

    def test_external_tool_orchestrator_and_graceful_fallback(self):
        import json
        import unittest.mock as mock
        from cyberaudit.core.external_orchestrator import ExternalToolOrchestrator

        orch = ExternalToolOrchestrator(timeout=2.0)

        # Test availability check
        self.assertIsInstance(orch.is_tool_available("python"), bool)
        self.assertTrue(orch.is_tool_available("python") or orch.is_tool_available("python3"))

        with tempfile.TemporaryDirectory() as tmpdir:
            # Empty folder: no manifest files -> no attempted tools
            findings, status = orch.run_external_first(tmpdir)
            self.assertEqual(len(findings), 0)
            self.assertEqual(len(status["attempted"]), 0)

            # Add package.json: orchestrator recognizes node project and attempts npm audit
            pkg_path = os.path.join(tmpdir, "package.json")
            with open(pkg_path, "w", encoding="utf-8") as f:
                f.write('{"name": "test-pkg", "version": "1.0.0"}')

            fresh_orch = ExternalToolOrchestrator(timeout=2.0)
            findings, status = fresh_orch.run_external_first(tmpdir)
            self.assertIn("npm_audit", status["attempted"])
            self.assertIsInstance(status["fallback_needed"], list)

            # Test normalization when mock data is processed
            mock_npm_data = {
                "vulnerabilities": {
                    "vulnerable-dep": {
                        "severity": "high",
                        "range": "<2.0.0",
                        "fixAvailable": True,
                        "via": [{"title": "Prototype Pollution", "url": "https://cve/CVE-2024-9999"}],
                    }
                }
            }
            with mock.patch("subprocess.run") as mock_sub:
                mock_sub.return_value = mock.Mock(stdout=json.dumps(mock_npm_data), returncode=1)
                norm_findings = fresh_orch._run_npm_audit(tmpdir)
                self.assertIsNotNone(norm_findings)
                self.assertEqual(len(norm_findings), 1)
                self.assertEqual(norm_findings[0].id, "EXT-NPM-AUDIT-VULNERABLE-DEP")
                self.assertEqual(norm_findings[0].cwe_id, "CWE-1357")

            # Verify AuditEngine runs Stage 0 external tools seamlessly
            engine = AuditEngine(enable_external_tools=True)
            report = engine.scan_path(tmpdir)
            self.assertIn(report.execution_status, ("PASS", "BLOCK"))

    def test_onboarding_engine_and_plan_id(self):
        from cyberaudit.core.onboarding import OnboardingEngine
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = OnboardingEngine(tmpdir)
            plan = engine.generate_plan(technical_level="technical", project_kind="software")
            self.assertTrue(plan["plan_id"].startswith("PLAN-"))
            self.assertEqual(len(plan["selected_components"]), 6)

            # Test applying plan
            ok, msg = engine.apply_plan(plan, plan["plan_id"])
            self.assertTrue(ok)
            self.assertIn("CYBERAUDIT_ONBOARDING_READY", msg)
            self.assertTrue(os.path.exists(os.path.join(tmpdir, ".cyberaudit.json")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, ".antigravity", "AGENTS.md")))

            # 01-TOOLS scaffolding verification
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "01-TOOLS", ".gitignore")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "01-TOOLS", "_TEMPLATE", "test_connection.sh")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "01-TOOLS", "_TEMPLATE", ".env.example")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "01-TOOLS", "_TEMPLATE", "CREDENTIALS.md")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "01-TOOLS", "_TEMPLATE", "README.md")))

            # 02-DOCS scaffolding verification
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "02-DOCS", "inbox", "README.md")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "02-DOCS", "raw", "worklog", "README.md")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "02-DOCS", "wiki", "index.md")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "02-DOCS", "wiki", "harness", "user-profile.md")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "02-DOCS", "wiki", "harness", "installation-plan.md")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "02-DOCS", "wiki", "harness", "decisions.md")))


if __name__ == "__main__":
    unittest.main()
