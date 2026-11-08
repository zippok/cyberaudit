import { test } from 'node:test';
import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const rootDir = resolve(dirname(__filename), '..');
const cliPath = join(rootDir, 'cli.js');

test('CyberAudit CLI - list outputs skills', () => {
  const res = spawnSync('node', [cliPath, 'list'], { cwd: rootDir, encoding: 'utf-8' });
  assert.strictEqual(res.status, 0);
  assert.match(res.stdout, /CyberAudit Skills & Tools Catalog/);
  assert.match(res.stdout, /cyberaudit-full/);
  assert.match(res.stdout, /cyberaudit-appsec/);
  assert.match(res.stdout, /cyberaudit-qa-resilience/);
  assert.match(res.stdout, /secure-coding/);
});

test('CyberAudit CLI - setup-tools reports external security tools', () => {
  const res = spawnSync('node', [cliPath, 'setup-tools'], { cwd: rootDir, encoding: 'utf-8' });
  assert.strictEqual(res.status, 0);
  assert.match(res.stdout, /External Security Tools Orchestrator/);
  assert.match(res.stdout, /npm_audit/);
  assert.match(res.stdout, /pip_audit/);
  assert.match(res.stdout, /gitleaks/);
  assert.match(res.stdout, /trivy/);
});

test('CyberAudit CLI - fix triggers real 4-phase TDD remediation loop', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'cyberaudit-fix-test-'));
  try {
    const vulnFile = join(tmp, 'credentials.py');
    writeFileSync(vulnFile, 'secret_key = "sk-abcdef1234567890abcdef"\n', 'utf-8');

    const res = spawnSync('node', [cliPath, 'fix', 'SECRET', '--path', tmp], { cwd: rootDir, encoding: 'utf-8' });
    assert.strictEqual(res.status, 0);
    assert.match(res.stdout, /Real TDD Remediation Loop/);
    assert.match(res.stdout, /Atomic Defensive Patch/);
    assert.match(res.stdout, /SELLO-CYBERAUDIT-VERIFICADO/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('CyberAudit CLI - harness run-skill and sello work seamlessly', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'cyberaudit-skill-test-'));
  try {
    const hRes = spawnSync('node', [cliPath, 'harness', 'run-skill', 'cyberaudit-appsec', tmp], { cwd: rootDir, encoding: 'utf-8' });
    assert.strictEqual(hRes.status, 0);
    assert.match(hRes.stdout, /Stage 1 Pre-Flight Result/);
    assert.match(hRes.stdout, /Scanners Executed \(12\)/);

    const sRes = spawnSync('node', [cliPath, 'harness', 'sello', tmp, '--skill', 'cyberaudit-full'], { cwd: rootDir, encoding: 'utf-8' });
    assert.strictEqual(sRes.status, 0);
    assert.match(sRes.stdout, /SELLO-CYBERAUDIT/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('CyberAudit CLI - onboard generates binding plan and applies with accept-plan', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'cyberaudit-onboard-test-'));
  try {
    // 1. Preview
    const pRes = spawnSync('node', [cliPath, 'onboard'], { cwd: tmp, encoding: 'utf-8' });
    assert.strictEqual(pRes.status, 0);
    assert.match(pRes.stdout, /CYBERAUDIT_ONBOARDING_PLAN/);
    const m = pRes.stdout.match(/Plan id:\s+(PLAN-[a-f0-9]+)/);
    assert.ok(m, 'Plan id found');
    const planId = m[1];

    // 2. Accept
    const aRes = spawnSync('node', [cliPath, 'onboard', '--accept-plan', planId], { cwd: tmp, encoding: 'utf-8' });
    assert.strictEqual(aRes.status, 0);
    assert.match(aRes.stdout, /CYBERAUDIT_ONBOARDING_READY/);
    assert.ok(existsSync(join(tmp, '.cyberaudit.json')), '.cyberaudit.json created');
    assert.ok(existsSync(join(tmp, '.antigravity', 'AGENTS.md')), 'AGENTS.md created');

    // 01-TOOLS scaffolding verification
    assert.ok(existsSync(join(tmp, '01-TOOLS', '.gitignore')), '01-TOOLS/.gitignore created');
    assert.ok(existsSync(join(tmp, '01-TOOLS', '_TEMPLATE', 'test_connection.sh')), 'test_connection.sh created');
    assert.ok(existsSync(join(tmp, '01-TOOLS', '_TEMPLATE', '.env.example')), '.env.example created');
    assert.ok(existsSync(join(tmp, '01-TOOLS', '_TEMPLATE', 'CREDENTIALS.md')), 'CREDENTIALS.md created');
    assert.ok(existsSync(join(tmp, '01-TOOLS', '_TEMPLATE', 'README.md')), 'README.md created');

    // 02-DOCS scaffolding verification
    assert.ok(existsSync(join(tmp, '02-DOCS', 'inbox', 'README.md')), 'inbox/README.md created');
    assert.ok(existsSync(join(tmp, '02-DOCS', 'raw', 'worklog', 'README.md')), 'raw/worklog/README.md created');
    assert.ok(existsSync(join(tmp, '02-DOCS', 'wiki', 'index.md')), 'wiki/index.md created');
    assert.ok(existsSync(join(tmp, '02-DOCS', 'wiki', 'harness', 'user-profile.md')), 'user-profile.md created');
    assert.ok(existsSync(join(tmp, '02-DOCS', 'wiki', 'harness', 'installation-plan.md')), 'installation-plan.md created');
    assert.ok(existsSync(join(tmp, '02-DOCS', 'wiki', 'harness', 'decisions.md')), 'decisions.md created');

    // 3. Verify Doctor passes in target directory
    const dRes = spawnSync('node', [cliPath, 'doctor'], { cwd: tmp, encoding: 'utf-8' });
    assert.strictEqual(dRes.status, 0);
    assert.match(dRes.stdout, /Status: HEALTHY/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
