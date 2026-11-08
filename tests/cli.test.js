import { test } from 'node:test';
import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
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
  assert.match(res.stdout, /cyberaudit-autofix/);
  assert.match(res.stdout, /secure-coding/);
});

test('CyberAudit CLI - doctor reports healthy', () => {
  const res = spawnSync('node', [cliPath, 'doctor'], { cwd: rootDir, encoding: 'utf-8' });
  assert.strictEqual(res.status, 0);
  assert.match(res.stdout, /Doctor Diagnostic/);
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
    assert.ok(existsSync(join(tmp, '02-DOCS', 'wiki', 'harness', 'user-profile.md')), 'user-profile.md created');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
