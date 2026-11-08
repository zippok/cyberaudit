#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-.}"
echo "=== CyberAudit Auto-Fix Pre-Flight Verification ==="
echo "Target: $TARGET"

if command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    echo "ERROR: python3 or python required for CyberAudit."
    exit 1
fi

"$PY" -c "
import sys, os
from cyberaudit.core.engine import AuditEngine

engine = AuditEngine()
report = engine.scan_path('$TARGET')
blocking = [f for f in report.findings if f.severity.value in ('CRITICAL', 'HIGH')]
if blocking:
    print(f'BLOCK: {len(blocking)} blocking finding(s) detected.')
    for b in blocking[:5]:
        print(f'  - [{b.severity.value}] {b.id}: {b.title}')
    sys.exit(1)
print(f'PASS: 0 blocking findings across {report.files_scanned} scanned files.')
"
echo "Auto-Fix Verification: PASS"
