#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-.}"
THRESHOLD="${2:-HIGH}"

if command -v cyberaudit >/dev/null 2>&1; then
    cyberaudit harness run-skill cyberaudit-architecture "$TARGET" --threshold "$THRESHOLD" --fail-on-block
elif [ -n "${CYBERAUDIT_HOME:-}" ] && [ -f "$CYBERAUDIT_HOME/cli.py" ]; then
    python "$CYBERAUDIT_HOME/cli.py" harness run-skill cyberaudit-architecture "$TARGET" --threshold "$THRESHOLD" --fail-on-block
elif [ -f "cyberaudit/cli.py" ]; then
    python cyberaudit/cli.py harness run-skill cyberaudit-architecture "$TARGET" --threshold "$THRESHOLD" --fail-on-block
else
    python -m cli harness run-skill cyberaudit-architecture "$TARGET" --threshold "$THRESHOLD" --fail-on-block
fi
