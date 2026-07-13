#!/usr/bin/env bash
# Stop the Mule Standalone instance started by boot-mule.sh.
# Best-effort — never fails the workflow.
set -uo pipefail

MULE_HOME_DIR=${MULE_HOME_DIR:-"$PWD/mule"}

if [[ ! -x "$MULE_HOME_DIR/bin/mule" ]]; then
  echo "→ No Mule installation at $MULE_HOME_DIR; nothing to stop"
  exit 0
fi

"$MULE_HOME_DIR/bin/mule" stop || true

# Belt-and-braces: kill anything still bound to the port.
pkill -f "$MULE_HOME_DIR" 2>/dev/null || true

echo "→ Mule stop requested"
