#!/bin/sh
# Resolve the scanner-pinned CodeGraph CLI for coordinator and subagent calls.
# Keep the caller's working directory so CodeGraph uses the target's local index.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BALLS_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LOCAL_CLI="$BALLS_ROOT/.tools/codegraph/node_modules/.bin/codegraph"

if [ -x "$LOCAL_CLI" ]; then
  exec "$LOCAL_CLI" "$@"
fi

if command -v codegraph >/dev/null 2>&1; then
  exec "$(command -v codegraph)" "$@"
fi

printf '%s\n' "CodeGraph CLI unavailable. Install the scanner-pinned version with:" \
  "  npm install --prefix \"$BALLS_ROOT/.tools/codegraph\" --no-audit --no-fund @colbymchenry/codegraph@1.6.2" >&2
exit 127
