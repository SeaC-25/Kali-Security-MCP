#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$ROOT/lab.pid"
LAB_PORT="${LAB_PORT:-18081}"
if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE")"
  kill "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  echo "stopped pid=$pid"
fi
fuser -k "${LAB_PORT}/tcp" 2>/dev/null || true
echo "lab port ${LAB_PORT} cleared"
