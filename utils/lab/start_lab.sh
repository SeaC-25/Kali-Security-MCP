#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export LAB_HOST="${LAB_HOST:-127.0.0.1}"
export LAB_PORT="${LAB_PORT:-18081}"
PID_FILE="$ROOT/lab.pid"
LOG_FILE="$ROOT/logs/lab.log"
mkdir -p "$ROOT/logs"
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "lab already running pid=$(cat "$PID_FILE") http://${LAB_HOST}:${LAB_PORT}/"
  exit 0
fi
fuser -k "${LAB_PORT}/tcp" 2>/dev/null || true
nohup python3 "$ROOT/lab_server.py" >"$LOG_FILE" 2>&1 &
echo $! >"$PID_FILE"
sleep 0.5
if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "lab started pid=$(cat "$PID_FILE") http://${LAB_HOST}:${LAB_PORT}/"
else
  echo "lab failed to start; see $LOG_FILE" >&2
  exit 1
fi
