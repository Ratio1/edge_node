#!/usr/bin/env bash
set -Eeuo pipefail

cd /edge_node

log() {
  echo "[edge-node-restart] $*"
}

cleanup_fastapi_servers() {
  local pids
  pids="$(pgrep -f '/usr/local/bin/uvicorn --app-dir /tmp/' 2>/dev/null || true)"
  [ -n "$pids" ] || return 0

  log "Stopping stale FastAPI child servers: $(printf '%s' "$pids" | tr '\n' ' ')"
  kill $pids >/dev/null 2>&1 || true
  sleep 2
  for pid in $pids; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  done
}

stop_node_processes() {
  local pids
  pids="$(pgrep -f 'python3 (device.py|naeural_core/start_nen.py)' 2>/dev/null || true)"
  [ -n "$pids" ] || return 0

  log "Stopping edge-node process: $(printf '%s' "$pids" | tr '\n' ' ')"
  kill $pids >/dev/null 2>&1 || true
  sleep 5
  for pid in $pids; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  done
}

ensure_watchdog() {
  if pgrep -f 'python3 .devcontainer/watch.py' >/dev/null 2>&1; then
    log "devcontainer watchdog is running"
    return 0
  fi

  log "Starting devcontainer watchdog"
  nohup python3 .devcontainer/watch.py > /proc/1/fd/1 2>/proc/1/fd/2 &
}

bash .devcontainer/post-start.sh
stop_node_processes
cleanup_fastapi_servers
ensure_watchdog
log "Restart requested"
