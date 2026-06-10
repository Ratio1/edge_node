#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  echo "[edge-node-post-start] $*"
}

prefer_nft_iptables() {
  command -v update-alternatives >/dev/null 2>&1 || return 0

  for tool in iptables ip6tables arptables ebtables; do
    if command -v "${tool}-nft" >/dev/null 2>&1; then
      update-alternatives --set "${tool}" "$(command -v "${tool}-nft")" >/dev/null 2>&1 || true
    fi
  done
}

start_docker_daemon() {
  command -v docker >/dev/null 2>&1 || {
    log "docker CLI is not installed; skipping Docker daemon startup"
    return 0
  }

  if docker info >/dev/null 2>&1; then
    log "Docker daemon is already running"
    return 0
  fi

  if [ ! -x /usr/local/share/docker-init.sh ]; then
    log "docker-init.sh is not installed; cannot start Docker daemon"
    return 0
  fi

  mkdir -p /edge_node/_local_cache/_data/run

  if pgrep -x dockerd >/dev/null 2>&1; then
    log "Docker daemon startup is already in progress"
  else
    pkill -f 'docker-init.sh sleep infinity' >/dev/null 2>&1 || true
    pkill -x containerd >/dev/null 2>&1 || true
    find /run /var/run -iname 'docker*.pid' -delete 2>/dev/null || true
    find /run /var/run -iname 'container*.pid' -delete 2>/dev/null || true

    log "Starting Docker daemon"
    nohup /usr/local/share/docker-init.sh sleep infinity \
      > /edge_node/_local_cache/_data/run/dind.log 2>&1 &
    echo "$!" > /edge_node/_local_cache/_data/run/dind.pid
  fi

  for _ in $(seq 1 45); do
    if docker info >/dev/null 2>&1; then
      log "Docker daemon is ready"
      return 0
    fi
    sleep 1
  done

  log "Docker daemon did not become ready; see /edge_node/_local_cache/_data/run/dind.log"
  return 0
}

cleanup_orphaned_fastapi_servers() {
  local main_pids uvicorn_entries stale_pids

  main_pids="$(pgrep -f 'python3 (device.py|naeural_core/start_nen.py)' 2>/dev/null || true)"
  uvicorn_entries="$(ps -eo pid=,ppid=,args= | awk '/\/usr\/local\/bin\/uvicorn --app-dir \/tmp\// {print $1 " " $2}' || true)"
  [ -n "$uvicorn_entries" ] || return 0

  stale_pids="$(
    while read -r pid ppid; do
      [ -n "${pid:-}" ] || continue
      if [ -z "$main_pids" ] || ! printf '%s\n' "$main_pids" | grep -qx "$ppid"; then
        printf '%s\n' "$pid"
      fi
    done <<EOF
$uvicorn_entries
EOF
  )"

  [ -n "$stale_pids" ] || return 0

  log "Stopping orphaned FastAPI servers: $(printf '%s' "$stale_pids" | tr '\n' ' ')"
  kill $stale_pids >/dev/null 2>&1 || true
  sleep 2
  for pid in $stale_pids; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  done
}

start_watchdog() {
  if pgrep -f 'python3 .devcontainer/watch.py' >/dev/null 2>&1; then
    log "devcontainer watchdog is already running"
    return 0
  fi

  log "Starting devcontainer watchdog"
  nohup python3 .devcontainer/watch.py > /proc/1/fd/1 2>/proc/1/fd/2 &
}

prefer_nft_iptables
start_docker_daemon
cleanup_orphaned_fastapi_servers
start_watchdog
