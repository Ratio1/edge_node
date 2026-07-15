#!/usr/bin/env bash
set -euo pipefail

EDGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${NAEURAL_CORE_ROOT:?Set NAEURAL_CORE_ROOT to the naeural_core worktree under test}"
: "${NAEURAL_CLIENT_ROOT:?Set NAEURAL_CLIENT_ROOT to an up-to-date naeural_client checkout}"

for container in r1_comms_emqx ratio1_comm_node_01; do
  if docker ps -a --format '{{.Names}}' | grep -qx "${container}"; then
    echo "Container ${container} already exists; remove it before running this isolated testbed." >&2
    exit 1
  fi
done

context="$(mktemp -d "${TMPDIR:-/tmp}/r1-pause-e2e.XXXXXX")"
project="r1_pause_e2e_${RANDOM}_$$"
compose=(
  docker compose -p "${project}"
  -f docker-compose_comms.yaml
  -f docker-compose/debug-fastapi-pause-cycle.yaml
)

cleanup() {
  if [[ -d "${context}/edge_node" ]]; then
    (cd "${context}/edge_node" && EDGE_NODE_COMMS_IMAGE=local_edge_node_pause_e2e "${compose[@]}" down -v --remove-orphans) || true
  fi
  rm -rf "${context}"
}
trap cleanup EXIT

mkdir -p "${context}"/{edge_node,naeural_core,naeural_client}
rsync -a --exclude=.git --exclude=__pycache__ --exclude='*.pyc' "${EDGE_ROOT}/" "${context}/edge_node/"
rsync -a --exclude=.git --exclude=__pycache__ --exclude='*.pyc' "${NAEURAL_CORE_ROOT}/" "${context}/naeural_core/"
git -C "${NAEURAL_CLIENT_ROOT}" fetch --prune origin
git -C "${NAEURAL_CLIENT_ROOT}" archive origin/main | tar -x -C "${context}/naeural_client"

cd "${context}/edge_node"
export EDGE_NODE_COMMS_IMAGE=local_edge_node_pause_e2e
export INSTALL_KUBO=0
export R1_PAUSE_E2E_NETWORK="${project}_network"
"${compose[@]}" config --quiet
"${compose[@]}" build ratio1_comm_node_01
"${compose[@]}" up -d --no-build emqx ratio1_comm_node_01
python3 tests/validate_debug_fastapi_pause_cycle.py --pause-seconds "${EE_DEBUG_FASTAPI_PAUSE_SECONDS:-5}"
