#!/usr/bin/env python3
"""Validate the optional local OracleSync comms testbed state.

This script is intentionally Docker/container based because OracleSync is a
runtime consensus behavior. Static tests can prove the overlay is wired, but
this check confirms the running oracles share a local era and actually load the
OracleSync admin plugin.
"""

import argparse
import json
import subprocess
import sys


ORACLE_CONTAINERS = ("ratio1_comm_oracle_01", "ratio1_comm_oracle_02")
NORMAL_CONTAINERS = ("ratio1_comm_node_01", "ratio1_comm_node_02")
ALL_CONTAINERS = ORACLE_CONTAINERS + NORMAL_CONTAINERS


INSPECT_CODE = r"""
import json
import os
import pickle

BASE = "/edge_node/_local_cache/_data"

def load_json(path):
  try:
    with open(path) as fh:
      return json.load(fh)
  except Exception:
    return None

local_info = load_json(f"{BASE}/local_info.json") or {}
admin_pipeline = load_json(f"{BASE}/box_configuration/streams/admin_pipeline.json") or {}
plugin_signatures = [
  plugin.get("SIGNATURE")
  for plugin in admin_pipeline.get("PLUGINS", [])
]

epochs_path = f"{BASE}/network_monitor/epochs_status.pkl"
epochs = {}
try:
  with open(epochs_path, "rb") as fh:
    raw_epochs = pickle.load(fh)
  node_states = raw_epochs.get("NODES", {})
  epochs = {
    "LAST_SYNC_EPOCH": raw_epochs.get("LAST_SYNC_EPOCH"),
    "FAULTY_EPOCHS": list(raw_epochs.get("FAULTY_EPOCHS", [])),
    "EE_GENESIS_EPOCH_DATE": raw_epochs.get("EE_GENESIS_EPOCH_DATE"),
    "EE_EPOCH_INTERVALS": raw_epochs.get("EE_EPOCH_INTERVALS"),
    "EE_EPOCH_INTERVAL_SECONDS": raw_epochs.get("EE_EPOCH_INTERVAL_SECONDS"),
    "NODES": len(node_states),
    "NODE_EPOCHS": {
      addr: {
        "epochs": dict(state.get("epochs", {})),
        "local_epochs": dict(state.get("local_epochs", {})),
        "current_epoch": (state.get("current_epoch") or {}).get("id"),
        "current_avail_seconds": round(state.get("current_avail_seconds") or 0, 3),
      }
      for addr, state in node_states.items()
    },
  }
except Exception as exc:
  epochs = {"ERROR": str(exc)}

print(json.dumps({
  "env": {
    key: os.environ.get(key)
    for key in [
      "EE_ID",
      "EE_SUPERVISOR",
      "EE_ENABLE_LOCAL_ORACLE_SYNC",
      "EE_ORACLE_SYNC_DEBUG_MODE",
      "EE_ORACLE_SYNC_BOOTSTRAP_PREVIOUS_EPOCH",
      "EE_GENESIS_EPOCH_DATE",
      "EE_EPOCH_INTERVALS",
      "EE_EPOCH_INTERVAL_SECONDS",
    ]
  },
  "local_info": {
    "alias": local_info.get("alias"),
    "address": local_info.get("address"),
    "current_epoch": (local_info.get("info") or {}).get("current_epoch"),
    "last_epochs": (local_info.get("info") or {}).get("last_epochs"),
  },
  "admin_plugins": plugin_signatures,
  "epochs": epochs,
}))
"""


def _run(args):
  return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def _inspect_container(container):
  raw = _run(["docker", "exec", container, "python3", "-c", INSPECT_CODE])
  # Some local images print shell profile warnings before Python output. Keep
  # the last non-empty line, which is the JSON payload emitted above.
  lines = [line for line in raw.splitlines() if line.strip()]
  return json.loads(lines[-1])


def _validate(require_synced=False, max_sync_lag=1):
  snapshots = {container: _inspect_container(container) for container in ALL_CONTAINERS}
  failures = []

  era_by_container = {}
  for container, snapshot in snapshots.items():
    env = snapshot["env"]
    era_by_container[container] = (
      env.get("EE_GENESIS_EPOCH_DATE"),
      env.get("EE_EPOCH_INTERVALS"),
      env.get("EE_EPOCH_INTERVAL_SECONDS"),
    )
    plugins = set(snapshot["admin_plugins"])
    if container in ORACLE_CONTAINERS:
      if "ORACLE_SYNC_01" not in plugins:
        failures.append(f"{container}: ORACLE_SYNC_01 is not active")
      if env.get("EE_ENABLE_LOCAL_ORACLE_SYNC") != "1":
        failures.append(f"{container}: local OracleSync env flag is not enabled")
      if env.get("EE_ORACLE_SYNC_DEBUG_MODE") != "1":
        failures.append(f"{container}: OracleSync debug mode is not enabled")
    else:
      if "ORACLE_SYNC_01" in plugins:
        failures.append(f"{container}: ORACLE_SYNC_01 should not run on normal node")
      if env.get("EE_ENABLE_LOCAL_ORACLE_SYNC"):
        failures.append(f"{container}: local OracleSync env flag leaked to normal node")
  if len(set(era_by_container.values())) != 1:
    failures.append(f"epoch era mismatch: {era_by_container}")

  for container in ORACLE_CONTAINERS:
    epochs = snapshots[container]["epochs"]
    if "ERROR" in epochs:
      failures.append(f"{container}: could not load epoch status: {epochs['ERROR']}")
      continue
    if epochs.get("NODES", 0) < len(ALL_CONTAINERS):
      failures.append(f"{container}: oracle epoch manager sees only {epochs.get('NODES')} nodes")
    if require_synced:
      last_sync = epochs.get("LAST_SYNC_EPOCH")
      current_epoch = snapshots[container]["local_info"].get("current_epoch")
      if not isinstance(last_sync, int) or last_sync <= 0:
        failures.append(f"{container}: LAST_SYNC_EPOCH did not advance: {last_sync}")
      if isinstance(current_epoch, int) and isinstance(last_sync, int):
        lag = current_epoch - last_sync
        if lag > max_sync_lag:
          failures.append(
            f"{container}: sync lag too large, current_epoch={current_epoch}, "
            f"LAST_SYNC_EPOCH={last_sync}, lag={lag}"
          )
      if epochs.get("FAULTY_EPOCHS"):
        failures.append(f"{container}: faulty epochs present: {epochs['FAULTY_EPOCHS']}")

  return snapshots, failures


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
    "--require-synced",
    action="store_true",
    help="Require OracleSync to have successfully advanced LAST_SYNC_EPOCH.",
  )
  parser.add_argument(
    "--max-sync-lag",
    type=int,
    default=1,
    help="Maximum allowed current_epoch - LAST_SYNC_EPOCH when --require-synced is used.",
  )
  args = parser.parse_args()

  snapshots, failures = _validate(
    require_synced=args.require_synced,
    max_sync_lag=args.max_sync_lag,
  )
  for container, snapshot in snapshots.items():
    env = snapshot["env"]
    epochs = snapshot["epochs"]
    print(
      f"{container}: plugins={snapshot['admin_plugins']} "
      f"era=({env.get('EE_GENESIS_EPOCH_DATE')}, "
      f"{env.get('EE_EPOCH_INTERVALS')}x{env.get('EE_EPOCH_INTERVAL_SECONDS')}) "
      f"current_epoch={snapshot['local_info'].get('current_epoch')} "
      f"last_sync={epochs.get('LAST_SYNC_EPOCH')} nodes={epochs.get('NODES')}"
    )

  if failures:
    print("OracleSync validation failed:")
    for failure in failures:
      print(f"- {failure}")
    return 1
  print("OracleSync validation OK.")
  return 0


if __name__ == "__main__":
  sys.exit(main())
