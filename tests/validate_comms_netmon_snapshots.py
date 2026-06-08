#!/usr/bin/env python3
"""
Validate saved NET_MON_01 snapshots from the local comms compose stack.

Run after the four nodes have been up long enough to exchange NET_MON_01
CURRENT_NETWORK payloads. This does not mutate nodes; it only reads the
diagnostic snapshot exposed by ``cmds/dump_netmon_status``.
"""

import json
import os
import subprocess
import sys
import time


NODES = {
  "ratio1_comm_oracle_01": ("comm_oracle_01", "supervisor"),
  "ratio1_comm_oracle_02": ("comm_oracle_02", "supervisor"),
  "ratio1_comm_node_01": ("comm_node_01", "normal"),
  "ratio1_comm_node_02": ("comm_node_02", "normal"),
}
EXPECTED_EEIDS = {eeid for eeid, _ in NODES.values()}
SNAPSHOT_PATH = "/edge_node/_local_cache/_data/netmon_status.json"
MAX_SNAPSHOT_AGE_SECONDS = int(os.environ.get("ECOMMS_MAX_SNAPSHOT_AGE_SECONDS", "60"))
MAX_LAST_SEEN_SECONDS = int(os.environ.get("ECOMMS_MAX_NETMON_LAST_SEEN_SECONDS", "60"))
WAIT_SECONDS = float(os.environ.get("ECOMMS_NETMON_SNAPSHOT_WAIT_SECONDS", "180"))
POLL_SECONDS = float(os.environ.get("ECOMMS_NETMON_SNAPSHOT_POLL_SECONDS", "2"))


def _run_json(container, command):
  output = subprocess.check_output(
    ["docker", "exec", container, command],
    text=True,
    timeout=15,
  )
  return json.loads(output)


def _snapshot_mtime(container):
  try:
    output = subprocess.check_output(
      ["docker", "exec", container, "stat", "-c", "%Y", SNAPSHOT_PATH],
      text=True,
      timeout=15,
    )
  except subprocess.CalledProcessError:
    return None
  return int(output.strip())


def _statuses_by_eeid(snapshot):
  return {
    value.get("eeid"): value
    for value in snapshot.values()
    if isinstance(value, dict)
  }


def _assert(condition, message, failures):
  if not condition:
    failures.append(message)


def _validate_once():
  failures = []
  observed = {}

  for container, (observer_eeid, observer_role) in NODES.items():
    snapshot_mtime = _snapshot_mtime(container)
    if snapshot_mtime is None:
      failures.append(f"{observer_eeid}: snapshot file is missing")
      continue
    snapshot_age = time.time() - snapshot_mtime
    _assert(
      snapshot_age <= MAX_SNAPSHOT_AGE_SECONDS,
      f"{observer_eeid}: snapshot file is stale ({snapshot_age:.1f}s old)",
      failures,
    )
    try:
      snapshot = _run_json(container, "dump_netmon_status")
    except Exception as exc:
      failures.append(f"{observer_eeid}: failed to read snapshot: {exc}")
      continue
    statuses = _statuses_by_eeid(snapshot)
    observed[observer_eeid] = sorted(k for k in statuses if k)

    missing = EXPECTED_EEIDS - set(statuses)
    _assert(not missing, f"{observer_eeid}: missing eeids {sorted(missing)}", failures)

    for target_eeid in EXPECTED_EEIDS:
      status = statuses.get(target_eeid, {})
      source = status.get("netmon_data_source", "direct")
      if observer_role == "normal" and target_eeid != observer_eeid:
        _assert(source == "summary", f"{observer_eeid}->{target_eeid}: expected summary source", failures)
        _assert(status.get("working") == "ONLINE", f"{observer_eeid}->{target_eeid}: summary working is not ONLINE", failures)
        _assert(status.get("trusted") is False, f"{observer_eeid}->{target_eeid}: summary status must be untrusted", failures)
        _assert(status.get("SCORE") == 0, f"{observer_eeid}->{target_eeid}: summary score must be zero", failures)
      else:
        _assert(source != "summary", f"{observer_eeid}->{target_eeid}: expected direct source", failures)
      last_seen = status.get("last_seen_sec")
      _assert(last_seen is not None, f"{observer_eeid}->{target_eeid}: missing last_seen_sec", failures)
      if last_seen is not None:
        try:
          last_seen = float(last_seen)
        except Exception:
          failures.append(f"{observer_eeid}->{target_eeid}: last_seen_sec={last_seen!r} is not numeric")
          continue
        _assert(
          last_seen <= MAX_LAST_SEEN_SECONDS,
          f"{observer_eeid}->{target_eeid}: last_seen_sec={last_seen} exceeds {MAX_LAST_SEEN_SECONDS}",
          failures,
        )

  return failures, observed


def main():
  deadline = time.time() + WAIT_SECONDS
  last_failures = []
  observed = {}

  while True:
    failures, observed = _validate_once()
    if not failures:
      break
    last_failures = failures
    if time.time() >= deadline:
      print("NetMon snapshot validation failed:", file=sys.stderr)
      for failure in last_failures:
        print(f"- {failure}", file=sys.stderr)
      return 1
    time.sleep(POLL_SECONDS)

  print(json.dumps({
    "nodes_checked": sorted(NODES),
    "observed_eeids": observed,
    "status": "ok",
  }, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
