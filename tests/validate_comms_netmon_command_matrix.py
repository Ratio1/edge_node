#!/usr/bin/env python3
"""
Exercise the live NET_MON_01 command API across the local comms compose stack.

The SDK probe has its own temporary address, so the isolated testbed does not
authorize it by default. This script installs a narrowly-scoped whitelist entry
for one generated session id, sends read-only NET_MON_01 requests, and restores
each container whitelist exactly as it was found.
"""

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKTREE_ROOT = REPO_ROOT.parent
for sibling in ("naeural_client", "naeural_core"):
  sibling_path = WORKTREE_ROOT / sibling
  if sibling_path.is_dir():
    sys.path.insert(0, str(sibling_path))

from ratio1 import Session  # noqa: E402


NODES = {
  "ratio1_comm_oracle_01": "comm_oracle_01",
  "ratio1_comm_oracle_02": "comm_oracle_02",
  "ratio1_comm_node_01": "comm_node_01",
  "ratio1_comm_node_02": "comm_node_02",
}
EXPECTED_ALIASES = set(NODES.values())
WHITELIST_PATH = "/edge_node/_local_cache/whitelist_commands.json"
SESSION_ID = f"ecomms-netmon-matrix-{uuid.uuid4()}"
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("ECOMMS_NETMON_COMMAND_TIMEOUT_SECONDS", "12"))
DISCOVERY_TIMEOUT_SECONDS = float(os.environ.get("ECOMMS_NETMON_COMMAND_DISCOVERY_SECONDS", "20"))
REQUEST_ATTEMPTS = int(os.environ.get("ECOMMS_NETMON_COMMAND_ATTEMPTS", "2"))


def _docker(container, args, *, input_text=None, timeout=15, check=True):
  return subprocess.run(
    ["docker", "exec", "-i", container, *args],
    input=input_text,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout=timeout,
    check=check,
  )


def _read_whitelist(container):
  exists = _docker(
    container,
    ["/bin/sh", "-c", f"test -f {WHITELIST_PATH}"],
    check=False,
  ).returncode == 0
  if not exists:
    return False, None
  result = _docker(container, ["/bin/sh", "-c", f"cat {WHITELIST_PATH}"])
  return True, result.stdout


def _write_whitelist(container, text):
  _docker(
    container,
    ["/bin/sh", "-c", f"cat > {WHITELIST_PATH}"],
    input_text=text,
  )


def _restore_whitelists(backups):
  for container, (existed, raw_text) in backups.items():
    if existed:
      _write_whitelist(container, raw_text)
    else:
      _docker(container, ["/bin/sh", "-c", f"rm -f {WHITELIST_PATH}"], check=False)


def _install_matrix_whitelist():
  backups = {}
  whitelist_entry = {
    "ACTION": "UPDATE_PIPELINE_INSTANCE",
    "SESSION_ID": SESSION_ID,
    "PAYLOAD": {
      "NAME": "admin_pipeline",
      "SIGNATURE": "NET_MON_01",
      "INSTANCE_ID": "NET_MON_01_INST",
    },
  }
  try:
    for container in NODES:
      existed, raw_text = _read_whitelist(container)
      backups[container] = (existed, raw_text)
      if existed and raw_text and raw_text.strip():
        entries = json.loads(raw_text)
      else:
        entries = []
      if whitelist_entry not in entries:
        entries.append(whitelist_entry)
      _write_whitelist(container, json.dumps(entries, indent=2))
  except Exception:
    _restore_whitelists(backups)
    raise
  return backups


def _response_matches(response, request_id):
  params = response.get("COMMAND_PARAMS", {})
  return isinstance(params, dict) and params.get("SDK_REQUEST") == request_id


def _wait_for_response(responses, request_id, timeout):
  deadline = time.time() + timeout
  while time.time() < deadline:
    with responses["lock"]:
      response = responses["by_request"].get(request_id)
    if response is not None:
      return response
    time.sleep(0.1)
  return None


def _assert_response(response, observer_alias, target_alias, request_type, failures):
  if response is None:
    failures.append(f"{observer_alias}->{target_alias}:{request_type}: no response")
    return

  if response.get("REQUEST") != request_type:
    failures.append(
      f"{observer_alias}->{target_alias}:{request_type}: wrong response request {response.get('REQUEST')!r}"
    )
  if response.get("E2_TARGET_ID") != target_alias:
    failures.append(
      f"{observer_alias}->{target_alias}:{request_type}: wrong target id {response.get('E2_TARGET_ID')!r}"
    )
  if not isinstance(response.get("CALL_HISTORY_TIME"), (int, float)):
    failures.append(f"{observer_alias}->{target_alias}:{request_type}: missing numeric CALL_HISTORY_TIME")

  if request_type == "history":
    history = response.get("NODE_HISTORY")
    if not isinstance(history, dict) or "timestamps" not in history:
      failures.append(f"{observer_alias}->{target_alias}:history: invalid NODE_HISTORY shape")
  elif request_type == "last_config":
    if "E2_PIPELINES" not in response:
      failures.append(f"{observer_alias}->{target_alias}:last_config: missing E2_PIPELINES key")


def _make_session(responses):
  def on_payload(_session, _node_addr, pipeline, signature, instance, payload):
    if pipeline != "admin_pipeline" or signature != "NET_MON_01" or instance != "NET_MON_01_INST":
      return
    data = dict(payload)
    params = data.get("COMMAND_PARAMS", {})
    if not isinstance(params, dict):
      return
    request_id = params.get("SDK_REQUEST")
    if request_id is None:
      return
    with responses["lock"]:
      responses["by_request"][request_id] = data

  config = {
    "USER": "",
    "PASS": "",
    "HOST": os.environ.get("ECOMMS_MQTT_HOST", "127.0.0.1"),
    "PORT": int(os.environ.get("ECOMMS_MQTT_PORT", "18883")),
    "SECURED": False,
  }
  return Session(
    name="ecomms_netmon_matrix",
    config=config,
    root_topic=os.environ.get("ECOMMS_ROOT_TOPIC", "naeural_comms_local"),
    subtopic="address",
    encrypt_comms=False,
    auto_configuration=False,
    run_dauth=False,
    use_home_folder=False,
    eth_enabled=False,
    silent=True,
    debug=0,
    on_payload=on_payload,
  )


def _discover_aliases(session):
  deadline = time.time() + DISCOVERY_TIMEOUT_SECONDS
  aliases = {}
  while time.time() < deadline:
    nodes = session.get_active_nodes()
    aliases = {
      session.get_node_alias(node): node
      for node in nodes
      if session.get_node_alias(node) is not None
    }
    if EXPECTED_ALIASES.issubset(aliases):
      return aliases
    time.sleep(0.5)
  return aliases


def main():
  backups = _install_matrix_whitelist()
  responses = {"by_request": {}, "lock": threading.Lock()}
  session = None
  failures = []
  checked = []

  try:
    session = _make_session(responses)
    aliases = _discover_aliases(session)
    missing = EXPECTED_ALIASES - set(aliases)
    if missing:
      failures.append(f"missing active aliases {sorted(missing)}")
    else:
      for observer_alias in sorted(EXPECTED_ALIASES):
        observer_addr = aliases[observer_alias]
        for target_alias in sorted(EXPECTED_ALIASES):
          target_addr = aliases[target_alias]
          for request_type in ("history", "last_config"):
            response = None
            # Fresh local containers can discover MQTT peers before every
            # command handler has fully warmed up. Retry the same logical
            # read-only request once so persistent routing defects still fail.
            for attempt in range(REQUEST_ATTEMPTS):
              request_id = str(uuid.uuid4())
              command = {
                "node": target_alias,
                "addr": target_addr,
                "request": request_type,
                "options": {"time_window_hours": 1, "step": 999},
                "SDK_REQUEST": request_id,
              }
              session._send_command_instance_command(
                worker=observer_addr,
                pipeline_name="admin_pipeline",
                signature="NET_MON_01",
                instance_id="NET_MON_01_INST",
                command=command,
                session_id=SESSION_ID,
              )
              response = _wait_for_response(responses, request_id, REQUEST_TIMEOUT_SECONDS)
              if response is not None or attempt + 1 >= REQUEST_ATTEMPTS:
                break
              time.sleep(1)
            _assert_response(response, observer_alias, target_alias, request_type, failures)
            checked.append(f"{observer_alias}->{target_alias}:{request_type}")
  finally:
    if session is not None:
      session.close(wait_close=True)
    _restore_whitelists(backups)

  if failures:
    print("NET_MON_01 command matrix validation failed:", file=sys.stderr)
    for failure in failures:
      print(f"- {failure}", file=sys.stderr)
    return 1

  print(json.dumps({
    "requests_checked": len(checked),
    "session_id": SESSION_ID,
    "status": "ok",
  }, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
