#!/usr/bin/env python3
"""
Validate the live EMQX state for ``docker-compose_comms.yaml``.

This is a host-side probe. It intentionally checks the broker's management API
instead of inferring subscriptions from node logs, because stale sessions and
wrong QoS values are broker-state problems.
"""

import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request


API_BASE = os.environ.get("ECOMMS_EMQX_API", "http://127.0.0.1:18083")
API_USER = os.environ.get("ECOMMS_EMQX_USER", "admin")
API_PASS = os.environ.get("ECOMMS_EMQX_PASS", "public")
API_TOKEN = os.environ.get("ECOMMS_EMQX_TOKEN")
ROOT_TOPIC = os.environ.get("ECOMMS_ROOT_TOPIC", "naeural_comms_local")
CTRL_TOPIC = f"{ROOT_TOPIC}/ctrl"
EXPECTED_NODES = {
  "comm_oracle_01": "supervisor",
  "comm_oracle_02": "supervisor",
  "comm_node_01": "normal",
  "comm_node_02": "normal",
}
EXPECTED_CLIENT_MARKERS = ["COMMAND", "HEARTBE", "DEFAULT", "NOTIFIC", "IoT_Listener"]
WAIT_SECONDS = float(os.environ.get("ECOMMS_BROKER_WAIT_SECONDS", "120"))
POLL_SECONDS = float(os.environ.get("ECOMMS_BROKER_POLL_SECONDS", "2"))
_AUTH_HEADERS = None


def _login_token():
  body = json.dumps({
    "username": API_USER,
    "password": API_PASS,
  }).encode("utf-8")
  request = urllib.request.Request(
    API_BASE.rstrip("/") + "/api/v5/login",
    data=body,
    headers={"Content-Type": "application/json"},
  )
  try:
    with urllib.request.urlopen(request, timeout=10) as response:
      payload = json.loads(response.read().decode("utf-8"))
    return payload.get("token")
  except Exception:
    return None


def _auth_headers():
  global _AUTH_HEADERS
  if _AUTH_HEADERS is not None:
    return _AUTH_HEADERS
  if API_TOKEN:
    _AUTH_HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}
    return _AUTH_HEADERS
  token = _login_token()
  if token:
    # EMQX 5.x dashboard APIs use the login bearer token for broker-state
    # reads. API-key deployments can still pass ECOMMS_EMQX_TOKEN directly.
    _AUTH_HEADERS = {"Authorization": f"Bearer {token}"}
    return _AUTH_HEADERS
  basic = base64.b64encode(f"{API_USER}:{API_PASS}".encode("utf-8")).decode("ascii")
  _AUTH_HEADERS = {"Authorization": f"Basic {basic}"}
  return _AUTH_HEADERS


def _request_json(path, params=None):
  url = API_BASE.rstrip("/") + path
  if params:
    url += "?" + urllib.parse.urlencode(params)
  request = urllib.request.Request(url, headers=_auth_headers())
  with urllib.request.urlopen(request, timeout=10) as response:
    return json.loads(response.read().decode("utf-8"))


def _fetch_collection(path):
  page = 1
  result = []
  while True:
    payload = _request_json(path, {"page": page, "limit": 1000})
    data = payload.get("data", payload if isinstance(payload, list) else [])
    result.extend(data)
    meta = payload.get("meta", {})
    count = meta.get("count", len(result))
    if len(result) >= count or len(data) == 0:
      return result
    page += 1


def _client_id(row):
  return row.get("clientid") or row.get("client_id") or row.get("clientid_b") or ""


def _qos(row):
  value = row.get("qos")
  return int(value) if value is not None else None


def _metric(row, *names):
  for name in names:
    if name not in row:
      continue
    value = row.get(name)
    try:
      return int(value)
    except Exception as exc:
      raise ValueError("Metric '{}' is not an integer for client '{}': {!r}".format(
        name, _client_id(row), value
      )) from exc
  raise KeyError("Missing metric keys {} for client '{}'. Available keys: {}".format(
    names, _client_id(row), sorted(row.keys())
  ))


def _assert(condition, message, failures):
  if not condition:
    failures.append(message)


def _assert_managed_clients_present(clients, failures):
  for alias in EXPECTED_NODES:
    alias_client_ids = [_client_id(row) for row in clients if alias in _client_id(row)]
    _assert(
      len(alias_client_ids) == len(EXPECTED_CLIENT_MARKERS),
      f"{alias}: expected {len(EXPECTED_CLIENT_MARKERS)} managed clients, found {len(alias_client_ids)}: {alias_client_ids}",
      failures,
    )
    for marker in EXPECTED_CLIENT_MARKERS:
      marker_matches = [client_id for client_id in alias_client_ids if marker in client_id]
      _assert(
        len(marker_matches) == 1,
        f"{alias}: expected exactly one managed client containing '{marker}', found {marker_matches}",
        failures,
      )


def _subscription_summary(row):
  return {
    "clientid": _client_id(row),
    "topic": row.get("topic"),
    "qos": _qos(row),
  }


def _validate_state(subscriptions, clients):
  failures = []
  managed_subscriptions = [
    row for row in subscriptions
    if any(alias in _client_id(row) for alias in EXPECTED_NODES)
  ]
  _assert(
    len(managed_subscriptions) == 14,
    f"expected exactly 14 managed subscriptions, found {len(managed_subscriptions)}: {[_subscription_summary(row) for row in managed_subscriptions]}",
    failures,
  )

  for alias, role in EXPECTED_NODES.items():
    alias_subs = [row for row in managed_subscriptions if alias in _client_id(row)]
    ctrl_subs = [
      row for row in alias_subs
      if alias in _client_id(row) and row.get("topic") == CTRL_TOPIC
    ]
    command_ctrl_subs = [
      row for row in alias_subs
      if alias in _client_id(row) and "_COMMAND" in _client_id(row) and row.get("topic") == CTRL_TOPIC
    ]
    heartbeat_config_subs = [
      row for row in alias_subs
      if alias in _client_id(row) and "_HEARTBE" in _client_id(row) and str(row.get("topic", "")).endswith("/config")
    ]
    iot_payload_broadcast_subs = [
      row for row in alias_subs
      if "IoT_Listener" in _client_id(row) and row.get("topic") == f"{ROOT_TOPIC}/payloads"
    ]
    iot_payload_addressed_subs = [
      row for row in alias_subs
      if (
        "IoT_Listener" in _client_id(row)
        and str(row.get("topic", "")).startswith(f"{ROOT_TOPIC}/0xai_")
        and str(row.get("topic", "")).endswith("/payloads")
      )
    ]

    expected_alias_subscriptions = 4 if role == "supervisor" else 3
    _assert(
      len(alias_subs) == expected_alias_subscriptions,
      f"{alias}: expected exactly {expected_alias_subscriptions} managed subscriptions, found {len(alias_subs)}: {[_subscription_summary(row) for row in alias_subs]}",
      failures,
    )

    if role == "supervisor":
      _assert(len(command_ctrl_subs) == 1, f"{alias}: expected exactly one COMMAND ctrl subscription", failures)
      _assert(len(ctrl_subs) == 1, f"{alias}: expected exactly one total ctrl subscription, found {len(ctrl_subs)}", failures)
      if command_ctrl_subs:
        _assert(_qos(command_ctrl_subs[0]) == 1, f"{alias}: COMMAND ctrl QoS is not 1", failures)
    else:
      _assert(len(command_ctrl_subs) == 0, f"{alias}: normal node must not subscribe COMMAND to ctrl", failures)
      _assert(len(ctrl_subs) == 0, f"{alias}: normal node must not have any ctrl subscription: {[_client_id(row) for row in ctrl_subs]}", failures)

    _assert(len(heartbeat_config_subs) == 1, f"{alias}: expected exactly one HEARTBE config subscription", failures)
    if heartbeat_config_subs:
      _assert(_qos(heartbeat_config_subs[0]) == 2, f"{alias}: HEARTBE config QoS is not 2", failures)
    _assert(len(iot_payload_broadcast_subs) == 1, f"{alias}: expected exactly one IoT broadcast payload subscription", failures)
    if iot_payload_broadcast_subs:
      _assert(_qos(iot_payload_broadcast_subs[0]) == 0, f"{alias}: IoT broadcast payload QoS is not 0", failures)
    _assert(len(iot_payload_addressed_subs) == 1, f"{alias}: expected exactly one IoT addressed payload subscription", failures)
    if iot_payload_addressed_subs:
      _assert(_qos(iot_payload_addressed_subs[0]) == 0, f"{alias}: IoT addressed payload QoS is not 0", failures)

  max_mqueue = int(os.environ.get("ECOMMS_MAX_MQUEUE_LEN", "0"))
  max_inflight = int(os.environ.get("ECOMMS_MAX_INFLIGHT_CNT", "32"))
  managed_clients = [row for row in clients if any(alias in _client_id(row) for alias in EXPECTED_NODES)]
  managed_client_ids = [_client_id(row) for row in managed_clients]
  _assert(
    len(managed_client_ids) == len(set(managed_client_ids)),
    f"duplicate managed client ids found: {managed_client_ids}",
    failures,
  )
  _assert(
    len(managed_clients) == len(EXPECTED_NODES) * len(EXPECTED_CLIENT_MARKERS),
    f"expected {len(EXPECTED_NODES) * len(EXPECTED_CLIENT_MARKERS)} managed clients, found {len(managed_clients)}",
    failures,
  )
  _assert_managed_clients_present(managed_clients, failures)
  for row in managed_clients:
    client = _client_id(row)
    try:
      mqueue = _metric(row, "mqueue_len", "message_queue_len", "mailbox_len")
      inflight = _metric(row, "inflight_cnt", "inflight", "inflight_len")
    except (KeyError, ValueError) as exc:
      failures.append(str(exc))
      continue
    _assert(mqueue <= max_mqueue, f"{client}: mqueue_len={mqueue} > {max_mqueue}", failures)
    _assert(inflight <= max_inflight, f"{client}: inflight_cnt={inflight} > {max_inflight}", failures)

  return failures, managed_clients


def main():
  deadline = time.time() + WAIT_SECONDS
  last_failures = []
  last_managed_clients = []

  while True:
    subscriptions = _fetch_collection("/api/v5/subscriptions")
    clients = _fetch_collection("/api/v5/clients")
    failures, managed_clients = _validate_state(subscriptions, clients)
    if not failures:
      print(json.dumps({
        "subscriptions_checked": len(subscriptions),
        "managed_clients_checked": len(managed_clients),
        "ctrl_topic": CTRL_TOPIC,
        "status": "ok",
      }, indent=2))
      return 0

    last_failures = failures
    last_managed_clients = managed_clients
    if time.time() >= deadline:
      break
    time.sleep(POLL_SECONDS)

  print("Broker validation failed:", file=sys.stderr)
  for failure in last_failures:
    print(f"- {failure}", file=sys.stderr)
  return 1


if __name__ == "__main__":
  raise SystemExit(main())
