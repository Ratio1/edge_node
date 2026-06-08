#!/usr/bin/env python3
"""
Validate live NetMon API behavior through the local-only FastAPI probe.

Run this only against ``docker-compose_comms.yaml``. The probe plugin is wired
by ``.config_startup_comms.json`` and exposes read-only calls to the in-process
``NetworkMonitor`` object on each node.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request


NODES = {
  "comm_oracle_01": {"role": "supervisor", "port": 3101},
  "comm_oracle_02": {"role": "supervisor", "port": 3102},
  "comm_node_01": {"role": "normal", "port": 3103},
  "comm_node_02": {"role": "normal", "port": 3104},
}
EXPECTED_EEIDS = set(NODES)
MAX_LAST_SEEN_SECONDS = int(os.environ.get("ECOMMS_MAX_NETMON_LAST_SEEN_SECONDS", "60"))
WAIT_SECONDS = float(os.environ.get("ECOMMS_NETMON_FASTAPI_WAIT_SECONDS", "180"))
POLL_SECONDS = float(os.environ.get("ECOMMS_NETMON_FASTAPI_POLL_SECONDS", "2"))


def _url(observer_eeid, endpoint, query=None):
  port = NODES[observer_eeid]["port"]
  url = f"http://127.0.0.1:{port}/{endpoint}"
  if query:
    url += "?" + urllib.parse.urlencode(query)
  return url


def _unwrap(payload):
  if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
    result = payload["result"]
    if result.get("ok") is True or "observer" in result:
      return result
  return payload


def _get_json(observer_eeid, endpoint, query=None, timeout=20):
  request = urllib.request.Request(_url(observer_eeid, endpoint, query=query))
  with urllib.request.urlopen(request, timeout=timeout) as response:
    return _unwrap(json.loads(response.read().decode("utf-8")))


def _method(probe, name):
  return probe.get("methods", {}).get(name, {})


def _value(probe, name, default=None):
  data = _method(probe, name)
  if data.get("ok") is not True:
    return default
  return data.get("value", default)


def _method_ok(probe, name):
  return _method(probe, name).get("ok") is True


def _history_timestamps(probe):
  history = _value(probe, "history", {})
  if not isinstance(history, dict):
    return []
  timestamps = history.get("timestamps")
  return timestamps if isinstance(timestamps, list) else []


def _today_heartbeats(probe):
  today = _value(probe, "today_heartbeats", [])
  return today if isinstance(today, list) else []


def _last_heartbeat(probe):
  heartbeat = _value(probe, "last_heartbeat", {})
  return heartbeat if isinstance(heartbeat, dict) else {}


def _status(probe):
  status = _value(probe, "status", {})
  return status if isinstance(status, dict) else {}


def _assert(condition, message, failures):
  if not condition:
    failures.append(message)


def _probe_seen_eeids(observer_eeid):
  payload = _get_json(observer_eeid, "probe_nodes")
  statuses = payload.get("nodes_status", {})
  if statuses.get("ok") is not True:
    return set(), payload
  values = statuses.get("value", {})
  if not isinstance(values, dict):
    return set(), payload
  seen = {
    item.get("eeid")
    for item in values.values()
    if isinstance(item, dict)
  }
  return {eeid for eeid in seen if eeid}, payload


def _wait_for_probe_matrix():
  deadline = time.time() + WAIT_SECONDS
  last_seen = {}
  last_errors = []
  while time.time() < deadline:
    ready = True
    last_errors = []
    for observer_eeid in EXPECTED_EEIDS:
      try:
        seen, _ = _probe_seen_eeids(observer_eeid)
      except Exception as exc:
        ready = False
        last_errors.append(f"{observer_eeid}: {exc}")
        continue
      last_seen[observer_eeid] = sorted(seen)
      if not EXPECTED_EEIDS.issubset(seen):
        ready = False
    if ready:
      return True, last_seen, []
    time.sleep(POLL_SECONDS)
  return False, last_seen, last_errors


def _validate_probe(observer_eeid, target_eeid, probe, failures):
  observer_role = NODES[observer_eeid]["role"]
  target_is_self = observer_eeid == target_eeid
  summary_expected = observer_role == "normal" and not target_is_self

  observer = probe.get("observer", {})
  _assert(
    observer.get("eeid") == observer_eeid,
    f"{observer_eeid}->{target_eeid}: wrong observer eeid {observer.get('eeid')!r}",
    failures,
  )
  _assert(
    bool(observer.get("is_supervisor")) is (observer_role == "supervisor"),
    f"{observer_eeid}->{target_eeid}: wrong observer supervisor flag {observer.get('is_supervisor')!r}",
    failures,
  )
  _assert(
    str(observer.get("addr", "")).startswith("0xai_"),
    f"{observer_eeid}->{target_eeid}: observer address is not prefixed: {observer.get('addr')!r}",
    failures,
  )

  target = probe.get("target", {})
  target_eeid_result = target.get("eeid", {})
  prefixed_addr = target.get("addr_from_eeid_prefixed", {})
  unprefixed_addr = target.get("addr_from_eeid_unprefixed", {})
  _assert(target_eeid_result.get("ok") is True, f"{observer_eeid}->{target_eeid}: eeid lookup failed", failures)
  _assert(
    target_eeid_result.get("value") == target_eeid,
    f"{observer_eeid}->{target_eeid}: resolved eeid {target_eeid_result.get('value')!r}",
    failures,
  )
  _assert(
    prefixed_addr.get("ok") is True and str(prefixed_addr.get("value", "")).startswith("0xai_"),
    f"{observer_eeid}->{target_eeid}: prefixed address lookup failed: {prefixed_addr}",
    failures,
  )
  _assert(
    unprefixed_addr.get("ok") is True and not str(unprefixed_addr.get("value", "")).lower().startswith(("0xai_", "aixp_")),
    f"{observer_eeid}->{target_eeid}: unprefixed address lookup failed: {unprefixed_addr}",
    failures,
  )

  for method in (
    "info_available",
    "status",
    "simple_status",
    "last_seen_sec",
    "is_online_direct_default",
    "is_online_summary_allowed",
    "is_available",
    "is_accessible",
    "last_heartbeat",
    "history",
    "today_heartbeats",
    "pipelines",
    "apps",
    "is_supervisor",
    "whitelist",
    "is_secured",
    "version",
    "py_ver",
    "remote_time",
    "deploy_type",
    "local_tz",
    "local_utc",
    "r1fs_id",
    "r1fs_online",
    "r1fs_relay",
    "comm_relay",
  ):
    _assert(_method_ok(probe, method), f"{observer_eeid}->{target_eeid}: {method} failed: {_method(probe, method)}", failures)

  _assert(
    _value(probe, "info_available") is True,
    f"{observer_eeid}->{target_eeid}: info_available is not true",
    failures,
  )
  last_seen = _value(probe, "last_seen_sec")
  _assert(isinstance(last_seen, (int, float)), f"{observer_eeid}->{target_eeid}: last_seen is not numeric", failures)
  if isinstance(last_seen, (int, float)):
    _assert(
      last_seen <= MAX_LAST_SEEN_SECONDS,
      f"{observer_eeid}->{target_eeid}: last_seen={last_seen} exceeds {MAX_LAST_SEEN_SECONDS}",
      failures,
    )

  status = _status(probe)
  source = status.get("netmon_data_source", "direct")
  heartbeat = _last_heartbeat(probe)
  history_timestamps = _history_timestamps(probe)
  today_heartbeats = _today_heartbeats(probe)

  if summary_expected:
    _assert(source == "summary", f"{observer_eeid}->{target_eeid}: expected summary status, got {source!r}", failures)
    _assert(status.get("working") == "ONLINE", f"{observer_eeid}->{target_eeid}: summary working is not ONLINE", failures)
    _assert(_value(probe, "simple_status") == "ONLINE", f"{observer_eeid}->{target_eeid}: summary simple_status is not ONLINE", failures)
    _assert(
      _value(probe, "is_online_summary_allowed") is True,
      f"{observer_eeid}->{target_eeid}: summary-allowed online predicate is not true",
      failures,
    )
    _assert(status.get("trusted") is False, f"{observer_eeid}->{target_eeid}: summary status must be untrusted", failures)
    _assert(status.get("SCORE") == 0, f"{observer_eeid}->{target_eeid}: summary score must be zero", failures)
    _assert(heartbeat == {}, f"{observer_eeid}->{target_eeid}: summary-only peer exposed direct heartbeat", failures)
    _assert(history_timestamps == [], f"{observer_eeid}->{target_eeid}: summary-only peer exposed heartbeat history", failures)
    _assert(today_heartbeats == [], f"{observer_eeid}->{target_eeid}: summary-only peer exposed today's heartbeats", failures)
    _assert(
      _value(probe, "is_available") is False,
      f"{observer_eeid}->{target_eeid}: summary-only peer must not be direct-heartbeat available",
      failures,
    )
    _assert(
      _value(probe, "is_accessible") is False,
      f"{observer_eeid}->{target_eeid}: summary-only peer must not be direct-heartbeat accessible",
      failures,
    )
    _assert(
      _value(probe, "is_online_direct_default") is False,
      f"{observer_eeid}->{target_eeid}: default online predicate must remain direct-heartbeat-only",
      failures,
    )
    getter_to_status = {
      "version": "version",
      "py_ver": "py_ver",
      "remote_time": "last_remote_time",
      "deploy_type": "deployment",
      "local_tz": "node_tz",
      "local_utc": "node_utc",
      "r1fs_id": "r1fs_id",
      "r1fs_online": "r1fs_online",
      "r1fs_relay": "r1fs_relay",
      "comm_relay": "comm_relay",
    }
    # These display fields must be present in NET_CONFIG_MONITOR summaries;
    # otherwise a getter could silently succeed from the wrong source. Some R1FS
    # fields are legitimately null in this isolated testbed before R1FS warms up.
    for status_key in (
      "version",
      "py_ver",
      "last_remote_time",
      "deployment",
      "node_tz",
      "node_utc",
      "r1fs_id",
      "r1fs_online",
      "r1fs_relay",
      "comm_relay",
    ):
      _assert(
        status_key in status,
        f"{observer_eeid}->{target_eeid}: summary status is missing {status_key}",
        failures,
      )
    for getter_name, status_key in getter_to_status.items():
      if status_key in status:
        _assert(
          _value(probe, getter_name) == status.get(status_key),
          f"{observer_eeid}->{target_eeid}: {getter_name}={_value(probe, getter_name)!r} disagrees with status {status_key}={status.get(status_key)!r}",
          failures,
        )
  else:
    _assert(source != "summary", f"{observer_eeid}->{target_eeid}: expected direct status, got summary", failures)
    _assert(bool(heartbeat), f"{observer_eeid}->{target_eeid}: direct path has empty last heartbeat", failures)
    _assert(bool(history_timestamps), f"{observer_eeid}->{target_eeid}: direct path has empty history", failures)

  expected_supervisor = NODES[target_eeid]["role"] == "supervisor"
  _assert(
    _value(probe, "is_supervisor") is expected_supervisor,
    f"{observer_eeid}->{target_eeid}: wrong supervisor flag",
    failures,
  )
  return


def main():
  ready, observed, errors = _wait_for_probe_matrix()
  if not ready:
    print("NetMon FastAPI probe matrix did not become ready.", file=sys.stderr)
    print(json.dumps({"observed": observed, "errors": errors}, indent=2), file=sys.stderr)
    return 1

  failures = []
  checked = []
  for observer_eeid in sorted(EXPECTED_EEIDS):
    for target_eeid in sorted(EXPECTED_EEIDS):
      probe = _get_json(observer_eeid, "probe_node", query={"target_eeid": target_eeid})
      _validate_probe(observer_eeid, target_eeid, probe, failures)
      checked.append(f"{observer_eeid}->{target_eeid}")

  if failures:
    print("NetMon FastAPI API validation failed:", file=sys.stderr)
    for failure in failures:
      print(f"- {failure}", file=sys.stderr)
    return 1

  print(json.dumps({
    "checks": checked,
    "observed": observed,
    "status": "ok",
  }, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
