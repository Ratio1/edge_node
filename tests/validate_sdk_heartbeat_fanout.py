#!/usr/bin/env python3
"""Prove SDK heartbeat modes by broker delivery, not post-delivery filtering.

Run this inside one node from ``docker-compose_comms.yaml``. The probe first
proves targeted mirroring comes from the node's persisted configuration, then
discovers one node and one NetMon publisher, starts real Ratio1 SDK sessions
for every mode, and compares EMQX delivery over one shared traffic window.
"""

import importlib.util
import json
import os
import pathlib
import tempfile
import threading
import time

import paho.mqtt.client as mqtt

from ratio1 import Session


ROOT_TOPIC = os.environ.get("ECOMMS_ROOT_TOPIC", "naeural_comms_local")
HOST = os.environ.get("ECOMMS_MQTT_HOST", "127.0.0.1")
PORT = int(os.environ.get("ECOMMS_MQTT_PORT", "18883"))
# The isolated broker accepts anonymous MQTT, but the public SDK deliberately
# requires non-empty credential fields before connecting. EMQX accepts these
# local-only placeholders while deployments can override both values.
USER = os.environ.get("ECOMMS_MQTT_USER", "ecomms")
PASSWORD = os.environ.get("ECOMMS_MQTT_PASS", "ecomms")
DISCOVERY_SECONDS = float(os.environ.get("ECOMMS_SDK_DISCOVERY_SECONDS", "90"))
MEASURE_SECONDS = float(os.environ.get("ECOMMS_SDK_MEASURE_SECONDS", "30"))
MIRROR_ENV_KEY = "EE_HEARTBEAT_TARGETED_MIRROR_ENABLED"
PERSISTED_CONFIG_PATH = pathlib.Path(os.environ.get(
  "ECOMMS_PERSISTED_CONFIG_PATH",
  "/edge_node/_local_cache/_data/box_configuration/config_app.txt",
))


def _assert_persisted_mirror_source():
  """Prove this live node mirrors from persisted config, not an env override.

  Returns
  -------
  str
    Path of the effective persisted application configuration.

  Raises
  ------
  AssertionError
    If an environment override exists or persisted mirroring is not enabled.
  """
  if MIRROR_ENV_KEY in os.environ:
    raise AssertionError(
      "Primary fanout validation must not use {}".format(MIRROR_ENV_KEY)
    )
  try:
    config = json.loads(PERSISTED_CONFIG_PATH.read_text())
    mirror_enabled = config["COMMUNICATION"]["PARAMS"][
      "HEARTBEAT_TARGETED_MIRROR_ENABLED"
    ]
  except Exception as exc:
    raise AssertionError(
      "Cannot read persisted mirror setting from {}".format(
        PERSISTED_CONFIG_PATH,
      )
    ) from exc
  if mirror_enabled is not True:
    raise AssertionError(
      "Persisted heartbeat targeted mirror must be true, got {!r}".format(
        mirror_enabled,
      )
    )
  return str(PERSISTED_CONFIG_PATH)


def _broker_module():
  path = pathlib.Path(__file__).with_name("validate_comms_broker_state.py")
  spec = importlib.util.spec_from_file_location("_ecomms_broker", path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def _mqtt_client(client_id):
  if hasattr(mqtt, "CallbackAPIVersion"):
    client = mqtt.Client(
      callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
      client_id=client_id,
      clean_session=True,
    )
  else:
    client = mqtt.Client(client_id=client_id, clean_session=True)
  client.username_pw_set(USER, PASSWORD)
  return client


def _discover_publishers():
  state = {
    "node": None,
    "summary_publisher": None,
  }
  ready = threading.Event()
  client = _mqtt_client("ecomms_sdk_discovery")

  def on_connect(connected_client, userdata, flags, reason_code, *args):
    reason_value = getattr(reason_code, "value", reason_code)
    if reason_value == 0:
      connected_client.subscribe([
        (f"{ROOT_TOPIC}/ctrl", 1),
        (f"{ROOT_TOPIC}/payloads", 0),
      ])

  def on_message(_client, _userdata, message):
    try:
      payload = json.loads(message.payload.decode("utf-8"))
    except Exception:
      return
    sender = payload.get("EE_SENDER")
    if message.topic == f"{ROOT_TOPIC}/ctrl" and sender:
      state["node"] = state["node"] or sender
    path = payload.get("EE_PAYLOAD_PATH", [None, None, None, None])
    if (
      message.topic == f"{ROOT_TOPIC}/payloads"
      and len(path) >= 3
      and str(path[1]).lower() == "admin_pipeline"
      and str(path[2]).upper() == "NET_MON_01"
      and sender
    ):
      state["summary_publisher"] = state["summary_publisher"] or sender
    if all(state.values()):
      ready.set()

  client.on_connect = on_connect
  client.on_message = on_message
  client.connect(HOST, PORT)
  client.loop_start()
  try:
    if not ready.wait(DISCOVERY_SECONDS):
      raise RuntimeError(
        "Timed out discovering heartbeat and NetMon publishers: {}".format(
          state
        )
      )
    return state
  finally:
    client.disconnect()
    client.loop_stop()


def _session(name, cache_root, **kwargs):
  return Session(
    host=HOST,
    port=PORT,
    user=USER,
    pwd=PASSWORD,
    secured=False,
    name=name,
    root_topic=ROOT_TOPIC,
    auto_configuration=False,
    run_dauth=False,
    eth_enabled=False,
    use_home_folder=False,
    local_cache_base_folder=cache_root,
    local_cache_app_folder=name,
    silent=True,
    verbosity=0,
    **kwargs,
  )


def _find_client(clients, session_name, marker):
  matches = [
    row for row in clients
    if session_name in str(row.get("clientid", ""))
    and marker in str(row.get("clientid", ""))
  ]
  if len(matches) != 1:
    raise AssertionError(
      "Expected one client for {} / {}, found {}".format(
        session_name,
        marker,
        [row.get("clientid") for row in matches],
      )
    )
  return matches[0]


def _delivery(row):
  return {
    "messages": int(row["send_msg"]),
    "bytes": int(row["send_oct"]),
  }


def _delta(before, after):
  return {
    key: after[key] - before[key]
    for key in before
  }


def _topics_by_client(subscriptions):
  result = {}
  for row in subscriptions:
    result.setdefault(row.get("clientid", ""), []).append(row.get("topic"))
  return result


def _session_topics(subscriptions, session_name):
  return [
    row.get("topic")
    for row in subscriptions
    if session_name in str(row.get("clientid", ""))
  ]


def _start_subscription_sampler(broker, interval=0.25):
  samples = []
  errors = []
  stop = threading.Event()

  def sample():
    while not stop.is_set():
      try:
        samples.append(broker._fetch_collection("/api/v5/subscriptions"))
      except Exception as exc:
        errors.append(str(exc))
      stop.wait(interval)

  thread = threading.Thread(target=sample, name="ecomms-subscription-sampler", daemon=True)
  thread.start()
  return stop, thread, samples, errors


def main():
  persisted_config_path = _assert_persisted_mirror_source()
  broker = _broker_module()
  discovered = _discover_publishers()
  selected_node = discovered["node"]
  summary_publisher = discovered["summary_publisher"]
  sessions = {}
  sampler_stop, sampler_thread, subscription_samples, sampler_errors = (
    _start_subscription_sampler(broker)
  )

  with tempfile.TemporaryDirectory(prefix="ecomms-sdk-fanout-") as cache_root:
    try:
      sessions["full_network"] = _session("ecomms_full_network", cache_root)
      unavailable_node = sessions["full_network"].bc_engine.address
      sessions.update({
        "selected_nodes": _session(
          "ecomms_selected_nodes",
          cache_root,
          heartbeat_observation_mode="selected_nodes",
          heartbeat_observation_nodes=[selected_node],
        ),
        "summary_discovery": _session(
          "ecomms_summary_discovery",
          cache_root,
          heartbeat_observation_mode="summary_discovery",
          heartbeat_summary_publishers=[summary_publisher],
        ),
        "post_delivery_filter": _session(
          "ecomms_post_delivery_filter",
          cache_root,
          filter_workers=[selected_node],
        ),
        "unavailable_selected": _session(
          "ecomms_unavailable_selected",
          cache_root,
          heartbeat_observation_mode="selected_nodes",
          heartbeat_observation_nodes=[unavailable_node],
          heartbeat_observation_timeout_seconds=5,
        ),
      })

      clients = broker._fetch_collection("/api/v5/clients")
      before_rows = {
        "full_network": _find_client(clients, "ecomms_full_network", "HEARTBE"),
        "selected_nodes": _find_client(clients, "ecomms_selected_nodes", "HEARTBE"),
        "summary_discovery": _find_client(clients, "ecomms_summary_discovery", "HEARTBE"),
        "post_delivery_filter": _find_client(clients, "ecomms_post_delivery_filter", "HEARTBE"),
        "unavailable_selected": _find_client(clients, "ecomms_unavailable_selected", "HEARTBE"),
      }
      before = {name: _delivery(row) for name, row in before_rows.items()}
      time.sleep(MEASURE_SECONDS)
      sampler_stop.set()
      sampler_thread.join(timeout=5.0)
      if sampler_thread.is_alive():
        raise RuntimeError("Subscription sampler did not stop")
      if sampler_errors:
        raise RuntimeError("Subscription sampler failed: {}".format(sampler_errors))

      clients = broker._fetch_collection("/api/v5/clients")
      subscriptions = broker._fetch_collection("/api/v5/subscriptions")
      after_rows = {
        name: _find_client(clients, row["clientid"].split("_HEARTBE")[0], "HEARTBE")
        for name, row in before_rows.items()
      }
      after = {name: _delivery(row) for name, row in after_rows.items()}
      delivery = {name: _delta(before[name], after[name]) for name in before}
      topics = _topics_by_client(subscriptions)

      full_id = before_rows["full_network"]["clientid"]
      selected_id = before_rows["selected_nodes"]["clientid"]
      summary_id = before_rows["summary_discovery"]["clientid"]
      negative_id = before_rows["post_delivery_filter"]["clientid"]
      unavailable_id = before_rows["unavailable_selected"]["clientid"]
      global_ctrl = f"{ROOT_TOPIC}/ctrl"
      targeted_ctrl = f"{ROOT_TOPIC}/ctrl/{selected_node}"
      unavailable_ctrl = f"{ROOT_TOPIC}/ctrl/{unavailable_node}"

      assert topics.get(full_id) == [global_ctrl], topics.get(full_id)
      assert topics.get(selected_id) == [targeted_ctrl], topics.get(selected_id)
      assert global_ctrl not in topics.get(selected_id, [])
      assert topics.get(summary_id, []) == [], topics.get(summary_id)
      assert topics.get(negative_id) == [global_ctrl], topics.get(negative_id)
      assert topics.get(unavailable_id) == [unavailable_ctrl], topics.get(unavailable_id)
      for sample in subscription_samples:
        for reduced_name in [
          "ecomms_selected_nodes",
          "ecomms_summary_discovery",
          "ecomms_unavailable_selected",
        ]:
          sampled_topics = _session_topics(sample, reduced_name)
          assert global_ctrl not in sampled_topics, {
            "session": reduced_name,
            "topics": sampled_topics,
          }
      assert delivery["full_network"]["messages"] > delivery["selected_nodes"]["messages"] > 0
      assert delivery["summary_discovery"]["messages"] == 0
      assert delivery["unavailable_selected"]["messages"] == 0
      assert delivery["post_delivery_filter"]["messages"] > delivery["selected_nodes"]["messages"]
      assert delivery["full_network"]["bytes"] > delivery["selected_nodes"]["bytes"] > 0

      statuses = {
        name: session.get_heartbeat_observation_status()
        for name, session in sessions.items()
      }
      assert statuses["selected_nodes"]["state"] == "ready", statuses
      assert statuses["selected_nodes"]["accepted_heartbeats"] > 0, statuses
      assert statuses["selected_nodes"]["accepted_summaries"] == 0, statuses
      assert statuses["selected_nodes"]["last_valid_sender"] == selected_node, statuses
      assert statuses["selected_nodes"]["last_valid_age_seconds"] <= MEASURE_SECONDS, statuses
      assert statuses["summary_discovery"]["state"] == "ready", statuses
      assert statuses["summary_discovery"]["accepted_summaries"] > 0, statuses
      assert statuses["summary_discovery"]["last_valid_sender"] == summary_publisher, statuses
      assert statuses["summary_discovery"]["last_valid_age_seconds"] <= MEASURE_SECONDS, statuses
      assert statuses["unavailable_selected"]["state"] == "degraded", statuses
      assert statuses["unavailable_selected"]["accepted_heartbeats"] == 0, statuses
      assert statuses["unavailable_selected"]["reason"] == "targeted_heartbeat_timeout", statuses

      print(json.dumps({
        "status": "ok",
        "persisted_mirror_config": persisted_config_path,
        "selected_node": selected_node,
        "summary_publisher": summary_publisher,
        "unavailable_node": unavailable_node,
        "delivery": delivery,
        "subscription_samples": len(subscription_samples),
        "observation_status": statuses,
      }, indent=2, default=str))
      return 0
    finally:
      sampler_stop.set()
      sampler_thread.join(timeout=5.0)
      for session in sessions.values():
        session.close(wait_close=True)


if __name__ == "__main__":
  raise SystemExit(main())
