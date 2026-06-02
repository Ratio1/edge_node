#!/usr/bin/env python3
import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from ratio1 import Session

from naeural_core import constants as ct
from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_PLUGIN_DATA, JOB_APP_TYPES
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin


CONTAINERS = ("deeploy_test_node_1", "deeploy_test_node_2")
APP_ID = "deeploy-delete-e2e-app"
JOB_ID = 2002
OWNER = "0xdeeploy-local-owner"
STREAM_TYPE = "DeeployTestbedStream"
PLUGIN_SIGNATURE = "DEEPLOY_TESTBED_PLUGIN"
PLUGIN_INSTANCES = ("worker-1", "worker-2")
BROKER_HOST = os.environ.get("DEEPLOY_TESTBED_MQTT_HOST", "127.0.0.1")
BROKER_PORT = int(os.environ.get("DEEPLOY_TESTBED_MQTT_PORT", "18883"))
ROOT_TOPIC = "deeploy_testbed"
POLL_TIMEOUT = int(os.environ.get("DEEPLOY_TESTBED_TIMEOUT", "120"))


def run(cmd, *, input_text=None, check=True):
  result = subprocess.run(
    cmd,
    input=input_text,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
  )
  if check and result.returncode != 0:
    raise RuntimeError(
      "Command failed: {}\nstdout:\n{}\nstderr:\n{}".format(
        " ".join(cmd), result.stdout, result.stderr
      )
    )
  return result


def docker_exec(container, *args, input_text=None, check=True):
  return run(["docker", "exec", "-i", container, *args], input_text=input_text, check=check)


def wait_for_node_info(container):
  deadline = time.time() + POLL_TIMEOUT
  last_error = None
  while time.time() < deadline:
    result = docker_exec(container, "get_node_info", check=False)
    if result.returncode == 0:
      try:
        info = json.loads(result.stdout)
        if info.get("address"):
          return info
      except json.JSONDecodeError as exc:
        last_error = exc
    else:
      last_error = result.stderr.strip() or result.stdout.strip()
    time.sleep(2)
  raise TimeoutError(f"Timed out waiting for node info from {container}: {last_error}")


def update_allowed(container, address, alias):
  line = f"{address} {alias}\n"
  docker_exec(container, "update_allowed_batch", input_text=line)


def stream_config_path(app_id):
  return f"/edge_node/_local_cache/_data/box_configuration/streams/{app_id}.json"


def stream_exists(container, app_id):
  result = docker_exec(container, "sh", "-c", f"test -f {stream_config_path(app_id)}", check=False)
  return result.returncode == 0


def read_stream_config(container, app_id):
  return read_json_file(container, stream_config_path(app_id))


def wait_for_stream_state(container, app_id, expected_exists):
  deadline = time.time() + POLL_TIMEOUT
  while time.time() < deadline:
    if stream_exists(container, app_id) == expected_exists:
      return
    time.sleep(2)
  state = "exist" if expected_exists else "be deleted"
  raise TimeoutError(f"Timed out waiting for {app_id} to {state} on {container}")


def wait_for_stream_generation(container, app_id, generation):
  deadline = time.time() + POLL_TIMEOUT
  last_generation = None
  while time.time() < deadline:
    if stream_exists(container, app_id):
      try:
        config = read_stream_config(container, app_id)
        specs = config.get("DEEPLOY_SPECS", {})
        last_generation = specs.get(DEEPLOY_KEYS.LIFECYCLE_GENERATION)
        if last_generation == generation:
          return config
      except Exception:
        pass
    time.sleep(2)
  raise TimeoutError(
    f"Timed out waiting for {app_id} generation {generation} on {container}; "
    f"last observed generation was {last_generation}"
  )


def list_received_command_files(container):
  cmd = "find /edge_node/_local_cache/_output/received_commands -type f -name '*.json' -print 2>/dev/null | sort"
  result = docker_exec(container, "sh", "-c", cmd, check=False)
  if result.returncode != 0:
    return []
  return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def read_json_file(container, path):
  result = docker_exec(container, "cat", path)
  return json.loads(result.stdout)


def count_delete_commands(container, app_id):
  count = 0
  for path in list_received_command_files(container):
    try:
      data = read_json_file(container, path)
    except Exception:
      continue
    payload = data.get("PAYLOAD")
    payload_app_id = payload.get("NAME") if isinstance(payload, dict) else payload
    if data.get("ACTION") == "DELETE_CONFIG" and payload_app_id == app_id:
      count += 1
  return count


def wait_for_delete_command_count(container, app_id, expected_count):
  deadline = time.time() + POLL_TIMEOUT
  last_count = None
  while time.time() < deadline:
    last_count = count_delete_commands(container, app_id)
    if last_count >= expected_count:
      return last_count
    time.sleep(2)
  raise TimeoutError(
    f"Timed out waiting for {expected_count} DELETE_CONFIG command(s) for {app_id} "
    f"on {container}; last observed count was {last_count}"
  )


def make_pipeline_config(app_id, node_addresses, lifecycle_generation=1, lifecycle_operation="create"):
  now = time.time()
  return {
    ct.CONFIG_STREAM.NAME: app_id,
    ct.CONFIG_STREAM.TYPE: STREAM_TYPE,
    ct.CONFIG_STREAM.LIVE_FEED: True,
    "CAP_RESOLUTION": 1,
    "URL": "",
    "OWNER": OWNER,
    "IS_DEEPLOYED": True,
    "DEEPLOY_SPECS": {
      DEEPLOY_KEYS.JOB_ID: JOB_ID,
      DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.NATIVE,
      DEEPLOY_KEYS.NR_TARGET_NODES: len(node_addresses),
      DEEPLOY_KEYS.CURRENT_TARGET_NODES: list(node_addresses),
      DEEPLOY_KEYS.DATE_CREATED: now,
      DEEPLOY_KEYS.DATE_UPDATED: now,
      DEEPLOY_KEYS.LIFECYCLE_GENERATION: lifecycle_generation,
      DEEPLOY_KEYS.LIFECYCLE_OPERATION: lifecycle_operation,
      DEEPLOY_KEYS.JOB_TAGS: ["deeploy-0003-e2e"],
      DEEPLOY_KEYS.SPARE_NODES: [],
      DEEPLOY_KEYS.ALLOW_REPLICATION_IN_THE_WILD: False,
    },
    ct.CONFIG_STREAM.PLUGINS: [
      {
        ct.CONFIG_PLUGIN.K_SIGNATURE: PLUGIN_SIGNATURE,
        ct.CONFIG_PLUGIN.K_INSTANCES: [
          {ct.CONFIG_INSTANCE.K_INSTANCE_ID: instance_id}
          for instance_id in PLUGIN_INSTANCES
        ],
      },
    ],
  }


def make_delete_payload(app_id, deeploy_specs):
  command_specs = {}
  for key in (
    DEEPLOY_KEYS.JOB_ID,
    DEEPLOY_KEYS.PROJECT_ID,
    DEEPLOY_KEYS.LIFECYCLE_GENERATION,
    DEEPLOY_KEYS.LIFECYCLE_OPERATION,
    DEEPLOY_KEYS.DATE_CREATED,
    DEEPLOY_KEYS.DATE_UPDATED,
  ):
    if key in deeploy_specs:
      command_specs[key] = copy.deepcopy(deeploy_specs[key])
  command_specs[DEEPLOY_KEYS.LIFECYCLE_OPERATION] = "delete"
  return {
    ct.CONFIG_STREAM.NAME: app_id,
    ct.CONFIG_STREAM.K_OWNER: OWNER,
    ct.CONFIG_STREAM.DEEPLOY_SPECS: command_specs,
  }


def make_discovered_instances(app_id, node_addresses, deeploy_specs):
  discovered = []
  for node in node_addresses:
    for instance_id in PLUGIN_INSTANCES:
      discovered.append({
        DEEPLOY_PLUGIN_DATA.APP_ID: app_id,
        DEEPLOY_PLUGIN_DATA.NODE: node,
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: PLUGIN_SIGNATURE,
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: instance_id,
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance": instance_id,
          "instance_conf": {},
        },
        DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: None,
        DEEPLOY_PLUGIN_DATA.DEEPLOY_SPECS: copy.deepcopy(deeploy_specs),
      })
  return discovered


class RuntimeDeleteHarness(_DeeployMixin):
  pass


def make_delete_harness(session):
  plugin = RuntimeDeleteHarness.__new__(RuntimeDeleteHarness)
  plugin.P = lambda msg, *args, **kwargs: print(f"[deeploy-delete] {msg}")
  plugin.Pd = plugin.P
  plugin.deepcopy = copy.deepcopy
  plugin.cmdapi_stop_pipeline = lambda node_address, name, command_content=None: session._send_command_delete_pipeline(
    node_address,
    command_content if command_content is not None else name,
    show_command=False,
  )
  return plugin


def main():
  node_infos = {container: wait_for_node_info(container) for container in CONTAINERS}
  node_addresses = [node_infos[container]["address"] for container in CONTAINERS]
  print(json.dumps({"nodes": node_infos}, indent=2))

  cache_dir = Path(".deeploy-testbed-sdk-cache")
  cache_dir.mkdir(exist_ok=True)
  session = Session(
    host=BROKER_HOST,
    port=BROKER_PORT,
    user="deeploy_test",
    pwd="deeploy_test",
    secured=False,
    encrypt_comms=False,
    root_topic=ROOT_TOPIC,
    name="deeploy-0003-e2e",
    auto_configuration=False,
    run_dauth=False,
    use_home_folder=False,
    local_cache_base_folder=str(cache_dir),
    local_cache_app_folder="_local_cache",
    debug=0,
    verbosity=0,
    silent=True,
    show_commands=False,
    eth_enabled=False,
  )

  try:
    for container in CONTAINERS:
      update_allowed(container, session.bc_engine.address, "deeploy_e2e")

    pipeline_config = make_pipeline_config(APP_ID, node_addresses)
    for node_address in node_addresses:
      session._send_command_create_pipeline(node_address, pipeline_config, show_command=False)

    for container in CONTAINERS:
      wait_for_stream_state(container, APP_ID, expected_exists=True)
      wait_for_stream_generation(container, APP_ID, generation=1)

    updated_pipeline_config = make_pipeline_config(
      APP_ID,
      node_addresses,
      lifecycle_generation=2,
      lifecycle_operation="update",
    )
    for node_address in node_addresses:
      session._send_command_create_pipeline(node_address, updated_pipeline_config, show_command=False)

    for container in CONTAINERS:
      wait_for_stream_generation(container, APP_ID, generation=2)

    stale_delete_counts = {
      container: count_delete_commands(container, APP_ID)
      for container in CONTAINERS
    }
    stale_payload = make_delete_payload(APP_ID, pipeline_config["DEEPLOY_SPECS"])
    for node_address in node_addresses:
      session._send_command_delete_pipeline(node_address, stale_payload, show_command=False)

    for container in CONTAINERS:
      wait_for_delete_command_count(container, APP_ID, stale_delete_counts[container] + 1)

    # The stale delete has been received; leave the node a short settle window
    # before asserting that the newer generation is still the saved config.
    time.sleep(5)
    for container in CONTAINERS:
      wait_for_stream_state(container, APP_ID, expected_exists=True)
      wait_for_stream_generation(container, APP_ID, generation=2)

    baseline_counts = {
      container: count_delete_commands(container, APP_ID)
      for container in CONTAINERS
    }

    harness = make_delete_harness(session)
    discovered = make_discovered_instances(
      APP_ID,
      node_addresses,
      updated_pipeline_config["DEEPLOY_SPECS"],
    )
    discovery_calls = []

    def discover(**kwargs):
      discovery_calls.append(kwargs)
      return discovered

    harness._discover_plugin_instances = discover
    returned = harness.delete_pipeline_from_nodes(
      app_id=APP_ID,
      owner=OWNER,
      target_nodes=0,
    )
    if returned is not discovered:
      raise AssertionError("delete_pipeline_from_nodes did not preserve discovered instance list")
    if discovery_calls != [{
      "app_id": APP_ID,
      "job_id": None,
      "owner": OWNER,
      "target_nodes": None,
    }]:
      raise AssertionError(f"Expected unfiltered discovery call; got {discovery_calls}")

    for container in CONTAINERS:
      wait_for_stream_state(container, APP_ID, expected_exists=False)

    final_counts = {
      container: count_delete_commands(container, APP_ID)
      for container in CONTAINERS
    }
    deltas = {
      container: final_counts[container] - baseline_counts[container]
      for container in CONTAINERS
    }
    if any(delta != 1 for delta in deltas.values()):
      raise AssertionError(f"Expected exactly one DELETE_CONFIG per node; got deltas {deltas}")

    print(json.dumps({
      "app_id": APP_ID,
      "node_addresses": node_addresses,
      "stale_delete_counts": stale_delete_counts,
      "baseline_delete_counts": baseline_counts,
      "final_delete_counts": final_counts,
      "delete_count_deltas": deltas,
      "discovery_calls": discovery_calls,
      "result": "ok",
    }, indent=2))
  finally:
    session.close(wait_close=True)


if __name__ == "__main__":
  sys.exit(main())
