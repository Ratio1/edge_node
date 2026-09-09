#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from ratio1 import Session

from naeural_core import constants as ct
from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, JOB_APP_TYPES


CONTAINERS = ("per-node-llm-e2e-per_node_llm_node_1-1", "per-node-llm-e2e-per_node_llm_node_2-1")
API_URLS = ("http://127.0.0.1:18101", "http://127.0.0.1:18102")
MODEL_ALIASES = ("llama-1b", "qwen-0.8b")
APP_ID = "per-node-llm-e2e-app"
BROKER_HOST = os.environ.get("PER_NODE_LLM_MQTT_HOST", "127.0.0.1")
BROKER_PORT = int(os.environ.get("PER_NODE_LLM_MQTT_PORT", "18884"))
POLL_TIMEOUT = int(os.environ.get("PER_NODE_LLM_TIMEOUT", "900"))
ROOT_TOPIC = "deeploy_testbed"


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


def update_allowed(container, entries):
  input_text = "".join(f"{address} {alias}\n" for address, alias in entries)
  docker_exec(container, "update_allowed_batch", input_text=input_text)


def wait_for_stream(container):
  path = f"/edge_node/_local_cache/_data/box_configuration/streams/{APP_ID}.json"
  deadline = time.time() + POLL_TIMEOUT
  while time.time() < deadline:
    if docker_exec(container, "test", "-f", path, check=False).returncode == 0:
      return
    time.sleep(2)
  raise TimeoutError(f"Timed out waiting for {APP_ID} on {container}")


def request_json(url, method="GET", payload=None, timeout=30):
  body = None if payload is None else json.dumps(payload).encode("utf-8")
  request = urllib.request.Request(
    url,
    data=body,
    method=method,
    headers={"Content-Type": "application/json"},
  )
  with urllib.request.urlopen(request, timeout=timeout) as response:
    return json.loads(response.read().decode("utf-8"))


def wait_for_api(base_url):
  deadline = time.time() + POLL_TIMEOUT
  last_error = None
  while time.time() < deadline:
    try:
      result = request_json(f"{base_url}/health", timeout=5)
      status = result.get("status") or result.get("result", {}).get("status")
      if status:
        return result
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
      last_error = exc
    time.sleep(3)
  raise TimeoutError(f"Timed out waiting for LLM API {base_url}: {last_error}")


def make_pipeline_config(node_addresses):
  now = time.time()
  base_instance = {
    "INSTANCE_ID": "llm-api",
    "AI_ENGINE": "llama_cpp_small",
    "STARTUP_AI_ENGINE_PARAMS": {
      "MODEL_PATH": "/models/model-a.gguf",
      "MODEL_N_CTX": 1024,
      "N_THREADS": 2,
      "N_GPU_LAYERS": 0,
    },
    "SERVED_MODELS": [MODEL_ALIASES[0]],
    "PORT": 18080,
    "TUNNEL_ENGINE_ENABLED": False,
    "REQUEST_TIMEOUT": 600,
    "REQUEST_BALANCING_ENABLED": True,
    "REQUEST_BALANCING_GROUP": "per-node-llm-e2e",
    "REQUEST_BALANCING_CAPACITY": 1,
    "REQUEST_BALANCING_ANNOUNCE_PERIOD": 2,
    "REQUEST_BALANCING_CAPACITY_REFRESH_PERIOD": 5,
    "REQUEST_BALANCING_CAPACITY_REFRESH_JITTER_SECONDS": 0,
    "REQUEST_BALANCING_PEER_STALE_SECONDS": 30,
    "REQUEST_BALANCING_MAILBOX_POLL_PERIOD": 0.25,
    "CHAINSTORE_PEERS": list(node_addresses),
    "PER_NODE_TARGET_NODES": list(node_addresses),
    "PER_NODE_CONFIG": {
      "byNode": {
        node_addresses[1]: {
          "AI_ENGINE": "llama_cpp_medium",
          "STARTUP_AI_ENGINE_PARAMS": {
            "MODEL_PATH": "/models/model-b.gguf",
            "MODEL_N_CTX": 1024,
            "N_THREADS": 2,
            "N_GPU_LAYERS": 0,
          },
          "SERVED_MODELS": [MODEL_ALIASES[1]],
        },
      },
    },
  }
  return {
    ct.CONFIG_STREAM.NAME: APP_ID,
    ct.CONFIG_STREAM.TYPE: "Loopback",
    ct.CONFIG_STREAM.LIVE_FEED: True,
    "CAP_RESOLUTION": 10,
    "URL": None,
    "IS_DEEPLOYED": True,
    "DEEPLOY_SPECS": {
      DEEPLOY_KEYS.JOB_ID: 250805,
      DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.NATIVE,
      DEEPLOY_KEYS.NR_TARGET_NODES: len(node_addresses),
      DEEPLOY_KEYS.CURRENT_TARGET_NODES: list(node_addresses),
      DEEPLOY_KEYS.DATE_CREATED: now,
      DEEPLOY_KEYS.DATE_UPDATED: now,
      DEEPLOY_KEYS.JOB_TAGS: ["per-node-config", "model-routing", "local-e2e"],
      DEEPLOY_KEYS.SPARE_NODES: [],
      DEEPLOY_KEYS.ALLOW_REPLICATION_IN_THE_WILD: False,
    },
    ct.CONFIG_STREAM.PLUGINS: [{
      ct.CONFIG_PLUGIN.K_SIGNATURE: "LLM_INFERENCE_API",
      ct.CONFIG_PLUGIN.K_INSTANCES: [base_instance],
    }],
  }


def predict(base_url, model):
  started = time.time()
  envelope = request_json(
    f"{base_url}/predict",
    method="POST",
    timeout=POLL_TIMEOUT,
    payload={
      "model": model,
      "messages": [{"role": "user", "content": "Reply with one short greeting."}],
      "temperature": 0.0,
      "max_tokens": 16,
    },
  )
  response = envelope.get("result", envelope)
  return {"elapsed_seconds": time.time() - started, "response": response}


def main():
  node_infos = {container: wait_for_node_info(container) for container in CONTAINERS}
  node_addresses = [node_infos[container]["address"] for container in CONTAINERS]

  cache_dir = Path(tempfile.mkdtemp(prefix="per-node-llm-e2e-sdk-"))
  session = Session(
    host=BROKER_HOST,
    port=BROKER_PORT,
    user="per_node_llm",
    pwd="per_node_llm",
    secured=False,
    encrypt_comms=False,
    root_topic=ROOT_TOPIC,
    name="per-node-llm-e2e",
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
    for idx, container in enumerate(CONTAINERS):
      update_allowed(container, [
        (session.bc_engine.address, "per_node_e2e"),
        (node_addresses[1 - idx], f"peer_{1 - idx}"),
      ])

    pipeline = make_pipeline_config(node_addresses)
    for node_address in node_addresses:
      session._send_command_create_pipeline(node_address, pipeline, show_command=False)
    for container in CONTAINERS:
      wait_for_stream(container)
    health = [wait_for_api(url) for url in API_URLS]

    cases = [
      ("node1-local-model-a", API_URLS[0], MODEL_ALIASES[0], node_addresses[0]),
      ("node2-local-model-b", API_URLS[1], MODEL_ALIASES[1], node_addresses[1]),
      ("node1-routes-model-b", API_URLS[0], MODEL_ALIASES[1], node_addresses[1]),
      ("node2-routes-model-a", API_URLS[1], MODEL_ALIASES[0], node_addresses[0]),
    ]
    results = []
    for name, url, model, expected_executor in cases:
      result = predict(url, model)
      executor = result["response"].get("EXECUTOR_NODE_ADDR")
      if executor != expected_executor:
        raise AssertionError(
          f"{name} expected executor {expected_executor}, got {executor}: {result['response']}"
        )
      result.update(name=name, requested_model=model, expected_executor=expected_executor)
      results.append(result)

    evidence = {
      "timestamp_utc": datetime.now(timezone.utc).isoformat(),
      "nodes": node_infos,
      "health": health,
      "cases": results,
      "result": "pass",
    }
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "latest.json"
    output_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))
  finally:
    session.close(wait_close=True)
    shutil.rmtree(cache_dir, ignore_errors=True)


if __name__ == "__main__":
  sys.exit(main())
