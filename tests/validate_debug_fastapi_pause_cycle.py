#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen


def request_json(url, timeout=2):
  with urlopen(url, timeout=timeout) as response:
    return json.load(response)


def wait_for_http(url, available, timeout):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    try:
      request_json(url)
      current = True
    except (OSError, URLError, ValueError):
      current = False
    if current == available:
      return time.monotonic()
    time.sleep(0.2)
  state = "available" if available else "unavailable"
  raise RuntimeError(f"{url} did not become {state} within {timeout}s")


def process_is_running(container, pattern):
  result = subprocess.run(
    ["docker", "exec", container, "pgrep", "-af", pattern],
    check=False,
    capture_output=True,
    text=True,
  )
  return result.returncode == 0


def wait_for_process(container, pattern, running, timeout):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if process_is_running(container, pattern) == running:
      return
    time.sleep(0.2)
  state = "running" if running else "stopped"
  raise RuntimeError(f"process {pattern!r} did not become {state} within {timeout}s")


def tunnel_ready_count(container):
  result = subprocess.run(
    ["docker", "logs", container],
    check=True,
    capture_output=True,
    text=True,
  )
  logs = result.stdout + result.stderr
  return logs.count("Cloudflare tunnel started successfully on:")


def wait_for_tunnel_ready_count(container, minimum, timeout):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    count = tunnel_ready_count(container)
    if count >= minimum:
      time.sleep(1)
      if process_is_running(container, "[c]loudflared.*127.0.0.1:3001"):
        return count
    time.sleep(0.5)
  raise RuntimeError(f"cloudflared did not reach readiness count {minimum} within {timeout}s")


def validate_pause_transition(base_url, container, pause_seconds, tunnel_count):
  health_url = f"{base_url}/openapi.json"
  unavailable_at = wait_for_http(health_url, available=False, timeout=10)
  wait_for_process(container, "[u]vicorn.*--port 3001", running=False, timeout=5)
  wait_for_process(container, "[c]loudflared.*127.0.0.1:3001", running=False, timeout=5)

  resume_timeout = pause_seconds + 20
  available_at = wait_for_http(health_url, available=True, timeout=resume_timeout)
  minimum_downtime = max(0, pause_seconds - 1)
  if available_at - unavailable_at < minimum_downtime:
    raise RuntimeError(
      f"pause lasted {available_at - unavailable_at:.2f}s, expected at least {minimum_downtime:.2f}s"
    )
  wait_for_process(container, "[u]vicorn.*--port 3001", running=True, timeout=10)
  wait_for_process(container, "[c]loudflared.*127.0.0.1:3001", running=True, timeout=10)
  return wait_for_tunnel_ready_count(container, tunnel_count + 1, timeout=30)


def validate_sequential_cycle(base_url, container, pause_seconds, tunnel_count):
  ping_url = f"{base_url}/ping"
  for request_nr in range(1, 11):
    response = request_json(ping_url)
    if response.get("result", {}).get("message") != "pong":
      raise RuntimeError(f"request {request_nr} returned an unexpected response: {response}")
  return validate_pause_transition(base_url, container, pause_seconds, tunnel_count)


def validate_concurrent_cycle(base_url, container, pause_seconds, tunnel_count):
  ping_url = f"{base_url}/ping"
  barrier = threading.Barrier(20)

  def send_request():
    barrier.wait()
    try:
      response = request_json(ping_url, timeout=10)
      return response.get("result", {}).get("message") == "pong"
    except Exception:
      return False

  with ThreadPoolExecutor(max_workers=20) as executor:
    successes = sum(executor.map(lambda _request_nr: send_request(), range(20)))
  if successes != 10:
    raise RuntimeError(f"concurrent boundary completed {successes} requests instead of exactly 10")
  return validate_pause_transition(base_url, container, pause_seconds, tunnel_count)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--base-url", default="http://127.0.0.1:3201")
  parser.add_argument("--container", default="ratio1_comm_node_01")
  parser.add_argument("--pause-seconds", type=float, default=5)
  args = parser.parse_args()

  wait_for_http(f"{args.base_url}/openapi.json", available=True, timeout=120)
  wait_for_process(args.container, "[u]vicorn.*--port 3001", running=True, timeout=10)
  wait_for_process(args.container, "[c]loudflared.*127.0.0.1:3001", running=True, timeout=30)
  tunnel_count = wait_for_tunnel_ready_count(args.container, minimum=1, timeout=30)
  tunnel_count = validate_concurrent_cycle(
    args.base_url, args.container, args.pause_seconds, tunnel_count
  )
  validate_sequential_cycle(args.base_url, args.container, args.pause_seconds, tunnel_count)
  print("Validated concurrent and sequential 10-request cycles with process and tunnel restarts.")


if __name__ == "__main__":
  main()
