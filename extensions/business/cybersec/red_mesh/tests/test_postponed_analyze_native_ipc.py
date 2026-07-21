import asyncio
import importlib.util
import inspect
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[5]
FRAMEWORK_PACKAGE = REPO_ROOT / "naeural_core" / "naeural_core"
IPC_MANAGER_PATH = FRAMEWORK_PACKAGE / "utils" / "uvicorn_fast_api_ipc_manager.py"
FASTAPI_PLUGIN_PATH = (
  FRAMEWORK_PACKAGE / "business" / "default" / "web_app" / "fast_api_web_app.py"
)
FASTAPI_UTILS_PATH = FRAMEWORK_PACKAGE / "utils" / "fastapi_utils.py"
NATIVE_RUNTIME_SOURCE_AVAILABLE = all(
  path.is_file()
  for path in (
    IPC_MANAGER_PATH,
    FASTAPI_PLUGIN_PATH,
    FASTAPI_UTILS_PATH,
  )
)


def _load_module(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  if spec is None or spec.loader is None:
    raise RuntimeError(f"Could not load {path}")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def _load_native_runtime():
  """Load the real scheduler with only its unrelated base dependencies stubbed."""
  module_names = (
    "naeural_core",
    "naeural_core.business",
    "naeural_core.business.base",
    "naeural_core.business.base.web_app",
    "naeural_core.business.base.web_app.base_web_app_plugin",
    "naeural_core.utils",
    "naeural_core.utils.fastapi_utils",
    "naeural_core.utils.uvicorn_fast_api_ipc_manager",
  )
  previous = {name: sys.modules.get(name) for name in module_names}
  try:
    for name in module_names:
      if name not in {
        "naeural_core.business.base.web_app.base_web_app_plugin",
        "naeural_core.utils.fastapi_utils",
        "naeural_core.utils.uvicorn_fast_api_ipc_manager",
      }:
        sys.modules[name] = types.ModuleType(name)

    class _BaseWebAppPlugin:
      CONFIG = {"VALIDATION_RULES": {}}

      def _process(self):
        return None

      def on_close(self):
        return None

    base_module = types.ModuleType(
      "naeural_core.business.base.web_app.base_web_app_plugin"
    )
    base_module.BaseWebAppPlugin = _BaseWebAppPlugin
    sys.modules[base_module.__name__] = base_module

    fastapi_utils = _load_module("_rm040_fastapi_utils", FASTAPI_UTILS_PATH)
    sys.modules["naeural_core.utils.fastapi_utils"] = fastapi_utils
    ipc_stub = types.ModuleType("naeural_core.utils.uvicorn_fast_api_ipc_manager")
    ipc_stub.get_server_manager = lambda _auth: None
    sys.modules[ipc_stub.__name__] = ipc_stub
    runtime = _load_module("_rm040_fastapi_runtime", FASTAPI_PLUGIN_PATH)
    return runtime.FastApiWebAppPlugin, fastapi_utils.PostponedRequest
  finally:
    for name, module in previous.items():
      if module is None:
        sys.modules.pop(name, None)
      else:
        sys.modules[name] = module


if NATIVE_RUNTIME_SOURCE_AVAILABLE:
  NativeFastApiPlugin, NativePostponedRequest = _load_native_runtime()
  ipc_manager = _load_module("_rm040_ipc_manager", IPC_MANAGER_PATH)
else:
  # Edge source checkouts do not vendor the Ratio1 runtime. The integration
  # fixture is exercised when a sibling runtime source checkout is available.
  NativeFastApiPlugin, NativePostponedRequest = object, None
  ipc_manager = None

from .conftest import mock_plugin_modules


mock_plugin_modules()

from extensions.business.cybersec.red_mesh.pentester_api_01 import (
  PentesterApi01Plugin,
  _ManualAnalysisOutcome,
)


class _SchedulerHarness(NativeFastApiPlugin):
  def P(self, *args, **_kwargs):
    if hasattr(self, "_test_messages") and args:
      self._test_messages.append(str(args[0]))
    return None

  def on_response(self, _method, _response):
    return None

  def get_additional_fastapi_data(self):
    return {}

  def get_process_budget_s(self):
    return None

  def get_max_incoming_per_loop(self):
    return 10

  def get_max_postponed_per_loop(self):
    return 10

  def _maybe_log_profile_stats(self):
    return None


class _Owner:
  def __init__(self, worker):
    self._manual_analysis_state = None
    self._manual_analysis_executor = ThreadPoolExecutor(
      max_workers=1,
      thread_name_prefix="rm040-native-test",
    )
    self._worker = worker
    self.solve_postponed_analyze_job = (
      lambda pending_id: PentesterApi01Plugin.solve_postponed_analyze_job(
        self,
        pending_id,
      )
    )

  def time(self):
    return time.monotonic()

  def create_postponed_request(self, solver_method, method_kwargs=None):
    return NativePostponedRequest(solver_method, dict(method_kwargs or {}))


@unittest.skipUnless(
  NATIVE_RUNTIME_SOURCE_AVAILABLE,
  "native Ratio1 runtime source fixture is unavailable",
)
class TestPostponedAnalyzeNativeIpc(unittest.TestCase):
  @staticmethod
  def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
      sock.bind(("127.0.0.1", 0))
      return sock.getsockname()[1]

  @staticmethod
  def _descriptor(name, method, parameters, *, require_token=False):
    return {
      "name": name,
      "method": method,
      "args": [str(parameter) for parameter in parameters],
      "params": [parameter.name for parameter in parameters],
      "endpoint_doc": "",
      "require_token": require_token,
      "has_kwargs": False,
      "streaming_type": None,
      "chunk_size": 1024 * 1024,
    }

  def _render_server(self, destination, manager_port, manager_auth):
    from jinja2 import Environment, FileSystemLoader

    analyze_parameters = list(
      inspect.signature(PentesterApi01Plugin.analyze_job).parameters.values()
    )[1:]
    status_parameters = [
      inspect.Parameter("job_id", inspect.Parameter.POSITIONAL_OR_KEYWORD),
    ]
    endpoints = [
      self._descriptor(
        "analyze_job",
        "post",
        analyze_parameters,
      ),
      self._descriptor("get_job_status", "get", status_parameters),
    ]
    template_dir = FRAMEWORK_PACKAGE / "business" / "base" / "uvicorn_templates"
    rendered = Environment(loader=FileSystemLoader(str(template_dir))).get_template(
      "basic_server.j2"
    ).render(
      additional_fastapi_data={},
      manager_port=manager_port,
      manager_auth=repr(manager_auth),
      request_timeout=120,
      api_title=repr("RM-041 native postponed test"),
      api_summary=repr("RM-041"),
      api_description=repr("RM-041"),
      api_version=repr("0.0.0-test"),
      static_directory="assets",
      debug_web_app=False,
      debug_timings=False,
      debug_timings_steps=False,
      default_route=None,
      profile_rate=0,
      profile_log_per_request=False,
      node_comm_params=endpoints,
      html_files=[],
    )
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "assets").mkdir()
    (destination / "main.py").write_text(rendered, encoding="utf-8")
    temp_utils = destination / "naeural_core" / "utils"
    temp_utils.mkdir(parents=True)
    (temp_utils.parent / "__init__.py").write_text("", encoding="utf-8")
    (temp_utils / "__init__.py").write_text("", encoding="utf-8")
    shutil.copy2(IPC_MANAGER_PATH, temp_utils / IPC_MANAGER_PATH.name)

  @staticmethod
  def _request(port, method, path, *, token="", payload=None, timeout=5):
    headers = {}
    if token:
      headers["Authorization"] = f"Bearer {token}"
    body = None
    if payload is not None:
      headers["Content-Type"] = "application/json"
      body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
      f"http://127.0.0.1:{port}{path}",
      data=body,
      headers=headers,
      method=method,
    )
    started = time.monotonic()
    try:
      with urllib.request.urlopen(request, timeout=timeout) as response:
        return (
          response.status,
          json.loads(response.read().decode("utf-8")),
          time.monotonic() - started,
        )
    except urllib.error.HTTPError as exc:
      return (
        exc.code,
        json.loads(exc.read().decode("utf-8")),
        time.monotonic() - started,
      )

  def test_ipc_timeout_drops_waiter_without_canceling_plugin_work(self):
    manager_auth = b"rm040-native-timeout"
    manager = ipc_manager.get_server_manager(manager_auth)
    self.addCleanup(manager.shutdown)
    _, manager_port = manager.address
    server_queue = manager.get_server_queue()
    client_queue = manager.get_client_queue()
    comms = ipc_manager.UvicornPluginComms(
      port=manager_port,
      auth=manager_auth,
      timeout_s=0.05,
      additional_fastapi_data={},
    )

    loop = asyncio.new_event_loop()
    try:
      result = loop.run_until_complete(
        comms.call_plugin("analyze_job", "job-1")
      )

      self.assertEqual(result["status_code"], 504)
      self.assertEqual(comms._commands, {})
      request = server_queue.get(timeout=1)
      self.assertEqual(request["value"][:2], ("analyze_job", "job-1"))
      with self.assertRaises(queue.Empty):
        server_queue.get(timeout=0.05)

      client_queue.put({
        "id": request["id"],
        "value": {"result": {"job_id": "job-1"}},
      })
      loop.run_until_complete(asyncio.sleep(0.1))
      self.assertEqual(comms._commands, {})
    finally:
      comms._stop_reader.set()
      if comms._reader_thread is not None:
        comms._reader_thread.join(timeout=1)
      loop.close()

  def test_real_postponed_scheduler_keeps_status_responsive(self):
    manager_auth = b"rm040-native-ipc"
    manager = ipc_manager.get_server_manager(manager_auth)
    self.addCleanup(manager.shutdown)
    _, manager_port = manager.address
    server_queue = manager.get_server_queue()
    client_queue = manager.get_client_queue()

    worker_entered = threading.Event()
    release_worker = threading.Event()

    def _blocking_worker(_work):
      worker_entered.set()
      if not release_worker.wait(timeout=10):
        raise TimeoutError("native test worker was not released")
      return _ManualAnalysisOutcome(
        sections={"executive_headline": "done"},
        failed=False,
      )

    owner = _Owner(_blocking_worker)
    self.addCleanup(owner._manual_analysis_executor.shutdown, wait=False)
    harness = _SchedulerHarness.__new__(_SchedulerHarness)
    harness._endpoints = {
      "analyze_job": lambda job_id, analysis_type="", focus_areas=None: (
        PentesterApi01Plugin.analyze_job(
          owner,
          job_id,
          analysis_type,
          focus_areas,
        )
      ),
      "get_job_status": lambda job_id: {"status": "ok", "job_id": job_id},
    }
    harness._incoming_requests = deque()
    harness.postponed_requests = deque()
    harness._incoming_lock = threading.Lock()
    harness._client_queue = client_queue
    harness._stop_request_monitor = threading.Event()
    harness._stop_request_monitor.set()
    harness._request_monitor_thread = None
    harness._profile_stats = {}
    harness.cfg_log_requests = False
    harness.cfg_response_format = "WRAPPED"
    harness.cfg_fair_scheduling = True
    harness._test_messages = []

    stop_dispatcher = threading.Event()

    def _dispatch():
      while not stop_dispatcher.is_set():
        try:
          request = server_queue.get_nowait()
        except queue.Empty:
          request = None
        if request is not None:
          with harness._incoming_lock:
            harness._incoming_requests.append(request)
        harness._process()
        time.sleep(0.005)

    dispatcher = threading.Thread(target=_dispatch, daemon=True)
    dispatcher.start()

    def _stop_dispatcher():
      stop_dispatcher.set()
      release_worker.set()
      dispatcher.join(timeout=2)

    self.addCleanup(_stop_dispatcher)

    state = {
      "pending_id": "unused",
      "job_id": "job-1",
      "job_revision": 1,
      "pass_nr": 1,
      "report_cid": "QmExpected",
      "target": "example.test",
      "num_workers": 1,
      "deadline_monotonic": time.monotonic() + 4,
      "next_check_monotonic": 0.0,
      "discard_result": False,
      "work": object(),
    }
    final_response = {
      "job_id": "job-1",
      "target": "example.test",
      "num_workers": 1,
      "pass_nr": 1,
      "analysis_type": "structured_report_sections",
      "llm_failed": False,
      "llm_report_sections": {"executive_headline": "done"},
    }

    with tempfile.TemporaryDirectory(prefix="rm040-native-") as temp_dir:
      app_dir = Path(temp_dir)
      self._render_server(app_dir, manager_port, manager_auth)
      port = self._find_free_port()
      process = subprocess.Popen(
        [
          sys.executable,
          "-m",
          "uvicorn",
          "--app-dir",
          str(app_dir),
          "main:app",
          "--host",
          "127.0.0.1",
          "--port",
          str(port),
        ],
        cwd=app_dir,
        env={**os.environ, "PYTHONPATH": str(app_dir)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
      )
      try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
          try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
              break
          except OSError:
            time.sleep(0.05)
        else:
          stderr = (process.stderr.read() or b"").decode("utf-8", errors="replace")
          self.fail(f"Generated Uvicorn server did not start:\n{stderr}")

        analysis_result = []

        def _request_analysis():
          analysis_result.append(self._request(
            port,
            "POST",
            "/analyze_job",
            payload={"job_id": "job-1"},
          ))

        def _prepare(_plugin, job_id):
          if job_id == "explode":
            raise RuntimeError("native admission failure")
          return dict(state), None

        with patch.object(
          PentesterApi01Plugin,
          "_prepare_manual_analysis",
          side_effect=_prepare,
        ), patch.object(
          PentesterApi01Plugin,
          "_finalize_manual_analysis",
          return_value=final_response,
        ), patch(
          "extensions.business.cybersec.red_mesh.pentester_api_01._run_manual_analysis_worker",
          side_effect=_blocking_worker,
        ):
          failed_status, failed_body, failed_elapsed = self._request(
            port,
            "POST",
            "/analyze_job",
            payload={"job_id": "explode"},
          )
          self.assertEqual(failed_status, 503, failed_body)
          self.assertLess(failed_elapsed, 1.0)
          self.assertEqual(
            failed_body["detail"]["error"],
            "analysis_executor_failed",
          )
          analysis_thread = threading.Thread(target=_request_analysis, daemon=True)
          analysis_thread.start()
          self.assertTrue(worker_entered.wait(timeout=2))

          status, body, elapsed = self._request(
            port,
            "GET",
            "/get_job_status?job_id=job-1",
          )
          self.assertEqual(status, 200, body)
          self.assertLess(elapsed, 1.0)
          self.assertEqual(body["result"]["status"], "ok")

          busy_status, busy_body, busy_elapsed = self._request(
            port,
            "POST",
            "/analyze_job",
            payload={"job_id": "job-1"},
          )
          self.assertEqual(busy_status, 409, busy_body)
          self.assertLess(busy_elapsed, 1.0)
          self.assertEqual(busy_body["detail"]["error"], "analysis_busy")

          release_worker.set()
          analysis_thread.join(timeout=3)
          self.assertFalse(analysis_thread.is_alive())

        self.assertEqual(analysis_result[0][0], 200, analysis_result)
        result_body = analysis_result[0][1]
        self.assertEqual(
          result_body["result"]["analysis_type"],
          "structured_report_sections",
        )
        self.assertNotIn("operation_id", json.dumps(result_body))
      finally:
        release_worker.set()
        process.terminate()
        try:
          process.wait(timeout=5)
        except subprocess.TimeoutExpired:
          process.kill()
          process.wait(timeout=5)
        if process.stdout:
          process.stdout.close()
        if process.stderr:
          process.stderr.close()


if __name__ == "__main__":
  unittest.main()
