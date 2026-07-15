from collections import deque
import os
import queue
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class _FakeProcess:
  def __init__(self):
    self.running = True

  def poll(self):
    return None if self.running else 0


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  @staticmethod
  def endpoint(method="get", require_token=False):  # pylint: disable=unused-argument
    def decorator(func):
      return func

    return decorator

  def __init__(self):
    self.cfg_requests_per_pause = 10
    self.cfg_pause_seconds = 600
    self._init_process_finalized = True
    self._now = 100.0
    self.base_responses = []
    self.lifecycle_events = []
    self.start_commands_started = [True, True]
    self.start_commands_finished = [True, True]
    self.start_commands_processes = [_FakeProcess(), _FakeProcess()]
    self.start_commands_start_time = [90.0, 95.0]
    self.failed = False
    self._stop_request_monitor = threading.Event()
    self._request_monitor_thread = None
    self._incoming_lock = threading.Lock()
    self._incoming_requests = deque()
    self.postponed_requests = deque()
    self._server_queue = queue.Queue()

  def on_init(self):
    self.lifecycle_events.append("init")

  def on_response(self, method, response):
    self.base_responses.append((method, response))

  def time(self):
    return self._now

  def get_start_commands(self):
    return ["uvicorn", "cloudflared"]

  def _maybe_close_start_commands(self):
    self.lifecycle_events.append("stop_commands")
    for process in self.start_commands_processes:
      if process is not None:
        process.running = False

  def _maybe_read_and_stop_all_log_readers(self):
    self.lifecycle_events.append("stop_log_readers")

  def reset_tunnel_engine(self):
    self.lifecycle_events.append("reset_tunnel")

  def _start_request_monitor_thread(self):
    self.lifecycle_events.append("start_monitor")


def _load_plugin_class(enabled=True):
  source_path = ROOT / "plugins" / "business" / "fastapi" / "debug_fastapi_pause_cycle.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin\n",
    "",
  )
  namespace = {"BasePlugin": _FakeBasePlugin, "__name__": "loaded_debug_fastapi_pause_cycle"}
  value = "1" if enabled else ""
  with patch.dict(os.environ, {"EE_ENABLE_DEBUG_FASTAPI_PAUSE_CYCLE": value}):
    exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["DebugFastapiPauseCyclePlugin"]


class DebugFastapiPauseCycleTests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.plugin_class = _load_plugin_class()

  def _make_plugin(self):
    plugin = self.plugin_class()
    plugin.on_init()
    return plugin

  def test_defaults_pause_for_ten_minutes_after_ten_requests(self):
    self.assertEqual(self.plugin_class.CONFIG["REQUESTS_PER_PAUSE"], 10)
    self.assertEqual(self.plugin_class.CONFIG["PAUSE_SECONDS"], 600)
    self.assertTrue(self.plugin_class.CONFIG["TUNNEL_ENGINE_ENABLED"])
    self.assertEqual(self.plugin_class.CONFIG["TUNNEL_ENGINE"], "cloudflare")
    self.assertEqual(self.plugin_class.CONFIG["MAX_INCOMING_PER_LOOP"], 1)

  def test_plugin_requires_explicit_debug_opt_in(self):
    with self.assertRaisesRegex(RuntimeError, "disabled outside"):
      _load_plugin_class(enabled=False)

  def test_tenth_response_starts_pause_and_lifecycle_resets_processes(self):
    plugin = self._make_plugin()

    for request_nr in range(1, 10):
      plugin.on_response("ping", {"request_nr": request_nr})
      self.assertFalse(plugin.should_pause())

    plugin.on_response("ping", {"request_nr": 10})
    self.assertTrue(plugin.should_pause())
    self.assertEqual(len(plugin.base_responses), 10)

    plugin.on_pause()
    self.assertEqual(
      plugin.lifecycle_events,
      ["init", "stop_commands", "stop_log_readers", "reset_tunnel"],
    )
    self.assertEqual(plugin.start_commands_started, [False, False])
    self.assertEqual(plugin.start_commands_finished, [False, False])
    self.assertEqual(plugin.start_commands_processes, [None, None])
    self.assertEqual(plugin.start_commands_start_time, [None, None])

    plugin._now = 699.9
    self.assertFalse(plugin.should_resume())
    plugin._now = 700.0
    self.assertTrue(plugin.should_resume())

  def test_resume_resets_counter_for_the_next_ten_request_cycle(self):
    plugin = self._make_plugin()
    for request_nr in range(10):
      plugin.on_response("ping", {"request_nr": request_nr})

    plugin.on_pause()
    plugin._now = 700.0
    plugin.failed = True
    plugin.on_resume()

    self.assertFalse(plugin.should_pause())
    self.assertFalse(plugin.failed)
    self.assertFalse(plugin._stop_request_monitor.is_set())
    self.assertEqual(plugin.lifecycle_events[-1], "start_monitor")
    for request_nr in range(9):
      plugin.on_response("ping", {"request_nr": request_nr})
    self.assertFalse(plugin.should_pause())
    plugin.on_response("ping", {"request_nr": 10})
    self.assertTrue(plugin.should_pause())

  def test_operator_pause_without_request_deadline_can_resume(self):
    plugin = self._make_plugin()

    self.assertTrue(plugin.should_resume())

  def test_initial_disabled_pause_is_safe_before_web_app_initialization(self):
    plugin = self._make_plugin()
    plugin._init_process_finalized = False

    plugin.on_pause()

    self.assertEqual(plugin.lifecycle_events, ["init"])

  def test_failed_process_teardown_blocks_resume_without_discarding_handles(self):
    plugin = self._make_plugin()
    processes = list(plugin.start_commands_processes)
    plugin._maybe_close_start_commands = lambda: None

    with self.assertRaisesRegex(RuntimeError, "Failed to stop"):
      plugin.on_pause()

    self.assertEqual(plugin.start_commands_processes, processes)
    with self.assertRaisesRegex(RuntimeError, "incomplete web app teardown"):
      plugin.on_resume()

  def test_pause_discards_requests_owned_by_the_stopped_uvicorn(self):
    plugin = self._make_plugin()
    plugin._incoming_requests.extend(["incoming-1", "incoming-2"])
    plugin.postponed_requests.append("postponed")
    plugin._server_queue.put("server")

    plugin.on_pause()

    self.assertTrue(plugin._stop_request_monitor.is_set())
    self.assertEqual(list(plugin._incoming_requests), [])
    self.assertEqual(list(plugin.postponed_requests), [])
    self.assertTrue(plugin._server_queue.empty())


if __name__ == "__main__":
  unittest.main()
