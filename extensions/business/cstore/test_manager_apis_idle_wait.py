import queue
import threading
import unittest
from collections import deque
from unittest import mock

from constants import ADMIN_PIPELINE
from extensions.business.cstore.cstore_manager_api import CstoreManagerApiPlugin
from extensions.business.r1fs.r1fs_manager_api import R1fsManagerApiPlugin


API_PLUGINS = {
  "CSTORE_MANAGER_API": CstoreManagerApiPlugin,
  "R1FS_MANAGER_API": R1fsManagerApiPlugin,
}


def _make_probe(plugin_class):
  """The real plugin class without its node-bound __init__, holding only what the wake paths use."""
  class _Probe(plugin_class):
    cfg_idle_loop_wait = plugin_class.CONFIG["IDLE_LOOP_WAIT"]
    cfg_plugin_stop_timeout = 0
    instance_hash = "probe"
    plugins_shared_mem = mock.Mock()
    uvicorn_server_started = True
    start_commands_finished = [True]
    upstream_inputs_deque = deque()  # a read-only property on the plugin; this class is new per probe

    def __init__(self):  # pylint: disable=super-init-not-called
      self._loop_wakeup = threading.Event()
      self._incoming_lock = threading.Lock()
      self._incoming_requests = deque()
      self.postponed_requests = deque()
      self.P = mock.Mock()

    def __repr__(self):  # the command log line formats the plugin
      return "<probe>"
  return _Probe()


class ManagerApisIdleWaitTests(unittest.TestCase):

  def test_cstore_and_r1fs_apis_opt_into_the_idle_wait(self):
    for signature, plugin_class in API_PLUGINS.items():
      with self.subTest(signature):
        self.assertEqual(plugin_class.CONFIG["IDLE_LOOP_WAIT"], 0.25)
        # The admin pipeline instance config must not turn it off again.
        self.assertNotIn("IDLE_LOOP_WAIT", ADMIN_PIPELINE[signature])


class ManagerApisWakeUpTests(unittest.TestCase):

  def test_waits_only_while_started_and_nothing_is_queued(self):
    for plugin_class in API_PLUGINS.values():
      with self.subTest(plugin_class.__name__):
        probe = _make_probe(plugin_class)
        self.assertEqual(probe._idle_loop_wait(), 0.25)
        probe._incoming_requests.append({"id": "r1"})
        self.assertEqual(probe._idle_loop_wait(), 0)
        probe._incoming_requests.clear()
        probe.postponed_requests.append(object())
        self.assertEqual(probe._idle_loop_wait(), 0)
        probe.postponed_requests.clear()
        probe.start_commands_finished = [False]  # the server is being restarted
        self.assertEqual(probe._idle_loop_wait(), 0)

  def test_inputs_wake_the_loop(self):
    for plugin_class in API_PLUGINS.values():
      with self.subTest(plugin_class.__name__):
        probe = _make_probe(plugin_class)
        probe.add_to_inputs_deque({"STREAM_NAME": "admin_pipeline"})
        self.assertTrue(probe._loop_wakeup.is_set())

  def test_requests_wake_the_loop(self):
    for plugin_class in API_PLUGINS.values():
      with self.subTest(plugin_class.__name__):
        probe = _make_probe(plugin_class)
        probe._stop_request_monitor = threading.Event()
        probe._request_monitor_thread = None
        probe.on_request = mock.Mock()
        probe.get_request_timeout = mock.Mock(return_value=None)
        probe.get_max_incoming_requests = mock.Mock(return_value=10)
        probe.get_max_queue_wait = mock.Mock(return_value=None)
        server_queue = queue.Queue()
        server_queue.put({"id": "r1", "value": ["get_value"]})

        def _get(block, timeout):
          if server_queue.empty():
            probe._stop_request_monitor.set()
          return server_queue.get(block, 0.01)
        probe._server_queue = mock.Mock(get=_get)
        probe._start_request_monitor_thread()
        probe._request_monitor_thread.join(timeout=5)
        self.assertEqual(list(probe._incoming_requests), [{"id": "r1", "value": ["get_value"]}])
        self.assertTrue(probe._loop_wakeup.is_set())

  def test_instance_commands_wake_the_loop(self):
    for plugin_class in API_PLUGINS.values():
      with self.subTest(plugin_class.__name__):
        probe = _make_probe(plugin_class)
        probe._upstream_config, probe.config_data, probe._session_id = {}, {}, None
        probe.maybe_update_instance_config({"INSTANCE_COMMAND": {"OP": "STATUS"}})
        self.assertEqual(probe.config_data["INSTANCE_COMMAND"], {"OP": "STATUS"})
        self.assertTrue(probe._loop_wakeup.is_set())

  def test_stop_wakes_the_loop_before_joining_it(self):
    for plugin_class in API_PLUGINS.values():
      with self.subTest(plugin_class.__name__):
        probe = _make_probe(plugin_class)
        woken_before_join = []
        probe.thread = mock.Mock(
          join=lambda timeout: woken_before_join.append(probe._loop_wakeup.is_set()),
          is_alive=mock.Mock(return_value=False),
        )
        probe.stop_thread()
        self.assertTrue(probe.done_loop)
        self.assertEqual(woken_before_join, [True])


if __name__ == "__main__":
  unittest.main()
