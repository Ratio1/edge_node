import unittest
import json

from extensions.business.container_apps.tests.support import make_container_app_runner


class ContainerAppRunnerSemaphoreExportTests(unittest.TestCase):

  def test_setup_semaphore_env_keeps_current_legacy_port_behavior(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.port = 20001
    plugin.extra_ports_mapping = {
      20001: 3000,
    }

    plugin._setup_semaphore_env()

    self.assertEqual(plugin.semaphore_env["HOST"], "127.0.0.1")
    self.assertEqual(plugin.semaphore_env["HOST_IP"], "127.0.0.1")
    self.assertEqual(plugin.semaphore_env["PORT"], "3000")
    self.assertEqual(plugin.semaphore_env["URL"], "http://127.0.0.1:3000")
    self.assertEqual(plugin.semaphore_env["HOST_PORT"], "20001")
    self.assertEqual(plugin.semaphore_env["HOST_URL"], "http://127.0.0.1:20001")
    self.assertEqual(plugin.semaphore_env["CONTAINER_PORT"], "3000")
    self.assertEqual(plugin.semaphore_env["CONTAINER_IP"], "172.18.0.5")

  def test_setup_semaphore_env_exports_explicit_main_port_keys_from_normalized_config(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3005": {
        "is_main_port": True,
      },
      "3006": {},
    }
    plugin.extra_ports_mapping = {
      21001: 3005,
      21002: 3006,
    }
    plugin.port = 21001
    plugin._refresh_normalized_exposed_ports_state()

    plugin._setup_semaphore_env()

    self.assertEqual(plugin.semaphore_env["HOST_IP"], "127.0.0.1")
    self.assertEqual(plugin.semaphore_env["HOST_PORT"], "21001")
    self.assertEqual(plugin.semaphore_env["HOST_URL"], "http://127.0.0.1:21001")
    self.assertEqual(plugin.semaphore_env["CONTAINER_PORT"], "3005")
    self.assertEqual(plugin.semaphore_env["CONTAINER_IP"], "172.18.0.5")
    self.assertEqual(plugin.semaphore_env["PORT"], "3005")
    self.assertEqual(plugin.semaphore_env["URL"], "http://127.0.0.1:3005")

  def test_setup_env_and_ports_sanitizes_hyphenated_semaphore_env_names(self):
    plugin = make_container_app_runner()
    plugin.ee_id = "node-id"
    plugin.ee_addr = "0xai_node"
    plugin.dynamic_env = {}
    plugin.cfg_env = {}
    plugin.cfg_semaphored_keys = ["my-semaphore-key"]
    plugin.extra_ports_mapping = {}
    plugin.json_dumps = json.dumps
    plugin.semaphore_get_env = lambda: {
      "my-semaphore-key_API_HOST": "127.0.0.1",
      "my-semaphore-key_API_PORT": "8000",
      "UNCHANGED_API_URL": "http://127.0.0.1:8000",
    }

    plugin._setup_env_and_ports()

    self.assertEqual(plugin.env["MY_SEMAPHORE_KEY_API_HOST"], "127.0.0.1")
    self.assertEqual(plugin.env["MY_SEMAPHORE_KEY_API_PORT"], "8000")
    self.assertEqual(plugin.env["UNCHANGED_API_URL"], "http://127.0.0.1:8000")
    self.assertEqual(plugin.env["R1EN_SEMAPHORED_KEYS"], '["MY_SEMAPHORE_KEY"]')
    self.assertNotIn("my-semaphore-key_API_HOST", plugin.env)
    self.assertNotIn("my-semaphore-key_API_PORT", plugin.env)


if __name__ == "__main__":
  unittest.main()
