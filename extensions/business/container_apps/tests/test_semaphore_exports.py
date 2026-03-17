import unittest

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
    self.assertEqual(plugin.semaphore_env["CONTAINER_PORT"], "3005")
    self.assertEqual(plugin.semaphore_env["CONTAINER_IP"], "172.18.0.5")
    self.assertEqual(plugin.semaphore_env["PORT"], "3005")
    self.assertEqual(plugin.semaphore_env["URL"], "http://127.0.0.1:3005")


if __name__ == "__main__":
  unittest.main()
