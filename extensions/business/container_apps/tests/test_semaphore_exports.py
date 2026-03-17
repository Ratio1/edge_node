import unittest

from extensions.business.container_apps.tests.support import make_container_app_runner


class ContainerAppRunnerSemaphoreExportTests(unittest.TestCase):

  def test_setup_semaphore_env_keeps_current_legacy_port_behavior(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.port = 20001

    plugin._setup_semaphore_env()

    self.assertEqual(plugin.semaphore_env["HOST"], "127.0.0.1")
    self.assertEqual(plugin.semaphore_env["PORT"], "3000")
    self.assertEqual(plugin.semaphore_env["URL"], "http://127.0.0.1:3000")
    self.assertEqual(plugin.semaphore_env["CONTAINER_IP"], "172.18.0.5")


if __name__ == "__main__":
  unittest.main()
