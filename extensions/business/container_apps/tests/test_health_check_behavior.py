import types
import unittest

from extensions.business.container_apps.tests.support import make_container_app_runner


class ContainerAppRunnerHealthCheckTests(unittest.TestCase):

  def test_valid_container_ports_include_main_and_extra_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.extra_ports_mapping = {
      20001: 3000,
      20002: 3002,
      20003: 3003,
    }

    self.assertEqual(plugin._get_valid_container_ports(), {3000, 3002, 3003})

  def test_invalid_health_port_disables_probing(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.extra_ports_mapping = {
      20001: 3000,
      20002: 3002,
    }
    plugin._get_health_config = lambda: types.SimpleNamespace(port=3005)

    is_valid = plugin._validate_health_endpoint_port()

    self.assertFalse(is_valid)
    self.assertTrue(plugin._health_probing_disabled)

  def test_valid_health_port_keeps_probing_enabled(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.extra_ports_mapping = {
      20001: 3000,
      20002: 3002,
    }
    plugin._get_health_config = lambda: types.SimpleNamespace(port=3002)

    is_valid = plugin._validate_health_endpoint_port()

    self.assertTrue(is_valid)
    self.assertFalse(plugin._health_probing_disabled)


if __name__ == "__main__":
  unittest.main()
