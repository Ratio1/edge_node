import unittest

from extensions.business.container_apps.tests.support import make_container_app_runner


class ContainerAppRunnerPortRuntimeTests(unittest.TestCase):

  def test_main_port_only_gets_dynamic_host_port(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000

    plugin._setup_resource_limits_and_ports()

    self.assertEqual(plugin.port, 20001)
    self.assertEqual(plugin.extra_ports_mapping, {20001: 3000})

  def test_list_ports_map_all_container_ports_and_track_main(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3001
    plugin.cfg_container_resources = {
      "ports": [3000, 3001, 3002]
    }

    plugin._setup_resource_limits_and_ports()

    self.assertEqual(plugin.extra_ports_mapping, {
      20001: 3000,
      20002: 3001,
      20003: 3002,
    })
    self.assertEqual(plugin.port, 20002)

  def test_dict_ports_preserve_requested_host_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3001
    plugin.cfg_container_resources = {
      "ports": {
        "18080": 3000,
        "18081": 3001,
      }
    }

    plugin._setup_resource_limits_and_ports()

    self.assertEqual(plugin.extra_ports_mapping, {
      18080: 3000,
      18081: 3001,
    })
    self.assertEqual(plugin.port, 18081)

  def test_main_port_is_added_when_missing_from_legacy_ports_list(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3001
    plugin.cfg_container_resources = {
      "ports": [3000]
    }

    plugin._setup_resource_limits_and_ports()

    self.assertEqual(plugin.extra_ports_mapping, {
      20001: 3000,
      20002: 3001,
    })
    self.assertEqual(plugin.port, 20002)


if __name__ == "__main__":
  unittest.main()
