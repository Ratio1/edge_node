import unittest

from extensions.business.container_apps.tests.support import make_container_app_runner


class ContainerAppRunnerLegacyConfigMappingTests(unittest.TestCase):

  def test_get_host_port_for_container_port_prefers_main_port_alias(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.port = 20001
    plugin.extra_ports_mapping = {
      20001: 3000,
      20002: 3002,
    }

    self.assertEqual(plugin._get_host_port_for_container_port(3000), 20001)
    self.assertEqual(plugin._get_host_port_for_container_port(3002), 20002)

  def test_extra_tunnels_can_define_exposed_port_without_legacy_ports_config(self):
    plugin = make_container_app_runner()
    plugin.cfg_extra_tunnels = {
      "3005": "token-3005"
    }

    plugin._validate_extra_tunnels_config()

    self.assertEqual(plugin.extra_tunnel_configs, {
      3005: {
        "token": "token-3005",
        "protocol": "http",
        "engine": "cloudflare",
      }
    })
    self.assertEqual(plugin.extra_ports_mapping, {
      20001: 3005
    })


  def test_legacy_cloudflare_protocol_flows_into_normalized_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 5432
    plugin.cfg_cloudflare_token = "tok-abc"
    plugin.cfg_cloudflare_protocol = "tcp"
    plugin.cfg_exposed_ports = {}
    plugin.cfg_container_resources = {"cpu": 1, "memory": "512m", "ports": {}}

    normalized = plugin._normalize_exposed_ports_config()

    entry = normalized[5432]
    self.assertEqual(entry["protocol"], "tcp")
    self.assertEqual(entry["token"], "tok-abc")
    self.assertTrue(entry["is_main_port"])

  def test_legacy_cloudflare_protocol_defaults_to_http_when_absent(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 8080
    plugin.cfg_cloudflare_token = "tok-xyz"
    plugin.cfg_exposed_ports = {}
    plugin.cfg_container_resources = {"cpu": 1, "memory": "512m", "ports": {}}

    normalized = plugin._normalize_exposed_ports_config()

    entry = normalized[8080]
    self.assertEqual(entry["protocol"], "http")


if __name__ == "__main__":
  unittest.main()
