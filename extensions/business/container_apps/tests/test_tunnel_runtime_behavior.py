import unittest

from extensions.business.container_apps.tests.support import make_container_app_runner


class ContainerAppRunnerTunnelRuntimeTests(unittest.TestCase):

  def test_extra_tunnels_allocate_host_ports_for_unmapped_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.cfg_container_resources = {
      "ports": [3000]
    }
    plugin._setup_resource_limits_and_ports()
    plugin.cfg_extra_tunnels = {
      "3002": "token-3002"
    }

    plugin._validate_extra_tunnels_config()

    self.assertEqual(plugin.extra_tunnel_configs, {
      3002: "token-3002"
    })
    self.assertEqual(plugin.extra_ports_mapping, {
      20001: 3000,
      20002: 3002,
    })

  def test_main_tunnel_is_skipped_when_main_port_is_in_extra_tunnels(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.cfg_cloudflare_token = "main-token"
    plugin.extra_tunnel_configs = {
      3000: "extra-token"
    }

    self.assertFalse(plugin._should_start_main_tunnel())

  def test_build_tunnel_command_uses_host_port_mapping(self):
    plugin = make_container_app_runner()
    plugin.extra_ports_mapping = {
      20005: 3002
    }

    command = plugin._build_tunnel_command(3002, "cf-token")

    self.assertEqual(command, [
      "cloudflared",
      "tunnel",
      "--no-autoupdate",
      "run",
      "--token",
      "cf-token",
      "--url",
      "http://127.0.0.1:20005",
    ])


if __name__ == "__main__":
  unittest.main()
