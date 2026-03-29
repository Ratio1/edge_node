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
      3002: {
        "token": "token-3002",
        "protocol": "http",
        "engine": "cloudflare",
        "max_retries": None,
        "backoff_initial": None,
        "backoff_max": None,
      }
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
      3000: {
        "token": "extra-token",
        "protocol": "http",
        "engine": "cloudflare",
        "max_retries": None,
        "backoff_initial": None,
        "backoff_max": None,
      }
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

  def test_normalized_main_tunnel_drives_cloudflare_token(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3000": {
        "is_main_port": True,
        "tunnel": {
          "enabled": True,
          "engine": "cloudflare",
          "token": "normalized-main-token",
        },
      }
    }

    plugin._refresh_normalized_exposed_ports_state()

    self.assertTrue(plugin._should_start_main_tunnel())
    self.assertEqual(plugin.get_cloudflare_token(), "normalized-main-token")

  def test_validate_extra_tunnels_config_uses_normalized_non_main_tunnels(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3000": {
        "is_main_port": True,
        "tunnel": {
          "enabled": True,
          "engine": "cloudflare",
          "token": "main-token",
        },
      },
      "3002": {
        "tunnel": {
          "enabled": True,
          "engine": "cloudflare",
          "token": "extra-token",
        },
      },
    }

    plugin._setup_resource_limits_and_ports()
    plugin._validate_extra_tunnels_config()

    self.assertEqual(plugin.extra_ports_mapping, {
      20001: 3000,
      20002: 3002,
    })
    self.assertEqual(plugin.extra_tunnel_configs, {
      3002: {
        "token": "extra-token",
        "protocol": "http",
        "engine": "cloudflare",
        "max_retries": None,
        "backoff_initial": None,
        "backoff_max": None,
      },
    })


if __name__ == "__main__":
  unittest.main()
