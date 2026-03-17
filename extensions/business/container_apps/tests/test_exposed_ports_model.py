import unittest

from extensions.business.container_apps.tests.support import make_container_app_runner


class ContainerAppRunnerExposedPortsModelTests(unittest.TestCase):

  def test_normalize_exposed_ports_accepts_minimal_valid_config(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3000": {
        "is_main_port": True,
        "host_port": None,
        "tunnel": {
          "enabled": True,
          "engine": "cloudflare",
          "token": "cf-token",
        },
      },
      "3001": {
        "tunnel": {
          "enabled": False,
        },
      },
    }

    normalized = plugin._normalize_exposed_ports_config()

    self.assertEqual(sorted(normalized.keys()), [3000, 3001])
    self.assertEqual(normalized[3000]["container_port"], 3000)
    self.assertTrue(normalized[3000]["is_main_port"])
    self.assertIsNone(normalized[3000]["host_port"])
    self.assertEqual(normalized[3000]["tunnel"]["token"], "cf-token")
    self.assertFalse(normalized[3001]["is_main_port"])
    self.assertIsNone(normalized[3001]["host_port"])
    self.assertEqual(normalized[3001]["tunnel"]["enabled"], False)

  def test_validate_runner_config_caches_normalized_exposed_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3000": {
        "is_main_port": True,
      }
    }
    plugin.cfg_container_entrypoint = None
    plugin.cfg_container_start_command = None
    plugin.cfg_build_and_run_commands = []

    plugin._validate_runner_config()

    self.assertEqual(plugin._normalized_exposed_ports[3000]["container_port"], 3000)
    self.assertEqual(plugin._normalized_main_exposed_port["container_port"], 3000)

  def test_normalize_exposed_ports_rejects_multiple_main_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3000": {"is_main_port": True},
      "3001": {"is_main_port": True},
    }

    with self.assertRaisesRegex(ValueError, "multiple main ports"):
      plugin._normalize_exposed_ports_config()

  def test_normalize_exposed_ports_rejects_duplicate_host_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3000": {"host_port": 18080},
      "3001": {"host_port": 18080},
    }

    with self.assertRaisesRegex(ValueError, "duplicate host_port"):
      plugin._normalize_exposed_ports_config()

  def test_normalize_exposed_ports_rejects_invalid_tunnel_config(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3000": {
        "tunnel": {
          "enabled": True,
          "engine": "cloudflare",
        }
      }
    }

    with self.assertRaisesRegex(ValueError, "tunnel.token is required"):
      plugin._normalize_exposed_ports_config()

  def test_normalize_exposed_ports_requires_dict_keyed_by_valid_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "not-a-port": {}
    }

    with self.assertRaisesRegex(ValueError, "key must be an integer port"):
      plugin._normalize_exposed_ports_config()

  def test_legacy_port_list_normalizes_into_exposed_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3001
    plugin.cfg_container_resources = {
      "ports": [3000, 3001, 3002]
    }

    normalized = plugin._normalize_exposed_ports_config()

    self.assertEqual(sorted(normalized.keys()), [3000, 3001, 3002])
    self.assertTrue(normalized[3001]["is_main_port"])
    self.assertIsNone(normalized[3000]["host_port"])
    self.assertIsNone(normalized[3002]["tunnel"])

  def test_legacy_explicit_host_port_mapping_normalizes_into_exposed_ports(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3001
    plugin.cfg_container_resources = {
      "ports": {
        "18080": 3000,
        "18081": 3001,
      }
    }

    normalized = plugin._normalize_exposed_ports_config()

    self.assertEqual(normalized[3000]["host_port"], 18080)
    self.assertEqual(normalized[3001]["host_port"], 18081)
    self.assertTrue(normalized[3001]["is_main_port"])

  def test_legacy_main_tunnel_token_attaches_to_main_port(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.cfg_cloudflare_token = "main-token"

    normalized = plugin._normalize_exposed_ports_config()

    self.assertEqual(normalized[3000]["tunnel"], {
      "enabled": True,
      "engine": "cloudflare",
      "token": "main-token",
    })

  def test_legacy_tunnel_engine_parameters_token_falls_back_for_main_port(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.cfg_tunnel_engine_parameters = {
      "CLOUDFLARE_TOKEN": "params-token"
    }

    normalized = plugin._normalize_exposed_ports_config()

    self.assertEqual(normalized[3000]["tunnel"]["token"], "params-token")

  def test_legacy_extra_tunnels_create_ports_and_attach_tunnel(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.cfg_extra_tunnels = {
      "3002": "extra-token"
    }

    normalized = plugin._normalize_exposed_ports_config()

    self.assertTrue(normalized[3000]["is_main_port"])
    self.assertEqual(normalized[3002]["tunnel"], {
      "enabled": True,
      "engine": "cloudflare",
      "token": "extra-token",
    })

  def test_legacy_main_extra_tunnel_override_prefers_explicit_per_port_token(self):
    plugin = make_container_app_runner()
    plugin.cfg_port = 3000
    plugin.cfg_cloudflare_token = "main-token"
    plugin.cfg_extra_tunnels = {
      "3000": "extra-token"
    }

    normalized = plugin._normalize_exposed_ports_config()

    self.assertEqual(normalized[3000]["tunnel"]["token"], "extra-token")
    self.assertTrue(any("overridden by EXTRA_TUNNELS" in msg for msg in plugin.logged_messages))

  def test_legacy_conflicting_explicit_host_ports_are_rejected(self):
    plugin = make_container_app_runner()
    exposed_ports = {
      "3000": {
        "host_port": 18080,
      }
    }

    with self.assertRaisesRegex(ValueError, "conflicting host ports"):
      plugin._merge_legacy_exposed_port_entry(
        exposed_ports,
        container_port=3000,
        host_port=18081,
      )

  def test_explicit_exposed_ports_win_over_legacy_fields(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "3005": {
        "is_main_port": True,
      }
    }
    plugin.cfg_port = 3000
    plugin.cfg_container_resources = {
      "ports": [3000, 3001]
    }
    plugin.cfg_extra_tunnels = {
      "3001": "extra-token"
    }

    normalized = plugin._normalize_exposed_ports_config()

    self.assertEqual(sorted(normalized.keys()), [3005])
    self.assertTrue(normalized[3005]["is_main_port"])


if __name__ == "__main__":
  unittest.main()
