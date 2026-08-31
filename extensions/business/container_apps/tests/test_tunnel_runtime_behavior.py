import unittest
from unittest.mock import MagicMock, patch

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
        "no_tls_verify": False,
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

  def test_build_https_tunnel_command_applies_explicit_origin_tls_override(self):
    plugin = make_container_app_runner()
    plugin.extra_ports_mapping = {
      20005: 8080
    }

    command = plugin._build_tunnel_command(
      8080,
      "dashboard-token",
      protocol="https",
      no_tls_verify=True,
    )

    self.assertEqual(command, [
      "cloudflared",
      "tunnel",
      "--no-autoupdate",
      "run",
      "--token",
      "dashboard-token",
      "--url",
      "https://127.0.0.1:20005",
      "--no-tls-verify",
    ])

  def test_start_extra_tunnel_redacts_token_from_debug_log(self):
    plugin = make_container_app_runner()
    plugin.extra_ports_mapping = {20005: 8080}
    plugin.LogReader = lambda *_args, **_kwargs: object()
    plugin._remember_process_group = lambda _process: None
    plugin._record_tunnel_restart_success = lambda _port: None
    plugin.time = lambda: 1.0
    process = MagicMock(pid=123, stdout=object(), stderr=object())

    with patch(
      "extensions.business.container_apps.container_app_runner.subprocess.Popen",
      return_value=process,
    ) as popen:
      started = plugin._start_extra_tunnel(8080, {
        "token": "dashboard-secret-token",
        "protocol": "https",
        "engine": "cloudflare",
        "no_tls_verify": True,
      })

    self.assertTrue(started)
    self.assertIn("dashboard-secret-token", popen.call_args.kwargs["args"])
    self.assertNotIn("dashboard-secret-token", "\n".join(plugin.logged_messages))
    self.assertIn("--token [REDACTED]", "\n".join(plugin.logged_messages))

  def test_run_main_tunnel_command_redacts_token_from_log(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "5432": {
        "is_main_port": True,
        "token": "main-secret-token",
        "protocol": "tcp",
      },
    }
    plugin._refresh_normalized_exposed_ports_state()
    plugin.LogReader = lambda *_args, **_kwargs: object()
    plugin._remember_process_group = lambda _process: None
    process = MagicMock(pid=321, stdout=object(), stderr=object())
    command = "cloudflared tunnel --no-autoupdate run --token main-secret-token --url tcp://127.0.0.1:20001"

    with patch(
      "extensions.business.container_apps.container_app_runner.subprocess.Popen",
      return_value=process,
    ) as popen:
      started = plugin.run_tunnel_command(command)

    self.assertIs(started, process)
    self.assertEqual(popen.call_args.kwargs["args"], [
      "cloudflared", "tunnel", "--no-autoupdate", "run", "--token",
      "main-secret-token", "--url", "tcp://127.0.0.1:20001",
    ])
    self.assertNotIn("shell", popen.call_args.kwargs)
    self.assertNotIn("main-secret-token", "\n".join(plugin.logged_messages))
    self.assertIn("--token [REDACTED]", "\n".join(plugin.logged_messages))

  def test_run_main_cloudflare_tunnel_keeps_token_as_one_opaque_argument(self):
    plugin = make_container_app_runner()
    token = "main-token; touch /tmp/must-not-run"
    plugin.cfg_exposed_ports = {
      "5432": {
        "is_main_port": True,
        "token": token,
        "protocol": "tcp",
      },
    }
    plugin._refresh_normalized_exposed_ports_state()
    plugin.extra_ports_mapping = {20001: 5432}
    plugin.LogReader = lambda *_args, **_kwargs: object()
    plugin._remember_process_group = lambda _process: None
    process = MagicMock(pid=321, stdout=object(), stderr=object())

    with patch(
      "extensions.business.container_apps.container_app_runner.subprocess.Popen",
      return_value=process,
    ) as popen:
      started = plugin.run_tunnel_engine()

    self.assertIs(started, process)
    self.assertEqual(popen.call_args.kwargs["args"][5], token)
    self.assertNotIn("shell", popen.call_args.kwargs)
    self.assertNotIn(token, "\n".join(plugin.logged_messages))

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
        "no_tls_verify": False,
      },
    })

  def test_validate_extra_tunnels_config_preserves_https_origin_tls_override(self):
    plugin = make_container_app_runner()
    plugin.cfg_exposed_ports = {
      "8080": {
        "token": "dashboard-token",
        "protocol": "https",
        "engine": "cloudflare",
        "no_tls_verify": True,
      },
    }

    plugin._setup_resource_limits_and_ports()
    plugin._validate_extra_tunnels_config()

    self.assertEqual(plugin.extra_tunnel_configs[8080], {
      "token": "dashboard-token",
      "protocol": "https",
      "engine": "cloudflare",
      "no_tls_verify": True,
    })


if __name__ == "__main__":
  unittest.main()
