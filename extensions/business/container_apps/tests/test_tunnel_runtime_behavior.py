import os
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
    """Use the published host port as the Cloudflare tunnel origin.

    Check that a tunnel configured for a container port dials its mapped
    host port and reads the tunnel token from standard input.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> ContainerAppRunnerTunnelRuntimeTests().test_build_tunnel_command_uses_host_port_mapping()
    """
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
      "--token-file",
      "/dev/stdin",
      "--url",
      "http://127.0.0.1:20005",
    ])

  def test_build_https_tunnel_command_applies_explicit_origin_tls_override(self):
    """Carry an explicit HTTPS verification override into the generated command.

    Expect an HTTPS URL with the mapped host port and the verification
    override, with the token supplied through standard input.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> ContainerAppRunnerTunnelRuntimeTests().test_build_https_tunnel_command_applies_explicit_origin_tls_override()
    """
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
      "--token-file",
      "/dev/stdin",
      "--url",
      "https://127.0.0.1:20005",
      "--no-tls-verify",
    ])

  def test_start_extra_tunnel_redacts_token_from_debug_log(self):
    """Keep the extra tunnel token in its subprocess input stream.

    Read the descriptor at process launch and check that the token reaches
    the tunnel there while the argument list and debug log stay redacted.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> ContainerAppRunnerTunnelRuntimeTests().test_start_extra_tunnel_redacts_token_from_debug_log()
    """
    plugin = make_container_app_runner()
    plugin.extra_ports_mapping = {20005: 8080}
    plugin.LogReader = lambda *_args, **_kwargs: object()
    plugin._remember_process_group = lambda _process: None
    plugin._record_tunnel_restart_success = lambda _port: None
    plugin.time = lambda: 1.0
    process = MagicMock(pid=123, stdout=object(), stderr=object())
    # The subprocess stub reads the real descriptor before Popen returns.
    pipe_reads = []

    with patch(
      "extensions.business.container_apps.container_app_runner.subprocess.Popen",
      side_effect=lambda **kwargs: (pipe_reads.append(os.read(kwargs["stdin"], 4096)) or process),
    ) as popen:
      started = plugin._start_extra_tunnel(8080, {
        "token": "dashboard-secret-token",
        "protocol": "https",
        "engine": "cloudflare",
        "no_tls_verify": True,
      })

    self.assertTrue(started)
    self.assertNotIn("dashboard-secret-token", popen.call_args.kwargs["args"])
    self.assertEqual(pipe_reads, [b"dashboard-secret-token"])
    self.assertNotIn("dashboard-secret-token", "\n".join(plugin.logged_messages))
    self.assertIn("--token-file /dev/stdin", "\n".join(plugin.logged_messages))

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

  def test_run_main_cloudflare_tunnel_keeps_token_in_one_opaque_pipe(self):
    """Pass the main tunnel token as a single value over standard input.

    Use a token with shell metacharacters to verify that the launcher passes
    the bytes through a pipe without invoking a shell or logging the token.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> ContainerAppRunnerTunnelRuntimeTests().test_run_main_cloudflare_tunnel_keeps_token_in_one_opaque_pipe()
    """
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
    # Pull the bytes from the standard-input descriptor without using Cloudflare.
    pipe_reads = []

    with patch(
      "extensions.business.container_apps.container_app_runner.subprocess.Popen",
      side_effect=lambda **kwargs: (pipe_reads.append(os.read(kwargs["stdin"], 4096)) or process),
    ) as popen:
      started = plugin.run_tunnel_engine()

    self.assertIs(started, process)
    self.assertEqual(popen.call_args.kwargs["args"][4:6], ["--token-file", "/dev/stdin"])
    self.assertEqual(pipe_reads, [token.encode()])
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
