"""Docker evidence required for node-owned deployment observations."""
import unittest
from unittest.mock import MagicMock, patch
import threading

from extensions.business.container_apps.tests.support import make_lifecycle_runner
from extensions.business.container_apps.container_app_runner import ContainerAppRunnerPlugin, ContainerState
import docker


class DeploymentRunnerTests(unittest.TestCase):
  def test_process_keeps_database_unready_until_authenticated_probe_succeeds(self):
    plugin, _, container = make_lifecycle_runner()
    plugin.container = container
    plugin.container_state = ContainerState.RUNNING
    plugin.container_start_time = 1
    plugin.time = lambda: 100
    plugin.cfg_image = "ghcr.io/ratio1/r1db:stable"
    plugin.env = {"CRDB_NODE_ID": "1", "CRDB_CA_CRT": "expected-CA"}
    plugin.set_plugin_ready = MagicMock()
    # Exercise the Core semaphore contract, which changes the same readiness
    # flag observed by the independent node reporter.
    plugin._semaphore_set_ready_flag = lambda: plugin.set_plugin_ready(True)
    plugin._maybe_execute_build_and_run = MagicMock()
    plugin._start_container_log_stream = MagicMock()
    plugin._perform_periodic_monitoring = MagicMock()
    with patch("extensions.business.container_apps.container_app_runner.probe_cockroachdb_readiness", side_effect=[False, True]):
      plugin.process()
      container.reload.assert_called_once()
      self.assertTrue(plugin.set_plugin_ready.call_args_list)
      self.assertTrue(all(call.args == (False,) for call in plugin.set_plugin_ready.call_args_list))
      plugin.set_plugin_ready.reset_mock()
      plugin.time = lambda: 106
      plugin.process()
      plugin.set_plugin_ready.assert_called_with(True)
      self.assertTrue(plugin._app_ready)

  def test_managed_database_never_falls_back_to_disabled_or_delay_health(self):
    for mode in ("disabled", "delay", "tcp"):
      with self.subTest(mode=mode):
        plugin, _, container = make_lifecycle_runner()
        plugin.container = container
        plugin.container_state = ContainerState.RUNNING
        plugin.container_start_time = 1
        plugin.time = lambda: 100
        plugin._app_ready = False
        plugin.cfg_image = "ghcr.io/ratio1/r1db:stable"
        plugin.env = {"CRDB_NODE_ID": "2", "CRDB_CA_CRT": "expected-previous-CA"}
        plugin.cfg_health_check = {"MODE": mode, "DELAY": 0, "ON_FAILURE": "start"}
        plugin._get_health_config = MagicMock()
        plugin._semaphore_set_ready_flag = MagicMock()
        with patch("extensions.business.container_apps.container_app_runner.probe_cockroachdb_readiness", return_value=False) as probe:
          self.assertFalse(plugin._is_app_ready())
          probe.assert_called_once_with(container, plugin.env)
          plugin._get_health_config.assert_not_called()
          plugin._semaphore_set_ready_flag.assert_not_called()
          # A repeated loop cannot launch another expensive SQL process yet.
          plugin.time = lambda: 102
          self.assertFalse(plugin._is_app_ready())
          self.assertEqual(probe.call_count, 1)

  def test_restored_database_requires_previous_certificate_probe_before_ready(self):
    plugin, _, container = make_lifecycle_runner()
    plugin.container = container
    plugin.container_state = ContainerState.RUNNING
    plugin.container_start_time = 1
    plugin.time = lambda: 100
    plugin._app_ready = False
    # Exact old configuration has no new marker and uses the previous image.
    plugin.cfg_image = "ghcr.io/ratio1/deeploy-cockroachdb-service:main"
    plugin.env = {"CRDB_NODE_ID": "1", "CRDB_CA_CRT": "previous-CA", "CRDB_NODE_CRT": "previous-node"}
    plugin._get_health_config = MagicMock()
    plugin._semaphore_set_ready_flag = MagicMock()
    with patch("extensions.business.container_apps.container_app_runner.probe_cockroachdb_readiness", side_effect=[False, True]) as probe:
      self.assertFalse(plugin._is_app_ready())
      plugin.time = lambda: 106
      self.assertTrue(plugin._is_app_ready())
      self.assertTrue(plugin._is_app_ready())
      self.assertEqual(probe.call_count, 2)
      probe.assert_called_with(container, plugin.env)
      plugin._semaphore_set_ready_flag.assert_called_once()
      plugin._get_health_config.assert_not_called()

  def test_orphan_reaper_preserves_volumes_and_verifies_absence(self):
    client = MagicMock()
    container = MagicMock()
    client.containers.get.side_effect = [container, docker.errors.NotFound("gone")]
    with patch("docker.from_env", return_value=client):
      self.assertTrue(ContainerAppRunnerPlugin.cleanup_deployment_instance("app", "worker"))
    container.stop.assert_called_once_with(timeout=5)
    container.remove.assert_called_once_with()
    self.assertEqual(client.containers.get.call_args_list[0].args, ("car_app_worker",))
    client.close.assert_called_once()

  def test_orphan_reaper_cannot_claim_stop_when_daemon_unavailable(self):
    client = MagicMock()
    client.containers.get.side_effect = docker.errors.DockerException("unavailable")
    with patch("docker.from_env", return_value=client):
      self.assertFalse(ContainerAppRunnerPlugin.cleanup_deployment_instance("app", "worker"))

  def test_failed_build_is_not_hidden_by_a_running_shell_container(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin.report_deployment_status = MagicMock()
    plugin._stream_logs = MagicMock()
    client.api.exec_inspect.return_value = {"ExitCode": 1, "Running": False}
    plugin._stream_deployment_exec("exec", [], threading.Event())
    plugin.report_deployment_status.assert_called_once_with("failed", error_code="WORKLOAD_START_FAILED")

  def test_intentional_stop_does_not_report_build_failure(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin.report_deployment_status = MagicMock()
    plugin._stream_logs = MagicMock()
    stop = threading.Event()
    stop.set()
    plugin._stream_deployment_exec("exec", [], stop)
    client.api.exec_inspect.assert_not_called()
    plugin.report_deployment_status.assert_not_called()

  def test_docker_status_error_immediately_clears_readiness(self):
    plugin, _, container = make_lifecycle_runner()
    plugin.container = container
    container.reload.side_effect = docker.errors.DockerException("unavailable")
    plugin.set_plugin_ready = MagicMock()
    plugin.report_deployment_status = MagicMock()
    self.assertFalse(plugin._check_container_status())
    plugin.set_plugin_ready.assert_called_with(False)
    plugin.report_deployment_status.assert_called_with("failed", error_code="WORKLOAD_UNHEALTHY")


if __name__ == "__main__":
  unittest.main()
