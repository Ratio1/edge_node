"""Docker evidence required for node-owned deployment observations."""
import unittest
from unittest.mock import MagicMock, patch
import threading
# The path of the node's journal in the tests that drive a real lifecycle.
import os
# A folder for that journal.
import tempfile
# Binding the real status methods to a runner in those tests.
import types
# The result of a command run in the container.
from types import SimpleNamespace

from extensions.business.container_apps.tests.support import make_lifecycle_runner
from extensions.business.container_apps.container_app_runner import ContainerAppRunnerPlugin, ContainerState
# The worker runner, whose source check those tests drive too.
from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin
# The node's own lifecycle, as it runs on a node.
from naeural_core.business.deployment_lifecycle import DeploymentLifecycle
# The status and readiness methods every plugin has.
from naeural_core.business.mixins_base.plugin_readiness_mixin import _PluginReadinessMixin
import docker


def observed_by_the_node(plugin, directory):
  """
  Attach a runner to a real node lifecycle, as a node does for a tracked deployment, and return its publisher.

  The runner gets the real status and readiness methods every plugin has (`_PluginReadinessMixin`) in place of
  the no-op stubs of the test base plugin, so its reports and its readiness reach the lifecycle as on a node.

  Parameters
  ----------
  plugin : ContainerAppRunnerPlugin
    The runner to observe; a worker runner too.
  directory : str
    A folder for the node's journal.

  Returns
  -------
  callable
    `publish()`: runs one publication pass of the node and returns the record it published last.

  Examples
  --------
  >>> publish = observed_by_the_node(plugin, folder)
  >>> plugin.report_deployment_status("starting")
  >>> publish()["status"]
  'starting'
  """
  # Each real method, bound to this runner.
  for name in ("report_deployment_status", "set_plugin_ready", "is_plugin_ready"):
    # In place of the stub's.
    setattr(plugin, name, types.MethodType(getattr(_PluginReadinessMixin, name), plugin))
  # No readiness decided yet, as `_PluginReadinessMixin.__init__` leaves it.
  plugin._is_plugin_ready = None
  # The pipeline of the deployment attempt the coordinator started.
  config = {"NAME": "app", "PLUGINS": [{"SIGNATURE": "CONTAINER_APP_RUNNER", "INSTANCES": [{"INSTANCE_ID": "app"}]}],
            "DEEPLOY_OPERATION": {"operation_id": "operation", "attempt": "deploy", "revision": 1,
                                  "coordinator": "oracle", "peers": [], "action": "start"}}
  # The node's lifecycle, with its journal in the folder.
  lifecycle = DeploymentLifecycle(os.path.join(directory, "journal.json"), "node")
  # The coordinator's start of the attempt.
  lifecycle.admit(config, "oracle", True)
  # The runner joins the attempt.
  lifecycle.attach(config, "CONTAINER_APP_RUNNER", "app", plugin)
  # Every record the node publishes.
  published = []

  def publish():
    """
    Run one publication pass of the node and return the record it published last.

    Every write is confirmed and kept; a pass that finds nothing changed writes nothing.

    Returns
    -------
    dict
      The last record written, by this pass or an earlier one.

    Examples
    --------
    >>> publish()["instances"][0]["status"]
    'starting'
    """
    # One pass: each record written is kept, and its write confirmed; signing is not needed here.
    lifecycle.publish(lambda key, value, **kwargs: published.append(value) or True, lambda value, **kwargs: None)
    # The last record written.
    return published[-1]

  # The publisher of this node.
  return publish


class DeploymentRunnerTests(unittest.TestCase):
  def test_a_retried_command_exec_leaves_failed_once_the_app_is_ready(self):
    """
    The real runner sequence takes back a retried start failure, with no "ready" report made by hand.

    A tracked app whose command exec could not be started is published as failed. On the next lap the exec
    starts (the runner reports "starting") and the app passes its health check: it is published as ready.
    """
    # A tracked container app with one command, whose health check passes as soon as its container runs.
    plugin, client, container = make_lifecycle_runner(
      _build_commands=["npm start"], cfg_health_check={"MODE": "delay", "DELAY": 0},
      _deployment_operation_key="operation|deploy")
    # Its container runs.
    plugin.container = container
    # In the running state.
    plugin.container_state = ContainerState.RUNNING
    # Started a while ago.
    plugin.container_start_time = 1
    # The time now.
    plugin.time = lambda: 100
    # The command keeps running; its output is not read here.
    plugin._stream_deployment_exec = MagicMock()
    # The container's log stream is not needed.
    plugin._start_container_log_stream = MagicMock()
    # Nothing periodic runs between the laps.
    plugin._perform_periodic_monitoring = MagicMock()
    # Docker cannot create the exec during the first lap (the lap tries twice), then can.
    client.api.exec_create.side_effect = [docker.errors.DockerException("exec unavailable")] * 2 + [{"Id": "exec"}]
    # A folder for the node's journal.
    with tempfile.TemporaryDirectory() as directory:
      # The node observes the runner.
      publish = observed_by_the_node(plugin, directory)
      # Lap 1: the exec cannot be started.
      plugin.process()
      # Published.
      failed = publish()
      # As failed, with a start failure.
      self.assertEqual((failed["status"], failed["instances"][0]["error"]["code"]),
                       ("failed", "WORKLOAD_START_FAILED"))
      # Lap 2: the exec starts and the app is ready.
      plugin.process()
      # Published again.
      ready = publish()
      # As ready, with no error.
      self.assertEqual((ready["status"], ready["instances"][0]["status"], ready["instances"][0]["error"]),
                       ("ready", "ready", None))

  def test_a_worker_whose_source_check_could_not_run_once_is_published_ready_and_never_failed(self):
    """
    A tracked worker whose source check could not run on one lap keeps "starting" and is published as ready once
    a later check passes: the error is logged in red and not reported as failed, so nothing has to be taken back.
    """
    # A runner on the lifecycle harness, whose health check passes as soon as its container runs.
    plugin, client, container = make_lifecycle_runner(cfg_health_check={"MODE": "delay", "DELAY": 0})
    # A real worker instance.
    worker = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    # On that harness state.
    worker.__dict__.update(plugin.__dict__)
    # Bound to its commit, as a restoration sends it.
    worker.cfg_deeploy_runtime_artifacts = {"image_id": "sha256:" + "a" * 64, "git_commit": "b" * 40}
    # Its container runs.
    worker.container = container
    # In the running state.
    worker.container_state = ContainerState.RUNNING
    # Started a while ago.
    worker.container_start_time = 1
    # The time now.
    worker.time = lambda: 100
    # Its clone and build commands already run.
    worker._maybe_execute_build_and_run = MagicMock()
    # The container's log stream is not needed.
    worker._start_container_log_stream = MagicMock()
    # Nothing periodic runs between the laps.
    worker._perform_periodic_monitoring = MagicMock()
    # The first source check cannot run; the second reads the bound commit.
    container.exec_run = MagicMock(side_effect=[
      docker.errors.DockerException("exec unavailable"), SimpleNamespace(exit_code=0, output=b"b" * 40 + b"\n")])
    # A folder for the node's journal.
    with tempfile.TemporaryDirectory() as directory:
      # The node observes the worker.
      publish = observed_by_the_node(worker, directory)
      # What `start_container` reported when it started the container.
      worker.report_deployment_status("starting")
      # Lap 1: the source check raises.
      worker.process()
      # Published.
      starting = publish()
      # As starting, not failed.
      self.assertEqual((starting["status"], starting["instances"][0]["status"], starting["instances"][0]["error"]),
                       ("starting", "starting", None))
      # The error was logged.
      self.assertTrue([line for line in worker.logged_messages if "Could not confirm the running source" in line])
      # Lap 2: the source check passes.
      worker.process()
      # Published again.
      ready = publish()
      # As ready, with no error.
      self.assertEqual((ready["status"], ready["instances"][0]["status"], ready["instances"][0]["error"]),
                       ("ready", "ready", None))

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
