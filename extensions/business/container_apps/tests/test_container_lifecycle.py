"""
Comprehensive integration tests for ContainerAppRunnerPlugin lifecycle.

These tests emulate the edge node environment by mocking Docker at the
docker-py client level and exercising the full plugin lifecycle:
init -> process (first launch) -> process (running) -> restart -> stop -> close.

All tests that trigger _restart_container() (which calls __reset_vars() ->
docker.from_env()) must patch the docker module to return the mock client.
"""

import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

from extensions.business.container_apps.tests.support import install_docker_stub_if_needed

install_docker_stub_if_needed()

import docker.errors
import docker.types

from extensions.business.container_apps.tests.support import (
  make_container_app_runner,
  make_lifecycle_runner,
  make_mock_container,
  make_mock_docker_client,
)
from extensions.business.container_apps.container_app_runner import (
  ContainerAppRunnerPlugin,
  ContainerState,
  StopReason,
)
from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin


def _patch_docker_module(client):
  """Context manager that patches the docker module for __reset_vars() calls."""
  mock_docker = MagicMock()
  mock_docker.from_env.return_value = client
  mock_docker.errors = docker.errors
  mock_docker.types = docker.types
  return patch(
    'extensions.business.container_apps.container_app_runner.docker',
    mock_docker,
  )


class _JoinableThread:
  def __init__(self):
    self.join_calls = 0
    self.join_timeout = None
    self._alive = True

  def is_alive(self):
    return self._alive

  def join(self, timeout=None):
    self.join_calls += 1
    self.join_timeout = timeout
    self._alive = False


# ===========================================================================
# Init Phase
# ===========================================================================

class TestLifecycleInit(unittest.TestCase):
  """Test initial state before any lifecycle methods run."""

  def test_state_is_uninitialized(self):
    plugin, _, _ = make_lifecycle_runner()
    self.assertEqual(plugin.container_state, ContainerState.UNINITIALIZED)

  def test_container_is_none(self):
    plugin, _, _ = make_lifecycle_runner()
    self.assertIsNone(plugin.container)

  def test_container_name_is_deterministic(self):
    plugin, _, _ = make_lifecycle_runner()
    # Name is stream_id-qualified and sanitized (with "car_" prefix).
    self.assertEqual(plugin.container_name, "car_test_stream_car_instance")

  def test_fixed_volumes_list_empty(self):
    plugin, _, _ = make_lifecycle_runner()
    self.assertEqual(plugin._fixed_volumes, [])

  def test_consecutive_failures_zero(self):
    plugin, _, _ = make_lifecycle_runner()
    self.assertEqual(plugin._consecutive_failures, 0)


# ===========================================================================
# First Launch
# ===========================================================================

class TestLifecycleFirstLaunch(unittest.TestCase):
  """Test _handle_initial_launch() starting the container for the first time."""

  def test_starts_container_via_docker_run(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    client.containers.run.assert_called_once()

  def test_state_transitions_to_running(self):
    plugin, _, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_container_object_is_set(self):
    plugin, _, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    self.assertIsNotNone(plugin.container)

  def test_container_id_is_set(self):
    plugin, _, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    self.assertEqual(plugin.container_id, "abc1234567")

  def test_stale_container_check_runs_before_docker_run(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    # containers.get should be called (stale check) as well as containers.run
    client.containers.get.assert_called_with("car_test_stream_car_instance")
    client.containers.run.assert_called_once()

  def test_image_availability_checked(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    self.assertTrue(
      client.images.get.called or client.images.pull.called,
      "Expected image availability check",
    )

  def test_container_receives_deterministic_name(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    _, kwargs = client.containers.run.call_args
    # Name is stream_id-qualified and sanitized (with "car_" prefix).
    self.assertEqual(kwargs["name"], "car_test_stream_car_instance")

  def test_container_is_not_run_with_auto_remove(self):
    # auto_remove=True destroys post-mortem observability and races with the
    # explicit stop_container() remove path. _ensure_no_stale_container
    # handles crash recovery without it.
    plugin, client, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    _, kwargs = client.containers.run.call_args
    self.assertNotIn("auto_remove", kwargs)

  def test_volumes_passed_to_docker_run(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin.volumes = {"/host/data": {"bind": "/app/data", "mode": "rw"}}
    plugin._handle_initial_launch()
    _, kwargs = client.containers.run.call_args
    self.assertIn("/host/data", kwargs["volumes"])

  def test_env_passed_to_docker_run(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin.env = {"MY_VAR": "hello"}
    plugin._handle_initial_launch()
    _, kwargs = client.containers.run.call_args
    self.assertEqual(kwargs["environment"]["MY_VAR"], "hello")

  def test_resource_limits_passed(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin._cpu_limit = 2.0
    plugin._mem_limit = "1g"
    plugin._handle_initial_launch()
    _, kwargs = client.containers.run.call_args
    self.assertEqual(kwargs["nano_cpus"], 2_000_000_000)
    self.assertEqual(kwargs["mem_limit"], "1g")


# ===========================================================================
# Running State
# ===========================================================================

class TestLifecycleRunning(unittest.TestCase):
  """Test _check_container_status() when container is running or crashed."""

  def _launch(self):
    plugin, client, container = make_lifecycle_runner()
    plugin._handle_initial_launch()
    return plugin, client, container

  def test_running_container_returns_true(self):
    plugin, _, container = self._launch()
    container.status = "running"
    self.assertTrue(plugin._check_container_status())
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_crash_detected_exit_code_nonzero(self):
    plugin, _, container = self._launch()
    container.status = "exited"
    container.attrs = {"State": {"ExitCode": 1, "Running": False}}
    self.assertFalse(plugin._check_container_status())
    self.assertEqual(plugin.container_state, ContainerState.FAILED)
    self.assertEqual(plugin.stop_reason, StopReason.CRASH)

  def test_normal_exit_detected_exit_code_zero(self):
    plugin, _, container = self._launch()
    container.status = "exited"
    container.attrs = {"State": {"ExitCode": 0, "Running": False}}
    self.assertFalse(plugin._check_container_status())
    self.assertEqual(plugin.stop_reason, StopReason.NORMAL_EXIT)

  def test_failure_count_incremented_on_crash(self):
    plugin, _, container = self._launch()
    self.assertEqual(plugin._consecutive_failures, 0)
    container.status = "exited"
    container.attrs = {"State": {"ExitCode": 1, "Running": False}}
    plugin._check_container_status()
    self.assertEqual(plugin._consecutive_failures, 1)

  def test_reload_called_to_refresh_status(self):
    plugin, _, container = self._launch()
    container.status = "running"
    plugin._check_container_status()
    container.reload.assert_called()

  def test_container_none_returns_false(self):
    plugin, _, _ = make_lifecycle_runner()
    plugin.container = None
    self.assertFalse(plugin._check_container_status())


class TestExtraTunnelCleanup(unittest.TestCase):

  def test_stop_extra_tunnels_logs_failure_when_any_tunnel_fails(self):
    plugin = make_container_app_runner()
    plugin.extra_tunnel_processes = {
      8001: object(),
      8002: object(),
    }
    plugin._stop_extra_tunnel = MagicMock(side_effect=[False, True])

    result = plugin.stop_extra_tunnels()

    self.assertFalse(result)
    self.assertEqual(plugin._stop_extra_tunnel.call_count, 2)
    self.assertIn(
      "One or more extra tunnels failed to stop",
      plugin.logged_messages[-1],
    )
    self.assertNotIn("All extra tunnels stopped", plugin.logged_messages[-1])


# ===========================================================================
# Restart
# ===========================================================================

class TestLifecycleRestart(unittest.TestCase):
  """Test _restart_container() flow."""

  def _launch_and_crash(self):
    plugin, client, container = make_lifecycle_runner()
    plugin._handle_initial_launch()
    container.status = "exited"
    container.attrs = {"State": {"ExitCode": 1, "Running": False}}
    plugin._check_container_status()
    return plugin, client, container

  def test_restart_stops_old_container(self):
    plugin, client, old_container = self._launch_and_crash()
    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    with _patch_docker_module(client):
      plugin._restart_container(StopReason.CRASH)

    old_container.stop.assert_called()
    old_container.remove.assert_called()

  def test_restart_starts_new_container(self):
    plugin, client, _ = self._launch_and_crash()
    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    with _patch_docker_module(client):
      plugin._restart_container(StopReason.CRASH)

    # 2 total run calls: initial launch + restart
    self.assertEqual(client.containers.run.call_count, 2)

  def test_restart_transitions_through_restarting_state(self):
    plugin, client, _ = self._launch_and_crash()
    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    states = []
    orig = plugin._set_container_state
    def track(s, r=None):
      states.append(s)
      orig(s, r)
    plugin._set_container_state = track

    with _patch_docker_module(client):
      plugin._restart_container(StopReason.CRASH)

    self.assertIn(ContainerState.RESTARTING, states)

  def test_restart_ends_in_running_state(self):
    plugin, client, _ = self._launch_and_crash()
    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    with _patch_docker_module(client):
      plugin._restart_container(StopReason.CRASH)

    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_restart_preserves_failure_count(self):
    plugin, client, _ = self._launch_and_crash()
    self.assertEqual(plugin._consecutive_failures, 1)

    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    with _patch_docker_module(client):
      plugin._restart_container(StopReason.CRASH)

    # Failure count preserved (not reset to 0 -- that happens via _maybe_reset_retry_counter
    # after the container runs successfully for RESTART_RESET_INTERVAL seconds)
    self.assertEqual(plugin._consecutive_failures, 1)

  def test_restart_reuses_deterministic_name(self):
    plugin, client, _ = self._launch_and_crash()
    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    with _patch_docker_module(client):
      plugin._restart_container(StopReason.CRASH)

    _, kwargs = client.containers.run.call_args
    # See test_container_receives_deterministic_name for the naming rule.
    self.assertEqual(kwargs["name"], "car_test_stream_car_instance")

  def test_restart_revalidates_sync_config_before_start(self):
    plugin, client, _ = self._launch_and_crash()
    plugin.cfg_sync = {"ENABLED": True, "KEY": "", "TYPE": "provider"}
    plugin._sync_unavailable = False
    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    with _patch_docker_module(client), \
         patch.object(plugin, "_configure_system_volume"), \
         patch.object(plugin, "_recover_stale_processing"), \
         patch.object(plugin, "_validate_sync_config", wraps=plugin._validate_sync_config) as validate:
      plugin._restart_container(StopReason.CRASH)

    validate.assert_called()
    self.assertFalse(plugin.cfg_sync["ENABLED"])


class TestWorkerAppRunnerLifecycle(unittest.TestCase):
  """WorkerAppRunner-specific lifecycle integration."""

  def test_additional_checks_runs_sync_before_git_updates(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    calls = []

    def base_sync(_plugin, current_time):
      calls.append(("sync", current_time))
      return None

    def git_updates(current_time):
      calls.append(("git", current_time))
      return StopReason.EXTERNAL_UPDATE

    plugin._check_git_updates = git_updates

    with patch.object(
      ContainerAppRunnerPlugin,
      "_perform_additional_checks",
      autospec=True,
      side_effect=base_sync,
    ):
      result = plugin._perform_additional_checks(123.0)

    self.assertEqual(result, StopReason.EXTERNAL_UPDATE)
    self.assertEqual(calls, [("sync", 123.0), ("git", 123.0)])


# ===========================================================================
# Stop and Close
# ===========================================================================

class TestLifecycleStop(unittest.TestCase):
  """Test stop_container() and on_close()."""

  def _launch(self):
    plugin, client, container = make_lifecycle_runner()
    plugin._handle_initial_launch()
    return plugin, client, container

  def test_stop_calls_docker_stop_and_remove(self):
    plugin, _, container = self._launch()
    result = plugin.stop_container()
    self.assertTrue(result)
    container.stop.assert_called_once_with(timeout=5)
    container.remove.assert_called_once()

  def test_stop_clears_container_reference(self):
    plugin, _, _ = self._launch()
    plugin.stop_container()
    self.assertIsNone(plugin.container)
    self.assertIsNone(plugin.container_id)

  def test_stop_noop_when_no_container(self):
    plugin, _, _ = make_lifecycle_runner()
    self.assertTrue(plugin.stop_container())  # should not raise

  def test_stop_failure_returns_false_and_keeps_container_reference(self):
    plugin, _, container = self._launch()
    container.stop.side_effect = RuntimeError("docker timeout")
    container.remove.side_effect = RuntimeError("still running")

    result = plugin.stop_container()

    self.assertFalse(result)
    self.assertIs(plugin.container, container)
    self.assertEqual(plugin.container_id, container.short_id)

  def test_stop_error_but_remove_success_returns_true_and_clears_reference(self):
    plugin, _, container = self._launch()
    container.stop.side_effect = RuntimeError("docker timeout")

    result = plugin.stop_container()

    self.assertTrue(result)
    container.remove.assert_called_once()
    self.assertIsNone(plugin.container)
    self.assertIsNone(plugin.container_id)

  def test_stop_and_save_logs_saves_to_disk(self):
    plugin, _, container = self._launch()
    plugin.diskapi_save_pickle_to_data = MagicMock()
    plugin._stop_container_and_save_logs_to_disk()
    container.stop.assert_called()
    plugin.diskapi_save_pickle_to_data.assert_called_once()

  def test_runtime_stop_cleans_sidecars_without_fixed_volume_cleanup(self):
    plugin, _, container = self._launch()
    log_thread = _JoinableThread()
    exec_thread = _JoinableThread()
    plugin.log_thread = log_thread
    plugin.exec_threads = [exec_thread]
    plugin._commands_started = True
    plugin._semaphore_reset_signal = MagicMock()
    plugin.stop_tunnel_engine = MagicMock()
    plugin.stop_extra_tunnels = MagicMock()
    plugin._cleanup_fixed_size_volumes = MagicMock()

    result = plugin._stop_container_runtime_for_restart()

    self.assertTrue(result)
    plugin._semaphore_reset_signal.assert_called_once()
    self.assertEqual(log_thread.join_calls, 1)
    # Runtime shutdown uses one shared deadline, so each join receives the
    # remaining budget rather than exactly the original 5 second timeout.
    self.assertLessEqual(log_thread.join_timeout, 5)
    self.assertGreater(log_thread.join_timeout, 0)
    self.assertIsNone(plugin.log_thread)
    self.assertEqual(exec_thread.join_calls, 1)
    self.assertLessEqual(exec_thread.join_timeout, 5)
    self.assertGreater(exec_thread.join_timeout, 0)
    self.assertEqual(plugin.exec_threads, [])
    self.assertFalse(plugin._stop_event.is_set())
    self.assertFalse(plugin._commands_started)
    plugin.stop_tunnel_engine.assert_called_once()
    plugin.stop_extra_tunnels.assert_called_once()
    container.stop.assert_called_once_with(timeout=5)
    container.remove.assert_called_once()
    plugin._cleanup_fixed_size_volumes.assert_not_called()
    self.assertFalse(plugin._runtime_stop_degraded)

  def test_runtime_stop_failure_marks_degraded(self):
    plugin, _, container = self._launch()
    container.remove.side_effect = RuntimeError("still running")

    result = plugin._stop_container_runtime_for_restart()

    self.assertFalse(result)
    self.assertTrue(plugin._runtime_stop_degraded)
    self.assertIs(plugin.container, container)

  def test_stop_and_save_logs_skips_volume_cleanup_on_stop_failure(self):
    plugin, _, container = self._launch()
    container.remove.side_effect = RuntimeError("still running")
    plugin.diskapi_save_pickle_to_data = MagicMock()
    plugin._cleanup_fixed_size_volumes = MagicMock()

    plugin._stop_container_and_save_logs_to_disk()

    plugin._cleanup_fixed_size_volumes.assert_not_called()
    plugin.diskapi_save_pickle_to_data.assert_called_once()

  def test_stop_and_save_logs_cleans_volumes_when_only_sidecar_cleanup_failed(self):
    plugin, _, container = self._launch()
    plugin.stop_tunnel_engine = MagicMock(return_value=False)
    plugin.stop_extra_tunnels = MagicMock(return_value=True)
    plugin.diskapi_save_pickle_to_data = MagicMock()
    plugin._cleanup_fixed_size_volumes = MagicMock(return_value=True)

    result = plugin._stop_container_and_save_logs_to_disk()

    self.assertFalse(result)
    self.assertTrue(plugin._cleanup_failed)
    self.assertFalse(plugin._runtime_stop_degraded)
    container.remove.assert_called_once()
    plugin._cleanup_fixed_size_volumes.assert_called_once()
    messages = "\n".join(plugin.logged_messages)
    self.assertIn("runtime sidecar cleanup still needs retry", messages)

  def test_on_close_stops_container(self):
    plugin, _, container = self._launch()
    plugin.on_close()
    container.stop.assert_called()
    container.remove.assert_called()


# ===========================================================================
# Stale Container Guardrail
# ===========================================================================

class TestLifecycleStaleContainer(unittest.TestCase):
  """Test _ensure_no_stale_container()."""

  def test_removes_stale_running_container(self):
    plugin, client, _ = make_lifecycle_runner()
    stale = make_mock_container(status="running")
    client.containers.get.side_effect = None
    client.containers.get.return_value = stale

    plugin._ensure_no_stale_container()

    stale.remove.assert_called_once_with(force=True)

  def test_removes_stale_exited_container(self):
    plugin, client, _ = make_lifecycle_runner()
    stale = make_mock_container(status="exited")
    client.containers.get.side_effect = None
    client.containers.get.return_value = stale

    plugin._ensure_no_stale_container()

    stale.remove.assert_called_once_with(force=True)

  def test_noop_when_no_stale_container(self):
    plugin, client, _ = make_lifecycle_runner()
    # Default: containers.get raises NotFound
    plugin._ensure_no_stale_container()  # should not raise

  def test_logs_error_on_removal_failure(self):
    plugin, client, _ = make_lifecycle_runner()
    stale = make_mock_container()
    stale.remove.side_effect = Exception("permission denied")
    client.containers.get.side_effect = None
    client.containers.get.return_value = stale

    plugin._ensure_no_stale_container()  # should not raise

    errors = [m for m in plugin.logged_messages if "Failed to remove" in m]
    self.assertTrue(len(errors) > 0)


# ===========================================================================
# Process Loop
# ===========================================================================

class TestLifecycleProcess(unittest.TestCase):
  """Test process() main loop behavior."""

  def test_process_launches_container_when_none(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin.process()
    client.containers.run.assert_called_once()
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_process_checks_status_when_running(self):
    plugin, _, container = make_lifecycle_runner()
    plugin._handle_initial_launch()
    container.status = "running"

    plugin.process()

    container.reload.assert_called()

  def test_process_triggers_restart_on_crash(self):
    """process() detects crash on one iteration and restarts on the next (after backoff)."""
    clock = {"now": 100}
    plugin, client, container = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    with _patch_docker_module(client):
      plugin._handle_initial_launch()

      # Simulate crash
      container.status = "exited"
      container.attrs = {"State": {"ExitCode": 1, "Running": False}}

      new_container = make_mock_container()
      client.containers.run.return_value = new_container

      # First process() detects crash, records failure, sets backoff
      plugin.process()
      self.assertEqual(plugin.container_state, ContainerState.FAILED)

      # Advance time past backoff, second process() does the restart
      clock["now"] += 600
      plugin.process()

    # Initial + restart = 2 run calls
    self.assertEqual(client.containers.run.call_count, 2)
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_process_skips_when_paused(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin.container_state = ContainerState.PAUSED
    plugin.process()
    client.containers.run.assert_not_called()

  def test_process_respects_restart_policy_no(self):
    """With restart_policy='no', crashed container should not restart."""
    plugin, client, container = make_lifecycle_runner(cfg_restart_policy="no")
    plugin._handle_initial_launch()

    container.status = "exited"
    container.attrs = {"State": {"ExitCode": 1, "Running": False}}

    plugin.process()

    # Only the initial launch, no restart
    self.assertEqual(client.containers.run.call_count, 1)

  def test_process_respects_max_retries(self):
    """After exceeding max retries, should stop restarting."""
    plugin, client, container = make_lifecycle_runner(cfg_restart_max_retries=2)
    plugin._handle_initial_launch()

    # Simulate already exceeded retries
    plugin._consecutive_failures = 3

    container.status = "exited"
    container.attrs = {"State": {"ExitCode": 1, "Running": False}}

    plugin.process()

    # Should NOT restart
    self.assertEqual(client.containers.run.call_count, 1)
    errors = [m for m in plugin.logged_messages if "abandoned" in m.lower()]
    self.assertTrue(len(errors) > 0)

  def test_failed_cleanup_abandonment_logs_once(self):
    clock = {"now": 100}
    plugin, _, _ = make_lifecycle_runner(cfg_restart_max_retries=2)
    plugin.time = lambda: clock["now"]
    plugin._cleanup_failed = True
    plugin._consecutive_failures = 2
    plugin._next_restart_time = 200
    plugin.container_state = ContainerState.FAILED

    plugin.process()
    clock["now"] += 1
    plugin.process()

    errors = [
      m for m in plugin.logged_messages
      if "Container cleanup retry abandoned" in m
    ]
    self.assertEqual(len(errors), 1)

  def test_abandoned_cleanup_retries_after_backoff_then_restarts(self):
    clock = {"now": 100}
    plugin, client, _ = make_lifecycle_runner(cfg_restart_max_retries=2)
    plugin.time = lambda: clock["now"]
    plugin._cleanup_failed = True
    plugin._consecutive_failures = 2
    plugin._next_restart_time = 90
    plugin.container_state = ContainerState.FAILED
    plugin._stop_container_and_save_logs_to_disk = MagicMock(return_value=True)

    plugin.process()

    self.assertFalse(plugin._cleanup_failed)
    plugin._stop_container_and_save_logs_to_disk.assert_called_once()
    client.containers.run.assert_called_once()
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_abandoned_cleanup_failure_schedules_future_probe_without_incrementing_failures(self):
    clock = {"now": 100}
    plugin, client, _ = make_lifecycle_runner(
      cfg_restart_max_retries=2,
      cfg_restart_backoff_max=60,
    )
    plugin.time = lambda: clock["now"]
    plugin._cleanup_failed = True
    plugin._consecutive_failures = 2
    plugin._next_restart_time = 90
    plugin.container_state = ContainerState.FAILED
    plugin._stop_container_and_save_logs_to_disk = MagicMock(return_value=False)

    plugin.process()

    self.assertTrue(plugin._cleanup_failed)
    self.assertEqual(plugin._consecutive_failures, 2)
    self.assertEqual(plugin._next_restart_time, 160)
    plugin._stop_container_and_save_logs_to_disk.assert_called_once()
    client.containers.run.assert_not_called()

  def test_process_retries_failed_cleanup_then_restarts(self):
    """A transient cleanup failure must not permanently block process()."""
    clock = {"now": 100}
    plugin, client, _ = make_lifecycle_runner(cfg_restart_backoff_initial=0)
    plugin.time = lambda: clock["now"]
    plugin._cleanup_failed = True
    plugin.container_state = ContainerState.FAILED

    attempts = {"count": 0}

    def retry_cleanup():
      attempts["count"] += 1
      plugin._cleanup_failed = attempts["count"] == 1
      return not plugin._cleanup_failed

    plugin._stop_container_and_save_logs_to_disk = retry_cleanup

    plugin.process()
    self.assertTrue(plugin._cleanup_failed)
    client.containers.run.assert_not_called()

    with _patch_docker_module(client):
      plugin.process()

    self.assertFalse(plugin._cleanup_failed)
    client.containers.run.assert_called_once()
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_manual_stop_persists_only_after_cleanup_success(self):
    plugin, _, _ = make_lifecycle_runner(cfg_restart_backoff_initial=0)
    plugin._save_persistent_state = MagicMock()
    plugin._clear_manual_stop_state = MagicMock()
    plugin._stop_container_and_save_logs_to_disk = MagicMock(return_value=False)

    plugin.on_command("STOP")

    plugin._save_persistent_state.assert_not_called()
    plugin._clear_manual_stop_state.assert_called_once()
    self.assertTrue(plugin._manual_stop_pending)
    self.assertEqual(plugin.container_state, ContainerState.FAILED)

  def test_pending_manual_stop_pauses_after_cleanup_retry_success(self):
    plugin, client, _ = make_lifecycle_runner(cfg_restart_backoff_initial=0)
    plugin._cleanup_failed = True
    plugin._manual_stop_pending = True
    plugin.container_state = ContainerState.FAILED
    plugin._save_persistent_state = MagicMock()
    plugin._stop_container_and_save_logs_to_disk = MagicMock(return_value=True)

    plugin.process()

    plugin._save_persistent_state.assert_called_once_with(manually_stopped=True)
    client.containers.run.assert_not_called()
    self.assertFalse(plugin._manual_stop_pending)
    self.assertEqual(plugin.container_state, ContainerState.PAUSED)

  def test_restart_clears_pending_manual_stop_before_cleanup_retry(self):
    plugin, client, _ = make_lifecycle_runner(cfg_restart_backoff_initial=0)
    plugin._manual_stop_pending = True
    plugin._cleanup_failed = True
    plugin._save_persistent_state = MagicMock()
    plugin._clear_manual_stop_state = MagicMock()
    attempts = {"count": 0}

    def cleanup():
      attempts["count"] += 1
      plugin._cleanup_failed = attempts["count"] == 1
      return not plugin._cleanup_failed

    plugin._stop_container_and_save_logs_to_disk = cleanup

    plugin.on_command("RESTART")

    plugin._clear_manual_stop_state.assert_called_once()
    plugin._save_persistent_state.assert_not_called()
    self.assertFalse(plugin._manual_stop_pending)
    self.assertTrue(plugin._cleanup_failed)

    with _patch_docker_module(client):
      plugin.process()

    plugin._save_persistent_state.assert_not_called()
    self.assertFalse(plugin._cleanup_failed)
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)

  def test_config_restart_respects_pending_manual_stop_cleanup(self):
    plugin, _, _ = make_lifecycle_runner(cfg_restart_backoff_initial=0)
    plugin._manual_stop_pending = True
    plugin._cleanup_failed = True
    plugin._save_persistent_state = MagicMock()
    plugin._stop_container_and_save_logs_to_disk = MagicMock(return_value=True)
    restart_callable = MagicMock()

    plugin._handle_config_restart(restart_callable)

    restart_callable.assert_not_called()
    plugin._save_persistent_state.assert_called_once_with(manually_stopped=True)
    self.assertFalse(plugin._manual_stop_pending)
    self.assertFalse(plugin._cleanup_failed)
    self.assertEqual(plugin.container_state, ContainerState.PAUSED)

  def test_process_multiple_iterations_running(self):
    """Multiple process() calls with a healthy container should all succeed."""
    plugin, _, container = make_lifecycle_runner()
    plugin._handle_initial_launch()
    container.status = "running"

    for _ in range(5):
      plugin.process()

    self.assertEqual(plugin.container_state, ContainerState.RUNNING)


class _FakeProcess:
  def __init__(self):
    self.terminated = False
    self.killed = False
    self.wait_calls = 0

  def poll(self):
    return 0 if self.killed else None

  def terminate(self):
    self.terminated = True
    return

  def kill(self):
    self.killed = True
    return

  def wait(self, timeout=None):
    self.wait_calls += 1
    if self.wait_calls == 1:
      raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)
    self.killed = True
    return 0


class _StoppedProcess:
  def __init__(self, pgid):
    self.pid = pgid
    self._r1_process_group_id = pgid
    self.terminated = False
    self.killed = False

  def poll(self):
    return 0

  def terminate(self):
    self.terminated = True
    return

  def kill(self):
    self.killed = True
    return

  def wait(self, timeout=None):
    return 0


def _fake_proc_stat_open(proc_entries):
  def fake_open(path, *args, **kwargs):
    pid_name = Path(path).parent.name
    state, pgid = proc_entries[pid_name]
    stat = f"{pid_name} (cloudflared) {state} 1 {pgid} 0 0\n"
    return MagicMock(__enter__=lambda self: self, __exit__=lambda *args: None, read=lambda: stat)
  return fake_open


class TestTunnelCompatibilityFallbacks(unittest.TestCase):
  """The edge PR must work even before the matching core PR is deployed."""

  def test_local_subprocess_termination_fallback_without_core_helper(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _FakeProcess()

    with patch("extensions.business.container_apps.container_app_runner.os.name", "nt"):
      self.assertTrue(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

    self.assertTrue(process.terminated)
    self.assertTrue(process.killed)

  def test_local_subprocess_fallback_treats_zombie_only_group_as_stopped(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    proc_entries = {"456": ("Z", 123)}

    with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
         patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
         patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=list(proc_entries)), \
         patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
         patch("builtins.open", _fake_proc_stat_open(proc_entries)):
      self.assertTrue(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

    self.assertFalse(process.terminated)
    self.assertFalse(process.killed)

  def test_local_subprocess_fallback_keeps_live_group_failed(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    proc_entries = {"456": ("S", 123)}

    with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
         patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
         patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=list(proc_entries)), \
         patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
         patch("builtins.open", _fake_proc_stat_open(proc_entries)):
      self.assertFalse(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

    self.assertFalse(process.terminated)
    self.assertFalse(process.killed)

  def test_extra_tunnel_stopped_parent_with_live_descendant_is_preserved(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    proc_entries = {"456": ("S", 123)}
    plugin.extra_tunnel_processes = {8080: process}
    plugin.extra_tunnel_log_readers = {8080: {}}
    plugin.extra_tunnel_urls = {8080: "https://example.test"}
    plugin.extra_tunnel_start_times = {8080: 10}

    with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
         patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
         patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=list(proc_entries)), \
         patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
         patch("builtins.open", _fake_proc_stat_open(proc_entries)):
      self.assertFalse(plugin._stop_extra_tunnel(8080))

    self.assertIn(8080, plugin.extra_tunnel_processes)
    self.assertIn(8080, plugin.extra_tunnel_log_readers)
    self.assertIn(8080, plugin.extra_tunnel_urls)


# ===========================================================================
# Fixed-Size Volume Integration
# ===========================================================================

class TestLifecycleFixedVolumes(unittest.TestCase):
  """Test fixed-size volumes through the lifecycle."""

  @patch("extensions.business.container_apps.fixed_volume.provision")
  @patch("extensions.business.container_apps.fixed_volume.cleanup_stale_mounts")
  @patch("extensions.business.container_apps.fixed_volume._require_tools")
  @patch("extensions.business.container_apps.fixed_volume.docker_bind_spec",
         return_value={"/mnt/vol": {"bind": "/app/data", "mode": "rw"}})
  def test_provision_before_start(self, mock_spec, mock_tools, mock_stale, mock_prov):
    plugin, client, _ = make_lifecycle_runner(
      cfg_fixed_size_volumes={"data": {"SIZE": "50M", "MOUNTING_POINT": "/app/data"}}
    )

    with patch.object(Path, "is_dir", return_value=False):
      plugin._configure_fixed_size_volumes()

    self.assertEqual(len(plugin._fixed_volumes), 1)
    self.assertIn("/mnt/vol", plugin.volumes)
    mock_prov.assert_called_once()

  @patch("extensions.business.container_apps.fixed_volume.cleanup")
  def test_cleanup_on_stop(self, mock_cleanup):
    from extensions.business.container_apps.fixed_volume import FixedVolume

    plugin, _, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()

    vol = FixedVolume(name="data", size="50M", root=Path("/tmp/fv"))
    plugin._fixed_volumes = [vol]

    plugin._stop_container_and_save_logs_to_disk()

    mock_cleanup.assert_called_once_with(vol, logger=plugin.P)
    self.assertEqual(plugin._fixed_volumes, [])

  @patch("extensions.business.container_apps.fixed_volume.cleanup")
  @patch("extensions.business.container_apps.fixed_volume.provision")
  @patch("extensions.business.container_apps.fixed_volume.cleanup_stale_mounts")
  @patch("extensions.business.container_apps.fixed_volume._require_tools")
  @patch("extensions.business.container_apps.fixed_volume.docker_bind_spec",
         return_value={"/mnt/vol": {"bind": "/app/data", "mode": "rw"}})
  def test_reprovision_on_restart(
    self, mock_spec, mock_tools, mock_stale, mock_prov, mock_cleanup
  ):
    from extensions.business.container_apps.fixed_volume import FixedVolume

    plugin, client, container = make_lifecycle_runner(
      cfg_fixed_size_volumes={"data": {"SIZE": "50M", "MOUNTING_POINT": "/app/data"}}
    )
    plugin._handle_initial_launch()

    vol = FixedVolume(name="data", size="50M", root=Path("/tmp/fv"))
    plugin._fixed_volumes = [vol]

    # Crash
    container.status = "exited"
    container.attrs = {"State": {"ExitCode": 1, "Running": False}}
    plugin._check_container_status()

    new_container = make_mock_container()
    client.containers.run.return_value = new_container

    with _patch_docker_module(client), \
         patch.object(Path, "is_dir", return_value=False):
      plugin._restart_container(StopReason.CRASH)

    mock_cleanup.assert_called()
    mock_prov.assert_called()

  @patch("extensions.business.container_apps.fixed_volume._require_tools",
         side_effect=RuntimeError("missing tools"))
  def test_graceful_degradation_missing_tools(self, mock_tools):
    plugin, client, _ = make_lifecycle_runner(
      cfg_fixed_size_volumes={"data": {"SIZE": "50M", "MOUNTING_POINT": "/app/data"}}
    )

    plugin._configure_fixed_size_volumes()

    # Should not crash, volumes list empty, container can still start
    self.assertEqual(plugin._fixed_volumes, [])
    plugin._handle_initial_launch()
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)


# ===========================================================================
# Deprecated VOLUMES Warning
# ===========================================================================

class TestLifecycleDeprecation(unittest.TestCase):
  """Test that VOLUMES deprecation warning is emitted."""

  @patch("os.makedirs")
  @patch("os.chmod")
  def test_volumes_logs_deprecation_warning(self, mock_chmod, mock_makedirs):
    plugin, _, _ = make_lifecycle_runner()
    plugin.cfg_volumes = {"/host/data": "/container/data"}

    plugin._configure_volumes()

    warnings = [m for m in plugin.logged_messages if "deprecated" in m.lower()]
    self.assertTrue(len(warnings) > 0, "Expected deprecation warning for VOLUMES")

  def test_no_warning_when_volumes_empty(self):
    plugin, _, _ = make_lifecycle_runner()
    plugin.cfg_volumes = {}
    plugin._configure_volumes()

    warnings = [m for m in plugin.logged_messages if "deprecated" in m.lower()]
    self.assertEqual(len(warnings), 0)


# ===========================================================================
# Full Lifecycle End-to-End
# ===========================================================================

class TestLifecycleEndToEnd(unittest.TestCase):
  """End-to-end lifecycle: launch -> run -> crash -> restart -> stop -> close."""

  def test_full_lifecycle(self):
    clock = {"now": 100}
    plugin, client, container = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    with _patch_docker_module(client):
      # Phase 1: First launch via process()
      plugin.process()
      self.assertEqual(plugin.container_state, ContainerState.RUNNING)
      self.assertIsNotNone(plugin.container)

      # Phase 2: Several healthy process() iterations
      container.status = "running"
      for _ in range(3):
        clock["now"] += 5
        plugin.process()
      self.assertEqual(plugin.container_state, ContainerState.RUNNING)

      # Phase 3: Container crashes
      container.status = "exited"
      container.attrs = {"State": {"ExitCode": 137, "Running": False}}

      new_container = make_mock_container()
      client.containers.run.return_value = new_container

      # First process() detects crash, sets backoff
      plugin.process()
      self.assertEqual(plugin.container_state, ContainerState.FAILED)

      # Advance time past backoff, second process() restarts
      clock["now"] += 600
      plugin.process()

      self.assertEqual(plugin.container_state, ContainerState.RUNNING)
      self.assertEqual(client.containers.run.call_count, 2)

      # Phase 4: Running again after restart
      new_container.status = "running"
      plugin.process()
      self.assertEqual(plugin.container_state, ContainerState.RUNNING)

      # Phase 5: Graceful shutdown
      plugin.on_close()
      self.assertIsNone(plugin.container)

  def test_multiple_crashes_increment_failures(self):
    plugin, client, container = make_lifecycle_runner()
    plugin._handle_initial_launch()

    for i in range(3):
      # Crash
      container.status = "exited"
      container.attrs = {"State": {"ExitCode": 1, "Running": False}}
      plugin._check_container_status()
      self.assertEqual(plugin._consecutive_failures, i + 1)

      # Restart
      new_container = make_mock_container()
      client.containers.run.return_value = new_container
      container = new_container

      with _patch_docker_module(client):
        plugin._restart_container(StopReason.CRASH)

    self.assertEqual(plugin._consecutive_failures, 3)


# ===========================================================================
# Image Pull Backoff
# ===========================================================================

class TestImagePullBackoff(unittest.TestCase):
  """Test exponential backoff with jitter for image pull retries."""

  def test_first_pull_has_no_backoff(self):
    plugin, _, _ = make_lifecycle_runner()
    self.assertFalse(plugin._is_image_pull_backoff_active())
    self.assertEqual(plugin._image_pull_failures, 0)

  def test_failure_sets_backoff(self):
    clock = {"now": 100}
    plugin, _, _ = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    plugin._record_image_pull_failure()

    self.assertEqual(plugin._image_pull_failures, 1)
    self.assertGreater(plugin._next_image_pull_time, clock["now"])
    self.assertTrue(plugin._is_image_pull_backoff_active())

  def test_backoff_clears_after_delay(self):
    clock = {"now": 100}
    plugin, _, _ = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    plugin._record_image_pull_failure()

    # Advance time well past backoff
    clock["now"] += 10000
    self.assertFalse(plugin._is_image_pull_backoff_active())

  def test_success_resets_counters(self):
    clock = {"now": 100}
    plugin, _, _ = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    # Accumulate failures
    for _ in range(5):
      plugin._record_image_pull_failure()
      clock["now"] += 1

    self.assertEqual(plugin._image_pull_failures, 5)

    plugin._record_image_pull_success()

    self.assertEqual(plugin._image_pull_failures, 0)
    self.assertEqual(plugin._next_image_pull_time, 0)
    self.assertFalse(plugin._is_image_pull_backoff_active())

  def test_backoff_grows_exponentially(self):
    clock = {"now": 100}
    plugin, _, _ = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    delays = []
    for i in range(5):
      plugin._image_pull_failures = i + 1
      backoff = plugin._calculate_image_pull_backoff()
      # Backoff = base * 2^(failures-1) + jitter, where jitter in [0, base * 2^(failures-1)]
      # So minimum is base * 2^(failures-1), maximum is 2 * base * 2^(failures-1)
      base_part = plugin.cfg_image_pull_backoff_base * (2 ** i)
      self.assertGreaterEqual(backoff, base_part)
      self.assertLessEqual(backoff, 2 * base_part)
      delays.append(backoff)

    # Each delay should be roughly double the previous (accounting for jitter)
    for i in range(1, len(delays)):
      # The minimum of delay[i] (= base * 2^i) should be >= minimum of delay[i-1] (= base * 2^(i-1))
      self.assertGreater(delays[i], delays[i - 1] * 0.5)

  def test_jitter_adds_randomness(self):
    """Multiple backoff calculations with same failure count should differ."""
    plugin, _, _ = make_lifecycle_runner()
    plugin._image_pull_failures = 5

    values = set()
    for _ in range(20):
      values.add(plugin._calculate_image_pull_backoff())

    # With random jitter, we should get multiple distinct values
    self.assertGreater(len(values), 1, "Expected jitter to produce varied backoff values")

  def test_max_retries_gives_up(self):
    plugin, client, _ = make_lifecycle_runner(cfg_image_pull_max_retries=3)
    plugin._image_pull_failures = 3

    result = plugin._pull_image_from_registry()

    self.assertIsNone(result)
    client.images.pull.assert_not_called()
    msgs = [m for m in plugin.logged_messages if "abandoned" in m.lower()]
    self.assertTrue(len(msgs) > 0)

  def test_unlimited_retries_when_max_zero(self):
    plugin, _, _ = make_lifecycle_runner(cfg_image_pull_max_retries=0)
    plugin._image_pull_failures = 9999
    self.assertFalse(plugin._has_exceeded_image_pull_retries())

  def test_pull_failure_triggers_backoff_in_registry_method(self):
    """_pull_image_from_registry should record failure and set backoff on exception."""
    clock = {"now": 100}
    plugin, client, _ = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]
    client.images.pull.side_effect = Exception("429 Too Many Requests")

    result = plugin._pull_image_from_registry()

    self.assertIsNone(result)
    self.assertEqual(plugin._image_pull_failures, 1)
    self.assertTrue(plugin._is_image_pull_backoff_active())

  def test_pull_success_resets_backoff_in_registry_method(self):
    """_pull_image_from_registry should reset counters on successful pull."""
    clock = {"now": 100}
    plugin, client, _ = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    # Simulate prior failures
    plugin._image_pull_failures = 3
    plugin._next_image_pull_time = 0  # Allow pull

    result = plugin._pull_image_from_registry()

    self.assertIsNotNone(result)
    self.assertEqual(plugin._image_pull_failures, 0)
    self.assertEqual(plugin._next_image_pull_time, 0)

  def test_backoff_skips_pull_attempt(self):
    """When in backoff, _pull_image_from_registry should return None without calling Docker."""
    clock = {"now": 100}
    plugin, client, _ = make_lifecycle_runner()
    plugin.time = lambda: clock["now"]

    # Set active backoff
    plugin._image_pull_failures = 1
    plugin._next_image_pull_time = 200  # Backoff until t=200

    result = plugin._pull_image_from_registry()

    self.assertIsNone(result)
    client.images.pull.assert_not_called()

  def test_no_max_backoff_cap(self):
    """Backoff should grow without limit (no artificial cap)."""
    plugin, _, _ = make_lifecycle_runner()

    # After 20 failures, backoff should be huge (base * 2^19 = 2 * 524288 = ~1M seconds)
    plugin._image_pull_failures = 20
    backoff = plugin._calculate_image_pull_backoff()

    expected_min = plugin.cfg_image_pull_backoff_base * (2 ** 19)  # 1,048,576 seconds
    self.assertGreaterEqual(backoff, expected_min)


if __name__ == "__main__":
  unittest.main()
