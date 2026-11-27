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
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from extensions.business.container_apps.tests.support import install_docker_stub_if_needed

install_docker_stub_if_needed()

import docker.errors
import docker.types

from extensions.business.container_apps.tests.support import (
  make_container_app_runner,
  make_lifecycle_runner,
  make_mock_container,
  make_mock_docker_client,
  # Gives a runner the core's `cfg_` getters, whose dict values are copies: a write into one is lost, as on a node.
  read_config_like_a_node,
)
from extensions.business.container_apps.container_app_runner import (
  ContainerAppRunnerPlugin,
  ContainerState,
  StopReason,
)
from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin
# The name of the file an app writes to ask for a publish.
from extensions.business.container_apps.sync.constants import SYNC_REQUEST_FILE
# The folder where the app leaves that file.
from extensions.business.container_apps.sync.manager import volume_sync_dir


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

  def _make_initializing_runner(self, image_results):
    plugin, _, _ = make_lifecycle_runner()
    plugin._ContainerAppRunnerPlugin__reset_vars = MagicMock()
    plugin._apply_per_node_config = MagicMock()
    plugin._login_to_registry = MagicMock(return_value=True)
    plugin._setup_resource_limits_and_ports = MagicMock()
    plugin._ensure_image_available = MagicMock(side_effect=image_results)
    plugin._configure_volumes = MagicMock()
    plugin._configure_file_volumes = MagicMock()
    plugin._configure_fixed_size_volumes = MagicMock()
    plugin._configure_system_volume = MagicMock()
    plugin._configure_env_overrides_control_dir = MagicMock()
    plugin._configure_reset_control_dir = MagicMock()
    plugin._recover_stale_processing = MagicMock()
    plugin._recover_env_overrides_processing = MagicMock()
    plugin._recover_reset_processing = MagicMock()
    plugin._validate_sync_config = MagicMock()
    plugin._setup_env_and_ports = MagicMock()
    plugin._inject_sync_env_vars = MagicMock()
    plugin._inject_env_overrides_env_vars = MagicMock()
    plugin._inject_reset_env_vars = MagicMock()
    plugin._validate_extra_tunnels_config = MagicMock()
    plugin._validate_runner_config = MagicMock()
    plugin._load_manual_stop_state = MagicMock(return_value=False)
    plugin._extra_on_init = MagicMock()
    plugin._handle_initial_launch = MagicMock()

    setup = MagicMock()
    for name in (
      '_configure_fixed_size_volumes',
      '_configure_system_volume',
      '_configure_env_overrides_control_dir',
      '_configure_reset_control_dir',
      '_recover_stale_processing',
      '_recover_env_overrides_processing',
      '_recover_reset_processing',
      '_validate_sync_config',
      '_setup_env_and_ports',
      '_inject_sync_env_vars',
      '_inject_env_overrides_env_vars',
      '_inject_reset_env_vars',
      '_handle_initial_launch',
    ):
      setup.attach_mock(getattr(plugin, name), name)
    return plugin, setup

  def _assert_volume_setup_order(self, setup, launched=False):
    expected = [
      call._configure_fixed_size_volumes(),
      call._configure_system_volume(),
      call._configure_env_overrides_control_dir(),
      call._configure_reset_control_dir(),
      call._recover_stale_processing(),
      call._recover_env_overrides_processing(),
      call._recover_reset_processing(),
      call._validate_sync_config(),
      call._setup_env_and_ports(),
      call._inject_sync_env_vars(),
      call._inject_env_overrides_env_vars(),
      call._inject_reset_env_vars(),
    ]
    if launched:
      expected.append(call._handle_initial_launch())
    self.assertEqual(setup.mock_calls, expected)

  def test_cached_image_configures_volumes_and_controls_in_order(self):
    plugin, setup = self._make_initializing_runner([True])

    plugin.on_init()

    self._assert_volume_setup_order(setup)
    self.assertFalse(plugin._fixed_volume_setup_pending)

  def test_a_failed_registry_login_ends_the_start_only_of_an_app_not_bound_to_an_image_yet(self):
    plugin, _ = self._make_initializing_runner([True])
    plugin._login_to_registry = MagicMock(return_value=False)
    with self.assertRaisesRegex(RuntimeError, "login to container registry"):
      plugin.on_init()  # a first start with credentials that do not work fails at once, as before
    # Already bound (its node's container was replaced while the registry was down): it goes on. The
    # image may be in the local store, and the recovery logs in again before every registry attempt.
    plugin, _ = self._make_initializing_runner([False])
    plugin._login_to_registry = MagicMock(return_value=False)
    plugin._deployment_operation_key = "operation|deploy"
    plugin._load_persistent_state = lambda: {"deployment_runtime_artifacts": {
      "operation_key": "operation|deploy", "artifacts": {"image_id": "sha256:" + "a" * 64},
    }}
    plugin.on_init()
    plugin._ensure_image_available.assert_called_once_with()
    self.assertTrue(plugin._fixed_volume_setup_pending)  # process() asks for the image again on every lap

  def test_initial_image_pull_failure_is_retried_before_volume_setup(self):
    plugin, setup = self._make_initializing_runner([False, False, True])

    plugin.on_init()

    self.assertEqual(setup.mock_calls, [])
    plugin._extra_on_init.assert_called_once_with()
    self.assertFalse(plugin._restart_container())
    plugin._configure_fixed_size_volumes.assert_not_called()
    plugin.container_state = ContainerState.PAUSED
    plugin.process()
    self.assertEqual(plugin._ensure_image_available.call_count, 1)
    plugin.container_state = ContainerState.UNINITIALIZED

    plugin.process()
    self.assertEqual(setup.mock_calls, [])
    plugin._configure_fixed_size_volumes.assert_not_called()
    plugin._handle_initial_launch.assert_not_called()

    plugin.process()
    plugin._configure_fixed_size_volumes.assert_called_once_with()
    plugin._handle_initial_launch.assert_called_once_with()
    self._assert_volume_setup_order(setup, launched=True)
    self.assertFalse(plugin._fixed_volume_setup_pending)

    setup.reset_mock()
    plugin.process()
    self.assertEqual(setup.mock_calls, [call._handle_initial_launch()])
    self.assertEqual(plugin._ensure_image_available.call_count, 3)

  def test_image_recovery_waits_for_semaphores_before_environment_setup(self):
    plugin, _ = self._make_initializing_runner([False, True])
    plugin.cfg_semaphored_keys = ['provider']
    plugin._wait_for_semaphores = MagicMock(return_value=False)
    plugin._handle_initial_launch.side_effect = lambda: (
      ContainerAppRunnerPlugin._handle_initial_launch(plugin)
    )
    plugin.on_init()
    plugin.process()

    plugin._configure_system_volume.assert_called_once_with()
    plugin._setup_env_and_ports.assert_not_called()
    plugin._inject_sync_env_vars.assert_not_called()
    self.assertFalse(plugin._fixed_volume_setup_pending)

    plugin._wait_for_semaphores.return_value = True
    plugin._ensure_image_available.side_effect = None
    plugin._ensure_image_available.return_value = True
    plugin._configure_dynamic_env = MagicMock()
    plugin.start_container = MagicMock(return_value=None)
    plugin.process()

    plugin._configure_system_volume.assert_called_once_with()
    plugin._setup_env_and_ports.assert_called_once_with()
    plugin._inject_sync_env_vars.assert_called_once_with()
    plugin._inject_env_overrides_env_vars.assert_called_once_with()
    plugin._inject_reset_env_vars.assert_called_once_with()
    plugin.start_container.assert_called_once_with()

  def test_image_recovery_provisions_controls_and_recovers_request_files(self):
    for system_available in (True, False):
      with self.subTest(system_available=system_available), tempfile.TemporaryDirectory() as tmp:
        plugin, _ = self._make_initializing_runner([False, True])
        plugin.get_data_folder = lambda: tmp
        plugin.cfg_fixed_size_volumes = {
          'data': {'SIZE': '10M', 'MOUNTING_POINT': '/data', 'OWNER_UID': 0, 'OWNER_GID': 0},
        }
        for name in (
          '_configure_fixed_size_volumes', '_configure_system_volume',
          '_configure_env_overrides_control_dir', '_configure_reset_control_dir',
          '_recover_stale_processing', '_recover_env_overrides_processing',
          '_recover_reset_processing', '_validate_sync_config',
          '_setup_env_and_ports', '_inject_sync_env_vars',
          '_inject_env_overrides_env_vars', '_inject_reset_env_vars',
        ):
          delattr(plugin, name)

        mounted = set()

        def provision(vol, **kwargs):
          if vol.name == 'r1en_system' and not system_available:
            raise RuntimeError('system volume unavailable')
          vol.mount_path.mkdir(parents=True, exist_ok=True)
          mounted.add(str(vol.mount_path))
          if vol.name == 'r1en_system':
            for directory in ('volume-sync', 'env-overrides', 'reset'):
              control = vol.mount_path / directory
              control.mkdir()
              (control / 'request.json.processing').write_text('{}')

        def assert_launch_controls():
          self.assertEqual(len(mounted), 2 if system_available else 1)
          for host, spec in plugin.volumes.items():
            self.assertIn(host, mounted)
            if spec['bind'] == '/r1en_system':
              for directory in ('volume-sync', 'env-overrides', 'reset'):
                control = Path(host) / directory
                self.assertEqual((control / 'request.json').read_text(), '{}')
                self.assertFalse((control / 'request.json.processing').exists())
          for env_key in (
            'R1_SYSTEM_VOLUME', 'R1_VOLUME_SYNC_DIR', 'R1_ENV_OVERRIDES_DIR', 'R1_RESET_DIR',
          ):
            self.assertEqual(env_key in plugin.env, system_available)

        plugin._handle_initial_launch.side_effect = assert_launch_controls
        with (
          patch('extensions.business.container_apps.fixed_volume._require_tools'),
          patch('extensions.business.container_apps.fixed_volume.provision', side_effect=provision),
          patch(
            'extensions.business.container_apps.fixed_volume.cleanup_stale_mounts',
            side_effect=lambda *args, **kwargs: mounted.clear(),
          ) as cleanup,
          patch('os.chown'),
        ):
          plugin.on_init()
          self.assertEqual(mounted, set())
          self.assertEqual(plugin.env, {})
          plugin.process()
          cleanup.assert_called_once()
          plugin._handle_initial_launch.assert_called_once_with()


# ===========================================================================
# First Launch
# ===========================================================================

class TestLifecycleFirstLaunch(unittest.TestCase):
  """Test _handle_initial_launch() starting the container for the first time."""

  def test_starts_container_via_docker_run(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin._handle_initial_launch()
    client.containers.run.assert_called_once()

  def test_bare_docker_memory_limit_and_reservation_use_bytes(self):
    plugin, client, _ = make_lifecycle_runner()
    plugin._mem_limit = 512 * 1024 ** 2
    plugin._handle_initial_launch()
    kwargs = client.containers.run.call_args.kwargs
    self.assertEqual(kwargs["mem_limit"], 512 * 1024 ** 2)
    self.assertEqual(kwargs["mem_reservation"], (512 * 1024 ** 2) * 9 // 10)

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
    """A restart checks the SYNC block again before the start; one without a KEY leaves SYNC off, also on a node."""
    # A runner whose app has crashed.
    plugin, client, _ = self._launch_and_crash()
    # Its configuration read as on a node (each read of the block is a copy): SYNC enabled, but no KEY.
    read_config_like_a_node(plugin, SYNC={"ENABLED": True, "KEY": "", "TYPE": "provider"})
    # The system volume was provisioned.
    plugin._sync_unavailable = False
    # The container the restart will start.
    new_container = make_mock_container()
    # Docker hands it out at the next run.
    client.containers.run.return_value = new_container

    # The restart on the mocked Docker, without the two steps that need a real system volume, recording the check.
    with _patch_docker_module(client), \
         patch.object(plugin, "_configure_system_volume"), \
         patch.object(plugin, "_recover_stale_processing"), \
         patch.object(plugin, "_validate_sync_config", wraps=plugin._validate_sync_config) as validate:
      # The restart after the crash.
      plugin._restart_container(StopReason.CRASH)

    # The check ran.
    validate.assert_called()
    # It refused the block with its red line, once.
    self.assertEqual(
      plugin.logged_messages.count("[sync] SYNC.ENABLED but SYNC.KEY missing/empty; disabling SYNC."), 1,
    )
    # SYNC is off on the plugin, though the stored block still says enabled (the node does not rewrite it).
    self.assertEqual((plugin._sync_enabled(), plugin.config_data["SYNC"]["ENABLED"]), (False, True))
    # The arguments the restarted container was started with.
    _, kwargs = client.containers.run.call_args
    # Its environment names no SYNC role.
    self.assertNotIn("R1_SYNC_TYPE", kwargs["environment"])


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

  def test_additional_checks_skips_git_after_reset_work(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    calls = []

    def base_reset(_plugin, current_time):
      calls.append(("base", current_time))
      _plugin._reset_processed_this_tick = True
      return None

    def git_updates(current_time):
      calls.append(("git", current_time))
      return StopReason.EXTERNAL_UPDATE

    plugin._check_git_updates = git_updates

    with patch.object(
      ContainerAppRunnerPlugin,
      "_perform_additional_checks",
      autospec=True,
      side_effect=base_reset,
    ):
      result = plugin._perform_additional_checks(123.0)

    self.assertIsNone(result)
    self.assertEqual(calls, [("base", 123.0)])


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
    """A running container with the app's name is force-removed before a start, with its anonymous volumes."""
    # An app with no container of its own yet.
    plugin, client, _ = make_lifecycle_runner()
    # A container an earlier run left running under the app's name.
    stale = make_mock_container(status="running")
    # Docker finds it by that name ...
    client.containers.get.side_effect = None
    # ... and hands it over.
    client.containers.get.return_value = stale

    # The guard that runs before every start.
    plugin._ensure_no_stale_container()

    # Forced, because it runs; with its volumes (v), which no later container would ever get.
    stale.remove.assert_called_once_with(force=True, v=True)

  def test_removes_stale_exited_container(self):
    """A stopped container with the app's name is removed before a start, with its anonymous volumes."""
    # An app with no container of its own yet.
    plugin, client, _ = make_lifecycle_runner()
    # A container a killed node left, stopped, in the Docker store that is kept across node restarts.
    stale = make_mock_container(status="exited")
    # Docker finds it by that name ...
    client.containers.get.side_effect = None
    # ... and hands it over.
    client.containers.get.return_value = stale

    # The guard that runs before every start.
    plugin._ensure_no_stale_container()

    # With its volumes (v): without that, each node restart left one more volume per app in the kept store.
    stale.remove.assert_called_once_with(force=True, v=True)

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
    def restart(reason, cleanup_first=True):
      plugin.container = object()
      plugin.container_state = ContainerState.RUNNING
      return True
    plugin._restart_container = MagicMock(side_effect=restart)

    plugin.process()

    self.assertFalse(plugin._cleanup_failed)
    plugin._stop_container_and_save_logs_to_disk.assert_called_once()
    plugin._restart_container.assert_called_once_with(
      StopReason.UNKNOWN,
      cleanup_first=False,
    )
    client.containers.run.assert_not_called()
    self.assertEqual(plugin.container_state, ContainerState.RUNNING)
    self.assertEqual(plugin._consecutive_failures, 0)
    self.assertEqual(plugin._restart_backoff_seconds, 0)
    self.assertEqual(plugin._next_restart_time, 0)

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

  def test_abandoned_cleanup_probe_respects_zero_max_backoff(self):
    clock = {"now": 100}
    plugin, _, _ = make_lifecycle_runner(
      cfg_restart_backoff_initial=30,
      cfg_restart_backoff_max=0,
    )
    plugin.time = lambda: clock["now"]

    plugin._schedule_abandoned_cleanup_probe()

    self.assertEqual(plugin._restart_backoff_seconds, 1.0)
    self.assertEqual(plugin._next_restart_time, 101.0)

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

  def test_cleanup_retry_success_uses_full_restart_path(self):
    """Recovered cleanup must rebuild runtime config before starting again."""
    plugin, client, _ = make_lifecycle_runner(cfg_restart_backoff_initial=0)
    plugin._cleanup_failed = True
    plugin.container_state = ContainerState.FAILED
    plugin.stop_reason = StopReason.ENV_OVERRIDE
    plugin._stop_container_and_save_logs_to_disk = MagicMock(return_value=True)
    plugin._restart_container = MagicMock(return_value=True)

    plugin.process()

    plugin._restart_container.assert_called_once_with(
      StopReason.ENV_OVERRIDE,
      cleanup_first=False,
    )
    client.containers.run.assert_not_called()

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
    if pid_name not in proc_entries:
      raise FileNotFoundError(path)
    entry = proc_entries[pid_name]
    if isinstance(entry, Exception):
      raise entry
    state, pgid = entry
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

  def test_local_subprocess_fallback_keeps_mixed_group_failed(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    proc_entries = {
      "456": ("Z", 123),
      "789": ("S", 123),
    }

    with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
         patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
         patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=list(proc_entries)), \
         patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
         patch("builtins.open", _fake_proc_stat_open(proc_entries)):
      self.assertFalse(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

    self.assertFalse(process.terminated)
    self.assertFalse(process.killed)

  def test_local_subprocess_fallback_keeps_stopped_or_traced_group_failed(self):
    for state in ("T", "t"):
      with self.subTest(state=state):
        plugin, _, _ = make_lifecycle_runner()
        process = _StoppedProcess(pgid=123)
        proc_entries = {"456": (state, 123)}

        with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
             patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
             patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=list(proc_entries)), \
             patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
             patch("builtins.open", _fake_proc_stat_open(proc_entries)):
          self.assertFalse(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

        self.assertFalse(process.terminated)
        self.assertFalse(process.killed)

  def test_local_subprocess_fallback_ignores_vanished_and_mismatched_members(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    proc_entries = {
      "456": ("Z", 123),
      "789": ("S", 999),
    }

    with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
         patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
         patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=["456", "789", "901"]), \
         patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
         patch("builtins.open", _fake_proc_stat_open(proc_entries)):
      self.assertTrue(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

    self.assertFalse(process.terminated)
    self.assertFalse(process.killed)

  def test_local_subprocess_fallback_keeps_group_conservative_without_proc_matches(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    proc_entries = {"456": ("S", 999)}

    with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
         patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
         patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=list(proc_entries)), \
         patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
         patch("builtins.open", _fake_proc_stat_open(proc_entries)):
      self.assertFalse(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

    self.assertFalse(process.terminated)
    self.assertFalse(process.killed)

  def test_local_subprocess_fallback_skips_unreadable_proc_entries(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    proc_entries = {
      "456": ("Z", 123),
      "789": RuntimeError("broken stat"),
    }

    with patch("extensions.business.container_apps.container_app_runner.os.name", "posix"), \
         patch("extensions.business.container_apps.container_app_runner.os.path.isdir", return_value=True), \
         patch("extensions.business.container_apps.container_app_runner.os.listdir", return_value=list(proc_entries)), \
         patch("extensions.business.container_apps.container_app_runner.os.killpg", return_value=None), \
         patch("builtins.open", _fake_proc_stat_open(proc_entries)):
      self.assertTrue(plugin._terminate_subprocess_tree(process, terminate_timeout=0, kill_timeout=0))

    self.assertFalse(process.terminated)
    self.assertFalse(process.killed)

  def test_extra_tunnel_stopped_parent_with_live_descendant_is_preserved(self):
    plugin, _, _ = make_lifecycle_runner()
    process = _StoppedProcess(pgid=123)
    plugin.extra_tunnel_processes = {8080: process}
    plugin.extra_tunnel_log_readers = {8080: {}}
    plugin.extra_tunnel_urls = {8080: "https://example.test"}
    plugin.extra_tunnel_start_times = {8080: 10}
    plugin._terminate_subprocess_tree = MagicMock(return_value=False)

    self.assertFalse(plugin._stop_extra_tunnel(8080))

    plugin._terminate_subprocess_tree.assert_called_once_with(
      process,
      label="Extra tunnel for port 8080",
    )
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

  def test_an_untracked_app_keeps_its_uncapped_pull_pause(self):
    """
    An app outside Deeploy keeps the pull pacing it had: its pause is not capped at one hour.

    The one-hour ceiling is for tracked deployments, which never give up; an untracked app still stops after
    IMAGE_PULL_MAX_RETRIES (`test_max_retries_gives_up`) and keeps the doubling pause on the way there.
    """
    # A clock.
    clock = {"now": 100}
    # An untracked app.
    plugin, client, _ = make_lifecycle_runner()
    # It reads that clock.
    plugin.time = lambda: clock["now"]
    # The registry does not answer.
    client.images.pull.side_effect = Exception("registry unreachable")
    # Nine failures in a row so far.
    plugin._image_pull_failures = 9
    # The tenth fails too.
    self.assertIsNone(plugin._pull_image_from_registry())
    # 3-6 hours to the next attempt, as before: more than the one hour a tracked deployment waits at most.
    self.assertGreater(plugin._next_image_pull_time - clock["now"], 3600)

  def test_no_max_backoff_cap(self):
    """Backoff should grow without limit (no artificial cap)."""
    plugin, _, _ = make_lifecycle_runner()

    # After 20 failures, backoff should be huge (base * 2^19 = 2 * 524288 = ~1M seconds)
    plugin._image_pull_failures = 20
    backoff = plugin._calculate_image_pull_backoff()

    expected_min = plugin.cfg_image_pull_backoff_base * (2 ** 19)  # 1,048,576 seconds
    self.assertGreaterEqual(backoff, expected_min)


# ===========================================================================
# The per-set sync secret in a job's configured ENV
# ===========================================================================

class TestSyncSecretConfig(unittest.TestCase):
  """How _validate_sync_config and the env build treat ENV.R1EN_SYNC_SECRET and a refused SYNC block.

  Every runner here reads ``SYNC`` and ``ENV`` through the core's ``cfg_`` getters, as on a node: each read of
  a block is a copy, so a refusal that only wrote into such a copy would leave SYNC on and fail these tests.
  """

  # A secret in the accepted form: 64 lowercase hex characters (a fixed test value).
  VALID = "0123456789abcdef" * 4

  def setUp(self):
    """Create the folder the runners of one test keep their data in.

    Returns
    -------
    None
    """
    # Removed in tearDown.
    self._tmp = tempfile.TemporaryDirectory()

  def tearDown(self):
    """Remove that folder.

    Returns
    -------
    None
    """
    # Everything the runners wrote.
    self._tmp.cleanup()

  def _runner(self, env, role="provider"):
    """Build a runner with SYNC enabled and the given configured ENV, recording its log lines with their color.

    Parameters
    ----------
    env : dict
      The job's configured ``ENV`` (``cfg_env``).
    role : str, optional
      ``SYNC.TYPE``: ``provider`` (default) or ``consumer``.

    Returns
    -------
    tuple
      ``(plugin, lines)``; ``lines`` is the list of ``(color, text)`` the plugin logs from now on. The runner
      reads ``SYNC`` and ``ENV`` through the core's getters; a test changes them in ``plugin.config_data``.

    Examples
    --------
    >>> plugin, lines = self._runner({"R1EN_SYNC_SECRET": self.VALID})
    >>> plugin._validate_sync_config()
    >>> plugin._sync_enabled()
    True
    """
    # A real runner on a mocked Docker client.
    plugin, _client, _container = make_lifecycle_runner()
    # A fresh, enabled SYNC block and the job's configured ENV, read as on a node (`plugin.config_data` holds them).
    read_config_like_a_node(plugin, SYNC={"ENABLED": True, "KEY": "set-key-1", "TYPE": role}, ENV=dict(env))
    # The system volume was provisioned.
    plugin._sync_unavailable = False
    # A node clock past the first store refresh interval (60 s): a consumer tick that runs would refresh the store.
    plugin.time = lambda: 1000.0
    # The data folder the env build's local-override step reads.
    plugin.get_data_folder = lambda: self._tmp.name
    # Local overrides are available.
    plugin._env_overrides_unavailable = False
    # Their manager is created on first use.
    plugin._env_overrides_manager = None
    # Each logged line with its color, to tell the red refusal from the green "SYNC enabled" line.
    lines = []
    # The plugin's logger.
    plugin.P = lambda msg, color=None, **_kwargs: lines.append((color, str(msg)))
    # R1FS, which a publish or an apply would call.
    plugin.r1fs = MagicMock()
    # The three chain-store calls of a publish or a consumer tick.
    plugin.chainstore_hset, plugin.chainstore_hget, plugin.chainstore_hsync = MagicMock(), MagicMock(), MagicMock()
    # The runner and what it logs.
    return plugin, lines

  def test_invalid_sync_secret_disables_sync(self):
    """A secret in any other form than 64 lowercase hex disables SYNC on the job, with no shared-key fallback."""
    # Wrong forms; three start with a full valid secret, so only a whole-string check refuses them.
    invalid = [
      ("empty string", ""),
      ("32 x a", "a" * 32),
      ("63 characters", self.VALID[:63]),
      ("65 characters", self.VALID + "0"),
      ("valid plus a newline", self.VALID + "\n"),
      ("valid plus a letter", self.VALID + "x"),
      ("uppercase", self.VALID.upper()),
      ("int", 1234567890123456),
    ]
    # Both roles.
    for role in ("provider", "consumer"):
      # Every wrong form.
      for label, secret in invalid:
        # A failure names the role and the form.
        with self.subTest(role=role, secret=label):
          # A job whose ENV holds the malformed secret.
          plugin, lines = self._runner({"R1EN_SYNC_SECRET": secret, "APP_VAR": "1"}, role=role)
          # The check that runs at init and at every restart.
          plugin._validate_sync_config()
          # The red line names the variable.
          self.assertIn(
            ("r", "[sync] R1EN_SYNC_SECRET must be 64 lowercase hex characters; disabling SYNC."), lines,
          )
          # The lines that report SYNC as enabled.
          enabled_lines = [text for _color, text in lines if "SYNC enabled" in text]
          # SYNC is off by the plugin's own answer (a node does not rewrite the block), and no such line exists.
          self.assertEqual((plugin._sync_enabled(), enabled_lines), (False, []))
          if secret != "":
            # No line repeats the value, not even its first 8 characters.
            self.assertEqual([text for _color, text in lines if str(secret)[:8] in text], [])
          # The real env build.
          plugin._setup_env_and_ports()
          # The injection that follows every build.
          plugin._inject_sync_env_vars()
          # Which of the set's three variables and the app's own one the app's environment holds.
          held = [name for name in ("R1_SYNC_KEY", "R1_SYNC_TYPE", "R1EN_SYNC_SECRET", "APP_VAR") if name in plugin.env]
          # No set KEY and no role for the app, no secret; the app's own variable is kept with its value.
          self.assertEqual((held, plugin.env["APP_VAR"]), (["APP_VAR"], "1"))
          # No manager for this job.
          self.assertIsNone(plugin._ensure_sync_manager())
          # A provider tick.
          plugin._sync_provider_tick(1000.0)
          # A consumer tick.
          plugin._sync_consumer_tick(1000.0)
          # What a publish, a fetch, a store write, a store read and a store refresh would have called.
          mocks = [plugin.r1fs.add_file, plugin.r1fs.get_file, plugin.chainstore_hset, plugin.chainstore_hget,
                   plugin.chainstore_hsync]
          # Nothing was published or fetched under any key, and the store was not written, read or refreshed.
          self.assertEqual([mock.call_count for mock in mocks], [0, 0, 0, 0, 0])

  def test_valid_sync_secret_keeps_sync_enabled(self):
    """A 64-lowercase-hex secret keeps SYNC enabled; the green line names the archive format, not the value."""
    # A job whose ENV holds a well-formed secret.
    plugin, lines = self._runner({"R1EN_SYNC_SECRET": self.VALID, "APP_VAR": "1"})
    # The check that runs at init and at every restart.
    plugin._validate_sync_config()
    # The green "SYNC enabled" lines.
    greens = [text for color, text in lines if color == "g" and "SYNC enabled" in text]
    # SYNC stays on, with one such line.
    self.assertEqual((plugin._sync_enabled(), len(greens)), (True, 1))
    # It names the set format.
    self.assertIn("encryption=r1fs-set-v1", greens[0])
    # No line holds the secret, not even its first 8 characters.
    self.assertEqual([text for _color, text in lines if self.VALID[:8] in text], [])
    # The real env build copies the configured variable into the container env.
    plugin._setup_env_and_ports()
    # It is there before the injection.
    self.assertEqual(plugin.env["R1EN_SYNC_SECRET"], self.VALID)
    # The injection that follows every build.
    plugin._inject_sync_env_vars()
    # The KEY is exported, the secret's variable is gone, the app's own variable is kept.
    self.assertEqual(
      (plugin.env["R1_SYNC_KEY"], "R1EN_SYNC_SECRET" in plugin.env, plugin.env["APP_VAR"]),
      ("set-key-1", False, "1"),
    )
    # No other variable holds the secret's value.
    self.assertNotIn(self.VALID, [str(value) for value in plugin.env.values()])
    # The node still reads it from the config.
    self.assertEqual(plugin.cfg_sync_secret, self.VALID)
    # A job without the variable, or with a JSON null.
    for env in ({"APP_VAR": "1"}, {"R1EN_SYNC_SECRET": None}):
      # A failure names the ENV.
      with self.subTest(cfg_env=env):
        # A job of a set that uses the shared key.
        plugin, lines = self._runner(env)
        # The same check.
        plugin._validate_sync_config()
        # The green "SYNC enabled" lines.
        greens = [text for color, text in lines if color == "g" and "SYNC enabled" in text]
        # SYNC stays on, with one such line.
        self.assertEqual((plugin._sync_enabled(), len(greens)), (True, 1))
        # It names the shared-key format.
        self.assertIn("encryption=r1fs-default", greens[0])

  def test_refused_sync_config_stays_off_on_a_node(self):
    """Each refusal (no KEY, wrong TYPE, malformed secret) leaves SYNC off on a node: no tick work, no SYNC env."""
    # The three refusals: the change to a valid SYNC block, the job's ENV, and the red line that names the reason.
    refusals = [
      ("no KEY", {"KEY": ""}, {}, "[sync] SYNC.ENABLED but SYNC.KEY missing/empty; disabling SYNC."),
      ("wrong TYPE", {"TYPE": "mirror"}, {},
       "[sync] SYNC.TYPE must be 'provider' or 'consumer' (got 'mirror'); disabling SYNC."),
      ("malformed secret", {}, {"R1EN_SYNC_SECRET": "not-64-hex"},
       "[sync] R1EN_SYNC_SECRET must be 64 lowercase hex characters; disabling SYNC."),
    ]
    # Both roles (the wrong TYPE replaces the role, so that refusal runs twice with the same block).
    for role in ("provider", "consumer"):
      # Every refusal.
      for label, sync_change, env, red_line in refusals:
        # A failure names the role and the refusal; each case keeps its data in a folder of its own.
        with self.subTest(role=role, refusal=label), tempfile.TemporaryDirectory() as data_folder:
          # A job with an enabled SYNC block and its own variable, read as on a node.
          plugin, lines = self._runner({"APP_VAR": "1", **env}, role=role)
          # This case's data folder, so a request another case left cannot be seen here.
          plugin.get_data_folder = lambda: data_folder
          # The refused field, written into the node's configuration of the plugin.
          plugin.config_data["SYNC"].update(sync_change)
          # The folder the app writes its publish request to.
          request_dir = volume_sync_dir(plugin)
          # It exists, as after the system volume was provisioned.
          request_dir.mkdir(parents=True)
          # A publish request the app left there.
          (request_dir / SYNC_REQUEST_FILE).write_text('{"archive_paths": ["/app/data"]}')
          # The check that runs at init and at every restart.
          plugin._validate_sync_config()
          # Its red line, once, is the only red line, and no line reports SYNC as enabled.
          self.assertEqual(
            ([text for color, text in lines if color == "r"], [text for _c, text in lines if "SYNC enabled" in text]),
            ([red_line], []),
          )
          # SYNC is off on the plugin; the stored block still says enabled, the node does not rewrite it.
          self.assertEqual((plugin._sync_enabled(), plugin.config_data["SYNC"]["ENABLED"]), (False, True))
          # The real env build.
          plugin._setup_env_and_ports()
          # The injection that follows every build.
          plugin._inject_sync_env_vars()
          # The app gets no SYNC key, role or secret; it keeps the system volume and its own variable.
          self.assertEqual(
            ("R1_SYNC_KEY" in plugin.env, "R1_SYNC_TYPE" in plugin.env, "R1EN_SYNC_SECRET" in plugin.env,
             plugin.env["R1_SYSTEM_VOLUME"], plugin.env["APP_VAR"]),
            (False, False, False, "/r1en_system", "1"),
          )
          # No manager for this job.
          self.assertIsNone(plugin._ensure_sync_manager())
          # A provider tick.
          plugin._sync_provider_tick(1000.0)
          # A consumer tick.
          plugin._sync_consumer_tick(1000.0)
          # Nothing was published or fetched, and the store was not written, read or refreshed.
          self.assertEqual(
            (plugin.r1fs.add_file.call_count, plugin.r1fs.get_file.call_count, plugin.chainstore_hset.call_count,
             plugin.chainstore_hget.call_count, plugin.chainstore_hsync.call_count),
            (0, 0, 0, 0, 0),
          )
          # The app's request was not claimed or answered: it is still the only file in the folder.
          self.assertEqual([path.name for path in request_dir.iterdir()], [SYNC_REQUEST_FILE])
          # The ticks logged nothing: the refusal's line is still the only line of the SYNC feature.
          self.assertEqual([text for _color, text in lines if "[sync]" in text], [red_line])

  def test_corrected_sync_config_turns_sync_back_on(self):
    """A refused block is refused again at every check, and the check after the owner's correction turns SYNC on."""
    # The red line of a malformed secret.
    red_line = "[sync] R1EN_SYNC_SECRET must be 64 lowercase hex characters; disabling SYNC."
    # A job whose ENV holds a malformed secret, read as on a node.
    plugin, lines = self._runner({"R1EN_SYNC_SECRET": "not-64-hex"}, role="consumer")
    # The check at init.
    plugin._validate_sync_config()
    # The check of a restart with the same configuration.
    plugin._validate_sync_config()
    # SYNC is off after both, with one red line per check and no "SYNC enabled" line.
    self.assertEqual(
      (plugin._sync_enabled(), lines.count(("r", red_line)), [text for _c, text in lines if "SYNC enabled" in text]),
      (False, 2, []),
    )
    # The owner corrects the secret: the node replaces the plugin's configuration with the edited one.
    plugin.config_data = {"SYNC": dict(plugin.config_data["SYNC"]), "ENV": {"R1EN_SYNC_SECRET": self.VALID}}
    # The check of the restart that follows a configuration edit.
    plugin._validate_sync_config()
    # The green "SYNC enabled" lines.
    greens = [text for color, text in lines if color == "g" and "SYNC enabled" in text]
    # SYNC is on, with one green line and no further red line.
    self.assertEqual((plugin._sync_enabled(), len(greens), lines.count(("r", red_line))), (True, 1, 2))
    # The real env build.
    plugin._setup_env_and_ports()
    # The injection that follows every build.
    plugin._inject_sync_env_vars()
    # The app now gets the set's KEY and its role, and still not the secret.
    self.assertEqual(
      (plugin.env["R1_SYNC_KEY"], plugin.env["R1_SYNC_TYPE"], "R1EN_SYNC_SECRET" in plugin.env),
      ("set-key-1", "consumer", False),
    )

  def test_refusal_holds_when_a_restart_fails_before_the_check(self):
    """A restart that fails after its state reset and before the SYNC check leaves a refused block refused."""
    # A job whose ENV holds a malformed secret, read as on a node.
    plugin, _lines = self._runner({"R1EN_SYNC_SECRET": "not-64-hex"}, role="consumer")
    # The check at init refuses the block.
    plugin._validate_sync_config()
    # SYNC is off.
    self.assertFalse(plugin._sync_enabled())
    # A restart on the mocked Docker whose registry login fails: the state reset has run, the SYNC check has not.
    with _patch_docker_module(plugin.docker_client), \
         patch.object(plugin, "_login_to_registry", side_effect=RuntimeError("registry login failed")):
      # The failure reaches the caller.
      with self.assertRaises(RuntimeError):
        # The restart, with nothing to clean up first.
        plugin._restart_container(StopReason.CRASH, cleanup_first=False)
    # The reset did not turn SYNC back on.
    self.assertFalse(plugin._sync_enabled())
    # A consumer tick of the loop that keeps running after the failed restart.
    plugin._sync_consumer_tick(1000.0)
    # It did not refresh or read the store.
    self.assertEqual((plugin.chainstore_hsync.call_count, plugin.chainstore_hget.call_count), (0, 0))


if __name__ == "__main__":
  unittest.main()
