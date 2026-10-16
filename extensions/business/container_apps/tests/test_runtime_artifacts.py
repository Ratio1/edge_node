"""Tracked deployments restore immutable runtime content, not mutable tags."""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from extensions.business.container_apps.tests.support import make_lifecycle_runner
from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin
import docker


IMAGE_ID = "sha256:" + "a" * 64
COMMIT = "b" * 40


class RuntimeArtifactTests(unittest.TestCase):
  def runner(self, state=None):
    plugin, client, container = make_lifecycle_runner()
    state = {} if state is None else state
    plugin._deployment_operation_key = "operation|deploy"
    plugin._load_persistent_state = lambda: copy.deepcopy(state)
    plugin._save_persistent_state = lambda **fields: state.update(copy.deepcopy(fields))
    plugin.report_deployment_status = MagicMock()
    return plugin, client, container, state

  def test_image_tag_resolves_once_and_survives_plugin_restart(self):
    plugin, client, _, state = self.runner()
    plugin._pull_image_with_fallback = MagicMock(return_value=SimpleNamespace(id=IMAGE_ID))
    self.assertTrue(plugin._ensure_image_available())
    self.assertEqual(plugin._get_full_image_ref(), IMAGE_ID)
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"], {"image_id": IMAGE_ID})
    plugin._pull_image_with_fallback.return_value.id = "sha256:" + "c" * 64
    self.assertTrue(plugin._ensure_image_available())
    plugin._pull_image_with_fallback.assert_called_once()
    client.images.get.assert_called_with(IMAGE_ID)
    restarted, restarted_client, _, _ = self.runner(state)
    restarted._pull_image_with_fallback = MagicMock()
    self.assertTrue(restarted._ensure_image_available())
    restarted_client.images.get.assert_called_with(IMAGE_ID)
    restarted._pull_image_with_fallback.assert_not_called()

  def test_missing_restore_image_fails_without_tag_or_registry_fallback(self):
    plugin, client, _, _ = self.runner()
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID}
    client.images.get.side_effect = docker.errors.NotFound("image removed")
    plugin._pull_image_with_fallback = MagicMock()
    self.assertFalse(plugin._ensure_image_available())
    plugin._pull_image_with_fallback.assert_not_called()
    self.assertEqual(plugin._get_full_image_ref(), IMAGE_ID)
    plugin.report_deployment_status.assert_called_with("failed", error_code="WORKLOAD_START_FAILED")

  def test_image_binding_must_persist_before_launch_can_continue(self):
    plugin, client, _, _ = self.runner()
    plugin._save_persistent_state = lambda **fields: None
    plugin._pull_image_with_fallback = MagicMock(return_value=SimpleNamespace(id=IMAGE_ID))
    with self.assertRaisesRegex(RuntimeError, "could not be persisted"):
      plugin._ensure_image_available()
    client.containers.run.assert_not_called()

  def test_runtime_getter_is_cached_and_tracks_actual_started_image(self):
    plugin, _, container, _ = self.runner()
    plugin.container = container
    container.image.id = IMAGE_ID
    plugin._capture_deployment_image()
    container.reset_mock()
    self.assertEqual(plugin.get_deployment_runtime_artifacts(), {"image_id": IMAGE_ID})
    container.assert_not_called()
    self.assertEqual(container.mock_calls, [])
    plugin.container = None
    self.assertEqual(plugin.get_deployment_runtime_artifacts(), {"image_id": IMAGE_ID})

  def test_tracked_runtime_never_autoupdates_image(self):
    plugin, _, _, _ = self.runner()
    plugin.cfg_autoupdate = True
    plugin._get_latest_image_hash = MagicMock()
    plugin._check_image_updates(100)
    plugin._get_latest_image_hash.assert_not_called()

  def test_worker_restores_commit_without_consulting_mutable_branch(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "git_commit": COMMIT}
    plugin.repo_url = "https://github.com/ratio1/example.git"
    plugin.branch = "moved-branch"
    command = plugin._build_git_clone_command("/app")
    self.assertIn("checkout --detach " + COMMIT, command)
    self.assertNotIn("moved-branch", command)
    plugin._repo_configured = False
    plugin._configure_repo_url = MagicMock()
    plugin._set_default_branch = MagicMock()
    plugin._get_latest_commit = MagicMock()
    plugin._ensure_repo_state()
    plugin._get_latest_commit.assert_not_called()
    plugin._set_default_branch.assert_not_called()
    self.assertIsNone(plugin._check_git_updates(100))

  def test_worker_records_actual_head_before_publishing_readiness(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "git_commit": COMMIT}
    plugin.container = MagicMock()
    plugin.container.exec_run.return_value = SimpleNamespace(exit_code=0, output=(COMMIT + "\n").encode())
    plugin._app_ready = False
    plugin.set_plugin_ready = MagicMock()
    plugin.report_deployment_status = MagicMock()
    plugin._semaphore_set_ready_flag = MagicMock(side_effect=lambda: self.assertEqual(
      plugin.get_deployment_runtime_artifacts()["git_commit"], COMMIT,
    ))
    self.assertTrue(plugin._confirm_app_readiness())
    plugin._semaphore_set_ready_flag.assert_called_once()
    plugin._deployment_git_captured = False
    plugin._semaphore_set_ready_flag.reset_mock()
    plugin.container.exec_run.return_value.output = ("d" * 40).encode()
    self.assertFalse(plugin._confirm_app_readiness())
    plugin._semaphore_set_ready_flag.assert_not_called()
    plugin.report_deployment_status.assert_called_with("failed", error_code="WORKLOAD_START_FAILED")

  def test_worker_waits_for_clone_without_publishing_ready_or_failure(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "git_commit": COMMIT}
    plugin.container = MagicMock()
    plugin.container.exec_run.return_value = SimpleNamespace(exit_code=128, output=b"not a repository yet")
    plugin._app_ready = False
    plugin.report_deployment_status = MagicMock()
    plugin._semaphore_set_ready_flag = MagicMock()
    self.assertFalse(plugin._confirm_app_readiness())
    plugin._semaphore_set_ready_flag.assert_not_called()
    plugin.report_deployment_status.assert_not_called()

  def test_worker_freezes_commit_before_clone_for_tracked_attempt(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    plugin._deployment_operation_key = "operation|deploy"
    state = {}
    plugin._load_persistent_state = lambda: copy.deepcopy(state)
    plugin._save_persistent_state = lambda **fields: state.update(copy.deepcopy(fields))
    plugin._repo_configured = False
    plugin._configure_repo_url = MagicMock()
    plugin._set_default_branch = MagicMock()
    plugin._get_latest_commit = MagicMock(return_value=COMMIT)
    plugin.repo_url, plugin.branch = "https://github.com/ratio1/example.git", "main"
    plugin.time = lambda: 100
    plugin.P = MagicMock()
    plugin._ensure_repo_state()
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"]["git_commit"], COMMIT)
    self.assertIn("checkout --detach " + COMMIT, plugin._build_git_clone_command("/app"))
