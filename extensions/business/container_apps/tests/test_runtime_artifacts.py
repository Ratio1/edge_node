"""Pinned and catalogue deployments restore exact content while generic deployments follow their source."""
import copy
import threading
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

from extensions.business.container_apps.tests.support import make_lifecycle_runner, make_mock_container
from extensions.business.container_apps.worker_app_runner import StopReason, WorkerAppRunnerPlugin
import docker


IMAGE_ID = "sha256:" + "a" * 64
COMMIT = "b" * 40
REF = "test/image@sha256:" + "d" * 64  # in the repository the test app is configured with ("test/image:latest")


def image(image_id=IMAGE_ID, *references):
  """An image of the Docker store: its id there, and where registries serve it."""
  return SimpleNamespace(id=image_id, attrs={"RepoDigests": list(references)})


def bound(image_id=IMAGE_ID, **more):
  """Saved state of a tracked deployment that already resolved its image."""
  return {"deployment_runtime_artifacts": {"operation_key": "operation|deploy", "artifacts": {"image_id": image_id, **more}}}


class RuntimeArtifactTests(unittest.TestCase):
  def runner(self, state=None):
    plugin, client, container = make_lifecycle_runner()
    state = {} if state is None else state
    plugin._deployment_source_mode = "pinned"
    plugin.cfg_pinned_version = True
    plugin.cfg_image_digest = REF.split("@")[1]
    plugin.cfg_vcs_data = {"COMMIT": COMMIT}
    plugin._deployment_operation_key = "operation|deploy"
    plugin._load_persistent_state = lambda: copy.deepcopy(state)
    plugin._save_persistent_state = lambda **fields: state.update(copy.deepcopy(fields))
    plugin.report_deployment_status = MagicMock()
    return plugin, client, container, state

  def test_requested_digest_resolves_once_and_survives_plugin_restart(self):
    plugin, client, _, state = self.runner()
    client.images.pull.return_value = image(IMAGE_ID, REF)
    self.assertTrue(plugin._ensure_image_available())
    self.assertEqual(plugin._get_full_image_ref(), IMAGE_ID)
    # The id names the image in this Docker store; the registry reference is what can be pulled again.
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"], {"image_id": IMAGE_ID, "image_ref": REF})
    client.images.pull.return_value.id = "sha256:" + "c" * 64
    self.assertTrue(plugin._ensure_image_available())
    client.images.pull.assert_called_once_with(REF)
    client.images.get.assert_called_with(IMAGE_ID)
    restarted, restarted_client, _, _ = self.runner(state)
    restarted._pull_image_with_fallback = MagicMock()
    self.assertTrue(restarted._ensure_image_available())
    restarted_client.images.get.assert_called_with(IMAGE_ID)
    restarted._pull_image_with_fallback.assert_not_called()
    restarted_client.images.pull.assert_not_called()

  def test_untracked_local_image_uses_existing_pull_policy(self):
    for policy in ("never", "if-not-present"):
      with self.subTest(policy=policy):
        plugin, client, _ = make_lifecycle_runner()
        plugin.cfg_autoupdate = False
        plugin.cfg_image_pull_policy = policy
        client.images.get.return_value = image(IMAGE_ID, REF)
        self.assertTrue(plugin._ensure_image_available())
        # A locally built image has no digest that can be looked up in a registry.
        client.images.get_registry_data.assert_not_called()
        client.images.pull.assert_not_called()

  def test_a_lost_image_is_pulled_back_by_its_exact_registry_reference(self):
    # The node's own container was replaced: the saved state survived, the nested Docker store did not.
    plugin, client, _, _ = self.runner(bound(image_ref=REF))
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    client.images.pull.return_value = image(IMAGE_ID, REF)
    self.assertTrue(plugin._ensure_image_available())
    client.images.pull.assert_called_once_with(REF)  # repository@sha256, never the tag
    self.assertNotIn(call("failed", error_code="WORKLOAD_START_FAILED"), plugin.report_deployment_status.mock_calls)
    self.assertEqual(plugin._get_full_image_ref(), IMAGE_ID)

  def test_a_binding_without_a_reference_is_found_again_only_if_the_registry_still_serves_that_image(self):
    # Every deployment made before the reference was saved, the ones that are down included.
    plugin, client, container, state = self.runner(bound())
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    client.images.pull.return_value = image(IMAGE_ID, REF)
    self.assertTrue(plugin._ensure_image_available())
    client.images.pull.assert_called_once_with(REF)
    # ... and once its container runs, the binding holds the reference it can be pulled by exactly.
    plugin.container = container
    container.image = image(IMAGE_ID, REF)
    plugin._capture_deployment_image()
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"]["image_ref"], REF)

  def test_a_moved_tag_is_never_run_in_place_of_the_bound_image(self):
    plugin, client, _, state = self.runner(bound(image_ref=REF))
    clock = [1000.0]
    plugin.time = lambda: clock[0]
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    client.images.pull.return_value = image("sha256:" + "f" * 64, "test/image@sha256:" + "9" * 64)
    plugin._pull_image_with_fallback = MagicMock()
    for _ in range(12):  # one minute of laps, about every 5 s
      self.assertFalse(plugin._ensure_image_available())
      clock[0] += 5
    self.assertLessEqual(client.images.pull.call_count, 3)  # the registry is asked after 20 s, 40 s, ... not every lap
    plugin.report_deployment_status.assert_called_with("failed", error_code="WORKLOAD_START_FAILED")
    self.assertEqual(plugin._get_full_image_ref(), IMAGE_ID)  # nothing else can be launched
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"]["image_ref"], REF)
    plugin._pull_image_with_fallback.assert_not_called()
    # However long it has been failing, the next registry attempt is at most an hour away. The count
    # is far past 1021, where the doubling no longer fitted a float and the pause could not be computed.
    plugin._image_pull_failures, plugin._next_image_pull_time = 5000, 0
    self.assertFalse(plugin._ensure_image_available())
    self.assertEqual(plugin._next_image_pull_time - clock[0], 3600)
    # The image is loaded onto the node by hand: it is used on the next lap, without waiting.
    client.images.get.side_effect = None
    self.assertTrue(plugin._ensure_image_available())
    self.assertEqual(plugin._image_pull_failures, 5001)  # a local find is not a pull; only a registry find resets

  def test_a_registry_error_is_retried_and_not_reported_as_a_failed_deployment(self):
    # A failed report cannot be taken back for that attempt, so it is kept for the case that is known.
    plugin, client, _, _ = self.runner(bound(image_ref=REF))
    clock = [1000.0]
    plugin.time = lambda: clock[0]
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    client.images.pull.side_effect = RuntimeError("registry unreachable")
    self.assertFalse(plugin._ensure_image_available())
    self.assertEqual(plugin.report_deployment_status.mock_calls, [call("pulling_image")])
    client.images.pull.side_effect = None
    client.images.pull.return_value = image(IMAGE_ID, REF)
    clock[0] += 3600
    self.assertTrue(plugin._ensure_image_available())
    self.assertEqual((plugin._image_pull_failures, plugin._next_image_pull_time), (0, 0))

  def test_a_pause_left_by_an_earlier_pull_does_not_stop_an_app_whose_image_is_present(self):
    plugin, client, _, _ = self.runner(bound(image_ref=REF))
    plugin.time = lambda: 1000.0
    plugin._image_pull_failures, plugin._next_image_pull_time = 8, 9000.0
    self.assertTrue(plugin._ensure_image_available())
    client.images.pull.assert_not_called()

  def test_unavailable_pinned_digest_never_falls_back_to_tag(self):
    # The exact reference was not looked at, so nothing final is known: the app keeps asking.
    plugin, client, _, _ = self.runner(bound(image_ref=REF))
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    client.images.pull.side_effect = RuntimeError("manifest unknown")
    self.assertFalse(plugin._ensure_image_available())
    self.assertEqual(client.images.pull.mock_calls, [call(REF)])
    self.assertEqual(plugin.report_deployment_status.mock_calls, [call("pulling_image")])

  def test_a_running_deployment_gets_its_registry_reference_at_its_next_start(self):
    plugin, client, container, state = self.runner(bound())
    client.images.pull.return_value = image(IMAGE_ID, REF)
    self.assertTrue(plugin._ensure_image_available())
    # An older binding is verified against the requested registry digest before use.
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"]["image_ref"], REF)
    plugin.container = container
    container.image = image(IMAGE_ID, "docker.io/other/copy@sha256:" + "1" * 64, REF)
    plugin._capture_deployment_image()
    # The repository the app is configured with, where its registry credentials apply; not the copy.
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"]["image_ref"], REF)
    client.images.pull.assert_called_once_with(REF)

  def test_a_restored_app_keeps_the_registry_reference_this_node_adds(self):
    # A restoration (or owner transfer) made from a record older than the reference: the id only.
    plugin, client, container, state = self.runner()
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID}
    client.images.pull.return_value = image(IMAGE_ID, REF)
    self.assertTrue(plugin._ensure_image_available())
    plugin.container = container
    container.image = image(IMAGE_ID, REF)
    plugin._capture_deployment_image()  # the first start adds the reference
    plugin._capture_deployment_image()  # a later start used to erase it again
    expected = {"image_id": IMAGE_ID, "image_ref": REF}
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"], expected)
    self.assertEqual(plugin.get_deployment_runtime_artifacts(), expected)  # what the node reports
    client.images.pull.reset_mock()
    # The Docker store is lost: the exact reference is asked, although the command never carried it.
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    client.images.pull.return_value = image(IMAGE_ID)
    self.assertTrue(plugin._ensure_image_available())
    client.images.pull.assert_called_once_with(REF)
    # A reference saved for another image is never attached to this one.
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": "sha256:" + "c" * 64}
    self.assertEqual(plugin._get_pinned_deployment_artifacts(), {"image_id": "sha256:" + "c" * 64})

  def test_only_a_plain_repository_and_digest_is_kept_as_a_registry_reference(self):
    plugin, _, _, _ = self.runner()
    self.assertIsNone(plugin._get_image_registry_ref(image(IMAGE_ID)))  # built or loaded locally
    plugin.cfg_image = "registry:5000/team/app:1"  # the ":" of a registry port is not the start of a tag
    self.assertIsNone(plugin._get_image_registry_ref(image(IMAGE_ID, "user:secret@registry:5000/team/app@sha256:" + "d" * 64)))
    self.assertIsNone(plugin._get_image_registry_ref(image(IMAGE_ID, "registry:5000/team/app:stable")))
    self.assertIsNone(plugin._get_image_registry_ref(image(IMAGE_ID, "registry:5000/team/app@sha256:short")))
    # The same image held by another deployment's repository is not this app's reference.
    self.assertIsNone(plugin._get_image_registry_ref(image(IMAGE_ID, "ghcr.io/other/copy@sha256:" + "1" * 64)))
    self.assertEqual(plugin._get_image_registry_ref(image(
      IMAGE_ID, "ghcr.io/other/copy@sha256:" + "1" * 64, "registry:5000/team/app@sha256:" + "d" * 64,
    )), "registry:5000/team/app@sha256:" + "d" * 64)
    plugin.cfg_image = "docker.io/library/nginx:1.27"  # Docker lists this Docker Hub image as "nginx"
    self.assertEqual(plugin._get_image_registry_ref(image(IMAGE_ID, "nginx@sha256:" + "d" * 64)), "nginx@sha256:" + "d" * 64)
    # A restoration command is refused when its reference carries a tag, with or without a digest.
    for tagged in ("registry/app:stable", "registry/app:stable@sha256:" + "d" * 64):
      plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "image_ref": tagged}
      with self.assertRaisesRegex(ValueError, "image binding"):
        plugin._get_pinned_deployment_artifacts()
    # A plain reference is accepted only in the configured repository: back to the one REF is in.
    plugin.cfg_image = "test/image:latest"
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "image_ref": REF}
    self.assertEqual(plugin._get_pinned_deployment_artifacts(), {"image_id": IMAGE_ID, "image_ref": REF})

  def test_a_restoration_may_name_only_the_configured_repository(self):
    plugin, client, _, _ = self.runner()
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    # Another registry with the same path, another repository, the same repository spelled another way:
    # each is refused before anything is pulled, although each has the shape of a reference.
    for elsewhere in ("other-registry:5000/test/image", "test/other", "docker.io/test/image"):
      plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "image_ref": elsewhere + "@sha256:" + "d" * 64}
      with self.assertRaisesRegex(ValueError, "image binding"):
        plugin._ensure_image_available()
    client.images.pull.assert_not_called()
    # What this node saves for its image always comes back accepted: registry port, Docker Hub names, a
    # registry server from CR_DATA, a configured digest instead of a tag.
    for configured, server, listed in (
      ("test/image:latest", "docker.io", REF),
      ("docker.io/library/nginx:1.27", None, "nginx@sha256:" + "d" * 64),
      ("team/app:1", "registry:5000", "registry:5000/team/app@sha256:" + "d" * 64),
      ("acme/shop@sha256:" + "e" * 64, "ghcr.io", "ghcr.io/acme/shop@sha256:" + "d" * 64),
    ):
      plugin.cfg_image, plugin.cfg_cr_data = configured, {"SERVER": server}
      saved = plugin._get_image_registry_ref(image(IMAGE_ID, "elsewhere/copy@sha256:" + "1" * 64, listed))
      self.assertEqual(saved, listed)
      plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "image_ref": saved}
      self.assertEqual(plugin._get_pinned_deployment_artifacts(), {"image_id": IMAGE_ID, "image_ref": saved})

  def test_an_image_lost_under_a_running_app_is_asked_for_beyond_the_restart_limit(self):
    # The image is removed by force under the running app, which then stops: its restart finds no image.
    plugin, client, container, _ = self.runner(bound(image_ref=REF))
    clock = [1000.0]
    plugin.time = lambda: clock[0]
    container.image = image(IMAGE_ID, REF)
    plugin._handle_initial_launch()
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    client.images.pull.side_effect = RuntimeError("manifest unknown")
    # Three crashes just before: the stop and the restart without an image bring the count to the limit.
    plugin._consecutive_failures = 3
    container.status, container.attrs = "exited", {"State": {"ExitCode": 1, "Running": False}}
    with patch.object(docker, "from_env", return_value=client):  # a restart makes a new Docker client
      for _ in range(12 * 60):  # twelve hours of laps, one a minute
        plugin.process()
        clock[0] += 60
      # The stop and the restart without an image reach the restart limit; the launch path still asks after that.
      self.assertEqual(plugin._consecutive_failures, plugin.cfg_restart_max_retries)
      self.assertGreater(plugin._image_pull_failures, plugin.cfg_restart_max_retries)
      self.assertFalse([line for line in plugin.logged_messages if "abandoned" in line])
      # The registry serves the bound image again: the app runs it within the hour.
      client.images.pull.side_effect = None
      client.images.pull.return_value = image(IMAGE_ID, REF)
      client.containers.run.return_value = make_mock_container()
      client.containers.run.return_value.image = image(IMAGE_ID, REF)
      for _ in range(61):
        plugin.process()
        clock[0] += 60
    self.assertEqual(client.containers.run.call_count, 2)
    self.assertIs(plugin.container, client.containers.run.return_value)

  def test_a_tracked_worker_whose_base_image_was_lost_pulls_it_again_and_keeps_its_commit(self):
    # A real worker instance on the harness state: the base image follows the pull policy, the commit stays.
    lost = "sha256:" + "e" * 64
    plugin, client, container, state = self.runner(bound(image_id=lost, git_commit=COMMIT))
    worker = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    worker.__dict__.update(plugin.__dict__)
    worker.repo_url, worker.branch = "https://github.com/ratio1/example.git", "moved-branch"
    worker.cfg_autoupdate = False  # a worker's own default: with "always" below it pulls at every start
    self.assertEqual(worker.cfg_image_pull_policy, "always")
    client.images.get.side_effect = docker.errors.NotFound("nothing in this Docker store")
    worker._pull_image_with_fallback = MagicMock(return_value=image(IMAGE_ID))
    self.assertEqual(worker._get_full_image_ref(), "test/image:latest")  # the configured base image, not the lost id
    self.assertTrue(worker._ensure_image_available())
    worker._pull_image_with_fallback.assert_called_once()
    worker.report_deployment_status.assert_not_called()
    command = worker._build_git_clone_command("/app")
    self.assertIn("checkout --detach " + COMMIT, command)
    self.assertNotIn("moved-branch", command)
    # The container then runs the newly pulled base image: recorded, not refused.
    worker.container = container
    container.image.id = IMAGE_ID
    worker._capture_deployment_image()
    self.assertEqual(state["deployment_runtime_artifacts"]["artifacts"], {"image_id": IMAGE_ID, "git_commit": COMMIT})

  def test_a_container_app_must_still_run_exactly_its_bound_image(self):
    plugin, _, container, _ = self.runner(bound())
    plugin.container = container
    container.image.id = "sha256:" + "f" * 64
    with self.assertRaisesRegex(RuntimeError, "does not match the immutable image binding"):
      plugin._capture_deployment_image()

  def test_a_worker_is_restored_from_its_commit_and_a_container_app_needs_its_image(self):
    worker = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    worker._deployment_source_mode = "pinned"
    worker.cfg_vcs_data = {"COMMIT": COMMIT}
    worker.cfg_deeploy_runtime_artifacts = {"git_commit": COMMIT}
    self.assertEqual(worker._get_pinned_deployment_artifacts(), {"git_commit": COMMIT})
    worker.cfg_deeploy_runtime_artifacts = {"git_commit": COMMIT, "image_id": "not-an-image-id"}
    with self.assertRaisesRegex(ValueError, "image binding"):
      worker._get_pinned_deployment_artifacts()
    plugin, _, _, _ = self.runner()
    for binding in ({"git_commit": COMMIT}, {}):
      plugin.cfg_deeploy_runtime_artifacts = binding
      with self.assertRaisesRegex(ValueError, "image binding"):
        plugin._get_pinned_deployment_artifacts()

  def test_image_binding_must_persist_before_launch_can_continue(self):
    plugin, client, _, _ = self.runner()
    plugin._save_persistent_state = lambda **fields: None
    client.images.pull.return_value = image(IMAGE_ID, REF)
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
    plugin._deployment_source_mode = "pinned"
    plugin.cfg_vcs_data = {"COMMIT": COMMIT}
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
    plugin._deployment_source_mode = "pinned"
    plugin.cfg_vcs_data = {"COMMIT": COMMIT}
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
    plugin._deployment_source_mode = "pinned"
    plugin.cfg_vcs_data = {"COMMIT": COMMIT}
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": IMAGE_ID, "git_commit": COMMIT}
    plugin.container = MagicMock()
    plugin.container.exec_run.return_value = SimpleNamespace(exit_code=128, output=b"not a repository yet")
    plugin._app_ready = False
    plugin.report_deployment_status = MagicMock()
    plugin._semaphore_set_ready_flag = MagicMock()
    self.assertFalse(plugin._confirm_app_readiness())
    plugin._semaphore_set_ready_flag.assert_not_called()
    plugin.report_deployment_status.assert_not_called()

  def test_worker_pins_requested_commit_before_clone(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    plugin._deployment_source_mode = "pinned"
    plugin.cfg_pinned_version = True
    plugin.cfg_image_digest = REF.split("@")[1]
    plugin.cfg_vcs_data = {"COMMIT": COMMIT}
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
    plugin._get_latest_commit.assert_not_called()
    self.assertIn("checkout --detach " + COMMIT, plugin._build_git_clone_command("/app"))

  def test_tracking_ignores_saved_and_restored_images_and_checks_actual_launch(self):
    plugin, client, container, state = self.runner(bound(image_ref=REF))
    plugin._deployment_source_mode = "following"
    plugin.cfg_deeploy_runtime_artifacts = {"image_id": "invalid old binding"}
    client.images.get_registry_data.return_value.id = REF.split("@")[1]
    client.images.pull.return_value = container.image = image(IMAGE_ID, REF)
    plugin._handle_initial_launch()
    client.images.get_registry_data.assert_called_once_with("test/image:latest")
    self.assertEqual(client.containers.run.call_args.args, (IMAGE_ID,))
    self.assertEqual(plugin._get_full_image_ref(), IMAGE_ID)  # Fixed-volume metadata inspects the same image.
    self.assertEqual(plugin.get_deployment_runtime_artifacts()["image_ref"], REF)
    self.assertEqual(state, bound(image_ref=REF))
    # Even the first check can see a replacement. It compares against the image this container runs.
    client.images.get_registry_data.return_value.id = "sha256:" + "e" * 64
    plugin._restart_container = MagicMock()
    plugin._check_image_updates(plugin._last_image_check + plugin.cfg_autoupdate_interval)
    plugin._restart_container.assert_called_once_with(StopReason.IMAGE_UPDATE)

  def test_source_poll_restarts_after_retries_are_exhausted_or_disallowed(self):
    for policy in ("no", "always"):
      plugin, client, _, _ = self.runner()
      plugin._deployment_source_mode = "following"
      plugin.current_image_hash = REF
      plugin.cfg_restart_policy = policy
      plugin._consecutive_failures = plugin.cfg_restart_max_retries
      plugin._next_restart_time = plugin.time() + 3600
      client.images.get_registry_data.return_value.id = REF.split("@")[1]
      plugin._restart_container = MagicMock()
      plugin.process()
      plugin._restart_container.assert_not_called()
      # A replacement gets its own restart budget regardless of the failed image's backoff.
      plugin._last_image_check -= plugin.cfg_autoupdate_interval
      client.images.get_registry_data.return_value.id = "sha256:" + "e" * 64
      plugin.process()
      plugin._restart_container.assert_called_once_with(StopReason.IMAGE_UPDATE)
      self.assertEqual(plugin._consecutive_failures, 0)

  def test_source_pull_retries_indefinitely_without_using_local_tag(self):
    plugin, client, _, _ = self.runner(bound(image_ref=REF))
    plugin._deployment_source_mode = "following"
    plugin._image_pull_failures = 5000
    client.images.get_registry_data.side_effect = RuntimeError("tag unavailable")
    plugin.time = lambda: 1000.0
    self.assertFalse(plugin._ensure_image_available())
    self.assertEqual(plugin._next_image_pull_time, 4600.0)
    plugin.report_deployment_status.assert_called_with("failed", error_code="IMAGE_PULL_FAILED")
    client.images.get.assert_not_called()
    plugin.time = lambda: 4600.0
    client.images.get_registry_data.side_effect = None
    client.images.get_registry_data.return_value.id = REF.split("@")[1]
    client.images.pull.return_value = image(IMAGE_ID, REF)
    self.assertTrue(plugin._ensure_image_available())
    self.assertEqual(plugin._image_pull_failures, 0)

  def test_catalogue_service_keeps_legacy_binding_and_tag_fallback(self):
    service, client, _, _ = self.runner(bound())
    service._deployment_source_mode = "service"
    client.images.get.side_effect = docker.errors.NotFound("store lost")
    client.images.pull.return_value = image(IMAGE_ID)
    self.assertTrue(service._ensure_image_available())
    client.images.pull.assert_called_once_with("test/image:latest")
    service._check_image_updates(100)
    client.images.get_registry_data.assert_not_called()

  def test_following_worker_keeps_failed_checkout_until_new_head(self):
    base, _, container, _ = self.runner(bound(git_commit=COMMIT))
    worker = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    worker.__dict__.update(base.__dict__)
    worker._after_reset()
    worker._deployment_source_mode = "following"
    worker.cfg_deeploy_runtime_artifacts = {"git_commit": "c" * 40}
    worker.cfg_vcs_data = {"REPO_OWNER": "acme", "REPO_NAME": "app", "BRANCH": "topic"}
    worker.cfg_setup_repo = True
    worker._build_commands = ["false"]
    worker.time = lambda: 1000
    # An unauthorized branch lookup at start and on the next poll still permits the real clone.
    with patch("extensions.business.container_apps.worker_app_runner.requests.get") as lookup:
      lookup.return_value.status_code = 401
      commands = worker._collect_exec_commands()
      self.assertIn("git clone --branch topic", " ".join(commands))
      self.assertNotIn("checkout --detach", " ".join(commands))
      self.assertNotIn("cd /app && false", commands)
      self.assertEqual(worker._deployment_source_error, "SOURCE_UNREACHABLE")
      self.assertIsNone(worker._check_git_updates(1060))
      self.assertEqual(lookup.call_count, 2)
      # The command observer captures the checkout before publishing a failed build.
      worker.container = container
      container.exec_run.return_value = SimpleNamespace(exit_code=0, output=(COMMIT + "\n").encode())
      worker.docker_client.api.exec_inspect.return_value = {"ExitCode": 0}
      worker._stream_deployment_exec("clone", iter([]), threading.Event())
      self.assertEqual(worker._collect_exec_commands(), ["cd /app && false"])
      worker.docker_client.api.exec_inspect.return_value = {"ExitCode": 1}
      worker._stream_deployment_exec("build", iter([]), threading.Event())
      self.assertEqual(worker.get_deployment_runtime_artifacts()["git_commit"], COMMIT)
      self.assertEqual(container.exec_run.call_args.args[0][-2:], ["rev-parse", "HEAD"])
      worker.report_deployment_status.assert_called_with("failed", error_code="WORKLOAD_START_FAILED")
      worker._deployment_error_code = "WORKLOAD_START_FAILED"
      worker._commands_started = True
      self.assertFalse(worker._is_app_ready())
      lookup.return_value.status_code = 200
      lookup.return_value.json.return_value = {"commit": {"sha": COMMIT}}
      self.assertIsNone(worker._check_git_updates(1120))
      self.assertIsNone(worker._deployment_source_error)
      lookup.return_value.json.return_value = {"commit": {"sha": "f" * 40}}
      self.assertEqual(worker._check_git_updates(1180), StopReason.EXTERNAL_UPDATE)
      # If neither the initial lookup nor the clone succeeded, recovery uses the first readable head.
      worker.current_commit = None
      self.assertEqual(worker._check_git_updates(1240), StopReason.EXTERNAL_UPDATE)

  def test_worker_preserves_an_externally_managed_checkout(self):
    for mode in ("following", "pinned"):
      with self.subTest(mode=mode):
        base, _, container, _ = self.runner()
        worker = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
        worker.__dict__.update(base.__dict__)
        worker._after_reset()
        worker._deployment_source_mode = mode
        worker.cfg_setup_repo = False
        worker.repo_url = "https://github.com/acme/app.git"
        worker._ensure_repo_state = MagicMock()
        worker._get_latest_commit = MagicMock(return_value="b" * 40)
        worker._build_commands = ["true"]
        worker.time = lambda: 1000
        self.assertEqual(worker._collect_exec_commands(), [worker._build_git_bootstrap_command()])
        worker.container = container
        container.exec_run.return_value = SimpleNamespace(exit_code=0, output=COMMIT.encode())
        self.assertTrue(worker._capture_checkout())
        self.assertEqual(worker._collect_exec_commands(), ["cd /app && true"])
        self.assertIsNone(worker._check_git_updates(1060))
        worker._get_latest_commit.assert_not_called()

  def test_externally_managed_tree_without_git_can_run_but_cannot_prove_a_pin(self):
    base, _, container, _ = self.runner()
    worker = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    worker.__dict__.update(base.__dict__)
    worker._after_reset()
    worker.cfg_setup_repo = False
    worker.container = container
    container.exec_run.return_value = SimpleNamespace(exit_code=128, output=b"not a git repository")
    self.assertFalse(worker._capture_checkout())  # A pin requires a verified checkout.
    worker._deployment_source_mode = "following"
    self.assertTrue(worker._capture_checkout())
    self.assertNotIn("git_commit", worker.get_deployment_runtime_artifacts())

  def test_live_container_with_failed_build_honors_restart_backoff(self):
    plugin, client, container, _ = self.runner()
    plugin._deployment_source_mode = "following"
    clock = [1000]
    plugin.time = lambda: clock[0]
    client.images.get_registry_data.return_value.id = REF.split("@")[1]
    client.images.pull.return_value = container.image = image(IMAGE_ID, REF)
    plugin._handle_initial_launch()
    plugin._deployment_error_code = "WORKLOAD_START_FAILED"
    plugin._restart_container = MagicMock()
    plugin.process()
    self.assertEqual(plugin._consecutive_failures, 1)
    self.assertFalse(plugin._is_app_ready())
    plugin._restart_container.assert_not_called()
    clock[0] = plugin._next_restart_time + 1
    plugin.process()
    plugin._restart_container.assert_called_once_with(StopReason.HEALTH_CHECK_FAILED)
    self.assertEqual(plugin._consecutive_failures, 1)

  def test_unreadable_default_branch_clones_remote_head_and_rediscovers_it(self):
    base, _, _, _ = self.runner()
    worker = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    worker.__dict__.update(base.__dict__)
    worker._after_reset()
    worker._deployment_source_mode = "following"
    worker.cfg_setup_repo = True
    worker.cfg_vcs_data = {"REPO_OWNER": "acme", "REPO_NAME": "app"}
    worker.time = lambda: 1000
    with patch("extensions.business.container_apps.worker_app_runner.requests.get") as lookup:
      lookup.return_value.status_code = 401
      worker._ensure_repo_state()
      self.assertEqual(worker._deployment_source_error, "SOURCE_UNREACHABLE")
      self.assertNotIn("--branch", worker._build_git_clone_command("/app"))
      self.assertEqual(lookup.call_count, 1)
      lookup.return_value.status_code = 200
      lookup.return_value.json.side_effect = [
        {"name": "app", "default_branch": "master"}, {"commit": {"sha": "c" * 40}},
      ]
      worker.current_commit = COMMIT  # The actual HEAD observed after cloning.
      self.assertEqual(worker._check_git_updates(1060), StopReason.EXTERNAL_UPDATE)
      self.assertEqual(worker.branch, "master")
      self.assertTrue(lookup.call_args.args[0].endswith("/branches/master"))
      self.assertIsNone(worker._deployment_source_error)

  def test_following_launch_applies_selected_image_user_after_semaphore_wait(self):
    plugin, client, container, _ = self.runner()
    plugin._deployment_source_mode = "following"
    plugin.cfg_fixed_size_volumes = {
      "auto": {"SIZE": "20M", "MOUNTING_POINT": "/data"},
      "explicit": {"SIZE": "20M", "MOUNTING_POINT": "/other", "OWNER_UID": 91, "OWNER_GID": 92},
    }
    plugin._semaphore_get_keys = lambda: ["provider"]
    plugin._wait_for_semaphores = MagicMock(side_effect=[False, True])
    old = image(IMAGE_ID, REF)
    replacement = image("sha256:" + "c" * 64, "test/image@sha256:" + "e" * 64)
    old.attrs["Config"] = {"User": "1000:1000"}
    client.images.pull.return_value = client.images.get.return_value = old
    replacement.attrs["Config"] = {"User": "2000:3000"}
    client.images.get_registry_data.return_value.id = REF.split("@")[1]
    def provision(volume, **kwargs):
      volume.mount_path.mkdir(parents=True, exist_ok=True)  # The kernel mount is outside this unit test.
    with tempfile.TemporaryDirectory() as folder, patch.object(docker, "from_env", return_value=client), \
         patch("extensions.business.container_apps.fixed_volume._require_tools"), \
         patch("extensions.business.container_apps.fixed_volume.cleanup_stale_mounts"), \
         patch("extensions.business.container_apps.fixed_volume.provision", side_effect=provision), \
         patch("extensions.business.container_apps.fixed_volume.cleanup", return_value=True), \
         patch("extensions.business.container_apps.mixins.fixed_size_volumes.os.chown") as chown:
      plugin.get_data_folder = lambda: folder
      plugin.on_init()
      # Setup separately enforces root ownership of the system control directories.
      self.assertTrue(all("r1en_system" in str(args[0]) for args, _ in chown.call_args_list))
      chown.reset_mock()
      plugin.process()  # A blocked semaphore must not resolve an image or chown a data root.
      client.images.get_registry_data.assert_not_called()
      chown.assert_not_called()
      client.images.get_registry_data.return_value.id = replacement.attrs["RepoDigests"][0].split("@")[1]
      client.images.pull.return_value = client.images.get.return_value = container.image = replacement
      plugin.process()
      self.assertEqual(client.images.pull.call_count, 1)
      self.assertEqual(client.containers.run.call_args.args, (replacement.id,))
      client.images.get.assert_called_once_with(replacement.id)
      mounts = {vol.name: vol for vol in plugin._fixed_volumes}
      self.assertEqual(set(mounts), {"auto", "explicit", "r1en_system"})
      chown.assert_called_once_with(mounts["auto"].mount_path, 2000, 3000, follow_symlinks=False)
      # A sync/reset start retains mounted volumes. Root and symbolic USER restore their default owner.
      for user in ("0", "app"):
        replacement.attrs["Config"]["User"] = user
        chown.reset_mock()
        plugin.start_container()
        chown.assert_called_once_with(mounts["auto"].mount_path, 0, 0, follow_symlinks=False)
      # If the selected image cannot be inspected, leave the mount unchanged and refuse the start.
      client.images.get.side_effect = RuntimeError("image metadata unavailable")
      client.containers.run.reset_mock()
      chown.reset_mock()
      self.assertIsNone(plugin.start_container())
      client.containers.run.assert_not_called()
      chown.assert_not_called()
      plugin.report_deployment_status.assert_called_with("failed", error_code="WORKLOAD_START_FAILED")
      self.assertTrue(plugin._cleanup_fixed_size_volumes())
      chown.reset_mock()
      plugin._apply_launch_volume_owners()
      chown.assert_not_called()  # Already cleaned-up mounts cannot be chowned by a later direct start.

  def test_following_owner_stop_clears_live_artifacts_until_restart(self):
    plugin, client, container, state = self.runner()
    plugin._deployment_source_mode = "following"
    client.images.get_registry_data.return_value.id = REF.split("@")[1]
    client.images.pull.return_value = container.image = image(IMAGE_ID, REF)
    plugin._handle_initial_launch()
    self.assertEqual(plugin.get_deployment_runtime_artifacts()["image_ref"], REF)
    plugin._deployment_source_error = "SOURCE_UNREACHABLE"
    plugin.on_command("STOP")
    self.assertTrue(state["manually_stopped"])
    self.assertEqual(plugin.get_deployment_runtime_artifacts(), {})
    self.assertIsNone(plugin._deployment_source_error)
    plugin.report_deployment_status.assert_called_with("stopped")
    client.images.pull.reset_mock()
    plugin.process()
    client.images.pull.assert_not_called()
    with patch.object(docker, "from_env", return_value=client):
      plugin.on_command("RESTART")
    self.assertFalse(state["manually_stopped"])
    client.images.pull.assert_called_once_with(REF)
    self.assertEqual(plugin.get_deployment_runtime_artifacts()["image_ref"], REF)
    plugin.report_deployment_status.assert_called_with("starting")
