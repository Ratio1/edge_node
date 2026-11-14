"""
What the container app runner does differently now that the node's Docker store survives a node restart.

Before, the store of the node's inner Docker daemon was deleted with the node container at every stop: every app
started from a fresh pull and nothing was ever left behind. With the store kept (`docker/daemon.json`):
- an app with AUTOUPDATE starts from the stored image, which its tag may have left, so the first update check must
  compare the registry's image with the image the container runs;
- what earlier runs left in the store is removed once per node run (`_maybe_sweep_docker_store`).
"""

# Loads the runner module a second time, as the node does for every plugin instance.
import importlib
# The table of loaded modules, where the node's plugin loader forgets a module before loading it again.
import sys
# The test framework.
import unittest
# Stand-ins for Docker objects, and the expected Docker requests.
from unittest.mock import MagicMock, call

# The docker-py stand-in for a test process without the docker package.
from extensions.business.container_apps.tests.support import install_docker_stub_if_needed

# Before the runner module is imported below: it imports docker at its top.
install_docker_stub_if_needed()

# The plugin base stand-in and the runner wired for lifecycle tests.
from extensions.business.container_apps.tests.support import install_dummy_base_plugin, make_lifecycle_runner
# The runner module itself, for its sweep delay and to load it a second time.
from extensions.business.container_apps import container_app_runner as car_module
# The reason an update restart is made with.
from extensions.business.container_apps.container_app_runner import StopReason


# The wall-clock time the plugin reads in the sweep tests.
NOW = 1_000_000_000.9
# How long into a node run the runner waits before the sweep.
DELAY = car_module._STORE_SWEEP_DELAY


def make_image(digest):
  """
  An image of the Docker store, as docker-py describes it.

  Parameters
  ----------
  digest : str or None
    The digest the registry serves the image under (`sha256:...`); None for an image that was loaded, not pulled.

  Returns
  -------
  MagicMock
    An image with `id` and `attrs["RepoDigests"]`.

  Examples
  --------
  >>> make_image("sha256:aaa").attrs["RepoDigests"]
  ['test/image@sha256:aaa']
  """
  # A docker-py image: only the fields `_get_image_digest` reads.
  image = MagicMock()
  # The id in this store; for a loaded image it is all there is to compare.
  image.id = "sha256:id-of-{}".format(digest)
  # The registry reference of a pulled image; a loaded image has none.
  image.attrs = {"RepoDigests": ["test/image@{}".format(digest)] if digest else []}
  # The image, as `container.image` or a pull gives it.
  return image


def make_running_runner(container_image):
  """
  A runner whose container is running from a given image, with no update check done yet.

  Parameters
  ----------
  container_image : MagicMock
    The image the running container was started from (`make_image`).

  Returns
  -------
  tuple
    `(plugin, docker_client)`; `plugin.current_image_hash` is None, as after every start.

  Examples
  --------
  >>> plugin, client = make_running_runner(make_image("sha256:aaa"))
  >>> plugin.current_image_hash is None
  True
  """
  # A runner with a mocked Docker client and the container that client starts.
  plugin, client, container = make_lifecycle_runner()
  # docker-py resolves `container.image` to the image the container was created from.
  container.image = container_image
  # The app is up: the update check and the sweep run only from the monitoring of a running container.
  plugin.container = container
  # The app and the Docker client its requests go to.
  return plugin, client


class TestUpdateCheckBaselineIsTheRunningImage(unittest.TestCase):

  def test_an_app_started_from_an_older_stored_image_is_restarted_on_the_first_check(self):
    """The tag moved while the node was down: the first check finds another image than the container runs and restarts."""
    # The container was started from the image the store held, an older one.
    plugin, _client = make_running_runner(make_image("sha256:old"))
    # The registry now serves another image under the tag.
    plugin._get_latest_image_hash = lambda: "sha256:new"
    # The restart itself is not under test.
    plugin._restart_container = MagicMock()
    # The first check of this run, due (the interval is 10 s, the last check was at 0).
    plugin._check_image_updates(current_time=100)
    # Restarted for the update; before, the pulled image became the baseline and the app kept the old one.
    plugin._restart_container.assert_called_once_with(StopReason.IMAGE_UPDATE)
    # The app is now known to be on the new image.
    self.assertEqual(plugin.current_image_hash, "sha256:new")

  def test_an_app_that_runs_the_registry_image_is_not_restarted_on_the_first_check(self):
    """The usual start: the stored image is still what the tag names, so the first check changes nothing."""
    # The container was started from the image the tag still names.
    plugin, _client = make_running_runner(make_image("sha256:same"))
    # The registry serves the image the container runs.
    plugin._get_latest_image_hash = lambda: "sha256:same"
    # Must not be called.
    plugin._restart_container = MagicMock()
    # The first check of this run.
    plugin._check_image_updates(current_time=100)
    # No restart.
    plugin._restart_container.assert_not_called()
    # The baseline is that image.
    self.assertEqual(plugin.current_image_hash, "sha256:same")

  def test_the_baseline_of_a_loaded_image_is_its_id(self):
    """An image that was loaded, not pulled, has no registry digest: it is compared by its id, as the pulled one is."""
    # No registry reference: `_get_image_digest` falls back to the image id for both sides.
    image = make_image(None)
    # The container runs that loaded image.
    plugin, _client = make_running_runner(image)
    # The check gives the id of the same image: nothing changed.
    self.assertFalse(plugin._has_image_hash_changed(image.id))
    # The baseline is the id.
    self.assertEqual(plugin.current_image_hash, image.id)
    # Another image under the tag later is an update.
    self.assertTrue(plugin._has_image_hash_changed("sha256:id-of-another"))

  def test_a_failed_pull_sets_no_baseline(self):
    """Without an answer from the registry nothing is compared and the baseline stays unset for the next check."""
    # A running app with no baseline yet.
    plugin, _client = make_running_runner(make_image("sha256:old"))
    # A failed pull gives no hash.
    self.assertFalse(plugin._has_image_hash_changed(None))
    # Still unset: the next check reads it from the running container.
    self.assertIsNone(plugin.current_image_hash)


class TestDockerStoreSweep(unittest.TestCase):

  def setUp(self):
    """
    Give each test its own node: a running app, and nothing yet in the memory the node's plugins share.

    Returns
    -------
    None
    """
    # One app of the node, with its Docker client.
    self.plugin, self.client = make_running_runner(make_image("sha256:same"))
    # The wall clock the plugin reads.
    self.plugin.time = lambda: NOW
    # What Docker answers to the request for stopped containers.
    self.client.containers.prune.return_value = {"ContainersDeleted": ["c1"], "SpaceReclaimed": 10}
    # What Docker answers to the request for volumes.
    self.client.volumes.prune.return_value = {"VolumesDeleted": ["v1"], "SpaceReclaimed": 200}
    # What Docker answers to the request for images.
    self.client.images.prune.return_value = {"ImagesDeleted": [{"Deleted": "sha256:x"}], "SpaceReclaimed": 3000}

  def at(self, running_time, plugin=None):
    """
    Call the sweep of an app when the node has been running for a given time.

    Parameters
    ----------
    running_time : float
      Seconds since the node started, as the plugin base reports it.
    plugin : ContainerAppRunnerPlugin, optional
      The app whose lap this is; the app of `setUp` when omitted.

    Returns
    -------
    None

    Examples
    --------
    >>> self.at(DELAY)   # the first lap after the delay: the store is swept
    """
    # The app of setUp unless the test names another.
    plugin = plugin or self.plugin
    # The node's own count of how long it runs; the sweep takes the start of the run from it.
    plugin.get_node_running_time = lambda: running_time
    # One lap of that app reaches the sweep.
    plugin._maybe_sweep_docker_store()

  def swept(self, client=None):
    """
    The sweep requests a Docker client received, in order.

    Parameters
    ----------
    client : MagicMock, optional
      The Docker client to read; the one of the app of `setUp` when omitted.

    Returns
    -------
    list
      The `mock.call` entries of the prune requests.

    Examples
    --------
    >>> self.swept()
    []
    """
    # The client of the app of setUp unless the test names another.
    client = client or self.client
    # Only the prune requests, in the order they were made across the three collections.
    return [one for one in client.mock_calls if one[0].endswith(".prune")]

  def test_nothing_is_removed_before_the_delay_is_over(self):
    """In the first hour of a node run the apps are still starting: the store is left alone."""
    # One second before the delay ends.
    self.at(DELAY - 1)
    # No request went to Docker.
    self.assertEqual(self.swept(), [])
    # The sweep is still to come: the early lap must not have used it up.
    self.at(DELAY)
    # All three requests of the sweep.
    self.assertEqual(len(self.swept()), 3)

  def test_the_sweep_removes_old_containers_then_free_volumes_then_unused_images(self):
    """After the delay: the stopped containers of earlier runs, then anonymous volumes, then every image no container uses."""
    # The node started 4000.5 s before NOW.
    self.at(4000.5)
    # The three requests, in this order.
    self.assertEqual(self.swept(), [
      # Only containers created before this node run (NOW - 4000.5, whole seconds, rounded down): a container of
      # this run that exited stays.
      call.containers.prune(filters={"until": 999_996_000}),
      # Their anonymous volumes; a volume a container still holds is not touched by Docker.
      call.volumes.prune(),
      # All unused images, tagged ones too ("dangling": False), after the containers that held some were removed.
      call.images.prune(filters={"dangling": False}),
    ])
    # The freed space of the three requests is logged once.
    self.assertEqual(sum("3210 bytes" in line for line in self.plugin.logged_messages), 1)

  def test_the_store_is_swept_once_per_node_run_for_all_apps(self):
    """All apps share one store: after one app swept it, neither that app nor another sweeps again in this run."""
    # The first app sweeps.
    self.at(DELAY)
    # Another app of the same node, with its own Docker client.
    other, other_client = make_running_runner(make_image("sha256:other"))
    # Plugins of one node share this memory.
    other.plugins_shmem = self.plugin.plugins_shmem
    # A lap of the other app, after the sweep.
    self.at(DELAY + 5, plugin=other)
    # A much later lap of the first app.
    self.at(10 * DELAY)
    # Three requests in all from the first app.
    self.assertEqual(len(self.swept()), 3)
    # None from the other app.
    self.assertEqual(self.swept(other_client), [])

  def test_another_node_sweeps_its_own_store(self):
    """The marker lives in the memory of one node's plugins: an app of another node is not held back by it."""
    # The app of this node sweeps.
    self.at(DELAY)
    # An app with its own shared memory, as on another node (or in the next run of this one).
    other, other_client = make_running_runner(make_image("sha256:other"))
    # Its lap after the delay.
    self.at(DELAY, plugin=other)
    # It swept its own store.
    other_client.images.prune.assert_called_once_with(filters={"dangling": False})

  def test_an_app_of_a_module_copy_loaded_later_does_not_sweep_again(self):
    """The node loads the runner module again for every plugin instance: the marker of the sweep is not module state."""
    # The first app sweeps.
    self.at(DELAY)
    # The name the runner module is loaded under.
    name = car_module.__name__
    # The plugin base stand-in, for the import below.
    restore = install_dummy_base_plugin()
    # As the node's plugin loader does for each new instance: forget the module ...
    loaded = sys.modules.pop(name)
    try:
      # ... and import it again.
      fresh = importlib.import_module(name)
    finally:
      # Put back the module the other tests use.
      sys.modules[name] = loaded
      # And the modules the stand-in replaced.
      restore()
    # A second copy of the module, with its own globals.
    self.assertIsNot(fresh, car_module)
    # An app whose class comes from that copy; only what the sweep reads is set below.
    other = fresh.ContainerAppRunnerPlugin.__new__(fresh.ContainerAppRunnerPlugin)
    # On the same node: the same shared memory.
    other.plugins_shmem = self.plugin.plugins_shmem
    # After the delay.
    other.get_node_running_time = lambda: DELAY + 5
    # The same wall clock.
    other.time = lambda: NOW
    # Its own Docker client.
    other.docker_client = MagicMock()
    # One lap of that app.
    other._maybe_sweep_docker_store()
    # It found the marker of the first sweep and asked Docker for nothing.
    self.assertEqual(other.docker_client.mock_calls, [])

  def test_a_docker_error_is_raised_and_ends_the_sweep_of_this_run(self):
    """A request Docker refuses is not hidden: it is raised into the plugin loop, and the sweep is left for the next run."""
    # Docker refuses the first request.
    self.client.containers.prune.side_effect = RuntimeError("docker said no")
    # The error reaches the caller.
    with self.assertRaises(RuntimeError):
      # The lap that sweeps.
      self.at(DELAY)
    # Nothing after the failed request was sent.
    self.client.images.prune.assert_not_called()
    # Docker would answer now.
    self.client.containers.prune.side_effect = None
    # A following lap of this run.
    self.at(DELAY + 5)
    # Not tried again.
    self.assertEqual(self.client.containers.prune.call_count, 1)

  def test_the_monitoring_of_a_running_app_calls_the_sweep(self):
    """The sweep is reached from the periodic monitoring, which runs only while the app's container is running."""
    # The sweep itself is tested above.
    self.plugin._maybe_sweep_docker_store = MagicMock()
    # The update check is not under test.
    self.plugin._check_image_updates = MagicMock()
    # Nor are the checks of subclasses and mixins.
    self.plugin._perform_additional_checks = MagicMock(return_value=None)
    # One monitoring lap.
    self.plugin._perform_periodic_monitoring()
    # It asked for the sweep, once.
    self.plugin._maybe_sweep_docker_store.assert_called_once_with()

  def test_the_delay_is_one_hour(self):
    """The sweep waits one hour into a node run."""
    # 3600 s: by then the apps of the run hold their images through their containers.
    self.assertEqual(DELAY, 3600)


# Run this file directly as well as through the test runner.
if __name__ == "__main__":
  # The standard entry of a unittest file.
  unittest.main()
