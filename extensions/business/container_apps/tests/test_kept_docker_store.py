"""
What the container app runner does differently now that the node's Docker store survives a node restart.

Before, the store of the node's inner Docker daemon was deleted with the node container at every stop: every app
started from a fresh pull and nothing was ever left behind. With the store kept (`docker/daemon.json`):
- an app with AUTOUPDATE starts from the stored image, which its tag may have left, so the first update check must
  compare the registry's image with the image the container runs.
"""

# The test framework.
import unittest
# Stand-ins for Docker objects.
from unittest.mock import MagicMock

# The docker-py stand-in for a test process without the docker package.
from extensions.business.container_apps.tests.support import install_docker_stub_if_needed

# Before the runner module is imported below: it imports docker at its top.
install_docker_stub_if_needed()

# The runner wired for lifecycle tests.
from extensions.business.container_apps.tests.support import make_lifecycle_runner
# The reason an update restart is made with.
from extensions.business.container_apps.container_app_runner import StopReason


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
  # The app is up: the update check runs only from the monitoring of a running container.
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


# Run this file directly as well as through the test runner.
if __name__ == "__main__":
  # The standard entry of a unittest file.
  unittest.main()
