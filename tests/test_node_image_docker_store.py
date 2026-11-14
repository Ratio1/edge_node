"""
The node images keep the inner Docker store under the mounted `_local_cache`: checks on the image files.

A node container starts its own Docker daemon (the base image entrypoint, `EE_DD=1`) and runs container apps in it.
`docker/daemon.json` is installed as that daemon's `/etc/docker/daemon.json` by every node Dockerfile and names the
directory of its store. These tests keep the file and the Dockerfiles consistent with each other, with what the
entrypoint passes to dockerd and with what the disk API of plugin code refuses, without building an image.
"""
# The daemon settings file is JSON.
import json
# The repository root and the files in it.
import pathlib
# The Dockerfile lines and the shape of the store directory.
import re
# A stand-in for the logger the disk API reads the cache folder from.
import types
# The test framework.
import unittest


# The repository root: this file is in tests/.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# The cache folder of a node inside its container: the only folder a host mounts, and the root of the plugins' disk API.
CACHE_ROOT = "/edge_node/_local_cache"

# The node Dockerfiles the repository builds images from; each starts the inner Docker daemon.
KNOWN_NODE_DOCKERFILES = {"Dockerfile_mainnet", "Dockerfile_testnet", "Dockerfile_devnet", "Dockerfile_devnet_local"}

# What the base image entrypoint passes to dockerd as flags (--host, --tlsverify, --tlscacert, --tlscert, --tlskey,
# --storage-driver), by their daemon.json names. dockerd refuses to start when an option is set both ways.
ENTRYPOINT_FLAG_KEYS = {"hosts", "tls", "tlsverify", "tlscacert", "tlscert", "tlskey", "storage-driver"}


def node_dockerfiles():
  """
  The Dockerfiles at the repository root that build a node image.

  Returns
  -------
  dict
    File name -> text, for every `Dockerfile_*` at the root except the `.dockerignore` companions. A Dockerfile
    added later is found too, so it cannot be left without the store settings unnoticed.

  Examples
  --------
  >>> sorted(node_dockerfiles())
  ['Dockerfile_devnet', 'Dockerfile_devnet_local', 'Dockerfile_mainnet', 'Dockerfile_testnet']
  """
  # Every root Dockerfile; the ".dockerignore" files next to them are not Dockerfiles.
  paths = [path for path in REPO_ROOT.glob("Dockerfile_*") if path.suffix != ".dockerignore"]
  # Name -> text, read once per test.
  return {path.name: path.read_text() for path in paths}


def daemon_config():
  """
  The settings file of the inner Docker daemon, as the images install it.

  Returns
  -------
  dict
    The parsed `docker/daemon.json`.

  Examples
  --------
  >>> daemon_config()["data-root"]
  '/edge_node/_local_cache/_bin/docker/29'
  """
  # The one file every node image copies to /etc/docker/daemon.json.
  return json.loads((REPO_ROOT / "docker" / "daemon.json").read_text())


def disk_api_of_a_plugin():
  """
  The disk API that plugin code gets, with the cache folder of a node as its root.

  Plugin code (customer code included) reads, copies, zips and deletes files only through this API, and every such
  call first asks `is_path_safe`. The object is the core's real mixin; only the logger it reads the cache folder
  from is a stand-in.

  Returns
  -------
  naeural_core.business.mixins_base.diskapi._DiskAPIMixin
    An object whose `is_path_safe(path)` answers as on a node whose cache folder is `CACHE_ROOT`.

  Examples
  --------
  >>> disk_api_of_a_plugin().is_path_safe("/edge_node/_local_cache/_data/x.json")
  True
  >>> disk_api_of_a_plugin().is_path_safe("/var/lib/docker")
  False
  """
  # The core's own path check; imported here, so the tests of the image files alone need no core.
  from naeural_core.business.mixins_base.diskapi import _DiskAPIMixin
  # All the check reads from its plugin: the logger's cache folder.
  log = types.SimpleNamespace(get_base_folder=lambda: CACHE_ROOT)
  # A plugin made of the mixin and that logger.
  return type("DiskApiOfAPlugin", (_DiskAPIMixin,), {"log": log})()


class TestNodeImageDockerStore(unittest.TestCase):

  def test_the_store_is_a_directory_per_docker_major_in_the_bin_folder_of_the_mounted_cache(self):
    """The store sits under /edge_node/_local_cache, the only folder a host mounts, in `_bin`, in a directory named by a Docker major."""
    # The directory the inner daemon keeps images, containers and volumes in.
    data_root = daemon_config()["data-root"]
    # Under the mounted cache folder, in its `_bin` folder, in the folder of the stores, named by the major only.
    self.assertRegex(data_root, r"^/edge_node/_local_cache/_bin/docker/[0-9]+$")

  def test_plugin_code_cannot_reach_the_store_through_the_disk_api(self):
    """The store holds every app's resolved environment, layers and logs: the plugins' disk API refuses every path into it."""
    # The path check every disk API call of plugin code goes through.
    disk_api = disk_api_of_a_plugin()
    # The directory the inner daemon keeps its store in.
    data_root = daemon_config()["data-root"]
    # Control: the check does accept a place of the cache folder, here the one the store had at first, next to `_bin`.
    self.assertTrue(disk_api.is_path_safe(CACHE_ROOT + "/_docker/29/containers/abc/config.v2.json"))
    # The store itself: a delete of it would remove every app's image and container.
    self.assertFalse(disk_api.is_path_safe(data_root))
    # A container's settings file in it, which holds the environment the app was started with.
    self.assertFalse(disk_api.is_path_safe(data_root + "/containers/abc/config.v2.json"))
    # The same file named through a folder plugins may use and `..`.
    self.assertFalse(disk_api.is_path_safe(CACHE_ROOT + "/_data/.." + data_root[len(CACHE_ROOT):] + "/containers/abc/config.v2.json"))

  def test_the_daemon_file_sets_nothing_the_entrypoint_passes_as_a_flag(self):
    """dockerd refuses to start when an option is both a flag and in daemon.json, so the file holds none of those."""
    # The options the file sets.
    keys = set(daemon_config())
    # None of them is among the flags of the base image entrypoint.
    self.assertEqual(keys & ENTRYPOINT_FLAG_KEYS, set())

  def test_every_node_dockerfile_is_checked(self):
    """The four node Dockerfiles are among those the other tests look at."""
    # What the discovery finds at the repository root.
    found = set(node_dockerfiles())
    # A renamed or moved Dockerfile must not drop out of the checks silently.
    self.assertLessEqual(KNOWN_NODE_DOCKERFILES, found)

  def test_every_node_image_starts_the_inner_daemon_and_installs_the_daemon_file_once(self):
    """Each node image enables the inner daemon and copies docker/daemon.json to /etc/docker/daemon.json exactly once."""
    # Every node Dockerfile, each reported under its own name.
    for name, text in node_dockerfiles().items():
      # One result per Dockerfile, so a failure names the file.
      with self.subTest(dockerfile=name):
        # The entrypoint starts dockerd only with EE_DD on.
        self.assertIn("\nENV EE_DD=1\n", text)
        # The file comes from this repository; the local-dependency image is built from the parent folder.
        copies = re.findall(r"^COPY \./(?:edge_node/)?docker/daemon\.json /etc/docker/daemon\.json$", text, re.M)
        # Once: a second copy or another target would leave two sources of the setting.
        self.assertEqual(len(copies), 1)
        # Nothing else in the image writes that file.
        self.assertEqual(text.count("/etc/docker/daemon.json"), 1)

  def test_every_node_image_build_fails_on_another_docker_major_than_the_store_is_named_after(self):
    """Each build validates the file with dockerd and stops when the base image has another Docker major than the directory name."""
    # The major the store directory is named after.
    major = daemon_config()["data-root"].rsplit("/", 1)[-1]
    # dockerd must accept the file, and its version must start with that major.
    check = 'RUN dockerd --validate && dockerd --version | grep -q "^Docker version {}\\."'.format(major)
    # Every node Dockerfile, each reported under its own name.
    for name, text in node_dockerfiles().items():
      # One result per Dockerfile, so a failure names the file.
      with self.subTest(dockerfile=name):
        # Exactly this line, once, in every node Dockerfile.
        self.assertEqual(text.splitlines().count(check), 1)
        # After the copy, so that the build validates the file that was installed.
        self.assertLess(text.index("/etc/docker/daemon.json"), text.index(check))


# Run this file directly as well as through the test runner.
if __name__ == "__main__":
  # The standard entry of a unittest file.
  unittest.main()
