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

# Where each Dockerfile finds the daemon file in its build context. The local-dependency image is built from the
# parent folder of the repository; every other image from the repository itself.
COPY_SOURCES = {"Dockerfile_devnet_local": "./edge_node/docker/daemon.json"}

# The build step that asks dockerd whether it accepts the installed file together with the entrypoint's flags.
VALIDATE_LINE = (
  "RUN dockerd --validate --host=unix:///var/run/docker.sock --storage-driver=vfs"
  " --tlscacert=/certs/server/ca.pem --tlscert=/certs/server/cert.pem --tlskey=/certs/server/key.pem"
)


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


def store_steps(name):
  """
  The build steps a node Dockerfile must have for the store, in their order.

  Parameters
  ----------
  name : str
    The Dockerfile's file name, which decides where the daemon file is in the build context.

  Returns
  -------
  list
    Five instruction lines: no daemon file in the base image, the copy, dockerd accepts the file with the
    entrypoint's flags, the entrypoint sets neither the store directory nor another settings file, and the Docker
    major is the one the store directory is named after.

  Examples
  --------
  >>> store_steps("Dockerfile_mainnet")[1]
  'COPY ./docker/daemon.json /etc/docker/daemon.json'
  >>> store_steps("Dockerfile_devnet_local")[1]
  'COPY ./edge_node/docker/daemon.json /etc/docker/daemon.json'
  """
  # The major the store directory is named after.
  major = daemon_config()["data-root"].rsplit("/", 1)[-1]
  # The five steps, as each Dockerfile must spell them.
  return [
    # A daemon file of the base image would be replaced by the copy without a word.
    "RUN test ! -e /etc/docker/daemon.json",
    # The file of this repository, from where this Dockerfile's build context has it.
    "COPY {} /etc/docker/daemon.json".format(COPY_SOURCES.get(name, "./docker/daemon.json")),
    # dockerd accepts the file and the flags together.
    VALIDATE_LINE,
    # Exactly 0 lines of the entrypoint name the store directory or another settings file; a missing file fails too.
    "RUN grep -cE -- '--(data-root|config-file)' /usr/local/bin/entrypoint.sh | grep -qx 0",
    # The Docker of the base image has that major.
    'RUN dockerd --version | grep -q "^Docker version {}\\."'.format(major),
  ]


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

  def test_every_node_image_starts_the_inner_daemon_and_has_the_store_steps_once_and_in_order(self):
    """Each node image enables the inner daemon and installs and checks the daemon file with the same five steps, in one order."""
    # Every node Dockerfile, each reported under its own name.
    for name, text in node_dockerfiles().items():
      # One result per Dockerfile, so a failure names the file.
      with self.subTest(dockerfile=name):
        # The entrypoint starts dockerd only with EE_DD on.
        self.assertIn("\nENV EE_DD=1\n", text)
        # The build instructions alone: comments and empty lines do not build anything.
        instructions = [line for line in text.splitlines() if line and not line.startswith("#")]
        # What this Dockerfile must have, with the copy source of its own build context.
        steps = store_steps(name)
        # Each step once: a second copy or check would leave two sources of one setting.
        self.assertEqual([instructions.count(step) for step in steps], [1] * len(steps))
        # Where the first of them is.
        first = instructions.index(steps[0])
        # The five follow each other in this order: the base image is looked at before the copy, the checks after it.
        self.assertEqual(instructions[first:first + len(steps)], steps)
        # No other instruction writes or removes that file.
        self.assertEqual([line for line in instructions if "/etc/docker/daemon.json" in line], steps[:2])

  def test_the_build_validates_the_file_with_every_flag_of_the_entrypoint_it_can(self):
    """The validate step passes each entrypoint flag except --tlsverify, whose certificates exist only on a started node."""
    # The long flags of the validate step that take a value, by name.
    flags = set(re.findall(r"--([a-z-]+)=", VALIDATE_LINE))
    # By their daemon.json names: only --host is spelled differently there.
    keys = {"hosts" if flag == "host" else flag for flag in flags}
    # `tls` and `tlsverify` in the file fail the build without a flag: dockerd then wants certificates the image lacks.
    self.assertEqual(keys, ENTRYPOINT_FLAG_KEYS - {"tls", "tlsverify"})


# Run this file directly as well as through the test runner.
if __name__ == "__main__":
  # The standard entry of a unittest file.
  unittest.main()
