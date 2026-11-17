"""
The node images keep the inner Docker store under the mounted `_local_cache`: checks on the image files.

A node container starts its own Docker daemon (the base image entrypoint, `EE_DD=1`) and runs container apps in it.
`docker/daemon.json` is installed as that daemon's `/etc/docker/daemon.json` by every node Dockerfile and names the
directory of its store. These tests keep the file and the Dockerfiles consistent with each other, with what the
entrypoint passes to dockerd and with what the disk API of plugin code refuses, without building an image.

The images start through `cmds/node_entrypoint`, which takes a lock beside the kept store, removes the containerd pid
file an earlier run of the container left, runs that base image entrypoint, tries once more when it fails and removes
the kept store when the second try fails too. The tests keep the script, the daemon file and
the Dockerfiles consistent, and run a copy of the script against a stand-in for the base image entrypoint (on Linux:
the copy uses flock, the checks read /proc).
"""
# The lock a running node holds on its cache folder, taken by the test as another container would.
import fcntl
# The daemon settings file is JSON.
import json
# Whether the entrypoint script can be executed.
import os
# The repository root and the files in it.
import pathlib
# The Dockerfile lines and the shape of the store directory.
import re
# A separate interpreter for the core's disk API.
import subprocess
# The interpreter this test runs on.
import sys
# A folder of its own for each run of the entrypoint script.
import tempfile
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

# The build step before the copy that looks at the base image: no daemon file of its own, which the copy would replace
# without a word, and flock, which cmds/node_entrypoint locks the kept store with (without it every node start would
# stop at that lock, so the build stops here with a line that says so).
BASE_IMAGE_LINE = (
  'RUN test ! -e /etc/docker/daemon.json && { command -v flock || { echo "The base image has no flock, which'
  ' cmds/node_entrypoint locks the kept Docker store with: not building." >&2; exit 1; }; }'
)

# The build step that asks dockerd whether it accepts the installed file together with the entrypoint's flags.
VALIDATE_LINE = (
  "RUN dockerd --validate --host=unix:///var/run/docker.sock --storage-driver=vfs"
  " --tlscacert=/certs/server/ca.pem --tlscert=/certs/server/cert.pem --tlskey=/certs/server/key.pem"
)

# The entrypoint of the base image, which starts the inner daemon: the build steps inspect it, the script runs it.
BASE_ENTRYPOINT = "/usr/local/bin/entrypoint.sh"

# How the script starts it, in the function that both tries call: without the oracle-only secret, which the node
# keeps out of every other environment.
DAEMON_START = "  env -u EE_ORACLE_R1FS_SECRET " + BASE_ENTRYPOINT + " true"

# The file in which dockerd keeps the process number of the containerd it started, under dockerd's default
# exec-root. A node container restarted in place keeps it; the script removes it before the first try.
CONTAINERD_PID_FILE = "/var/run/docker/containerd/containerd.pid"

# dockerd's default exec-root, the folder of that file, which the copy of the script moves into its own folder.
EXEC_ROOT = "/var/run/docker"

# The script the node images start through. Every node Dockerfile copies `cmds/` to /usr/local/bin.
ENTRYPOINT_SCRIPT = REPO_ROOT / "cmds" / "node_entrypoint"

# The instruction that makes the script the entrypoint of a node image.
ENTRYPOINT_LINE = 'ENTRYPOINT ["/usr/local/bin/{}"]'.format(ENTRYPOINT_SCRIPT.name)

# Where each Dockerfile finds `cmds/` in its build context (see COPY_SOURCES for the two kinds of context).
CMDS_SOURCES = {"Dockerfile_devnet_local": "./edge_node/cmds"}


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
    Five instruction lines: no daemon file but flock in the base image, the copy, dockerd accepts the file with the
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
    # A daemon file of the base image would be replaced by the copy without a word; without flock in it, the build
    # stops there with a line that names flock.
    BASE_IMAGE_LINE,
    # The file of this repository, from where this Dockerfile's build context has it.
    "COPY {} /etc/docker/daemon.json".format(COPY_SOURCES.get(name, "./docker/daemon.json")),
    # dockerd accepts the file and the flags together.
    VALIDATE_LINE,
    # Exactly 0 lines of the entrypoint name the store directory or another settings file; a missing file fails too.
    "RUN grep -cE -- '--(data-root|config-file)' /usr/local/bin/entrypoint.sh | grep -qx 0",
    # The Docker of the base image has that major.
    'RUN dockerd --version | grep -q "^Docker version {}\\."'.format(major),
  ]


# What the separate interpreter runs: the core's real path check on a plugin whose cache folder is the first
# argument, for each further argument; it prints the answers as one JSON list.
DISK_API_PROGRAM = """
import json, sys, types
from naeural_core.business.mixins_base.diskapi import _DiskAPIMixin
log = types.SimpleNamespace(get_base_folder=lambda: sys.argv[1])
disk_api = type("DiskApiOfAPlugin", (_DiskAPIMixin,), {"log": log})()
print(json.dumps([disk_api.is_path_safe(path) for path in sys.argv[2:]]))
"""


def disk_api_accepts(paths):
  """
  Ask the disk API that plugin code gets whether it accepts each of some paths.

  Plugin code (customer code included) reads, copies, zips and deletes files only through this API, and every such
  call first asks `is_path_safe`. The answers come from the core's real mixin on a node whose cache folder is
  `CACHE_ROOT`; only the logger it reads that folder from is a stand-in. The core is loaded in an interpreter of its
  own, because other test files of this repository leave stand-ins for core modules loaded in the test process.

  Parameters
  ----------
  paths : list
    Absolute paths, as plugin code would pass them.

  Returns
  -------
  list
    One bool per path: True when the disk API would work on it.

  Raises
  ------
  subprocess.CalledProcessError
    When the core cannot be loaded or the check itself fails.

  Examples
  --------
  >>> disk_api_accepts(["/edge_node/_local_cache/_data/x.json", "/var/lib/docker"])
  [True, False]
  """
  # The same interpreter and module path as this test, with nothing loaded yet.
  command = [sys.executable, "-c", DISK_API_PROGRAM, CACHE_ROOT] + list(paths)
  # A failure there fails the test with the interpreter's own error.
  done = subprocess.run(command, check=True, capture_output=True, text=True)
  # The answers are the last line; a library may print a warning before them.
  return json.loads(done.stdout.splitlines()[-1])


def script_code():
  """
  The command lines of `cmds/node_entrypoint`, without its comments and empty lines.

  Returns
  -------
  list
    The lines as they are in the file, indentation kept; a comment line is one whose first non-blank character
    is `#`, so the comments inside the script's function are left out too.

  Examples
  --------
  >>> script_code()[-1]
  'exec "$@"'
  """
  # Every line that is neither empty nor a comment, in the order of the file.
  return [line for line in ENTRYPOINT_SCRIPT.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]


def run_entrypoint_script(base_exit_codes, command, lock_held=False, first_start=False, env=None, leftover=False):
  """
  Run a copy of the entrypoint script in a folder of its own, with a stand-in for the base image entrypoint.

  The copy differs from `cmds/node_entrypoint` in three places only: the base image entrypoint becomes a stand-in;
  the cache folder becomes a stand-in cache folder, so the store, the folder of the stores and the lock file are
  the same places under it, between files that are not the store's; and dockerd's exec-root becomes a folder of
  the run, so the containerd pid file is there. Other tests pin the real paths.

  The stand-in treats the containerd pid file as dockerd does: when the number in it is a live process (dockerd
  looks for /proc/<number>), it ends with 1 and leaves the file as it was. Otherwise it writes its own number into
  the file, as dockerd writes the number of the containerd it started, and ends with its code from
  `base_exit_codes`; once it has ended that number is dead, as the containerd of a failed dockerd is. On each call
  it first writes down its arguments, whether the store's lock is held, what it found in the pid file, whether the
  store is there and the oracle-only secret it got.

  Parameters
  ----------
  base_exit_codes : list
    What the stand-in ends with on its first, second, ... call when the pid file names no live process: 0 stands
    for a daemon that started. A call past the end of the list ends with the last code.
  command : list
    The node command the script is started with, as a container starts it with the image's `CMD`.
  lock_held : bool
    True: during the run the test holds the store's lock through an open file of its own, as a node running in
    another container on the same cache folder does.
  first_start : bool
    True: the cache folder holds node data only, without the folder of the stores, as on the first start of a
    node on an image that keeps the store.
  env : dict, optional
    Variables added to the environment the script is started with, as a container's environment; None adds none.
  leftover : bool
    True: before the run the containerd pid file holds the number of a live process (the test's own), as in a node
    container restarted in place.

  Returns
  -------
  dict
    `pid`: the process id the script was started with; `exit_code`, `stdout` and `stderr` of the run; `calls`:
    one dict per call of the stand-in, in order, empty when it was not run, with `arguments` (its arguments joined
    by spaces), `lock` ("held", "free" or "missing": the store's lock file as it found it), `pid_file` ("live",
    "dead" or "none": the number in the pid file, or no file), `store` ("there" or "gone") and `secret` (the value
    of EE_ORACLE_R1FS_SECRET it got, "" when unset);
    `pid_file_after`: the text of the containerd pid file after the run, None when there is none; `before` and
    `after`: every path under the stand-in cache folder, relative to it and sorted, before and after the run;
    `store` and `lock`: the store directory and the lock file, relative in the same way.

  Raises
  ------
  AssertionError
    When the copy would still name a path outside its folder; it is not run then.
  subprocess.TimeoutExpired
    When the copy has not ended after 60 s, for example because it waits for a lock.

  Examples
  --------
  >>> run_entrypoint_script([0], ["true"])["exit_code"]
  0
  >>> len(run_entrypoint_script([3, 0], ["true"])["calls"])
  2
  >>> run_entrypoint_script([3], ["true"])["exit_code"]
  1
  >>> run_entrypoint_script([3], ["true"], lock_held=True)["calls"]
  []
  """
  # The store directory, as the daemon file has it.
  data_root = daemon_config()["data-root"]
  # A folder for this run alone, removed with everything in it when the run is over.
  with tempfile.TemporaryDirectory() as folder:
    # The same folder as a path object.
    root = pathlib.Path(folder)
    # The stand-in for the cache folder a host mounts.
    cache = root / "cache"
    # The stand-in store, at the place under the cache folder that the real one has.
    store = cache / pathlib.PurePosixPath(data_root).relative_to(CACHE_ROOT)
    # The stand-in lock file, beside the store, where the script keeps it.
    lock = store.parent / (store.name + ".lock")
    # What is under the cache folder before the run.
    files = [
      # A file of the store.
      store / "image" / "repositories.json",
      # The store of another Docker major, next to it.
      store.parent / "0" / "engine-id",
      # A file next to the folder of the stores.
      store.parent.parent / "other",
      # Node data.
      cache / "_data" / "e2.pem",
    ]
    # A first start finds node data only.
    if first_start:
      # The last of the files above.
      files = files[-1:]
    # Each of them is created.
    for path in files:
      # Its folder first.
      path.parent.mkdir(parents=True, exist_ok=True)
      # Any content will do.
      path.write_text("kept")
    # The stand-in for dockerd's exec-root, and in it the containerd pid file at the place the real one has.
    pid_file = root / "exec_root" / pathlib.PurePosixPath(CONTAINERD_PID_FILE).relative_to(EXEC_ROOT)
    # An in-place restart: the file an earlier run of the container left.
    if leftover:
      # Its folder first.
      pid_file.parent.mkdir(parents=True)
      # A number that is alive during the run, as the old number often is in the new run: this test's process.
      pid_file.write_text(str(os.getpid()))
    # The stand-in base entrypoint. It counts its calls; tries the store's lock through an open file of its own (as a
    # second container would; flock would create a missing file, so it looks first); looks at the number in the pid
    # file and for the store; writes one line per call with those and its arguments and the oracle-only secret it got
    # (empty when unset); ends with 1 when the number is a live process, as dockerd does; otherwise writes its own
    # number into that file, as dockerd writes the number of the containerd it starts, and ends with the code of this
    # call. The doubled braces are format's escape for one brace.
    base = root / "base_entrypoint"
    # A shell file, as the real one.
    base.write_text(
      # The number of this call, kept in a file beside the stand-in.
      '#!/bin/sh\nn=$(( $(cat "$0.count" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$0.count"\n'
      # The lock file, the pid file and the store of this run.
      'l="{}"; p="{}"; d="{}"\n'
      # The lock as another open file finds it.
      'if [ ! -e "$l" ]; then s=missing; elif flock -n "$l" true; then s=free; else s=held; fi\n'
      # No pid file, or one whose number is a live process (dockerd's test: /proc/<number> exists) or a dead one.
      'if [ ! -e "$p" ]; then f=none; elif [ -d "/proc/$(cat "$p")" ]; then f=live; else f=dead; fi\n'
      # Whether the store is there.
      'if [ -e "$d" ]; then t=there; else t=gone; fi\n'
      # One line for this call, the secret last.
      'printf "%s|%s|%s|%s|%s\\n" "$*" "$s" "$f" "$t" "${{EE_ORACLE_R1FS_SECRET-}}" >> "$0.calls"\n'
      # A live number: refused, the file left as it was.
      'if [ "$f" = live ]; then exit 1; fi\n'
      # Otherwise the file of the containerd this try started; its number is dead once this call has ended.
      'mkdir -p "${{p%/*}}"; echo "$$" > "$p"\n'
      # The code of this call.
      'exit "$(sed -n "${{n}}p" "$0.codes")"\n'.format(lock, pid_file, store)
    )
    # The code of each call, one per line; the last one repeated for calls past the end of the list.
    (root / "base_entrypoint.codes").write_text("".join("{}\n".format(code) for code in list(base_exit_codes) + [base_exit_codes[-1]] * 3))
    # The script runs it by its path.
    base.chmod(0o755)
    # The script with the base entrypoint, the cache folder and the exec-root moved into the folder of this run.
    text = ENTRYPOINT_SCRIPT.read_text().replace(BASE_ENTRYPOINT, str(base)).replace(CACHE_ROOT, str(cache))
    # The exec-root last: the pid file path is the one the stand-in looks at.
    text = text.replace(EXEC_ROOT, str(root / "exec_root"))
    # The absolute paths its command lines (not its comments) still name.
    named = re.findall(r"(?<![\w.])/[^\s;\"']+", "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#")))
    # A script that names its paths in another way would run or remove something real.
    if not named or not all(path.startswith(folder) for path in named):
      # Stop before the copy is run.
      raise AssertionError("the copy of the entrypoint script names paths outside its folder: {}".format(named))
    # The copy, under the script's own name.
    copy = root / ENTRYPOINT_SCRIPT.name
    # Its text is the changed one.
    copy.write_text(text)
    # A container runtime executes the entrypoint directly, so the copy is executed directly too.
    copy.chmod(0o755)
    # A node in another container on this cache folder: it holds the lock through its own open file of the lock.
    if lock_held:
      # That open file (the script's own open of the lock file is another one, so the two locks exclude each other).
      holder = lock.open("a")
      # Exclusive, as a running node holds it.
      fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # What is under the cache folder now.
    before = sorted(str(path.relative_to(cache)) for path in cache.rglob("*"))
    # Start the copy with the node command as its arguments and the run's variables; it does not inherit the test's
    # open file.
    process = subprocess.Popen([str(copy)] + list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env={**os.environ, **(env or {})})
    # Wait for its end; a script that hangs fails the test instead of the run.
    stdout, stderr = process.communicate(timeout=60)
    # Only when the test held the lock.
    if lock_held:
      # The other node ends: its file closes, and the lock goes with it.
      holder.close()
    # The file the stand-in writes one line per call to; it is there only when the stand-in was run.
    calls = root / "base_entrypoint.calls"
    # Its lines, empty when the stand-in was not run.
    lines = calls.read_text().splitlines() if calls.exists() else []
    # Everything a test asks about, read before the folder goes.
    return {
      # The process the script was started as.
      "pid": process.pid,
      # How the run ended.
      "exit_code": process.returncode,
      # What the run printed.
      "stdout": stdout,
      # What the run printed as errors.
      "stderr": stderr,
      # One dict per call; the secret is last, so a "|" in it stays in it.
      "calls": [dict(zip(("arguments", "lock", "pid_file", "store", "secret"), line.split("|", 4))) for line in lines],
      # What dockerd would find at the next start.
      "pid_file_after": pid_file.read_text().strip() if pid_file.exists() else None,
      # The cache folder before the run.
      "before": before,
      # The cache folder after the run.
      "after": sorted(str(path.relative_to(cache)) for path in cache.rglob("*")),
      # The store directory in those lists.
      "store": str(store.relative_to(cache)),
      # The lock file in those lists.
      "lock": str(lock.relative_to(cache)),
    }


class TestNodeImageDockerStore(unittest.TestCase):
  """The daemon file and the node Dockerfiles agree with each other, the entrypoint's flags and the disk API."""

  def test_the_store_is_a_directory_per_docker_major_in_the_bin_folder_of_the_mounted_cache(self):
    """The store sits under /edge_node/_local_cache, the only folder a host mounts, in `_bin`, in a directory named by a Docker major."""
    # The directory the inner daemon keeps images, containers and volumes in.
    data_root = daemon_config()["data-root"]
    # Under the mounted cache folder, in its `_bin` folder, in the folder of the stores, named by the major only.
    self.assertRegex(data_root, r"^/edge_node/_local_cache/_bin/docker/[0-9]+$")

  def test_plugin_code_cannot_reach_the_store_through_the_disk_api(self):
    """The store holds every app's resolved environment, layers and logs: the plugins' disk API refuses every path into it."""
    # The directory the inner daemon keeps its store in.
    data_root = daemon_config()["data-root"]
    # One question per path, all in one interpreter start.
    answers = disk_api_accepts([
      # Control: a place of the cache folder the check does accept, here the one the store had at first, next to `_bin`.
      CACHE_ROOT + "/_docker/29/containers/abc/config.v2.json",
      # The store itself: a delete of it would remove every app's image and container.
      data_root,
      # A container's settings file in it, which holds the environment the app was started with.
      data_root + "/containers/abc/config.v2.json",
      # The same file named through a folder plugins may use and `..`.
      CACHE_ROOT + "/_data/.." + data_root[len(CACHE_ROOT):] + "/containers/abc/config.v2.json",
    ])
    # Only the control is accepted.
    self.assertEqual(answers, [True, False, False, False])

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

  def test_the_build_stops_with_a_line_that_names_flock_on_a_base_image_without_it(self):
    """The step before the copy stops the build on a base image without flock, with a line that names it, since the
    script's lock would stop every node start; it passes on a base image with flock, and still stops, without that
    line, on a base image with a daemon file of its own."""
    # Every node Dockerfile, each reported under its own name.
    for dockerfile, text in node_dockerfiles().items():
      # One result per Dockerfile, so a failure names the file; a folder of its own for the stand-in paths.
      with self.subTest(dockerfile=dockerfile), tempfile.TemporaryDirectory() as folder:
        # The step that looks at the base image before the copy, as this Dockerfile spells it (another test pins it
        # once, first of the five), without its RUN: the shell text the build's /bin/sh runs.
        step = next(line for line in text.splitlines() if line.startswith("RUN test ! -e /etc/docker/daemon.json"))
        # The daemon file it looks for moved into this folder, so the host that runs the test cannot change the answer.
        script = step[len("RUN "):].replace("/etc/docker/daemon.json", folder + "/daemon.json")
        # The only folder on the PATH of a base image with flock.
        with_flock = pathlib.Path(folder, "with_flock")
        # Created, with an executable named flock in it: the step only looks for one.
        with_flock.mkdir()
        # Any content will do.
        (with_flock / "flock").write_text("#!/bin/sh\n")
        # Executable, as the real one.
        (with_flock / "flock").chmod(0o755)
        # Per base image: the step's exit code and what it printed as errors.
        ended = {}
        # A base image with flock, one without it (a PATH folder that does not exist), and one with flock and a
        # daemon file of its own; the last creates the file, so it runs last.
        for name, path in (("flock", str(with_flock)), ("no flock", folder + "/none"), ("daemon file", str(with_flock))):
          if name == "daemon file":
            # The base image brings a daemon file.
            pathlib.Path(folder, "daemon.json").write_text("{}")
          # The step on that base image, with only its PATH, through which the shell finds flock.
          run = subprocess.run(["/bin/sh", "-c", script], env={"PATH": path}, capture_output=True, text=True,
                               timeout=60)
          # How it ended.
          ended[name] = (run.returncode, run.stderr)
        # Passes with flock; stops with the line without it; stops without that line on the base image's daemon file.
        self.assertEqual(ended, {
          "flock": (0, ""),
          "no flock": (1, "The base image has no flock, which cmds/node_entrypoint locks the kept Docker store with:"
                          " not building.\n"),
          "daemon file": (1, ""),
        })


class TestNodeImageEntrypoint(unittest.TestCase):
  """The node images start through `cmds/node_entrypoint`, which removes the kept store when the inner daemon fails to start twice."""

  def test_every_node_image_starts_through_the_script_right_after_the_store_steps(self):
    """Each node image has one ENTRYPOINT, the script, after the daemon file steps; the script is copied before it, a command follows."""
    # Every node Dockerfile, each reported under its own name.
    for name, text in node_dockerfiles().items():
      # One result per Dockerfile, so a failure names the file.
      with self.subTest(dockerfile=name):
        # The build instructions alone: comments and empty lines do not build anything.
        instructions = [line for line in text.splitlines() if line and not line.startswith("#")]
        # One entrypoint instruction in the file, and it names the script.
        self.assertEqual([line for line in instructions if line.startswith("ENTRYPOINT")], [ENTRYPOINT_LINE])
        # Where it is.
        position = instructions.index(ENTRYPOINT_LINE)
        # Directly after the last of the five store steps: the image is checked first, then told how to start.
        self.assertEqual(instructions[position - 1], store_steps(name)[-1])
        # The copy that brings the script into the image, from where this Dockerfile's build context has it.
        copied = instructions.index("COPY {} /usr/local/bin/".format(CMDS_SOURCES.get(name, "./cmds")))
        # Before the entrypoint instruction the script is copied and then made executable in the image.
        self.assertLess(copied, instructions.index("RUN chmod +x /usr/local/bin/*", copied))
        # That step too is before the entrypoint instruction.
        self.assertLess(instructions.index("RUN chmod +x /usr/local/bin/*", copied), position)
        # ENTRYPOINT drops the command of the base image, and the script ends with code 0 when it gets none: the
        # image names its own node command after it, once.
        self.assertEqual(len([line for line in instructions[position:] if line.startswith("CMD ")]), 1)

  def test_the_script_removes_the_containerd_pid_file_and_the_directory_the_daemon_file_names_and_nothing_else(self):
    """The script removes two things: the containerd pid file under dockerd's default exec-root, which the daemon
    file does not change, and the data-root of `docker/daemon.json`, so the two cannot name different stores."""
    # The directory the inner daemon keeps its store in.
    data_root = daemon_config()["data-root"]
    # The command lines of the script, without its comments.
    code = "\n".join(script_code())
    # Every removal in them, up to the end of the command: the pid file, then the store.
    self.assertEqual(re.findall(r"\brm\b[^;\n]*", code), ["rm -f " + CONTAINERD_PID_FILE, "rm -rf " + data_root])
    # The pid file is where dockerd keeps it only while the daemon file sets no other exec-root.
    self.assertNotIn("exec-root", daemon_config())
    # No second mention of the directory that a change of the daemon file could leave behind; the name of the lock
    # file beside it starts with it, and another test pins that name.
    self.assertEqual(ENTRYPOINT_SCRIPT.read_text().replace(data_root + ".lock", "").count(data_root), 1)

  def test_the_script_takes_the_lock_beside_the_store_before_the_daemon_and_removes_only_under_it(self):
    """The script's command lines, in order: the lock's folder, the lock file on an inherited descriptor, a lock
    that does not wait and stops the start, the removal of the containerd pid file, a try that starts the daemon,
    two such tries of which only a second failure removes the store, the node command."""
    # The directory the inner daemon keeps its store in.
    data_root = daemon_config()["data-root"]
    # The command lines of the script, without its comments and empty lines.
    code = script_code()
    # Nine lines and nothing else.
    self.assertEqual(len(code), 9)
    # The folder of the stores, which a first start does not find yet.
    self.assertEqual(code[0], "mkdir -p " + str(pathlib.PurePosixPath(data_root).parent))
    # The lock file beside the store, not in it, opened by the shell itself so that every process it starts, and
    # the node command that replaces it, keeps the descriptor and with it the lock.
    self.assertEqual(code[1], "exec 9>>" + data_root + ".lock")
    # The lock is exclusive and does not wait for another holder; when it cannot be taken the start ends there,
    # non-zero.
    self.assertTrue(code[2].startswith("flock -n 9 || { echo ") and code[2].endswith(" >&2; exit 1; }"))
    # That step removes nothing.
    self.assertNotIn("rm ", code[2])
    # After the lock, the pid file of an earlier run goes, once; then one try, which starts the daemon without the
    # oracle-only secret.
    self.assertEqual(code[3:7], ["rm -f " + CONTAINERD_PID_FILE, "start_daemon() {", DAEMON_START, "}"])
    # The first try; when it fails, a line and the second try; when that fails too, a line, the store's removal and
    # a non-zero end.
    self.assertRegex(code[7], r'^start_daemon \|\| \{ echo "[^"]+" >&2; start_daemon; \} \|\| \{ echo "[^"]+" >&2; rm -rf '
                     + re.escape(data_root) + r'; exit 1; \}$')
    # Last, the node command in the place of the script's own process.
    self.assertEqual(code[8], 'exec "$@"')

  def test_the_script_runs_the_base_entrypoint_the_build_inspects(self):
    """The script starts the daemon through the file the build checks for a store flag, and `cmds/` does not replace that file."""
    # The command lines of the script, without its comments and empty lines.
    code = script_code()
    # One of them names the base image entrypoint: it runs it with `true` and without the oracle-only secret.
    self.assertEqual([line for line in code if BASE_ENTRYPOINT in line], [DAEMON_START])
    # Every node Dockerfile, each reported under its own name.
    for name in node_dockerfiles():
      # One result per Dockerfile, so a failure names the file.
      with self.subTest(dockerfile=name):
        # The build step that reads the entrypoint for a store flag reads that same file.
        self.assertIn(" " + BASE_ENTRYPOINT + " ", store_steps(name)[3])
    # `cmds/` is copied over /usr/local/bin: a file there with the base entrypoint's name would replace it, and the
    # script would then run itself.
    self.assertFalse((REPO_ROOT / "cmds" / pathlib.PurePosixPath(BASE_ENTRYPOINT).name).exists())

  def test_the_script_is_an_executable_shell_file_with_unix_line_ends(self):
    """A container runtime can execute the script: executable bit, a `/bin/sh` first line, no carriage return in any checkout."""
    # The script, byte for byte.
    data = ENTRYPOINT_SCRIPT.read_bytes()
    # The image keeps the mode of the copied file, and the entrypoint is executed directly.
    self.assertTrue(os.access(ENTRYPOINT_SCRIPT, os.X_OK))
    # The interpreter of the base image entrypoint, so the start needs no other shell than before.
    self.assertTrue(data.startswith(b"#!/bin/sh\n"))
    # With a carriage return after the first line the kernel finds no interpreter and the container does not start.
    self.assertNotIn(b"\r", data)
    # A checkout that converts line ends leaves this file alone.
    self.assertIn("cmds/{} text eol=lf".format(ENTRYPOINT_SCRIPT.name), (REPO_ROOT / ".gitattributes").read_text().splitlines())

  def test_a_started_daemon_hands_the_node_command_on_as_the_same_process(self):
    """After a good daemon start the script becomes the node command (process 1 in a container), arguments and exit code kept."""
    # A node command that prints its own process id and its two arguments, then ends with a code of its own.
    result = run_entrypoint_script([0], ["/bin/sh", "-c", 'echo "$$|$0|$1"; exit 7', "first argument", "second argument"])
    # One try: the base entrypoint is asked to start the daemon and run `true`, not the node command.
    self.assertEqual([call["arguments"] for call in result["calls"]], ["true"])
    # The command ran as the process the script was started as, so in a container it is process 1; its arguments
    # arrive whole.
    self.assertEqual(result["stdout"], "{}|first argument|second argument\n".format(result["pid"]))
    # The node's exit code is the container's.
    self.assertEqual(result["exit_code"], 7)
    # Nothing said about the start.
    self.assertEqual(result["stderr"], "")
    # The store and everything else are as they were; the lock file is new beside the store.
    self.assertEqual(result["after"], sorted(result["before"] + [result["lock"]]))

  def test_the_daemon_starts_without_the_oracle_secret_and_the_node_command_keeps_it(self):
    """With the oracle-only secret in the container's environment, as on a seed, the base entrypoint (and so the
    dockerd it leaves running) does not get it, and the node command, which moves it into memory, does."""
    # A good start whose node command prints the variable, in an environment that has it.
    result = run_entrypoint_script([0], ["/bin/sh", "-c", 'echo "$EE_ORACLE_R1FS_SECRET"'],
                                   env={"EE_ORACLE_R1FS_SECRET": "fake-oracle-secret-for-tests-only"})
    # The base entrypoint got no value, and the node command got the value.
    self.assertEqual(([call["secret"] for call in result["calls"]], result["stdout"]),
                     ([""], "fake-oracle-secret-for-tests-only\n"))

  def test_a_containerd_pid_file_of_an_earlier_run_does_not_cost_the_store(self):
    """A node container restarted in place finds the containerd pid file of its earlier run, which makes dockerd
    refuse to start: the script removes it before the start, so the first try starts and the store stays."""
    # The file an earlier run left, with a live number; the stand-in refuses to start on it, as dockerd does.
    result = run_entrypoint_script([0], ["/bin/sh", "-c", "echo the node command ran"], leftover=True)
    # One try, under the lock, without the file, on the store.
    self.assertEqual([(call["lock"], call["pid_file"], call["store"]) for call in result["calls"]], [("held", "none", "there")])
    # The node command ran and the container goes on; nothing was said about the start.
    self.assertEqual((result["stdout"], result["exit_code"], result["stderr"]), ("the node command ran\n", 0, ""))
    # The store and everything else are as they were; the lock file is new beside the store.
    self.assertEqual(result["after"], sorted(result["before"] + [result["lock"]]))
    # The file now holds the number the started daemon wrote, not the earlier run's.
    self.assertNotIn(result["pid_file_after"], (None, str(os.getpid())))

  def test_a_failed_first_try_is_followed_by_a_second_that_keeps_the_store(self):
    """When the first try fails, the script says so in one line and tries once more, again under the lock and
    without a removal: the pid file the first try left holds a dead number, which dockerd passes over. A good
    second try keeps the store and runs the node command."""
    # The first try fails and leaves its pid file, the second starts.
    result = run_entrypoint_script([3, 0], ["/bin/sh", "-c", "echo the node command ran"])
    # Two tries, both under the lock and on the store; the first without a pid file, the second with the first
    # one's file, whose number ended with it.
    self.assertEqual([(call["lock"], call["pid_file"], call["store"]) for call in result["calls"]],
                     [("held", "none", "there"), ("held", "dead", "there")])
    # The one line of the failed try.
    self.assertEqual(result["stderr"], "The inner Docker daemon did not start: trying once more.\n")
    # The node command ran and the container goes on.
    self.assertEqual((result["stdout"], result["exit_code"]), ("the node command ran\n", 0))
    # The store and everything else are as they were; the lock file is new beside the store.
    self.assertEqual(result["after"], sorted(result["before"] + [result["lock"]]))

  def test_a_daemon_that_fails_twice_costs_the_store_and_only_the_store(self):
    """After two failed tries, the second still on the store, the script says so once per try, removes the store
    and nothing else, and ends non-zero without the node command, also when a pid file of an earlier run was there."""
    # Both tries fail with a code that is not the script's own; the node command would print a line.
    result = run_entrypoint_script([3, 3], ["/bin/sh", "-c", "echo the node command ran"], leftover=True)
    # Two tries in the same way as in a good start: under the lock, the first without the earlier run's pid file,
    # the second with the dead number of the first, and the store still there at the second.
    self.assertEqual([(call["arguments"], call["lock"], call["pid_file"], call["store"]) for call in result["calls"]],
                     [("true", "held", "none", "there"), ("true", "held", "dead", "there")])
    # One line per failed try, the second says what happens to the store.
    self.assertEqual(result["stderr"].splitlines(), [
      "The inner Docker daemon did not start: trying once more.",
      "The inner Docker daemon did not start a second time: removing its kept store.",
    ])
    # The container stops with a failure code, so whoever started it sees a failed start.
    self.assertEqual(result["exit_code"], 1)
    # The node command was not run without a daemon.
    self.assertEqual(result["stdout"], "")
    # The store directory was there before the run.
    self.assertIn(result["store"], result["before"])
    # Afterwards the store directory and what was in it are gone, and every other path is still there, the lock
    # file beside the store too.
    kept = [path for path in result["before"] if not (path + "/").startswith(result["store"] + "/")]
    # The lock file is the one path the run added.
    self.assertEqual(result["after"], sorted(kept + [result["lock"]]))

  def test_a_lock_held_by_another_container_stops_the_start_before_the_daemon_and_removes_nothing(self):
    """With the store's lock held elsewhere (a node running on the same cache folder), the script says so and ends
    non-zero: no daemon start, no removal, not even of the containerd pid file, no node command."""
    # A base entrypoint that would fail, as a second daemon on a store in use does, and so would remove the store;
    # a containerd pid file there as well.
    result = run_entrypoint_script([3], ["/bin/sh", "-c", "echo the node command ran"], lock_held=True, leftover=True)
    # The start ends with a failure code, so whoever started it sees a failed start.
    self.assertEqual(result["exit_code"], 1)
    # The log says why, in one line.
    self.assertEqual(result["stderr"].count("locked by another container"), 1)
    # No daemon start was tried and the node command did not run.
    self.assertEqual((result["calls"], result["stdout"]), ([], ""))
    # The store, the lock file and everything else are as they were.
    self.assertEqual(result["after"], result["before"])
    # The pid file too, with the earlier run's number.
    self.assertEqual(result["pid_file_after"], str(os.getpid()))

  def test_the_lock_is_held_from_before_the_daemon_start_through_the_node_command(self):
    """The daemon starts with the lock already held, and the node command keeps the lock's descriptor across the exec: the lock lasts as long as the node."""
    # A node command that names the file of its descriptor 9, then tries the lock through an open file of its own.
    command = ["/bin/sh", "-c", 'f=$(readlink /proc/$$/fd/9); echo "$f"; flock -n "$f" true; echo "$?"']
    # A good start.
    result = run_entrypoint_script([0], command)
    # The base entrypoint, which starts the daemon, found the lock held.
    self.assertEqual([call["lock"] for call in result["calls"]], ["held"])
    # The two lines the node command printed.
    named, tried = result["stdout"].splitlines()
    # Its descriptor 9 is open on the lock file of the stand-in cache folder.
    self.assertTrue(named.endswith("/cache/" + result["lock"]), named)
    # The lock is held while the node command runs: flock without waiting ends with 1.
    self.assertEqual(tried, "1")
    # The node's exit code is the container's.
    self.assertEqual(result["exit_code"], 0)

  def test_a_first_start_creates_the_folder_of_the_lock_and_starts(self):
    """On a cache folder without `_bin/docker` (the first start on an image that keeps the store) the script creates the folder and the lock file and starts the daemon under the lock."""
    # A good start on node data only.
    result = run_entrypoint_script([0], ["true"], first_start=True)
    # The start goes on to the node command.
    self.assertEqual(result["exit_code"], 0)
    # The daemon start was tried once, under the lock.
    self.assertEqual([(call["arguments"], call["lock"]) for call in result["calls"]], [("true", "held")])
    # The folder of the stores, its parent and the lock file are new; the store itself is the daemon's to create.
    self.assertEqual(sorted(set(result["after"]) - set(result["before"])), ["_bin", "_bin/docker", result["lock"]])


# Run this file directly as well as through the test runner.
if __name__ == "__main__":
  # The standard entry of a unittest file.
  unittest.main()
