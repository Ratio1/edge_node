"""Unit tests for sync_manager.SyncManager pure helpers.

Covers the path-validation chokepoint (resolve_container_path), atomic JSON
writes, and history append/latest/update operations using a temporary
plugin-data directory and a stub owner that mimics the BasePlugin surface
the manager depends on.
"""

import json
import os
import io
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.container_apps.sync import (
  SYNC_PROCESSING_FILE,
  SYSTEM_VOLUME_NAME,
  SYSTEM_VOLUME_MOUNT,
  SyncManager,
  history_received_dir,
  history_sent_dir,
  system_volume_host_root,
  volume_sync_dir,
)
from extensions.business.container_apps.sync.manager import (
  PROVIDER_CAPTURE_ONLINE,
  SyncRequest,
  SyncRuntimePolicy,
)


def _tar_bytes(name: str, content: bytes) -> bytes:
  buff = io.BytesIO()
  with tarfile.open(fileobj=buff, mode="w") as tar:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(content))
  return buff.getvalue()


class _FakeDockerArchiveContainer:
  def __init__(self, archives: dict[str, bytes]):
    self.archives = dict(archives)
    self.get_archive_calls: list[str] = []

  def get_archive(self, path):
    self.get_archive_calls.append(path)
    archive = self.archives[path]
    name = os.path.basename(path.rstrip("/")) or "/"
    return iter([archive]), {"name": name}


class _FakeR1FS:
  """Minimal r1fs stub for orchestrator tests."""

  def __init__(self):
    self.added: dict[str, bytes] = {}
    self.deleted: list[tuple[str, bool, bool]] = []
    self.add_should_raise: Exception | None = None
    self.add_should_return_empty = False
    self.get_should_raise: Exception | None = None
    self.delete_should_raise: Exception | None = None
    self._counter = 0

  def add_file(self, file_path: str) -> str:
    if self.add_should_raise:
      raise self.add_should_raise
    if self.add_should_return_empty:
      return ""
    self._counter += 1
    cid = f"QmFAKE{self._counter:08d}"
    with open(file_path, "rb") as handle:
      self.added[cid] = handle.read()
    return cid

  def get_file(self, cid: str) -> str:
    if self.get_should_raise:
      raise self.get_should_raise
    if cid not in self.added:
      return ""
    fd, path = tempfile.mkstemp(suffix=".tar.gz")
    with os.fdopen(fd, "wb") as out:
      out.write(self.added[cid])
    return path

  def delete_file(
    self,
    cid: str,
    unpin_remote: bool = False,
    cleanup_local_files: bool = False,
    **_kwargs,
  ) -> dict:
    if self.delete_should_raise:
      raise self.delete_should_raise
    self.added.pop(cid, None)
    self.deleted.append((cid, unpin_remote, cleanup_local_files))
    return {"ok": True}


class _FakeChainStore:
  """Minimal chainstore stub: a process-local hkey/key dict."""

  def __init__(self):
    self.store: dict[tuple[str, str], object] = {}
    self.hset_calls: list[tuple[str, str, object]] = []
    self.hsync_calls: list[str] = []
    self.hset_should_raise: Exception | None = None
    self.hsync_should_raise: Exception | None = None
    self.hset_returns: bool = True

  def hset(self, hkey, key, value, **_kwargs):
    if self.hset_should_raise:
      raise self.hset_should_raise
    self.hset_calls.append((hkey, key, value))
    self.store[(hkey, key)] = value
    return self.hset_returns

  def hget(self, hkey, key, **_kwargs):
    return self.store.get((hkey, key))

  def hsync(self, hkey, **_kwargs):
    self.hsync_calls.append(hkey)
    if self.hsync_should_raise:
      raise self.hsync_should_raise
    return None


def _make_owner(tmpdir: Path) -> SimpleNamespace:
  """Build a minimal owner stub for SyncManager tests."""
  data_folder = tmpdir / "_local_cache" / "_data"
  data_folder.mkdir(parents=True)
  instance_subfolder = "pipelines_data/test_pipe/test_inst"

  fixed_root = data_folder / instance_subfolder / "fixed_volumes" / "mounts"
  fixed_root.mkdir(parents=True)
  (fixed_root / SYSTEM_VOLUME_NAME).mkdir()
  (fixed_root / "appdata").mkdir()
  (fixed_root / "legacy_bind").mkdir()  # pretend FILE_VOLUMES path

  volumes = {
    str(fixed_root / SYSTEM_VOLUME_NAME): {"bind": SYSTEM_VOLUME_MOUNT, "mode": "rw"},
    str(fixed_root / "appdata"): {"bind": "/app/data", "mode": "rw"},
    # A path that looks like a fixed-size volume but isn't (no fixed_volumes/mounts/ root)
    str(tmpdir / "tmpfs_legacy"): {"bind": "/app/legacy", "mode": "rw"},
  }
  (tmpdir / "tmpfs_legacy").mkdir()

  output_folder = tmpdir / "output"
  output_folder.mkdir()

  msgs: list[str] = []
  r1fs = _FakeR1FS()
  cs = _FakeChainStore()
  # Track time so each call to time() returns a slightly larger float, which
  # lets us emit successive snapshots with distinct version timestamps in
  # the same test without sleeping.
  clock = [1714742400.0]
  def _time():
    clock[0] += 1.0
    return clock[0]
  return SimpleNamespace(
    get_data_folder=lambda: str(data_folder),
    _get_instance_data_subfolder=lambda: instance_subfolder,
    get_output_folder=lambda: str(output_folder),
    volumes=volumes,
    time=_time,
    ee_id="ee_test_provider",
    cfg_sync_key="11111111-1111-1111-1111-111111111111",
    cfg_sync_type="provider",
    r1fs=r1fs,
    chainstore_hset=cs.hset,
    chainstore_hget=cs.hget,
    chainstore_hsync=cs.hsync,
    P=lambda msg, color=None: msgs.append(f"[{color or ''}] {msg}"),
    _msgs=msgs,
    _fixed_root=fixed_root,
    _output_folder=output_folder,
    _r1fs=r1fs,
    _cs=cs,
  )


# ---------------------------------------------------------------------------
# resolve_container_path
# ---------------------------------------------------------------------------

class TestResolveContainerPath(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.owner = _make_owner(self.tmpdir)
    self.sm = SyncManager(self.owner)

  def tearDown(self):
    self._tmp.cleanup()

  def test_happy_path_directory(self):
    host, bind, host_root = self.sm.resolve_container_path("/app/data/")
    self.assertTrue(host.endswith("fixed_volumes/mounts/appdata"))
    self.assertEqual(bind, "/app/data")
    self.assertTrue(host_root.endswith("fixed_volumes/mounts/appdata"))

  def test_happy_path_subfile(self):
    host, _, _ = self.sm.resolve_container_path("/app/data/foo.bin")
    self.assertTrue(host.endswith("fixed_volumes/mounts/appdata/foo.bin"))

  def test_rejects_relative(self):
    with self.assertRaisesRegex(ValueError, "must be absolute"):
      self.sm.resolve_container_path("app/data/")

  def test_rejects_dotdot(self):
    with self.assertRaisesRegex(ValueError, r"must not contain"):
      self.sm.resolve_container_path("/app/data/../../etc/passwd")

  def test_rejects_unmounted(self):
    with self.assertRaisesRegex(ValueError, "no mounted volume covers"):
      self.sm.resolve_container_path("/nope/")

  def test_rejects_anonymous_mount(self):
    """Rule 3 admits FIXED_SIZE_VOLUMES and legacy VOLUMES (both per-instance
    host directories under known roots). Mounts that aren't under either —
    anonymous Docker mounts, FILE_VOLUMES content files, ephemeral container
    fs — are still rejected. The fixture's ``/app/legacy`` mount is bound at
    ``tmpdir/tmpfs_legacy`` (outside both allow-listed roots) so it stands in
    for the "anonymous mount" case here.
    """
    with self.assertRaisesRegex(ValueError, "non-volume-backed mount"):
      self.sm.resolve_container_path("/app/legacy/x")

  def test_rejects_system_volume(self):
    with self.assertRaisesRegex(ValueError, "anti-recursion"):
      self.sm.resolve_container_path("/r1en_system/foo")

  def test_rejects_system_volume_root(self):
    with self.assertRaisesRegex(ValueError, "anti-recursion"):
      self.sm.resolve_container_path("/r1en_system")

  def test_rejects_empty(self):
    with self.assertRaisesRegex(ValueError, "non-empty"):
      self.sm.resolve_container_path("")

  def test_longest_prefix_wins_for_nested_mounts(self):
    """Nested fixed-size mounts (/app and /app/data) must resolve by the most
    specific bind, not by dict insertion order. Docker overlays the deeper
    mount on top of the broader one inside the container, so a path under
    /app/data must resolve to the /app/data mount's host root even when /app
    was added to self.volumes first. The previous first-match-wins iteration
    silently mapped to the wrong host root (codex review finding 3 on PR #399).
    """
    fixed_root = self.owner._fixed_root
    (fixed_root / "outer_app").mkdir(exist_ok=True)
    (fixed_root / "inner_data").mkdir(exist_ok=True)
    # Order matters: insert the broader mount FIRST so first-match-wins would
    # pick the wrong one.
    self.owner.volumes = {
      str(fixed_root / "outer_app"): {"bind": "/app", "mode": "rw"},
      str(fixed_root / "inner_data"): {"bind": "/app/data", "mode": "rw"},
    }
    host, bind, host_root = self.sm.resolve_container_path("/app/data/foo.bin")
    self.assertTrue(host.endswith("fixed_volumes/mounts/inner_data/foo.bin"))
    self.assertEqual(bind, "/app/data")
    self.assertTrue(host_root.endswith("fixed_volumes/mounts/inner_data"))

  def test_longest_prefix_wins_regardless_of_insertion_order(self):
    """Same as above but with the dict items in the opposite order. The result
    must be identical — specificity, not insertion order, decides the winner.
    """
    fixed_root = self.owner._fixed_root
    (fixed_root / "outer_app").mkdir(exist_ok=True)
    (fixed_root / "inner_data").mkdir(exist_ok=True)
    self.owner.volumes = {
      str(fixed_root / "inner_data"): {"bind": "/app/data", "mode": "rw"},
      str(fixed_root / "outer_app"): {"bind": "/app", "mode": "rw"},
    }
    host, bind, _ = self.sm.resolve_container_path("/app/data/foo.bin")
    self.assertTrue(host.endswith("fixed_volumes/mounts/inner_data/foo.bin"))
    self.assertEqual(bind, "/app/data")

  def test_outer_bind_still_resolves_for_paths_only_it_covers(self):
    """Paths that fall under the broader mount but NOT the nested one must
    still resolve to the broader mount — longest-prefix-match must not break
    legitimate routes through the outer bind.
    """
    fixed_root = self.owner._fixed_root
    (fixed_root / "outer_app").mkdir(exist_ok=True)
    (fixed_root / "inner_data").mkdir(exist_ok=True)
    self.owner.volumes = {
      str(fixed_root / "outer_app"): {"bind": "/app", "mode": "rw"},
      str(fixed_root / "inner_data"): {"bind": "/app/data", "mode": "rw"},
    }
    host, bind, _ = self.sm.resolve_container_path("/app/other.bin")
    self.assertTrue(host.endswith("fixed_volumes/mounts/outer_app/other.bin"))
    self.assertEqual(bind, "/app")

  def test_legacy_volumes_resolves_to_host_root(self):
    """Rule 3 admits legacy VOLUMES. Their host roots live under
    CONTAINER_VOLUMES_PATH (/edge_node/_local_cache/_data/container_volumes/),
    which is per-instance and bounded — functionally equivalent to
    fixed-size for sync purposes. Plan: extend-sync-to-legacy-VOLUMES.
    """
    from extensions.business.container_apps.container_utils import (
      CONTAINER_VOLUMES_PATH,
    )
    # Place a fake legacy host root and bind it into the volumes dict.
    # We can't use the real CONTAINER_VOLUMES_PATH on a CI host without root,
    # so monkeypatch it (constants_in_path comparison normalizes the value).
    legacy_root = Path(self.tmpdir) / "edge_node" / "_local_cache" / "_data" / "container_volumes"
    instance_dir = legacy_root / "test_instance_appdata"
    instance_dir.mkdir(parents=True)

    self.owner.volumes = {
      str(instance_dir): {"bind": "/app/data", "mode": "rw"},
    }

    # Patch CONTAINER_VOLUMES_PATH on the manager module so the resolver
    # accepts our temp legacy root for the duration of the test.
    import extensions.business.container_apps.sync.manager as manager_mod
    original = manager_mod.CONTAINER_VOLUMES_PATH
    manager_mod.CONTAINER_VOLUMES_PATH = str(legacy_root)
    try:
      host, bind, host_root = self.sm.resolve_container_path("/app/data/foo.bin")
    finally:
      manager_mod.CONTAINER_VOLUMES_PATH = original

    self.assertTrue(host.endswith("test_instance_appdata/foo.bin"))
    self.assertEqual(bind, "/app/data")
    self.assertEqual(host_root, str(instance_dir))


# ---------------------------------------------------------------------------
# _write_json_atomic
# ---------------------------------------------------------------------------

class TestAtomicJsonWrite(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.owner = _make_owner(self.tmpdir)
    self.sm = SyncManager(self.owner)

  def tearDown(self):
    self._tmp.cleanup()

  def test_writes_json_and_creates_parent(self):
    target = self.tmpdir / "deep" / "nested" / "out.json"
    self.sm._write_json_atomic(target, {"hello": "world", "n": 7})
    self.assertTrue(target.is_file())
    data = json.loads(target.read_text())
    self.assertEqual(data, {"hello": "world", "n": 7})

  def test_no_orphan_tmp_on_success(self):
    target = self.tmpdir / "out.json"
    self.sm._write_json_atomic(target, {"x": 1})
    leftovers = [p for p in self.tmpdir.iterdir() if p.name.startswith(".out.json")]
    self.assertEqual(leftovers, [], f"leftover tmps: {leftovers}")

  def test_overwrites_existing(self):
    target = self.tmpdir / "out.json"
    target.write_text('{"old": true}')
    self.sm._write_json_atomic(target, {"new": True})
    self.assertEqual(json.loads(target.read_text()), {"new": True})


# ---------------------------------------------------------------------------
# History readers / writers
# ---------------------------------------------------------------------------

class TestHistory(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.owner = _make_owner(self.tmpdir)
    self.sm = SyncManager(self.owner)

  def tearDown(self):
    self._tmp.cleanup()

  def test_filename_pads_version_and_truncates_cid(self):
    fname = SyncManager._history_filename(1714742400, "QmHash1234567890ABCDEF")
    self.assertEqual(fname, "1714742400__QmHash123456.json")

  def test_filename_handles_short_cid(self):
    fname = SyncManager._history_filename(7, "Qm")
    self.assertEqual(fname, "0000000007__Qm.json")

  def test_filename_handles_missing_cid(self):
    fname = SyncManager._history_filename(7, "")
    self.assertEqual(fname, "0000000007__no_cid.json")

  def test_append_sent_writes_under_history_sent(self):
    entry = {"cid": "QmAA1", "version": 100, "node_id": "ee_x"}
    path = self.sm.append_sent(entry)
    self.assertEqual(path.parent, history_sent_dir(self.owner))
    self.assertEqual(path.name, "0000000100__QmAA1.json")
    data = json.loads(path.read_text())
    self.assertEqual(data["cid"], "QmAA1")
    self.assertEqual(data["deletion"], {
      "deleted_at": None, "deletion_succeeded": None, "deletion_error": None
    })

  def test_append_received_uses_received_dir(self):
    entry = {"cid": "QmBB", "version": 50, "node_id": "ee_y"}
    path = self.sm.append_received(entry)
    self.assertEqual(path.parent, history_received_dir(self.owner))

  def test_latest_picks_most_recently_written(self):
    """latest_sent / latest_received use mtime, not filename ordering, so a
    back-dated version (e.g. clock-skewed provider) doesn't permanently
    'win' over an entry written after it."""
    self.sm.append_sent({"cid": "Qm1", "version": 100})
    # Tiny sleep to guarantee distinct mtimes on filesystems with low
    # mtime resolution.
    import time as _t; _t.sleep(0.01)
    self.sm.append_sent({"cid": "Qm3", "version": 300})
    _t.sleep(0.01)
    # Entry written LAST has version=200 — lex-smaller filename than
    # Qm3's, but the most recent on disk. mtime sort returns it.
    self.sm.append_sent({"cid": "Qm2", "version": 200})
    latest = self.sm.latest_sent()
    self.assertIsNotNone(latest)
    self.assertEqual(latest["cid"], "Qm2")
    self.assertEqual(latest["version"], 200)

  def test_latest_returns_none_when_empty(self):
    self.assertIsNone(self.sm.latest_sent())
    self.assertIsNone(self.sm.latest_received())

  def test_update_history_deletion_modifies_in_place(self):
    entry = {"cid": "Qm9", "version": 999}
    path = self.sm.append_sent(entry)

    self.sm.update_history_deletion(
      history_sent_dir(self.owner), entry, succeeded=True, error=None
    )
    data = json.loads(path.read_text())
    self.assertTrue(data["deletion"]["deletion_succeeded"])
    self.assertEqual(data["deletion"]["deletion_error"], None)
    self.assertGreater(data["deletion"]["deleted_at"], 1714742400.0)
    self.assertEqual(data["cid"], "Qm9")  # rest of payload preserved

  def test_update_history_deletion_records_failure(self):
    entry = {"cid": "Qm9", "version": 999}
    self.sm.append_sent(entry)
    self.sm.update_history_deletion(
      history_sent_dir(self.owner), entry, succeeded=False, error="daemon down"
    )
    path = history_sent_dir(self.owner) / "0000000999__Qm9.json"
    data = json.loads(path.read_text())
    self.assertFalse(data["deletion"]["deletion_succeeded"])
    self.assertEqual(data["deletion"]["deletion_error"], "daemon down")

  def test_update_history_deletion_missing_file_logs(self):
    entry = {"cid": "QmMissing", "version": 1}
    # Don't append; just call update — should log warning, not raise.
    self.sm.update_history_deletion(
      history_sent_dir(self.owner), entry, succeeded=True, error=None
    )
    self.assertTrue(any("history file missing" in m for m in self.owner._msgs))


# ---------------------------------------------------------------------------
# claim_request
# ---------------------------------------------------------------------------

class TestClaimRequest(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.owner = _make_owner(self.tmpdir)
    self.sm = SyncManager(self.owner)
    # Provision the volume-sync subdir on the host (mimics _configure_system_volume)
    self.vsd = volume_sync_dir(self.owner)
    self.vsd.mkdir(parents=True, exist_ok=True)

  def tearDown(self):
    self._tmp.cleanup()

  def _write_request(self, body):
    (self.vsd / "request.json").write_text(json.dumps(body))

  def _read_invalid(self):
    p = self.vsd / "request.json.invalid"
    if not p.exists():
      return None
    return json.loads(p.read_text())

  def _read_response(self):
    p = self.vsd / "response.json"
    if not p.exists():
      return None
    return json.loads(p.read_text())

  def test_no_pending_returns_none(self):
    self.assertIsNone(self.sm.claim_request())

  def test_happy_path(self):
    self._write_request({"archive_paths": ["/app/data/"], "metadata": {"k": 1}})
    result = self.sm.claim_request()
    self.assertIsNotNone(result)
    self.assertEqual(result.archive_paths, ["/app/data/"])
    self.assertEqual(result.metadata, {"k": 1})
    self.assertEqual(result.runtime.provider_capture, "offline")
    self.assertEqual(result.runtime.consumer_apply, "offline_restart")
    # request.json gone, .processing present, no .invalid
    self.assertFalse((self.vsd / "request.json").exists())
    self.assertTrue((self.vsd / "request.json.processing").exists())
    self.assertIsNone(self._read_invalid())

  def test_runtime_policy_parsed(self):
    self.owner.cfg_sync_allow_online_provider_capture = True
    self._write_request({
      "archive_paths": ["/app/data/"],
      "runtime": {
        "provider_capture": "online",
        "consumer_apply": "online_no_restart",
      },
    })

    result = self.sm.claim_request()

    self.assertIsNotNone(result)
    self.assertEqual(result.runtime.provider_capture, "online")
    self.assertEqual(result.runtime.consumer_apply, "online_no_restart")

  def test_runtime_policy_must_be_object(self):
    self._write_request({"archive_paths": ["/app/data/"], "runtime": "online"})

    self.assertIsNone(self.sm.claim_request())

    self.assertIn("runtime must be a JSON object", self._read_invalid()["_error"]["error"])

  def test_invalid_provider_capture_rejected(self):
    self._write_request({
      "archive_paths": ["/app/data/"],
      "runtime": {"provider_capture": "maybe"},
    })

    self.assertIsNone(self.sm.claim_request())

    err = self._read_invalid()["_error"]["error"]
    self.assertIn("provider_capture", err)
    self.assertIn("maybe", err)

  def test_invalid_consumer_apply_rejected(self):
    self._write_request({
      "archive_paths": ["/app/data/"],
      "runtime": {"consumer_apply": "sometimes"},
    })

    self.assertIsNone(self.sm.claim_request())

    err = self._read_invalid()["_error"]["error"]
    self.assertIn("consumer_apply", err)
    self.assertIn("sometimes", err)

  def test_online_provider_capture_allows_unmounted_path(self):
    self.owner.cfg_sync_allow_online_provider_capture = True
    self._write_request({
      "archive_paths": ["/tmp/generated.txt"],
      "runtime": {"provider_capture": "online"},
    })

    result = self.sm.claim_request()

    self.assertIsNotNone(result)
    self.assertEqual(result.archive_paths, ["/tmp/generated.txt"])
    self.assertEqual(result.runtime.provider_capture, "online")

  def test_online_provider_capture_rejected_without_local_opt_in(self):
    self._write_request({
      "archive_paths": ["/tmp/generated.txt"],
      "runtime": {"provider_capture": "online"},
    })

    self.assertIsNone(self.sm.claim_request())

    err = self._read_invalid()["_error"]["error"]
    self.assertIn("ALLOW_ONLINE_PROVIDER_CAPTURE", err)

  def test_malformed_json(self):
    (self.vsd / "request.json").write_text("not-json{")
    self.assertIsNone(self.sm.claim_request())
    invalid = self._read_invalid()
    self.assertIsNotNone(invalid)
    self.assertIsNone(invalid["request"])
    self.assertEqual(invalid["_error"]["stage"], "validation")
    self.assertIn("malformed JSON", invalid["_error"]["error"])
    self.assertEqual(invalid["_error"]["raw_body"], "not-json{")
    response = self._read_response()
    self.assertEqual(response["status"], "error")
    self.assertEqual(response["stage"], "validation")
    self.assertFalse((self.vsd / "request.json.processing").exists())

  def test_request_symlink_rejected_without_leaking_target_body(self):
    secret = self.tmpdir / "host-secret.txt"
    secret.write_text("not-json-secret-token")
    os.symlink(str(secret), str(self.vsd / "request.json"))

    self.assertIsNone(self.sm.claim_request())

    invalid = self._read_invalid()
    self.assertIsNotNone(invalid)
    self.assertIsNone(invalid["request"])
    self.assertEqual(invalid["_error"]["stage"], "validation")
    self.assertIn("symlink control file", invalid["_error"]["error"])
    self.assertNotIn("raw_body", invalid["_error"])
    self.assertNotIn("not-json-secret-token", json.dumps(invalid))
    self.assertFalse((self.vsd / "request.json.processing").exists())

  def test_not_an_object(self):
    self._write_request(["just", "a", "list"])
    self.assertIsNone(self.sm.claim_request())
    self.assertEqual(self._read_invalid()["_error"]["error"],
                     "request.json must be a JSON object")

  def test_missing_archive_paths(self):
    self._write_request({"metadata": {}})
    self.assertIsNone(self.sm.claim_request())
    self.assertIn("archive_paths must be a non-empty list",
                  self._read_invalid()["_error"]["error"])

  def test_empty_archive_paths(self):
    self._write_request({"archive_paths": []})
    self.assertIsNone(self.sm.claim_request())
    self.assertIn("archive_paths must be a non-empty list",
                  self._read_invalid()["_error"]["error"])

  def test_metadata_must_be_object(self):
    self._write_request({"archive_paths": ["/app/data/"], "metadata": "nope"})
    self.assertIsNone(self.sm.claim_request())
    self.assertIn("metadata must be a JSON object",
                  self._read_invalid()["_error"]["error"])

  def test_path_traversal_rejected(self):
    self._write_request({"archive_paths": ["/app/../../etc/passwd"]})
    self.assertIsNone(self.sm.claim_request())
    invalid = self._read_invalid()
    self.assertEqual(invalid["_error"]["stage"], "validation")
    self.assertIn("..", invalid["_error"]["error"])
    self.assertEqual(invalid["request"]["archive_paths"], ["/app/../../etc/passwd"])

  def test_unmounted_path_rejected(self):
    self._write_request({"archive_paths": ["/nope/"]})
    self.assertIsNone(self.sm.claim_request())
    self.assertIn("no mounted volume covers",
                  self._read_invalid()["_error"]["error"])

  def test_anonymous_mount_rejected(self):
    """The fixture's ``/app/legacy`` mount is bound at ``tmpdir/tmpfs_legacy``
    (outside both allow-listed roots), standing in for an anonymous Docker
    mount or ephemeral fs. claim_request must surface a clear error so the
    app sees ``request.json.invalid`` instead of a silent stall.
    """
    self._write_request({"archive_paths": ["/app/legacy/x"]})
    self.assertIsNone(self.sm.claim_request())
    self.assertIn("non-volume-backed mount",
                  self._read_invalid()["_error"]["error"])

  def test_system_volume_rejected(self):
    self._write_request({"archive_paths": ["/r1en_system/x"]})
    self.assertIsNone(self.sm.claim_request())
    self.assertIn("anti-recursion",
                  self._read_invalid()["_error"]["error"])

  def test_invalid_response_carries_archive_paths(self):
    self._write_request({"archive_paths": ["/nope/"], "metadata": {"v": 1}})
    self.sm.claim_request()
    response = self._read_response()
    self.assertEqual(response["archive_paths"], ["/nope/"])

  def test_failure_clears_processing(self):
    self._write_request({"archive_paths": ["/nope/"]})
    self.sm.claim_request()
    self.assertFalse((self.vsd / "request.json.processing").exists())


# ---------------------------------------------------------------------------
# make_archive + extract_archive
# ---------------------------------------------------------------------------

class TestArchiveRoundtrip(unittest.TestCase):
  """Build a tar from a fake provider mount, extract it into a fake consumer
  mount with the same container path layout, and confirm bytes round-trip."""

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.provider = _make_owner(self.tmpdir / "provider")
    self.consumer = _make_owner(self.tmpdir / "consumer")
    self.sm_p = SyncManager(self.provider)
    self.sm_c = SyncManager(self.consumer)
    # Seed provider's /app/data with content
    self.appdata_p = self.provider._fixed_root / "appdata"
    (self.appdata_p / "foo.bin").write_bytes(b"hello world\x00\xff")
    (self.appdata_p / "subdir").mkdir()
    (self.appdata_p / "subdir" / "nested.txt").write_text("nested!")

  def tearDown(self):
    self._tmp.cleanup()

  def test_round_trip_directory(self):
    tar_path, size = self.sm_p.make_archive(["/app/data/"])
    self.assertTrue(os.path.isfile(tar_path))
    self.assertGreater(size, 0)

    extracted = self.sm_c.extract_archive(tar_path)
    self.assertTrue(any(e == "/app/data/" or e.startswith("/app/data/") for e in extracted))

    appdata_c = self.consumer._fixed_root / "appdata"
    self.assertEqual((appdata_c / "foo.bin").read_bytes(), b"hello world\x00\xff")
    self.assertEqual((appdata_c / "subdir" / "nested.txt").read_text(), "nested!")

  def test_round_trip_file_only(self):
    tar_path, _ = self.sm_p.make_archive(["/app/data/foo.bin"])
    self.sm_c.extract_archive(tar_path)
    self.assertEqual(
      (self.consumer._fixed_root / "appdata" / "foo.bin").read_bytes(),
      b"hello world\x00\xff",
    )

  def test_make_archive_rejects_non_existent_host_path(self):
    # Container path passes resolve_container_path but host file missing.
    with self.assertRaisesRegex(FileNotFoundError, "does not exist"):
      self.sm_p.make_archive(["/app/data/missing.bin"])

  def test_make_archive_propagates_validation(self):
    with self.assertRaisesRegex(ValueError, "no mounted volume covers"):
      self.sm_p.make_archive(["/nope/"])

  def test_make_archive_rejects_symlink_path(self):
    outside = self.tmpdir / "outside-provider"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (self.appdata_p / "escape").symlink_to(outside, target_is_directory=True)

    with self.assertRaisesRegex(ValueError, "symlink"):
      self.sm_p.make_archive(["/app/data/escape/secret.txt"])

  def test_make_archive_rejects_symlink_descendant(self):
    outside = self.tmpdir / "outside-provider-desc"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (self.appdata_p / "subdir" / "escape").symlink_to(
      outside, target_is_directory=True
    )

    with self.assertRaisesRegex(ValueError, "symlink"):
      self.sm_p.make_archive(["/app/data/"])

  # ---- legacy VOLUMES round-trip tests ------------------------------------
  #
  # Rule 3 admits legacy VOLUMES in addition to FIXED_SIZE_VOLUMES; these
  # tests prove the round-trip works regardless of which root backs each
  # side's mount. The fake legacy root lives under tmpdir, and we
  # monkeypatch ``manager_mod.CONTAINER_VOLUMES_PATH`` to point at it for
  # the duration of each test so Rule 3 accepts the synthetic location.
  #
  # The cross-type cases (legacy ↔ fixed-size) confirm the soft-migration
  # path: a snapshot can flow from a legacy provider into a fixed-size
  # consumer (and vice versa) because resolve_container_path keys off the
  # container path, not the host layout.

  def _patch_legacy_root(self):
    """Return a legacy root path under tmpdir and patch CONTAINER_VOLUMES_PATH
    to match. Caller must call self._unpatch_legacy_root() to restore."""
    import extensions.business.container_apps.sync.manager as manager_mod
    legacy = self.tmpdir / "edge_node" / "_local_cache" / "_data" / "container_volumes"
    legacy.mkdir(parents=True, exist_ok=True)
    self._manager_mod = manager_mod
    self._legacy_orig = manager_mod.CONTAINER_VOLUMES_PATH
    manager_mod.CONTAINER_VOLUMES_PATH = str(legacy)
    return legacy

  def _unpatch_legacy_root(self):
    self._manager_mod.CONTAINER_VOLUMES_PATH = self._legacy_orig

  def test_round_trip_legacy_volumes_only(self):
    """Provider + consumer both use legacy VOLUMES at the same container
    path. Snapshots round-trip byte-for-byte across the legacy root."""
    legacy = self._patch_legacy_root()
    try:
      prov_host = legacy / "provider_inst_appdata"
      cons_host = legacy / "consumer_inst_appdata"
      prov_host.mkdir()
      cons_host.mkdir()
      (prov_host / "weights.bin").write_bytes(b"legacy-only-payload")
      (prov_host / "sub").mkdir()
      (prov_host / "sub" / "n.txt").write_text("nested")
      self.provider.volumes = {str(prov_host): {"bind": "/app/data", "mode": "rw"}}
      self.consumer.volumes = {str(cons_host): {"bind": "/app/data", "mode": "rw"}}

      tar_path, _ = self.sm_p.make_archive(["/app/data/"])
      self.sm_c.extract_archive(tar_path)

      self.assertEqual((cons_host / "weights.bin").read_bytes(), b"legacy-only-payload")
      self.assertEqual((cons_host / "sub" / "n.txt").read_text(), "nested")
    finally:
      self._unpatch_legacy_root()

  def test_round_trip_legacy_to_fixed_size(self):
    """Provider legacy, consumer fixed-size at the same container path.
    Proves the soft-migration scenario: a new fixed-size node can absorb
    state from a legacy node without rebuilding the data on the operator
    side. Container path is the routing key — host layout differences
    are invisible to the archive."""
    legacy = self._patch_legacy_root()
    try:
      prov_host = legacy / "provider_inst_appdata"
      prov_host.mkdir()
      (prov_host / "weights.bin").write_bytes(b"legacy-to-fixed")
      self.provider.volumes = {str(prov_host): {"bind": "/app/data", "mode": "rw"}}
      # Consumer keeps its default fixed-size mount at /app/data
      # (set up by _make_owner — host root under fixed_volumes/mounts/).

      tar_path, _ = self.sm_p.make_archive(["/app/data/"])
      self.sm_c.extract_archive(tar_path)

      cons_host = self.consumer._fixed_root / "appdata"
      self.assertEqual((cons_host / "weights.bin").read_bytes(), b"legacy-to-fixed")
    finally:
      self._unpatch_legacy_root()

  def test_round_trip_fixed_size_to_legacy(self):
    """Symmetric of the above: provider fixed-size, consumer legacy. Same
    archive, opposite host-layout pairing. Result must be identical —
    container path drives the routing on both ends."""
    legacy = self._patch_legacy_root()
    try:
      cons_host = legacy / "consumer_inst_appdata"
      cons_host.mkdir()
      # Provider's default fixed-size mount at /app/data is already seeded
      # by setUp (foo.bin = b"hello world\x00\xff").
      self.consumer.volumes = {str(cons_host): {"bind": "/app/data", "mode": "rw"}}

      tar_path, _ = self.sm_p.make_archive(["/app/data/"])
      self.sm_c.extract_archive(tar_path)

      self.assertEqual((cons_host / "foo.bin").read_bytes(), b"hello world\x00\xff")
      self.assertEqual((cons_host / "subdir" / "nested.txt").read_text(), "nested!")
    finally:
      self._unpatch_legacy_root()

  def test_extract_aborts_on_member_with_no_consumer_mount(self):
    # Build a bespoke tar with a member at /app/missing/ that consumer
    # doesn't have a mount for.
    import tarfile as _tarfile
    bad_tar = self.tmpdir / "bad.tar.gz"
    src = self.tmpdir / "src"
    src.mkdir()
    (src / "x.bin").write_text("x")
    with _tarfile.open(str(bad_tar), "w:gz") as tar:
      tar.add(str(src / "x.bin"), arcname="/app/missing/x.bin")

    with self.assertRaisesRegex(ValueError, "no mounted volume covers"):
      self.sm_c.extract_archive(str(bad_tar))
    # No file was created
    self.assertFalse((self.consumer._fixed_root / "appdata" / "x.bin").exists())

  def test_extract_rejects_member_outside_manifest_archive_paths(self):
    bad_tar = self.tmpdir / "outside-manifest.tar.gz"
    src = self.tmpdir / "outside-manifest.txt"
    src.write_text("outside")
    with tarfile.open(str(bad_tar), "w:gz") as tar:
      tar.add(str(src), arcname="/app/data/other.txt")

    with self.assertRaisesRegex(ValueError, "outside manifest archive_paths"):
      self.sm_c.extract_archive(
        str(bad_tar), allowed_archive_paths=["/app/data/declared/"]
      )

    self.assertFalse((self.consumer._fixed_root / "appdata" / "other.txt").exists())

  def test_extract_skips_symlink_members(self):
    import tarfile as _tarfile
    sym_tar = self.tmpdir / "sym.tar.gz"
    src = self.tmpdir / "sym_src"
    src.mkdir()
    (src / "real.txt").write_text("real")
    link_path = src / "link"
    os.symlink("real.txt", str(link_path))
    with _tarfile.open(str(sym_tar), "w:gz") as tar:
      tar.add(str(src / "real.txt"), arcname="/app/data/real.txt")
      info = tar.gettarinfo(str(link_path), arcname="/app/data/link")
      tar.addfile(info)
    self.sm_c.extract_archive(str(sym_tar))
    self.assertEqual(
      (self.consumer._fixed_root / "appdata" / "real.txt").read_text(), "real"
    )
    self.assertFalse((self.consumer._fixed_root / "appdata" / "link").exists())

  def test_extract_rejects_member_through_symlink_directory(self):
    outside = self.tmpdir / "outside"
    outside.mkdir()
    symlink_dir = self.consumer._fixed_root / "appdata" / "escape"
    symlink_dir.symlink_to(outside, target_is_directory=True)

    bad_tar = self.tmpdir / "symlink-dir-escape.tar.gz"
    src = self.tmpdir / "escape-src.txt"
    src.write_text("escaped")
    with tarfile.open(str(bad_tar), "w:gz") as tar:
      tar.add(str(src), arcname="/app/data/escape/pwn.txt")

    with self.assertRaisesRegex(ValueError, "escapes volume root"):
      self.sm_c.extract_archive(str(bad_tar))

    self.assertFalse((outside / "pwn.txt").exists())

  def test_extract_rejects_member_over_symlink_file(self):
    outside = self.tmpdir / "outside-file.txt"
    outside.write_text("outside")
    symlink_file = self.consumer._fixed_root / "appdata" / "link.txt"
    symlink_file.symlink_to(outside)

    bad_tar = self.tmpdir / "symlink-file-escape.tar.gz"
    src = self.tmpdir / "replacement.txt"
    src.write_text("replacement")
    with tarfile.open(str(bad_tar), "w:gz") as tar:
      tar.add(str(src), arcname="/app/data/link.txt")

    with self.assertRaisesRegex(ValueError, "escapes volume root"):
      self.sm_c.extract_archive(str(bad_tar))

    self.assertTrue(symlink_file.is_symlink())
    self.assertEqual(outside.read_text(), "outside")

  def test_extract_strips_special_mode_bits(self):
    mode_tar = self.tmpdir / "special-modes.tar.gz"
    with tarfile.open(str(mode_tar), "w:gz") as tar:
      dir_info = tarfile.TarInfo(name="/app/data/special")
      dir_info.type = tarfile.DIRTYPE
      dir_info.mode = 0o7777
      tar.addfile(dir_info)

      content = b"payload"
      file_info = tarfile.TarInfo(name="/app/data/special/run.sh")
      file_info.size = len(content)
      file_info.mode = 0o6755
      tar.addfile(file_info, io.BytesIO(content))

    self.sm_c.extract_archive(str(mode_tar))

    target_dir = self.consumer._fixed_root / "appdata" / "special"
    target_file = target_dir / "run.sh"
    self.assertEqual(target_file.read_bytes(), b"payload")
    self.assertEqual(os.stat(target_dir).st_mode & 0o7000, 0)
    self.assertEqual(os.stat(target_file).st_mode & 0o7000, 0)

  def test_extract_chowns_restored_entries_to_volume_owner(self):
    owner_tar = self.tmpdir / "owner.tar.gz"
    with tarfile.open(str(owner_tar), "w:gz") as tar:
      dir_info = tarfile.TarInfo(name="/app/data/owned")
      dir_info.type = tarfile.DIRTYPE
      dir_info.mode = 0o755
      tar.addfile(dir_info)

      content = b"payload"
      file_info = tarfile.TarInfo(name="/app/data/owned/file.txt")
      file_info.size = len(content)
      file_info.mode = 0o644
      tar.addfile(file_info, io.BytesIO(content))

    calls = []

    def _fake_chown(path, uid, gid):
      calls.append((os.path.basename(path), uid, gid))

    with patch.object(self.sm_c, "_volume_owner", return_value=(1234, 2345)), patch(
      "extensions.business.container_apps.sync.manager.os.chown",
      side_effect=_fake_chown,
    ):
      self.sm_c.extract_archive(str(owner_tar))

    self.assertIn(("owned", 1234, 2345), calls)
    self.assertTrue(any(call[1:] == (1234, 2345) for call in calls))
    self.assertEqual(
      (self.consumer._fixed_root / "appdata" / "owned" / "file.txt").read_bytes(),
      b"payload",
    )


# ---------------------------------------------------------------------------
# publish_snapshot
# ---------------------------------------------------------------------------

class TestPublishSnapshot(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.owner = _make_owner(self.tmpdir)
    self.sm = SyncManager(self.owner)
    self.vsd = volume_sync_dir(self.owner)
    self.vsd.mkdir(parents=True, exist_ok=True)
    # Seed the data volume so make_archive can find content
    appdata = self.owner._fixed_root / "appdata"
    (appdata / "weights.bin").write_bytes(b"weights-content")
    # Simulate having claimed a request — leave a .processing file so
    # publish_snapshot's clean-up paths can be exercised.
    (self.vsd / SYNC_PROCESSING_FILE).write_text(
      json.dumps({"archive_paths": ["/app/data/"], "metadata": {}})
    )

  def tearDown(self):
    self._tmp.cleanup()

  def test_happy_path_writes_response_history_and_chainstore(self):
    ok = self.sm.publish_snapshot(["/app/data/"], {"epoch": 1})
    self.assertTrue(ok)

    # Response.json
    resp = json.loads((self.vsd / "response.json").read_text())
    self.assertEqual(resp["status"], "ok")
    self.assertTrue(resp["cid"].startswith("QmFAKE"))
    self.assertGreater(resp["archive_size_bytes"], 0)
    self.assertTrue(resp["chainstore_ack"])

    # ChainStore record
    self.assertEqual(len(self.owner._cs.hset_calls), 1)
    hkey, key, value = self.owner._cs.hset_calls[0]
    self.assertEqual(hkey, "CHAINSTORE_SYNC")
    self.assertEqual(key, "11111111-1111-1111-1111-111111111111")
    self.assertEqual(value["cid"], resp["cid"])
    self.assertEqual(value["manifest"]["archive_paths"], ["/app/data/"])
    self.assertEqual(value["manifest"]["schema_version"], 1)
    self.assertEqual(value["manifest"]["archive_format"], "tar.gz")
    self.assertEqual(value["manifest"]["runtime"]["provider_capture"], "offline")
    self.assertEqual(value["manifest"]["runtime"]["consumer_apply"], "offline_restart")
    self.assertEqual(value["metadata"], {"epoch": 1})

    # History
    sent_dir = history_sent_dir(self.owner)
    files = list(sent_dir.glob("*.json"))
    self.assertEqual(len(files), 1)
    entry = json.loads(files[0].read_text())
    self.assertEqual(entry["cid"], resp["cid"])
    self.assertEqual(entry["chainstore_ack"], True)
    self.assertEqual(entry["request"]["archive_paths"], ["/app/data/"])
    self.assertIsNone(entry["deletion"]["deleted_at"])

    # .processing cleaned up
    self.assertFalse((self.vsd / "request.json.processing").exists())
    # No .invalid because success
    self.assertFalse((self.vsd / "request.json.invalid").exists())

  def test_online_provider_capture_uses_docker_archive_for_unmounted_path(self):
    self.owner.cfg_sync_allow_online_provider_capture = True
    self.owner.container = _FakeDockerArchiveContainer({
      "/tmp/generated.txt": _tar_bytes("generated.txt", b"from-container"),
    })
    request = SyncRequest(
      archive_paths=["/tmp/generated.txt"],
      metadata={"epoch": 2},
      runtime=SyncRuntimePolicy(provider_capture=PROVIDER_CAPTURE_ONLINE),
    )

    ok = self.sm.publish_snapshot(request)

    self.assertTrue(ok)
    self.assertEqual(self.owner.container.get_archive_calls, ["/tmp/generated.txt"])
    record = self.owner._cs.hset_calls[0][2]
    self.assertEqual(record["manifest"]["archive_paths"], ["/tmp/generated.txt"])
    self.assertEqual(record["manifest"]["runtime"]["provider_capture"], "online")

    stored_tar = self.owner._r1fs.added[record["cid"]]
    tar_path = self.tmpdir / "online.tar.gz"
    tar_path.write_bytes(stored_tar)
    with tarfile.open(tar_path, "r:gz") as tar:
      member = tar.getmember("tmp/generated.txt")
      self.assertEqual(tar.extractfile(member).read(), b"from-container")

  def test_clears_existing_invalid_on_success(self):
    (self.vsd / "request.json.invalid").write_text('{"old": true}')
    self.sm.publish_snapshot(["/app/data/"], {})
    self.assertFalse((self.vsd / "request.json.invalid").exists())

  def test_archive_build_failure(self):
    self.owner._fixed_root.joinpath("appdata", "weights.bin").unlink()
    ok = self.sm.publish_snapshot(["/app/data/missing.bin"], {})
    self.assertFalse(ok)
    invalid = json.loads((self.vsd / "request.json.invalid").read_text())
    self.assertEqual(invalid["_error"]["stage"], "archive_build")
    resp = json.loads((self.vsd / "response.json").read_text())
    self.assertEqual(resp["status"], "error")
    self.assertEqual(resp["stage"], "archive_build")
    # No history entry written
    self.assertEqual(len(list(history_sent_dir(self.owner).glob("*.json"))), 0)

  def test_r1fs_upload_failure(self):
    self.owner._r1fs.add_should_raise = RuntimeError("ipfs offline")
    ok = self.sm.publish_snapshot(["/app/data/"], {})
    self.assertFalse(ok)
    invalid = json.loads((self.vsd / "request.json.invalid").read_text())
    self.assertEqual(invalid["_error"]["stage"], "r1fs_upload")
    self.assertIn("ipfs offline", invalid["_error"]["error"])
    self.assertEqual(self.owner._cs.hset_calls, [])

  def test_chainstore_publish_failure(self):
    self.owner._cs.hset_should_raise = RuntimeError("peers unreachable")
    ok = self.sm.publish_snapshot(["/app/data/"], {})
    self.assertFalse(ok)
    invalid = json.loads((self.vsd / "request.json.invalid").read_text())
    self.assertEqual(invalid["_error"]["stage"], "chainstore_publish")
    # No history because we failed before append
    self.assertEqual(len(list(history_sent_dir(self.owner).glob("*.json"))), 0)
    # CID landed in r1fs but was cleaned up before returning failure.
    self.assertEqual(len(self.owner._r1fs.added), 0)
    self.assertEqual(len(self.owner._r1fs.deleted), 1)

  def test_chainstore_no_ack_fails_and_cleans_uploaded_cid(self):
    self.owner._cs.hset_returns = False

    ok = self.sm.publish_snapshot(["/app/data/"], {})

    self.assertFalse(ok)
    invalid = json.loads((self.vsd / "request.json.invalid").read_text())
    self.assertEqual(invalid["_error"]["stage"], "chainstore_publish")
    self.assertIn("ack", invalid["_error"]["error"])
    self.assertEqual(len(list(history_sent_dir(self.owner).glob("*.json"))), 0)
    self.assertEqual(self.owner._r1fs.added, {})
    self.assertEqual(len(self.owner._r1fs.deleted), 1)

  def test_two_snapshots_retire_first_cid(self):
    self.sm.publish_snapshot(["/app/data/"], {"epoch": 1})
    # Update content for the second snapshot
    (self.owner._fixed_root / "appdata" / "weights.bin").write_bytes(b"v2")
    # Re-create .processing because publish_snapshot deleted it
    (self.vsd / SYNC_PROCESSING_FILE).write_text("{}")
    self.sm.publish_snapshot(["/app/data/"], {"epoch": 2})

    files = sorted(history_sent_dir(self.owner).glob("*.json"))
    self.assertEqual(len(files), 2)
    older = json.loads(files[0].read_text())
    newer = json.loads(files[1].read_text())

    self.assertTrue(older["deletion"]["deletion_succeeded"])
    self.assertIsNotNone(older["deletion"]["deleted_at"])
    self.assertIsNone(older["deletion"]["error"]) if older["deletion"].get("error") else None

    self.assertIsNone(newer["deletion"]["deleted_at"])

    deleted_cids = [d[0] for d in self.owner._r1fs.deleted]
    self.assertEqual(deleted_cids, [older["cid"]])

  def test_retire_records_failure(self):
    self.sm.publish_snapshot(["/app/data/"], {"epoch": 1})
    (self.owner._fixed_root / "appdata" / "weights.bin").write_bytes(b"v2")
    (self.vsd / SYNC_PROCESSING_FILE).write_text("{}")
    self.owner._r1fs.delete_should_raise = RuntimeError("daemon paused")

    self.sm.publish_snapshot(["/app/data/"], {"epoch": 2})

    files = sorted(history_sent_dir(self.owner).glob("*.json"))
    older = json.loads(files[0].read_text())
    self.assertIsNone(older["deletion"]["deleted_at"])
    self.assertFalse(older["deletion"]["deletion_succeeded"])
    self.assertIn("daemon paused", older["deletion"]["deletion_error"])

  def test_retire_retries_after_failure(self):
    self.sm.publish_snapshot(["/app/data/"], {"epoch": 1})
    (self.owner._fixed_root / "appdata" / "weights.bin").write_bytes(b"v2")
    (self.vsd / SYNC_PROCESSING_FILE).write_text("{}")
    self.owner._r1fs.delete_should_raise = RuntimeError("daemon paused")

    self.sm.publish_snapshot(["/app/data/"], {"epoch": 2})
    self.owner._r1fs.delete_should_raise = None
    self.sm._retire_previous_cid(history_sent_dir(self.owner))

    files = sorted(history_sent_dir(self.owner).glob("*.json"))
    older = json.loads(files[0].read_text())
    self.assertIsNotNone(older["deletion"]["deleted_at"])
    self.assertTrue(older["deletion"]["deletion_succeeded"])

  def test_retire_uses_mtime_not_version(self):
    """A higher-version entry that was written BEFORE a lower-version entry
    must be retired when the lower-version one is "latest". Mirrors the
    contract from ``_latest_in``: the answer to "what did we just do?" is
    insert-order (mtime), not whatever ``version`` happens to be in the
    entry. Without this guarantee a clock-skewed provider or multi-provider
    sync set can cause the just-published CID to be retired on the next
    publish.
    """
    sent_dir = history_sent_dir(self.owner)
    sent_dir.mkdir(parents=True, exist_ok=True)

    # Older-by-mtime but higher version (would sort last by filename).
    # Use the canonical filename helper so update_history_deletion can find
    # the file via its <version>__<short_cid>.json convention.
    older_path = sent_dir / self.sm._history_filename(100, "QmCID_A")
    older_path.write_text(json.dumps({
      "cid": "QmCID_A", "version": 100,
      "deletion": {"deleted_at": None, "deletion_succeeded": None, "deletion_error": None},
    }))
    os.utime(older_path, (1000, 1000))

    # Newer-by-mtime but lower version (would sort first by filename)
    newer_path = sent_dir / self.sm._history_filename(50, "QmCID_B")
    newer_path.write_text(json.dumps({
      "cid": "QmCID_B", "version": 50,
      "deletion": {"deleted_at": None, "deletion_succeeded": None, "deletion_error": None},
    }))
    os.utime(newer_path, (2000, 2000))

    self.sm._retire_previous_cid(sent_dir)

    older_after = json.loads(older_path.read_text())
    newer_after = json.loads(newer_path.read_text())

    # The just-written (newer-by-mtime) entry must be left alone.
    self.assertIsNone(newer_after["deletion"]["deleted_at"])
    # The older-by-mtime entry should be retired, even though it has the
    # higher version number.
    self.assertIsNotNone(older_after["deletion"]["deleted_at"])
    self.assertTrue(older_after["deletion"]["deletion_succeeded"])

    deleted_cids = [d[0] for d in self.owner._r1fs.deleted]
    self.assertEqual(deleted_cids, ["QmCID_A"])

  def test_archive_tmp_cleaned_up_on_success(self):
    self.sm.publish_snapshot(["/app/data/"], {})
    leftovers = list(self.owner._output_folder.glob("sync_archive_*.tar.gz"))
    self.assertEqual(leftovers, [])

  def test_archive_tmp_cleaned_up_on_failure(self):
    self.owner._cs.hset_should_raise = RuntimeError("boom")
    self.sm.publish_snapshot(["/app/data/"], {})
    leftovers = list(self.owner._output_folder.glob("sync_archive_*.tar.gz"))
    self.assertEqual(leftovers, [])


# ---------------------------------------------------------------------------
# fetch_latest + validate_manifest + apply_snapshot
# ---------------------------------------------------------------------------

class TestConsumerFlow(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    # Build provider AND consumer owners that share an r1fs+chainstore so
    # we can do a true end-to-end publish→apply round-trip.
    shared_r1fs = _FakeR1FS()
    shared_cs = _FakeChainStore()

    self.provider = _make_owner(self.tmpdir / "p")
    self.consumer = _make_owner(self.tmpdir / "c")
    for o in (self.provider, self.consumer):
      o.r1fs = shared_r1fs
      o._r1fs = shared_r1fs
      o.chainstore_hset = shared_cs.hset
      o.chainstore_hget = shared_cs.hget
      o.chainstore_hsync = shared_cs.hsync
      o._cs = shared_cs
    self.consumer.cfg_sync_type = "consumer"

    self.sm_p = SyncManager(self.provider)
    self.sm_c = SyncManager(self.consumer)

    # Provision provider's volume-sync subdir + seed data
    volume_sync_dir(self.provider).mkdir(parents=True, exist_ok=True)
    volume_sync_dir(self.consumer).mkdir(parents=True, exist_ok=True)
    (self.provider._fixed_root / "appdata" / "weights.bin").write_bytes(b"hello")

  def tearDown(self):
    self._tmp.cleanup()

  # ----- validate_manifest --------------------------------------------------

  def _ok_manifest(self, **overrides):
    """Return a minimally-valid manifest dict. Tests override fields they
    care about; the rest stay sane defaults so we don't have to copy the
    schema boilerplate everywhere."""
    manifest = {
      "schema_version": 1,
      "archive_format": "tar.gz",
      "encryption": "r1fs-default",
      "archive_paths": ["/app/data/"],
    }
    manifest.update(overrides)
    return {"manifest": manifest}

  def test_validate_manifest_empty_when_aligned(self):
    self.assertEqual(self.sm_c.validate_manifest(self._ok_manifest()), [])

  def test_validate_manifest_returns_missing_paths(self):
    record = self._ok_manifest(archive_paths=["/app/data/", "/somewhere/else/"])
    reasons = self.sm_c.validate_manifest(record)
    self.assertEqual(len(reasons), 1)
    self.assertIn("/somewhere/else/", reasons[0])
    self.assertIn("unmapped archive_paths", reasons[0])

  def test_validate_manifest_rejects_unsupported_schema_version(self):
    """A manifest from a future CAR that bumped MANIFEST_SCHEMA_VERSION must
    be refused rather than silently applied — schema bumps signal breaking
    format changes the current consumer can't safely interpret. Codex
    review finding 4 on PR #399."""
    record = self._ok_manifest(schema_version=999)
    reasons = self.sm_c.validate_manifest(record)
    self.assertEqual(len(reasons), 1)
    self.assertIn("schema_version", reasons[0])
    self.assertIn("999", reasons[0])

  def test_validate_manifest_rejects_missing_schema_version(self):
    record = {"manifest": {"archive_format": "tar.gz", "archive_paths": ["/app/data/"]}}
    reasons = self.sm_c.validate_manifest(record)
    self.assertTrue(any("schema_version" in r for r in reasons))

  def test_validate_manifest_rejects_non_int_schema_version(self):
    record = self._ok_manifest(schema_version="1")
    reasons = self.sm_c.validate_manifest(record)
    self.assertTrue(any("schema_version" in r for r in reasons))

  def test_validate_manifest_rejects_unsupported_archive_format(self):
    record = self._ok_manifest(archive_format="zip")
    reasons = self.sm_c.validate_manifest(record)
    self.assertEqual(len(reasons), 1)
    self.assertIn("archive_format", reasons[0])
    self.assertIn("zip", reasons[0])
    self.assertIn("tar.gz", reasons[0])

  def test_validate_manifest_rejects_unsupported_encryption(self):
    record = self._ok_manifest(encryption="plaintext")
    reasons = self.sm_c.validate_manifest(record)
    self.assertEqual(len(reasons), 1)
    self.assertIn("encryption", reasons[0])
    self.assertIn("plaintext", reasons[0])
    self.assertIn("r1fs-default", reasons[0])

  def test_validate_manifest_collects_multiple_violations(self):
    """Schema + format + path violations all surface in one pass so the
    operator sees the full picture in a single log line."""
    record = self._ok_manifest(
      schema_version=999, archive_format="zip",
      archive_paths=["/app/data/", "/nope/"],
    )
    reasons = self.sm_c.validate_manifest(record)
    self.assertEqual(len(reasons), 3)
    joined = "; ".join(reasons)
    self.assertIn("schema_version", joined)
    self.assertIn("archive_format", joined)
    self.assertIn("/nope/", joined)

  def test_validate_manifest_handles_no_manifest(self):
    # An empty record / empty manifest is non-conformant (missing required
    # schema_version + archive_format), so it must be rejected.
    self.assertNotEqual(self.sm_c.validate_manifest({}), [])
    self.assertNotEqual(self.sm_c.validate_manifest({"manifest": {}}), [])

  def test_validate_manifest_rejects_non_dict_manifest(self):
    reasons = self.sm_c.validate_manifest({"manifest": "not-an-object"})

    self.assertEqual(reasons, ["manifest must be a JSON object"])

  def test_validate_manifest_rejects_missing_archive_paths(self):
    record = self._ok_manifest()
    del record["manifest"]["archive_paths"]
    reasons = self.sm_c.validate_manifest(record)
    self.assertTrue(any("archive_paths" in r for r in reasons))

  def test_validate_manifest_rejects_empty_archive_paths(self):
    reasons = self.sm_c.validate_manifest(self._ok_manifest(archive_paths=[]))
    self.assertTrue(any("non-empty list" in r for r in reasons))

  def test_validate_manifest_rejects_non_list_archive_paths(self):
    reasons = self.sm_c.validate_manifest(self._ok_manifest(archive_paths="/app/data/"))
    self.assertTrue(any("non-empty list" in r for r in reasons))

  def test_validate_manifest_rejects_non_string_archive_path_entries(self):
    reasons = self.sm_c.validate_manifest(self._ok_manifest(archive_paths=["/app/data/", 7]))
    self.assertTrue(any("invalid archive_paths" in r for r in reasons))

  def test_validate_manifest_rejects_non_dict(self):
    self.assertEqual(self.sm_c.validate_manifest(None), ["manifest record is not a dict"])
    self.assertEqual(self.sm_c.validate_manifest("string"), ["manifest record is not a dict"])

  def test_validate_record_rejects_missing_envelope_fields(self):
    reasons = self.sm_c.validate_record_for_apply({
      "cid": "",
      "version": "1",
      "manifest": self._ok_manifest()["manifest"],
    })

    joined = "; ".join(reasons)
    self.assertIn("cid", joined)
    self.assertIn("version", joined)

  # ----- fetch_latest -------------------------------------------------------

  def test_fetch_latest_empty_returns_none(self):
    self.assertIsNone(self.sm_c.fetch_latest())
    # hsync was still called
    self.assertEqual(self.consumer._cs.hsync_calls, ["CHAINSTORE_SYNC"])

  def test_fetch_latest_after_publish_returns_record(self):
    (self.provider.__dict__["_fixed_root"] / "appdata" / "weights.bin").write_bytes(b"x")
    (volume_sync_dir(self.provider) / SYNC_PROCESSING_FILE).write_text("{}")
    self.sm_p.publish_snapshot(["/app/data/"], {"epoch": 5})
    record = self.sm_c.fetch_latest()
    self.assertIsNotNone(record)
    self.assertEqual(record["metadata"], {"epoch": 5})

  def test_fetch_latest_no_sync_key_returns_none(self):
    self.consumer.cfg_sync_key = None
    self.assertIsNone(self.sm_c.fetch_latest())

  def test_hsync_gated_by_interval_skips_within_window(self):
    """The expensive chainstore_hsync is rate-limited; a second fetch_latest
    inside the configured HSYNC_POLL_INTERVAL window only does the cheap
    local hget, leaving hsync_calls at one entry."""
    self.consumer.cfg_sync_hsync_poll_interval = 60.0
    self.sm_c.fetch_latest()
    self.sm_c.fetch_latest()  # ~1s later (mock clock increments per time() call)
    self.assertEqual(self.consumer._cs.hsync_calls, ["CHAINSTORE_SYNC"])

  def test_hsync_fires_again_after_interval_elapses(self):
    """Once HSYNC_POLL_INTERVAL has elapsed since the last hsync, the next
    fetch_latest does a fresh network round-trip."""
    self.consumer.cfg_sync_hsync_poll_interval = 60.0
    self.sm_c.fetch_latest()
    # Back-date the last-hsync stamp so the next call falls outside the
    # window without having to actually wait 60s.
    self.sm_c._last_hsync = self.sm_c._last_hsync - 70.0
    self.sm_c.fetch_latest()
    self.assertEqual(self.consumer._cs.hsync_calls, ["CHAINSTORE_SYNC", "CHAINSTORE_SYNC"])

  def test_hsync_failure_retries_before_full_success_interval(self):
    """A timing-out / failing hsync should not suppress retries for the full
    success interval. It still avoids retrying on the immediate next tick, but
    becomes eligible again after the shorter failure retry window."""
    self.consumer.cfg_sync_hsync_poll_interval = 60.0
    self.consumer._cs.hsync_should_raise = RuntimeError("offline")
    self.sm_c.fetch_latest()           # hsync raises (caught), retry after 30s
    self.sm_c.fetch_latest()           # immediate next tick -> still skipped
    self.assertEqual(self.consumer._cs.hsync_calls, ["CHAINSTORE_SYNC"])
    self.sm_c._last_hsync = self.sm_c._last_hsync - 31.0
    self.sm_c.fetch_latest()
    self.assertEqual(self.consumer._cs.hsync_calls, ["CHAINSTORE_SYNC", "CHAINSTORE_SYNC"])

  # ----- apply_snapshot -----------------------------------------------------

  def test_apply_round_trip(self):
    (volume_sync_dir(self.provider) / SYNC_PROCESSING_FILE).write_text("{}")
    self.sm_p.publish_snapshot(["/app/data/"], {"epoch": 9})

    record = self.sm_c.fetch_latest()
    ok = self.sm_c.apply_snapshot(record)
    self.assertTrue(ok)

    # File extracted
    target = self.consumer._fixed_root / "appdata" / "weights.bin"
    self.assertEqual(target.read_bytes(), b"hello")

    # last_apply.json written
    la = json.loads((volume_sync_dir(self.consumer) / "last_apply.json").read_text())
    self.assertEqual(la["cid"], record["cid"])
    self.assertEqual(la["version"], record["version"])
    self.assertIn("applied_timestamp", la)

    # History entry
    files = list(history_received_dir(self.consumer).glob("*.json"))
    self.assertEqual(len(files), 1)
    entry = json.loads(files[0].read_text())
    self.assertEqual(entry["cid"], record["cid"])
    # tarfile strips trailing slashes on directory members; the consumer
    # re-prepends the leading slash on extract, so directory entries land
    # without their trailing slash.
    self.assertEqual(entry["extracted_paths"], ["/app/data", "/app/data/weights.bin"])
    self.assertIsNone(entry["deletion"]["deleted_at"])

  def test_apply_skips_when_misaligned(self):
    # Provider includes a path consumer doesn't have a mount for.
    # We can't legitimately publish such a record (provider would also reject
    # it), so build it manually and stuff into chainstore.
    self.consumer._cs.store[("CHAINSTORE_SYNC", self.consumer.cfg_sync_key)] = {
      "cid": "QmFAKE99999999",
      "version": 9999999999,
      "timestamp": 1234.0,
      "node_id": "ee_someone",
      "metadata": {},
      "manifest": {
        "schema_version": 1,
        "archive_paths": ["/app/data/", "/foo/bar/"],
        "archive_format": "tar.gz",
        "encryption": "r1fs-default",
        "archive_size_bytes": 100,
      },
    }
    record = self.sm_c.fetch_latest()
    ok = self.sm_c.apply_snapshot(record)
    self.assertFalse(ok)
    # No last_apply, no history advance
    self.assertFalse((volume_sync_dir(self.consumer) / "last_apply.json").exists())
    self.assertEqual(len(list(history_received_dir(self.consumer).glob("*.json"))), 0)
    # Useful error message — should name the path that couldn't be mapped.
    self.assertTrue(any("unmapped archive_paths" in m for m in self.consumer._msgs))
    self.assertTrue(any("/foo/bar/" in m for m in self.consumer._msgs))

  def test_apply_rejects_non_dict_manifest_without_raising(self):
    record = {
      "cid": "QmFAKE_BAD_MANIFEST",
      "version": 123,
      "timestamp": 1234.0,
      "node_id": "ee_someone",
      "metadata": {},
      "manifest": "not-an-object",
    }

    ok = self.sm_c.apply_snapshot(record)

    self.assertFalse(ok)
    self.assertFalse((volume_sync_dir(self.consumer) / "last_apply.json").exists())
    self.assertTrue(any("manifest must be a JSON object" in m for m in self.consumer._msgs))

  def test_apply_rejects_tar_member_outside_manifest_archive_paths(self):
    cid = "QmOUTSIDE_MANIFEST"
    bad_tar = self.tmpdir / "outside-manifest-apply.tar.gz"
    src = self.tmpdir / "outside-apply.txt"
    src.write_text("outside")
    with tarfile.open(str(bad_tar), "w:gz") as tar:
      tar.add(str(src), arcname="/app/data/other.txt")
    self.consumer._r1fs.added[cid] = bad_tar.read_bytes()

    record = {
      "cid": cid,
      "version": 123,
      "timestamp": 1.0,
      "node_id": "ee_provider",
      "metadata": {},
      "manifest": {
        "schema_version": 1,
        "archive_paths": ["/app/data/declared/"],
        "archive_format": "tar.gz",
        "encryption": "r1fs-default",
      },
    }

    ok = self.sm_c.apply_snapshot(record)

    self.assertFalse(ok)
    self.assertFalse((volume_sync_dir(self.consumer) / "last_apply.json").exists())
    self.assertFalse((self.consumer._fixed_root / "appdata" / "other.txt").exists())
    self.assertTrue(
      any("outside manifest archive_paths" in m for m in self.consumer._msgs)
    )

  def test_apply_aborts_on_r1fs_get_failure(self):
    (volume_sync_dir(self.provider) / SYNC_PROCESSING_FILE).write_text("{}")
    self.sm_p.publish_snapshot(["/app/data/"], {})
    record = self.sm_c.fetch_latest()
    self.consumer._r1fs.get_should_raise = RuntimeError("network down")
    ok = self.sm_c.apply_snapshot(record)
    self.assertFalse(ok)
    self.assertFalse((volume_sync_dir(self.consumer) / "last_apply.json").exists())

  def test_apply_rejects_symlink_escape_without_advancing_state(self):
    outside = self.tmpdir / "outside"
    outside.mkdir()
    symlink_dir = self.consumer._fixed_root / "appdata" / "escape"
    symlink_dir.symlink_to(outside, target_is_directory=True)

    bad_tar = self.tmpdir / "bad-apply.tar.gz"
    src = self.tmpdir / "bad-apply-src.txt"
    src.write_text("escaped")
    with tarfile.open(str(bad_tar), "w:gz") as tar:
      tar.add(str(src), arcname="/app/data/escape/pwn.txt")

    cid = "QmBADSYMLINKESCAPE"
    self.consumer._r1fs.added[cid] = bad_tar.read_bytes()
    record = {
      "cid": cid,
      "version": 123,
      "timestamp": 456.0,
      "node_id": "ee_bad",
      "metadata": {},
      "manifest": {
        "schema_version": 1,
        "archive_paths": ["/app/data/"],
        "archive_format": "tar.gz",
        "encryption": "r1fs-default",
        "archive_size_bytes": bad_tar.stat().st_size,
      },
    }

    ok = self.sm_c.apply_snapshot(record)

    self.assertFalse(ok)
    self.assertFalse((outside / "pwn.txt").exists())
    self.assertFalse((volume_sync_dir(self.consumer) / "last_apply.json").exists())
    self.assertEqual(len(list(history_received_dir(self.consumer).glob("*.json"))), 0)

  def test_apply_two_snapshots_retires_first(self):
    # First publish + apply
    (volume_sync_dir(self.provider) / SYNC_PROCESSING_FILE).write_text("{}")
    self.sm_p.publish_snapshot(["/app/data/"], {"v": 1})
    rec1 = self.sm_c.fetch_latest()
    self.sm_c.apply_snapshot(rec1)
    # Second publish + apply
    (self.provider._fixed_root / "appdata" / "weights.bin").write_bytes(b"v2")
    (volume_sync_dir(self.provider) / SYNC_PROCESSING_FILE).write_text("{}")
    self.sm_p.publish_snapshot(["/app/data/"], {"v": 2})
    rec2 = self.sm_c.fetch_latest()
    self.sm_c.apply_snapshot(rec2)

    files = sorted(history_received_dir(self.consumer).glob("*.json"))
    self.assertEqual(len(files), 2)
    older = json.loads(files[0].read_text())
    newer = json.loads(files[1].read_text())
    self.assertTrue(older["deletion"]["deletion_succeeded"])
    self.assertIsNone(newer["deletion"]["deleted_at"])
    # Consumer-side delete used cleanup_local_files=True
    deleted = self.consumer._r1fs.deleted
    self.assertTrue(any(cid == older["cid"] and cleanup
                        for (cid, _, cleanup) in deleted))
    self.assertTrue(any(cid == older["cid"] and not unpin_remote
                        for (cid, unpin_remote, _) in deleted))


if __name__ == "__main__":
  unittest.main()
