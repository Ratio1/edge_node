"""Unit tests for sync_manager.SyncManager pure helpers.

Covers the path-validation chokepoint (resolve_container_path), atomic JSON
writes, and history append/latest/update operations using a temporary
plugin-data directory and a stub owner that mimics the BasePlugin surface
the manager depends on.
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

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

  def test_rejects_non_fixed_size(self):
    with self.assertRaisesRegex(ValueError, "non-fixed-size mount"):
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
    archive_paths, metadata = result
    self.assertEqual(archive_paths, ["/app/data/"])
    self.assertEqual(metadata, {"k": 1})
    # request.json gone, .processing present, no .invalid
    self.assertFalse((self.vsd / "request.json").exists())
    self.assertTrue((self.vsd / "request.json.processing").exists())
    self.assertIsNone(self._read_invalid())

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

  def test_non_fixed_size_rejected(self):
    self._write_request({"archive_paths": ["/app/legacy/x"]})
    self.assertIsNone(self.sm.claim_request())
    self.assertIn("non-fixed-size mount",
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
    # CID landed in r1fs but was not retired
    self.assertEqual(len(self.owner._r1fs.added), 1)

  def test_chainstore_no_ack_still_succeeds(self):
    # hset returning False (no peer confirmation) is recorded but not fatal.
    self.owner._cs.hset_returns = False
    ok = self.sm.publish_snapshot(["/app/data/"], {})
    self.assertTrue(ok)
    files = list(history_sent_dir(self.owner).glob("*.json"))
    self.assertEqual(len(files), 1)
    entry = json.loads(files[0].read_text())
    self.assertFalse(entry["chainstore_ack"])

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
    self.assertFalse(older["deletion"]["deletion_succeeded"])
    self.assertIn("daemon paused", older["deletion"]["deletion_error"])

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

  def test_validate_manifest_empty_when_aligned(self):
    record = {"manifest": {"archive_paths": ["/app/data/"]}}
    self.assertEqual(self.sm_c.validate_manifest(record), [])

  def test_validate_manifest_returns_missing_paths(self):
    record = {"manifest": {"archive_paths": ["/app/data/", "/somewhere/else/"]}}
    self.assertEqual(self.sm_c.validate_manifest(record), ["/somewhere/else/"])

  def test_validate_manifest_handles_no_manifest(self):
    self.assertEqual(self.sm_c.validate_manifest({}), [])
    self.assertEqual(self.sm_c.validate_manifest({"manifest": {}}), [])

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
        "archive_size_bytes": 100,
      },
    }
    record = self.sm_c.fetch_latest()
    ok = self.sm_c.apply_snapshot(record)
    self.assertFalse(ok)
    # No last_apply, no history advance
    self.assertFalse((volume_sync_dir(self.consumer) / "last_apply.json").exists())
    self.assertEqual(len(list(history_received_dir(self.consumer).glob("*.json"))), 0)
    # Useful error message
    self.assertTrue(any("missing mounts for" in m for m in self.consumer._msgs))

  def test_apply_aborts_on_r1fs_get_failure(self):
    (volume_sync_dir(self.provider) / SYNC_PROCESSING_FILE).write_text("{}")
    self.sm_p.publish_snapshot(["/app/data/"], {})
    record = self.sm_c.fetch_latest()
    self.consumer._r1fs.get_should_raise = RuntimeError("network down")
    ok = self.sm_c.apply_snapshot(record)
    self.assertFalse(ok)
    self.assertFalse((volume_sync_dir(self.consumer) / "last_apply.json").exists())

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


if __name__ == "__main__":
  unittest.main()
