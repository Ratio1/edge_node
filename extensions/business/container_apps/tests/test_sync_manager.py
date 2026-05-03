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

from extensions.business.container_apps.sync_manager import (
  SYSTEM_VOLUME_NAME,
  SYSTEM_VOLUME_MOUNT,
  SyncManager,
  history_received_dir,
  history_sent_dir,
  system_volume_host_root,
  volume_sync_dir,
)


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
  return SimpleNamespace(
    get_data_folder=lambda: str(data_folder),
    _get_instance_data_subfolder=lambda: instance_subfolder,
    get_output_folder=lambda: str(output_folder),
    volumes=volumes,
    time=lambda: 1714742400.0,
    ee_id="ee_test_provider",
    P=lambda msg, color=None: msgs.append(f"[{color or ''}] {msg}"),
    _msgs=msgs,
    _fixed_root=fixed_root,
    _output_folder=output_folder,
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

  def test_latest_picks_highest_version(self):
    self.sm.append_sent({"cid": "Qm1", "version": 100})
    self.sm.append_sent({"cid": "Qm3", "version": 300})
    self.sm.append_sent({"cid": "Qm2", "version": 200})
    latest = self.sm.latest_sent()
    self.assertIsNotNone(latest)
    self.assertEqual(latest["version"], 300)
    self.assertEqual(latest["cid"], "Qm3")

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
    self.assertEqual(data["deletion"]["deleted_at"], 1714742400.0)
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


if __name__ == "__main__":
  unittest.main()
