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

  msgs: list[str] = []
  return SimpleNamespace(
    get_data_folder=lambda: str(data_folder),
    _get_instance_data_subfolder=lambda: instance_subfolder,
    volumes=volumes,
    time=lambda: 1714742400.0,
    P=lambda msg, color=None: msgs.append(f"[{color or ''}] {msg}"),
    _msgs=msgs,
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


if __name__ == "__main__":
  unittest.main()
