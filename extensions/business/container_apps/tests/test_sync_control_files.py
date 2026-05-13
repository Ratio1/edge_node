"""Unit tests for sync JSON control-file mechanics."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.business.container_apps.sync.control_files import (
  JsonControlFile,
  JsonControlFileDecodeError,
  JsonControlFileObjectError,
  JsonControlFileUnsafeError,
  write_json_atomic,
)


class TestWriteJsonAtomic(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.root = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def test_writes_json_atomically_with_app_readable_mode(self):
    target = self.root / "nested" / "response.json"

    write_json_atomic(target, {"status": "ok", "version": 2})

    self.assertEqual(json.loads(target.read_text()), {"status": "ok", "version": 2})
    self.assertEqual(os.stat(target).st_mode & 0o777, 0o666)
    self.assertEqual(list(target.parent.glob(".response.json.*.tmp")), [])

  def test_cleans_tmp_file_on_write_failure(self):
    target = self.root / "state.json"

    with patch(
      "extensions.business.container_apps.sync.control_files.json.dump",
      side_effect=RuntimeError("boom"),
    ):
      with self.assertRaises(RuntimeError):
        write_json_atomic(target, {"status": "ok"})

    self.assertFalse(target.exists())
    self.assertEqual(list(self.root.glob(".state.json.*.tmp")), [])

  def test_rejects_symlink_parent_directory(self):
    outside = self.root / "outside"
    outside.mkdir()
    control_root = self.root / "volume-sync"
    os.symlink(str(outside), str(control_root))

    with self.assertRaises(JsonControlFileUnsafeError):
      write_json_atomic(control_root / "response.json", {"status": "ok"})

    self.assertFalse((outside / "response.json").exists())


class TestJsonControlFile(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.root = Path(self._tmp.name)
    self.control = JsonControlFile(
      self.root, "request.json", "request.json.processing"
    )

  def tearDown(self):
    self._tmp.cleanup()

  def test_claim_object_returns_none_when_absent(self):
    self.assertIsNone(self.control.claim_object())

  def test_claim_object_renames_and_parses_pending_file(self):
    (self.root / "request.json").write_text(
      '{"archive_paths":["/app/data/"],"metadata":{"k":1}}'
    )

    claimed = self.control.claim_object()

    self.assertIsNotNone(claimed)
    self.assertEqual(claimed.body["archive_paths"], ["/app/data/"])
    self.assertEqual(claimed.body["metadata"], {"k": 1})
    self.assertFalse((self.root / "request.json").exists())
    self.assertTrue((self.root / "request.json.processing").is_file())
    self.assertEqual(claimed.processing_path, self.root / "request.json.processing")

  def test_claim_object_reports_malformed_json_with_raw_body(self):
    (self.root / "request.json").write_text("not-json{")

    with self.assertRaises(JsonControlFileDecodeError) as ctx:
      self.control.claim_object()

    self.assertEqual(ctx.exception.raw_body, "not-json{")
    self.assertTrue((self.root / "request.json.processing").is_file())

  def test_claim_object_reports_non_object_json_with_raw_body(self):
    (self.root / "request.json").write_text('["just","a","list"]')

    with self.assertRaises(JsonControlFileObjectError) as ctx:
      self.control.claim_object()

    self.assertEqual(ctx.exception.raw_body, '["just","a","list"]')
    self.assertIn("request.json must be a JSON object", str(ctx.exception))

  def test_claim_object_rejects_symlink_without_reading_target(self):
    secret = self.root / "secret.txt"
    secret.write_text("host-secret")
    os.symlink(str(secret), str(self.root / "request.json"))

    with self.assertRaises(JsonControlFileUnsafeError) as ctx:
      self.control.claim_object()

    self.assertNotIn("host-secret", str(ctx.exception))
    self.assertIsNone(ctx.exception.raw_body)
    self.assertFalse((self.root / "request.json").exists())
    self.assertTrue((self.root / "request.json.processing").is_symlink())

  def test_discard_processing_removes_processing_file(self):
    (self.root / "request.json.processing").write_text("{}")

    self.control.discard_processing()

    self.assertFalse((self.root / "request.json.processing").exists())

  def test_discard_processing_removes_broken_symlink(self):
    os.symlink(str(self.root / "missing.json"), str(self.root / "request.json.processing"))

    self.control.discard_processing()

    self.assertFalse(os.path.lexists(str(self.root / "request.json.processing")))

  def test_recover_stale_processing_removes_symlink(self):
    os.symlink(str(self.root / "missing.json"), str(self.root / "request.json.processing"))

    recovered = self.control.recover_stale_processing()

    self.assertFalse(recovered)
    self.assertFalse(os.path.lexists(str(self.root / "request.json.processing")))

  def test_recover_stale_processing_renames_only_orphan(self):
    (self.root / "request.json.processing").write_text('{"old":true}')

    recovered = self.control.recover_stale_processing()

    self.assertTrue(recovered)
    self.assertTrue((self.root / "request.json").is_file())
    self.assertFalse((self.root / "request.json.processing").exists())

  def test_recover_stale_processing_does_not_overwrite_pending(self):
    (self.root / "request.json").write_text('{"new":true}')
    (self.root / "request.json.processing").write_text('{"old":true}')

    recovered = self.control.recover_stale_processing()

    self.assertFalse(recovered)
    self.assertEqual(json.loads((self.root / "request.json").read_text()), {"new": True})
    self.assertTrue((self.root / "request.json.processing").exists())

  def test_write_json_writes_relative_to_control_root(self):
    self.control.write_json("response.json", {"status": "ok"})

    self.assertEqual(
      json.loads((self.root / "response.json").read_text()), {"status": "ok"}
    )


if __name__ == "__main__":
  unittest.main()
