import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from extensions.business.container_apps.reset import (
  RESET_APPLY_RESTART_NOW,
  RESET_MODE_VOLUMES,
  ResetApplyResult,
  ResetManager,
  ResetValidationError,
)


def _make_owner(tmpdir: Path, *, active=True):
  data_folder = tmpdir / "_local_cache" / "_data"
  instance_subfolder = "pipelines_data/test_stream/car_instance"
  mounts_root = data_folder / instance_subfolder / "fixed_volumes" / "mounts"
  data_root = mounts_root / "data"
  logs_root = mounts_root / "logs"
  data_root.mkdir(parents=True)
  logs_root.mkdir(parents=True)

  fixed_volumes = []
  if active:
    fixed_volumes = [
      SimpleNamespace(name="data", mount_path=data_root, owner_uid=None, owner_gid=None),
      SimpleNamespace(name="logs", mount_path=logs_root, owner_uid=None, owner_gid=None),
    ]

  return SimpleNamespace(
    get_data_folder=lambda: str(data_folder),
    _get_instance_data_subfolder=lambda: instance_subfolder,
    cfg_fixed_size_volumes={
      "data": {"SIZE": "10M", "MOUNTING_POINT": "/app/data"},
      "logs": {"SIZE": "5M", "MOUNTING_POINT": "/app/logs"},
    },
    _fixed_volumes=fixed_volumes,
  )


class TestResetManagerPlanning(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.owner = _make_owner(self.tmpdir)
    self.manager = ResetManager(self.owner)

  def tearDown(self):
    self._tmp.cleanup()

  def test_defaults_to_all_fixed_size_volumes_and_restart_now(self):
    plan = self.manager.plan_request({
      "schema_version": 1,
      "request_id": "reset-001",
      "mode": RESET_MODE_VOLUMES,
    })

    self.assertEqual(plan.request_id, "reset-001")
    self.assertEqual(plan.apply, RESET_APPLY_RESTART_NOW)
    self.assertEqual(plan.volume_names(), ["data", "logs"])

  def test_specific_volume_selection_is_logical_name_only(self):
    plan = self.manager.plan_request({
      "schema_version": 1,
      "mode": RESET_MODE_VOLUMES,
      "volumes": ["logs"],
    })

    self.assertEqual(plan.volume_names(), ["logs"])

  def test_invalid_requests_are_rejected(self):
    cases = [
      ({"schema_version": 2, "mode": "volumes"}, "schema_version"),
      ({"schema_version": 1}, "mode"),
      ({"schema_version": 1, "mode": "everything"}, "mode"),
      ({"schema_version": 1, "mode": "volumes", "apply": "later"}, "apply"),
      ({"schema_version": 1, "mode": "volumes", "volumes": "data"}, "volumes"),
      ({"schema_version": 1, "mode": "volumes", "volumes": []}, "empty"),
      ({"schema_version": 1, "mode": "volumes", "volumes": ["/app/data"]}, "not a path"),
      ({"schema_version": 1, "mode": "volumes", "volumes": ["missing"]}, "unknown"),
      ({"schema_version": 1, "mode": "volumes", "request_id": 123}, "request_id"),
      (
        {
          "schema_version": 1,
          "mode": "volumes",
          "preserve": {"env_overrides": False},
        },
        "env_overrides",
      ),
    ]

    for request, message in cases:
      with self.subTest(message=message):
        with self.assertRaisesRegex(ResetValidationError, message):
          self.manager.plan_request(request)

  def test_rejects_when_volume_is_not_active(self):
    owner = _make_owner(self.tmpdir / "inactive", active=False)
    manager = ResetManager(owner)

    with self.assertRaisesRegex(ResetValidationError, "not active"):
      manager.plan_request({"schema_version": 1, "mode": "volumes"})

  def test_rejects_active_volume_outside_car_mount_root(self):
    outside = self.tmpdir / "outside" / "data"
    outside.mkdir(parents=True)
    self.owner._fixed_volumes[0].mount_path = outside

    with self.assertRaisesRegex(ResetValidationError, "escapes"):
      self.manager.plan_request({
        "schema_version": 1,
        "mode": "volumes",
        "volumes": ["data"],
      })


class TestResetManagerExecution(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.owner = _make_owner(self.tmpdir)
    self.manager = ResetManager(self.owner)

  def tearDown(self):
    self._tmp.cleanup()

  def test_reset_clears_contents_without_following_symlinks(self):
    data_root = Path(self.owner._fixed_volumes[0].mount_path)
    nested = data_root / "nested"
    nested.mkdir()
    (nested / "file.txt").write_text("data", encoding="utf-8")
    outside = self.tmpdir / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    os.symlink(str(outside), str(data_root / "outside-link"))

    plan = self.manager.plan_request({
      "schema_version": 1,
      "mode": RESET_MODE_VOLUMES,
      "volumes": ["data"],
    })
    cleared = self.manager.reset_volumes(plan)

    self.assertEqual(cleared, 2)
    self.assertEqual(list(data_root.iterdir()), [])
    self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

  def test_response_reports_preserved_env_overrides(self):
    response = ResetApplyResult(
      request_id="reset-001",
      volumes=("data",),
      cleared_count=3,
      restart_started=True,
    ).to_response()

    self.assertEqual(response["status"], "ok")
    self.assertEqual(response["request_id"], "reset-001")
    self.assertEqual(response["reset"]["preserved"]["env_overrides"], True)
    self.assertEqual(response["restart"]["started"], True)


if __name__ == "__main__":
  unittest.main()
