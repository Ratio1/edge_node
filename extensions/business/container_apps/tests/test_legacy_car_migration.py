"""Tests for ContainerAppRunnerPlugin._migrate_legacy_car_data.

Pre-refactor CAR data lived under {data_folder}/container_apps/{plugin_id}/.
After the isolation refactor it lives under
{data_folder}/pipelines_data/{sid}/{iid}/plugin_data/. Without an explicit
migration, manually_stopped flags and co-located logs reset on upgrade.
"""

import os
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
  sys.path.insert(0, REPO_ROOT)

from extensions.business.container_apps.tests import support  # noqa: F401
from extensions.business.container_apps.container_app_runner import ContainerAppRunnerPlugin


class _Harness:
  """Minimal object exposing only the attributes the migration helper uses."""

  def __init__(self, data_folder, plugin_id, sid, iid):
    self._data_folder = data_folder
    self.plugin_id = plugin_id
    self._sid = sid
    self._iid = iid
    self.logged = []

  def P(self, msg, *a, **k):
    self.logged.append(str(msg))

  def get_data_folder(self):
    return self._data_folder

  def _get_plugin_absolute_base(self):
    return os.path.join(self._data_folder, "pipelines_data", self._sid, self._iid)

  # Bind the real helper so we test the production code path.
  _migrate_legacy_car_data = ContainerAppRunnerPlugin._migrate_legacy_car_data


class LegacyCarMigrationTests(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp(prefix="legacy_car_")
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.plugin_id = "pipe__SIG__inst"
    self.sid = "pipe"
    self.iid = "inst"

  def _legacy_dir(self):
    return os.path.join(self.tmp, "container_apps", self.plugin_id)

  def _new_dir(self):
    return os.path.join(self.tmp, "pipelines_data", self.sid, self.iid, "plugin_data")

  def _seed_legacy(self, files):
    legacy = self._legacy_dir()
    os.makedirs(legacy, exist_ok=True)
    for name, content in files.items():
      with open(os.path.join(legacy, name), "wb") as f:
        f.write(content)

  def test_moves_files_to_new_dir_and_removes_legacy(self):
    self._seed_legacy({
      "persistent_state.pkl": b"state-bytes",
      "container_logs.pkl": b"log-bytes",
    })
    h = _Harness(self.tmp, self.plugin_id, self.sid, self.iid)
    h._migrate_legacy_car_data()

    new_dir = self._new_dir()
    self.assertTrue(os.path.isdir(new_dir))
    with open(os.path.join(new_dir, "persistent_state.pkl"), "rb") as f:
      self.assertEqual(f.read(), b"state-bytes")
    with open(os.path.join(new_dir, "container_logs.pkl"), "rb") as f:
      self.assertEqual(f.read(), b"log-bytes")
    self.assertFalse(os.path.isdir(self._legacy_dir()))
    # container_apps/ wrapper dir is also cleaned up when empty
    self.assertFalse(os.path.isdir(os.path.join(self.tmp, "container_apps")))

  def test_idempotent_when_legacy_absent(self):
    h = _Harness(self.tmp, self.plugin_id, self.sid, self.iid)
    h._migrate_legacy_car_data()  # no legacy dir -- no-op
    # No error, no warning logs either
    self.assertEqual(
      [m for m in h.logged if "migration" in m.lower() and "skipped" not in m.lower()],
      [],
    )

  def test_destination_conflict_new_wins_legacy_is_discarded(self):
    # Seed both sides; only the new-side file should survive with its bytes.
    self._seed_legacy({"persistent_state.pkl": b"legacy"})
    new_dir = self._new_dir()
    os.makedirs(new_dir, exist_ok=True)
    with open(os.path.join(new_dir, "persistent_state.pkl"), "wb") as f:
      f.write(b"new-wins")

    h = _Harness(self.tmp, self.plugin_id, self.sid, self.iid)
    h._migrate_legacy_car_data()

    with open(os.path.join(new_dir, "persistent_state.pkl"), "rb") as f:
      self.assertEqual(f.read(), b"new-wins")
    self.assertFalse(os.path.isdir(self._legacy_dir()))
    self.assertTrue(
      any("already exists" in m for m in h.logged),
      "expected a conflict warning in logs",
    )

  def test_exception_during_move_does_not_raise(self):
    # Make shutil.move raise; the migration must log a warning and return.
    self._seed_legacy({"persistent_state.pkl": b"x"})
    h = _Harness(self.tmp, self.plugin_id, self.sid, self.iid)
    import unittest.mock as mock
    with mock.patch(
      "extensions.business.container_apps.container_app_runner.shutil.move",
      side_effect=OSError("boom"),
    ):
      h._migrate_legacy_car_data()  # must not raise
    self.assertTrue(
      any("Legacy CAR data migration skipped" in m for m in h.logged),
      "expected a skipped-migration warning in logs",
    )

  def test_second_run_is_noop(self):
    self._seed_legacy({"persistent_state.pkl": b"x"})
    h = _Harness(self.tmp, self.plugin_id, self.sid, self.iid)
    h._migrate_legacy_car_data()
    h.logged.clear()
    h._migrate_legacy_car_data()  # legacy is gone after first run
    self.assertEqual(
      [m for m in h.logged if "complete" in m],
      [],
      "second run should not re-announce a migration",
    )


if __name__ == "__main__":
  unittest.main()
