"""RM-201 phase 4: final marker, checkpoint GC, deletion on the stop paths, republish after a restart."""
import os
import pickle
import shutil
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from .conftest import mock_plugin_modules
from .test_checkpoint import _FakeOwner
from extensions.business.cybersec.red_mesh.services import checkpoint as ckpt
from extensions.business.cybersec.red_mesh.services import control

ME = "node-A"
MAX_AGE = 1000


class _Owner(_FakeOwner):
  ee_addr = ME

  def P(self, *a, **k):
    pass


def _payload(job_id="job1", pass_nr=1, prefix="1", scan_type="network", ee_addr=ME):
  return {
    "version": ckpt.CHECKPOINT_VERSION, "job_id": job_id, "pass_nr": pass_nr, "ee_addr": ee_addr,
    "scan_type": scan_type, "local_id_prefix": prefix, "state": {}, "metrics": {}, "saved_at": time.time(),
  }


def _live_row(cid="QmCID", revision=1, **kw):
  row = {
    "job_id": "job1", "worker_addr": ME, "pass_nr": 1, "assignment_revision_seen": revision,
    "progress": 100.0, "phase": "done", "scan_type": "network", "phase_index": 5, "total_phases": 5,
    "ports_scanned": 10, "ports_total": 10, "open_ports_found": [22, 80], "completed_tests": ["a"],
    "updated_at": 1.0, "started_at": 5.0, "first_seen_live_at": 4.0, "last_seen_at": 1.0,
    "finished": True, "report_cid": cid, "live_metrics": {"total_duration": 3.0},
    "threads": {"t1": {"phase": "done", "ports_scanned": 5, "ports_total": 5, "open_ports_found": [22]}},
  }
  row.update(kw)
  return row


class _Base(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.owner = _Owner(self.tmp)
    self.root = os.path.join(self.tmp, _Owner.INSTANCE, "plugin_data", "redmesh_ckpt")

  def path(self, job_id, name):
    return os.path.join(self.root, job_id, name)

  def files(self, job_id):
    folder = os.path.join(self.root, job_id)
    return sorted(os.listdir(folder)) if os.path.isdir(folder) else []

  def age(self, job_id, name, seconds):
    old = time.time() - seconds
    os.utime(self.path(job_id, name), (old, old))


class TestFinalMarker(_Base):

  def test_roundtrip_stamps_identity_and_keeps_only_summary_fields(self):
    row = _live_row(job_id="other", progress=100.0, secret="hunter2", report_cid="QmX")
    self.assertTrue(ckpt.save_final_marker(self.owner, "job1", 1, row))
    marker = ckpt.load_final_marker(self.owner, "job1", 1)
    self.assertEqual((marker["job_id"], marker["pass_nr"], marker["ee_addr"], marker["done"]), ("job1", 1, ME, True))
    self.assertEqual(marker["report_cid"], "QmX")
    self.assertEqual(marker["open_ports_found"], [22, 80])
    self.assertTrue(set(marker) <= set(ckpt.FINAL_FIELDS))
    self.assertNotIn("secret", marker)
    self.assertEqual(self.files("job1"), ["final_1.pkl"])

  def test_load_all_ignores_marker_and_does_not_delete_it(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 1)), ["1"])
    self.assertIn("final_1.pkl", self.files("job1"))

  def test_delete_pass_keeps_marker_and_delete_job_removes_all(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    ckpt.save(self.owner, "job1", 2, "1", _payload(pass_nr=2))
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    ckpt.delete_pass(self.owner, "job1", 1)
    self.assertEqual(self.files("job1"), ["2_1.pkl", "final_1.pkl"])
    ckpt.delete_job(self.owner, "job1")
    self.assertEqual(self.files("job1"), [])

  def test_marker_for_another_pass_is_not_loaded(self):
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 2))
    self.assertEqual(self.files("job1"), ["final_1.pkl"])

  def test_missing_marker_is_none(self):
    self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))

  def test_mismatched_or_malformed_marker_is_deleted(self):
    bad = {
      "other node": lambda m: m.update(ee_addr="node-B"),
      "other job": lambda m: m.update(job_id="job2"),
      "other pass": lambda m: m.update(pass_nr=7),
      "not done": lambda m: m.update(done=False),
      "no cid": lambda m: m.update(report_cid=""),
      "old version": lambda m: m.update(version=99),
    }
    for label, mutate in bad.items():
      with self.subTest(label):
        ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
        marker = ckpt.load_final_marker(self.owner, "job1", 1)
        mutate(marker)
        with open(self.path("job1", "final_1.pkl"), "wb") as fh:
          pickle.dump(marker, fh)
        self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))
        self.assertEqual(self.files("job1"), [])

  def test_load_returns_only_final_fields(self):
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    marker = ckpt.load_final_marker(self.owner, "job1", 1)
    with open(self.path("job1", "final_1.pkl"), "wb") as fh:
      pickle.dump(dict(marker, error="boom", secret="hunter2"), fh)
    loaded = ckpt.load_final_marker(self.owner, "job1", 1)
    self.assertEqual(loaded, marker)
    self.assertTrue(set(loaded) <= set(ckpt.FINAL_FIELDS))

  def test_wrong_typed_field_rejects_and_deletes_the_marker(self):
    bad = {
      "cid not a str": {"report_cid": 12},
      "cid too long": {"report_cid": "Q" * (ckpt.MAX_CID_LEN + 1)},
      "count not an int": {"ports_scanned": "10"},
      "count is a bool": {"ports_total": True},
      "ports not a list": {"open_ports_found": "22"},
      "port not an int": {"open_ports_found": [22, "80"]},
      "tests not str": {"completed_tests": [1]},
      "metrics not a dict": {"live_metrics": [1]},
      "time not a number": {"started_at": "now"},
    }
    for label, change in bad.items():
      with self.subTest(label):
        ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
        marker = ckpt.load_final_marker(self.owner, "job1", 1)
        with open(self.path("job1", "final_1.pkl"), "wb") as fh:
          pickle.dump(dict(marker, **change), fh)
        self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))
        self.assertEqual(self.files("job1"), [])

  def test_marker_missing_a_required_field_is_deleted(self):
    for field in ckpt.FINAL_REQUIRED:
      with self.subTest(field):
        ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
        marker = ckpt.load_final_marker(self.owner, "job1", 1)
        marker.pop(field)
        with open(self.path("job1", "final_1.pkl"), "wb") as fh:
          pickle.dump(marker, fh)
        self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))
        self.assertEqual(self.files("job1"), [])

  def test_refused_global_and_oversize_marker_are_deleted(self):
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    with open(self.path("job1", "final_1.pkl"), "wb") as fh:
      pickle.dump({"x": os.getcwd}, fh)  # a global outside the allow-list
    self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))
    self.assertEqual(self.files("job1"), [])
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    with patch.object(ckpt, "MAX_FILE_BYTES", 10):
      self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))
    self.assertEqual(self.files("job1"), [])

  def test_symlinked_marker_is_not_followed(self):
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    real = self.path("job1", "real.pkl")
    os.rename(self.path("job1", "final_1.pkl"), real)
    os.symlink(real, self.path("job1", "final_1.pkl"))
    self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))
    self.assertTrue(os.path.islink(self.path("job1", "final_1.pkl")))  # left alone
    self.assertTrue(os.path.exists(real))

  def test_save_failure_reports_false(self):
    self.assertFalse(ckpt.save_final_marker(_Owner(self.tmp, fail_save=True), "job1", 1, _live_row()))
    self.assertFalse(ckpt.save_final_marker(self.owner, "../evil", 1, _live_row()))


class TestCleanup(_Base):
  """One `cleanup` pass per test; `jobs` maps job_id to the record `get_job` returns."""

  def run_gc(self, jobs, missing_before=frozenset(), max_age=MAX_AGE):
    def get_job(job_id):
      value = jobs.get(job_id)
      if isinstance(value, Exception):
        raise value
      return value
    return ckpt.cleanup(self.owner, get_job, set(missing_before), max_age)

  @staticmethod
  def job(pass_nr=1, status="RUNNING", finished=False, **extra):
    return {"job_pass": pass_nr, "job_status": status, "workers": {ME: {"finished": finished}}, **extra}

  def save(self, job_id="job1", pass_nr=1, prefix="1", **kw):
    ckpt.save(self.owner, job_id, pass_nr, prefix, _payload(job_id, pass_nr, prefix, **kw))

  def test_live_checkpoint_of_running_job_stays(self):
    self.save()
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    files, size, missing = self.run_gc({"job1": self.job()})
    self.assertEqual((files, size, missing), (0, 0, set()))
    self.assertEqual(self.files("job1"), ["1_1.pkl", "final_1.pkl"])

  def test_missing_job_survives_the_first_tick_and_goes_on_the_second(self):
    self.save()
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    files, _, missing = self.run_gc({})
    self.assertEqual((files, missing), (0, {"job1"}))
    self.assertEqual(self.files("job1"), ["1_1.pkl", "final_1.pkl"])
    files, size, missing = self.run_gc({}, missing_before=missing)
    self.assertEqual(files, 2)
    self.assertGreater(size, 0)
    self.assertEqual(self.files("job1"), [])
    self.assertFalse(os.path.isdir(os.path.join(self.root, "job1")))

  def test_job_back_in_cstore_resets_the_missing_count(self):
    self.save()
    _, _, missing = self.run_gc({})
    _, _, missing = self.run_gc({"job1": self.job()}, missing_before=missing)
    self.assertEqual(missing, set())
    _, _, missing = self.run_gc({}, missing_before=missing)  # one miss again, not two in a row
    self.assertEqual(self.files("job1"), ["1_1.pkl"])

  def test_missing_job_with_old_file_goes_on_the_first_tick(self):
    self.save()
    self.age("job1", "1_1.pkl", MAX_AGE + 1)
    files, _, missing = self.run_gc({})
    self.assertEqual((files, missing), (1, {"job1"}))
    self.assertEqual(self.files("job1"), [])

  def test_terminal_job_loses_everything(self):
    for status in ("FINALIZED", "STOPPED"):
      with self.subTest(status):
        self.save()
        ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
        files, _, _ = self.run_gc({"job1": self.job(status=status)})
        self.assertEqual(files, 2)
        self.assertEqual(self.files("job1"), [])

  def test_older_pass_goes_current_and_newer_pass_stay(self):
    self.save(pass_nr=1)
    self.save(pass_nr=2)
    self.save(pass_nr=3)
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    files, _, _ = self.run_gc({"job1": self.job(pass_nr=2)})
    self.assertEqual(files, 2)  # pass 1 worker file and pass 1 marker
    # pass 3 is newer than a lagging replica's pass 2: it is a resume checkpoint, kept
    self.assertEqual(self.files("job1"), ["2_1.pkl", "3_1.pkl"])

  def test_pass_below_a_malformed_job_pass_is_kept(self):
    self.save(pass_nr=1)
    self.run_gc({"job1": self.job(pass_nr="2")})
    self.assertEqual(self.files("job1"), ["1_1.pkl"])

  def test_finished_worker_loses_pass_files_and_marker(self):
    self.save()
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    files, _, _ = self.run_gc({"job1": self.job(finished=True)})
    self.assertEqual(files, 2)
    self.assertEqual(self.files("job1"), [])

  def test_other_nodes_finished_flag_does_not_count(self):
    self.save()
    record = self.job()
    record["workers"]["node-B"] = {"finished": True}
    self.assertEqual(self.run_gc({"job1": record})[0], 0)

  def test_old_file_goes_young_file_stays(self):
    self.save(prefix="1")
    self.save(prefix="2")
    self.age("job1", "1_1.pkl", MAX_AGE + 1)
    files, _, _ = self.run_gc({"job1": self.job()})
    self.assertEqual(files, 1)
    self.assertEqual(self.files("job1"), ["1_2.pkl"])

  def test_old_marker_goes(self):
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    self.age("job1", "final_1.pkl", MAX_AGE + 1)
    self.assertEqual(self.run_gc({"job1": self.job()})[0], 1)

  def test_non_network_job_loses_the_whole_folder(self):
    self.save()
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    files, _, _ = self.run_gc({"job1": self.job(scan_type="webapp")})
    self.assertEqual(files, 2)
    self.assertFalse(os.path.isdir(os.path.join(self.root, "job1")))
    self.save("job2")
    self.run_gc({"job2": self.job(job_type="model_test")})
    self.assertFalse(os.path.isdir(os.path.join(self.root, "job2")))

  def test_job_without_scan_type_or_with_network_stays(self):
    self.save("job1")
    self.save("job2")
    self.run_gc({"job1": self.job(), "job2": self.job(scan_type="network")})
    self.assertEqual((self.files("job1"), self.files("job2")), (["1_1.pkl"], ["1_1.pkl"]))

  def test_gc_never_unpickles(self):
    self.save()
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    with open(self.path("job1", "1_2.pkl"), "wb") as fh:
      fh.write(b"not a pickle")
    with patch.object(ckpt, "_read_file", side_effect=AssertionError("unpickled")):
      self.run_gc({"job1": self.job()})
      self.run_gc({})
      self.run_gc({}, missing_before={"job1"})
    self.assertEqual(self.files("job1"), [])

  def test_unreadable_file_is_left_to_the_resume_path(self):
    with open(self.path_for_new("job1", "1_2.pkl"), "wb") as fh:
      fh.write(b"not a pickle")
    self.run_gc({"job1": self.job()})
    self.assertEqual(self.files("job1"), ["1_2.pkl"])

  def path_for_new(self, job_id, name):
    os.makedirs(os.path.join(self.root, job_id), exist_ok=True)
    return self.path(job_id, name)

  def test_stray_tmp_goes_when_old_and_stays_when_young(self):
    self.save()
    old, young = "1_1.pkl.ab12cd34.tmp", "1_1.pkl.zz99yy88.tmp"
    for name in (old, young):
      with open(self.path("job1", name), "wb") as fh:
        fh.write(b"partial")
    self.age("job1", old, ckpt.TMP_MIN_AGE + 10)
    files, size, _ = self.run_gc({"job1": self.job()})
    self.assertEqual((files, size), (1, len(b"partial")))
    self.assertEqual(self.files("job1"), ["1_1.pkl", young])

  def test_tmp_pattern_matches_what_save_pickle_makes(self):
    import tempfile as tf
    fd, made = tf.mkstemp(prefix="final_3.pkl.", suffix=".tmp", dir=self.tmp)
    os.close(fd)
    self.assertTrue(ckpt._TMP_FILE.match(os.path.basename(made)))
    self.assertFalse(ckpt._TMP_FILE.match("notes.tmp"))

  def test_strangers_and_symlinks_are_left_alone(self):
    self.save()
    with open(self.path("job1", "notes.txt"), "w") as fh:
      fh.write("keep")
    outside = os.path.join(self.tmp, "outside.pkl")
    with open(outside, "wb") as fh:
      pickle.dump(_payload(scan_type="webapp"), fh)
    os.symlink(outside, self.path("job1", "1_9.pkl"))
    self.age("job1", "1_1.pkl", MAX_AGE + 1)
    self.run_gc({"job1": self.job()})
    self.assertEqual(self.files("job1"), ["1_9.pkl", "notes.txt"])
    self.assertTrue(os.path.exists(outside))

  def test_symlinked_job_folder_is_skipped(self):
    target = os.path.join(self.tmp, "elsewhere")
    os.makedirs(target)
    with open(os.path.join(target, "1_1.pkl"), "wb") as fh:
      pickle.dump(_payload(), fh)
    os.makedirs(self.root, exist_ok=True)
    os.symlink(target, os.path.join(self.root, "job1"))
    self.assertEqual(self.run_gc({"job1": self.job(status="FINALIZED")})[0], 0)
    self.assertEqual(os.listdir(target), ["1_1.pkl"])

  def test_malformed_job_record_skips_only_its_own_folder(self):
    self.save("job1")
    self.save("job2")
    bad = {"job_pass": 1, "job_status": "RUNNING", "workers": ["not", "a", "dict"]}
    files, _, missing = self.run_gc({"job1": bad, "job2": self.job(status="STOPPED")}, missing_before={"job1"})
    self.assertEqual(files, 1)
    self.assertEqual(self.files("job1"), ["1_1.pkl"])
    self.assertEqual(self.files("job2"), [])

  def test_symlinked_checkpoint_root_is_left_alone_by_every_helper(self):
    elsewhere = os.path.join(self.tmp, "elsewhere")
    os.makedirs(os.path.join(elsewhere, "job1"))
    for name in ("1_1.pkl", "final_1.pkl"):
      with open(os.path.join(elsewhere, "job1", name), "wb") as fh:
        pickle.dump(_payload() if name == "1_1.pkl" else {}, fh)
    os.makedirs(os.path.dirname(self.root), exist_ok=True)
    os.symlink(elsewhere, self.root)
    self.assertEqual(ckpt.list_jobs(self.owner), [])
    self.assertEqual(self.run_gc({"job1": self.job(status="STOPPED")}), (0, 0, set()))
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertIsNone(ckpt.load_final_marker(self.owner, "job1", 1))
    self.assertFalse(ckpt.save(self.owner, "job1", 1, "9", _payload()))
    self.assertFalse(ckpt.save_final_marker(self.owner, "job1", 1, _live_row()))
    ckpt.delete_pass(self.owner, "job1", 1)
    ckpt.delete_final_marker(self.owner, "job1", 1)
    ckpt.delete_job(self.owner, "job1")
    self.assertEqual(sorted(os.listdir(os.path.join(elsewhere, "job1"))), ["1_1.pkl", "final_1.pkl"])

  def test_lookup_failure_leaves_the_folder_alone(self):
    self.save()
    self.save("job2")
    files, _, missing = self.run_gc({"job1": RuntimeError("cstore down"), "job2": self.job(status="STOPPED")},
                                    missing_before={"job1"})
    self.assertEqual(files, 1)
    self.assertEqual(missing, set())
    self.assertEqual(self.files("job1"), ["1_1.pkl"])

  def test_one_lookup_per_job_folder(self):
    self.save("job1")
    self.save("job2")
    self.save("job2", prefix="2")
    calls = []
    ckpt.cleanup(self.owner, lambda j: calls.append(j) or self.job(), set(), MAX_AGE)
    self.assertEqual(sorted(calls), ["job1", "job2"])

  def test_no_checkpoint_folder_is_a_noop(self):
    self.assertEqual(self.run_gc({}), (0, 0, set()))


class _Fixture(_Base):
  """A MagicMock plugin over a real temp checkpoint store, with the real RM-201 methods."""

  def setUp(self):
    super().setUp()
    if "extensions.business.cybersec.red_mesh.pentester_api_01" not in sys.modules:
      mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    self.Plugin = PentesterApi01Plugin
    plugin = MagicMock()
    plugin.ee_addr = ME
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_worker_checkpoint = {}
    plugin.time.return_value = 1000.0
    plugin.completed_jobs_reports = {}
    plugin.get_data_folder.return_value = self.tmp
    plugin._get_instance_data_subfolder.return_value = _Owner.INSTANCE
    for name in ("diskapi_save_pickle_to_data", "diskapi_delete_file", "diskapi_delete_directory"):
      setattr(plugin, name, getattr(self.owner, name))
    self.live = {}
    plugin.chainstore_hset.side_effect = lambda hkey, key, value, **kw: self.live.__setitem__((hkey, key), value)
    repo = MagicMock()
    repo.get_live_progress.side_effect = lambda key: self.live.get(("test-instance:live", key))
    repo.put_live_progress_model.side_effect = lambda progress: self.live.__setitem__(
      ("test-instance:live", f"{progress.job_id}:{progress.worker_addr}"), progress.to_dict())
    patcher = patch.object(PentesterApi01Plugin, "_get_job_state_repository", lambda owner: repo)
    patcher.start()
    self.addCleanup(patcher.stop)
    plugin._normalize_job_record.side_effect = lambda job_id, raw: (job_id, raw)
    plugin._get_worker_assignment_revision = lambda entry: self.Plugin._get_worker_assignment_revision(entry)
    self.plugin, self.repo = plugin, repo


class TestWriteFinalMarker(_Fixture):

  def worker(self, ctx=True):
    return SimpleNamespace(_checkpoint_context={"pass_nr": 1} if ctx else None)

  def test_marker_written_and_pass_files_deleted(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    ckpt.save(self.owner, "job1", 2, "1", _payload(pass_nr=2))
    self.live[("test-instance:live", f"job1:{ME}")] = _live_row()
    self.Plugin._write_final_marker(self.plugin, "job1", "QmCID", {"a": self.worker(), "b": self.worker()})
    self.assertEqual(self.files("job1"), ["2_1.pkl", "final_1.pkl"])
    self.assertEqual(ckpt.load_final_marker(self.owner, "job1", 1)["report_cid"], "QmCID")

  def test_failed_marker_save_keeps_the_pass_files(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    self.live[("test-instance:live", f"job1:{ME}")] = _live_row()
    with patch.object(ckpt, "save_final_marker", return_value=False):
      self.Plugin._write_final_marker(self.plugin, "job1", "QmCID", {"a": self.worker()})
    self.assertEqual(self.files("job1"), ["1_1.pkl"])

  def test_no_checkpoint_context_writes_nothing(self):
    self.live[("test-instance:live", f"job1:{ME}")] = _live_row()
    self.Plugin._write_final_marker(self.plugin, "job1", "QmCID", {"a": self.worker(ctx=False)})
    self.assertEqual(self.files("job1"), [])

  def test_row_for_another_report_writes_nothing(self):
    self.live[("test-instance:live", f"job1:{ME}")] = _live_row(cid="QmOLD")
    self.Plugin._write_final_marker(self.plugin, "job1", "QmCID", {"a": self.worker()})
    self.assertEqual(self.files("job1"), [])

  def test_failure_never_raises(self):
    self.repo.get_live_progress.side_effect = RuntimeError("boom")
    self.Plugin._write_final_marker(self.plugin, "job1", "QmCID", {"a": self.worker()})

  def prepare_close(self, report_cid="QmReport"):
    """A plugin with one checkpointed network worker, ready for `_close_job`."""
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    worker = MagicMock()
    worker.state = {"ports_scanned": [22, 80], "open_ports": [22], "completed_tests": ["t"]}
    worker.initial_ports = [22, 80]
    worker._checkpoint_context = {"pass_nr": 1}
    worker.get_status.return_value = {"open_ports": [22], "service_info": {}}
    plugin = self.plugin
    plugin.scan_jobs = {"job1": {"RM-1-aaaa": worker}}
    plugin._get_aggregated_report = MagicMock(return_value={"open_ports": [22], "service_info": {}})
    plugin.r1fs.add_json.return_value = report_cid
    record = {"job_id": "job1", "job_pass": 1, "target": "10.0.0.1", "workers": {ME: {"assignment_revision": 1}}}
    self.repo.get_job.return_value = record
    plugin._get_job_config = MagicMock(return_value={"redact_credentials": False})
    plugin._redact_report = MagicMock(side_effect=lambda r: r)
    plugin.chainstore_hget.return_value = record
    plugin._execution_live_meta = {}
    plugin.global_shmem.get.return_value = {}
    return plugin

  def test_close_job_writes_marker_after_publishing_the_final_row(self):
    """End to end through `_close_job`, for a normal close and for a canceled one."""
    for canceled in (False, True):
      with self.subTest(canceled=canceled):
        shutil.rmtree(self.root, ignore_errors=True)
        self.live.clear()
        plugin = self.prepare_close()
        self.Plugin._close_job(plugin, "job1", canceled=canceled)
        self.assertEqual(self.files("job1"), ["final_1.pkl"])
        marker = ckpt.load_final_marker(self.owner, "job1", 1)
        self.assertEqual(marker["report_cid"], "QmReport")
        self.assertEqual(marker["ports_scanned"], 2)
        self.assertEqual(marker["open_ports_found"], [22])

  def test_close_job_without_report_cid_keeps_pass_files(self):
    plugin = self.prepare_close(report_cid=None)
    self.Plugin._close_job(plugin, "job1")
    self.assertEqual(self.files("job1"), ["1_1.pkl"])

  def test_close_job_writes_no_marker_when_the_final_row_was_not_published(self):
    plugin = self.prepare_close()
    with patch.object(self.Plugin, "_publish_live_progress_final", return_value=False), \
         patch.object(ckpt, "save_final_marker") as save_marker:
      self.Plugin._close_job(plugin, "job1")
    save_marker.assert_not_called()
    self.assertEqual(self.files("job1"), ["1_1.pkl"])


class TestRepublishFromMarker(_Fixture):

  def spec(self, **kw):
    spec = {"job_id": "job1", "job_pass": 1, "job_status": "RUNNING", "scan_type": "network"}
    spec.update(kw)
    return spec

  def put_marker(self, **kw):
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row(**kw))

  def test_republishes_terminal_row_without_launching(self):
    self.put_marker(cid="QmCID", revision=2)
    published = self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 2})
    self.assertTrue(published)
    row = self.live[("test-instance:live", f"job1:{ME}")]
    self.assertEqual((row["finished"], row["report_cid"], row["phase"], row["progress"]), (True, "QmCID", "done", 100.0))
    self.assertEqual((row["pass_nr"], row["worker_addr"], row["assignment_revision_seen"]), (1, ME, 2))
    self.assertEqual((row["ports_scanned"], row["ports_total"], row["open_ports_found"]), (10, 10, [22, 80]))
    self.assertEqual((row["started_at"], row["first_seen_live_at"]), (5.0, 4.0))
    self.assertEqual(row["updated_at"], 1000.0)
    self.assertEqual(row["live_metrics"], {"total_duration": 3.0})
    self.assertIn("job1", self.plugin.completed_jobs_reports)
    self.assertEqual(self.files("job1"), ["final_1.pkl"])  # GC removes it once the launcher merged

  def test_no_marker_does_not_publish(self):
    self.assertFalse(self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1}))
    self.assertEqual(self.live, {})

  def test_marker_of_another_revision_is_deleted_and_not_published(self):
    self.put_marker(revision=1)
    self.assertFalse(self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 2}))
    self.assertEqual(self.live, {})
    self.assertEqual(self.files("job1"), [])

  def test_marker_of_another_pass_is_ignored(self):
    self.put_marker()
    self.assertFalse(self.Plugin._republish_final_marker(
      self.plugin, "job1", self.spec(job_pass=2), {"assignment_revision": 1}))
    self.assertEqual(self.live, {})

  def test_publish_failure_keeps_the_marker_and_blocks_the_launch(self):
    self.put_marker()
    working = self.repo.put_live_progress_model.side_effect
    self.repo.put_live_progress_model.side_effect = RuntimeError("cstore down")
    self.assertTrue(self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1}))
    self.assertEqual(self.files("job1"), ["final_1.pkl"])
    self.assertEqual(self.live, {})
    self.repo.put_live_progress_model.side_effect = working  # next tick: CStore is back
    self.assertTrue(self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1}))
    self.assertEqual(self.live[("test-instance:live", f"job1:{ME}")]["report_cid"], "QmCID")

  def test_failure_without_a_marker_does_not_block_the_launch(self):
    with patch.object(ckpt, "load_final_marker", side_effect=RuntimeError("x")):
      self.assertFalse(self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1}))

  def test_logs_never_carry_marker_content(self):
    self.put_marker(cid="QmSECRETCID")
    self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1})
    self.repo.put_live_progress_model.side_effect = RuntimeError("QmSECRETCID")
    self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1})
    logs = " ".join(str(c) for c in self.plugin.P.call_args_list)
    self.assertTrue(logs)
    self.assertNotIn("QmSECRETCID", logs)

  def test_unusable_marker_is_deleted(self):
    self.put_marker()
    with open(self.path("job1", "final_1.pkl"), "wb") as fh:
      fh.write(b"junk")
    self.assertFalse(self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1}))
    self.assertEqual(self.files("job1"), [])

  def test_disabled_checkpointing_ignores_the_marker(self):
    self.put_marker()
    self.plugin.cfg_worker_checkpoint = {"ENABLED": False}
    self.assertFalse(self.Plugin._republish_final_marker(self.plugin, "job1", self.spec(), {"assignment_revision": 1}))
    self.assertEqual(self.live, {})

  def test_launch_loop_republishes_instead_of_scanning(self):
    from extensions.business.cybersec.red_mesh.tests.test_execution_binding_models import binding_payload
    self.put_marker(cid="QmCID", revision=1)
    plugin = self.plugin
    plugin.cfg_check_jobs_each = 15
    plugin.scan_jobs = {}
    plugin.lst_completed_jobs = []
    plugin._active_execution_identities = {}
    plugin._execution_live_meta = {}
    plugin._foreign_jobs_logged = set()
    plugin._PentesterApi01Plugin__last_checked_jobs = 0
    plugin.time.return_value = 1000.0
    plugin._get_worker_entry = lambda job_id, spec: self.Plugin._get_worker_entry(plugin, job_id, spec)
    spec = self.spec(
      launcher="node-L", launcher_alias="rm1", execution_binding=binding_payload(),
      workers={ME: {"start_port": 1, "end_port": 10, "assignment_revision": 1}},
    )
    plugin.chainstore_hgetall.return_value = {"job1": spec}
    with patch("extensions.business.cybersec.red_mesh.pentester_api_01.launch_local_jobs") as launch:
      self.Plugin._maybe_launch_jobs(plugin)
    launch.assert_not_called()
    self.assertEqual(self.live[("test-instance:live", f"job1:{ME}")]["report_cid"], "QmCID")
    self.assertEqual(plugin.scan_jobs, {})

  def test_launch_loop_does_not_scan_when_the_republish_fails_and_retries_next_tick(self):
    from extensions.business.cybersec.red_mesh.tests.test_execution_binding_models import binding_payload
    self.put_marker(cid="QmCID", revision=1)
    plugin = self.plugin
    plugin.cfg_check_jobs_each = 15
    plugin.scan_jobs = {}
    plugin.lst_completed_jobs = []
    plugin._active_execution_identities = {}
    plugin._execution_live_meta = {}
    plugin._foreign_jobs_logged = set()
    plugin._PentesterApi01Plugin__last_checked_jobs = 0
    plugin._get_worker_entry = lambda job_id, spec: self.Plugin._get_worker_entry(plugin, job_id, spec)
    spec = self.spec(
      launcher="node-L", launcher_alias="rm1", execution_binding=binding_payload(),
      workers={ME: {"start_port": 1, "end_port": 10, "assignment_revision": 1}},
    )
    plugin.chainstore_hgetall.return_value = {"job1": spec}
    working = self.repo.put_live_progress_model.side_effect
    self.repo.put_live_progress_model.side_effect = RuntimeError("cstore down")
    with patch("extensions.business.cybersec.red_mesh.pentester_api_01.launch_local_jobs") as launch:
      self.Plugin._maybe_launch_jobs(plugin)
      launch.assert_not_called()
      self.assertEqual(self.files("job1"), ["final_1.pkl"])
      self.repo.put_live_progress_model.side_effect = working
      plugin._PentesterApi01Plugin__last_checked_jobs = 0
      self.Plugin._maybe_launch_jobs(plugin)
      launch.assert_not_called()
    self.assertEqual(self.live[("test-instance:live", f"job1:{ME}")]["report_cid"], "QmCID")

  def test_launch_loop_launches_when_marker_is_stale(self):
    from extensions.business.cybersec.red_mesh.tests.test_execution_binding_models import binding_payload
    self.put_marker(cid="QmCID", revision=1)
    plugin = self.plugin
    plugin.cfg_check_jobs_each = 15
    plugin.scan_jobs = {}
    plugin.lst_completed_jobs = []
    plugin._active_execution_identities = {}
    plugin._execution_live_meta = {}
    plugin._foreign_jobs_logged = set()
    plugin._PentesterApi01Plugin__last_checked_jobs = 0
    plugin._get_worker_entry = lambda job_id, spec: self.Plugin._get_worker_entry(plugin, job_id, spec)
    plugin._remember_execution_identity = lambda *a: self.Plugin._remember_execution_identity(plugin, *a)
    binding = binding_payload()
    plugin._get_job_config.return_value = {"scan_type": "network", "execution_binding": binding}
    spec = self.spec(
      launcher="node-L", launcher_alias="rm1", execution_binding=binding,
      workers={ME: {"start_port": 1, "end_port": 10, "assignment_revision": 5}},
    )
    plugin.chainstore_hgetall.return_value = {"job1": spec}
    with patch("extensions.business.cybersec.red_mesh.pentester_api_01.launch_local_jobs") as launch:
      self.Plugin._maybe_launch_jobs(plugin)
    launch.assert_called_once()
    self.assertEqual(self.files("job1"), [])


class TestMaybeCleanupCheckpoints(_Fixture):

  def setUp(self):
    super().setUp()
    self.records = {}
    self.repo.get_job.side_effect = lambda job_id: self.records.get(job_id)
    self.plugin.cfg_worker_checkpoint = {"GC_INTERVAL": 600, "MAX_AGE": MAX_AGE}
    del self.plugin._checkpoint_gc_at  # MagicMock invents attributes; the plugin has none before the first run
    del self.plugin._checkpoint_gc_missing

  def run_gc(self, now):
    self.plugin.time.return_value = now
    self.Plugin._maybe_cleanup_checkpoints(self.plugin)

  def test_runs_at_once_then_only_every_gc_interval(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    self.records["job1"] = {"job_id": "job1", "job_pass": 1, "job_status": "FINALIZED", "workers": {}}
    self.run_gc(100.0)
    self.assertEqual(self.files("job1"), [])
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    self.run_gc(699.0)  # not due
    self.assertEqual(self.files("job1"), ["1_1.pkl"])
    self.run_gc(700.0)
    self.assertEqual(self.files("job1"), [])

  def test_missing_job_needs_two_ticks(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    self.run_gc(100.0)
    self.assertEqual(self.files("job1"), ["1_1.pkl"])
    self.run_gc(701.0)
    self.assertEqual(self.files("job1"), [])

  def test_logs_files_and_bytes_only_when_something_went(self):
    self.records["job1"] = {"job_id": "job1", "job_pass": 1, "job_status": "RUNNING", "workers": {}}
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    self.run_gc(100.0)
    self.plugin.P.assert_not_called()
    self.records["job1"]["job_status"] = "STOPPED"
    self.run_gc(701.0)
    (message,) = [c.args[0] for c in self.plugin.P.call_args_list]
    self.assertRegex(message, r"removed 1 files, \d+ bytes")

  def test_invalid_job_record_leaves_files(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    self.records["job1"] = {"junk": 1}
    self.plugin._normalize_job_record.side_effect = lambda job_id, raw: (None, None)
    self.run_gc(100.0)
    self.run_gc(701.0)
    self.assertEqual(self.files("job1"), ["1_1.pkl"])

  def test_error_is_logged_and_never_raised(self):
    with patch.object(ckpt, "cleanup", side_effect=RuntimeError("disk")):
      self.run_gc(100.0)
    self.assertIn("cleanup failed", self.plugin.P.call_args.args[0])

  def test_gc_wired_into_warmup_and_process(self):
    import inspect
    src = inspect.getsource(self.Plugin)
    post_init = src[src.index("def __post_init"):src.index("def _coerce_scan_type")]
    self.assertIn("_maybe_cleanup_checkpoints", post_init)
    process = src[src.index("  def process(self):"):]
    self.assertLess(process.index("self._maybe_close_jobs()"), process.index("_maybe_cleanup_checkpoints"))


class TestStopPathsDeleteCheckpoints(_Base):

  def owner_mock(self):
    owner = MagicMock()
    owner.ee_addr = ME
    owner.scan_jobs = {}
    owner._normalize_job_record.side_effect = lambda job_id, raw: (job_id, raw)
    owner.get_data_folder.return_value = self.tmp
    owner._get_instance_data_subfolder.return_value = _Owner.INSTANCE
    owner.diskapi_delete_file.side_effect = self.owner.diskapi_delete_file
    owner.diskapi_delete_directory.side_effect = self.owner.diskapi_delete_directory
    return owner

  def seed(self):
    ckpt.save(self.owner, "job1", 1, "1", _payload())
    ckpt.save_final_marker(self.owner, "job1", 1, _live_row())
    ckpt.save(self.owner, "job2", 1, "1", _payload("job2"))

  def test_hard_stop_deletes_the_jobs_checkpoints_marker_included(self):
    self.seed()
    owner = self.owner_mock()
    spec = {"job_id": "job1", "job_pass": 1, "job_status": "RUNNING", "launcher": ME, "run_mode": "SINGLEPASS",
            "workers": {ME: {}}}
    result = control.stop_monitoring(owner, "job1", "HARD", checked_job=spec)
    self.assertNotIn("error", result)
    self.assertEqual(self.files("job1"), [])
    self.assertEqual(self.files("job2"), ["1_1.pkl"])

  def test_soft_stop_keeps_the_checkpoints(self):
    self.seed()
    owner = self.owner_mock()
    spec = {"job_id": "job1", "job_pass": 1, "job_status": "RUNNING", "launcher": ME,
            "run_mode": "CONTINUOUS_MONITORING", "workers": {ME: {}}}
    result = control.stop_monitoring(owner, "job1", "SOFT", checked_job=spec)
    self.assertNotIn("error", result)
    self.assertEqual(self.files("job1"), ["1_1.pkl", "final_1.pkl"])

  def test_stop_and_delete_deletes_the_jobs_checkpoints_marker_included(self):
    self.seed()
    owner = self.owner_mock()
    spec = {"job_id": "job1", "job_pass": 1, "job_status": "RUNNING", "launcher": ME, "workers": {ME: {}}}
    with patch.object(control, "purge_job", return_value={"status": "ok"}):
      control.stop_and_delete_job(owner, "job1", checked_job=spec)
    self.assertEqual(self.files("job1"), [])
    self.assertEqual(self.files("job2"), ["1_1.pkl"])

  def test_delete_failure_is_logged_and_does_not_block_the_stop(self):
    owner = self.owner_mock()
    spec = {"job_id": "job1", "job_pass": 1, "job_status": "RUNNING", "launcher": ME, "run_mode": "SINGLEPASS",
            "workers": {ME: {}}}
    with patch.object(control.checkpoint, "delete_job", side_effect=OSError("disk")):
      result = control.stop_monitoring(owner, "job1", "HARD", checked_job=spec)
    self.assertNotIn("error", result)
    self.assertTrue(any("Could not delete checkpoints" in c.args[0] for c in owner.P.call_args_list))


if __name__ == "__main__":
  unittest.main()
