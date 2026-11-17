import os
import pickle
import shutil
import tempfile
import unittest

from extensions.business.cybersec.red_mesh.services import checkpoint as ckpt


class _FakeOwner:
  """Minimal diskapi stand-in over a temp folder; save swallows errors like the real helper."""

  INSTANCE = "pipelines_data/s/i"

  def __init__(self, root, fail_save=False):
    self.root = root
    self.fail_save = fail_save

  def get_data_folder(self):
    return self.root

  def _get_instance_data_subfolder(self):
    return self.INSTANCE

  def diskapi_save_pickle_to_data(self, obj, filename, subfolder=None, compress=False, verbose=True):
    if self.fail_save:
      return None
    folder = os.path.join(self.root, self.INSTANCE, subfolder)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, filename), "wb") as fh:
      pickle.dump(obj, fh)

  def diskapi_load_pickle_from_data(self, filename, subfolder=None, decompress=False, verbose=True):
    try:
      with open(os.path.join(self.root, self.INSTANCE, subfolder, filename), "rb") as fh:
        return pickle.load(fh)
    except Exception:
      return None

  def diskapi_delete_file(self, path):
    os.remove(path)

  def diskapi_delete_directory(self, path):
    shutil.rmtree(path)


def _payload(**kw):
  base = {"version": ckpt.CHECKPOINT_VERSION, "job_id": "job1", "pass_nr": 1, "state": {}}
  base.update(kw)
  return base


class TestCheckpointStore(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.owner = _FakeOwner(self.tmp)
    self.base = os.path.join(self.tmp, _FakeOwner.INSTANCE, "plugin_data", "redmesh_ckpt")

  def test_save_load_roundtrip_path(self):
    self.assertTrue(ckpt.save(self.owner, "job1", 1, "a", _payload(x=1)))
    self.assertTrue(os.path.isfile(os.path.join(self.base, "job1", "1_a.pkl")))
    loaded = ckpt.load_all(self.owner, "job1", 1)
    self.assertEqual(list(loaded), ["a"])
    self.assertEqual(loaded["a"]["x"], 1)

  def test_load_all_filters_by_pass(self):
    ckpt.save(self.owner, "job1", 1, "a", _payload())
    ckpt.save(self.owner, "job1", 2, "a", _payload(pass_nr=2))
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 2)), ["a"])
    self.assertEqual(ckpt.load_all(self.owner, "job1", 3), {})

  def test_save_false_when_file_missing(self):
    self.assertFalse(ckpt.save(_FakeOwner(self.tmp, fail_save=True), "job1", 1, "a", _payload()))

  def test_illegal_job_id_rejected(self):
    for bad in ("../x", "a/b", "", "a b", "a.b", "job1\n", None):
      self.assertFalse(ckpt.save(self.owner, bad, 1, "a", _payload()), bad)
      self.assertEqual(ckpt.load_all(self.owner, bad, 1), {})
    self.assertFalse(ckpt.save(self.owner, "job1", 1, "../a", _payload()))
    self.assertFalse(os.path.exists(self.base))

  def test_corrupt_file_ignored_and_deleted(self):
    ckpt.save(self.owner, "job1", 1, "good", _payload())
    bad = os.path.join(self.base, "job1", "1_bad.pkl")
    with open(bad, "wb") as fh:
      fh.write(b"not a pickle")
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 1)), ["good"])
    self.assertFalse(os.path.exists(bad))

  def test_wrong_version_ignored_and_deleted(self):
    ckpt.save(self.owner, "job1", 1, "old", _payload(version=ckpt.CHECKPOINT_VERSION + 1))
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_old.pkl")))

  def test_non_dict_payload_deleted(self):
    ckpt.save(self.owner, "job1", 1, "lst", [1, 2])
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_lst.pkl")))

  def test_load_raising_is_ignored_and_deleted(self):
    ckpt.save(self.owner, "job1", 1, "a", _payload())
    def boom(*a, **k):
      raise RuntimeError("x")
    self.owner.diskapi_load_pickle_from_data = boom
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_a.pkl")))

  def test_bad_pass_nr_is_safe(self):
    self.assertFalse(ckpt.save(self.owner, "job1", "x", "a", _payload()))
    self.assertEqual(ckpt.load_all(self.owner, "job1", None), {})
    ckpt.delete_pass(self.owner, "job1", "x")

  def test_stale_file_not_a_successful_save(self):
    ckpt.save(self.owner, "job1", 1, "a", _payload())
    self.owner.fail_save = True
    self.assertFalse(ckpt.save(self.owner, "job1", 1, "a", _payload()))
    # The last good checkpoint survives a failed write.
    self.assertIn("a", ckpt.load_all(self.owner, "job1", 1))

  def test_payload_fields_pinned(self):
    self.assertEqual(len(ckpt.PAYLOAD_FIELDS), 16)
    self.assertNotIn("reference_dump", ckpt.PAYLOAD_FIELDS)

  def test_delete_pass_and_job_and_list(self):
    ckpt.save(self.owner, "job1", 1, "a", _payload())
    ckpt.save(self.owner, "job1", 2, "a", _payload())
    ckpt.save(self.owner, "job2", 1, "a", _payload())
    self.assertEqual(ckpt.list_jobs(self.owner), ["job1", "job2"])
    ckpt.delete_pass(self.owner, "job1", 1)
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 2)), ["a"])
    ckpt.delete_job(self.owner, "job1")
    self.assertEqual(ckpt.list_jobs(self.owner), ["job2"])

  def test_delete_illegal_job_id_noop(self):
    ckpt.save(self.owner, "job1", 1, "a", _payload())
    ckpt.delete_job(self.owner, "..")
    ckpt.delete_pass(self.owner, "../job1", 1)
    self.assertEqual(ckpt.list_jobs(self.owner), ["job1"])

  def test_list_jobs_missing_root(self):
    self.assertEqual(ckpt.list_jobs(self.owner), [])


class TestCheckpointConfig(unittest.TestCase):

  def test_defaults(self):
    cfg = ckpt.get_worker_checkpoint_config(type("O", (), {})())
    self.assertEqual(cfg, ckpt.DEFAULT_WORKER_CHECKPOINT_CONFIG)

  def test_override_and_bad_values(self):
    owner = type("O", (), {})()
    owner.cfg_worker_checkpoint = {
      "ENABLED": "off", "MIN_INTERVAL": 5, "PORT_EVERY": "x", "GC_INTERVAL": -1, "MAX_AGE": float("nan"),
    }
    cfg = ckpt.get_worker_checkpoint_config(owner)
    self.assertFalse(cfg["ENABLED"])
    self.assertEqual(cfg["MIN_INTERVAL"], 5)
    self.assertEqual(cfg["PORT_EVERY"], 250)
    self.assertEqual(cfg["GC_INTERVAL"], 600)
    self.assertEqual(cfg["MAX_AGE"], 172800)

  def test_port_every_below_one_is_clamped(self):
    owner = type("O", (), {})()
    owner.cfg_worker_checkpoint = {"PORT_EVERY": 0.5}
    self.assertEqual(ckpt.get_worker_checkpoint_config(owner)["PORT_EVERY"], 1)


if __name__ == "__main__":
  unittest.main()
