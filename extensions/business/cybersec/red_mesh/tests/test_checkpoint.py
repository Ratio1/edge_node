import os
import pickle
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone

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


class _Evil:
  def __reduce__(self):
    return (os.system, ("echo pwned",))


class _Custom:
  pass


class _CallsStr:
  def __reduce__(self):
    return (str, ("x",))


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

  def test_truncated_file_is_ignored_and_deleted(self):
    ckpt.save(self.owner, "job1", 1, "a", _payload())
    path = os.path.join(self.base, "job1", "1_a.pkl")
    with open(path, "rb") as fh:
      raw = fh.read()
    with open(path, "wb") as fh:
      fh.write(raw[:len(raw) // 2])
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertFalse(os.path.exists(path))

  def test_realistic_state_roundtrips_through_restricted_load(self):
    state = {
      "open_ports": [22, 80], "ports_scanned": [1, 2], "port_banners": {22: "SSH-2.0", 80: ""},
      "service_info": {22: {"banner": "x", "findings": [{"title": "t", "severity": "HIGH"}]}},
      "scan_metadata": {"internal_ips": ["10.0.0.1"], "seen": {1, 2}, "frozen": frozenset({3})},
      "raw": b"\x00\xff", "odd": OrderedDict(a=1), "dq": deque([1, 2]),
      "when": datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
      "delta": timedelta(seconds=5), "pair": (1, "a", None, 2.5, True),
    }
    ckpt.save(self.owner, "job1", 1, "a", _payload(state=state, metrics={"_connection_log": [(1.5, "connected")]}))
    loaded = ckpt.load_all(self.owner, "job1", 1)["a"]
    self.assertEqual(loaded["state"], state)
    self.assertEqual(loaded["metrics"]["_connection_log"], [(1.5, "connected")])

  def test_disallowed_global_is_rejected_and_deleted(self):
    for prefix, obj in (("evil", _Evil()), ("custom", _Custom())):
      ckpt.save(self.owner, "job1", 1, prefix, _payload(state={"x": obj}))
    ckpt.save(self.owner, "job1", 1, "good", _payload())
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 1)), ["good"])
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_evil.pkl")))
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_custom.pkl")))

  def test_str_called_through_reduce_is_refused(self):
    ckpt.save(self.owner, "job1", 1, "s", _payload(state={"x": _CallsStr()}))
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_s.pkl")))

  def test_memo_shared_dag_is_rejected_and_deleted_quickly(self):
    dag = []
    for _ in range(30):  # 2**30 nodes when walked, a few hundred bytes on disk
      dag = [dag, dag]
    ckpt.save(self.owner, "job1", 1, "dag", _payload(state={"x": dag}))
    ckpt.save(self.owner, "job1", 1, "ok", _payload())
    path = os.path.join(self.base, "job1", "1_dag.pkl")
    self.assertLess(os.path.getsize(path), 5000)
    started = time.monotonic()
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 1)), ["ok"])
    self.assertLess(time.monotonic() - started, 10)
    self.assertFalse(os.path.exists(path))

  def test_node_bound_counts_each_shared_reference(self):
    shared = list(range(10))
    self.assertTrue(ckpt._within_node_bound({"a": shared, "b": shared}))
    with patch.object(ckpt, "MAX_NODES", 20):
      self.assertFalse(ckpt._within_node_bound({"a": shared, "b": shared}))
      self.assertTrue(ckpt._within_node_bound({"a": shared}))

  def test_full_port_range_state_stays_inside_the_bound(self):
    ports = list(range(1, 65536))
    state = {"ports_scanned": ports, "open_ports": ports[:50], "port_protocols": {p: "http" for p in ports[:50]}}
    metrics = {"_connection_log": [(1.5, "refused")] * 65535, "_response_times": [0.1] * 65535}
    ckpt.save(self.owner, "job1", 1, "big", _payload(state=state, metrics=metrics))
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 1)), ["big"])

  def test_bytearray_global_is_refused(self):
    ckpt.save(self.owner, "job1", 1, "ba", _payload(state={"x": bytearray(b"ab")}))
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_ba.pkl")))

  def test_oversized_file_is_corrupt_and_deleted(self):
    ckpt.save(self.owner, "job1", 1, "big", _payload(blob="x" * 5000))
    ckpt.save(self.owner, "job1", 1, "small", _payload())
    with patch.object(ckpt, "MAX_FILE_BYTES", 2000):
      self.assertEqual(list(ckpt.load_all(self.owner, "job1", 1)), ["small"])
    self.assertFalse(os.path.exists(os.path.join(self.base, "job1", "1_big.pkl")))
    self.assertEqual(ckpt.MAX_FILE_BYTES, 32 * 1024 * 1024)

  def test_symlinked_file_is_skipped_and_never_followed(self):
    ckpt.save(self.owner, "job1", 1, "real", _payload())
    outside = os.path.join(self.tmp, "outside.pkl")
    with open(outside, "wb") as fh:
      pickle.dump(_payload(), fh)
    link = os.path.join(self.base, "job1", "1_link.pkl")
    os.symlink(outside, link)
    self.assertEqual(list(ckpt.load_all(self.owner, "job1", 1)), ["real"])
    ckpt.delete_pass(self.owner, "job1", 1)
    self.assertTrue(os.path.islink(link))
    self.assertTrue(os.path.exists(outside))

  def test_symlinked_job_folder_is_skipped(self):
    ckpt.save(self.owner, "real", 1, "a", _payload())
    os.symlink(os.path.join(self.base, "real"), os.path.join(self.base, "job1"))
    self.assertEqual(ckpt.load_all(self.owner, "job1", 1), {})
    ckpt.delete_pass(self.owner, "job1", 1)
    self.assertEqual(list(ckpt.load_all(self.owner, "real", 1)), ["a"])
    self.assertEqual(ckpt.list_jobs(self.owner), ["real"])

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
