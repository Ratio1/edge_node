"""Save points in the network worker (RM-201 phase 2)."""
import shutil
import threading
import tempfile
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import checkpoint as ckpt
from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.tests.test_checkpoint import _FakeOwner

CTX = {
  "pass_nr": 2, "ee_addr": "node-1", "scan_type": "network", "start_port": 1,
  "end_port": 20, "target_ports": None, "config_cid": "cid1",
}


class _Owner(_FakeOwner):
  def __init__(self, root, config=None, **kw):
    super().__init__(root, **kw)
    self.config_data = config or {}
    self.cfg_instance_id = "i"

  def P(self, *a, **k):
    pass


def _worker(owner, ctx=CTX, ports=None):
  w = PentestLocalWorker(
    owner=owner, target="127.0.0.1", job_id="job1", initiator="node-1", local_id_prefix="1",
    worker_target_ports=ports or [1, 2, 3, 4], checkpoint_context=ctx,
  )
  w.stop_event = threading.Event()
  return w


class TestWorkerCheckpoint(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.owner = _Owner(self.tmp)

  def _saves(self):
    return patch.object(ckpt, "save", wraps=ckpt.save)

  def test_no_context_never_saves(self):
    w = _worker(self.owner, ctx=None)
    with self._saves() as save:
      w._maybe_checkpoint(force=True)
      w._checkpoint_after_port(250)
    save.assert_not_called()

  def test_forced_save_payload_matches_schema(self):
    w = _worker(self.owner)
    w.state["open_ports"].append(3)
    w._maybe_checkpoint(force=True)
    data = ckpt.load_all(self.owner, "job1", 2)
    self.assertEqual(list(data), ["1"])
    payload = data["1"]
    self.assertEqual(set(payload), set(ckpt.PAYLOAD_FIELDS))
    self.assertEqual(payload["config_cid"], "cid1")
    self.assertEqual(payload["initial_ports"], [1, 2, 3, 4])
    self.assertEqual(payload["state"]["open_ports"], [3])
    self.assertIsNot(payload["state"], w.state)

  def test_throttle_skips_until_interval_but_force_passes(self):
    w = _worker(self.owner)
    with self._saves() as save:
      w._maybe_checkpoint(force=True)
      w._maybe_checkpoint()
      w._maybe_checkpoint()
      self.assertEqual(save.call_count, 1)
      w._maybe_checkpoint(force=True)
      self.assertEqual(save.call_count, 2)

  def test_throttle_releases_after_interval(self):
    w = _worker(self.owner)
    w._maybe_checkpoint(force=True)
    w._checkpoint_last -= 31
    with self._saves() as save:
      w._maybe_checkpoint()
    self.assertEqual(save.call_count, 1)

  def test_port_every(self):
    owner = _Owner(self.tmp, config={"WORKER_CHECKPOINT": {"PORT_EVERY": 2, "MIN_INTERVAL": 1}})
    w = _worker(owner)
    with patch.object(w, "_maybe_checkpoint") as mc:
      for n in range(1, 6):
        w._checkpoint_after_port(n)
    self.assertEqual(mc.call_count, 2)

  def test_disabled_config_never_saves(self):
    owner = _Owner(self.tmp, config={"WORKER_CHECKPOINT": {"ENABLED": False}})
    w = _worker(owner)
    with self._saves() as save:
      w._maybe_checkpoint(force=True)
    save.assert_not_called()

  def test_failed_save_logged_once_and_never_raises(self):
    owner = _Owner(self.tmp, fail_save=True)
    logs = []
    owner.P = lambda msg, **k: logs.append(msg)
    w = _worker(owner)
    logs.clear()
    w._maybe_checkpoint(force=True)
    w._maybe_checkpoint(force=True)
    self.assertEqual(len([m for m in logs if "Checkpoint" in m]), 1)

  def test_each_phase_end_saves_and_state_grows(self):
    w = _worker(self.owner)
    for name in ("_scan_ports_step", "_capture_response_fingerprint", "_active_fingerprint_ports",
                 "_gather_service_info", "_run_web_tests", "_run_correlation_tests"):
      setattr(w, name, lambda: None)
    seen = []
    real = ckpt.save

    def spy(owner, job_id, pass_nr, prefix, payload):
      seen.append(list(payload["state"]["completed_tests"]))
      return real(owner, job_id, pass_nr, prefix, payload)

    with patch.object(ckpt, "save", side_effect=spy):
      w.execute_job()
    # start save + one per executed phase (comparison phase skipped, no comparison tier)
    self.assertEqual(len(seen), 1 + 5)
    self.assertEqual(seen[0], [])
    self.assertEqual(seen[1], [])
    self.assertIn("fingerprint_completed", seen[2])
    self.assertIn("correlation_completed", seen[-1])
    final = ckpt.load_all(self.owner, "job1", 2)["1"]
    self.assertIn("correlation_completed", final["state"]["completed_tests"])

  def test_port_scan_saves_every_port_every(self):
    owner = _Owner(self.tmp, config={"WORKER_CHECKPOINT": {"PORT_EVERY": 2, "MIN_INTERVAL": 1}})
    w = _worker(owner, ports=[1, 2, 3, 4, 5])
    w.scan_mode = "syn"
    w._syn_scan_one = lambda target, port: None
    w._interruptible_sleep = lambda: False
    with patch.object(w, "_maybe_checkpoint") as mc:
      w._scan_ports_step()
    self.assertEqual(mc.call_count, 2)
    self.assertEqual(w.state["ports_scanned"], [1, 2, 3, 4, 5])

  def _enabled_methods(self, w, category, names):
    w._get_enabled_feature_methods = lambda category=None: list(names)
    for n in names:
      setattr(w, n, lambda target, port: None)

  def test_service_loop_saves_after_each_method(self):
    w = _worker(self.owner)
    w.state["open_ports"] = [1]
    self._enabled_methods(w, "service", ["_svc_a", "_svc_b"])
    with patch.object(w, "_maybe_checkpoint") as mc:
      w._gather_service_info()
    self.assertEqual(mc.call_count, 2)

  def test_web_loop_saves_after_each_method(self):
    w = _worker(self.owner)
    w.state["open_ports"] = [1]
    self._enabled_methods(w, "web", ["_web_a", "_web_b"])
    with patch.object(w, "_maybe_checkpoint") as mc:
      w._run_web_tests()
    self.assertEqual(mc.call_count, 2)

  def test_connect_path_saves_every_port_every(self):
    owner = _Owner(self.tmp, config={"WORKER_CHECKPOINT": {"PORT_EVERY": 2, "MIN_INTERVAL": 1}})
    w = _worker(owner, ports=[1, 2, 3, 4, 5])
    w._interruptible_sleep = lambda: False

    class _Sock:
      def __init__(self, *a, **k): pass
      def settimeout(self, t): pass
      def connect_ex(self, addr): return 111
      def close(self): pass

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", _Sock), \
         patch.object(w, "_maybe_checkpoint") as mc:
      w._scan_ports_step()
    self.assertEqual(w.state["ports_scanned"], [1, 2, 3, 4, 5])
    self.assertEqual(mc.call_count, 2)

  def test_stopped_phase_does_not_save_false_marker(self):
    w = _worker(self.owner)
    w._scan_ports_step = lambda: None
    w._gather_service_info = lambda: w.stop_event.set()
    phase = {"phase": "service_probes", "runner": "_gather_service_info",
             "completion_marker": "service_info_completed"}
    seen = []
    real = ckpt.save

    def spy(owner, job_id, pass_nr, prefix, payload):
      seen.append(list(payload["state"]["completed_tests"]))
      return real(owner, job_id, pass_nr, prefix, payload)

    with patch.object(ckpt, "save", side_effect=spy):
      w._execute_phase(phase)
    self.assertEqual(seen, [])

  def test_credentials_redacted_in_saved_copy_only(self):
    w = _worker(self.owner)
    w.state["service_info"] = {22: {"banner": "Default credentials accepted: admin:hunter2"}}
    w._maybe_checkpoint(force=True)
    saved = ckpt.load_all(self.owner, "job1", 2)["1"]["state"]["service_info"][22]["banner"]
    self.assertNotIn("hunter2", saved)
    self.assertIn("hunter2", w.state["service_info"][22]["banner"])
    self.assertNotIn("redact_credentials", ckpt.load_all(self.owner, "job1", 2)["1"])

  def test_credentials_kept_when_redaction_off(self):
    w = _worker(self.owner, ctx=dict(CTX, redact_credentials=False))
    w.state["service_info"] = {22: {"banner": "Default credentials accepted: admin:hunter2"}}
    w._maybe_checkpoint(force=True)
    saved = ckpt.load_all(self.owner, "job1", 2)["1"]["state"]["service_info"][22]["banner"]
    self.assertIn("hunter2", saved)

  def test_save_raising_is_contained_and_logged_once(self):
    logs = []
    self.owner.P = lambda msg, **k: logs.append(msg)
    w = _worker(self.owner)
    logs.clear()
    with patch.object(ckpt, "save", side_effect=RuntimeError("boom")):
      w._maybe_checkpoint(force=True)
      w._maybe_checkpoint(force=True)
    self.assertEqual(len([m for m in logs if "Checkpoint" in m]), 1)

  def test_unreadable_config_disables_checkpointing(self):
    w = _worker(self.owner)
    with patch.object(ckpt, "get_worker_checkpoint_config", side_effect=RuntimeError("x")):
      w._checkpoint_after_port(250)
      w._maybe_checkpoint(force=True)
    self.assertEqual(ckpt.load_all(self.owner, "job1", 2), {})


if __name__ == "__main__":
  unittest.main()
