"""Save points in the network worker (RM-201 phase 2)."""
import copy
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

  def test_bare_accepted_credential_pairs_redacted_in_saved_copy(self):
    # Probes store accepted pairs without a lead phrase (database.py `accepted_credentials`,
    # common.py `accepted`); the phrase-anchored walker alone leaves them in plaintext.
    w = _worker(self.owner)
    w.state["service_info"] = {3306: {"_service_info_mysql": {
      "accepted_credentials": ["root:toor"], "accepted": ["admin:1234"]}}}
    w._maybe_checkpoint(force=True)
    saved = ckpt.load_all(self.owner, "job1", 2)["1"]["state"]["service_info"][3306]["_service_info_mysql"]
    self.assertEqual(saved, {"accepted_credentials": ["root:***"], "accepted": ["admin:***"]})
    self.assertEqual(w.state["service_info"][3306]["_service_info_mysql"]["accepted"], ["admin:1234"])

  def test_no_save_after_stop(self):
    # A HARD stop deletes the job's checkpoints right after job.stop(); a save still in
    # flight on the worker thread must not write the file again.
    w = _worker(self.owner)
    w.stop_event = threading.Event()
    w.stop_event.set()
    w._maybe_checkpoint(force=True)
    self.assertEqual(ckpt.load_all(self.owner, "job1", 2), {})

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


class _Crash(BaseException):
  """Stands in for a node restart: leaves `execute_job` without a clean finish."""


class TestWorkerResume(unittest.TestCase):
  """Resume from a checkpoint with deterministic fake probes (RM-201 phase 3)."""

  PORTS = [21, 22, 23, 79, 80, 81]
  OPEN = {22, 80}

  def setUp(self):
    self.tmp = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.owner = _Owner(self.tmp, config={"WORKER_CHECKPOINT": {"MIN_INTERVAL": 0.001}})

  def _run(self, w, log, crash_on=None, fail_connect=None):
    """Run `execute_job` with fake sockets and probes; `log` collects every probe made."""
    open_ports = self.OPEN

    class _Sock:
      def __init__(self, *a, **k): pass
      def settimeout(self, t): pass
      def recv(self, n): return b""
      def close(self): pass
      def connect_ex(self, addr):
        log.append(("connect", addr[1]))
        if fail_connect == addr[1]:
          w._maybe_checkpoint(force=True)
          raise _Crash()
        return 0 if addr[1] in open_ports else 111

    def probe(name):
      def run(target, port):
        log.append((name, port))
        if crash_on == (name, port):
          w._maybe_checkpoint(force=True)
          raise _Crash()
        return {"findings": [{"title": f"{name}-{port}", "severity": "INFO"}]}
      return run

    for name in ("_svc_a", "_svc_b", "_web_a"):
      setattr(w, name, probe(name))
    w._active_fingerprint_ports = lambda: None
    w._interruptible_sleep = lambda: False
    methods = {"service": ["_svc_a", "_svc_b"], "web": ["_web_a"]}
    w._get_enabled_feature_methods = lambda category=None: list(methods.get(category, []))
    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", _Sock):
      w.execute_job()

  def _clean(self):
    w = _worker(_Owner(tempfile.mkdtemp()), ctx=None, ports=self.PORTS)
    log = []
    self._run(w, log)
    return w, log

  def _crash_then_resume(self, **crash):
    w1 = _worker(self.owner, ports=self.PORTS)
    with self.assertRaises(_Crash):
      self._run(w1, [], **crash)
    saved = ckpt.load_all(self.owner, "job1", 2)["1"]
    w2 = _worker(self.owner, ports=self.PORTS)
    w2.restore_from_checkpoint(copy.deepcopy(saved))
    log = []
    self._run(w2, log)
    return w1, w2, saved, log

  def _assert_same_result(self, resumed, clean):
    for key in ("open_ports", "ports_scanned", "completed_tests", "service_info", "web_tests_info",
                "port_protocols", "correlation_findings", "web_tested", "done", "canceled"):
      self.assertEqual(resumed.state[key], clean.state[key], key)

  def test_resume_mid_service_phase_skips_finished_work(self):
    clean, _ = self._clean()
    _, w2, saved, log = self._crash_then_resume(crash_on=("_svc_b", 80))
    self.assertEqual([e for e in log if e[0] == "connect"], [])  # every port was scanned already
    self.assertFalse([e for e in log if e[0] == "_svc_a"])  # finished method not probed again
    self.assertEqual([e for e in log if e[0] == "_svc_b"], [("_svc_b", 22), ("_svc_b", 80)])  # cut off: reruns
    self.assertIn("_web_a", {e[0] for e in log})
    self._assert_same_result(w2, clean)
    self.assertEqual(w2.local_worker_id, saved["local_worker_id"])

  def test_resume_mid_port_scan_covers_only_remaining_ports(self):
    clean, _ = self._clean()
    _, w2, saved, log = self._crash_then_resume(fail_connect=79)
    self.assertEqual(saved["state"]["ports_scanned"], [21, 22, 23])
    self.assertEqual([e[1] for e in log if e[0] == "connect"], [79, 80, 81])
    self._assert_same_result(w2, clean)

  def test_resume_keeps_findings_without_duplicates(self):
    _, w2, saved, _ = self._crash_then_resume(crash_on=("_web_a", 80))
    self.assertEqual(saved["state"]["service_info"][22]["_svc_a"]["findings"][0]["title"], "_svc_a-22")
    titles = [f["title"] for port in w2.state["service_info"].values() for info in port.values()
              for f in info["findings"]]
    self.assertEqual(len(titles), len(set(titles)))
    self.assertEqual(sorted(titles), ["_svc_a-22", "_svc_a-80", "_svc_b-22", "_svc_b-80"])
    self.assertEqual(w2.state["web_tests_info"][80]["_web_a"]["findings"][0]["title"], "_web_a-80")

  def test_resume_phase_marker_skips_whole_phase(self):
    _, w2, _, log = self._crash_then_resume(crash_on=("_web_a", 80))
    self.assertEqual([e for e in log if e[0] in ("_svc_a", "_svc_b")], [])  # service phase marker present
    self.assertEqual(log, [("_web_a", 80)])

  def test_restore_keeps_scan_start_and_records_resume_event(self):
    w1 = _worker(self.owner, ports=self.PORTS)
    with self.assertRaises(_Crash):
      self._run(w1, [], crash_on=("_svc_b", 22))
    saved = ckpt.load_all(self.owner, "job1", 2)["1"]
    w2 = _worker(self.owner, ports=self.PORTS)
    with patch.object(w2.metrics, "start_scan") as start_scan:
      w2.restore_from_checkpoint(copy.deepcopy(saved))
      self._run(w2, [])
    start_scan.assert_not_called()
    self.assertEqual(w2.metrics._scan_start, saved["metrics"]["_scan_start"])
    events = w2.state["resume_events"]
    self.assertEqual(len(events), 1)
    self.assertEqual(events[0]["from_checkpoint_at"], saved["saved_at"])
    self.assertIn("resumed_at", events[0])
    self.assertEqual(w2.get_status()["resume_events"], events)

  def test_fresh_worker_has_no_resume_events_in_status(self):
    clean, _ = self._clean()
    self.assertNotIn("resume_events", clean.get_status())
    self.assertIsNotNone(clean.metrics._scan_start)

  def test_restored_worker_is_live_and_keeps_saving(self):
    w1 = _worker(self.owner, ports=self.PORTS)
    with self.assertRaises(_Crash):
      self._run(w1, [], crash_on=("_svc_b", 22))
    saved = ckpt.load_all(self.owner, "job1", 2)["1"]
    saved["state"]["done"] = True
    saved["state"]["canceled"] = True
    w2 = _worker(self.owner, ports=self.PORTS)
    w2.restore_from_checkpoint(saved)
    self.assertFalse(w2.state["done"] or w2.state["canceled"])
    self._run(w2, [])
    final = ckpt.load_all(self.owner, "job1", 2)["1"]
    self.assertIn("correlation_completed", final["state"]["completed_tests"])
    self.assertEqual(len(final["state"]["resume_events"]), 1)

  def test_restore_with_all_ports_scanned_adds_missing_port_marker(self):
    w1 = _worker(self.owner, ports=self.PORTS)
    w1.state["ports_scanned"] = list(self.PORTS)
    w1._maybe_checkpoint(force=True)
    w2 = _worker(self.owner, ports=self.PORTS)
    w2.restore_from_checkpoint(ckpt.load_all(self.owner, "job1", 2)["1"])
    self.assertEqual(w2.state["ports_to_scan"], [])
    self.assertIn("scan_ports_step_completed", w2.state["completed_tests"])

  def test_restore_ignores_unknown_metrics_keys(self):
    w1 = _worker(self.owner, ports=self.PORTS)
    w1._maybe_checkpoint(force=True)
    saved = ckpt.load_all(self.owner, "job1", 2)["1"]
    saved["metrics"].update({"evil": 1, "__class__": "x", "_ports_scanned": 3})
    w2 = _worker(self.owner, ports=self.PORTS)
    w2.restore_from_checkpoint(saved)
    self.assertFalse(hasattr(w2.metrics, "evil"))
    self.assertIsNot(w2.metrics.__class__, "x")
    self.assertEqual(w2.metrics._ports_scanned, 3)  # a known key is restored

  def test_second_restart_resumes_again_and_keeps_both_events(self):
    clean, _ = self._clean()
    w1 = _worker(self.owner, ports=self.PORTS)
    with self.assertRaises(_Crash):
      self._run(w1, [], crash_on=("_svc_b", 80))
    first = ckpt.load_all(self.owner, "job1", 2)["1"]
    w2 = _worker(self.owner, ports=self.PORTS)
    w2.restore_from_checkpoint(copy.deepcopy(first))
    with self.assertRaises(_Crash):
      self._run(w2, [], crash_on=("_web_a", 80))
    second = ckpt.load_all(self.owner, "job1", 2)["1"]
    self.assertEqual(len(second["state"]["resume_events"]), 1)
    w3 = _worker(self.owner, ports=self.PORTS)
    w3.restore_from_checkpoint(copy.deepcopy(second))
    log = []
    self._run(w3, log)
    self.assertEqual(len(w3.state["resume_events"]), 2)
    self.assertEqual(w3.metrics._scan_start, first["metrics"]["_scan_start"])
    self.assertEqual(log, [("_web_a", 80)])  # no port, no finished method probed again
    self._assert_same_result(w3, clean)


if __name__ == "__main__":
  unittest.main()
