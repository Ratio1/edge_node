"""Worker-level plumbing for the SYN scan mode (RM-094 phase 1)."""

import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.worker import syn_scan
from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker


class DummyOwner:
  def P(self, *args, **kwargs):
    pass


def _worker(scan_mode="connect", ports=(80, 81)):
  worker = PentestLocalWorker(
    owner=DummyOwner(),
    target="127.0.0.1",
    job_id="job-syn",
    initiator="init@example",
    local_id_prefix="1",
    worker_target_ports=list(ports),
    exceptions=None,
    scan_mode=scan_mode,
  )
  worker.stop_event = MagicMock()
  worker.stop_event.is_set.return_value = False
  worker._interruptible_sleep = lambda: False
  return worker


class ScanModePlumbingTests(unittest.TestCase):
  def test_default_mode_is_connect(self):
    worker = _worker()
    self.assertEqual(worker.scan_mode, "connect")
    self.assertEqual(worker.state["scan_mode"], "connect")
    self.assertEqual(worker.state["scan_mode_effective"], "connect")

  def test_status_reports_scan_mode(self):
    worker = _worker()
    status = worker.get_status()
    self.assertEqual(status["scan_mode"], "connect")
    self.assertEqual(status["scan_mode_effective"], "connect")

  def test_unknown_mode_falls_back_to_connect(self):
    worker = _worker(scan_mode="bogus")
    self.assertEqual(worker.scan_mode, "connect")


class SynRefusalTests(unittest.TestCase):
  def test_syn_without_raw_socket_refuses_at_construction(self):
    with patch.object(syn_scan, "raw_socket_available", return_value=False):
      with self.assertRaises(ValueError) as ctx:
        _worker(scan_mode="syn")
    self.assertEqual(str(ctx.exception), "scan_mode_unavailable")

  def test_syn_with_raw_socket_constructs(self):
    with patch.object(syn_scan, "raw_socket_available", return_value=True):
      worker = _worker(scan_mode="syn")
    self.assertEqual(worker.scan_mode, "syn")
    self.assertEqual(worker.state["scan_mode"], "syn")


class SynDiscoveryLoopTests(unittest.TestCase):
  def test_scan_step_uses_syn_probe_and_records_open_without_banner(self):
    with patch.object(syn_scan, "raw_socket_available", return_value=True):
      worker = _worker(scan_mode="syn", ports=(80, 81))

    # 80 open, 81 closed. connect_ex must never be called in SYN mode.
    def fake_probe(target, port, timeout, **kwargs):
      return syn_scan.OPEN if port == 80 else syn_scan.CLOSED

    with patch.object(syn_scan, "syn_probe", side_effect=fake_probe) as probe, \
         patch("socket.socket") as sock_ctor:
      worker._scan_ports_step()

    self.assertTrue(probe.called)
    sock_ctor.assert_not_called()
    self.assertEqual(worker.state["open_ports"], [80])
    # SYN open ports carry no confirmed banner; active fingerprint refines them.
    self.assertFalse(worker.state["port_banner_confirmed"].get(80, False))
    self.assertEqual(worker.state["port_banners"].get(80), "")


if __name__ == "__main__":
  unittest.main()
