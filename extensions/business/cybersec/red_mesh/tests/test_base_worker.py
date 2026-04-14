"""
Contract enforcement tests for BaseLocalWorker.

Verifies the abstract base class contract is correctly implemented
and that PentestLocalWorker's retrofit preserves all API-facing behavior.
"""

import threading
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.worker.base import BaseLocalWorker
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from .conftest import DummyOwner


def _make_pentest_worker(**overrides):
  """Helper: create a PentestLocalWorker with sensible defaults."""
  defaults = dict(
    owner=DummyOwner(),
    target="127.0.0.1",
    job_id="test-job",
    initiator="test-addr",
    local_id_prefix="1",
    worker_target_ports=[80, 443],
  )
  defaults.update(overrides)
  return PentestLocalWorker(**defaults)


class TestBaseLocalWorkerContract(unittest.TestCase):
  """Verify BaseLocalWorker enforces the API contract."""

  # ── Abstract method enforcement ──

  def test_cannot_instantiate_base(self):
    """BaseLocalWorker is abstract — cannot be instantiated directly."""
    with self.assertRaises(TypeError):
      BaseLocalWorker(
        owner=MagicMock(), job_id="test", initiator="addr",
        local_id_prefix="1", target="127.0.0.1",
      )

  # ── Shared attribute initialization ──

  def test_pentest_worker_is_base_worker(self):
    """PentestLocalWorker inherits from BaseLocalWorker."""
    self.assertTrue(issubclass(PentestLocalWorker, BaseLocalWorker))

  def test_shared_attributes_set(self):
    """Base __init__ sets all shared attributes."""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner, target="127.0.0.1", job_id="j1",
      initiator="addr", local_id_prefix="1",
      worker_target_ports=[80, 443],
    )
    self.assertIs(worker.owner, owner)
    self.assertEqual(worker.job_id, "j1")
    self.assertEqual(worker.initiator, "addr")
    self.assertEqual(worker.target, "127.0.0.1")
    self.assertTrue(worker.local_worker_id.startswith("RM-1-"))
    self.assertIsNone(worker.thread)       # set by start()
    self.assertIsNone(worker.stop_event)   # set by start()
    self.assertTrue(hasattr(worker, 'metrics'))
    self.assertTrue(hasattr(worker, 'initial_ports'))
    self.assertTrue(hasattr(worker, 'state'))

  # ── Threading contract ──

  def test_start_creates_thread_and_event(self):
    """start() sets thread and stop_event."""
    worker = _make_pentest_worker()
    worker.execute_job = lambda: None
    worker.start()
    self.assertIsInstance(worker.thread, threading.Thread)
    self.assertIsInstance(worker.stop_event, threading.Event)
    worker.thread.join(timeout=2)

  def test_stop_sets_event_and_canceled(self):
    """stop() sets the stop_event AND state['canceled']."""
    worker = _make_pentest_worker()
    worker.execute_job = lambda: None
    worker.start()
    worker.stop()
    self.assertTrue(worker.stop_event.is_set())
    self.assertTrue(worker.state["canceled"])
    worker.thread.join(timeout=2)

  def test_check_stopped_after_stop(self):
    """_check_stopped() returns True after stop_event is set."""
    worker = _make_pentest_worker()
    worker.stop_event = threading.Event()
    worker.state["done"] = False
    self.assertFalse(worker._check_stopped())
    worker.stop_event.set()
    self.assertTrue(worker._check_stopped())

  def test_check_stopped_when_done(self):
    """_check_stopped() returns True when state['done'] is True."""
    worker = _make_pentest_worker()
    worker.stop_event = threading.Event()
    worker.state["done"] = True
    self.assertTrue(worker._check_stopped())

  def test_check_stopped_when_canceled(self):
    """_check_stopped() returns True when state['canceled'] is True."""
    worker = _make_pentest_worker()
    worker.stop_event = threading.Event()
    worker.state["canceled"] = True
    self.assertTrue(worker._check_stopped())

  def test_check_stopped_before_start(self):
    """_check_stopped() works even before start() (stop_event is None)."""
    worker = _make_pentest_worker()
    self.assertIsNone(worker.stop_event)
    self.assertFalse(worker._check_stopped())

  # ── State dict contract ──

  def test_state_has_required_keys(self):
    """State dict has all keys the API reads."""
    worker = _make_pentest_worker()
    required_keys = [
      "done", "canceled", "open_ports", "ports_scanned",
      "completed_tests", "service_info", "web_tests_info",
      "port_protocols", "correlation_findings",
    ]
    for key in required_keys:
      self.assertIn(key, worker.state, f"Missing state key: {key}")

  def test_ports_scanned_is_list(self):
    """ports_scanned must be a list (API calls len() on it)."""
    worker = _make_pentest_worker()
    self.assertIsInstance(worker.state["ports_scanned"], list)

  def test_open_ports_is_list(self):
    """open_ports must be a list (API calls set.update() on it)."""
    worker = _make_pentest_worker()
    self.assertIsInstance(worker.state["open_ports"], list)

  def test_done_defaults_false(self):
    self.assertFalse(_make_pentest_worker().state["done"])

  def test_canceled_defaults_false(self):
    self.assertFalse(_make_pentest_worker().state["canceled"])

  # ── initial_ports contract ──

  def test_initial_ports_is_list(self):
    """initial_ports must be a list (API calls len() on it)."""
    worker = _make_pentest_worker()
    self.assertIsInstance(worker.initial_ports, list)
    self.assertGreater(len(worker.initial_ports), 0)

  # ── local_worker_id contract ──

  def test_local_worker_id_is_string(self):
    worker = _make_pentest_worker()
    self.assertIsInstance(worker.local_worker_id, str)
    self.assertTrue(worker.local_worker_id.startswith("RM-"))

  # ── get_status contract ──

  def test_get_status_returns_dict(self):
    worker = _make_pentest_worker()
    status = worker.get_status()
    self.assertIsInstance(status, dict)

  def test_get_status_has_required_keys(self):
    """get_status() returns all keys needed by _close_job."""
    worker = _make_pentest_worker()
    status = worker.get_status()
    required = [
      "job_id", "initiator", "target",
      "open_ports", "ports_scanned", "completed_tests",
      "service_info", "web_tests_info", "port_protocols",
      "correlation_findings", "scan_metrics",
    ]
    for key in required:
      self.assertIn(key, status, f"Missing status key: {key}")

  def test_get_status_scan_metrics_is_dict(self):
    worker = _make_pentest_worker()
    status = worker.get_status()
    self.assertIsInstance(status["scan_metrics"], dict)

  # ── get_worker_specific_result_fields contract ──

  def test_result_fields_is_static(self):
    """get_worker_specific_result_fields is a static method returning dict."""
    fields = PentestLocalWorker.get_worker_specific_result_fields()
    self.assertIsInstance(fields, dict)

  def test_result_fields_has_core_keys(self):
    """Aggregation fields include the keys the API expects."""
    fields = PentestLocalWorker.get_worker_specific_result_fields()
    required = [
      "open_ports", "service_info", "web_tests_info",
      "completed_tests", "port_protocols", "correlation_findings",
      "scan_metrics",
    ]
    for key in required:
      self.assertIn(key, fields, f"Missing aggregation field: {key}")

  # ── P() logging ──

  def test_p_delegates_to_owner(self):
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner, target="t", job_id="j",
      initiator="a", local_id_prefix="1",
      worker_target_ports=[80],
    )
    worker.P("test message")
    self.assertTrue(len(owner.messages) > 0)
    # Find the "test message" log entry (init also logs)
    matching = [m for m in owner.messages if "test message" in m]
    self.assertTrue(len(matching) > 0, "P() did not delegate to owner")
    self.assertIn(worker.local_worker_id, matching[0])


class TestPentestWorkerRetrofit(unittest.TestCase):
  """Verify PentestLocalWorker still works after BaseLocalWorker retrofit."""

  def test_mro_has_base(self):
    """BaseLocalWorker is in the MRO."""
    self.assertIn(BaseLocalWorker, PentestLocalWorker.__mro__)

  def test_start_stop_inherited(self):
    """start() and stop() come from BaseLocalWorker, not redefined."""
    self.assertNotIn('start', PentestLocalWorker.__dict__)
    self.assertNotIn('stop', PentestLocalWorker.__dict__)

  def test_check_stopped_inherited(self):
    self.assertNotIn('_check_stopped', PentestLocalWorker.__dict__)

  def test_p_inherited(self):
    self.assertNotIn('P', PentestLocalWorker.__dict__)

  def test_execute_job_overridden(self):
    """execute_job is defined on PentestLocalWorker (not inherited)."""
    self.assertIn('execute_job', PentestLocalWorker.__dict__)

  def test_get_status_overridden(self):
    self.assertIn('get_status', PentestLocalWorker.__dict__)

  def test_get_worker_specific_result_fields_overridden(self):
    self.assertIn('get_worker_specific_result_fields', PentestLocalWorker.__dict__)


if __name__ == '__main__':
  unittest.main()
