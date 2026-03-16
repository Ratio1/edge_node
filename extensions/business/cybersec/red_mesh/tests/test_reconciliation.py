import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.services.reconciliation import reconcile_job_workers


class TestWorkerReconciliation(unittest.TestCase):

  def _make_owner(self, now=100.0, stale_timeout=30):
    owner = MagicMock()
    owner.time.return_value = now
    owner.cfg_distributed_stale_timeout = stale_timeout
    return owner

  def test_reconcile_job_workers_marks_active_worker(self):
    owner = self._make_owner()
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    live_payloads = {
      "job-1:worker-A": {
        "job_id": "job-1",
        "worker_addr": "worker-A",
        "pass_nr": 2,
        "assignment_revision_seen": 3,
        "progress": 40.0,
        "phase": "service_probes",
        "ports_scanned": 4,
        "ports_total": 10,
        "open_ports_found": [],
        "completed_tests": [],
        "updated_at": 100.0,
        "started_at": 90.0,
        "first_seen_live_at": 90.0,
        "last_seen_at": 100.0,
      },
    }

    reconciled = reconcile_job_workers(owner, job_specs, live_payloads=live_payloads, now=100.0)

    self.assertEqual(reconciled["worker-A"]["worker_state"], "active")

  def test_reconcile_job_workers_marks_stale_worker(self):
    owner = self._make_owner(now=100.0, stale_timeout=10)
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    live_payloads = {
      "job-1:worker-A": {
        "job_id": "job-1",
        "worker_addr": "worker-A",
        "pass_nr": 2,
        "assignment_revision_seen": 3,
        "progress": 40.0,
        "phase": "service_probes",
        "ports_scanned": 4,
        "ports_total": 10,
        "open_ports_found": [],
        "completed_tests": [],
        "updated_at": 80.0,
        "started_at": 70.0,
        "first_seen_live_at": 70.0,
        "last_seen_at": 80.0,
      },
    }

    reconciled = reconcile_job_workers(owner, job_specs, live_payloads=live_payloads, now=100.0)

    self.assertEqual(reconciled["worker-A"]["worker_state"], "stale")

  def test_reconcile_job_workers_marks_unreachable_worker(self):
    owner = self._make_owner()
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "workers": {
        "worker-A": {
          "start_port": 1,
          "end_port": 10,
          "assignment_revision": 3,
          "terminal_reason": "unreachable",
        },
      },
    }

    reconciled = reconcile_job_workers(owner, job_specs, live_payloads={}, now=100.0)

    self.assertEqual(reconciled["worker-A"]["worker_state"], "unreachable")

  def test_reconcile_job_workers_marks_unseen_when_live_revision_mismatch(self):
    owner = self._make_owner()
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    live_payloads = {
      "job-1:worker-A": {
        "job_id": "job-1",
        "worker_addr": "worker-A",
        "pass_nr": 2,
        "assignment_revision_seen": 2,
        "progress": 40.0,
        "phase": "service_probes",
        "ports_scanned": 4,
        "ports_total": 10,
        "open_ports_found": [],
        "completed_tests": [],
        "updated_at": 100.0,
        "started_at": 90.0,
        "first_seen_live_at": 90.0,
        "last_seen_at": 100.0,
      },
    }

    reconciled = reconcile_job_workers(owner, job_specs, live_payloads=live_payloads, now=100.0)

    self.assertEqual(reconciled["worker-A"]["worker_state"], "unseen")
    self.assertEqual(reconciled["worker-A"]["ignored_live_reason"], "revision_mismatch")
