import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.services.config import (
  get_llm_agent_config,
  resolve_config_block,
)
from extensions.business.cybersec.red_mesh.services.reconciliation import (
  get_distributed_job_reconciliation_config,
  reconcile_job_workers,
)


class TestWorkerReconciliation(unittest.TestCase):

  def _make_owner(self, now=100.0, stale_timeout=30):
    owner = MagicMock()
    owner.time.return_value = now
    owner.cfg_distributed_job_reconciliation = {"STALE_TIMEOUT": stale_timeout}
    return owner

  def test_resolve_config_block_uses_defaults(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = None
    owner.CONFIG = {}

    config = resolve_config_block(
      owner,
      "DISTRIBUTED_JOB_RECONCILIATION",
      {"STARTUP_TIMEOUT": 45.0, "STALE_TIMEOUT": 120.0},
    )

    self.assertEqual(config, {"STARTUP_TIMEOUT": 45.0, "STALE_TIMEOUT": 120.0})

  def test_resolve_config_block_merges_partial_override(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = {"STARTUP_TIMEOUT": 20}

    config = resolve_config_block(
      owner,
      "DISTRIBUTED_JOB_RECONCILIATION",
      {"STARTUP_TIMEOUT": 45.0, "STALE_TIMEOUT": 120.0},
    )

    self.assertEqual(config, {"STARTUP_TIMEOUT": 20, "STALE_TIMEOUT": 120.0})

  def test_resolve_config_block_ignores_non_dict_override(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = "bad"
    owner.CONFIG = {"DISTRIBUTED_JOB_RECONCILIATION": {"STARTUP_TIMEOUT": 25}}

    config = resolve_config_block(
      owner,
      "DISTRIBUTED_JOB_RECONCILIATION",
      {"STARTUP_TIMEOUT": 45.0, "STALE_TIMEOUT": 120.0},
    )

    self.assertEqual(config, {"STARTUP_TIMEOUT": 45.0, "STALE_TIMEOUT": 120.0})

  def test_resolve_config_block_returns_copy(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = None
    defaults = {"STARTUP_TIMEOUT": 45.0}

    config = resolve_config_block(owner, "DISTRIBUTED_JOB_RECONCILIATION", defaults)
    config["STARTUP_TIMEOUT"] = 10.0

    self.assertEqual(defaults["STARTUP_TIMEOUT"], 45.0)

  def test_llm_agent_config_uses_defaults(self):
    owner = MagicMock()
    owner.cfg_llm_agent = None
    owner.CONFIG = {}

    config = get_llm_agent_config(owner)

    self.assertEqual(config["ENABLED"], False)
    self.assertEqual(config["TIMEOUT"], 120.0)
    self.assertEqual(config["AUTO_ANALYSIS_TYPE"], "security_assessment")

  def test_llm_agent_config_merges_partial_override(self):
    owner = MagicMock()
    owner.cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 30}

    config = get_llm_agent_config(owner)

    self.assertEqual(config["ENABLED"], True)
    self.assertEqual(config["TIMEOUT"], 30.0)
    self.assertEqual(config["AUTO_ANALYSIS_TYPE"], "security_assessment")

  def test_llm_agent_config_normalizes_invalid_values(self):
    owner = MagicMock()
    owner.cfg_llm_agent = {
      "ENABLED": True,
      "TIMEOUT": 0,
      "AUTO_ANALYSIS_TYPE": "",
    }

    config = get_llm_agent_config(owner)

    self.assertEqual(config["ENABLED"], True)
    self.assertEqual(config["TIMEOUT"], 120.0)
    self.assertEqual(config["AUTO_ANALYSIS_TYPE"], "security_assessment")

  def test_reconciliation_config_uses_defaults(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = None
    owner.CONFIG = {}

    config = get_distributed_job_reconciliation_config(owner)

    self.assertEqual(config["STARTUP_TIMEOUT"], 45.0)
    self.assertEqual(config["STALE_TIMEOUT"], 120.0)
    self.assertEqual(config["STALE_GRACE"], 30.0)
    self.assertEqual(config["MAX_REANNOUNCE_ATTEMPTS"], 3)

  def test_reconciliation_config_merges_partial_override(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = {"STARTUP_TIMEOUT": 20}

    config = get_distributed_job_reconciliation_config(owner)

    self.assertEqual(config["STARTUP_TIMEOUT"], 20.0)
    self.assertEqual(config["STALE_TIMEOUT"], 120.0)
    self.assertEqual(config["STALE_GRACE"], 30.0)
    self.assertEqual(config["MAX_REANNOUNCE_ATTEMPTS"], 3)

  def test_reconciliation_config_normalizes_invalid_values(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = {
      "STARTUP_TIMEOUT": 0,
      "STALE_TIMEOUT": -1,
      "STALE_GRACE": -5,
      "MAX_REANNOUNCE_ATTEMPTS": "bad",
    }

    config = get_distributed_job_reconciliation_config(owner)

    self.assertEqual(config["STARTUP_TIMEOUT"], 45.0)
    self.assertEqual(config["STALE_TIMEOUT"], 120.0)
    self.assertEqual(config["STALE_GRACE"], 30.0)
    self.assertEqual(config["MAX_REANNOUNCE_ATTEMPTS"], 3)

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
