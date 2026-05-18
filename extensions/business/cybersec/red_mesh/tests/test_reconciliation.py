import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.services.config import (
  get_attestation_config,
  get_graybox_budgets_config,
  get_llm_agent_config,
  resolve_config_block,
)
from extensions.business.cybersec.red_mesh.services.reconciliation import (
  DEFAULT_LIVE_HSYNC_INTERVAL_SECONDS,
  get_distributed_job_reconciliation_config,
  reconcile_job_workers,
  reconcile_workers_from_live,
)


class TestWorkerReconciliation(unittest.TestCase):

  def _make_owner(self, now=100.0, stale_timeout=30):
    owner = MagicMock()
    owner.time.return_value = now
    owner.cfg_distributed_job_reconciliation = {"STALE_TIMEOUT": stale_timeout}
    return owner

  def _make_live_reconcile_owner(self, job_specs, live_payloads=None):
    owner = MagicMock()
    owner.ee_addr = "launcher-A"
    repo = MagicMock()
    repo.get_job.return_value = job_specs
    repo.list_live_progress.return_value = live_payloads or {}
    owner._get_job_state_repository.return_value = repo
    owner._normalize_job_record.return_value = (job_specs.get("job_id", "job-1"), job_specs)
    owner._emit_timeline_event = MagicMock()
    owner._write_job_record = MagicMock()
    return owner, repo

  def _terminal_live_payload(self, job_id="job-1", worker_addr="worker-A", pass_nr=2, revision=3, cid="QmAAA"):
    return {
      f"{job_id}:{worker_addr}": {
        "job_id": job_id,
        "worker_addr": worker_addr,
        "pass_nr": pass_nr,
        "assignment_revision_seen": revision,
        "progress": 100.0,
        "phase": "done",
        "ports_scanned": 10,
        "ports_total": 10,
        "open_ports_found": [80],
        "completed_tests": ["correlation_completed"],
        "updated_at": 100.0,
        "started_at": 90.0,
        "first_seen_live_at": 90.0,
        "last_seen_at": 100.0,
        "finished": True,
        "report_cid": cid,
      },
    }

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

  def test_attestation_config_uses_defaults(self):
    owner = MagicMock()
    owner.cfg_attestation = None
    owner.CONFIG = {}

    config = get_attestation_config(owner)

    self.assertEqual(config["ENABLED"], True)
    self.assertEqual(config["PRIVATE_KEY"], "")
    self.assertEqual(config["MIN_SECONDS_BETWEEN_SUBMITS"], 86400.0)
    self.assertEqual(config["RETRIES"], 2)

  def test_attestation_config_merges_partial_override(self):
    owner = MagicMock()
    owner.cfg_attestation = {"ENABLED": False, "RETRIES": 5}

    config = get_attestation_config(owner)

    self.assertEqual(config["ENABLED"], False)
    self.assertEqual(config["PRIVATE_KEY"], "")
    self.assertEqual(config["MIN_SECONDS_BETWEEN_SUBMITS"], 86400.0)
    self.assertEqual(config["RETRIES"], 5)

  def test_attestation_config_normalizes_invalid_values(self):
    owner = MagicMock()
    owner.cfg_attestation = {
      "ENABLED": True,
      "PRIVATE_KEY": None,
      "MIN_SECONDS_BETWEEN_SUBMITS": -1,
      "RETRIES": "bad",
    }

    config = get_attestation_config(owner)

    self.assertEqual(config["ENABLED"], True)
    self.assertEqual(config["PRIVATE_KEY"], "")
    self.assertEqual(config["MIN_SECONDS_BETWEEN_SUBMITS"], 86400.0)
    self.assertEqual(config["RETRIES"], 2)

  def test_graybox_budgets_config_uses_defaults(self):
    owner = MagicMock()
    owner.cfg_graybox_budgets = None
    owner.CONFIG = {}

    config = get_graybox_budgets_config(owner)

    self.assertEqual(config["AUTH_ATTEMPTS"], 10)
    self.assertEqual(config["ROUTE_DISCOVERY"], 100)
    self.assertEqual(config["STATEFUL_ACTIONS"], 1)

  def test_graybox_budgets_config_merges_partial_override(self):
    owner = MagicMock()
    owner.cfg_graybox_budgets = {"AUTH_ATTEMPTS": 3, "STATEFUL_ACTIONS": 0}

    config = get_graybox_budgets_config(owner)

    self.assertEqual(config["AUTH_ATTEMPTS"], 3)
    self.assertEqual(config["ROUTE_DISCOVERY"], 100)
    self.assertEqual(config["STATEFUL_ACTIONS"], 0)

  def test_graybox_budgets_config_normalizes_invalid_values(self):
    owner = MagicMock()
    owner.cfg_graybox_budgets = {
      "AUTH_ATTEMPTS": 0,
      "ROUTE_DISCOVERY": -1,
      "STATEFUL_ACTIONS": "bad",
    }

    config = get_graybox_budgets_config(owner)

    self.assertEqual(config["AUTH_ATTEMPTS"], 10)
    self.assertEqual(config["ROUTE_DISCOVERY"], 100)
    self.assertEqual(config["STATEFUL_ACTIONS"], 1)

  def test_reconciliation_config_uses_defaults(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = None
    owner.CONFIG = {}

    config = get_distributed_job_reconciliation_config(owner)

    self.assertEqual(config["STARTUP_TIMEOUT"], 180.0)
    self.assertEqual(config["STALE_TIMEOUT"], 120.0)
    self.assertEqual(config["STALE_GRACE"], 90.0)
    self.assertEqual(config["MAX_REANNOUNCE_ATTEMPTS"], 3)
    self.assertEqual(config["LIVE_HSYNC_ENABLED"], True)
    self.assertEqual(
      config["LIVE_HSYNC_INTERVAL_SECONDS"],
      DEFAULT_LIVE_HSYNC_INTERVAL_SECONDS,
    )
    self.assertEqual(config["LIVE_HSYNC_TIMEOUT"], 3.0)
    self.assertEqual(config["LIVE_HSYNC_MAX_PEERS_PER_TICK"], 6)
    self.assertEqual(config["LIVE_HSYNC_FALLBACK_DEFAULT_PEERS"], True)

  def test_reconciliation_config_merges_partial_override(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = {
      "STARTUP_TIMEOUT": 20,
      "LIVE_HSYNC_ENABLED": True,
      "LIVE_HSYNC_INTERVAL_SECONDS": 120,
      "LIVE_HSYNC_TIMEOUT": 5,
      "LIVE_HSYNC_MAX_PEERS_PER_TICK": 2,
      "LIVE_HSYNC_FALLBACK_DEFAULT_PEERS": False,
    }

    config = get_distributed_job_reconciliation_config(owner)

    self.assertEqual(config["STARTUP_TIMEOUT"], 20.0)
    self.assertEqual(config["STALE_TIMEOUT"], 120.0)
    self.assertEqual(config["STALE_GRACE"], 90.0)
    self.assertEqual(config["MAX_REANNOUNCE_ATTEMPTS"], 3)
    self.assertEqual(config["LIVE_HSYNC_ENABLED"], True)
    self.assertEqual(config["LIVE_HSYNC_INTERVAL_SECONDS"], 120.0)
    self.assertEqual(config["LIVE_HSYNC_TIMEOUT"], 5.0)
    self.assertEqual(config["LIVE_HSYNC_MAX_PEERS_PER_TICK"], 2)
    self.assertEqual(config["LIVE_HSYNC_FALLBACK_DEFAULT_PEERS"], False)

  def test_reconciliation_config_normalizes_invalid_values(self):
    owner = MagicMock()
    owner.cfg_distributed_job_reconciliation = {
      "STARTUP_TIMEOUT": 0,
      "STALE_TIMEOUT": -1,
      "STALE_GRACE": -5,
      "MAX_REANNOUNCE_ATTEMPTS": "bad",
      "LIVE_HSYNC_ENABLED": "not-a-bool",
      "LIVE_HSYNC_INTERVAL_SECONDS": 0,
      "LIVE_HSYNC_TIMEOUT": -3,
      "LIVE_HSYNC_MAX_PEERS_PER_TICK": 0,
      "LIVE_HSYNC_FALLBACK_DEFAULT_PEERS": "not-a-bool",
    }

    config = get_distributed_job_reconciliation_config(owner)

    self.assertEqual(config["STARTUP_TIMEOUT"], 180.0)
    self.assertEqual(config["STALE_TIMEOUT"], 120.0)
    self.assertEqual(config["STALE_GRACE"], 90.0)
    self.assertEqual(config["MAX_REANNOUNCE_ATTEMPTS"], 3)
    self.assertEqual(config["LIVE_HSYNC_ENABLED"], True)
    self.assertEqual(
      config["LIVE_HSYNC_INTERVAL_SECONDS"],
      DEFAULT_LIVE_HSYNC_INTERVAL_SECONDS,
    )
    self.assertEqual(config["LIVE_HSYNC_TIMEOUT"], 3.0)
    self.assertEqual(config["LIVE_HSYNC_MAX_PEERS_PER_TICK"], 6)
    self.assertEqual(config["LIVE_HSYNC_FALLBACK_DEFAULT_PEERS"], True)

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

  def test_reconcile_workers_from_live_repairs_terminal_worker(self):
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {
          "start_port": 1,
          "end_port": 10,
          "finished": False,
          "assignment_revision": 3,
        },
      },
      "timeline": [],
    }
    owner, _repo = self._make_live_reconcile_owner(
      job_specs,
      self._terminal_live_payload(),
    )

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertTrue(changed)
    worker = job_specs["workers"]["worker-A"]
    self.assertEqual(worker["finished"], True)
    self.assertEqual(worker["report_cid"], "QmAAA")
    self.assertIsNone(worker["result"])
    owner._emit_timeline_event.assert_called_once()
    owner._write_job_record.assert_called_once_with(
      "job-1",
      job_specs,
      context="reconcile_from_live",
    )

  def test_reconcile_workers_from_live_is_idempotent(self):
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {
          "start_port": 1,
          "end_port": 10,
          "finished": True,
          "report_cid": "QmAAA",
          "assignment_revision": 3,
        },
      },
      "timeline": [],
    }
    owner, _repo = self._make_live_reconcile_owner(
      job_specs,
      self._terminal_live_payload(),
    )

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertFalse(changed)
    owner._emit_timeline_event.assert_not_called()
    owner._write_job_record.assert_not_called()

  def test_reconcile_workers_from_live_ignores_stale_pass(self):
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    owner, _repo = self._make_live_reconcile_owner(
      job_specs,
      self._terminal_live_payload(pass_nr=1),
    )

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertFalse(changed)
    self.assertNotIn("report_cid", job_specs["workers"]["worker-A"])
    owner._write_job_record.assert_not_called()

  def test_reconcile_workers_from_live_ignores_stale_revision(self):
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    owner, _repo = self._make_live_reconcile_owner(
      job_specs,
      self._terminal_live_payload(revision=2),
    )

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertFalse(changed)
    self.assertNotIn("report_cid", job_specs["workers"]["worker-A"])
    owner._write_job_record.assert_not_called()

  def test_reconcile_workers_from_live_requires_report_cid(self):
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    live_payloads = self._terminal_live_payload(cid=None)
    owner, _repo = self._make_live_reconcile_owner(job_specs, live_payloads)

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertFalse(changed)
    self.assertNotIn("report_cid", job_specs["workers"]["worker-A"])
    owner._write_job_record.assert_not_called()

  def test_reconcile_workers_from_live_skips_canceled_and_unreachable(self):
    job_specs = {
      "job_id": "job-1",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {
          "start_port": 1,
          "end_port": 10,
          "assignment_revision": 3,
          "canceled": True,
        },
        "worker-B": {
          "start_port": 11,
          "end_port": 20,
          "assignment_revision": 3,
          "terminal_reason": "unreachable",
        },
      },
    }
    live_payloads = self._terminal_live_payload()
    live_payloads.update(self._terminal_live_payload(worker_addr="worker-B"))
    owner, _repo = self._make_live_reconcile_owner(job_specs, live_payloads)

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertFalse(changed)
    self.assertNotIn("report_cid", job_specs["workers"]["worker-A"])
    self.assertNotIn("report_cid", job_specs["workers"]["worker-B"])
    owner._write_job_record.assert_not_called()

  def test_reconcile_workers_from_live_skips_finalized_job(self):
    job_specs = {
      "job_id": "job-1",
      "job_cid": "QmFinal",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    owner, _repo = self._make_live_reconcile_owner(
      job_specs,
      self._terminal_live_payload(),
    )

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertFalse(changed)
    owner._write_job_record.assert_not_called()
