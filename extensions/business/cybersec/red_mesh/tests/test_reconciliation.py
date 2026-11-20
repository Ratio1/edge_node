import pickle
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from .conftest import mock_plugin_modules
from .test_worker_checkpoint import _Owner
from extensions.business.cybersec.red_mesh.services import checkpoint as ckpt

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

  def test_reconcile_workers_from_terminal_error_stops_job(self):
    job_specs = {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "job_pass": 2,
      "launcher": "launcher-A",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "assignment_revision": 3},
      },
    }
    live_payloads = self._terminal_live_payload(cid=None)
    live_payloads["job-1:worker-A"]["phase"] = "failed"
    live_payloads["job-1:worker-A"]["error_class"] = "launch_failed"
    owner, _repo = self._make_live_reconcile_owner(job_specs, live_payloads)

    changed = reconcile_workers_from_live(owner, "job-1")

    self.assertTrue(changed)
    self.assertEqual(job_specs["job_status"], "STOPPED")
    worker = job_specs["workers"]["worker-A"]
    self.assertTrue(worker["finished"])
    self.assertEqual(worker["terminal_reason"], "launch_failed")
    owner._write_job_record.assert_called_once_with(
      "job-1", job_specs, context="reconcile_from_live",
    )

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


CKPT_CTX = {
  "pass_nr": 2, "ee_addr": "node-1", "scan_type": "network", "start_port": 1, "end_port": 6,
  "target_ports": None, "config_cid": "cid1", "redact_credentials": True,
}


class _RefusedByUnpickler:
  def __reduce__(self):
    return (print, ("x",))


class TestResumePayloadRules(unittest.TestCase):
  """`_load_resume_payloads` decides resume or fresh launch from the saved checkpoints (RM-201)."""

  def setUp(self):
    if "extensions.business.cybersec.red_mesh.pentester_api_01" not in sys.modules:
      mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    self.plugin = PentesterApi01Plugin
    self.tmp = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.owner = _Owner(self.tmp, config={"WORKER_CHECKPOINT": {"MAX_AGE": 100}})
    self.logs = []
    self.owner.P = lambda msg, **k: self.logs.append(msg)

  def _payload(self, prefix, ports, **over):
    ctx = {k: v for k, v in CKPT_CTX.items() if k != "redact_credentials"}
    payload = dict(
      ctx, version=ckpt.CHECKPOINT_VERSION, job_id="job1", local_id_prefix=prefix,
      local_worker_id=f"RM-{prefix}-abcd", initial_ports=list(ports), state={"ports_scanned": []},
      metrics={}, ics_detected=False, saved_at=time.time(),
    )
    payload.update(over)
    return payload

  def _save(self, *payloads):
    for payload in payloads:
      ckpt.save(self.owner, "job1", payload["pass_nr"], payload["local_id_prefix"], payload)

  def _full_set(self, **over):
    return [self._payload("1", [1, 2, 3], **over), self._payload("2", [4, 5, 6], **over)]

  def _load(self, status="RUNNING", finished=False, ctx=None, config=None):
    return self.plugin._load_resume_payloads(
      self.owner, "job1", {"job_status": status}, config or {}, ctx or dict(CKPT_CTX), finished,
    )

  def _files(self, pass_nr=2):
    return sorted(ckpt.load_all(self.owner, "job1", pass_nr))

  def test_matching_complete_set_resumes_every_worker(self):
    self._save(*self._full_set())
    got = self._load()
    self.assertEqual(sorted(p["local_id_prefix"] for p in got), ["1", "2"])
    self.assertEqual(self._files(), ["1", "2"])
    self.assertEqual(self.logs, ["Resuming 2 workers of job job1 pass 2 from checkpoints"])

  def test_scheduled_for_stop_still_resumes(self):
    self._save(*self._full_set())
    self.assertEqual(len(self._load(status="SCHEDULED_FOR_STOP")), 2)

  def test_resume_after_reannounce_ignores_assignment_revision(self):
    # Saved under revision 1; the launcher reannounced the same slice as revision 3. The context
    # carries no revision, so the same checkpoints resume.
    self._save(*self._full_set())
    self.assertNotIn("assignment_revision", CKPT_CTX)
    self.assertEqual(len(self._load()), 2)

  def test_partial_set_starts_fresh_and_deletes_the_pass(self):
    self._save(self._payload("1", [1, 2, 3]))  # worker 2 never saved
    self._save(self._payload("1", [1, 2, 3], pass_nr=1))
    self.assertIsNone(self._load())
    self.assertEqual(self._files(), [])
    self.assertEqual(self._files(pass_nr=1), ["1"])  # another pass is untouched
    self.assertEqual(len(self.logs), 1)
    self.assertIn("do not cover the slice", self.logs[0])

  def test_each_failed_rule_discards_all_checkpoints(self):
    cases = {
      "job stopped": dict(status="STOPPED"),
      "job finalized": dict(status="FINALIZED"),
      "worker finished": dict(finished=True),
      "other node": dict(over=dict(ee_addr="node-2")),
      "start_port": dict(over=dict(start_port=2)),
      "end_port": dict(over=dict(end_port=7)),
      "target_ports": dict(over=dict(target_ports=[1, 2])),
      "config_cid": dict(over=dict(config_cid="other")),
      "scan_type": dict(over=dict(scan_type="webapp")),
      "job_id": dict(over=dict(job_id="job9")),
      "too old": dict(over=dict(saved_at=time.time() - 101)),
      "future": dict(over=dict(saved_at=time.time() + 1000)),
      "malformed": dict(over=dict(state=[])),
    }
    for name, case in cases.items():
      with self.subTest(name):
        shutil.rmtree(f"{self.tmp}/{self.owner.INSTANCE}", ignore_errors=True)
        self._save(*self._full_set(**case.get("over", {})))
        got = self._load(status=case.get("status", "RUNNING"), finished=case.get("finished", False))
        self.assertIsNone(got)
        self.assertEqual(self._files(), [])

  def test_ports_outside_the_slice_discard_the_pass(self):
    cases = {
      "open port outside": {"open_ports": [99]},
      "excluded port open": {"open_ports": [3]},
      "scanned outside": {"ports_scanned": [99]},
      "protocol key outside": {"port_protocols": {99: "http"}},
      "service key outside": {"service_info": {99: {}}},
      "web key outside": {"web_tests_info": {"99": {}}},
      "banner key outside": {"port_banners": {99: ""}},
      "non-port key": {"open_ports": [None]},
    }
    for name, state in cases.items():
      with self.subTest(name):
        shutil.rmtree(f"{self.tmp}/{self.owner.INSTANCE}", ignore_errors=True)
        first = self._payload("1", [1, 2], state=dict(state))
        self._save(first, self._payload("2", [4, 5, 6]))
        got = self._load(config={"exceptions": [3]})
        self.assertIsNone(got)
        self.assertEqual(self._files(), [])

  def test_duplicate_open_or_scanned_ports_discard_the_pass(self):
    for name, state in {
      "open dup": {"open_ports": [1, 1]},
      "scanned dup": {"ports_scanned": [2, 1, 2]},
      "str and int dup": {"open_ports": ["1", 1]},
      "str port": {"ports_scanned": ["2"]},
    }.items():
      with self.subTest(name):
        shutil.rmtree(f"{self.tmp}/{self.owner.INSTANCE}", ignore_errors=True)
        self._save(self._payload("1", [1, 2, 3], state=state), self._payload("2", [4, 5, 6]))
        self.assertIsNone(self._load())
        self.assertEqual(self._files(), [])

  def test_ports_inside_the_slice_pass_with_str_or_int_keys(self):
    state = {"open_ports": [1], "ports_scanned": [1, 2], "port_protocols": {"1": "http"},
             "service_info": {1: {}}, "web_tests_info": {2: {}}}
    self._save(self._payload("1", [1, 2], state=state), self._payload("2", [4, 5, 6]))
    self.assertEqual(len(self._load(config={"exceptions": [3]})), 2)

  def test_worker_id_must_match_the_generator_format_and_be_unique(self):
    for name, ids in {
      "no prefix": ("RM-9-abcd", "RM-2-abcd"),
      "bad chars": ("RM-1-zzzz", "RM-2-abcd"),
      "too long": ("RM-1-abcde", "RM-2-abcd"),
      "traversal": ("RM-1-../..", "RM-2-abcd"),
      "other worker's id": ("RM-1-abcd", "RM-1-abcd"),
    }.items():
      with self.subTest(name):
        shutil.rmtree(f"{self.tmp}/{self.owner.INSTANCE}", ignore_errors=True)
        self._save(self._payload("1", [1, 2, 3], local_worker_id=ids[0]),
                   self._payload("2", [4, 5, 6], local_worker_id=ids[1]))
        self.assertIsNone(self._load())
        self.assertEqual(self._files(), [])

  def test_prefix_in_file_must_match_filename(self):
    first, second = self._full_set()
    ckpt.save(self.owner, "job1", 2, "1", first)
    ckpt.save(self.owner, "job1", 2, "2", dict(second, local_id_prefix="1"))
    self.assertIsNone(self._load())
    self.assertEqual(self._files(), [])

  def test_overlap_or_extra_or_short_ports_do_not_cover_the_slice(self):
    for name, (first, second) in {
      "overlap": ([1, 2, 3], [3, 4, 5, 6]),
      "extra": ([1, 2, 3], [4, 5, 6, 7]),
      "short": ([1, 2, 3], [4, 5]),
    }.items():
      with self.subTest(name):
        shutil.rmtree(f"{self.tmp}/{self.owner.INSTANCE}", ignore_errors=True)
        self._save(self._payload("1", first), self._payload("2", second))
        self.assertIsNone(self._load())

  def test_exceptions_are_removed_from_the_slice(self):
    self._save(self._payload("1", [1, 2]), self._payload("2", [4, 5, 6]))
    self.assertEqual(len(self._load(config={"exceptions": [3]})), 2)

  def test_target_ports_slice(self):
    ctx = dict(CKPT_CTX, target_ports=[10, 20, 30])
    self._save(self._payload("1", [10, 30], target_ports=[10, 20, 30]),
               self._payload("2", [20], target_ports=[10, 20, 30]))
    self.assertEqual(len(self._load(ctx=ctx)), 2)

  def test_refused_pickle_file_makes_the_set_partial(self):
    good, _ = self._full_set()
    self._save(good)
    path = f"{self.tmp}/{self.owner.INSTANCE}/plugin_data/redmesh_ckpt/job1/2_2.pkl"
    with open(path, "wb") as fh:
      pickle.dump({"version": 1, "x": _RefusedByUnpickler()}, fh)
    self.assertIsNone(self._load())
    self.assertEqual(self._files(), [])

  def test_no_checkpoints_is_silent(self):
    self.assertIsNone(self._load())
    self.assertEqual(self.logs, [])

  def test_unreadable_store_never_blocks_launch(self):
    with patch.object(ckpt, "load_all", side_effect=OSError("disk")):
      self.assertIsNone(self._load())

  def test_log_never_contains_payload_contents(self):
    self._save(*self._full_set(state={"ports_scanned": [], "secret": "hunter2"}))
    self._load()
    self.assertFalse(any("hunter2" in line for line in self.logs))


class TestMaybeLaunchJobsResume(unittest.TestCase):
  """`_maybe_launch_jobs` hands matching checkpoints to `launch_local_jobs` as `restored=`."""

  def _launch(self, payload_ports):
    if "extensions.business.cybersec.red_mesh.pentester_api_01" not in sys.modules:
      mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin as Plugin
    from extensions.business.cybersec.red_mesh.services.launch_api import build_network_workers
    from extensions.business.cybersec.red_mesh.tests.test_execution_binding_models import binding_payload

    tmp = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
    store = _Owner(tmp)
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_check_jobs_each = 15
    plugin.ee_addr = "node-A"
    plugin.scan_jobs = {}
    plugin.completed_jobs_reports = {}
    plugin.lst_completed_jobs = []
    plugin._active_execution_identities = {}
    plugin._execution_live_meta = {}
    plugin._foreign_jobs_logged = set()
    plugin._PentesterApi01Plugin__last_checked_jobs = 0
    plugin.time.return_value = 100.0
    plugin.get_data_folder.return_value = tmp
    plugin._get_instance_data_subfolder.return_value = store.INSTANCE
    plugin._normalize_job_record.side_effect = lambda job_id, payload: (job_id, payload)
    plugin._get_worker_entry = lambda job_id, spec: Plugin._get_worker_entry(plugin, job_id, spec)
    plugin._remember_execution_identity = lambda *a: Plugin._remember_execution_identity(plugin, *a)
    binding = binding_payload()
    plugin._get_job_config.return_value = {"scan_type": "network", "execution_binding": binding}
    workers, error = build_network_workers(plugin, ["node-A"], 1, 100, "MIRROR")
    self.assertIsNone(error)
    entry = workers["node-A"]
    job_specs = {
      "job_id": "job-1", "target": "10.0.0.1", "scan_type": "network", "job_pass": 1,
      "job_status": "RUNNING", "launcher": "node-launcher", "launcher_alias": "rm1",
      "execution_binding": binding, "workers": workers, "job_config_cid": "cid9",
    }
    plugin.chainstore_hgetall.return_value = {"job-1": job_specs}
    for index, ports in enumerate(payload_ports, start=1):
      payload = {
        "version": ckpt.CHECKPOINT_VERSION, "job_id": "job-1", "pass_nr": 1, "ee_addr": "node-A",
        "scan_type": "network", "start_port": entry["start_port"], "end_port": entry["end_port"],
        "target_ports": entry.get("target_ports"), "config_cid": "cid9",
        "local_id_prefix": str(index), "local_worker_id": f"RM-{index}-abcd",
        "initial_ports": ports, "state": {}, "metrics": {}, "ics_detected": False,
        "saved_at": time.time(),
      }
      ckpt.save(store, "job-1", 1, str(index), payload)
    with patch("extensions.business.cybersec.red_mesh.pentester_api_01.launch_local_jobs") as launch:
      Plugin._maybe_launch_jobs(plugin)
    launch.assert_called_once()
    return launch.call_args.kwargs

  def test_matching_checkpoints_are_passed_as_restored(self):
    kwargs = self._launch([list(range(1, 51)), list(range(51, 101))])
    self.assertEqual([p["local_id_prefix"] for p in kwargs["restored"]], ["1", "2"])
    self.assertEqual(kwargs["checkpoint_context"]["config_cid"], "cid9")

  def test_partial_checkpoint_set_launches_fresh(self):
    kwargs = self._launch([list(range(1, 51))])
    self.assertNotIn("restored", kwargs)

  def test_no_checkpoints_launches_as_before(self):
    kwargs = self._launch([])
    self.assertNotIn("restored", kwargs)
