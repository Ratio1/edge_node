"""Execution guards through the real finalization, aggregation and provider path."""
from concurrent.futures import Future
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import requests

from extensions.business.cybersec.red_mesh.mixins.redmesh_llm_agent import _RedMeshLlmAgentMixin
from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin
from extensions.business.cybersec.red_mesh.services.finalization import maybe_finalize_pass
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest


def execution_binding():
  target = {"kind": "network", "address": "192.0.2.10"}
  return {
    "schema_version": 1, "namespace": "deployment",
    "tenant_id": "tn_11111111-1111-4111-8111-111111111111",
    "asset_id": "as_22222222-2222-4222-8222-222222222222",
    "asset_target": target, "asset_target_digest": canonical_digest(target),
    "actor_id": "actor", "actor_generation": "generation-1",
    "node_failure_policy": "stop", "original_launcher": "node-a",
    "participant_order": ["node-a"],
  }


class MemoryArtifacts:
  def __init__(self, values):
    self.values = deepcopy(values)
    self.reads = []
    self.writes = []
    self.after_write = None

  def get_json(self, cid):
    self.reads.append(cid)
    return deepcopy(self.values.get(cid))

  def add_json(self, value, **kwargs):
    self.writes.append(deepcopy(value))
    cid = f"artifact-{len(self.writes)}"
    self.values[cid] = deepcopy(value)
    if self.after_write is not None:
      self.after_write()
    return cid


class QueuedExecutor:
  def __init__(self):
    self.submissions = []

  def submit(self, fn, *args, **kwargs):
    future = Future()
    self.submissions.append((future, fn, args, kwargs))
    return future

  def run(self, index=0):
    future, fn, args, kwargs = self.submissions[index]
    if future.set_running_or_notify_cancel():
      try:
        future.set_result(fn(*args, **kwargs))
      except Exception as exc:
        future.set_exception(exc)


class FinalizationOwner(_RedMeshLlmAgentMixin, _ReportMixin, _RiskScoringMixin):
  """Runtime/store/provider boundaries are fake; report and finalization code is real."""

  def __init__(self, *, bound=True, continuous=False):
    self.ee_addr = "node-a"
    self.ee_id = "node-a"
    self.cfg_instance_id = "deployment"
    self.cfg_llm_agent = {"ENABLED": True, "PROVIDER": "remote", "MODEL": "deepseek-chat"}
    self.cfg_monitor_interval = 60
    self.cfg_monitor_jitter = 0
    self.cfg_event_export = {"ENABLED": False}
    self.cfg_wazuh = {"ENABLED": False}
    self.REDMESH_ATTESTATION_NETWORK = "fixture"
    self.current_allowed = True
    self.new_pass_allowed = True
    self.authority_checks = []
    self.executor = QueuedExecutor()
    self.provider_calls = []
    self.attestations = []
    self.archives = []
    self.completed_jobs_reports = {}
    self.lst_completed_jobs = []
    self._automatic_analysis_state = None
    self.job = {
      "job_id": "job-1", "job_status": "RUNNING", "job_pass": 1, "job_revision": 0,
      "run_mode": "CONTINUOUS_MONITORING" if continuous else "SINGLEPASS",
      "launcher": "node-a", "target": "192.0.2.10", "scan_type": "network",
      "start_port": 443, "end_port": 443, "date_created": 1,
      "job_config_cid": "config", "workers": {"node-a": {
        "finished": True, "report_cid": "worker-report", "start_port": 443, "end_port": 443,
      }}, "pass_reports": [], "timeline": [],
    }
    config = {"target": "192.0.2.10", "start_port": 443, "end_port": 443,
              "created_by_id": "actor", "monitor_interval": 60}
    if bound:
      self.job["execution_binding"] = execution_binding()
      config["execution_binding"] = execution_binding()
    self.r1fs = MemoryArtifacts({
      "config": config,
      "worker-report": {"target": "192.0.2.10", "start_port": 443, "end_port": 443,
                        "ports_scanned": 1, "open_ports": [443], "service_info": {},
                        "web_tests_info": {}, "completed_tests": ["port_scan"]},
    })

  def P(self, *args, **kwargs):
    pass

  Pd = P
  _log_audit_event = P
  _clear_live_progress = P

  def time(self):
    return 100

  def chainstore_hgetall(self, hkey):
    return {"job-1": deepcopy(self.job)} if hkey == self.cfg_instance_id else {}

  def chainstore_hget(self, hkey, key):
    return deepcopy(self.job) if hkey == self.cfg_instance_id and key == "job-1" else None

  def _normalize_job_record(self, key, value):
    return key, value

  def _write_job_record(self, key, value, **kwargs):
    value = deepcopy(value)
    value["job_revision"] = self.job["job_revision"] + 1
    self.job = value
    return deepcopy(value)

  def _get_job_from_cstore(self, job_id):
    return self.chainstore_hget(self.cfg_instance_id, job_id)

  def _get_job_config(self, job_specs, **kwargs):
    return self.r1fs.get_json(job_specs["job_config_cid"])

  def _execution_operation_allowed(self, job_specs, *, operation="current", config=None, **kwargs):
    self.authority_checks.append((operation, deepcopy(job_specs), deepcopy(config)))
    return self.new_pass_allowed if operation == "new_pass" else self.current_allowed

  def _get_timeline_date(self, *args):
    return 1

  def _emit_timeline_event(self, job_specs, event, label, **kwargs):
    job_specs["timeline"].append({"type": event, "label": label})

  def _build_job_archive(self, key, job_specs):
    self.archives.append(deepcopy(job_specs))
    self.job = deepcopy(job_specs)

  def _get_manual_analysis_executor(self):
    return self.executor

  def _submit_redmesh_test_attestation(self, **kwargs):
    self.attestations.append(kwargs)
    return {"tx_hash": "fixture-transaction"}

  def _call_llm_agent_api(self, **kwargs):
    self.provider_calls.append(kwargs)
    return {"choices": [{"message": {"content": json.dumps({
      "executive_headline": "Verified exposure needs remediation.",
      "background_draft": "Authorized external assessment.",
      "overall_posture": "The assessment found exposed services requiring review.",
      "recommendation_summary": ["Review the exposed services."],
      "strategic_roadmap": {"near_term": ["Review exposure."], "mid_term": ["Add tests."],
                            "long_term": ["Maintain assurance."]},
      "attack_chain_narratives": ["Exposure may allow unauthorized access."],
      "coverage_gaps": ["Social engineering was outside scope."],
      "conclusion": "Review and retest the exposed services.",
    })}}]}


class TestTenantExecutionFinalization(unittest.TestCase):
  def test_denied_analysis_still_preserves_the_completed_pass(self):
    owner = FinalizationOwner()
    owner.current_allowed = False

    maybe_finalize_pass(owner)

    self.assertEqual(owner.executor.submissions, [])
    self.assertEqual(owner.provider_calls, [])
    self.assertEqual(owner.job["job_status"], "FINALIZED")
    self.assertEqual(len(owner.job["pass_reports"]), 1)
    self.assertIn("worker-report", owner.r1fs.reads)
    self.assertEqual(owner.archives[0]["execution_binding"], execution_binding())

  def test_new_pass_denial_preserves_finished_assignments_and_reports(self):
    owner = FinalizationOwner(continuous=True)
    owner.new_pass_allowed = False
    owner.job["next_pass_at"] = 50
    owner.job["pass_reports"] = [{"pass_nr": 1, "report_cid": "completed-pass"}]
    original = deepcopy(owner.job)

    maybe_finalize_pass(owner)

    self.assertEqual(owner.job, original)
    self.assertEqual(owner.executor.submissions, [])

  def test_queued_analysis_rechecks_authority_at_the_actual_provider_call(self):
    owner = FinalizationOwner()
    maybe_finalize_pass(owner)
    self.assertEqual(len(owner.executor.submissions), 1)
    owner.current_allowed = False

    owner.executor.run()

    self.assertEqual(owner.provider_calls, [])

  def test_queued_analysis_rejects_changed_execution_identity(self):
    for field, value in (
      ("launcher", "node-b"), ("job_revision", 100), ("job_pass", 2),
      ("execution_binding", None), ("job_status", "STOPPED"),
    ):
      with self.subTest(field=field):
        owner = FinalizationOwner()
        maybe_finalize_pass(owner)
        owner.job[field] = value
        owner.executor.run()
        self.assertEqual(owner.provider_calls, [])

  def test_changed_revision_discards_a_completed_analysis_before_publication(self):
    owner = FinalizationOwner()
    maybe_finalize_pass(owner)
    owner.executor.run()
    self.assertTrue(owner.provider_calls)
    owner.job["job_revision"] += 1

    maybe_finalize_pass(owner)

    self.assertEqual(owner.r1fs.writes, [])
    self.assertEqual(owner.archives, [])

  def test_revocation_cancels_queued_analysis_and_finishes_saved_reports(self):
    owner = FinalizationOwner()
    maybe_finalize_pass(owner)
    future = owner.executor.submissions[0][0]
    owner.current_allowed = False

    maybe_finalize_pass(owner)

    self.assertTrue(future.cancelled())
    self.assertEqual(owner.job["job_status"], "FINALIZED")
    self.assertEqual(owner.provider_calls, [])
    self.assertEqual(len(owner.job["pass_reports"]), 1)

  def test_denied_bound_finalization_sends_neither_attestation_nor_soc_events(self):
    owner = FinalizationOwner()
    owner.current_allowed = False
    owner.job["blockchain_attestation_enabled"] = True
    owner.cfg_event_export = {"ENABLED": True, "SIGN_PAYLOADS": False}
    owner.cfg_wazuh_export = {"ENABLED": True, "MODE": "syslog", "SYSLOG_HOST": "192.0.2.20"}
    with patch("extensions.business.cybersec.red_mesh.services.log_export.socket.socket") as socket:
      maybe_finalize_pass(owner)
      self.assertEqual(owner.attestations, [])
      socket.return_value.__enter__.return_value.sendto.assert_not_called()
    self.assertEqual(len(owner.job["pass_reports"]), 1)

  def test_provider_http_retries_recheck_authority_after_the_first_response(self):
    class ProviderTransportOwner(FinalizationOwner):
      _call_llm_agent_api = _RedMeshLlmAgentMixin._call_llm_agent_api
    owner = ProviderTransportOwner()
    owner.cfg_llm_agent_api_host = "provider.example"
    owner.cfg_llm_agent_api_port = 8080
    owner.cfg_llm_api_retries = 2
    maybe_finalize_pass(owner)

    def revoke_after_response(*args, **kwargs):
      owner.current_allowed = False
      response = requests.Response()
      response.status_code = 503
      response._content = b'{"error":"unavailable"}'
      return response

    with patch("requests.post", side_effect=revoke_after_response) as post:
      owner.executor.run()
      self.assertEqual(post.call_count, 1)

  def test_finalization_effects_recheck_the_current_owner_after_local_storage(self):
    owner = FinalizationOwner()
    owner.cfg_llm_agent["ENABLED"] = False
    owner.job["blockchain_attestation_enabled"] = True
    def change_owner():
      owner.job["launcher"] = "node-b"
    owner.r1fs.after_write = change_owner

    maybe_finalize_pass(owner)

    self.assertEqual(len(owner.attestations), 0)

  def test_completed_analysis_is_rechecked_immediately_before_pass_publication(self):
    owner = FinalizationOwner()
    maybe_finalize_pass(owner)
    owner.executor.run()
    def revoke():
      owner.current_allowed = False
    owner.r1fs.after_write = revoke

    maybe_finalize_pass(owner)

    pass_reports = [value for value in owner.r1fs.writes if "worker_reports" in value]
    self.assertEqual(len(pass_reports), 1)
    self.assertIsNone(pass_reports[0].get("llm_report_sections"))
    self.assertEqual(len(owner.job["pass_reports"]), 1)

  def test_unchanged_authorized_analysis_is_published_with_completed_reports(self):
    owner = FinalizationOwner()
    maybe_finalize_pass(owner)
    owner.executor.run()
    maybe_finalize_pass(owner)
    pass_reports = [value for value in owner.r1fs.writes if "worker_reports" in value]
    self.assertEqual(pass_reports[0]["llm_report_sections"]["executive_headline"],
                     "Verified exposure needs remediation.")
    self.assertEqual(owner.job["job_status"], "FINALIZED")

  def test_legacy_restart_supplies_saved_creator_config_to_new_pass_authority(self):
    owner = FinalizationOwner(bound=False, continuous=True)
    owner.job["next_pass_at"] = 50
    maybe_finalize_pass(owner)
    self.assertEqual(owner.job["job_pass"], 2)
    self.assertEqual(owner.authority_checks[0][0], "new_pass")
    self.assertEqual(owner.authority_checks[0][2]["created_by_id"], "actor")

  def test_missing_authority_seam_denies_bound_analysis_and_legacy_restart(self):
    class MissingGuardOwner(FinalizationOwner):
      _execution_operation_allowed = None
    owner = MissingGuardOwner()
    maybe_finalize_pass(owner)
    self.assertEqual(len(owner.executor.submissions), 0)
    self.assertEqual(owner.job["job_status"], "FINALIZED")
    legacy = MissingGuardOwner(bound=False, continuous=True)
    legacy.job["next_pass_at"] = 50
    original = deepcopy(legacy.job)
    maybe_finalize_pass(legacy)
    self.assertEqual(legacy.job, original)

  def test_authority_lost_during_analysis_state_write_prevents_executor_submission(self):
    class RevokedDuringWriteOwner(FinalizationOwner):
      def _write_job_record(self, key, value, **kwargs):
        result = super()._write_job_record(key, value, **kwargs)
        if value["job_status"] == "ANALYZING":
          self.current_allowed = False
        return result
    owner = RevokedDuringWriteOwner()
    maybe_finalize_pass(owner)
    self.assertEqual(len(owner.executor.submissions), 0)
    self.assertEqual(owner.job["job_status"], "FINALIZED")
