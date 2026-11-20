"""RM-221: a finished job whose end attestation failed keeps its results and can retry the attestation."""
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.models import CStoreJobFinalized, JobArchive, PassReport
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied

from . import test_api as api_fixtures

ARCHIVE = {
  "archive_version": 1, "job_id": "retry-job", "job_config": {}, "timeline": [], "ui_aggregate": {},
  "duration": 0, "date_created": 0, "date_completed": 0,
  "passes": [{"pass_nr": 1, "date_started": 1, "date_completed": 2, "risk_score": 50,
              "aggregated_report_cid": "QmAggregate",
              "worker_reports": {"node-a": {"node_ip": "192.0.2.1"}, "node-b": {"node_ip": "192.0.2.2"}},
              "findings": [{"finding_id": "f-1", "title": "Issue"}]}],
}


def _stub(**fields):
  case = api_fixtures.TestPhase5Endpoints()
  stub = {**case._build_finalized_stub("retry-job"), "scan_type": "network", "risk_score": 50,
          "attestation_status": "failed", "attestation_failure_reason": "account_changed", **fields}
  return case, stub


def _plugin(case, stub, archive=ARCHIVE):
  Plugin = case._get_plugin_class()
  plugin = case._build_plugin({"retry-job": stub})
  plugin.r1fs.get_json.return_value = archive
  actor = case._read_actor(plugin)
  plugin._write_job_record = MagicMock(side_effect=lambda job_id, value, **kwargs: value)
  plugin._submit_redmesh_test_attestation = MagicMock(return_value={"tx_hash": "0xretry"})
  plugin._attestation_get_tenant_private_key = MagicMock(return_value="key")
  plugin._execution_service().execution_basis_end_reason.return_value = None  # engagement and contract valid
  return Plugin, plugin, actor


def _retry(Plugin, plugin, actor, case):
  return Plugin.retry_job_attestation(plugin, job_id="retry-job", request_actor=actor, tenant_id=case._tenant_id)


def test_retry_submits_the_end_attestation_from_the_archive_without_rescanning():
  case, stub = _stub(worker_count=3)  # three workers assigned, two reported in the last pass
  Plugin, plugin, actor = _plugin(case, stub)
  with patch("extensions.business.cybersec.red_mesh.services.event_hooks.emit_attestation_status_event") as soc:
    result = _retry(Plugin, plugin, actor, case)
  assert result == {"success": True, "attestation_status": "submitted", "tx_hash": "0xretry"}
  args, kwargs = plugin._submit_redmesh_test_attestation.call_args
  assert (len(args[2]), kwargs["vulnerability_score"], kwargs["report_cid"], kwargs["node_ips"]) == (
    3, 50, "QmAggregate", ["192.0.2.1", "192.0.2.2"])
  assert soc.call_args.kwargs == {"state": "submitted", "network": plugin.REDMESH_ATTESTATION_NETWORK,
                                  "tx_hash": "0xretry"}
  claim, settle = (call.args[1] for call in plugin._write_job_record.call_args_list)
  assert claim["attestation_status"] == "submitting" and not claim.get("attestation_failure_reason")
  assert settle["attestation_status"] == "submitted" and settle["redmesh_test_attestation"] == {
    "tx_hash": "0xretry", "network": plugin.REDMESH_ATTESTATION_NETWORK}
  assert plugin._log_audit_event.call_args.args[1]["outcome"] == "submitted"
  assert not plugin.scan_jobs.mock_calls  # nothing was rescanned or restarted


def test_a_failed_retry_settles_back_to_failed_with_its_reason():
  case, stub = _stub()
  Plugin, plugin, actor = _plugin(case, stub)
  plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
  result = _retry(Plugin, plugin, actor, case)
  assert result == {"success": False, "attestation_status": "failed", "attestation_failure_reason": "submit_failed"}
  assert plugin._write_job_record.call_args.args[1]["attestation_status"] == "failed"


def test_only_a_failed_attestation_can_be_retried():
  for status in ("submitted", "submitting", None):
    case, stub = _stub(attestation_status=status)
    Plugin, plugin, actor = _plugin(case, stub)
    assert _retry(Plugin, plugin, actor, case) == {
      "success": False, "error": "attestation_not_failed", "status_code": 409}
    plugin._submit_redmesh_test_attestation.assert_not_called()
    plugin._write_job_record.assert_not_called()


def test_a_refused_reauthorization_blocks_the_retry_names_the_reason_and_audits_it():
  for error, expected in (("account_changed", "account_changed"), ("", "forbidden")):  # an empty code fails closed
    case, stub = _stub()
    Plugin, plugin, actor = _plugin(case, stub)
    service = MagicMock()
    service.reauthorize_execution.side_effect = AdministrationDenied(409, error)
    plugin._execution_service = lambda: service
    result = _retry(Plugin, plugin, actor, case)
    assert (result["error"], result["attestation_failure_reason"]) == ("execution_denied", expected)
    plugin._submit_redmesh_test_attestation.assert_not_called()
    plugin._write_job_record.assert_not_called()  # not claimed: the record is left alone
    assert plugin._log_audit_event.call_args.args == (
      "attestation_retry", {"job_id": "retry-job", "actor": "reader", "outcome": "denied", "reason": expected})


def test_an_ended_engagement_or_an_unreadable_store_blocks_the_retry():
  from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
  for ended, expected in (("engagement_revoked", "engagement_revoked"), ("engagement_expired", "engagement_expired"),
                          ("contract_invalid", "contract_invalid"),
                          (TenantStoreError("down"), "store_unavailable")):  # owner 2026-11-20: active engagements only
    case, stub = _stub()
    Plugin, plugin, actor = _plugin(case, stub)
    service = plugin._execution_service()
    service.execution_basis_end_reason = MagicMock(side_effect=ended if isinstance(ended, Exception) else None,
                                              return_value=None if isinstance(ended, Exception) else ended)
    plugin._execution_service = lambda: service
    result = _retry(Plugin, plugin, actor, case)
    assert (result["error"], result["attestation_failure_reason"]) == ("execution_denied", expected)
    plugin._submit_redmesh_test_attestation.assert_not_called()
    plugin._write_job_record.assert_not_called()


def test_a_failing_soc_event_still_settles_and_audits_the_submitted_retry():
  case, stub = _stub()
  Plugin, plugin, actor = _plugin(case, stub)
  with patch("extensions.business.cybersec.red_mesh.services.event_hooks.emit_attestation_status_event",
             side_effect=RuntimeError("no export secret")):
    result = _retry(Plugin, plugin, actor, case)
  assert result == {"success": True, "attestation_status": "submitted", "tx_hash": "0xretry"}
  assert plugin._write_job_record.call_args.args[1]["attestation_status"] == "submitted"
  assert plugin._log_audit_event.call_args.args[1]["outcome"] == "submitted"


def test_a_settle_failure_after_a_submit_still_returns_and_audits_the_tx_hash():
  for settle in (None, RuntimeError("cstore down")):  # the settle write is refused, or raises
    case, stub = _stub()
    Plugin, plugin, actor = _plugin(case, stub)
    plugin._write_job_record = MagicMock(side_effect=[stub, settle])  # claim lands, settle fails
    result = _retry(Plugin, plugin, actor, case)
    assert result == {"success": False, "error": "conflict", "status_code": 409, "tx_hash": "0xretry"}
    assert plugin._log_audit_event.call_args.args[1]["outcome"] == "settle_failed"
    assert plugin._log_audit_event.call_args.args[1]["tx_hash"] == "0xretry"


def test_a_model_test_retry_attests_the_stub_worker_count():
  case, stub = _stub(job_type="model_test", scan_type="model_test", worker_count=1)
  Plugin, plugin, actor = _plugin(
    case, stub, archive={"job_id": "retry-job", "ui_aggregate": {"worker_result_cid": "QmWorker"}})
  assert _retry(Plugin, plugin, actor, case)["success"] is True
  args, kwargs = plugin._submit_redmesh_test_attestation.call_args
  assert (len(args[2]), kwargs["report_cid"], kwargs["vulnerability_score"]) == (1, "QmWorker", 0)


def test_a_caller_without_the_operation_or_another_tenants_job_is_refused_before_any_submit():
  from .read_endpoint_fixtures import install_tenant_read_store
  case, stub = _stub()
  Plugin, plugin, actor = _plugin(case, stub)
  weak, tenant = install_tenant_read_store(case, plugin, Plugin, jobs={"retry-job": stub}, role="tenant_user")
  denied = Plugin.retry_job_attestation(plugin, job_id="retry-job", request_actor=weak, tenant_id=tenant)
  assert (denied["success"], denied["status_code"]) == (False, 403)
  foreign = Plugin.retry_job_attestation(
    plugin, job_id="retry-job", request_actor=actor, tenant_id="tn_00000000-0000-4000-8000-000000000000")
  assert foreign["success"] is False and foreign["status_code"] in (403, 404)
  plugin._submit_redmesh_test_attestation.assert_not_called()
  plugin._write_job_record.assert_not_called()


def test_a_lost_claim_submits_nothing():
  case, stub = _stub()
  Plugin, plugin, actor = _plugin(case, stub)
  plugin._write_job_record = MagicMock(return_value=None)
  assert _retry(Plugin, plugin, actor, case)["error"] == "conflict"
  plugin._submit_redmesh_test_attestation.assert_not_called()


def test_a_legacy_attestation_failed_archive_stays_readable():
  case, stub = _stub(job_status="FAILED", failure_class="attestation_failed", attestation_status=None)
  Plugin, plugin, actor = _plugin(case, stub)
  args = dict(job_id="retry-job", request_actor=actor, tenant_id=case._tenant_id)
  archive = Plugin.get_job_archive(plugin, **args)["archive"]
  assert archive["passes"][0]["findings"][0]["finding_id"] == "f-1" and archive["passes"][0]["risk_score"] == 50
  job = Plugin.get_job_data(plugin, **args)["job"]
  assert (job["job_status"], job["failure_class"], job["job_cid"]) == ("FAILED", "attestation_failed", "QmArchiveCID")
  # Not a retry candidate: only a record that carries attestation_status failed can be retried.
  assert _retry(Plugin, plugin, actor, case)["error"] == "attestation_not_failed"


def test_the_attestation_and_narrative_reasons_survive_the_models():
  stub = CStoreJobFinalized.from_dict({
    **_stub()[1], "redmesh_test_attestation": {"tx_hash": "0x1"}, "attestation_status": "submitted"}).to_dict()
  assert (stub["attestation_status"], stub["redmesh_test_attestation"]["tx_hash"]) == ("submitted", "0x1")
  archive = JobArchive.from_dict({**ARCHIVE, "attestation_status": "failed",
                                  "attestation_failure_reason": "identity_mismatch"}).to_dict()
  assert (archive["attestation_status"], archive["attestation_failure_reason"]) == ("failed", "identity_mismatch")
  report = PassReport.from_dict({**ARCHIVE["passes"][0], "llm_failed": True,
                                 "llm_failure_reason": "execution_authority_denied"}).to_dict()
  assert report["llm_failure_reason"] == "execution_authority_denied"
