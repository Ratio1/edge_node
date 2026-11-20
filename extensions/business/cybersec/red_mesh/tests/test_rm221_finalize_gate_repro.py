"""RM-221 regression: launcher finalization of a reconciled multi-worker graybox job when the
ownership gate refuses. The refusal reproduces the 559e88e1 signature (no narrative, no end
attestation, nothing logged); it must now name its reason on the job timeline and keep the results.

Real: maybe_finalize_pass, the finalization ownership wrapper, PentesterApi01Plugin's
_write_job_record / _normalize_job_record / _execution_operation_allowed, JobStateRepository
(CStoreJobRunning coercion) over a JSON round-trip chainstore, reconcile_workers_from_live.
Fake: the tenant service (records reauthorize calls), R1FS, attestation submit, LLM provider.
"""
from copy import deepcopy
import json

from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest

from . import test_api as _api
from .test_tenant_execution_finalization import FinalizationOwner, execution_binding

_api.TestPhase1ConfigCID._mock_plugin_modules()
from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin  # noqa: E402
from extensions.business.cybersec.red_mesh.services import finalization  # noqa: E402
from extensions.business.cybersec.red_mesh.services.reconciliation import reconcile_workers_from_live  # noqa: E402

WORKERS = [f"0xai_worker{i}" for i in range(1, 10)]
TARGET = {"kind": "webapp", "url": "https://target.example/", "allowedPathPrefix": "/"}


def webapp_binding():
  binding = execution_binding()
  binding.update(asset_target=TARGET, asset_target_digest=canonical_digest(TARGET),
                 original_launcher="node-a", participant_order=list(WORKERS))
  return binding


class RecordingService:
  def __init__(self):
    self.calls = []

  def reauthorize_execution(self, binding, *, worker_node=None):
    self.calls.append((deepcopy(binding.to_dict()), worker_node))
    return True


class RealStoreOwner(FinalizationOwner):
  """Launcher node-a, not a worker. Job state goes through the real write/normalize/gate code."""

  def __init__(self):
    super().__init__()
    self.store = {}
    self.service = RecordingService()
    self.gate_log = []
    binding = webapp_binding()
    job = {
      "job_id": "job-1", "job_status": "RUNNING", "job_pass": 1, "job_revision": 0,
      "run_mode": "SINGLEPASS", "launcher": "node-a", "launcher_alias": "archicava_03",
      "target": "target.example", "scan_type": "webapp", "target_url": TARGET["url"],
      "start_port": 443, "end_port": 443, "date_created": 1, "job_config_cid": "config",
      "blockchain_attestation_enabled": True, "end_attestation_required": True,
      "workers": {w: {"start_port": 443, "end_port": 443, "finished": False,
                      "assignment_revision": 1} for w in WORKERS},
      "pass_reports": [], "timeline": [], "execution_binding": binding,
    }
    self._put(job)
    config = deepcopy(self.r1fs.values["config"])
    config.update(execution_binding=binding, scan_type="webapp", target_url=TARGET["url"],
                  blockchain_attestation_enabled=True)
    self.r1fs.values["config"] = config
    for w in WORKERS:
      self.r1fs.values[f"report-{w}"] = deepcopy(self.r1fs.values["worker-report"])

  # JSON round-trip chainstore, one hkey for jobs, one for live rows.
  def _put(self, job):
    self.store[("deployment", job["job_id"])] = json.dumps(job)

  @property
  def job(self):
    raw = getattr(self, "store", {}).get(("deployment", "job-1"))
    return json.loads(raw) if raw else self.__dict__.get("_seed_job")

  @job.setter
  def job(self, value):
    if hasattr(self, "store"):
      self._put(value)
    else:
      self.__dict__["_seed_job"] = value

  def chainstore_hget(self, hkey, key):
    raw = self.store.get((hkey, key))
    return json.loads(raw) if raw else None

  def chainstore_hgetall(self, hkey):
    return {k: json.loads(v) for (h, k), v in self.store.items() if h == hkey and v}

  def chainstore_hset(self, hkey, key, value, **kwargs):
    self.store[(hkey, key)] = json.dumps(value) if value is not None else None
    return True

  def _normalize_job_record(self, key, value):
    return PentesterApi01Plugin._normalize_job_record(self, key, value)

  def _write_job_record(self, key, value, **kwargs):
    return PentesterApi01Plugin._write_job_record(self, key, value, **kwargs)

  def _execution_service(self):
    return self.service

  def _get_job_state_repository(self):
    return PentesterApi01Plugin._get_job_state_repository(self)

  def _execution_operation_allowed(self, job_specs, *, operation="current", config=None, **kwargs):
    result = PentesterApi01Plugin._execution_operation_allowed(
      self, job_specs, operation=operation, config=config, **kwargs)
    self.gate_log.append(("api", operation, config is not None, result))
    return result

  def _execution_denial_reason(self, job_specs, *, operation="current", config=None, **kwargs):
    return PentesterApi01Plugin._execution_denial_reason(
      self, job_specs, operation=operation, config=config, **kwargs)

  def _archive_identity_valid(self, *args):
    return True

  def _collect_node_reports(self, workers):
    return {w: self.r1fs.get_json(e["report_cid"]) for w, e in workers.items()}

  def _get_aggregated_report(self, node_reports, **kwargs):
    # Aggregation is not under test; graybox merge needs graybox-shaped reports.
    return deepcopy(next(iter(node_reports.values())))

  def _emit_timeline_event(self, job_specs, event, label, **kwargs):
    job_specs.setdefault("timeline", []).append(
      {"type": event, "label": label, "meta": kwargs.get("meta") or {}})


def _finish_via_live(owner, batches):
  """Workers publish finished live rows; the launcher reconciles them in batches (5 events)."""
  live = {}
  for batch in batches:
    for w in batch:
      live[f"job-1:{w}"] = {"job_id": "job-1", "worker_addr": w, "pass_nr": 1,
                            "assignment_revision_seen": 1, "finished": True,
                            "report_cid": f"report-{w}", "scan_type": "webapp"}
    assert reconcile_workers_from_live(owner, "job-1", live_payloads=dict(live))


def _finalize(owner):
  _finish_via_live(owner, [WORKERS[0:2], WORKERS[2:4], WORKERS[4:6], WORKERS[6:8], WORKERS[8:9]])
  finalization.maybe_finalize_pass(owner)
  return owner.job, [e for e in owner.job["timeline"] if e["type"] == "execution_denied"]


def _pass_report(owner):
  return next(v for v in reversed(owner.r1fs.writes) if "worker_reports" in v)


def _assert_refused_but_kept(owner, job, denials, reason):
  assert owner.executor.submissions == [] and owner.attestations == []
  assert [(e["meta"]["operation"], e["meta"]["reason"], e["meta"]["pass_nr"]) for e in denials] == [
    ("llm_analysis", reason, 1), ("attestation", reason, 1)]
  # The scan finished: the job keeps its normal terminal status and its results (owner, 2026-11-20).
  assert job["job_status"] == "FINALIZED" and not job.get("failure_class")
  assert (job["attestation_status"], job["attestation_failure_reason"]) == ("failed", reason)
  assert len(job["pass_reports"]) == 1
  report = _pass_report(owner)
  assert report["llm_failed"] is True and report["llm_failure_reason"] == "execution_authority_denied"
  assert report["aggregated_report_cid"] and len(report["worker_reports"]) == len(WORKERS)


def test_a_refused_reauthorization_names_its_reason_and_keeps_the_results():
  """M1: the tenant service refuses (account_changed, a role denial, a store error...)."""
  from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
  owner = RealStoreOwner()

  def deny(binding, *, worker_node=None):
    raise AdministrationDenied(409, "account_changed")

  owner.service.reauthorize_execution = deny
  job, denials = _finalize(owner)
  _assert_refused_but_kept(owner, job, denials, "account_changed")


def test_a_rolled_back_replica_names_identity_mismatch():
  """M2: the launcher's job replica returns to the previous revision after the collecting write."""
  owner = RealStoreOwner()
  real_hset = owner.chainstore_hset

  def hset(hkey, key, value, **kwargs):
    before = owner.store.get(("deployment", "job-1"))
    result = real_hset(hkey, key, value, **kwargs)
    if isinstance(value, dict) and value.get("job_status") == "COLLECTING":
      owner.store[("deployment", "job-1")] = before
    return result

  owner.chainstore_hset = hset
  job, denials = _finalize(owner)
  _assert_refused_but_kept(owner, job, denials, "identity_mismatch")


def test_an_allowed_pass_logs_no_denial_and_submits_the_attestation():
  owner = RealStoreOwner()
  _finish_via_live(owner, [WORKERS[0:2], WORKERS[2:4], WORKERS[4:6], WORKERS[6:8], WORKERS[8:9]])
  finalization.maybe_finalize_pass(owner)
  owner.executor.run()
  finalization.maybe_finalize_pass(owner)
  job = owner.job
  assert not [e for e in job["timeline"] if e["type"] == "execution_denied"]
  assert len(owner.attestations) == 1 and job["job_status"] == "FINALIZED"
  assert job["attestation_status"] == "submitted"


class _ReasonOwner:
  ee_addr = "node-a"
  calls = 0

  def P(self, *args, **kwargs):
    pass

  def __init__(self, reason):
    self.reason = reason
    self.calls = 0

  def _execution_denial_reason(self, job_specs, *, operation="current", config=None):
    self.calls += 1
    if isinstance(self.reason, Exception):
      raise self.reason
    return self.reason


def test_the_gate_asks_the_owner_once_and_reports_unexpected_errors_as_internal_error():
  job = {"job_id": "job-1", "launcher": "node-a", "job_status": "RUNNING", "execution_binding": webapp_binding()}
  repo = type("Repo", (), {"get_job": lambda self, job_id: job})()
  with patch_repo(repo):
    for reason, expected in ((None, None), ("account_changed", "account_changed"), ("", "forbidden"),
                             (RuntimeError("boom"), "internal_error")):
      owner = _ReasonOwner(reason)
      assert finalization._execution_denial_reason(owner, job) == expected
      assert owner.calls == 1


def patch_repo(repo):
  from unittest.mock import patch
  return patch.object(finalization, "_job_repo", lambda owner: repo)


def test_llm_failure_reasons_are_told_apart():
  denied = finalization._ANALYSIS_DENIED_MESSAGE
  cases = (
    (None, "provider_error"),
    ({"errors": [{"code": "llm_call_failed", "message": "LLM call raised after 1s: HTTP 503"}]}, "provider_error"),
    ({"errors": [{"code": "llm_call_failed", "message": f"LLM call raised after 0s: {denied}"}]},
     "execution_authority_denied"),
    ({"errors": [{"code": "empty_response", "message": ""}]}, "provider_error"),
    ({"errors": [{"code": "missing_section", "message": "overall_posture"}]}, "validation_failed"),
  )
  for validation, expected in cases:
    owner = type("O", (), {"_last_structured_llm_validation": validation})()
    assert finalization._llm_failure_reason(owner) == expected
