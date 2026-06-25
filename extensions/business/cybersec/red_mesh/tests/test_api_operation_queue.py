import hashlib
import copy
import json
import sys
import types
import unittest

if "pymisp" not in sys.modules:
  pymisp_stub = types.ModuleType("pymisp")
  pymisp_stub.MISPEvent = object
  pymisp_stub.MISPObject = object
  pymisp_stub.MISPAttribute = object
  pymisp_stub.PyMISP = object
  sys.modules["pymisp"] = pymisp_stub

from extensions.business.cybersec.red_mesh.services.api_operations import (
  ApiOperationRepository,
  cancel_api_operation,
  create_analyze_job_operation,
  get_api_operation_result,
  get_api_operation_status,
  maybe_start_api_operation_worker,
)
from extensions.business.cybersec.red_mesh.services.config import (
  DEFAULT_API_OPERATIONS_CONFIG,
  get_api_operations_config,
)


def _token_hash(token: str) -> str:
  return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _join_worker(owner):
  worker = getattr(owner, "_api_operation_worker_thread", None)
  if worker:
    worker.join(timeout=2)


def _structured_sections(owner):
  owner.llm_calls += 1
  owner._last_structured_llm_failed = False
  return {
    "executive_headline": "High priority HTTPS exposure",
    "overall_posture": "The exposed service should be reviewed.",
    "recommendation_summary": ["Review TLS and authentication controls."],
    "strategic_roadmap": {},
    "attack_chain_narratives": [],
    "coverage_gaps": [],
    "conclusion": "Remediation is practical.",
  }


class _Owner:
  def __init__(self, *, token_hashes=None, max_queue_global=32, max_queue_per_job=1):
    self.cfg_instance_id = "test-instance"
    self.ee_addr = "node-a"
    self.cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 5}
    self.cfg_llm_agent_api_port = 8080
    self.cfg_llm_api_retries = 2
    self.cfg_api_operations = {
      "ENABLED": True,
      "TOKEN_HASHES": token_hashes if token_hashes is not None else [_token_hash("good-token")],
      "TOKEN_ENV": "",
      "HMAC_SECRET": "operation-hmac-secret",
      "HMAC_SECRET_ENV": "",
      "MAX_QUEUE_GLOBAL": max_queue_global,
      "MAX_QUEUE_PER_JOB": max_queue_per_job,
      "MAX_QUEUE_PER_ACTOR": 8,
      "POLL_AFTER_MS": 500,
    }
    self._store = {}
    self._jobs = {}
    self.r1fs = _R1FS()
    self.audit_events = []
    self.timeline_events = []
    self.llm_calls = 0

  def add_job(self, job_id="job-1"):
    self.r1fs.objects["QmPassReport"] = {
      "pass_nr": 1,
      "aggregated_report_cid": "QmAggregatedReport",
      "worker_reports": {},
      "risk_score": 12,
    }
    self._jobs[job_id] = {
      "job_id": job_id,
      "job_revision": 3,
      "workers": {
        "node-a": {
          "finished": True,
          "report_cid": "QmWorkerReport",
        },
      },
      "pass_reports": [
        {"pass_nr": 1, "report_cid": "QmPassReport"},
      ],
    }
    return self._jobs[job_id]

  def _get_job_from_cstore(self, job_id):
    return self._jobs.get(job_id)

  def chainstore_hget(self, *, hkey, key):
    return self._store.get(hkey, {}).get(key)

  def chainstore_hgetall(self, *, hkey):
    return dict(self._store.get(hkey, {}))

  def chainstore_hset(self, *, hkey, key, value):
    self._store.setdefault(hkey, {})
    if value is None:
      self._store[hkey].pop(key, None)
    else:
      self._store[hkey][key] = value

  def _log_audit_event(self, event, payload):
    self.audit_events.append((event, payload))

  def _collect_node_reports(self, workers):
    return {"node-a": {"open_ports": [443], "service_info": {"443": {"name": "https"}}}}

  def _get_aggregated_report(self, node_reports):
    return {"open_ports": [443], "service_info": {"443": {"name": "https"}}}

  def _compute_risk_and_findings(self, aggregated_report):
    return {"score": 12, "breakdown": {"findings_score": 12}}, [
      {"severity": "HIGH", "port": 443, "category": "tls"}
    ]

  def _get_job_config(self, job_specs):
    return {"engagement": {"name": "test engagement"}}

  def _run_structured_report_sections(self, **kwargs):
    return _structured_sections(self)

  def _emit_timeline_event(self, job_specs, event_type, message, actor_type="system", meta=None):
    event = {
      "event_type": event_type,
      "message": message,
      "actor_type": actor_type,
      "meta": dict(meta or {}),
    }
    self.timeline_events.append(event)
    job_specs.setdefault("timeline", []).append(event)

  def _write_job_record(self, job_id, job_specs, expected_revision=None, context=""):
    current = self._jobs.get(job_id, {})
    job_specs["job_revision"] = int(current.get("job_revision", 0) or 0) + 1
    job_specs["write_context"] = context
    self._jobs[job_id] = job_specs
    return job_specs

  def P(self, *args, **kwargs):
    return None


class _R1FS:
  def __init__(self):
    self.objects = {}
    self.added_payloads = []

  def get_json(self, cid):
    payload = self.objects.get(cid)
    return copy.deepcopy(payload) if isinstance(payload, dict) else payload

  def add_json(self, payload, show_logs=False):
    self.added_payloads.append(copy.deepcopy(payload))
    cid = f"QmGeneratedPassReport{len(self.added_payloads)}"
    self.objects[cid] = copy.deepcopy(payload)
    return cid


class TestApiOperationConfig(unittest.TestCase):

  def test_default_api_operations_are_disabled(self):
    owner = _Owner()
    owner.cfg_api_operations = None

    cfg = get_api_operations_config(owner)

    self.assertFalse(cfg["ENABLED"])
    self.assertEqual(DEFAULT_API_OPERATIONS_CONFIG["TOKEN_ENV"], "REDMESH_API_OPERATION_TOKEN")

  def test_api_operation_config_bounds_values(self):
    owner = _Owner()
    owner.cfg_api_operations.update({
      "MAX_QUEUE_GLOBAL": 0,
      "MAX_QUEUE_PER_ACTOR": -1,
      "MAX_IDEMPOTENCY_KEY_LENGTH": 2,
      "POLL_AFTER_MS": 1,
    })

    cfg = get_api_operations_config(owner)

    self.assertEqual(cfg["MAX_QUEUE_GLOBAL"], DEFAULT_API_OPERATIONS_CONFIG["MAX_QUEUE_GLOBAL"])
    self.assertEqual(cfg["MAX_QUEUE_PER_ACTOR"], DEFAULT_API_OPERATIONS_CONFIG["MAX_QUEUE_PER_ACTOR"])
    self.assertEqual(
      cfg["MAX_IDEMPOTENCY_KEY_LENGTH"],
      DEFAULT_API_OPERATIONS_CONFIG["MAX_IDEMPOTENCY_KEY_LENGTH"],
    )
    self.assertEqual(cfg["POLL_AFTER_MS"], DEFAULT_API_OPERATIONS_CONFIG["POLL_AFTER_MS"])


class TestApiOperationAdmission(unittest.TestCase):

  def test_create_requires_configured_server_actor(self):
    owner = _Owner(token_hashes=[])
    owner.add_job()

    result = create_analyze_job_operation(owner, "good-token", "job-1")

    self.assertEqual(result["error"], "operation_auth_not_configured")

  def test_create_rejects_unauthorized_token(self):
    owner = _Owner()
    owner.add_job()

    result = create_analyze_job_operation(owner, "bad-token", "job-1")

    self.assertEqual(result["error"], "operation_auth_denied")

  def test_create_returns_sanitized_queued_operation(self):
    owner = _Owner()
    owner.add_job()

    result = create_analyze_job_operation(
      owner,
      "good-token",
      "job-1",
      focus_areas=["web", "web", "network"],
      idempotency_key="idem-secret",
    )

    self.assertEqual(result["status"], "accepted")
    operation = result["operation"]
    self.assertEqual(operation["state"], "queued")
    self.assertEqual(operation["operation_type"], "analyze_job")
    self.assertNotIn("actor_hash", operation)
    self.assertNotIn("request_fingerprint", operation)

    serialized_store = json.dumps(owner._store, sort_keys=True)
    self.assertNotIn("good-token", serialized_store)
    self.assertNotIn("idem-secret", serialized_store)

  def test_same_idempotency_key_replays_same_operation(self):
    owner = _Owner()
    owner.add_job()

    first = create_analyze_job_operation(owner, "good-token", "job-1", idempotency_key="idem-1")
    second = create_analyze_job_operation(owner, "good-token", "job-1", idempotency_key="idem-1")

    self.assertTrue(second["idempotent_replay"])
    self.assertEqual(first["operation"]["operation_id"], second["operation"]["operation_id"])

  def test_same_idempotency_key_different_request_conflicts_without_enqueue(self):
    owner = _Owner(max_queue_per_job=2)
    owner.add_job()

    first = create_analyze_job_operation(owner, "good-token", "job-1", idempotency_key="idem-1")
    before_count = len(owner._store["test-instance:api_operations"])
    conflict = create_analyze_job_operation(
      owner,
      "good-token",
      "job-1",
      focus_areas=["web"],
      idempotency_key="idem-1",
    )

    self.assertEqual(first["status"], "accepted")
    self.assertEqual(conflict["error"], "idempotency_conflict")
    self.assertEqual(len(owner._store["test-instance:api_operations"]), before_count)

  def test_create_rejects_invalid_analysis_type_and_focus_area(self):
    owner = _Owner()
    owner.add_job()

    invalid_type = create_analyze_job_operation(
      owner,
      "good-token",
      "job-1",
      analysis_type="legacy_raw_summary",
    )
    invalid_focus = create_analyze_job_operation(
      owner,
      "good-token",
      "job-1",
      focus_areas=["custom prompt"],
    )

    self.assertEqual(invalid_type["error"], "invalid_analysis_type")
    self.assertEqual(invalid_focus["error"], "invalid_focus_area")

  def test_same_idempotency_key_different_actor_does_not_replay_or_conflict(self):
    owner = _Owner(token_hashes=[_token_hash("good-token"), _token_hash("other-token")])
    owner.add_job("job-1")
    owner.add_job("job-2")

    first = create_analyze_job_operation(owner, "good-token", "job-1", idempotency_key="idem-1")
    second = create_analyze_job_operation(owner, "other-token", "job-2", idempotency_key="idem-1")

    self.assertEqual(first["status"], "accepted")
    self.assertEqual(second["status"], "accepted")
    self.assertNotEqual(first["operation"]["operation_id"], second["operation"]["operation_id"])

  def test_queue_full_returns_backpressure_without_operation_record(self):
    owner = _Owner(max_queue_global=1)
    owner.add_job("job-1")
    owner.add_job("job-2")

    first = create_analyze_job_operation(owner, "good-token", "job-1")
    before_count = len(owner._store["test-instance:api_operations"])
    second = create_analyze_job_operation(owner, "good-token", "job-2")

    self.assertEqual(first["status"], "accepted")
    self.assertEqual(second["error"], "operation_backpressure")
    self.assertTrue(second["retryable"])
    self.assertEqual(len(owner._store["test-instance:api_operations"]), before_count)

  def test_expired_queued_operation_does_not_consume_backpressure(self):
    owner = _Owner(max_queue_global=1)
    owner.add_job("job-1")
    owner.add_job("job-2")
    first = create_analyze_job_operation(owner, "good-token", "job-1")
    repo = ApiOperationRepository(owner)
    raw = repo.get_operation(first["operation"]["operation_id"])
    raw["expires_at"] = "2000-01-01T00:00:00Z"
    repo.put_operation(raw, expected_revision=raw["revision"], context="test_expire")

    second = create_analyze_job_operation(owner, "good-token", "job-2")
    status = get_api_operation_status(owner, "good-token", first["operation"]["operation_id"])

    self.assertEqual(second["status"], "accepted")
    self.assertEqual(status["operation"]["state"], "expired")


class TestApiOperationAccessAndState(unittest.TestCase):

  def test_cross_actor_status_and_unknown_status_are_indistinguishable(self):
    owner = _Owner(token_hashes=[_token_hash("good-token"), _token_hash("other-token")])
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")
    operation_id = created["operation"]["operation_id"]

    foreign = get_api_operation_status(owner, "other-token", operation_id)
    unknown = get_api_operation_status(owner, "other-token", "op_missing")

    self.assertEqual(foreign, unknown)
    self.assertEqual(foreign["error"], "operation_not_found")

  def test_status_requires_continued_job_visibility(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")
    owner._jobs.pop("job-1")

    status = get_api_operation_status(owner, "good-token", created["operation"]["operation_id"])

    self.assertEqual(status["error"], "operation_not_found")

  def test_cancel_queued_operation_prevents_worker_start(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")

    canceled = cancel_api_operation(owner, "good-token", created["operation"]["operation_id"])

    self.assertEqual(canceled["operation"]["state"], "canceled")
    self.assertEqual(canceled["operation"]["phase"], "canceled")
    self.assertEqual(canceled["operation"]["cancel"]["side_effects"], "none")

  def test_status_response_does_not_expose_raw_cids_or_diagnostics(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")
    repo = ApiOperationRepository(owner)
    raw = repo.get_operation(created["operation"]["operation_id"])
    raw["state"] = "succeeded"
    raw["result_ref"] = "QmInternalResult"
    raw["result_public"] = {
      "kind": "redmesh_analyze_job_result",
      "handle": "opaque-handle",
      "pass_nr": 1,
      "summary": {
        "llm_report_sections_available": True,
        "nested": {
          "url": "https://provider.example/internal",
          "note": "token abc",
        },
      },
      "report_cid": "QmShouldNotLeak",
    }
    raw["failure"] = {
      "failure_class": "llm_provider_error",
      "retryable": False,
      "short_message": "Provider failed",
      "details": "secret diagnostic",
      "provider_url": "https://provider.example",
    }
    repo.put_operation(raw, expected_revision=raw["revision"], context="test")

    status = get_api_operation_status(owner, "good-token", raw["operation_id"])
    serialized = json.dumps(status, sort_keys=True)

    self.assertIn("opaque-handle", serialized)
    self.assertNotIn("QmInternalResult", serialized)
    self.assertNotIn("QmShouldNotLeak", serialized)
    self.assertNotIn("secret diagnostic", serialized)
    self.assertNotIn("provider.example", serialized)
    self.assertNotIn("token abc", serialized)

  def test_raw_cid_is_rejected_by_operation_result_endpoint(self):
    owner = _Owner()

    result = get_api_operation_result(owner, "good-token", "Qmabcdefghijklmnopqrstuvwx")

    self.assertEqual(result["error"], "invalid_result_handle")

  def test_worker_executes_analyze_job_and_exposes_opaque_result(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")

    started = maybe_start_api_operation_worker(owner)
    _join_worker(owner)

    self.assertTrue(started)
    self.assertEqual(owner.llm_calls, 1)
    status = get_api_operation_status(owner, "good-token", created["operation"]["operation_id"])
    self.assertEqual(status["operation"]["state"], "succeeded")
    self.assertEqual(status["operation"]["phase"], "succeeded")
    handle = status["operation"]["result"]["handle"]
    self.assertTrue(handle.startswith("opres_"))

    latest_ref = owner._jobs["job-1"]["pass_reports"][-1]
    self.assertNotEqual(latest_ref["report_cid"], "QmPassReport")
    updated_pass = owner.r1fs.get_json(latest_ref["report_cid"])
    self.assertEqual(updated_pass["llm_operation_id"], created["operation"]["operation_id"])
    self.assertIn("llm_report_sections", updated_pass)
    self.assertIn("llm_analysis", updated_pass)
    self.assertEqual(owner.timeline_events[0]["meta"], {"pass_nr": 1})

    result = get_api_operation_result(owner, "good-token", handle)
    serialized_status = json.dumps(status, sort_keys=True)
    serialized_result = json.dumps(result, sort_keys=True)
    self.assertEqual(result["operation_id"], created["operation"]["operation_id"])
    self.assertEqual(result["result"]["handle"], handle)
    self.assertNotIn("QmPassReport", serialized_status)
    self.assertNotIn(latest_ref["report_cid"], serialized_status)
    self.assertNotIn(latest_ref["report_cid"], serialized_result)

  def test_worker_aborts_if_job_changes_during_llm_wait(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")

    def _llm_changes_job(**kwargs):
      owner._jobs["job-1"]["job_revision"] += 1
      owner._jobs["job-1"]["pass_reports"][-1]["report_cid"] = "QmConcurrentPassReport"
      owner.r1fs.objects["QmConcurrentPassReport"] = {"pass_nr": 1, "aggregated_report_cid": "QmOther"}
      return _structured_sections(owner)

    owner._run_structured_report_sections = _llm_changes_job
    started = maybe_start_api_operation_worker(owner)
    _join_worker(owner)

    status = get_api_operation_status(owner, "good-token", created["operation"]["operation_id"])
    self.assertTrue(started)
    self.assertEqual(status["operation"]["state"], "failed")
    self.assertEqual(status["operation"]["phase"], "job_changed")
    self.assertEqual(status["operation"]["failure"]["failure_class"], "job_changed")
    self.assertEqual(owner._jobs["job-1"]["pass_reports"][-1]["report_cid"], "QmConcurrentPassReport")
    self.assertEqual(owner.r1fs.added_payloads, [])

  def test_worker_aborts_if_job_revision_changes_during_llm_wait(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")

    def _llm_changes_job_revision_only(**kwargs):
      owner._jobs["job-1"]["job_revision"] += 1
      owner._jobs["job-1"]["unrelated_update"] = "export status changed"
      return _structured_sections(owner)

    owner._run_structured_report_sections = _llm_changes_job_revision_only
    started = maybe_start_api_operation_worker(owner)
    _join_worker(owner)

    status = get_api_operation_status(owner, "good-token", created["operation"]["operation_id"])
    self.assertTrue(started)
    self.assertEqual(status["operation"]["state"], "failed")
    self.assertEqual(status["operation"]["phase"], "job_changed")
    self.assertEqual(owner._jobs["job-1"]["pass_reports"][-1]["report_cid"], "QmPassReport")
    self.assertEqual(owner._jobs["job-1"]["unrelated_update"], "export status changed")
    self.assertEqual(owner.r1fs.added_payloads, [])

  def test_worker_cancel_during_llm_wait_avoids_side_effects(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")
    operation_id = created["operation"]["operation_id"]

    def _llm_cancels(**kwargs):
      cancel_api_operation(owner, "good-token", operation_id, reason="operator stop")
      return _structured_sections(owner)

    owner._run_structured_report_sections = _llm_cancels
    started = maybe_start_api_operation_worker(owner)
    _join_worker(owner)

    status = get_api_operation_status(owner, "good-token", operation_id)
    self.assertTrue(started)
    self.assertEqual(status["operation"]["state"], "canceled")
    self.assertEqual(status["operation"]["cancel"]["side_effects"], "none")
    self.assertEqual(owner._jobs["job-1"]["pass_reports"][-1]["report_cid"], "QmPassReport")
    self.assertEqual(owner.r1fs.added_payloads, [])

  def test_worker_expired_during_llm_wait_avoids_side_effects(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")
    operation_id = created["operation"]["operation_id"]

    def _llm_expires_operation(**kwargs):
      repo = ApiOperationRepository(owner)
      raw = repo.get_operation(operation_id)
      raw["expires_at"] = "2000-01-01T00:00:00Z"
      repo.put_operation(raw, expected_revision=raw["revision"], context="test_expire_running")
      return _structured_sections(owner)

    owner._run_structured_report_sections = _llm_expires_operation
    started = maybe_start_api_operation_worker(owner)
    _join_worker(owner)

    status = get_api_operation_status(owner, "good-token", operation_id)
    self.assertTrue(started)
    self.assertEqual(status["operation"]["state"], "expired")
    self.assertEqual(status["operation"]["phase"], "expired")
    self.assertEqual(owner._jobs["job-1"]["pass_reports"][-1]["report_cid"], "QmPassReport")
    self.assertEqual(owner.r1fs.added_payloads, [])

  def test_worker_cancel_after_r1fs_write_does_not_update_job_record(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")
    operation_id = created["operation"]["operation_id"]
    original_add_json = owner.r1fs.add_json

    def _cancel_after_add_json(payload, show_logs=False):
      cid = original_add_json(payload, show_logs=show_logs)
      cancel_api_operation(owner, "good-token", operation_id, reason="late stop")
      return cid

    owner.r1fs.add_json = _cancel_after_add_json
    started = maybe_start_api_operation_worker(owner)
    _join_worker(owner)

    status = get_api_operation_status(owner, "good-token", operation_id)
    self.assertTrue(started)
    self.assertEqual(status["operation"]["state"], "canceled")
    self.assertEqual(status["operation"]["cancel"]["side_effects"], "result_artifact_written")
    self.assertEqual(owner._jobs["job-1"]["pass_reports"][-1]["report_cid"], "QmPassReport")
    self.assertEqual(len(owner.r1fs.added_payloads), 1)

  def test_worker_failure_does_not_expose_provider_diagnostics_or_token_values(self):
    owner = _Owner()
    owner.add_job()
    created = create_analyze_job_operation(owner, "good-token", "job-1")
    operation_id = created["operation"]["operation_id"]

    def _llm_raises(**kwargs):
      raise RuntimeError("OpenAI provider returned sk-liveverysecretvalue via https://provider.example")

    owner._run_structured_report_sections = _llm_raises
    started = maybe_start_api_operation_worker(owner)
    _join_worker(owner)

    status = get_api_operation_status(owner, "good-token", operation_id)
    serialized = json.dumps(status, sort_keys=True)
    self.assertTrue(started)
    self.assertEqual(status["operation"]["state"], "failed")
    self.assertEqual(status["operation"]["failure"]["failure_class"], "operation_failed")
    self.assertEqual(status["operation"]["failure"]["short_message"], "Operation failed")
    self.assertNotIn("OpenAI", serialized)
    self.assertNotIn("provider.example", serialized)
    self.assertNotIn("sk-liveverysecretvalue", serialized)

  def test_operation_row_stale_revision_is_audit_logged(self):
    owner = _Owner()
    repo = ApiOperationRepository(owner)
    operation = {
      "operation_id": "op_1",
      "state": "queued",
      "phase": "queued",
      "revision": 0,
    }
    stored = repo.put_operation(operation, expected_revision=0, context="first")
    stale = dict(stored)
    stale["revision"] = 0
    stale["state"] = "running"

    repo.put_operation(stale, expected_revision=0, context="stale")

    current = repo.get_operation("op_1")
    self.assertEqual(owner.audit_events[0][0], "api_operation_stale_write_detected")
    self.assertEqual(owner.audit_events[0][1]["operation_id"], "op_1")
    self.assertEqual(owner.audit_events[0][1]["write_mode"], "detection_only")
    self.assertEqual(current["state"], "queued")


if __name__ == "__main__":
  unittest.main()
