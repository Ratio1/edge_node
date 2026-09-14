"""Checked legacy rulebook reads preserve producer state without acquiring write authority."""
import asyncio
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from .test_rulebook_assessment import _Owner, checked_read_producer
from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms
from extensions.business.cybersec.red_mesh.services import rulebook_assessment as service
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied


PROFILE = service.DEFAULT_RULEBOOK_PROFILE_ID
READERS = (service.get_rulebook_assessment_status, service.get_rulebook_review)


@pytest.mark.parametrize("reader", READERS)
def test_missing_rulebook_records_use_only_checked_job_and_exact_record_keys(reader):
  owner = _Owner()
  owner._get_job_from_cstore = MagicMock(side_effect=AssertionError("global fallback"))
  owner.artifact_repo.get_json = MagicMock(side_effect=AssertionError("unneeded artifact"))
  checked = deepcopy(owner.job_specs)
  result = reader(owner, "job-1", checked_job=checked, snapshot_mode="legacy_unbound")
  assert result["job_id"] == "job-1"
  assert result["submissions"] == [] and result["latest_submission"] is None
  if reader is service.get_rulebook_review:
    assert result["found"] is False and result["review"] == {"review_state": "draft", "answers": {}}
  else:
    assert result["found"] is True and result["generated"] is False
    assert result["profile_id"] == PROFILE
  assert owner.job_specs == checked and owner.records == {}
  owner.r1fs.add_json.assert_not_called()


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("kind,value", (
  ("review", []), ("review", False), ("review", {}),
  ("review", {"job_id": "foreign", "profile_id": PROFILE}),
  ("review", {"job_id": "job-1", "profile_id": PROFILE, "answers": []}),
  ("review", {"job_id": "job-1", "profile_id": PROFILE, "updated_at": float("nan")}),
  ("registry", []), ("registry", {"submissions": [False]}),
  ("registry", {"pending": []}),
  ("registry", {"submissions": [{"cid": "cid", "profile_id": "foreign"}]}),
  ("metadata", []), ("metadata", {"profile_id": "foreign"}),
  ("metadata", {"generated": True}), ("metadata", {"submission_contract_version": "private"}),
  ("review", {"job_id": "job-1", "profile_id": PROFILE, "note": {"private": "value"}}),
  ("review", {"job_id": "job-1", "profile_id": PROFILE, "answers": {"q": {"note": []}}}),
  ("registry", {"submissions": [{"cid": {"private": "value"}, "profile_id": PROFILE}]}),
  ("metadata", {"profile_version": []}), ("metadata", {"history": False}),
  ("metadata", {"history": [{"profile_id": "foreign"}]}),
  ("metadata", {"status_counts": []}), ("metadata", {"last_error": {"error": []}}),
  ("metadata", {"status": "error"}), ("metadata", {"review": {}}), ("metadata", {"audit": []}),
))
def test_corrupt_or_foreign_selected_records_are_not_coerced_to_success(reader, kind, value):
  owner = _Owner()
  if kind == "metadata":
    owner.job_specs["rulebook_assessments"] = {PROFILE: value}
  else:
    suffix = "rulebook_review" if kind == "review" else "rulebook_review:submissions"
    owner.records[(owner.cfg_instance_id + ":" + suffix, "job-1:" + PROFILE)] = value
  with pytest.raises(TenantStoreError):
    reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("profile,job,status,code", (
  ("unknown", {}, 400, "invalid_profile"),
  (PROFILE, {"job_type": "model_test"}, 400, "unsupported_job_type"),
))
def test_checked_known_domain_errors_are_typed(reader, profile, job, status, code):
  owner = _Owner()
  with pytest.raises(AdministrationDenied) as caught:
    reader(owner, "job-1", profile, checked_job={"job_id": "job-1", **job}, snapshot_mode="legacy_unbound")
  assert (caught.value.status_code, caught.value.error) == (status, code)


@pytest.mark.parametrize("reader", READERS)
def test_native_method_requires_current_account_and_uses_checked_job(reader):
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.job["job_status"] = "FINALIZED"
    writes = list(fixture.store.writes)
    method = getattr(fixture.Plugin, reader.__name__)
    denied = method(fixture.owner, "job-1")
    assert denied == {"success": False, "error": "not_found", "status_code": 404}
    allowed = method(fixture.owner, "job-1", request_actor=fixture.actor)
    assert allowed["job_id"] == "job-1" and allowed["submissions"] == []
    assert fixture.artifact_reads == [] and fixture.store.writes == writes


PRODUCER_STATES = ("missing", "generated", "generation_failed", "draft", "submitted", "submission_failed", "reopened", "legacy")


def install_rulebook_producer(fixture, state):
  """Install real writer state into the native fixture's independent auth/storage namespace."""
  producer = checked_read_producer(state)
  fixture.job.clear()
  fixture.job.update(deepcopy(producer.job_specs))
  for (hkey, key), row in producer.records.items():
    if hkey.startswith(producer.cfg_instance_id + ":rulebook_review"):
      fixture.store.data[(fixture.owner.cfg_instance_id + hkey[len(producer.cfg_instance_id):], key)] = deepcopy(row)
  fixture.artifacts["archive-cid"] = deepcopy(producer.archive)
  fixture.artifacts.update(deepcopy(producer.artifacts))
  return producer


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("state", PRODUCER_STATES)
def test_actual_producer_records_preserve_read_projection_without_effects(reader, state):
  owner = checked_read_producer(state)
  expected = reader(owner, "job-1")
  owner._get_job_from_cstore = MagicMock(side_effect=AssertionError("unchecked lookup"))
  owner.chainstore_hset = MagicMock(side_effect=AssertionError("write"))
  owner.r1fs.reset_mock()
  owner.r1fs.add_json.side_effect = AssertionError("artifact write")
  actual = reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
  assert actual == expected
  owner.r1fs.add_json.assert_not_called()


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("state", PRODUCER_STATES)
def test_actual_native_transports_publish_real_producer_rows(read_native, reader, response_format, state):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    producer = install_rulebook_producer(fixture, state)
    expected = reader(producer, "job-1")
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, {
      "job_id": "job-1", "request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    # Native deployment fields may be added around RAW content; the read contract is unchanged.
    assert all(actual[key] == value for key, value in expected.items())
    assert calls == 1 and fixture.store.writes == writes
    assert all(cid == "archive-cid" for cid, _ in fixture.artifact_reads)


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("metadata", (
  {"auto_enabled": "false"}, {"run_state": "private-invalid-state"},
  {"history": [{"pass_nr": -1}]}, {"history": [{"status_counts": []}]},
  {"history": [{"last_error": {"error": 7}}]}, {"history": [{"artifact_cid": {}}]},
  {"history": [{"last_error": False}]},
  {"stale": "false"}, {"cached": 0}, {"review_state": "private-invalid-state"},
  *({"history": [{field: "private-invalid-value"}]} for field in (
    "auto_enabled", "stale", "cached", "run_state", "review_state")),
))
def test_actual_native_rejects_malformed_selected_metadata_and_history(read_native, reader, response_format, metadata):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_rulebook_producer(fixture, "generated")
    fixture.job["rulebook_assessments"][PROFILE].update(deepcopy(metadata))
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, {
      "job_id": "job-1", "request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1 and fixture.store.writes == writes and fixture.artifact_reads == []


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("history", (False, True))
def test_native_metadata_error_null_is_corruption_not_absence(read_native, reader, response_format, history):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_rulebook_producer(fixture, "generated")
    metadata = fixture.job["rulebook_assessments"][PROFILE]
    if history:
      metadata["history"] = [{"last_error": None}]
    else:
      metadata["last_error"] = None
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, {
      "job_id": "job-1", "request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1 and fixture.store.writes == writes and fixture.artifact_reads == []


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("state", ("generated", "submission_failed", "submitted"))
def test_native_absent_metadata_and_nullable_submission_errors_remain_valid(read_native, reader, response_format, state):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    producer = install_rulebook_producer(fixture, state)
    if state == "generated":
      generated = service.generate_rulebook_assessment(producer, "job-1", persist=True, force=True)
      assert generated["status"] == "ok"
      fixture.job.update(deepcopy(producer.job_specs))
      metadata = fixture.job["rulebook_assessments"][PROFILE]
      assert "last_error" not in metadata and metadata["history"]
      assert all("last_error" not in row for row in metadata["history"])
    elif state == "submission_failed":
      registry = fixture.store.data[(fixture.owner.cfg_instance_id + ":rulebook_review:submissions", "job-1:" + PROFILE)]
      registry["pending"]["last_error"] = None
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, {
      "job_id": "job-1", "request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert actual["submission_error"] is None
    assert actual["submission_operation_state"] == ("submitting" if state == "submission_failed" else None)
    if state == "generated" and reader is service.get_rulebook_assessment_status:
      assert actual["history"] == metadata["history"] and "last_error" not in actual
    assert calls == 1 and fixture.store.writes == writes


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("run_state", ("pending", "running", "succeeded", "failed"))
def test_actual_native_preserves_valid_optional_metadata_and_history(read_native, reader, response_format, run_state):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    producer = install_rulebook_producer(fixture, "generated")
    # A second unchanged producer generation records the first artifact as real history.
    generated = service.generate_rulebook_assessment(producer, "job-1", persist=True, force=True)
    assert generated["status"] == "ok"
    fixture.job.update(deepcopy(producer.job_specs))
    metadata = fixture.job["rulebook_assessments"][PROFILE]
    assert metadata["history"]
    metadata.update({"auto_enabled": False, "stale": True, "cached": False, "run_state": run_state})
    metadata["history"][0].update({
      "profile_version": "0.9.0", "review_state": "reviewed", "auto_enabled": True,
      "stale": False, "cached": True, "run_state": run_state,
      "last_error": {"error": "artifact_write_failed", "message": "Fixture failure", "retryable": True,
                       "at": "2026-09-13T00:00:00Z"},
    })
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, {
      "job_id": "job-1", "request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    if reader is service.get_rulebook_assessment_status:
      assert actual["history"] == metadata["history"]
      assert actual["auto_enabled"] is False and actual["stale"] is True and actual["cached"] is False
    assert calls == 1


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("reader,fault,status,code", (
  *((reader, fault, 400, code) for reader in READERS for fault, code in (
    ("profile", "invalid_profile"), ("model", "unsupported_job_type"))),
  (service.get_rulebook_review, "running", 409, "job_not_finalized"),
  (service.get_rulebook_review, "version", 503, "submission_contract_unsupported"),
))
def test_actual_native_rulebook_domain_errors_are_endpoint_local(read_native, reader, response_format, fault, status, code):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.job["job_status"] = "RUNNING" if fault == "running" else "FINALIZED"
    if fault == "model":
      fixture.job["job_type"] = "model_test"
    if fault == "version":
      fixture.store.data[(fixture.owner.cfg_instance_id + ":rulebook_review:submissions", "job-1:" + PROFILE)] = {
        "contract_version": "future", "submissions": []}
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, {
      "job_id": "job-1", "profile_id": "unknown" if fault == "profile" else PROFILE,
      "request_actor": fixture.actor})), status)
    assert result == {"success": False, "error": code, "status_code": status}
    assert calls == 1 and fixture.artifact_reads == []


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("kwargs", (
  {"snapshot_mode": "legacy_unbound"}, {"checked_job": None, "snapshot_mode": "legacy_unbound"},
  {"checked_job": {"job_id": "foreign"}, "snapshot_mode": "legacy_unbound"},
  {"checked_job": {"job_id": "job-1", "execution_binding": None}, "snapshot_mode": "legacy_unbound"},
  {"checked_job": {"job_id": "job-1"}, "snapshot_mode": "unknown"}, {"snapshot_mode": None},
))
def test_invalid_checked_snapshot_never_falls_back(reader, kwargs):
  owner = MagicMock()
  with pytest.raises(TenantStoreError):
    reader(owner, "job-1", **kwargs)
  assert owner.mock_calls == []


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("profile", (None, "", PROFILE))
def test_checked_profile_defaults_and_historical_metadata(reader, profile):
  owner = checked_read_producer("generated")
  meta = owner.job_specs["rulebook_assessments"][PROFILE]
  del meta["profile_id"]
  meta["profile_version"] = "0.9.0"
  result = reader(owner, "job-1", profile, checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
  assert result.get("profile_id", result.get("profile", {}).get("profile_id")) == PROFILE
  if reader is service.get_rulebook_assessment_status:
    assert result["profile_version"] == "0.9.0" and result["generated"] is True


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("corrupt", (False, True))
def test_explicit_unsupported_contract_is_distinct_from_child_corruption(reader, corrupt):
  owner = checked_read_producer("submitted")
  row = owner.records[(owner.cfg_instance_id + ":rulebook_review:submissions", "job-1:" + PROFILE)]
  row["contract_version"] = "future"
  if corrupt:
    row["submissions"][0]["profile_id"] = "foreign"
    with pytest.raises(TenantStoreError):
      reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
  elif reader is service.get_rulebook_review:
    with pytest.raises(AdministrationDenied) as caught:
      reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
    assert (caught.value.status_code, caught.value.error) == (503, "submission_contract_unsupported")
  else:
    result = reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
    assert result["submission_contract_version"] is None and result["submission_contract_unsupported"] is True
    assert "submissions" not in result


@pytest.mark.parametrize("value", (False, "", {}, [False], [{"job_id": "foreign", "profile_id": PROFILE}],
  [{"job_id": "job-1", "profile_id": PROFILE, "review_state": "private"}],
  [{"job_id": "job-1", "profile_id": PROFILE, "previous_answers": []}],
  [{"job_id": "job-1", "profile_id": PROFILE, "note": {"private": "value"}}]))
def test_audit_integrity_is_not_hidden_by_compatibility_getter(value):
  owner = _Owner()
  owner.records[(owner.cfg_instance_id + ":rulebook_review:audit", "job-1:" + PROFILE)] = value
  with pytest.raises(TenantStoreError):
    service.get_rulebook_review(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("fault", ("foreign", "missing", "binding", "nonfinite", "no_pass", "last_order"))
def test_staleness_uses_checked_pass_parents_only_and_does_not_hide_integrity_errors(reader, fault):
  owner = checked_read_producer("submitted")
  archive = owner.archive
  if fault == "foreign":
    archive["job_id"] = "foreign"
  elif fault == "missing":
    owner.artifact_repo.get_json = lambda cid: None
  elif fault == "binding":
    archive["execution_binding"] = None
  elif fault == "nonfinite":
    archive["passes"][0]["pass_nr"] = float("nan")
  elif fault == "no_pass":
    archive["passes"] = []
  else:
    archive["passes"] = [{"pass_nr": 99}, {"pass_nr": 3}]
  original_read = owner.artifact_repo.get_json
  reads = []
  def read(cid):
    reads.append(cid)
    assert cid == "archive-cid", "No aggregate, worker, configuration or submission CID hydration"
    return original_read(cid)
  owner.artifact_repo.get_json = read
  owner._get_job_from_cstore = MagicMock(side_effect=AssertionError("unchecked lookup"))
  if fault in ("no_pass", "last_order"):
    result = reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
    assert result["latest_submission"]["stale"] is False
  else:
    with pytest.raises(TenantStoreError):
      reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
  assert reads == ["archive-cid"]


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("fault,status", (
  ("empty_memberships", 403), ("null_memberships", 404), ("malformed_memberships", 404),
  ("inactive", 404), ("rollout", 403), ("store", 503), ("bound", 404),
  ("missing", 404), ("alias", 404), ("collision", 503),
))
def test_real_account_and_job_revocation_denies_before_rulebook_reads(reader, fault, status):
  with read_endpoint_fixture(bound=False) as fixture:
    if fault.endswith("memberships"):
      fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = {
        "empty_memberships": [], "null_memberships": None, "malformed_memberships": "private"}[fault]
    elif fault == "inactive":
      fixture.store.account("reader", active=False)
    elif fault == "rollout":
      fixture.owner.cfg_tenant_execution_stage = "draining"
    elif fault == "store":
      fixture.store.fail_hkey = fixture.store.cfg_instance_id
    elif fault == "bound":
      fixture.job["execution_binding"] = None
    elif fault == "missing":
      fixture.store.jobs.clear()
    elif fault == "collision":
      fixture.store.jobs["other"] = {"job_id": "job-1", "execution_binding": None}
    writes = list(fixture.store.writes)
    result = getattr(fixture.Plugin, reader.__name__)(fixture.owner,
      "legacy-alias" if fault == "alias" else "job-1", request_actor=fixture.actor)
    assert result == {"success": False, "status_code": status,
                      "error": {403: "forbidden", 404: "not_found", 503: "unavailable"}[status]}
    assert fixture.store.writes == writes and fixture.artifact_reads == []
    assert not any(":rulebook_review" in row[1] for row in fixture.store.reads)


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("kind", ("review", "registry", "metadata"))
def test_deepcopied_records_are_validated_after_copy(reader, kind):
  class ChangingRecord(dict):
    def __deepcopy__(self, memo):
      return {**self, "job_id": "foreign"}
  owner = _Owner()
  if kind == "metadata":
    owner.job_specs["rulebook_assessments"] = {PROFILE: ChangingRecord(artifact_cid="cid")}
  else:
    suffix = "rulebook_review" if kind == "review" else "rulebook_review:submissions"
    owner.records[(owner.cfg_instance_id + ":" + suffix, "job-1:" + PROFILE)] = ChangingRecord(
      job_id="job-1", profile_id=PROFILE)
  with pytest.raises(TenantStoreError):
    reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")


@pytest.mark.parametrize("reader", READERS)
def test_record_copy_precedes_the_next_storage_read_and_output_is_detached(reader):
  owner = checked_read_producer("draft")
  original = owner.chainstore_hget
  review_key = (owner.cfg_instance_id + ":rulebook_review", "job-1:" + PROFILE)
  def get(hkey, key):
    if hkey.endswith(":submissions"):
      owner.records[review_key]["profile_id"] = "mutated-after-review-read"
    return original(hkey, key)
  owner.chainstore_hget = get
  result = reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
  assert result["review_revision"] == 1
  if reader is service.get_rulebook_review:
    assert result["review"]["profile_id"] == PROFILE
    result["audit"].clear()
    assert owner.records[(owner.cfg_instance_id + ":rulebook_review:audit", "job-1:" + PROFILE)]


@pytest.mark.parametrize("reader", READERS)
def test_live_staleness_reads_pass_parents_in_producer_order_without_hydrating_children(reader):
  owner = checked_read_producer("submitted")
  owner.job_specs.pop("job_cid")
  owner.job_specs["pass_reports"] = [{"pass_nr": 99, "report_cid": "older"}, {"pass_nr": 3, "report_cid": "newest"}]
  owner.artifacts.update({"older": {"pass_nr": 99, "aggregated_report_cid": "private-aggregate"},
                           "newest": {"pass_nr": 3, "worker_reports": {"node": {"report_cid": "private-worker"}}}})
  reads = []
  def read(cid):
    reads.append(cid)
    assert cid in ("older", "newest")
    return owner.artifacts[cid]
  owner.artifact_repo.get_json = read
  result = reader(owner, "job-1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
  assert result["latest_submission"]["stale"] is False and reads == ["older", "newest"]


@pytest.mark.parametrize("reader", READERS)
def test_colon_bearing_job_uses_the_exact_canonical_profile_record_key(reader):
  owner = _Owner()
  owner.job_specs["job_id"] = "job:1"
  owner.chainstore_hget = MagicMock(return_value=None)
  result = reader(owner, "job:1", checked_job=owner.job_specs, snapshot_mode="legacy_unbound")
  assert result["job_id"] == "job:1"
  assert all(call.kwargs["key"] == "job:1:" + PROFILE for call in owner.chainstore_hget.call_args_list)


@pytest.mark.parametrize("name,status,code,expected", (
  ("get_job_status", 409, "job_not_finalized", 503),
  ("get_rulebook_assessment_status", 409, "job_not_finalized", 503),
  ("get_rulebook_review", 409, "request_conflict", 503),
  ("get_rulebook_assessment_status", 503, "submission_contract_unsupported", 503),
))
def test_rulebook_safe_error_allowance_does_not_generalize_to_other_errors(read_native, name, status, code, expected):
  module, _ = read_native
  install(module)
  async def supplied_response(*args, **kwargs):
    module.eng.calls.append((args, kwargs))
    return {"success": False, "error": code, "status_code": status}
  module.eng.call_plugin = supplied_response
  result, calls = assert_json_response(asyncio.run(request(module, name, {
    "job_id": "job-1", "request_actor": {"account_id": "reader"}})), expected)
  assert result == {"success": False, "error": "unavailable", "status_code": expected}
  assert calls == 1


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("field", ("previous_answers", "current_answers"))
@pytest.mark.parametrize("value", (
  None, "yes", [], False, {"q": "yes"}, {"q": {}},
  {"q": {"value": None}}, {"q": {"value": "private-invalid"}}, {"q": {"value": []}},
))
def test_native_raw_audit_answers_cannot_rely_on_absent_model_coercion(read_native, response_format, field, value):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_rulebook_producer(fixture, "draft")
    audit = fixture.store.data[(fixture.owner.cfg_instance_id + ":rulebook_review:audit", "job-1:" + PROFILE)]
    audit[0][field] = deepcopy(value)
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_review", {
      "job_id": "job-1", "request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1 and fixture.store.writes == writes and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_raw_audit_requires_explicit_review_state(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_rulebook_producer(fixture, "draft")
    audit = fixture.store.data[(fixture.owner.cfg_instance_id + ":rulebook_review:audit", "job-1:" + PROFILE)]
    del audit[0]["review_state"]
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_review", {
      "job_id": "job-1", "request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1 and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("answers,expected", (
  (None, {}), ({"q": "yes"}, {"q": {"value": "yes", "note": "", "reviewer": "", "updated_at": 0.0}}),
  ({"q": {}}, {"q": {"value": "unknown", "note": "", "reviewer": "", "updated_at": 0.0}}),
))
def test_native_model_coerced_review_defaults_remain_valid_without_optional_audit_containers(
    read_native, response_format, answers, expected):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_rulebook_producer(fixture, "draft")
    review = fixture.store.data[(fixture.owner.cfg_instance_id + ":rulebook_review", "job-1:" + PROFILE)]
    review["answers"] = deepcopy(answers)
    del review["review_state"]
    audit = fixture.store.data[(fixture.owner.cfg_instance_id + ":rulebook_review:audit", "job-1:" + PROFILE)]
    del audit[0]["previous_answers"]
    del audit[0]["current_answers"]
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_review", {
      "job_id": "job-1", "request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert actual["review"]["answers"] == expected and actual["review"]["review_state"] == "draft"
    assert actual["audit"] == audit and calls == 1


def probe_record(fixture, location):
  """Select a real writer record; extensions remain attached to its original keyed owner."""
  state = {"metadata": "generated", "history": "generated", "extension": "generated",
           "review": "draft", "audit": "draft", "registry": "submitted",
           "reference": "submitted", "pending": "submission_failed"}[location]
  install_rulebook_producer(fixture, state)
  if location in ("metadata", "history", "extension"):
    row = fixture.job["rulebook_assessments"][PROFILE]
    if location == "history":
      row["history"] = [{}]
      return row["history"][0]
    if location == "extension":
      row["extension"] = {"nested": [{}]}
      return row["extension"]["nested"][0]
    return row
  suffix = "rulebook_review" + (":audit" if location == "audit" else
    ":submissions" if location in ("registry", "reference", "pending") else "")
  row = fixture.store.data[(fixture.owner.cfg_instance_id + ":" + suffix, "job-1:" + PROFILE)]
  return row[0] if location == "audit" else row["submissions"][0] if location == "reference" else (
    row["pending"] if location == "pending" else row)


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("location", ("metadata", "history", "extension", "review", "audit", "registry", "reference", "pending"))
@pytest.mark.parametrize("field", ("execution_binding", "executionBinding", "tenant_id", "tenantId", "asset_id", "assetId"))
def test_native_legacy_rulebook_records_reject_all_tenant_authority_markers(read_native, response_format, location, field):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    row = probe_record(fixture, location)
    row[field] = None
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    endpoint = "get_rulebook_review" if location == "audit" else "get_rulebook_assessment_status"
    result, calls = assert_json_response(asyncio.run(request(module, endpoint, {
      "job_id": "job-1", "request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1 and fixture.store.writes == writes and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("location", ("metadata", "history", "pending"))
@pytest.mark.parametrize("value", (None, False, 7, [], {}))
def test_native_error_class_has_one_string_contract_in_every_published_error(read_native, response_format, location, value):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    row = probe_record(fixture, location)
    row["last_error"] = {"error": "fixture_failure", "error_class": value}
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_assessment_status", {
      "job_id": "job-1", "request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1 and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("value", (None, False, "1", [], {}, float("nan"), float("inf")))
def test_native_raw_audit_updated_at_is_an_optional_finite_number(read_native, response_format, value):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    probe_record(fixture, "audit")["updated_at"] = value
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_review", {
      "job_id": "job-1", "request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1 and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("location", ("metadata", "history", "pending", "audit"))
def test_native_matching_identities_and_valid_optional_fields_remain_visible(read_native, response_format, location):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    row = probe_record(fixture, location)
    row["extension"] = {"nested": [{"job_id": "job-1", "profile_id": PROFILE}]}
    if location == "audit":
      row["updated_at"] = 1.5
    else:
      row["last_error"] = {"error": "fixture_failure", "error_class": "provider_unavailable"}
    module.eng = scheduler_comms(fixture, response_format)
    endpoint = "get_rulebook_review" if location == "audit" else "get_rulebook_assessment_status"
    result, calls = assert_json_response(asyncio.run(request(module, endpoint, {
      "job_id": "job-1", "request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    if location == "audit":
      assert actual["audit"][0]["updated_at"] == 1.5 and actual["audit"][0]["extension"] == row["extension"]
    else:
      error = (actual["submission_error"] if location == "pending" else
               actual["history"][0]["last_error"] if location == "history" else actual["last_error"])
      assert error["error_class"] == "provider_unavailable"
    assert calls == 1


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("location", ("metadata", "history", "extension", "review", "audit", "reference"))
def test_native_integer_overflow_cannot_publish_nonfinite_consumer_numbers(read_native, response_format, location):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    row = probe_record(fixture, location)
    field = "review_revision" if location in ("review", "audit") else "pass_nr"
    row[field] = 10 ** 309
    module.eng = scheduler_comms(fixture, response_format)
    endpoint = "get_rulebook_review" if location == "audit" else "get_rulebook_assessment_status"
    native = asyncio.run(request(module, endpoint, {"job_id": "job-1", "request_actor": fixture.actor}))
    assert native[0] == 503, native[2].decode("utf-8")
    result, calls = assert_json_response(native, 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert calls == 1


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_large_finite_integer_and_boolean_metadata_are_preserved(read_native, reader, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    metadata = probe_record(fixture, "metadata")
    metadata["pass_nr"] = 10 ** 100
    metadata["auto_enabled"] = False
    metadata["extension"] = {"boolean": True, "negative_finite_integer": -(10 ** 100)}
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, {
      "job_id": "job-1", "request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    if reader is service.get_rulebook_assessment_status:
      assert actual["pass_nr"] == 10 ** 100 and actual["auto_enabled"] is False
      assert actual["extension"] == metadata["extension"]
    assert calls == 1
