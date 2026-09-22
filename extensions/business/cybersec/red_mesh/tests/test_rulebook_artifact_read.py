"""The typed rulebook artifact read: a CID is served only when the checked job records it.

RM-026 left rulebook artifacts to I1b and forbade authorizing them through `get_report`, which
serves ordinary report edges only. `get_rulebook_artifact` is that dedicated read: the current
generated assessment, an older one from the metadata history, or a submitted review snapshot from
the submission registry -- nothing else, and nothing read from R1FS before the CID is matched.
"""
import asyncio
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from .test_rulebook_assessment import _Owner, checked_read_producer
from .read_endpoint_fixtures import as_role, read_endpoint_fixture
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms
from .test_tenant_rulebook_reads import install_rulebook_producer
from extensions.business.cybersec.red_mesh.services import rulebook_assessment as service
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError


PROFILE = service.DEFAULT_RULEBOOK_PROFILE_ID


def producer_with_history():
  """Two real generations: QmRulebook2 is current, QmRulebook1 moved to the history."""
  owner = checked_read_producer("generated")
  assert service.generate_rulebook_assessment(owner, "job-1", persist=True, force=True)["status"] == "ok"
  meta = owner.job_specs["rulebook_assessments"][PROFILE]
  assert meta["artifact_cid"] == "QmRulebook2"
  assert [row["artifact_cid"] for row in meta["history"]] == ["QmRulebook1"]
  return owner


def read(owner, cid, profile_id=PROFILE, job=None):
  return service.get_rulebook_artifact(owner, "job-1", cid, profile_id,
                                       checked_job=owner.job_specs if job is None else job,
                                       snapshot_mode="legacy_unbound")


def guard_effects(owner):
  owner._get_job_from_cstore = MagicMock(side_effect=AssertionError("unchecked lookup"))
  owner.chainstore_hset = MagicMock(side_effect=AssertionError("write"))
  owner.r1fs.reset_mock()
  owner.r1fs.add_json.side_effect = AssertionError("artifact write")


@pytest.mark.parametrize("state,cid,kind", (
  ("history", "QmRulebook2", "generated_assessment"),
  ("history", "QmRulebook1", "generated_assessment"),
  ("submitted", "QmRulebook1", "review_submission"),
  # A legacy reviewed profile's submission is its metadata artifact.
  ("legacy", "QmRulebook1", "generated_assessment"),
))
def test_a_recorded_cid_returns_its_artifact_without_effects(state, cid, kind):
  owner = producer_with_history() if state == "history" else checked_read_producer(state)
  stored = deepcopy(owner.artifacts[cid])
  guard_effects(owner)
  result = read(owner, cid)
  assert result == {"job_id": "job-1", "profile_id": PROFILE, "cid": cid, "artifact_kind": kind,
                    "report": stored}
  owner.r1fs.add_json.assert_not_called()


@pytest.mark.parametrize("cid", ("archive-cid", "agg-cid", "QmRulebook9", " QmRulebook1", "QmRulebook1 "))
def test_a_cid_the_job_does_not_record_is_not_found_without_reading_it(cid):
  owner = checked_read_producer("submitted")
  owner.artifact_repo.get_json = MagicMock(side_effect=AssertionError("unrecorded read"))
  with pytest.raises(AdministrationDenied) as caught:
    read(owner, cid)
  assert (caught.value.status_code, caught.value.error) == (404, "not_found")


def test_a_missing_profile_record_serves_nothing():
  owner = _Owner()
  owner.artifact_repo.get_json = MagicMock(side_effect=AssertionError("unrecorded read"))
  with pytest.raises(AdministrationDenied) as caught:
    read(owner, "QmRulebook1")
  assert (caught.value.status_code, caught.value.error) == (404, "not_found")


@pytest.mark.parametrize("cid", ("", "   ", None, 7, ["QmRulebook1"]))
def test_an_empty_or_non_string_cid_is_an_invalid_request(cid):
  owner = checked_read_producer("generated")
  owner.artifact_repo.get_json = MagicMock(side_effect=AssertionError("read"))
  with pytest.raises(AdministrationDenied) as caught:
    read(owner, cid)
  assert (caught.value.status_code, caught.value.error) == (400, "invalid_request")


@pytest.mark.parametrize("state", ("generated", "submitted"))
@pytest.mark.parametrize("corrupt", (
  lambda artifact: None,
  lambda artifact: [artifact],
  lambda artifact: {**artifact, "job_id": "foreign"},
  lambda artifact: {key: value for key, value in artifact.items() if key != "job_id"},
  lambda artifact: {**artifact, "profile": {**artifact["profile"], "profile_id": "foreign"}},
  lambda artifact: {**artifact, "profile": None},
  lambda artifact: {**artifact, "artifact_kind": "aggregated_report"},
  lambda artifact: {key: value for key, value in artifact.items() if key != "artifact_kind"},
  lambda artifact: {**artifact, "submission": {"profile_id": "foreign"}},
  lambda artifact: {**artifact, "submission": "private"},
))
def test_a_recorded_cid_holding_a_foreign_or_corrupt_artifact_is_not_success(state, corrupt):
  owner = checked_read_producer(state)
  owner.artifacts["QmRulebook1"] = corrupt(owner.artifacts["QmRulebook1"])
  with pytest.raises(TenantStoreError):
    read(owner, "QmRulebook1")


@pytest.mark.parametrize("profile,job,status,code", (
  ("unknown", {}, 400, "invalid_profile"),
  (PROFILE, {"job_type": "model_test"}, 400, "unsupported_job_type"),
))
def test_known_domain_errors_are_typed(profile, job, status, code):
  owner = checked_read_producer("generated")
  owner.artifact_repo.get_json = MagicMock(side_effect=AssertionError("read"))
  with pytest.raises(AdministrationDenied) as caught:
    read(owner, "QmRulebook1", profile, job={"job_id": "job-1", **job})
  assert (caught.value.status_code, caught.value.error) == (status, code)


def test_there_is_no_unchecked_reader():
  owner = checked_read_producer("generated")
  with pytest.raises(TypeError):
    service.get_rulebook_artifact(owner, "job-1", "QmRulebook1")


def test_corrupt_selected_records_are_not_coerced_to_success():
  owner = checked_read_producer("generated")
  owner.job_specs["rulebook_assessments"][PROFILE]["history"] = [{"artifact_cid": {}}]
  with pytest.raises(TenantStoreError):
    read(owner, "QmRulebook1")


def test_native_method_requires_the_tenant_and_the_job_owner():
  with read_endpoint_fixture(bound=True) as fixture:
    install_rulebook_producer(fixture, "generated")
    method = fixture.Plugin.get_rulebook_artifact
    writes = list(fixture.store.writes)
    tenant_id = as_role(fixture, "tenant_user")
    unscoped = method(fixture.owner, "job-1", "QmRulebook1", PROFILE, request_actor=fixture.actor)
    assert unscoped == {"success": False, "error": "invalid_request", "status_code": 400}
    anonymous = method(fixture.owner, "job-1", "QmRulebook1", PROFILE, tenant_id=tenant_id)
    assert anonymous == {"success": False, "error": "not_found", "status_code": 404}
    assert fixture.artifact_reads == []
    allowed = method(fixture.owner, "job-1", "QmRulebook1", PROFILE, request_actor=fixture.actor,
                     tenant_id=tenant_id)
    assert allowed["job_id"] == "job-1" and allowed["cid"] == "QmRulebook1"
    assert allowed["artifact_kind"] == "generated_assessment"
    assert allowed["report"] == fixture.artifacts["QmRulebook1"]
    assert [cid for cid, _ in fixture.artifact_reads] == ["QmRulebook1"]
    assert fixture.store.writes == writes


def rulebook_request(fixture, **overrides):
  return {"job_id": "job-1", "cid": "QmRulebook1", "profile_id": PROFILE,
          "request_actor": fixture.actor, "tenant_id": as_role(fixture, "tenant_admin"), **overrides}


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("state,kind", (("generated", "generated_assessment"),
                                        ("submitted", "review_submission")))
def test_actual_native_transports_serve_the_recorded_artifact(read_native, response_format, state, kind):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_rulebook_producer(fixture, state)
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_artifact",
                                                             rulebook_request(fixture))), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert {key: actual[key] for key in ("job_id", "profile_id", "cid", "artifact_kind")} == {
      "job_id": "job-1", "profile_id": PROFILE, "cid": "QmRulebook1", "artifact_kind": kind}
    assert actual["report"] == fixture.artifacts["QmRulebook1"]
    assert calls == 1 and fixture.store.writes == writes


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("overrides,status,code", (
  ({"cid": "archive-cid"}, 404, "not_found"),
  ({"cid": "pass"}, 404, "not_found"),
  ({"profile_id": "unknown"}, 400, "invalid_profile"),
  ({"tenant_id": None}, 400, "invalid_request"),
))
def test_actual_native_transports_refuse_without_reading(read_native, response_format, overrides, status, code):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_rulebook_producer(fixture, "generated")
    module.eng = scheduler_comms(fixture, response_format)
    payload = {key: value for key, value in rulebook_request(fixture, **overrides).items()
               if value is not None}
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_artifact", payload)),
                                         status)
    assert result == {"success": False, "error": code, "status_code": status}
    assert calls == 1 and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_native_transports_treat_a_foreign_artifact_as_unavailable(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_rulebook_producer(fixture, "generated")
    fixture.artifacts["QmRulebook1"] = {**fixture.artifacts["QmRulebook1"], "job_id": "foreign"}
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, "get_rulebook_artifact",
                                                             rulebook_request(fixture))), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    assert "foreign" not in str(result)


def test_get_report_still_refuses_a_rulebook_cid():
  with read_endpoint_fixture(bound=True) as fixture:
    install_rulebook_producer(fixture, "generated")
    tenant_id = as_role(fixture, "tenant_admin")
    result = fixture.Plugin.get_report(fixture.owner, "QmRulebook1", "job-1",
                                       request_actor=fixture.actor, tenant_id=tenant_id)
    assert result == {"success": False, "error": "not_found", "status_code": 404}
    assert "QmRulebook1" not in [cid for cid, _ in fixture.artifact_reads]
