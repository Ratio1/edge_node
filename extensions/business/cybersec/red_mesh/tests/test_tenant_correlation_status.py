"""Tenant reader admission for correlation status, with no provider or storage effects.

RM-084 P2: the endpoint requires the caller's tenant (`reports:view`), so the unscoped reader half
this file used to cover is gone -- a missing selector is a bad request and a job outside the named
tenant is indistinguishable from an absent one.
"""
import asyncio
from copy import deepcopy

import pytest

from .read_endpoint_fixtures import as_role, read_endpoint_fixture
from .test_tenant_read_native import (
  assert_json_response, body_for, install, read_native, request as native_request, scheduler_comms,
)


def test_status_uses_real_tenant_authority_and_detached_projection():
  with read_endpoint_fixture(bound=True) as fixture:
    summary = {"job_id": "job-1", "status": "completed", "counts": {"matched_events": 2}}
    fixture.job["detection_correlation"] = deepcopy(summary)
    writes = list(fixture.store.writes)
    result = fixture.Plugin.get_detection_correlation(fixture.owner, "job-1",
      request_actor=fixture.actor, tenant_id=as_role(fixture, "tenant_admin"))
    assert result == {"job_id": "job-1", "found": True, "correlation": summary}
    result["correlation"]["counts"]["matched_events"] = 99
    assert fixture.job["detection_correlation"] == summary
    assert fixture.store.reads[0] == ("get", "auth", "reader")
    assert sum(row == ("get", "auth", "reader") for row in fixture.store.reads) == 1
    # The tenant reader point-reads the job; it never enumerates the shared job hash.
    assert fixture.store.reads[-1] == ("get", fixture.store.cfg_instance_id, "job-1")
    assert fixture.store.writes == writes
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("role", ("tenant_user", "tenant_pentester", "tenant_admin",
                                  "super_pentester", "super_tenant_admin"))
def test_every_tenant_role_holding_reports_view_can_read_without_effects(role):
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, role)
    writes = list(fixture.store.writes)
    result = fixture.Plugin.get_detection_correlation(fixture.owner, "job-1", fixture.actor,
                                                      tenant_id)
    assert result == {"job_id": "job-1", "found": True, "correlation": None}
    assert fixture.artifact_reads == [] and fixture.store.writes == writes


@pytest.mark.parametrize("fault,status", (
  ("missing_actor", 404), ("none_scope", 404), ("null_memberships", 404),
  ("malformed_memberships", 404), ("inactive", 404), ("other_tenant", 404),
  ("broken_store", 503), ("unbound_job", 404), ("null_binding", 404), ("foreign_binding", 404),
  ("missing_job", 404), ("collision", 503), ("foreign_summary", 503), ("model", 400),
  ("missing_tenant", 400),
))
def test_real_admission_denials_never_read_artifacts_or_write(fault, status):
  with read_endpoint_fixture(bound=True) as fixture:
    actor, job_id = fixture.actor, "job-1"
    tenant_id = as_role(fixture, "tenant_admin")
    if fault == "missing_actor":
      actor = None
    elif fault.endswith("memberships") or fault == "none_scope":
      fixture.store.data[("auth", "reader")]["memberships"] = {
        "none_scope": [], "null_memberships": None, "malformed_memberships": "private",
      }[fault]
    elif fault == "inactive":
      fixture.store.account("reader", active=False,
        memberships=[{"role": "tenant_admin", "tenant_id": fixture.tenant_id}])
    elif fault == "other_tenant":
      tenant_id = "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"
    elif fault == "broken_store":
      fixture.store.fail_hkey = fixture.store.cfg_instance_id
    elif fault in ("unbound_job", "null_binding", "foreign_binding"):
      fixture.job["execution_binding"] = {
        "unbound_job": {}, "null_binding": None,
        "foreign_binding": {**fixture.job["execution_binding"],
                            "tenant_id": "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"},
      }[fault]
    elif fault == "missing_job":
      fixture.store.jobs.clear()
    elif fault == "collision":
      fixture.store.jobs["job-1"] = {**fixture.job, "job_id": "other"}
    elif fault == "foreign_summary":
      fixture.job["detection_correlation"] = {"job_id": "foreign", "private": "must not return"}
    elif fault == "model":
      fixture.job["job_type"] = "model_test"
    elif fault == "missing_tenant":
      tenant_id = None
    writes = list(fixture.store.writes)
    result = fixture.Plugin.get_detection_correlation(fixture.owner, job_id, actor, tenant_id)
    assert result == {"success": False, "error": {400: "unsupported_job_type" if fault == "model"
                       else "invalid_request", 403: "forbidden", 404: "not_found",
                       503: "unavailable"}[status], "status_code": status}
    assert fixture.artifact_reads == [] and fixture.store.writes == writes
    if fault in ("missing_actor", "none_scope", "null_memberships", "malformed_memberships",
                 "inactive", "other_tenant", "missing_tenant"):
      assert not any(row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("outcome,status", (("empty", 200), ("summary", 200), ("model", 400),
  ("member", 404), ("missing", 404), ("actorless", 404), ("malformed_summary", 503), ("scope", 400)))
def test_actual_native_status_wire_and_typed_denials(read_native, response_format, outcome, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    payload = {"job_id": "job-1", "request_actor": fixture.actor,
               "tenant_id": as_role(fixture, "tenant_admin")}
    if outcome == "summary":
      fixture.job["detection_correlation"] = {"job_id": "job-1", "status": "completed"}
    elif outcome == "model":
      fixture.job["job_type"] = "model_test"
    elif outcome == "member":
      fixture.store.data[("auth", "reader")]["memberships"] = []
    elif outcome == "missing":
      fixture.store.jobs.clear()
    elif outcome == "actorless":
      payload.pop("request_actor")
    elif outcome == "malformed_summary":
      fixture.job["detection_correlation"] = {"job_id": "foreign"}
    elif outcome == "scope":
      payload["tenant_id"] = ""
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    response, calls = assert_json_response(asyncio.run(native_request(
      module, "get_detection_correlation", payload)), status)
    assert calls == (0 if outcome == "scope" else 1)
    if status == 200:
      value = response["result"] if response_format == "WRAPPED" else response
      assert value == {"job_id": "job-1", "found": True, "correlation": fixture.job.get("detection_correlation")}
    else:
      code = {"model": "unsupported_job_type", "member": "not_found", "missing": "not_found",
              "actorless": "not_found", "malformed_summary": "unavailable", "scope": "invalid_request"}[outcome]
      assert response == {"success": False, "error": code, "status_code": status}
    assert fixture.store.writes == writes and fixture.artifact_reads == []


@pytest.mark.parametrize("name", ("get_detection_correlation", "get_job_data"))
@pytest.mark.parametrize("detail,valid", (
  ({"success": False, "error": "unsupported_job_type", "status_code": 400, "private": "hidden"}, True),
  ({"success": True, "error": "unsupported_job_type", "status_code": 400}, False),
  ({"success": 0, "error": "unsupported_job_type", "status_code": 400}, False),
  ({"success": False, "error": "unsupported_job_type", "status_code": "400"}, False),
  ({"success": False, "error": "private", "status_code": 400}, False),
  ({"error": "unsupported_job_type", "status_code": 400}, False),
  ({"detail": "unsupported_job_type", "private": "hidden"}, True),
  ({"detail": "unsupported_job_type", "success": True}, False),
  ({"detail": "unsupported_job_type", "error": "private"}, False),
  ({"detail": "private"}, False),
))
def test_http_model_error_allowance_is_exact_and_operation_local(read_native, name, detail, valid):
  module, _ = read_native
  install(module)

  async def error_reply(*args, **kwargs):
    module.eng.calls.append((args, kwargs))
    return {"status_code": 400, "result": detail}

  module.eng.call_plugin = error_reply
  response, calls = assert_json_response(asyncio.run(native_request(module, name, body_for(name))), 400)
  code = "unsupported_job_type" if valid and name == "get_detection_correlation" else "invalid_request"
  assert response == {"success": False, "error": code, "status_code": 400}
  assert calls == 1
