"""Every ordinary native endpoint uses fresh real requester policy before content effects."""
from copy import deepcopy
import inspect

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture


REQUESTS = {
  "get_job_status": ("job-1",), "get_job_data": ("job-1",), "get_job_archive": ("job-1",),
  "get_job_triage": ("job-1",), "get_job_progress": ("job-1",), "list_network_jobs": (),
  "list_local_jobs": (), "get_report": ("aggregate", "job-1"), "get_audit_log": (),
  "get_analysis": ("job-1",),
}


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("name", ("list_network_jobs", "list_local_jobs"))
def test_supported_response_hook_protects_list_data_without_changing_direct_results(response_format, name):
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.cfg_response_format = response_format
    jobs = {"status_code": {"job_id": "job-1"}, "error": {"job_id": "job-2"}}
    before = deepcopy(jobs)
    value = jobs if response_format == "RAW" else {"result": jobs, "status_code": jobs["status_code"],
                                                   "server_node_addr": "serving-node"}
    response = {"id": "request-1", "value": value}
    fixture.Plugin.on_response(fixture.owner, name, response)
    payload = response["value"] if response_format == "RAW" else response["value"]["result"]
    assert "__redmesh_checked_job_list_v1" in payload
    assert jobs == before
    assert response["id"] == "request-1"
    if response_format == "WRAPPED":
      assert "status_code" not in response["value"]
      assert response["value"]["server_node_addr"] == "serving-node"


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("status", (403, 404, 503))
def test_supported_response_hook_preserves_real_denials_and_unrelated_responses(response_format, status):
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.cfg_response_format = response_format
    denied = {"success": False, "error": "forbidden", "status_code": status}
    value = denied if response_format == "RAW" else {"result": denied, "status_code": status}
    response = {"id": "request-1", "value": value}
    before = deepcopy(response)
    fixture.Plugin.on_response(fixture.owner, "list_network_jobs", response)
    assert response == before
    response = {"id": "request-2", "value": {"status_code": {"job_id": "job-1"}}}
    before = deepcopy(response)
    fixture.Plugin.on_response(fixture.owner, "get_job_status", response)
    assert response == before


def invoke(fixture, name, *, actor=None, tenant_id=None, args=None):
  return getattr(fixture.Plugin, name)(fixture.owner, *(REQUESTS[name] if args is None else args),
    request_actor=fixture.actor if actor is None else actor,
    tenant_id=fixture.tenant_id if tenant_id is None else tenant_id)


@pytest.mark.parametrize("bound", (False, True))
@pytest.mark.parametrize("name", REQUESTS)
def test_every_endpoint_reads_from_fresh_stored_requester_and_checked_job(bound, name):
  with read_endpoint_fixture(bound=bound) as fixture:
    writes = list(fixture.store.writes)
    result = invoke(fixture, name)
    assert isinstance(result, dict) and "error" not in result, result
    assert fixture.store.reads[0] == ("get", "auth", "reader")
    assert sum(row == ("get", "auth", "reader") for row in fixture.store.reads) == 1
    assert fixture.store.writes == writes
    if name == "get_report":
      assert result["job_id"] == "job-1" and result["cid"] == "aggregate"
      assert result["report"] == fixture.artifacts["aggregate"]
      assert "job_id" not in result["report"]
      assert all(options == {"pin": False} for _, options in fixture.artifact_reads)
    elif name == "get_audit_log":
      assert result == {"audit_log": [{"job_id": "job-1", "event": "visible"}], "total": 1}
    elif name == "list_network_jobs":
      assert list(result) == ["job-1" if bound else "legacy-alias"]


@pytest.mark.parametrize("bound", (False, True))
@pytest.mark.parametrize("name", REQUESTS)
@pytest.mark.parametrize("fault", ("revoked", "missing", "malformed", "memberships"))
def test_denial_precedes_jobs_artifacts_and_audit(bound, name, fault):
  with read_endpoint_fixture(bound=bound) as fixture:
    if fault == "revoked":
      fixture.store.account("reader", active=False)
    elif fault == "missing":
      fixture.store.data.pop(("auth", "reader"))
    elif fault == "malformed":
      fixture.actor = {"account_id": []}
    else:
      fixture.store.account("reader", memberships=[])
    result = invoke(fixture, name)
    assert result["status_code"] in (403, 404), result
    assert result["success"] is False
    assert not fixture.artifact_reads
    assert not any(row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)


@pytest.mark.parametrize("name", REQUESTS)
def test_tenant_account_selector_omission_never_becomes_legacy(name):
  with read_endpoint_fixture() as fixture:
    result = getattr(fixture.Plugin, name)(fixture.owner, *REQUESTS[name], request_actor=fixture.actor)
    assert result["status_code"] == 403
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name", [name for name in REQUESTS if name not in ("list_network_jobs", "list_local_jobs", "get_audit_log")])
def test_point_requests_never_recover_foreign_jobs_or_select_list_response(name):
  with read_endpoint_fixture() as fixture:
    fixture.job["execution_binding"]["tenant_id"] = "foreign"
    result = invoke(fixture, name)
    assert result["status_code"] == 404
    assert fixture.artifact_reads == []
  for job_id in (None, "", " ", [], 1):
    with read_endpoint_fixture() as fixture:
      args = ("aggregate", job_id) if name == "get_report" else (job_id,)
      result = invoke(fixture, name, args=args)
      assert result["status_code"] == 400
      assert fixture.artifact_reads == []
      assert not any(row[0] == "list" for row in fixture.store.reads)


@pytest.mark.parametrize("bound", (False, True))
def test_absence_is_404_broken_reference_is_503_and_empty_lists_are_success(bound):
  with read_endpoint_fixture(bound=bound, archived=False) as fixture:
    assert invoke(fixture, "get_job_archive")["status_code"] == 404
    fixture.artifacts["pass"].pop("llm_analysis")
    assert invoke(fixture, "get_analysis")["status_code"] == 404
    assert invoke(fixture, "get_report", args=("unassociated", "job-1"))["status_code"] == 404
    fixture.artifacts["pass"] = RuntimeError("private artifact context")
    result = invoke(fixture, "get_analysis")
    assert result == {"success": False, "error": "unavailable", "status_code": 503}
    fixture.store.jobs.clear()
    assert invoke(fixture, "list_network_jobs") == {}
    assert invoke(fixture, "list_local_jobs") == {}


def test_audit_uses_named_permission_and_filters_before_total_and_limit():
  with read_endpoint_fixture() as fixture:
    fixture.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": fixture.tenant_id}])
    assert invoke(fixture, "get_audit_log")["status_code"] == 403
    assert not any(row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)
    fixture.store.account("reader", memberships=[{"role": "tenant_admin", "tenant_id": fixture.tenant_id}])
    fixture.owner._audit_log.extend([{"job_id": "job-1", "event": "second"}, {"event": "unattributed"},
                                     {"job_id": "foreign", "event": "last"}])
    assert invoke(fixture, "get_audit_log", args=(1,)) == {
      "audit_log": [{"job_id": "job-1", "event": "second"}], "total": 2}


def test_endpoint_signatures_preserve_all_original_positional_fields():
  original = {
    "get_job_status": ["job_id"], "get_job_data": ["job_id"],
    "get_job_archive": ["job_id", "summary_only", "pass_offset", "pass_limit"],
    "get_job_triage": ["job_id", "finding_id"], "get_job_progress": ["job_id"],
    "list_network_jobs": [], "list_local_jobs": [], "get_report": ["cid", "job_id"],
    "get_audit_log": ["limit"], "get_analysis": ["job_id", "cid", "pass_nr"],
  }
  with read_endpoint_fixture() as fixture:
    for name, fields in original.items():
      parameters = inspect.signature(getattr(fixture.Plugin, name)).parameters
      assert list(parameters) == ["self", *fields, "request_actor", "tenant_id"]
      assert all(parameter.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD for parameter in parameters.values())


def test_reused_owner_observes_current_rollout_and_account_each_time():
  with read_endpoint_fixture(bound=False) as fixture:
    assert "error" not in invoke(fixture, "get_job_data")
    fixture.owner.cfg_tenant_execution_stage = "draining"
    assert invoke(fixture, "get_job_data")["status_code"] == 403
    fixture.owner.cfg_tenant_execution_stage = "compatibility"
    assert "error" not in invoke(fixture, "get_job_data")
    fixture.store.account("reader", active=False)
    assert invoke(fixture, "get_job_data")["status_code"] == 404


def test_direct_legacy_cannot_access_any_present_binding_or_unassociated_cid():
  for binding in (None, {}, {"namespace": "foreign"}):
    with read_endpoint_fixture(bound=False) as fixture:
      fixture.job["execution_binding"] = deepcopy(binding)
      result = invoke(fixture, "get_report")
      assert result["status_code"] == 404
      assert fixture.artifact_reads == []
