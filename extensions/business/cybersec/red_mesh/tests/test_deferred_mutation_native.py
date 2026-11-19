"""RM-169 step 4a S8: `update_finding_triage` through the real effect admission (it was a 503 until now).

The file keeps its name from the deferral. The native-transport cases of that era pinned the 503 and the legacy
body fields; the strict-guard cases below test the same transport (`_ReadApiGuard`) for the new fields.
"""
import asyncio
import json
from contextlib import contextmanager
from copy import deepcopy
from unittest.mock import patch
from uuid import uuid4

import pytest

from extensions.business.cybersec.red_mesh.services import rulebook_assessment, triage
from extensions.business.cybersec.red_mesh.tenancy import http_runtime
from extensions.business.cybersec.red_mesh.tenancy.policy import PLATFORM_ROLES
from .contract_fixture import contract_terms
from .read_endpoint_fixtures import allow_pentester, as_role, read_endpoint_fixture

HOST = "192.0.2.10"


@contextmanager
def triage_fixture(role="tenant_pentester", *, allow=True):
  with read_endpoint_fixture(role=role) as fixture:
    owner = fixture.owner
    owner.ee_addr = "node-a"  # the fixture job's launcher
    owner._get_job_from_cstore = lambda job_id: deepcopy(fixture.store.jobs.get(job_id))
    findings = [{"finding_id": "finding-1", "title": "a", "confidence": "firm"},
                {"finding_id": "finding-2", "title": "b", "confidence": "firm"},
                {"finding_id": "finding-3", "title": "c", "confidence": "tentative"}]
    fixture.artifacts["archive"]["passes"][0]["findings"] = findings
    fixture.tenant = allow_pentester(fixture, allow)
    with patch.object(triage, "emit_finding_event"):
      yield fixture


def write(fixture, finding_ids=("finding-1",), status="false_positive", tenant="same", **kw):
  return fixture.Plugin.update_finding_triage(
    fixture.owner, job_id=kw.pop("job_id", "job-1"), finding_ids=list(finding_ids), status=status,
    request_actor=kw.pop("request_actor", fixture.actor),
    tenant_id=fixture.tenant_id if tenant == "same" else tenant, **kw)


def stored(fixture):
  return {key: value for key, value in fixture.store.data.items() if ":triage:" in key[0] and value is not None}


def second_tenant(fixture):
  request_id = str(uuid4())
  fixture.store.account("other-initial")
  prepared = fixture.administration.prepare_tenant({"account_id": "creator"}, request_id, "Other", "other-tenant",
                                                   "other-initial", **contract_terms())
  assert prepared["success"], prepared
  tenant_id = prepared["data"]["tenantId"]
  fixture.store.grant("other-initial", tenant_id)
  assert fixture.administration.activate_tenant({"account_id": "creator"}, request_id)["success"]
  return tenant_id


def test_a_tenant_pentester_stores_the_record_by_tenant_and_host_with_the_session_actor():
  with triage_fixture() as fixture:
    result = write(fixture, note="reviewed")
    assert result["success"] is True and result["complete"] is True, result
    member = result["results"][0]
    assert member["outcome"] == "updated" and "audit" not in member
    rows = stored(fixture)
    key = (f"shared-jobs:triage:t:{fixture.tenant_id}", f"{HOST}\x1ffinding-1")
    assert rows[key]["actor"] == "reader" and rows[key]["tenant_id"] == fixture.tenant_id
    assert rows[key]["host"] == HOST and rows[key]["note"] == "reviewed"
    assert not [k for k in rows if k[0].endswith(":triage") or k[0].endswith(":triage:audit")]  # no legacy rows


def test_a_rollup_dismiss_returns_each_member_and_a_retry_changes_nothing():
  with triage_fixture() as fixture:
    ids = ("finding-1", "finding-2", "finding-3")
    first = write(fixture, ids)
    assert [m["outcome"] for m in first["results"]] == ["updated"] * 3 and first["complete"] is True
    before = deepcopy(stored(fixture))
    again = write(fixture, ids)
    assert [m["outcome"] for m in again["results"]] == ["unchanged"] * 3
    assert stored(fixture) == before
    partial = write(fixture, ("finding-1", "missing"))
    assert partial["success"] is True and partial["complete"] is False
    assert [m["outcome"] for m in partial["results"]] == ["unchanged", "not_found"]


def test_get_job_triage_still_reads_with_reports_view_and_shows_the_write():
  with triage_fixture() as fixture:
    write(fixture)
    as_role(fixture, "tenant_user")  # holds reports:view, not findings:triage
    read = fixture.Plugin.get_job_triage(fixture.owner, job_id="job-1", request_actor=fixture.actor,
                                         tenant_id=fixture.tenant_id)
    assert read["triage"]["finding-1"]["status"] == "false_positive"
    denied = write(fixture, ("finding-2",))
    assert (denied["status_code"], denied["error"]) == (403, "forbidden")
    assert "finding-2" not in str(stored(fixture))


@pytest.mark.parametrize("role,allow,status,error", (
  ("tenant_user", True, 403, "forbidden"),
  ("tenant_pentester", False, 403, "pentesting_disabled"),
  ("tenant_admin", False, 403, "pentesting_disabled"),
))
def test_denied_callers_write_nothing(role, allow, status, error):
  with triage_fixture(role, allow=allow) as fixture:
    result = write(fixture)
    assert (result["status_code"], result["error"], result["success"]) == (status, error, False)
    assert stored(fixture) == {}


@pytest.mark.parametrize("role", ("super_tenant_admin", "super_pentester", "tenant_admin", "tenant_pentester"))
def test_every_role_that_holds_review_may_triage_without_a_reviewer_designation(role):
  with triage_fixture(role, allow=True) as fixture:
    assert write(fixture)["success"] is True
    assert len(stored(fixture)) == 2  # the record and its audit row


def test_another_tenants_member_cannot_reach_the_job_and_nothing_is_written():
  with triage_fixture() as fixture:
    other = second_tenant(fixture)
    fixture.store.account("reader", memberships=[{"role": "tenant_pentester", "tenant_id": other}])
    fixture.tenant_store.put("tenant", other, record={**fixture.tenant_store.get("tenant", other),
                                                      "allow_pentester": True})
    # naming their own tenant with a job of the first: the job is not theirs
    result = write(fixture, tenant=other)
    assert (result["success"], result["status_code"], result["error"]) == (False, 404, "not_found")
    # naming the job's tenant with only the other membership: no scope there
    result = write(fixture)
    assert result["success"] is False and result["status_code"] in (403, 404)
    assert stored(fixture) == {}
    assert fixture.store.writes == [] or all(":triage:" not in key[0] for key in fixture.store.writes)


def test_a_missing_tenant_or_unknown_account_is_refused_before_any_effect():
  with triage_fixture() as fixture:
    assert write(fixture, tenant=None)["status_code"] == 400
    assert write(fixture, request_actor=None)["success"] is False
    assert write(fixture, request_actor={"account_id": "nobody"})["success"] is False
    assert write(fixture, job_id="foreign-job")["status_code"] == 404
    assert stored(fixture) == {}


def test_typed_validation_errors_are_public_and_carry_no_prose():
  with triage_fixture() as fixture:
    for kwargs, ids in (({"status": "wont_fix"}, ("finding-1",)), ({"status": "accepted_risk"}, ("finding-1",)),
                        ({"status": "accepted_risk", "review_at": 5}, ("finding-1",)),
                        ({"status": "false_positive", "confirm": True}, ("finding-1",)), ({}, ())):
      result = write(fixture, ids, **kwargs)
      assert result == {"success": False, "error": "validation_error", "status_code": 400}, kwargs
    assert stored(fixture) == {}


def test_a_pending_review_submission_on_the_job_blocks_the_write_with_a_typed_conflict():
  with triage_fixture() as fixture:
    profile = rulebook_assessment.list_rulebook_profiles()[0]["profile_id"]
    fixture.store.data[("shared-jobs:rulebook_review:submissions", f"job-1:{profile}")] = {"pending": {"x": 1}}
    result = write(fixture)
    assert result == {"success": False, "error": "submission_in_progress", "status_code": 409}
    assert stored(fixture) == {}


def test_a_failure_after_the_first_record_reports_the_effect_not_unavailable():
  with triage_fixture() as fixture:
    real = triage.JobStateRepository.put_host_triage
    calls = []

    def flaky(repo, state):
      calls.append(state.finding_id)
      if len(calls) == 2:
        raise RuntimeError("store down: private")
      return real(repo, state)
    with patch.object(triage.JobStateRepository, "put_host_triage", flaky):
      result = write(fixture, ("finding-1", "finding-2"))
    assert result == {"success": False, "error": "effect_incomplete", "effect_state": "persisted", "status_code": 500}
    assert "private" not in json.dumps(result)
    retry = write(fixture, ("finding-1", "finding-2"))
    assert [m["outcome"] for m in retry["results"]] == ["unchanged", "updated"]


def test_confirm_marks_a_possible_finding_and_refuses_a_firm_one():
  with triage_fixture() as fixture:
    ok = write(fixture, ("finding-3",), status="open", confirm=True)
    assert ok["results"][0]["triage"]["confirmed_by"] == "reader"
    firm = write(fixture, ("finding-1",), status="open", confirm=True)
    assert firm["results"][0]["outcome"] == "not_tentative" and firm["complete"] is False


# -- the strict transport ---------------------------------------------------------------------

def run_guard(body, *, method="POST", path="/update_finding_triage", app_status=200, app_body=None):
  seen = []

  async def app(scope, receive, send):
    seen.append(await receive())
    await send({"type": "http.response.start", "status": app_status, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": json.dumps(app_body or {"success": True}).encode()})

  sent = []

  async def send(event):
    sent.append(event)

  async def receive():
    return {"type": "http.request", "body": body if isinstance(body, bytes) else json.dumps(body).encode(),
            "more_body": False}
  scope = {"type": "http", "method": method, "path": path, "query_string": b""}
  asyncio.run(http_runtime._ReadApiGuard(app)(scope, receive, send))
  status = sent[0]["status"]
  payload = json.loads(b"".join(e.get("body", b"") for e in sent if e["type"] == "http.response.body"))
  return status, payload, len(seen)


VALID = {"job_id": "j", "finding_ids": ["f"], "status": "false_positive", "tenant_id": "tn_x",
         "request_actor": {"account_id": "a"}}


def test_the_guard_takes_the_new_fields_with_exact_types_and_nothing_else():
  assert run_guard(VALID)[0] == 200
  assert run_guard({**VALID, "review_at": 2_000_000_000, "confirm": True, "note": "n"})[0] == 200
  for bad in ({**VALID, "review_at": 2_000_000_000.5}, {**VALID, "finding_ids": "f"}, {**VALID, "confirm": 1},
              {**VALID, "actor": "forged"}, {**VALID, "finding_id": "f"}, {**VALID, "execution_binding": {}},
              {**VALID, "tenant_id": " "}, [], "x"):
    status, payload, calls = run_guard(bad)
    assert (status, payload, calls) == (400, {"success": False, "error": "invalid_request", "status_code": 400}, 0), bad
  assert run_guard(VALID, method="GET")[0] == 405


def test_typed_triage_refusals_survive_the_guard_and_untyped_codes_do_not():
  for status, code in ((400, "validation_error"), (409, "submission_in_progress"), (409, "job_launcher_mismatch"),
                       (409, "triage_contention"), (409, "not_available"), (400, "model_test_not_supported")):
    assert (status, code) in http_runtime._TYPED_READ_PAIRS
    assert (status, code) in http_runtime._TYPED_READ_ERRORS["/update_finding_triage"]
  response = http_runtime._read_error_response(409, code="submission_in_progress")
  assert response.status_code == 409 and json.loads(response.body)["error"] == "submission_in_progress"
  assert http_runtime._read_error_response(409, code="made_up").status_code == 503


def test_the_endpoint_is_an_effect_path_not_a_read_path():
  assert "update_finding_triage" in http_runtime._EFFECT_FIELDS
  assert "update_finding_triage" not in http_runtime._READ_FIELDS
  assert "findings:triage" in __import__(
    "extensions.business.cybersec.red_mesh.pentester_api_01", fromlist=["x"]).PentesterApi01Plugin._TENANT_EFFECT_OPERATIONS
