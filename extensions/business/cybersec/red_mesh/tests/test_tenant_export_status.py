"""Checked export metadata: pure reads, real admission and native transport.

RM-084 P1: the endpoints require the caller's tenant. The pure service readers still accept the
legacy snapshot mode until RM-084 P6 removes it."""
import asyncio
from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest

from . import test_misp_export as misp_fixtures
from . import test_stix_export as stix_fixtures
from . import test_opencti_export as opencti_fixtures
from . import test_taxii_export as taxii_fixtures
from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms
from extensions.business.cybersec.red_mesh.services import misp_export, stix_export, opencti_export, taxii_export
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError


CASES = (
  (misp_export.get_misp_export_status, "misp_export", None),
  (stix_export.get_stix_export_status, "stix_export", None),
  (opencti_export.get_opencti_export_status, "opencti_export", "pushed"),
  (taxii_export.get_taxii_export_status, "taxii_export", "published"),
)


@pytest.mark.parametrize("reader,key,published", CASES)
def test_checked_status_uses_detached_snapshot_without_fallback_or_effects(reader, key, published):
  owner = MagicMock()
  meta = {"job_id": "job-1", "passes_exported": [1], "status": published or "stored"}
  source = {"job_id": "job-1", key: meta}
  result = reader(owner, "job-1", checked_job=source, snapshot_mode="legacy_unbound")
  assert result["job_id"] == "job-1" and result["found"] is True and result["exported"] is True
  result["passes_exported"].append(2)
  assert meta["passes_exported"] == [1]
  assert owner.mock_calls == []


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("kwargs", (
  {"snapshot_mode": "legacy_unbound"},
  {"checked_job": None, "snapshot_mode": "legacy_unbound"},
  {"checked_job": {"job_id": "foreign"}, "snapshot_mode": "legacy_unbound"},
  {"checked_job": {"job_id": "job-1", "execution_binding": None}, "snapshot_mode": "legacy_unbound"},
  {"checked_job": {"job_id": "job-1"}, "snapshot_mode": "unknown"},
  {"snapshot_mode": None},
))
def test_invalid_checked_snapshot_denies_before_fallback(reader, key, published, kwargs):
  owner = MagicMock()
  with pytest.raises(TenantStoreError):
    reader(owner, "job-1", **kwargs)
  assert owner.mock_calls == []


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("metadata", (None, {}))
def test_checked_empty_status_is_not_a_missing_job(reader, key, published, metadata):
  owner = MagicMock()
  result = reader(owner, "job-1", checked_job={"job_id": "job-1", key: metadata},
                  snapshot_mode="legacy_unbound")
  assert result == {"job_id": "job-1", "found": True, "exported": False}
  assert owner.mock_calls == []


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("metadata", ([], "", False, 0, "private", {"job_id": "foreign"},
  {"job_id": None}, *({field: None} for field in (
    "success", "error", "status_code", "result", "detail", "exception_metadata",
    "execution_binding", "found", "exported"))))
def test_checked_metadata_corruption_denies_without_repair(reader, key, published, metadata):
  owner = MagicMock()
  with pytest.raises(TenantStoreError):
    reader(owner, "job-1", checked_job={"job_id": "job-1", key: metadata},
           snapshot_mode="legacy_unbound")
  assert owner.mock_calls == []


@pytest.mark.parametrize("reader,key,published", CASES)
def test_checked_model_error_is_typed_and_unchecked_compatibility_remains(reader, key, published):
  owner = MagicMock()
  job = {"job_id": "job-1", "job_type": "model_test"}
  with pytest.raises(AdministrationDenied) as caught:
    reader(owner, "job-1", checked_job=job, snapshot_mode="legacy_unbound")
  assert caught.value.status_code == 400 and caught.value.error == "unsupported_job_type"
  assert owner.mock_calls == []
  owner._get_job_from_cstore.return_value = job
  legacy = reader(owner, "job-1")
  assert legacy["error"] == "unsupported_job_type" and legacy["found"] is True


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("role", ("tenant_admin", "tenant_pentester", "tenant_user", "super_tenant_admin"))
def test_endpoint_admits_every_tenant_reader(reader, key, published, role):
  with read_endpoint_fixture(bound=True) as fixture:
    fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = [
      {"role": role, "tenant_id": None if role == "super_tenant_admin" else fixture.tenant_id}]
    writes = list(fixture.store.writes)
    result = getattr(fixture.Plugin, reader.__name__)(fixture.owner, "job-1", request_actor=fixture.actor,
                                                      tenant_id=fixture.tenant_id)
    assert result == {"job_id": "job-1", "found": True, "exported": False}
    assert fixture.store.reads[0] == ("get", "auth", "reader")
    # The tenant reader point-reads the job; it never enumerates the shared job hash.
    assert fixture.store.reads[-1] == ("get", fixture.store.cfg_instance_id, "job-1")
    assert not any(row[0] == "list" and row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)
    assert fixture.store.writes == writes and fixture.artifact_reads == []


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_native_empty_status_is_post_and_no_store(read_native, reader, key, published, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__,
      {"job_id": "job-1", "request_actor": fixture.actor,
       "tenant_id": fixture.tenant_id})), 200)
    value = result["result"] if response_format == "WRAPPED" else result
    assert value == {"job_id": "job-1", "found": True, "exported": False}
    assert calls == 1


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("fault,status", (
  ("actorless", 404), ("empty_memberships", 404), ("null_memberships", 404),
  ("malformed_memberships", 404), ("inactive", 404), ("other_tenant", 404), ("no_tenant", 400),
  ("store", 503), ("unbound", 404), ("missing", 404), ("foreign_summary", 503), ("model", 400),
))
def test_real_account_and_stored_job_denials_have_no_effects(reader, key, published, fault, status):
  with read_endpoint_fixture(bound=True) as fixture:
    actor, job_id, tenant_id = fixture.actor, "job-1", fixture.tenant_id
    if fault == "actorless":
      actor = None
    elif fault.endswith("memberships"):
      fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = {
        "empty_memberships": [], "null_memberships": None, "malformed_memberships": "private",
      }[fault]
    elif fault == "inactive":
      fixture.store.account("reader", active=False)
    elif fault == "other_tenant":
      tenant_id = "tn_00000000-0000-4000-8000-000000000000"
    elif fault == "no_tenant":
      tenant_id = None
    elif fault == "store":
      fixture.store.fail_hkey = fixture.store.cfg_instance_id
    elif fault == "unbound":
      fixture.job.pop("execution_binding")
    elif fault == "missing":
      fixture.store.jobs.clear()
    elif fault == "foreign_summary":
      fixture.job[key] = {"job_id": "foreign", "private": "hidden"}
    elif fault == "model":
      fixture.job["job_type"] = "model_test"
    writes = list(fixture.store.writes)
    result = getattr(fixture.Plugin, reader.__name__)(fixture.owner, job_id, actor, tenant_id)
    code = "invalid_request" if fault == "no_tenant" else {400: "unsupported_job_type", 403: "forbidden",
                                                          404: "not_found", 503: "unavailable"}[status]
    assert result == {"success": False, "error": code, "status_code": status}
    assert fixture.store.writes == writes and fixture.artifact_reads == []
    if fault in ("actorless", "empty_memberships", "null_memberships", "malformed_memberships", "inactive",
                 "other_tenant", "no_tenant"):
      assert not any(row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("fault", ("job", "binding", "metadata"))
def test_copy_is_validated_before_status_projection(reader, key, published, fault):
  class ChangingJob(dict):
    def __deepcopy__(self, memo):
      copied = dict(self)
      if fault == "job":
        copied["job_id"] = "foreign"
      elif fault == "binding":
        copied["execution_binding"] = None
      else:
        copied[key] = {"job_id": "foreign"}
      return copied
  owner = MagicMock()
  with pytest.raises(TenantStoreError):
    reader(owner, "job-1", checked_job=ChangingJob(job_id="job-1"), snapshot_mode="legacy_unbound")
  assert owner.mock_calls == []


def producer_job(key, *, dry_run=False):
  """Use unchanged real export producers; only external dependencies are fixture transports."""
  if key == "misp_export":
    owner = misp_fixtures.TestPushToMisp()._setup_owner()
    job = {"job_id": "job-1", "job_cid": "archive_cid_123"}
    owner._get_job_from_cstore = lambda job_id: job
    from pymisp import MISPEvent
    event = MISPEvent()
    event.uuid, event.id = "fixture-event", 99
    with patch.object(misp_export, "PyMISP") as client, patch.object(misp_export, "emit_export_status_event"):
      client.return_value.add_event.return_value = event
      result = misp_export.push_to_misp(owner, "job-1")
      client.return_value.add_event.assert_called_once()
  elif key == "stix_export":
    owner = stix_fixtures._owner()
    job = owner.job_specs
    with patch.object(stix_export, "emit_export_status_event"):
      result = stix_export.export_stix_bundle(owner, "job-1")
  else:
    module, fixtures, producer = ((opencti_export, opencti_fixtures,
      opencti_export.dry_run_opencti_export if dry_run else opencti_export.push_to_opencti)
      if key == "opencti_export" else (taxii_export, taxii_fixtures,
      taxii_export.dry_run_taxii_export if dry_run else taxii_export.publish_to_taxii))
    owner = fixtures._owner()
    job = owner.job_specs
    with patch.dict("os.environ", {"REDMESH_OPENCTI_TOKEN_TEST": "fixture-only",
                                  "REDMESH_TAXII_TOKEN_TEST": "fixture-only"}), \
         patch.object(module.requests, "post", return_value=fixtures._Response()) as post, \
         patch.object(module, "emit_export_status_event"):
      result = producer(owner, "job-1")
      assert post.call_count == (0 if dry_run else 1)
  assert result["status"] == "ok", result
  assert isinstance(job[key], dict) and job[key]
  return deepcopy(job)


PRODUCERS = (("misp_export", False), ("stix_export", False), ("opencti_export", False),
             ("opencti_export", True), ("taxii_export", False), ("taxii_export", True))


@pytest.mark.parametrize("key,dry_run", PRODUCERS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_real_producer_metadata_survives_checked_native_transport(read_native, key, dry_run, response_format):
  job = producer_job(key, dry_run=dry_run)
  reader, _, published = next(case for case in CASES if case[1] == key)
  pure_owner = MagicMock()
  expected = reader(pure_owner, "job-1", checked_job=job, snapshot_mode="legacy_unbound")
  assert pure_owner.mock_calls == []
  assert expected["exported"] is (not dry_run)
  if dry_run:
    assert expected["status"] == "dry_run"
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    fixture.job[key] = deepcopy(job[key])
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__,
      {"job_id": "job-1", "request_actor": fixture.actor,
       "tenant_id": fixture.tenant_id})), 200)
    assert (result["result"] if response_format == "WRAPPED" else result) == expected
    assert calls == 1 and fixture.store.writes == writes and fixture.artifact_reads == []


@pytest.mark.parametrize("reader,key,published", CASES)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("outcome,status", (("model", 400), ("member", 404), ("tenant_user", 200),
  ("missing", 404), ("actorless", 404), ("malformed", 503), ("no_tenant", 400), ("blank_tenant", 400)))
def test_actual_native_denials_are_sanitized_and_no_store(read_native, reader, key, published, response_format, outcome, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    payload = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
    if outcome == "model":
      fixture.job["job_type"] = "model_test"
    elif outcome == "member":
      fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = []
    elif outcome == "missing":
      fixture.store.jobs.clear()
    elif outcome == "actorless":
      payload.pop("request_actor")
    elif outcome == "malformed":
      fixture.job[key] = {"result": {"private": "hidden"}}
    elif outcome == "tenant_user":
      fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = [
        {"role": "tenant_user", "tenant_id": fixture.tenant_id}]
    elif outcome == "no_tenant":
      payload.pop("tenant_id")
    elif outcome == "blank_tenant":
      payload["tenant_id"] = ""
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, reader.__name__, payload)), status)
    if outcome == "tenant_user":
      # reports:view is every tenant role's; a Tenant User reads export status like the others.
      assert (result["result"] if response_format == "WRAPPED" else result)["found"] is True
      return
    code = {"model": "unsupported_job_type", "member": "not_found", "missing": "not_found",
            "actorless": "not_found", "malformed": "unavailable", "no_tenant": "invalid_request",
            "blank_tenant": "invalid_request"}[outcome]
    assert result == {"success": False, "error": code, "status_code": status}
    assert calls == (0 if outcome == "blank_tenant" else 1)
    assert fixture.store.writes == writes and fixture.artifact_reads == []
