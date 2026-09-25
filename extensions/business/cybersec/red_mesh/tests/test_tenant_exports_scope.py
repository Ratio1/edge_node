"""RM-084 P1: every export endpoint (E1) is tenant-scoped with no unscoped half.

One matrix over all sixteen endpoints, through real admission against the stored account, tenant
and job: the caller's tenant is required (400), a job owned by another tenant is indistinguishable
from a missing one (404), and a role without the operation is refused (403) before any artifact or
destination is touched.
"""
from uuid import uuid4

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture

# (endpoint, extra kwargs). Effects and the MISP/STIX/SIEM downloads need reports:export; the
# per-job status reads need reports:view; the job-less reads and the synthetic delivery need
# reports:export.
JOB_EXPORTS = (
  ("export_misp", {}), ("export_misp_json", {}), ("export_stix_bundle", {}),
  ("export_stix_json", {}), ("export_siem_events_json", {}),
  ("dry_run_opencti_export", {}), ("push_to_opencti", {}),
  ("dry_run_taxii_export", {}), ("publish_to_taxii", {}),
)
JOB_STATUS_READS = (
  ("get_misp_export_status", {}), ("get_stix_export_status", {}),
  ("get_opencti_export_status", {}), ("get_taxii_export_status", {}),
)
JOBLESS = (
  ("get_integration_status", {}), ("get_misp_export_config_status", {}), ("test_event_export", {}),
)
JOB_ENDPOINTS = JOB_EXPORTS + JOB_STATUS_READS
ALL = JOB_ENDPOINTS + JOBLESS


def invoke(fixture, name, extra, *, tenant_id, job_id="job-1"):
  method = getattr(fixture.Plugin, name)
  kwargs = dict(extra, request_actor=fixture.actor, tenant_id=tenant_id)
  if (name, extra) in JOB_ENDPOINTS:
    return method(fixture.owner, job_id, **kwargs)
  return method(fixture.owner, **kwargs)


def second_tenant(fixture):
  request_id = str(uuid4())
  fixture.store.account("other-admin")
  prepared = fixture.administration.prepare_tenant({"account_id": "creator"}, request_id,
    "Other tenant", "other-tenant", "other-admin")
  assert prepared["success"], prepared
  tenant_id = prepared["data"]["tenantId"]
  fixture.store.grant("other-admin", tenant_id)
  assert fixture.administration.activate_tenant({"account_id": "creator"}, request_id)["success"]
  return tenant_id


def assert_denied(result, status, error):
  # Effect denials also carry `status: "error"` for the panels; the typed triple is the contract.
  assert (result.get("success"), result.get("status_code"), result.get("error")) == (False, status, error), result


def set_membership(fixture, role, tenant_id):
  fixture.store.data[("auth", "reader")]["memberships"] = [
    {"role": role, "tenant_id": tenant_id}]


@pytest.mark.parametrize("name,extra", ALL)
@pytest.mark.parametrize("tenant_id", (None, "", "   "))
def test_a_missing_tenant_is_refused_before_admission(name, extra, tenant_id):
  with read_endpoint_fixture(bound=True) as fixture:
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert_denied(result, 400, "invalid_request")
    assert fixture.artifact_reads == []
    assert not any(row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)


@pytest.mark.parametrize("name,extra", JOB_ENDPOINTS)
def test_a_job_owned_by_another_tenant_is_not_found(name, extra):
  """The caller is fully authorized in its own tenant and names it; the job is not in it."""
  with read_endpoint_fixture(bound=True) as fixture:
    other = second_tenant(fixture)
    set_membership(fixture, "tenant_admin", other)
    result = invoke(fixture, name, extra, tenant_id=other)
    assert_denied(result, 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra", ALL)
def test_a_tenant_the_caller_does_not_belong_to_is_not_found(name, extra):
  with read_endpoint_fixture(bound=True) as fixture:
    other = second_tenant(fixture)
    result = invoke(fixture, name, extra, tenant_id=other)
    assert_denied(result, 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra", JOB_EXPORTS + JOBLESS)
def test_a_tenant_user_cannot_export(name, extra):
  with read_endpoint_fixture(bound=True) as fixture:
    set_membership(fixture, "tenant_user", fixture.tenant_id)
    writes = list(fixture.store.writes)
    result = invoke(fixture, name, extra, tenant_id=fixture.tenant_id)
    assert_denied(result, 403, "forbidden")
    assert fixture.artifact_reads == [] and fixture.store.writes == writes


@pytest.mark.parametrize("name,extra", JOB_STATUS_READS)
@pytest.mark.parametrize("role", ("tenant_user", "tenant_pentester", "tenant_admin"))
def test_every_tenant_role_reads_export_status(name, extra, role):
  with read_endpoint_fixture(bound=True) as fixture:
    set_membership(fixture, role, fixture.tenant_id)
    result = invoke(fixture, name, extra, tenant_id=fixture.tenant_id)
    assert result == {"job_id": "job-1", "found": True, "exported": False}


@pytest.mark.parametrize("name,extra", JOB_EXPORTS + JOBLESS)
@pytest.mark.parametrize("role", ("tenant_pentester", "tenant_admin", "super_tenant_admin"))
def test_every_export_role_is_admitted(name, extra, role):
  """Admission only: what the destination does afterwards is each service's own suite."""
  with read_endpoint_fixture(bound=True) as fixture:
    set_membership(fixture, role, None if role == "super_tenant_admin" else fixture.tenant_id)
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    result = invoke(fixture, name, extra, tenant_id=fixture.tenant_id)
    assert not (isinstance(result, dict) and result.get("success") is False
                and result.get("status_code") in (400, 403, 404)), result
