"""RM-084 P2: every E2 endpoint is tenant-scoped with no unscoped half.

One matrix over the rulebook reads and mutations, the assessment builder, the detection-correlation
read and ingest, and raw model-test evidence, through real admission against the stored account,
tenant and job: the caller's tenant is required (400), a job owned by another tenant is
indistinguishable from a missing one (404), and a role without the operation is refused (403)
before any record, artifact or shared status row is touched.

The gates differ across the group, which is the point of the matrix: `reports:view` for the three
reads (every member), `reports:export` for the mutations (not a tenant_user), and `evidence:read`
for raw evidence (platform roles only, so the owning tenant's own administrator is refused).
"""
from uuid import uuid4

import pytest

from .read_endpoint_fixtures import allow_pentester, as_role, read_endpoint_fixture
from .contract_fixture import contract_terms

PROFILE = "nis2.eu_baseline.v1"

READS = (
  ("get_detection_correlation", {}),
  ("get_rulebook_assessment_status", {"profile_id": PROFILE}),
  ("get_rulebook_review", {"profile_id": PROFILE}),
  # Report-level review (RM-086 item 4) runs through the same admission seams.
  ("get_report_review", {}),
)
MUTATIONS = (
  ("generate_rulebook_assessment", {"profile_id": PROFILE, "persist": False}),
  ("save_rulebook_review_draft", {"profile_id": PROFILE, "answers": {}}),
  ("submit_rulebook_review", {"profile_id": PROFILE}),
  ("reopen_rulebook_review", {"profile_id": PROFILE}),
  ("update_rulebook_review", {"profile_id": PROFILE, "answers": {}}),
  ("correlate_suricata_eve", {"eve_jsonl": "{}"}),
  ("approve_report", {"expected_review_revision": 0}),
  ("reject_report", {"expected_review_revision": 0, "note": "no"}),
)
EVIDENCE = (("get_raw_model_test_evidence", {}),)
# The typed rulebook artifact read answers 404 for a CID the job does not record, so its
# role matrix seeds one (below) instead of joining READS.
ARTIFACT = (("get_rulebook_artifact", {"cid": "rulebook", "profile_id": PROFILE}),)
ALL = READS + MUTATIONS + EVIDENCE + ARTIFACT

# The operation each endpoint runs as, and therefore which roles hold it.
VIEW_ROLES = ("tenant_user", "tenant_pentester", "tenant_admin", "super_pentester",
              "super_tenant_admin")
EXPORT_ROLES = ("tenant_pentester", "tenant_admin", "super_pentester", "super_tenant_admin")
# Owner, 2026-09-30: the review mutations run as `reports:review`, held by the launch roles under the
# launch Allow Pentester rule. `correlate_suricata_eve` is an ingest and stays `reports:export`.
REVIEW_ROLES = ("tenant_pentester", "super_pentester", "super_tenant_admin")
REVIEW = tuple(row for row in MUTATIONS if row[0] != "correlate_suricata_eve")
EXPORT_MUTATIONS = tuple(row for row in MUTATIONS if row[0] == "correlate_suricata_eve")
EVIDENCE_ROLES = ("super_pentester", "super_tenant_admin")
OTHER_TENANT = "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"


def invoke(fixture, name, extra, *, tenant_id, job_id="job-1"):
  method = getattr(fixture.Plugin, name)
  return method(fixture.owner, job_id, **dict(extra, request_actor=fixture.actor,
                                              tenant_id=tenant_id))


def second_tenant(fixture):
  """A real second tenant, so a cross-tenant call is refused by the store rather than by shape."""
  request_id = str(uuid4())
  fixture.store.account("other-admin")
  prepared = fixture.administration.prepare_tenant({"account_id": "creator"}, request_id,
    "Other tenant", "other-tenant", "other-admin", **contract_terms())
  assert prepared["success"], prepared
  tenant_id = prepared["data"]["tenantId"]
  fixture.store.grant("other-admin", tenant_id)
  assert fixture.administration.activate_tenant({"account_id": "creator"}, request_id)["success"]
  return tenant_id


def allow_pentester_in(fixture, tenant_id):
  """Switch Allow Pentester on for a tenant other than the fixture's own."""
  tenant = fixture.tenant_store.get("tenant", tenant_id)
  fixture.tenant_store.put("tenant", tenant_id, record={**tenant, "allow_pentester": True})


def record_artifact(fixture, name):
  """Give the artifact read a CID the job records, so a denial is admission's and not the CID check's."""
  if name == "get_rulebook_artifact":
    fixture.job["rulebook_assessments"] = {PROFILE: {"artifact_cid": "rulebook"}}
    fixture.artifacts["rulebook"] = {"artifact_kind": "generated_assessment", "job_id": "job-1",
                                     "profile": {"profile_id": PROFILE}}


def assert_denied(result, status, error):
  # Mutation denials also carry `status: "error"` for the panels; the typed triple is the contract.
  assert (result.get("success"), result.get("status_code"), result.get("error")) == (False, status, error), result


def assert_admitted(result):
  """Admission only: what the record or artifact layer answers afterwards is its own suite."""
  assert not (isinstance(result, dict) and result.get("success") is False
              and result.get("status_code") in (400, 403, 404)), result


@pytest.mark.parametrize("name,extra", ALL)
@pytest.mark.parametrize("tenant_id", (None, "", "   "))
def test_a_missing_tenant_is_refused_before_admission(name, extra, tenant_id):
  with read_endpoint_fixture(bound=True) as fixture:
    as_role(fixture, "super_tenant_admin")
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert_denied(result, 400, "invalid_request")
    assert fixture.artifact_reads == []
    assert not any(row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)


@pytest.mark.parametrize("name,extra", ALL)
def test_a_job_owned_by_another_tenant_is_not_found(name, extra):
  """The caller is fully authorized in the tenant it names; the job is not in it."""
  with read_endpoint_fixture(bound=True) as fixture:
    other = second_tenant(fixture)
    # A membership that holds the endpoint's own operation in that tenant, so the 404 is the job's
    # ownership and not the role: raw evidence needs a platform role for `evidence:read`.
    fixture.store.data[("auth", "reader")]["memberships"] = [
      {"role": "super_tenant_admin", "tenant_id": None} if (name, extra) in EVIDENCE
      else {"role": "tenant_pentester" if (name, extra) in REVIEW else "tenant_admin",
            "tenant_id": other}]
    if (name, extra) in REVIEW:
      allow_pentester_in(fixture, other)
    record_artifact(fixture, name)
    result = invoke(fixture, name, extra, tenant_id=other)
    assert_denied(result, 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra", ALL)
def test_a_tenant_the_caller_does_not_belong_to_is_not_found(name, extra):
  with read_endpoint_fixture(bound=True) as fixture:
    other = second_tenant(fixture)
    as_role(fixture, "tenant_admin")  # a member of the fixture tenant only
    record_artifact(fixture, name)
    result = invoke(fixture, name, extra, tenant_id=other)
    assert_denied(result, 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra", ALL)
def test_an_unknown_tenant_is_not_found(name, extra):
  with read_endpoint_fixture(bound=True) as fixture:
    as_role(fixture, "super_tenant_admin")  # authorized everywhere; the tenant does not exist
    record_artifact(fixture, name)
    result = invoke(fixture, name, extra, tenant_id=OTHER_TENANT)
    assert_denied(result, 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra", MUTATIONS)
def test_a_tenant_user_cannot_mutate_a_review(name, extra):
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_user")
    writes = list(fixture.store.writes)
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert_denied(result, 403, "forbidden")
    assert fixture.artifact_reads == [] and fixture.store.writes == writes


@pytest.mark.parametrize("name,extra", EVIDENCE)
@pytest.mark.parametrize("role", ("tenant_user", "tenant_pentester", "tenant_admin"))
def test_no_tenant_local_role_reads_raw_evidence(name, extra, role):
  """The P2 acceptance criterion: `evidence:read` is platform-only, so the owning tenant's
  administrator keeps every report it can read and still cannot open the decrypted raw evidence."""
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, role)
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert_denied(result, 403, "forbidden")
    assert result.get("error") != "unsupported_job_type"
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra", READS)
@pytest.mark.parametrize("role", VIEW_ROLES)
def test_every_tenant_role_reads_review_state(name, extra, role):
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, role)
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert result.get("job_id") == "job-1", result
    assert_admitted(result)


@pytest.mark.parametrize("name,extra", ARTIFACT)
@pytest.mark.parametrize("role", VIEW_ROLES)
def test_every_tenant_role_reads_a_recorded_rulebook_artifact(name, extra, role):
  with read_endpoint_fixture(bound=True) as fixture:
    record_artifact(fixture, name)
    tenant_id = as_role(fixture, role)
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert result.get("cid") == "rulebook" and result.get("report") == fixture.artifacts["rulebook"], result


@pytest.mark.parametrize("name,extra", EXPORT_MUTATIONS)
@pytest.mark.parametrize("role", EXPORT_ROLES)
def test_every_export_role_is_admitted_to_the_ingest(name, extra, role):
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, role)
    assert_admitted(invoke(fixture, name, extra, tenant_id=tenant_id))


@pytest.mark.parametrize("name,extra", REVIEW)
@pytest.mark.parametrize("role", REVIEW_ROLES)
def test_every_launch_role_is_admitted_to_the_review_mutations(name, extra, role):
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, role)
    allow_pentester(fixture)
    assert_admitted(invoke(fixture, name, extra, tenant_id=tenant_id))


@pytest.mark.parametrize("name,extra", REVIEW)
def test_a_tenant_admin_cannot_mutate_a_review(name, extra):
  """A Tenant Admin downloads reports (`reports:export`) but does not sign them off."""
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_admin")
    allow_pentester(fixture)
    writes = list(fixture.store.writes)
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert_denied(result, 403, "forbidden")
    assert fixture.artifact_reads == [] and fixture.store.writes == writes


@pytest.mark.parametrize("name,extra", REVIEW)
@pytest.mark.parametrize("role,bound", (("tenant_pentester", True), ("super_pentester", False),
                                        ("super_tenant_admin", False)))
def test_the_review_mutations_follow_the_launch_pentesting_rule(name, extra, role, bound):
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, role)
    allow_pentester(fixture, False)
    writes = list(fixture.store.writes)
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    if bound:
      assert_denied(result, 403, "pentesting_disabled")
      assert fixture.artifact_reads == [] and fixture.store.writes == writes
    else:
      assert_admitted(result)


@pytest.mark.parametrize("name,extra", EVIDENCE)
@pytest.mark.parametrize("role", EVIDENCE_ROLES)
def test_the_platform_roles_are_admitted_to_raw_evidence(name, extra, role):
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, role)
    result = invoke(fixture, name, extra, tenant_id=tenant_id)
    # job-1 is a network scan, so an admitted caller gets the job-type answer, not a denial.
    assert result.get("error") == "unsupported_job_type", result
    assert_admitted(result)


@pytest.mark.parametrize("name,extra,code", (
  ("save_rulebook_review_draft", {"profile_id": PROFILE, "answers": {}},
   "review_revision_conflict"),
  ("submit_rulebook_review", {"profile_id": PROFILE}, "submission_pass_stale"),
  ("approve_report", {}, "review_revision_conflict"),
  ("reject_report", {"note": "no"}, "review_revision_conflict"),
))
def test_a_typed_review_conflict_code_survives_the_tenant_path(name, extra, code):
  """The revision fence is the reason these four keep their own response shape; scoping them must
  not route them through the effect wrapper's `effect_incomplete` rewrite."""
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_pentester")
    allow_pentester(fixture)
    result = invoke(fixture, name, dict(extra, expected_review_revision=999), tenant_id=tenant_id)
    assert result.get("error") != "effect_incomplete", result
    assert result.get("error_code") == code, result
    # The rich payload the fence UX reads is still there, not a bare denial.
    assert set(result) - {"status", "job_id", "error_code"}, result
