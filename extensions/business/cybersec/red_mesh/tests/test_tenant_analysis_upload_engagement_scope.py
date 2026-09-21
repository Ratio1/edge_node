"""RM-084 P3: every E3 endpoint is tenant-scoped with no unscoped half.

One matrix over manual analysis, the authorization upload, engagement deletion and stop-monitoring,
through real admission against the stored account, tenant and job: the caller's tenant is required
(400), a job owned by another tenant is indistinguishable from a missing one (404), and a role
without the operation is refused (403) before any record, artifact or effect is touched.

The four gates differ, which is the point of the matrix:
  * `analysis:run` -- the launch roles, bound to Allow Pentester (the platform roles too, RM-078);
  * `authorization:upload` -- new in P3, the same role set and the same Allow Pentester binding;
  * `engagement:delete` -- the Super-Tenant Admin alone, because it irreversibly deletes documents;
  * `reports:export` -- stop-monitoring, which every role but `tenant_user` holds.

The confused-deputy this phase closes is at the end: a permission-to-test document uploaded in one
tenant cannot authorize a launch in another.
"""
import base64
import sys
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from .read_endpoint_fixtures import allow_pentester, as_role, read_endpoint_fixture

OTHER_TENANT = "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64).decode("ascii")
UPLOAD = {"filename": "permission.png", "content_b64": PNG}

# (endpoint, extra arguments, roles admitted, whether the tenant's Allow Pentester must be on)
ENDPOINTS = (
  ("analyze_job", {"analysis_type": "summary"},
   ("tenant_pentester", "super_pentester", "super_tenant_admin"), True),
  ("upload_authorization", dict(UPLOAD),
   ("tenant_pentester", "super_pentester", "super_tenant_admin"), True),
  ("delete_job_engagement", {"delete_documents": False}, ("super_tenant_admin",), False),
  ("stop_monitoring", {"stop_type": "SOFT"},
   ("tenant_pentester", "tenant_admin", "super_pentester", "super_tenant_admin"), False),
)
ALL_ROLES = ("tenant_user", "tenant_pentester", "tenant_admin", "super_pentester",
             "super_tenant_admin")
JOBLESS = ("upload_authorization",)


#: What an admitted call reports when the effect canary fires rather than a denial being returned.
ADMITTED = {"status_code": 200, "success": True, "error": None}


def invoke(fixture, name, extra, *, tenant_id):
  """Call the endpoint the way the transport does: keyword arguments only.

  Under `no_effects` an admitted call reaches a canary that raises, so that raise *is* the
  admission result and is reported as one. A denial never gets that far, and every assertion here
  is about the denial.
  """
  method = getattr(fixture.Plugin, name)
  arguments = dict(extra, request_actor=fixture.actor, tenant_id=tenant_id)
  if name not in JOBLESS:
    arguments["job_id"] = "job-1"
  try:
    return method(fixture.owner, **arguments)
  except RuntimeError as exc:
    assert str(exc) == "effect ran", exc
    return dict(ADMITTED)


def no_effects(fixture):
  """Canary on every irreversible symbol the four endpoints call, bound where the plugin reads it."""
  module = sys.modules[fixture.Plugin.__module__]
  names = ("stop_monitoring", "delete_engagement_data", "collect_engagement_document_cids",
           "store_authorization_document")
  for name in names:
    assert hasattr(module, name), "the plugin no longer imports %s; the canary is vacuous" % name
  return patch.multiple(module, **{name: Mock(side_effect=RuntimeError("effect ran"))
                                   for name in names})


def second_tenant(fixture):
  """A real second tenant, so a cross-tenant call is refused by the store rather than by shape."""
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
  assert (result.get("success"), result.get("status_code"), result.get("error")) == (
    False, status, error), result


@pytest.mark.parametrize("name,extra,roles,pentesting", ENDPOINTS)
@pytest.mark.parametrize("tenant_id", (None, "", "   "))
def test_a_missing_tenant_is_refused_before_admission(name, extra, roles, pentesting, tenant_id):
  with read_endpoint_fixture(bound=True, role="super_tenant_admin") as fixture:
    allow_pentester(fixture)
    with no_effects(fixture):
      result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert_denied(result, 400, "invalid_request")
    assert fixture.artifact_reads == []
    assert not any(row[1] == fixture.store.cfg_instance_id for row in fixture.store.reads)


@pytest.mark.parametrize("name,extra,roles,pentesting", ENDPOINTS)
def test_a_job_owned_by_another_tenant_is_not_found(name, extra, roles, pentesting):
  """The caller is fully authorized in the tenant it names; the job is not in it.

  `upload_authorization` has no job, so it is admitted rather than refused -- which is the fact
  worth pinning: the tenant it names is the one the document is filed under.
  """
  with read_endpoint_fixture(bound=True, role="super_tenant_admin") as fixture:
    other = second_tenant(fixture)
    fixture.tenant_store.put("tenant", other,
      record={**fixture.tenant_store.get("tenant", other), "allow_pentester": True})
    with no_effects(fixture):
      result = invoke(fixture, name, extra, tenant_id=other)
    if name in JOBLESS:
      assert result.get("status_code") not in (400, 403, 404), result
    else:
      assert_denied(result, 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra,roles,pentesting", ENDPOINTS)
def test_a_tenant_the_caller_does_not_belong_to_is_not_found(name, extra, roles, pentesting):
  with read_endpoint_fixture(bound=True) as fixture:
    other = second_tenant(fixture)
    as_role(fixture, "tenant_admin")  # a member of the fixture tenant only
    with no_effects(fixture):
      assert_denied(invoke(fixture, name, extra, tenant_id=other), 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra,roles,pentesting", ENDPOINTS)
def test_an_unknown_tenant_is_not_found(name, extra, roles, pentesting):
  with read_endpoint_fixture(bound=True, role="super_tenant_admin") as fixture:
    with no_effects(fixture):
      assert_denied(invoke(fixture, name, extra, tenant_id=OTHER_TENANT), 404, "not_found")
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name,extra,roles,pentesting", ENDPOINTS)
@pytest.mark.parametrize("role", ALL_ROLES)
def test_only_the_roles_holding_the_operation_are_admitted(name, extra, roles, pentesting, role):
  """The whole point of giving each endpoint its own matrix operation: a Tenant Admin may stop a
  job and delete nothing, and a Tenant Pentester may analyse and upload but not delete."""
  with read_endpoint_fixture(bound=True, role=role) as fixture:
    tenant_id = allow_pentester(fixture)
    with no_effects(fixture):
      result = invoke(fixture, name, extra, tenant_id=tenant_id)
    if role in roles:
      assert result.get("status_code") != 403, result
    else:
      assert_denied(result, 403, "forbidden")


@pytest.mark.parametrize("name,extra,roles,pentesting",
                         [row for row in ENDPOINTS if row[3]])
@pytest.mark.parametrize("role", ("tenant_pentester", "super_pentester", "super_tenant_admin"))
def test_pentesting_switched_off_refuses_analysis_and_upload(name, extra, roles, pentesting, role):
  """The P3 acceptance criterion. RM-078 binds these for the platform roles too, so a tenant that
  switched pentesting off cannot have one run in it by a Super-Tenant Admin either."""
  with read_endpoint_fixture(bound=True, role=role) as fixture:
    tenant_id = allow_pentester(fixture, False)
    with no_effects(fixture):
      assert_denied(invoke(fixture, name, extra, tenant_id=tenant_id), 403, "pentesting_disabled")


@pytest.mark.parametrize("name,extra,roles,pentesting",
                         [row for row in ENDPOINTS if not row[3]])
def test_the_administrative_operations_ignore_the_pentesting_switch(name, extra, roles, pentesting):
  """Deletion and stopping are administrative: the owner's RM-078 decision binds neither."""
  with read_endpoint_fixture(bound=True, role="super_tenant_admin") as fixture:
    tenant_id = allow_pentester(fixture, False)
    with no_effects(fixture):
      result = invoke(fixture, name, extra, tenant_id=tenant_id)
    assert result.get("error") != "pentesting_disabled", result
    assert result.get("status_code") != 403, result


def test_the_uploaded_document_records_the_tenant_that_authorized_it():
  with read_endpoint_fixture(bound=True, role="tenant_pentester") as fixture:
    tenant_id = allow_pentester(fixture)
    stored = {}
    repo = Mock()
    repo.put_json = Mock(side_effect=lambda envelope, **_kwargs: stored.update(envelope) or "cid-1")
    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo):
      result = fixture.Plugin.upload_authorization(fixture.owner, **UPLOAD,
        request_actor=fixture.actor, tenant_id=tenant_id)
    assert result.get("cid") == "cid-1", result
    assert stored.get("tenant_id") == tenant_id, stored
    # Both attributions come from admission, never from the request body.
    assert stored.get("uploaded_by") == "reader", stored


@pytest.mark.parametrize("stored_tenant,admitted", (("same", True), ("other", False),
                                                    (None, False), ("unreadable", False)))
def test_a_document_from_another_tenant_cannot_authorize_a_launch(stored_tenant, admitted):
  """The acceptance criterion: an upload from tenant A cannot launch in tenant B.

  A document with no tenant, and one whose envelope cannot be read, are refused the same way -- a
  caller probing for a fallback cannot tell the three apart.
  """
  with read_endpoint_fixture(bound=True) as fixture:
    context = Mock()
    context.to_dict = Mock(return_value={"tenant_id": fixture.tenant_id})
    envelope = {"kind": "redmesh_authorization_document"}
    if stored_tenant == "same":
      envelope["tenant_id"] = fixture.tenant_id
    elif stored_tenant == "other":
      envelope["tenant_id"] = OTHER_TENANT
    repo = Mock()
    repo.get_json = Mock(side_effect=(RuntimeError("R1FS down") if stored_tenant == "unreadable"
                                      else lambda _cid, **_kwargs: envelope))
    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo):
      denial = fixture.Plugin._admit_authorization_document(fixture.owner, context, "cid-1", None)
    if admitted:
      assert denial is None
    else:
      assert_denied(denial, 404, "not_found")


def test_the_typed_authorization_payload_is_checked_as_well_as_the_flat_reference():
  """`authorization.document_cid` and the legacy flat `authorization_ref` are the same document by
  two names; checking only one leaves the other as the way around the tenant binding."""
  with read_endpoint_fixture(bound=True) as fixture:
    context = Mock()
    context.to_dict = Mock(return_value={"tenant_id": fixture.tenant_id})
    repo = Mock()
    repo.get_json = Mock(return_value={"tenant_id": OTHER_TENANT})
    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo):
      for reference, typed in (("cid-1", None), ("", {"document_cid": "cid-1"})):
        denial = fixture.Plugin._admit_authorization_document(fixture.owner, context, reference,
                                                              typed)
        assert_denied(denial, 404, "not_found")


def test_a_launch_with_no_document_is_not_gated_on_one():
  """Not every engagement files a document through us; the check must only bind the ones that do."""
  with read_endpoint_fixture(bound=True) as fixture:
    context = Mock()
    context.to_dict = Mock(return_value={"tenant_id": fixture.tenant_id})
    repo = Mock()
    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo):
      assert fixture.Plugin._admit_authorization_document(fixture.owner, context, "", None) is None
      assert fixture.Plugin._admit_authorization_document(fixture.owner, context, "", {}) is None
    repo.get_json.assert_not_called()
