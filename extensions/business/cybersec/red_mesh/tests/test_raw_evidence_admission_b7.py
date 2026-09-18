"""RM-026 I1b B7: admission for get_raw_model_test_evidence.

The sharpest remaining read on the surface, and the last GET. It takes only a `job_id`, reads the
job unscoped, then resolves the secret-store key and returns the *decrypted* restricted artifact
(`model_testing/raw_evidence.py:260-262`) -- the raw prompts and model responses a model test
captured. Anyone who could guess a job id could read it.

Contracts 4 and 6 are vacuous here: this is a read, it lands no effect, and there is nothing to
revalidate at completion. It gets admission, POST, and a wire assertion, and no further ceremony.

RM-084 P2: the endpoint requires the caller's tenant and the gate is `evidence:read`, which the
matrix grants to the platform roles only -- so a Tenant Admin of the owning tenant is refused the
decrypted artifact while keeping every other report it can read. The previous `reports:export` gate
was the strictest one the deleted legacy seam could satisfy, not the right one.

Boundary tests first, and this time the fixture is checked for the ability to express the assertion
before a failure is read as a defect (B6 closeout).
"""
import asyncio
import json
import sys
from unittest.mock import Mock, patch

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b7-canary"

# Faults, each expressed on the tenant path. `member` is the P2 acceptance criterion: the owning
# tenant's administrator holds reports:view and reports:export and still may not read raw evidence.
FAULTS = (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("none_scope", 404),
  ("member", 403), ("pentester", 403), ("user", 403), ("other_tenant", 404),
  ("identity_store", 503),
)


def admit(fixture, role="super_tenant_admin"):
  """Give the reader a membership that holds evidence:read, and return the call's tenant."""
  fixture.store.data[("auth", "reader")]["memberships"] = [
    {"role": role, "tenant_id": None}]
  return fixture.tenant_id


def apply_fault(fixture, fault):
  """Return the actor and tenant the call should use. Faults are real store state, not mocks."""
  memberships = {"member": "tenant_admin", "pentester": "tenant_pentester", "user": "tenant_user"}
  actor, tenant_id = fixture.actor, admit(fixture)
  if fault == "actor":
    actor = None
  elif fault == "deleted":
    fixture.store.data.pop(("auth", "reader"))
  elif fault == "inactive":
    fixture.store.account("reader", active=False,
      memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
  elif fault == "none_scope":
    fixture.store.data[("auth", "reader")]["memberships"] = []
  elif fault in memberships:
    fixture.store.data[("auth", "reader")]["memberships"] = [
      {"role": memberships[fault], "tenant_id": fixture.tenant_id}]
  elif fault == "other_tenant":
    tenant_id = "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"
  elif fault == "identity_store":
    fixture.store.fail_hkey = "auth"
  return actor, tenant_id


def _no_artifact_read(fixture):
  """Canary on the symbol the plugin actually calls.

  Patched in the plugin's own namespace, not the defining module: this plugin imports the name, so
  patching `model_testing.raw_evidence` would bind nothing and the canary would be vacuous. That
  trap has landed twice in this task already.
  """
  module = sys.modules[fixture.Plugin.__module__]
  assert hasattr(module, "get_raw_evidence_artifact"), (
    "the plugin no longer imports this symbol; the canary would bind nothing")
  return patch.object(module, "get_raw_evidence_artifact", Mock(side_effect=RuntimeError(SECRET)))


@pytest.mark.parametrize("fault,status", FAULTS)
def test_denials_never_resolve_the_secret_key_or_read_the_artifact(fault, status):
  with read_endpoint_fixture(bound=True) as fixture:
    actor, tenant_id = apply_fault(fixture, fault)
    with _no_artifact_read(fixture) as artifact:
      result = fixture.Plugin.get_raw_model_test_evidence(
        fixture.owner, "job-1", request_actor=actor, tenant_id=tenant_id)
    assert result.get("status_code") == status
    assert result.get("success") is False
    artifact.assert_not_called()
    assert SECRET not in repr(result)


def test_a_denial_outranks_the_job_type_check():
  """The unsupported-job-type answer distinguishes a real job from an absent one, so an unadmitted
  caller must never reach it. job-1 is a network scan, so the old code would have answered
  `unsupported_job_type` for a caller with no authority at all."""
  with read_endpoint_fixture(bound=True) as fixture:
    result = fixture.Plugin.get_raw_model_test_evidence(
      fixture.owner, "job-1", request_actor=fixture.actor, tenant_id=fixture.tenant_id)
    assert result.get("status_code") == 403
    assert result.get("error") != "unsupported_job_type"


@pytest.mark.parametrize("tenant_id", (None, "", "   "))
def test_a_missing_tenant_is_refused_before_admission(tenant_id):
  """There is no unscoped half left: the selector is a bad request, not a fallback."""
  with read_endpoint_fixture(bound=True) as fixture:
    admit(fixture)
    with _no_artifact_read(fixture) as artifact:
      result = fixture.Plugin.get_raw_model_test_evidence(
        fixture.owner, "job-1", request_actor=fixture.actor, tenant_id=tenant_id)
    assert result == {"success": False, "error": "invalid_request", "status_code": 400}
    artifact.assert_not_called()
    assert fixture.store.reads == []


def test_the_endpoint_reads_no_job_of_its_own():
  """Admission already read the job under the reader's authority; a second unscoped read of the
  same record is the defect this whole phase exists to remove."""
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = admit(fixture)
    fixture.owner._get_job_from_cstore = Mock(side_effect=RuntimeError(SECRET))
    with _no_artifact_read(fixture):
      fixture.Plugin.get_raw_model_test_evidence(
        fixture.owner, "job-1", request_actor=fixture.actor, tenant_id=tenant_id)
    fixture.owner._get_job_from_cstore.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("member", 403), ("actor", 404)))
def test_the_denial_keeps_its_status_over_the_wire(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    actor, tenant_id = apply_fault(fixture, fault)
    payload = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": tenant_id}
    if actor is None:
      payload.pop("request_actor")
    with _no_artifact_read(fixture) as artifact:
      actual, _headers, body, calls = asyncio.run(
        request(module, "get_raw_model_test_evidence", payload))
    assert actual == status, body
    assert calls == 1
    artifact.assert_not_called()
    assert _headers[b"cache-control"] == b"no-store"
    detail = json.loads(body)["detail"]
    # WRAPPED keeps the typed dict; RAW unwraps it to `{"detail": "<code>"}`. Both must carry the
    # decision -- a control live in one deployment format and inert in the other is the failure this
    # series shipped five times.
    code = detail.get("error", detail.get("detail")) if isinstance(detail, dict) else detail
    assert code in ("forbidden", "not_found"), detail


def test_the_route_is_post_only(read_native):
  """It shipped as the last GET on the surface, so a job id could travel in a URL -- into proxy
  logs, browser history and referrers -- for the most restricted payload the plugin serves."""
  module, _ = read_native
  install(module)
  route = next(route for route in module.app.routes
               if route.path == "/get_raw_model_test_evidence")
  assert route.methods == {"POST"}


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_the_decrypted_payload_is_never_cacheable(read_native, response_format):
  """This endpoint is off the strict read transport, and the guard is what stamps `no-store` on
  every other read. It returns the decrypted restricted artifact, so it is the single response on
  this surface where the header earns its keep -- stamped by a header-only path set that does not
  drag in the error rebuild."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    status, headers, body, _calls = asyncio.run(request(module, "get_raw_model_test_evidence",
      {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": admit(fixture)}))
    # job-1 is a network scan, so this is the unsupported_job_type answer -- a successful admitted
    # call. The header must be there regardless of which branch the body came from.
    assert headers[b"cache-control"] == b"no-store", (status, body)


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_the_typed_codes_are_not_collapsed(read_native, response_format):
  """Why this endpoint stays off the strict transport. The two formats do NOT behave alike, and the
  original justification for the choice was written as if they did:

    RAW      -- `_handle_plugin_result` sees a top-level `error` and raises 500 with the code in
                `detail`. On the guard, `_read_error_response` would rewrite that to
                `503 {"error": "unavailable"}` and the code would be gone.
    WRAPPED  -- `on_response` nests the plugin dict under `result`, so no HTTPException is ever
                raised and the code arrives inside a 200 body. The guard could not collapse what
                never became an error in the first place.

  Both are asserted rather than assumed symmetric.
  """
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    status, _headers, body, _calls = asyncio.run(request(module, "get_raw_model_test_evidence",
      {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": admit(fixture)}))
    payload = json.loads(body)
    if response_format == "RAW":
      assert status == 500
      assert payload["detail"] == {"detail": "unsupported_job_type"}
    else:
      assert status == 200
      assert payload["result"]["error"] == "unsupported_job_type"
