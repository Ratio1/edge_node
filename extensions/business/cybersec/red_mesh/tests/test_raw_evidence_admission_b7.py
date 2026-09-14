"""RM-026 I1b B7: admission for get_raw_model_test_evidence.

The sharpest remaining read on the surface, and the last GET. It takes only a `job_id`, reads the
job unscoped, then resolves the secret-store key and returns the *decrypted* restricted artifact
(`model_testing/raw_evidence.py:260-262`) -- the raw prompts and model responses a model test
captured. Anyone who could guess a job id could read it.

Contracts 4 and 6 are vacuous here: this is a read, it lands no effect, and there is nothing to
revalidate at completion. It gets admission, POST, and a wire assertion, and no further ceremony.

The gate decides itself rather than needing an owner call. `audit:view` requires a
`super_tenant_admin` membership, which the legacy seam forbids outright -- `_admitted_snapshot`
requires memberships absent -- so it is unreachable in the legacy half. `reports:export` is the
strictest gate that can actually be satisfied, and it is what the other restricted exports use.

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


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_never_resolve_the_secret_key_or_read_the_artifact(fault, status):
  with read_endpoint_fixture(bound=False) as fixture:
    account = fixture.store.data[("auth", "reader")]
    actor = fixture.actor
    if fault == "actor": actor = None
    elif fault == "deleted": fixture.store.data.pop(("auth", "reader"))
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault == "user": fixture.store.account("reader", role="user")
    elif fault == "memberships": account["metadata"]["tenant_memberships"] = []
    elif fault == "rollout":
      fixture.tenant_store.put("execution_rollout", fixture.owner.cfg_instance_id,
        record={"stage": "draining", "enabled": False})
    elif fault == "identity_store": fixture.store.fail_hkey = "auth"

    with _no_artifact_read(fixture) as artifact:
      result = fixture.Plugin.get_raw_model_test_evidence(
        fixture.owner, "job-1", request_actor=actor)
    assert result.get("status_code") == status
    assert result.get("success") is False
    artifact.assert_not_called()
    assert SECRET not in repr(result)


def test_a_denial_outranks_the_job_type_check():
  """The unsupported-job-type answer distinguishes a real job from an absent one, so an unadmitted
  caller must never reach it. job-1 is a network scan, so the old code would have answered
  `unsupported_job_type` for a caller with no authority at all."""
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    result = fixture.Plugin.get_raw_model_test_evidence(
      fixture.owner, "job-1", request_actor=fixture.actor)
    assert result.get("status_code") == 403
    assert result.get("error") != "unsupported_job_type"


def test_the_endpoint_reads_no_job_of_its_own():
  """Admission already read the job under the reader's authority; a second unscoped read of the
  same record is the defect this whole phase exists to remove."""
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner._get_job_from_cstore = Mock(side_effect=RuntimeError(SECRET))
    with _no_artifact_read(fixture):
      fixture.Plugin.get_raw_model_test_evidence(
        fixture.owner, "job-1", request_actor=fixture.actor)
    fixture.owner._get_job_from_cstore.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("user", 403), ("actor", 404)))
def test_the_denial_keeps_its_status_over_the_wire(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {"job_id": "job-1", "request_actor": fixture.actor}
    if fault == "user":
      fixture.store.account("reader", role="user")
    else:
      payload.pop("request_actor")
    with _no_artifact_read(fixture) as artifact:
      actual, _headers, body, calls = asyncio.run(
        request(module, "get_raw_model_test_evidence", payload))
    assert actual == status, body
    assert calls == 1
    artifact.assert_not_called()
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
