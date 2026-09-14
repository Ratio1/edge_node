"""RM-026 I1b B5: admission for generate_rulebook_assessment.

The assessment builder is the seam B4 budgeted and did not reach: `build_rulebook_assessment`
descends to `_resolve_scan_context`, which reads the job from the store directly. This endpoint
also persists an artifact and writes assessment metadata three times.

Boundary tests are written before the implementation, per the rule five earlier controls were
shipped without and which caught the sixth before commit in B4.
"""
import asyncio
from unittest.mock import patch

import pytest

from extensions.business.cybersec.red_mesh.services import rulebook_assessment
from extensions.business.cybersec.red_mesh.tenancy.effects import EffectState
from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  assert_json_response, install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b5-canary"
BODY = {"job_id": "job-1", "profile_id": "nis2.eu_baseline.v1"}


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_never_build_persist_or_write_metadata(fault, status):
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

    with patch.object(rulebook_assessment, "build_rulebook_assessment",
                      side_effect=AssertionError(SECRET)) as build, \
         patch.object(rulebook_assessment, "_write_assessment_meta",
                      side_effect=AssertionError(SECRET)) as meta:
      result = fixture.Plugin.generate_rulebook_assessment(
        fixture.owner, **BODY, request_actor=actor)
    assert result["status_code"] == status and result["success"] is False
    build.assert_not_called()
    meta.assert_not_called()


def test_the_assessment_builder_no_longer_reads_the_job_unscoped():
  """The B4-to-B5 seam: build_rulebook_assessment descends to _resolve_scan_context."""
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(fixture.owner, "_get_job_from_cstore", create=True,
                      side_effect=AssertionError(SECRET)) as unscoped:
      fixture.Plugin.generate_rulebook_assessment(
        fixture.owner, **BODY, request_actor=fixture.actor)
    unscoped.assert_not_called()


def test_a_persisted_assessment_is_not_reported_as_nothing_happened():
  """The artifact is content-addressed; a later failure must not claim no trace."""
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.r1fs.add_json = lambda payload, show_logs=False: "assessment-cid"
    with patch.object(rulebook_assessment, "_write_assessment_meta",
                      side_effect=RuntimeError(SECRET)):
      result = fixture.Plugin.generate_rulebook_assessment(
        fixture.owner, **BODY, request_actor=fixture.actor)
  if result.get("error") == "effect_incomplete":
    assert result["effect_state"] in (EffectState.PERSISTED.value, EffectState.DELIVERED.value)
  assert SECRET not in repr(result)


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_the_assessment_payload_survives_the_wire(read_native, response_format):
  """This endpoint returns a rich assessment, so it keeps its own shape like the B4 four."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    # persist=False: the fixture's fake r1fs has no add_json, so a persisting call fails with
    # nothing landed and correctly reports 503. The response shape is what this test is about.
    result, calls = assert_json_response(asyncio.run(request(module,
      "generate_rulebook_assessment",
      {**BODY, "persist": False, "request_actor": fixture.actor})), 200)
    body = result["result"] if response_format == "WRAPPED" else result
    assert calls == 1
    assert set(body) - {"status", "job_id"}, (
      "the response was flattened to the projection's shape: %r" % (body,))
    assert body.get("error") != "effect_incomplete"
