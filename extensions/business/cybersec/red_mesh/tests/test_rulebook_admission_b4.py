"""RM-026 I1b B4: admission and derived attribution for the rulebook review mutations.

A rulebook review is an attestation: its value is that a named person signed it. Before this slice
the backend accepted whatever name it was handed, in a `actor: str` parameter that looks like an
identity and is not one -- the shape the I1a exit gate recorded as "a parameter named actor is not
evidence of admission".

These four also allocate a caller-keyed lock before the job read, so probing job ids grew an
unbounded module-global dict on a denial path.

The boundary tests are written first, per the rule four earlier controls were shipped without.
"""
import asyncio
from unittest.mock import patch

import pytest

from extensions.business.cybersec.red_mesh.services import rulebook_assessment
from .read_endpoint_fixtures import as_role, read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  assert_json_response, install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b4-canary"
MUTATIONS = ("save_rulebook_review_draft", "submit_rulebook_review",
             "reopen_rulebook_review", "update_rulebook_review")


def body_for(name):
  base = {"job_id": "job-1", "profile_id": "nis2.eu_baseline.v1"}
  if name in ("save_rulebook_review_draft", "update_rulebook_review"):
    base["answers"] = {}
  return base


# RM-084 P2: faults on the tenant path. `reports:export` is the gate, so the owning tenant's
# administrator and pentester are admitted and a tenant_user is not.
FAULTS = (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("none_scope", 404),
  ("user", 403), ("other_tenant", 404), ("identity_store", 503),
)


def apply_fault(fixture, fault):
  """Return (actor, tenant_id) for a call that must be refused, from real store state."""
  actor, tenant_id = fixture.actor, as_role(fixture, "tenant_admin")
  if fault == "actor":
    actor = None
  elif fault == "deleted":
    fixture.store.data.pop(("auth", "reader"))
  elif fault == "inactive":
    fixture.store.account("reader", active=False,
      memberships=[{"role": "tenant_admin", "tenant_id": fixture.tenant_id}])
  elif fault == "none_scope":
    fixture.store.data[("auth", "reader")]["memberships"] = []
  elif fault == "user":
    as_role(fixture, "tenant_user")
  elif fault == "other_tenant":
    tenant_id = "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"
  elif fault == "identity_store":
    fixture.store.fail_hkey = "auth"
  return actor, tenant_id


@pytest.mark.parametrize("name", MUTATIONS)
@pytest.mark.parametrize("fault,status", FAULTS)
def test_denials_never_reach_the_review_store_or_allocate_a_lock(name, fault, status):
  """Contract 2, plus the unbounded caller-keyed lock: admission must precede the `with`."""
  with read_endpoint_fixture(bound=True) as fixture:
    actor, tenant_id = apply_fault(fixture, fault)
    locks_before = dict(rulebook_assessment._SUBMISSION_LOCKS)
    with patch.object(rulebook_assessment, "_put_review_with_audit",
                      side_effect=AssertionError(SECRET)) as helper, \
         patch.object(rulebook_assessment, "_submission_lock",
                      side_effect=AssertionError(SECRET)) as lock:
      result = getattr(fixture.Plugin, name)(fixture.owner, **body_for(name),
                                             request_actor=actor, tenant_id=tenant_id)
    assert result["status_code"] == status and result["success"] is False
    helper.assert_not_called()
    lock.assert_not_called(), "a denied caller allocated a submission lock"
    assert dict(rulebook_assessment._SUBMISSION_LOCKS) == locks_before


def test_the_stored_signer_is_the_admitted_account():
  """The end-to-end case: update_rulebook_review reaches the write under this fixture, so the
  stored reviewer can be read straight off the response."""
  with read_endpoint_fixture(bound=True) as fixture:
    result = fixture.Plugin.update_rulebook_review(
      fixture.owner, **body_for("update_rulebook_review"), request_actor=fixture.actor,
      tenant_id=as_role(fixture, "tenant_admin"))
  assert result.get("status") == "ok"
  assert result["review"]["reviewer"] == "reader", (
    "the stored signer was not the admitted account: %r" % (result["review"]["reviewer"],))


@pytest.mark.parametrize("name", MUTATIONS)
def test_the_derived_signer_is_what_reaches_the_service(name):
  """The other three hit a precondition before the write under this fixture, so the assertion is
  made where the derivation happens: the endpoint-to-service boundary.

  The first version of this test was vacuous three ways -- a stub whose signature could not bind, a
  path that never reached the helper, and an assertion behind `if captured:` -- so substituting the
  literal "attacker" for the derived signer left all 42 tests green.
  """
  import sys
  seen = {}
  plugin_module = None
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_admin")
    plugin_module = sys.modules[fixture.Plugin.__module__]
    real = getattr(plugin_module, name)

    def capture(owner, job_id, **kwargs):
      seen["signer"] = kwargs.get("actor", kwargs.get("reviewer"))
      return real(owner, job_id, **kwargs)

    with patch.object(plugin_module, name, capture):
      getattr(fixture.Plugin, name)(fixture.owner, **body_for(name),
                                    request_actor=fixture.actor, tenant_id=tenant_id)
  assert seen.get("signer") == "reader", (
    "%s passed %r to the service instead of the admitted account" % (name, seen.get("signer")))


def test_a_validation_failure_publishes_a_typed_code_without_echoing_the_body():
  # Asserted on update_rulebook_review: save_draft hits a submission precondition before answer
  # validation under this fixture, so the interpolating path is not reachable there. Both call the
  # same _validate_review_answers and both had the same str(exc) leak, now removed from both.
  name = "update_rulebook_review"
  """Contract 7: _validate_review_answers interpolates question_id and answer_value from the
  request body, and both endpoints passed str(exc) straight into the response message."""
  probe = "pwn<img src=x>"
  with read_endpoint_fixture(bound=True) as fixture:
    result = getattr(fixture.Plugin, name)(
      fixture.owner, job_id="job-1", profile_id="nis2.eu_baseline.v1",
      answers={probe: "yes"}, request_actor=fixture.actor,
      tenant_id=as_role(fixture, "tenant_admin"))
  assert probe not in repr(result), "the request body was echoed back in the response"
  assert result.get("error_code") in ("invalid_review_answer", "invalid_profile")


@pytest.mark.parametrize("name", MUTATIONS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_the_review_payload_survives_the_wire(read_native, name, response_format):
  """These four keep their own rich response: public_effect_result would drop `review`, `audit`,
  `found`, `profile`, `effective_review_state`, `latest_submission`,
  `submission_operation_state`, `review_revision` and `idempotent_replay` -- everything the UI
  reads. Asserted at the boundary, not from a direct plugin call."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, name,
      {**body_for(name), "request_actor": fixture.actor,
       "tenant_id": as_role(fixture, "tenant_admin")})), 200)
    body = result["result"] if response_format == "WRAPPED" else result
    assert calls == 1
    assert isinstance(body, dict)
    # Whatever the outcome, the response must carry more than the two keys the projection keeps.
    assert set(body) - {"status", "job_id"}, (
      "the response was flattened to the projection's shape: %r" % (body,))


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_a_typed_conflict_code_is_not_flattened_to_effect_incomplete(read_native, response_format):
  """_effect_operation rewrites any status:error dict to effect_incomplete once the ledger is
  non-NONE. That is why these four use _admitted_snapshot instead: the revision fence's whole UX is
  the typed code and its retryable flag."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    result, _calls = assert_json_response(asyncio.run(request(module,
      "save_rulebook_review_draft",
      {**body_for("save_rulebook_review_draft"), "expected_review_revision": 999,
       "request_actor": fixture.actor, "tenant_id": as_role(fixture, "tenant_admin")})), 200)
    body = result["result"] if response_format == "WRAPPED" else result
    assert body.get("error") != "effect_incomplete", (
      "a typed conflict code was collapsed by the effect wrapper")
    assert body.get("error_code") == "review_revision_conflict", (
      "the typed conflict code did not survive the wire: %r" % (body,))
    assert body.get("retryable") is not None or "review" in body
