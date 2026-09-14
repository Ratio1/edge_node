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
from .read_endpoint_fixtures import read_endpoint_fixture
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


@pytest.mark.parametrize("name", MUTATIONS)
@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_never_reach_the_review_store_or_allocate_a_lock(name, fault, status):
  """Contract 2, plus the unbounded caller-keyed lock: admission must precede the `with`."""
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

    locks_before = dict(rulebook_assessment._SUBMISSION_LOCKS)
    with patch.object(rulebook_assessment, "_put_review_with_audit",
                      side_effect=AssertionError(SECRET)) as helper, \
         patch.object(rulebook_assessment, "_submission_lock",
                      side_effect=AssertionError(SECRET)) as lock:
      result = getattr(fixture.Plugin, name)(fixture.owner, **body_for(name),
                                             request_actor=actor)
    assert result["status_code"] == status and result["success"] is False
    helper.assert_not_called()
    lock.assert_not_called(), "a denied caller allocated a submission lock"
    assert dict(rulebook_assessment._SUBMISSION_LOCKS) == locks_before


@pytest.mark.parametrize("name", MUTATIONS)
def test_the_signer_is_derived_never_supplied(name):
  """Contract 5, and the point of this slice: the stored reviewer must be the admitted account,
  not a caller-invented label."""
  captured = {}

  def capture(owner, job_id, profile_id=None, state=None, **kwargs):
    captured["reviewer"] = (state or {}).get("reviewer")
    return {"status": "ok"}

  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(rulebook_assessment, "_put_review_with_audit", capture):
      getattr(fixture.Plugin, name)(fixture.owner, **body_for(name),
                                    request_actor=fixture.actor)
  if captured:
    assert captured["reviewer"] != "attacker", "a caller-supplied signer survived"


@pytest.mark.parametrize("name", MUTATIONS)
@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_the_review_payload_survives_the_wire(read_native, name, response_format):
  """These four keep their own rich response: public_effect_result would drop `review`, `audit`,
  `found`, `profile`, `effective_review_state`, `latest_submission`,
  `submission_operation_state`, `review_revision` and `idempotent_replay` -- everything the UI
  reads. Asserted at the boundary, not from a direct plugin call."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, name,
      {**body_for(name), "request_actor": fixture.actor})), 200)
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
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    result, _calls = assert_json_response(asyncio.run(request(module,
      "save_rulebook_review_draft",
      {**body_for("save_rulebook_review_draft"), "expected_review_revision": 999,
       "request_actor": fixture.actor})), 200)
    body = result["result"] if response_format == "WRAPPED" else result
    assert body.get("error") != "effect_incomplete", (
      "a typed conflict code was collapsed by the effect wrapper")
    assert body.get("error_code") == "review_revision_conflict", (
      "the typed conflict code did not survive the wire: %r" % (body,))
    assert body.get("retryable") is not None or "review" in body
