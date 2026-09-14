"""RM-026 I1b B6: admission for analyze_job.

This is the one endpoint with a genuinely measurable TOCTOU window. The work is submitted to an
executor and finalized later on the plugin loop, and `_ManualAnalysisWork` is frozen with no plugin
reference, so the worker cannot revalidate. `_finalize_manual_analysis` is therefore the only place
a completion effect can be re-checked -- which is exactly what the owner's decision requires.

Ships the legacy half only: the owner granted manual analysis to scoped STA/SP/Tenant Pentesters as
well, and that half is RM-078.
"""
import asyncio
import json
from unittest.mock import Mock, patch

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b6-canary"
BODY = {"job_id": "job-1", "analysis_type": "summary"}


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_never_prepare_or_submit_analysis(fault, status):
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

    result = fixture.Plugin.analyze_job(fixture.owner, **BODY, request_actor=actor)
    assert result.get("status_code") == status
    assert result.get("success") is False
    # Admission ran before any preparation: no analysis slot was claimed.
    assert fixture.owner.__dict__.get("_manual_analysis_state") is None


def test_a_denied_caller_cannot_observe_or_disturb_the_busy_state():
  """The manual-analysis slot is global. A denial must not read or clear it, or an unadmitted
  caller could probe whether an analysis is running and interfere with the drain."""
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    fixture.owner._manual_analysis_state = {"pending_id": "existing", "job_id": "other"}
    result = fixture.Plugin.analyze_job(fixture.owner, **BODY, request_actor=fixture.actor)
    assert result.get("status_code") == 403
    assert result.get("error") != "analysis_busy", (
      "a denied caller learned the analysis slot was occupied")
    assert fixture.owner._manual_analysis_state == {"pending_id": "existing", "job_id": "other"}


def test_completion_revalidates_the_requester_before_any_completion_effect():
  """The worker is frozen and plugin-less, so the requester travels on the state and
  _finalize_manual_analysis is the only seam that can re-check it. A requester revoked while the
  analysis ran must not have its result persisted."""
  import sys
  for revoke, expect_denial in ((True, True), (False, False)):
    with read_endpoint_fixture(bound=False) as fixture:
      outcome = sys.modules[fixture.Plugin.__module__]._ManualAnalysisOutcome(
        sections={"executive_headline": "done"}, failed=False)
      state = {"job_id": "job-1", "pass_nr": 1, "job_revision": 1, "report_cid": "pass",
               "request_actor": fixture.actor}
      if revoke:
        fixture.store.account("reader", role="user")
      reached = Mock(side_effect=RuntimeError(SECRET))
      # Bound on the instance, not the class, where the plugin reads it through `self`; a class
      # patch would bind nothing there and the canary would be vacuous.
      fixture.owner._get_job_from_cstore = Mock(side_effect=RuntimeError("unscoped read"))
      with patch.object(fixture.Plugin, "_manual_analysis_state_matches", reached):
        if expect_denial:
          result = fixture.Plugin._finalize_manual_analysis(fixture.owner, state, outcome)
          assert result == {"success": False, "error": "forbidden", "status_code": 403}
          reached.assert_not_called()
        else:
          # Control: without the revocation the same call runs on past revalidation, so the denial
          # above came from the actor and not from an unconditional early return.
          with pytest.raises(RuntimeError, match=SECRET):
            fixture.Plugin._finalize_manual_analysis(fixture.owner, state, outcome)
      # Either way the completion step works from the revalidated snapshot, never a fresh
      # unscoped read of the same record.
      fixture.owner._get_job_from_cstore.assert_not_called()


def test_the_checked_snapshot_reaches_the_preparation_step():
  """Admission reads the job once under the reader's authority. The preparation step must consume
  that snapshot; a signature check cannot see the call site, so capture the real object and refuse
  any second unscoped read of the same record."""
  with read_endpoint_fixture(bound=False) as fixture:
    admitted = []
    real_snapshot = fixture.Plugin._admitted_snapshot

    def _record(instance, *args, **kwargs):
      snapshot, mode = real_snapshot(instance, *args, **kwargs)
      admitted.append(snapshot)
      return snapshot, mode

    received = []
    fixture.owner._get_job_from_cstore = Mock(side_effect=RuntimeError(SECRET))
    with patch.object(fixture.Plugin, "_admitted_snapshot", _record), \
         patch.object(fixture.Plugin, "_prepare_manual_analysis",
                      side_effect=lambda _p, _job_id, *, checked_job: (
                        received.append(checked_job) or (None, {"error": "stop"}))):
      fixture.Plugin.analyze_job(fixture.owner, **BODY, request_actor=fixture.actor)
    assert len(admitted) == 1 and admitted[0] is not None
    assert received == [admitted[0]], (
      "the preparation step did not receive the admitted snapshot: %r" % (received,))
    fixture.owner._get_job_from_cstore.assert_not_called()



@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("user", 403), ("actor", 404)))
def test_the_denial_keeps_its_status_over_the_wire(read_native, response_format, fault, status):
  """Five earlier controls in this series were live in the plugin and inert over HTTP, so the
  admission decision is asserted at the boundary, in both response formats, not from a direct
  plugin call. The generated server honours the plugin's own `status_code` (basic_server.j2), which
  is what carries 403/404 here -- `analyze_job` is deliberately not on the strict read transport."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {**BODY, "request_actor": fixture.actor}
    if fault == "user":
      fixture.store.account("reader", role="user")
    else:
      payload.pop("request_actor")
    actual, _headers, body, calls = asyncio.run(request(module, "analyze_job", payload))
    assert actual == status, body
    assert calls == 1
    assert fixture.owner.__dict__.get("_manual_analysis_state") is None
    assert "mock-only" not in body.decode()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_the_typed_operational_codes_still_reach_the_wire(read_native, response_format):
  """Admission must not cost `analyze_job` its own typed codes. Putting it on the strict read
  transport did exactly that: `_read_error_response` allowlists only {400,401,403,404,405,503}, so
  analysis_busy 409 -- and analysis_state_changed, analysis_request_unavailable,
  analysis_input_too_large, analysis_input_invalid, analysis_timeout with it -- arrived as a generic
  `unavailable`, losing the `retryable` flag a client needs. The suite that asserts 409 over HTTP
  renders the server without the guard, so only a guarded fixture like this one can see it."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    occupied = {"pending_id": "existing", "job_id": "other"}
    fixture.owner._manual_analysis_state = occupied
    status, _headers, body, calls = asyncio.run(request(module, "analyze_job",
      {**BODY, "request_actor": fixture.actor}))
    assert calls == 1
    assert status == 409, body
    detail = json.loads(body)["detail"]
    if response_format == "RAW":
      # RAW unwraps the typed dict to its bare error string, so the code survives and the
      # `retryable` flag does not. Pre-existing divergence, asserted rather than assumed.
      assert detail == {"detail": "analysis_busy"}
    else:
      assert detail["error"] == "analysis_busy"
      assert detail["retryable"] is True
    assert fixture.owner._manual_analysis_state == occupied
