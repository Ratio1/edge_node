"""RM-026 I1b B6: admission for analyze_job.

This is the one endpoint with a genuinely measurable TOCTOU window. The work is submitted to an
executor and finalized later on the plugin loop, and `_ManualAnalysisWork` is frozen with no plugin
reference, so the worker cannot revalidate. `_finalize_manual_analysis` is therefore the only place
a completion effect can be re-checked -- which is exactly what the owner's decision requires.

Ships the legacy half only: the owner granted manual analysis to scoped STA/SP/Tenant Pentesters as
well, and that half is RM-078.
"""
import asyncio
from unittest.mock import Mock

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  assert_json_response, install, read_native, request, scheduler_comms,
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
      # Bound on the instance, not the class: the plugin reads this through `self`, so a class
      # patch would bind nothing here and the canary would be vacuous.
      fixture.owner._get_job_from_cstore = reached
      if expect_denial:
        result = fixture.Plugin._finalize_manual_analysis(fixture.owner, state, outcome)
        assert result == {"success": False, "error": "forbidden", "status_code": 403}
        reached.assert_not_called()
      else:
        # Control: without the revocation the same call runs on past revalidation, so the denial
        # above came from the actor and not from an unconditional early return.
        with pytest.raises(RuntimeError, match=SECRET):
          fixture.Plugin._finalize_manual_analysis(fixture.owner, state, outcome)


def test_the_checked_snapshot_reaches_the_preparation_step():
  """Admission reads the job once; the preparation step must consume that checked snapshot rather
  than issuing its own unscoped store read."""
  import inspect
  with read_endpoint_fixture(bound=False) as fixture:
    prepare = inspect.signature(fixture.Plugin._prepare_manual_analysis)
  assert "checked_job" in prepare.parameters



@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("user", 403), ("actor", 404)))
def test_the_denial_keeps_its_status_over_the_wire(read_native, response_format, fault, status):
  """Five earlier controls in this series were inert over HTTP: the framework maps any dict
  carrying `error` to a plugin error and answers 503, so a 403/404 admission decision reaches the
  caller as a generic outage unless the endpoint is on the strict transport."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {**BODY, "request_actor": fixture.actor}
    if fault == "user":
      fixture.store.account("reader", role="user")
    else:
      # Omitted, not null: the strict transport rejects an explicit null field as invalid_request
      # before the plugin sees it, so omission is the only way to reach admission without an actor.
      payload.pop("request_actor")
    result, calls = assert_json_response(asyncio.run(request(module, "analyze_job", payload)),
                                         status)
    assert calls == 1
    assert fixture.owner.__dict__.get("_manual_analysis_state") is None
    assert "mock-only" not in repr(result)
