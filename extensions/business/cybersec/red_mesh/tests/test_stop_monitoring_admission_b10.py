"""RM-026 I1b B10: admission for stop_monitoring.

Split out of the B9 Controls group by the owner's decision (2026-09-14): it stops monitoring rather
than deleting, it is already POST, it carries none of the purge machinery, and it is admissible
through the existing legacy seam — so it is not blocked on RM-078 the way the three destructive
operations are.

It was reachable with no requester at all. A HARD stop cancels running workers, marks the job
stopped, emits a `redmesh.job.stopped` lifecycle event to the SOC, and persists the job record; a
SOFT stop schedules the same for the end of the current pass. None of that is undoable by the caller.

Contract 4 is vacuous: the sequence is synchronous on the plugin loop, so the requester cannot change
between admission and effect.
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

SECRET = "mock-only-b10-canary"
BODY = {"job_id": "job-1", "stop_type": "HARD"}


def _no_stop(fixture):
  """Canary bound where the plugin reads it.

  `pentester_api_01` imports `stop_monitoring` into its own namespace, so patching
  `services.control` would bind nothing -- the vacuous-canary trap that has landed twice here.
  """
  module = sys.modules[fixture.Plugin.__module__]
  assert hasattr(module, "stop_monitoring"), (
    "the plugin no longer imports stop_monitoring; the canary would bind nothing")
  return patch.object(module, "stop_monitoring", Mock(side_effect=RuntimeError(SECRET)))


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_never_stop_a_worker_or_emit_a_lifecycle_event(fault, status):
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
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

    with _no_stop(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=actor)
    assert result.get("status_code") == status
    assert result.get("success") is False
    stop.assert_not_called()
    assert SECRET not in repr(result)


def test_the_stop_reads_no_job_of_its_own():
  """Admission already read the job under the reader's authority.

  Asserted by object identity, not `is not None`: the weaker form passes for any snapshot at all,
  including one the endpoint fetched itself, which is the defect this is meant to exclude.
  """
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    module = sys.modules[fixture.Plugin.__module__]
    admitted = []
    real_snapshot = fixture.Plugin._admitted_snapshot

    def _record(instance, *args, **kwargs):
      snapshot, mode = real_snapshot(instance, *args, **kwargs)
      admitted.append(snapshot)
      return snapshot, mode

    received = []
    with patch.object(fixture.Plugin, "_admitted_snapshot", _record), \
         patch.object(module, "stop_monitoring",
                      Mock(side_effect=lambda *a, **k: received.append(k) or {"job_id": "job-1"})):
      fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=fixture.actor)
    assert len(admitted) == 1 and admitted[0] is not None
    assert received and received[0].get("checked_job") is admitted[0], (
      "the stop did not receive the admitted snapshot: %r" % (received,))


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("user", 403), ("actor", 404)))
def test_the_denial_keeps_its_status_over_the_wire(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {**BODY, "request_actor": fixture.actor}
    if fault == "user":
      fixture.store.account("reader", role="user")
    else:
      payload.pop("request_actor")
    with _no_stop(fixture) as stop:
      actual, _headers, body, calls = asyncio.run(request(module, "stop_monitoring", payload))
    assert actual == status, body
    assert calls == 1
    stop.assert_not_called()
    detail = json.loads(body)
    detail = detail.get("detail", detail)
    code = detail.get("error", detail.get("detail")) if isinstance(detail, dict) else detail
    assert code in ("forbidden", "not_found"), detail


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_the_launcher_mismatch_keeps_its_code_over_the_wire(read_native, response_format):
  """This endpoint is on the strict transport, which rebuilds error bodies and allowlists only
  {400,401,403,404,405,503} unless a code is registered in `_TYPED_READ_ERRORS`. Collapsed to
  `unavailable`, a refusal that means "this node did not launch the job" reads as an outage, and
  the caller retries against a node that can never serve it.

  This is the third endpoint in the series to need the carve-out, which is why the check was
  generalised from one hardcoded path to every registered pair.
  """
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    fixture.owner.ee_addr = "some-other-node"   # the fixture job was launched by node-a
    fixture.owner.P = lambda *_args, **_kwargs: None
    fixture.owner._log_audit_event = lambda *_args, **_kwargs: None
    status, headers, body, _calls = asyncio.run(request(module, "stop_monitoring",
      {**BODY, "request_actor": fixture.actor}))
    assert status == 409, body
    assert headers[b"cache-control"] == b"no-store"
    assert json.loads(body)["error"] == "job_launcher_mismatch", body


# --- RM-026 MVP: stop_monitoring through the tenant seam -------------------------------------------
# The MVP walkthrough stops a tenant-bound job as a tenant-scoped actor. Until now stop_monitoring
# passed tenant_id=None to the effect seam (legacy only), and its operation "reports:export" was in
# neither _TENANT_EFFECT_OPERATIONS nor _TENANT_OPERATIONS, so a tenant member could not stop a job
# at all. Same admission shape as purge_job; the service receives the admitted snapshot unchanged.

def _stop_ok(fixture):
  module = sys.modules[fixture.Plugin.__module__]
  return patch.object(module, "stop_monitoring", Mock(return_value={"success": True, "status_code": 200}))


def _membership(fixture, role):
  fixture.store.account("reader", memberships=[{"role": role, "tenant_id": fixture.tenant_id}])


def test_a_tenant_admin_can_stop_a_bound_job_through_the_tenant_seam():
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    _membership(fixture, "tenant_admin")
    with _stop_ok(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=fixture.actor,
                                              tenant_id=fixture.tenant_id)
    assert result.get("success") is True, result
    stop.assert_called_once()
    assert stop.call_args.kwargs["checked_job"]["job_id"] == "job-1"


def test_a_tenant_user_cannot_stop_a_bound_job():
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    _membership(fixture, "tenant_user")
    with _stop_ok(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=fixture.actor,
                                              tenant_id=fixture.tenant_id)
    assert (result.get("success"), result.get("status_code")) == (False, 403), result
    stop.assert_not_called()


def test_a_bound_job_is_refused_on_the_legacy_seam():
  """Omitting the selector must not fall back to legacy authority over a bound job."""
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    _membership(fixture, "tenant_admin")
    with _stop_ok(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=fixture.actor)
    assert result.get("success") is False and result.get("status_code") in (403, 404), result
    stop.assert_not_called()


def test_an_unbound_job_is_not_found_through_a_tenant_selector():
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    _membership(fixture, "tenant_admin")
    with _stop_ok(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, job_id="legacy-alias", stop_type="HARD",
                                              request_actor=fixture.actor, tenant_id=fixture.tenant_id)
    assert (result.get("success"), result.get("status_code")) == (False, 404), result
    stop.assert_not_called()


def test_a_tenant_bound_record_is_normalized_before_the_service_touches_it():
  """The tenant read seam returns the detached raw record; the legacy seam normalizes; the service
  assumes normalized. On a malformed-but-stored record (workers: None) the un-normalized path stopped
  the worker and then raised after the irreversible step -- a 503 that invites a duplicating retry.
  Pinned at the seam: what the service receives must already be normalized. (The read fixture cannot
  run the real service to completion -- no persistence -- so the effect itself is not asserted here.)"""
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    _membership(fixture, "tenant_admin")
    fixture.store.jobs["job-1"]["workers"] = None
    with _stop_ok(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=fixture.actor,
                                              tenant_id=fixture.tenant_id)
    assert result.get("success") is True, result
    received = stop.call_args.kwargs["checked_job"]
    assert isinstance(received.get("workers"), dict), received.get("workers")
    assert received.get("launcher"), received
