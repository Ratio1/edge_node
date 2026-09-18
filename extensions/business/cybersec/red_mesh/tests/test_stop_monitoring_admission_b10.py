"""RM-026 I1b B10: admission for stop_monitoring.

Split out of the B9 Controls group by the owner's decision (2026-09-14): it stops monitoring rather
than deleting, it is already POST and it carries none of the purge machinery.

RM-084 P3 removed the unscoped half: the caller's tenant is required, and the job must be bound to
it. Every case below therefore names a tenant.

It was reachable with no requester at all. A HARD stop cancels running workers, marks the job
stopped, emits a `redmesh.job.stopped` lifecycle event to the SOC, and persists the job record; a
SOFT stop schedules the same for the end of the current pass. None of that is undoable by the caller.

Contract 4 is vacuous: the sequence is synchronous on the plugin loop, so the requester cannot change
between admission and effect.
"""
import asyncio
import json
import sys
from copy import deepcopy
from unittest.mock import Mock, patch

import pytest

from .read_endpoint_fixtures import as_role, read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b10-canary"
BODY = {"job_id": "job-1", "stop_type": "HARD"}
OTHER_TENANT = "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"


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
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("none_scope", 404),
  ("tenant_user", 403), ("missing_tenant", 400), ("other_tenant", 404),
  # The "rollout" fault left with the unscoped seam: the execution rollout gated that seam only,
  # never the tenant reader, so it is no longer a denial for this endpoint. P6 deletes it entirely.
  ("identity_store", 503),
))
def test_denials_never_stop_a_worker_or_emit_a_lifecycle_event(fault, status):
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    account = fixture.store.data[("auth", "reader")]
    actor, tenant_id = fixture.actor, fixture.tenant_id
    if fault == "actor": actor = None
    elif fault == "deleted": fixture.store.data.pop(("auth", "reader"))
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault == "none_scope": account["metadata"]["tenant_memberships"] = []
    elif fault == "tenant_user": as_role(fixture, "tenant_user")
    elif fault == "missing_tenant": tenant_id = None
    elif fault == "other_tenant": tenant_id = OTHER_TENANT
    elif fault == "identity_store": fixture.store.fail_hkey = "auth"

    with _no_stop(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=actor,
                                              tenant_id=tenant_id)
    assert result.get("status_code") == status
    assert result.get("success") is False
    stop.assert_not_called()
    assert SECRET not in repr(result)


def test_the_stop_reads_no_job_of_its_own():
  """Admission already read the job under the reader's authority.

  Asserted by object identity, not `is not None`: the weaker form passes for any snapshot at all,
  including one the endpoint fetched itself, which is the defect this is meant to exclude.
  """
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
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
      fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=fixture.actor,
                                     tenant_id=fixture.tenant_id)
    assert len(admitted) == 1 and admitted[0] is not None
    # The tenant seam hands back the detached raw record, which the endpoint normalizes before the
    # service sees it -- so the identity to assert is against that normalization of the admitted
    # snapshot, not a second read of the store.
    _, expected = fixture.owner._normalize_job_record("job-1", admitted[0])
    assert received and received[0].get("checked_job") == expected, (
      "the stop did not receive the admitted snapshot: %r" % (received,))


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("tenant_user", 403), ("actor", 404)))
def test_the_denial_keeps_its_status_over_the_wire(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {**BODY, "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
    if fault == "tenant_user":
      as_role(fixture, "tenant_user")
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
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    fixture.owner.ee_addr = "some-other-node"   # the fixture job was launched by node-a
    fixture.owner.P = lambda *_args, **_kwargs: None
    fixture.owner._log_audit_event = lambda *_args, **_kwargs: None
    status, headers, body, _calls = asyncio.run(request(module, "stop_monitoring",
      {**BODY, "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}))
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


@pytest.mark.parametrize("tenant_id", (None, "", "   "))
def test_omitting_the_tenant_is_refused_rather_than_falling_back(tenant_id):
  """RM-084 P3: there is no unscoped half left to fall back to, so this is a 400 and not a stop."""
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    _membership(fixture, "tenant_admin")
    with _stop_ok(fixture) as stop:
      result = fixture.Plugin.stop_monitoring(fixture.owner, **BODY, request_actor=fixture.actor,
                                              tenant_id=tenant_id)
    assert (result.get("success"), result.get("status_code"), result.get("error")) == (
      False, 400, "invalid_request"), result
    stop.assert_not_called()


def test_an_unbound_job_is_not_found_through_a_tenant_selector():
  """A record with no binding belongs to no tenant, so a tenant caller cannot reach it at all."""
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    _membership(fixture, "tenant_admin")
    fixture.store.jobs["legacy-alias"] = {**deepcopy(fixture.job), "job_id": "legacy-alias"}
    fixture.store.jobs["legacy-alias"].pop("execution_binding")
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
