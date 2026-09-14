"""RM-026 I1b B8: admission for delete_job_engagement.

A GDPR redaction that rewrites the persisted JobConfig and deletes uploaded authorization documents
from R1FS. The document deletion is irreversible, and the endpoint was reachable with no requester.

It also carries the B4 defect on a destructive operation: `requested_by: str` is a caller-supplied
string written straight into the audit record as the attributed actor
(`services/engagement_deletion.py:315-316`). A parameter named after an identity is not evidence of
one -- the lesson the I1a audit paid for, here deciding who a legal-hold deletion is attributed to.

Contract 4 is vacuous: the whole sequence runs synchronously on the plugin loop, so there is no
window in which the requester can change between admission and effect. Contract 5 is already
honoured better than the ledger could: the endpoint reports explicit per-stage counts
(`fields_cleared`, `documents_deleted`, `documents_failed`, `new_job_config_cid`) rather than an
aggregate, so the ledger is used only to mark what landed for an unexpected raise.

Boundary tests before the implementation, and the caller search for the pairing run without a
truncating pipe (B7 closeout).
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

SECRET = "mock-only-b8-canary"
BODY = {"job_id": "job-1", "delete_documents": True}


def _no_deletion(fixture):
  """Canary on the symbols the plugin calls, bound in the plugin's own namespace.

  `pentester_api_01` imports both names at module scope, so patching
  `services.engagement_deletion` would bind nothing -- the trap that has landed twice in this task.
  """
  module = sys.modules[fixture.Plugin.__module__]
  for name in ("delete_engagement_data", "collect_engagement_document_cids"):
    assert hasattr(module, name), "the plugin no longer imports %s; the canary is vacuous" % name
  return patch.multiple(module,
    delete_engagement_data=Mock(side_effect=RuntimeError(SECRET)),
    collect_engagement_document_cids=Mock(side_effect=RuntimeError(SECRET)))


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_never_redact_or_delete_a_document(fault, status):
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

    with _no_deletion(fixture):
      result = fixture.Plugin.delete_job_engagement(fixture.owner, **BODY, request_actor=actor)
    assert result.get("status_code") == status
    assert result.get("success") is False
    assert SECRET not in repr(result)


def test_a_caller_cannot_supply_the_identity_the_redaction_is_attributed_to():
  """`requested_by` decided the `actor` field of a GDPR deletion audit record from an unverified
  request body. The attribution must come from the resolved account and nowhere else."""
  import inspect
  with read_endpoint_fixture(bound=False) as fixture:
    parameters = inspect.signature(fixture.Plugin.delete_job_engagement).parameters
  assert "requested_by" not in parameters, (
    "a caller can still name the actor a deletion is attributed to")
  assert "request_actor" in parameters


def test_the_audit_record_carries_the_resolved_account():
  """Not just that the caller cannot supply it -- that the resolved identity actually lands."""
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    # The launcher gate runs before the redaction, and the fixture job is launched by node-a.
    fixture.owner.ee_addr = "node-a"
    module = sys.modules[fixture.Plugin.__module__]
    captured = {}

    def _capture(**kwargs):
      captured.update(kwargs)
      raise RuntimeError(SECRET)

    # delete_documents=False skips the JobConfig read; the attribution is what is under test.
    with patch.object(module, "delete_engagement_data", _capture):
      fixture.Plugin.delete_job_engagement(fixture.owner, job_id="job-1", delete_documents=False,
                                           request_actor=fixture.actor)
    assert captured.get("requested_by") == "reader", captured


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("user", 403), ("actor", 404)))
def test_the_denial_keeps_its_status_over_the_wire(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    payload = {**BODY, "request_actor": fixture.actor}
    if fault == "user":
      fixture.store.account("reader", role="user")
    else:
      payload.pop("request_actor")
    with _no_deletion(fixture):
      actual, _headers, body, calls = asyncio.run(
        request(module, "delete_job_engagement", payload))
    assert actual == status, body
    assert calls == 1
    detail = json.loads(body)
    detail = detail.get("detail", detail)
    code = detail.get("error", detail.get("detail")) if isinstance(detail, dict) else detail
    assert code in ("forbidden", "not_found"), detail


def test_failures_do_not_publish_exception_prose():
  """Every failure branch interpolated `{exc}` into the returned message, so a storage or
  serialization error reached the caller as backend internals."""
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.owner.ee_addr = "node-a"
    module = sys.modules[fixture.Plugin.__module__]
    with patch.object(module, "collect_engagement_document_cids",
                      Mock(side_effect=RuntimeError(SECRET))):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, **BODY, request_actor=fixture.actor)
    assert SECRET not in repr(result), result
