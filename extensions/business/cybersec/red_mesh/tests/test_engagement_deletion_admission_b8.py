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


@pytest.mark.parametrize("branch,code", (
  ("config", "config_not_found"),
  ("state_persist", "state_persist_failed"),
  ("audit_persist", "audit_persist_failed"),
))
def test_failures_do_not_publish_exception_prose(branch, code):
  """Every failure branch interpolated `{exc}` into the returned message, so a storage error
  reached the caller as backend internals.

  An earlier version of this test patched `collect_engagement_document_cids`, which is called
  outside any `try`, so the raise escaped to the wrapper's generic handler and the assertion was
  satisfied by `unavailable` rather than by the prose removal -- vacuous for all four branches it
  claimed to guard. Each branch is now reached on its own terms and its code asserted.
  """
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.owner.ee_addr = "node-a"
    fixture.owner.P = lambda *_args, **_kwargs: None
    fixture.store.jobs["legacy-alias"]["job_config_cid"] = "cfg-cid"
    module = sys.modules[fixture.Plugin.__module__]
    repo = Mock()
    repo.put_job_config = Mock(return_value="new-cid")
    repo.delete = Mock(return_value=True)
    repo.get_job_config = (Mock(side_effect=RuntimeError(SECRET)) if branch == "config"
                           else Mock(return_value={"engagement": {"client": "acme"}}))
    writes = []

    def _write(_plugin, _job_id, _specs, **_kwargs):
      writes.append(1)
      if branch == "state_persist" or (branch == "audit_persist" and len(writes) > 1):
        raise RuntimeError(SECRET)
      return {"ok": True}

    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo), \
         patch.object(module, "collect_engagement_document_cids", Mock(return_value=["doc-a"])), \
         patch.object(fixture.Plugin, "_write_job_record", _write):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, **BODY, request_actor=fixture.actor)
    assert result.get("error_code") == code, result
    assert SECRET not in repr(result), result


def test_only_a_legacy_admin_may_delete_engagement_data():
  """The shared reports:export gate admits an admin *or* an app_role pentester, which is right for
  the rulebook mutations and broader than the owner's B8 decision. This endpoint irreversibly
  deletes authorization documents, so it takes the narrower of the two."""
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    # A legacy pentester: exactly the account the shared reports:export gate would admit.
    fixture.store.account("reader", role="user")
    fixture.store.data[("auth", "reader")]["metadata"]["appRole"] = "pentester"
    module = sys.modules[fixture.Plugin.__module__]
    with _no_deletion(fixture):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, **BODY, request_actor=fixture.actor)
      module.delete_engagement_data.assert_not_called()
    assert result == {"success": False, "error": "forbidden", "status_code": 403}, result


def test_the_delivered_state_is_recorded_once_a_document_is_gone():
  """PERSISTED and DELIVERED are not interchangeable here. The first says a sanitized config was
  written -- recoverable. The second says an authorization document no longer exists. An unexpected
  raise after the delete loop must report the stronger one, or the caller is told a retry is safe
  when documents are already gone.

  Driven by making the audit branch's own logging raise, which is the one way an exception escapes
  after deletion: every other post-delete failure is caught and answered with counts.
  """
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.owner.ee_addr = "node-a"
    fixture.store.jobs["legacy-alias"]["job_config_cid"] = "cfg-cid"
    module = sys.modules[fixture.Plugin.__module__]
    repo = Mock()
    repo.get_job_config = Mock(return_value={"engagement": {"client": "acme"}})
    repo.put_job_config = Mock(return_value="new-cid")
    repo.delete = Mock(return_value=True)
    writes = []

    def _write(_plugin, _job_id, _specs, **_kwargs):
      writes.append(1)
      if len(writes) > 1:
        raise RuntimeError("audit write failed")
      return {"ok": True}

    def _raising_printer(*_args, **_kwargs):
      raise RuntimeError("printer unavailable")

    fixture.owner.P = _raising_printer
    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo), \
         patch.object(module, "collect_engagement_document_cids", Mock(return_value=["doc-a"])), \
         patch.object(fixture.Plugin, "_write_job_record", _write):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, **BODY, request_actor=fixture.actor)
    assert repo.delete.call_count == 1, "the document was not deleted, so this proves nothing"
    assert result.get("effect_state") == "delivered", (
      "a deleted document was reported as a merely persisted effect: %r" % (result,))


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


@pytest.mark.parametrize("branch,code", (
  ("config", "config_not_found"),
  ("state_persist", "state_persist_failed"),
  ("audit_persist", "audit_persist_failed"),
))
def test_failures_do_not_publish_exception_prose(branch, code):
  """Every failure branch interpolated `{exc}` into the returned message, so a storage error
  reached the caller as backend internals.

  An earlier version of this test patched `collect_engagement_document_cids`, which is called
  outside any `try`, so the raise escaped to the wrapper's generic handler and the assertion was
  satisfied by `unavailable` rather than by the prose removal -- vacuous for all four branches it
  claimed to guard. Each branch is now reached on its own terms and its code asserted.
  """
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.owner.ee_addr = "node-a"
    fixture.owner.P = lambda *_args, **_kwargs: None
    fixture.store.jobs["legacy-alias"]["job_config_cid"] = "cfg-cid"
    module = sys.modules[fixture.Plugin.__module__]
    repo = Mock()
    repo.put_job_config = Mock(return_value="new-cid")
    repo.delete = Mock(return_value=True)
    repo.get_job_config = (Mock(side_effect=RuntimeError(SECRET)) if branch == "config"
                           else Mock(return_value={"engagement": {"client": "acme"}}))
    writes = []

    def _write(_plugin, _job_id, _specs, **_kwargs):
      writes.append(1)
      if branch == "state_persist" or (branch == "audit_persist" and len(writes) > 1):
        raise RuntimeError(SECRET)
      return {"ok": True}

    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo), \
         patch.object(module, "collect_engagement_document_cids", Mock(return_value=["doc-a"])), \
         patch.object(fixture.Plugin, "_write_job_record", _write):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, **BODY, request_actor=fixture.actor)
    assert result.get("error_code") == code, result
    assert SECRET not in repr(result), result


def test_only_a_legacy_admin_may_delete_engagement_data():
  """The shared reports:export gate admits an admin *or* an app_role pentester, which is right for
  the rulebook mutations and broader than the owner's B8 decision. This endpoint irreversibly
  deletes authorization documents, so it takes the narrower of the two."""
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    # A legacy pentester: exactly the account the shared reports:export gate would admit.
    fixture.store.account("reader", role="user")
    fixture.store.data[("auth", "reader")]["metadata"]["appRole"] = "pentester"
    module = sys.modules[fixture.Plugin.__module__]
    with _no_deletion(fixture):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, **BODY, request_actor=fixture.actor)
      module.delete_engagement_data.assert_not_called()
    assert result == {"success": False, "error": "forbidden", "status_code": 403}, result


def test_the_service_layer_does_not_publish_exception_prose_either():
  """The plugin's four interpolations were removed first; two more lived in the service and were
  returned verbatim as `DeleteEngagementError.message`. delete_documents=False routes past the
  plugin's own sanitized branch straight into the service, which is how this one stayed hidden."""
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.owner.ee_addr = "node-a"
    repo = Mock()
    repo.get_job_config = Mock(side_effect=RuntimeError(SECRET))
    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, job_id="job-1", delete_documents=False, request_actor=fixture.actor)
    assert SECRET not in repr(result), result


def test_the_requester_is_revalidated_before_the_irreversible_delete():
  """`record` does not run the checkpoint callback -- only `checkpoint` does. Without an explicit
  checkpoint the authority established before three storage round-trips would be the only authority
  ever checked, which is not what the sibling effect paths do."""
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.owner.ee_addr = "node-a"
    fixture.store.jobs["legacy-alias"]["job_config_cid"] = "cfg-cid"
    module = sys.modules[fixture.Plugin.__module__]
    deleted = []
    repo = Mock()
    repo.get_job_config = Mock(return_value={"engagement": {"client": "acme"}})
    repo.put_job_config = Mock(return_value="new-cid")
    repo.delete = Mock(side_effect=lambda cid, **_kw: deleted.append(cid) or True)

    def _revoke_then_collect(_config):
      # Deactivate the requester after admission and before the delete loop.
      fixture.store.account("reader", active=False)
      return ["doc-cid"]

    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo), \
         patch.object(module, "collect_engagement_document_cids", _revoke_then_collect), \
         patch.object(fixture.Plugin, "_write_job_record", Mock(return_value={"ok": True})):
      result = fixture.Plugin.delete_job_engagement(
        fixture.owner, job_id="job-1", delete_documents=True, request_actor=fixture.actor)
    assert deleted == [], "a revoked requester's documents were deleted anyway"
    # The sanitized config already landed, so this is an incomplete effect, not a clean denial.
    assert result.get("error_code") == "effect_incomplete" or result.get("error") == "effect_incomplete", result


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_a_partial_redaction_reports_its_counts_over_the_wire(read_native, response_format):
  """The per-stage counts are the reason this endpoint keeps its own shape, and an earlier revision
  lost them in RAW: the framework maps any dict carrying `error` to a plugin error, and the template
  reduces the whole body to the bare code string. Under the review projection the code travels as
  `error_code`, the response stays 2xx, and every count survives in both formats."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False, archived=False) as fixture:
    fixture.owner.ee_addr = "node-a"
    fixture.owner.P = lambda *_args, **_kwargs: None
    fixture.store.jobs["legacy-alias"]["job_config_cid"] = "cfg-cid"
    module.eng = scheduler_comms(fixture, response_format)
    plugin_module = sys.modules[fixture.Plugin.__module__]
    repo = Mock()
    repo.get_job_config = Mock(return_value={"engagement": {"client": "acme"}})
    repo.put_job_config = Mock(return_value="new-cid")
    repo.delete = Mock(return_value=True)  # both documents are irreversibly gone

    # The state write succeeds, the audit write fails: the worst partial there is. Two documents are
    # deleted and the record of it did not persist, so the counts in this response are the only
    # place the truth exists.
    writes = []

    def _write(_plugin, _job_id, _specs, **_kwargs):
      writes.append(1)
      if len(writes) > 1:
        raise RuntimeError("audit write failed")
      return {"ok": True}

    with patch.object(fixture.Plugin, "_get_artifact_repository", return_value=repo), \
         patch.object(plugin_module, "collect_engagement_document_cids",
                      Mock(return_value=["doc-a", "doc-b"])), \
         patch.object(fixture.Plugin, "_write_job_record", _write):
      status, headers, body, _calls = asyncio.run(request(module, "delete_job_engagement",
        {"job_id": "job-1", "delete_documents": True, "request_actor": fixture.actor}))
    assert status == 200, body
    assert headers[b"cache-control"] == b"no-store"
    payload = json.loads(body)
    payload = payload["result"] if response_format == "WRAPPED" else payload
    assert payload["error_code"] == "audit_persist_failed", payload
    assert payload["documents_deleted"] == 2, payload
    assert payload["documents_failed"] == 0, payload
    assert payload["new_job_config_cid"] == "new-cid", payload
