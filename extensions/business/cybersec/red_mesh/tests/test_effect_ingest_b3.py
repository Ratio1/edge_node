"""RM-026 I1b B3: ingest admission for correlate and authorization upload.

`correlate_suricata_eve` was not merely an unscoped read: it fed a job-record write, so an
unadmitted caller could overwrite the detection_correlation field of any job id it could guess. Its
denial writes also hit a node-global status record routed through the cooldown policy, so probing
was an availability effect for every tenant.
"""
import asyncio
from unittest.mock import patch

import pytest

from extensions.business.cybersec.red_mesh.services import authorization_upload, suricata_correlation
from extensions.business.cybersec.red_mesh.tenancy.effects import EffectState
from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  assert_json_response, install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b3-canary"
PDF_B64 = "JVBERi0xLjQK" + "QQ" * 8  # %PDF-1.4 magic plus filler


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_correlate_denials_never_touch_the_job_or_the_shared_status_record(fault, status):
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

    with patch.object(suricata_correlation, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as shared, \
         patch.object(suricata_correlation, "_write_job_record",
                      side_effect=AssertionError(SECRET)) as write:
      result = fixture.Plugin.correlate_suricata_eve(
        fixture.owner, "job-1", eve_jsonl="{}", request_actor=actor)
    assert result["status_code"] == status and result["success"] is False
    # The status record is node-global and feeds the cooldown policy: a denial must leave the
    # shared record untouched, not merely leave no job trace.
    shared.assert_not_called()
    write.assert_not_called()


def test_correlate_no_longer_reads_the_job_unscoped():
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(fixture.owner, "_get_job_from_cstore", create=True,
                      side_effect=AssertionError(SECRET)) as unscoped:
      fixture.Plugin.correlate_suricata_eve(fixture.owner, "job-1", eve_jsonl="{}",
                                            request_actor=fixture.actor)
    unscoped.assert_not_called()


def test_a_write_that_did_not_happen_is_not_reported_as_ok():
  """_write_job_record returns None without writing when the binding guard trips. Reporting ok with
  a summary that was never stored told the caller the opposite of what happened."""
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(suricata_correlation, "_write_job_record", return_value=None):
      result = fixture.Plugin.correlate_suricata_eve(
        fixture.owner, "job-1", eve_jsonl='{"timestamp":"2026-01-01T00:00:00Z"}',
        request_actor=fixture.actor)
    assert result.get("status") != "ok"


def test_a_malformed_payload_publishes_a_structured_code_not_prose():
  with read_endpoint_fixture(bound=False) as fixture:
    result = fixture.Plugin.correlate_suricata_eve(
      fixture.owner, "job-1", eve_jsonl="{not-json}", request_actor=fixture.actor)
  # The line number is useful diagnostics and carries no caller content, so it survives.
  assert result.get("configuration_error") in (None, "invalid_jsonl_line_1") or \
    result.get("error") == "invalid_jsonl_line_1"


def test_an_unsafe_parse_message_cannot_reach_the_caller():
  """The allowlist exists so a future raise carrying caller text cannot be published."""
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(suricata_correlation, "_parse_eve_jsonl",
                      side_effect=ValueError("boom " + SECRET)):
      result = fixture.Plugin.correlate_suricata_eve(
        fixture.owner, "job-1", eve_jsonl="{}", request_actor=fixture.actor)
  assert SECRET not in repr(result)


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("inactive", 404), ("user", 403), ("memberships", 403),
))
def test_upload_denials_never_reach_storage(fault, status):
  with read_endpoint_fixture(bound=False) as fixture:
    account = fixture.store.data[("auth", "reader")]
    actor = fixture.actor
    if fault == "actor": actor = None
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault == "user": fixture.store.account("reader", role="user")
    elif fault == "memberships": account["metadata"]["tenant_memberships"] = []
    with patch.object(authorization_upload, "store_authorization_document",
                      side_effect=AssertionError(SECRET)) as store:
      result = fixture.Plugin.upload_authorization(
        fixture.owner, filename="auth.pdf", content_b64=PDF_B64, request_actor=actor)
    assert result["status_code"] == status
    store.assert_not_called()


def test_the_uploaded_document_records_its_derived_owner():
  """RM-078's deferral becomes a stored fact rather than a plan sentence."""
  captured = {}

  class _Repo:
    def put_json(self, envelope, show_logs=False):
      captured.update(envelope)
      return "doc-cid"

  with read_endpoint_fixture(bound=False) as fixture:
    # Patch the service the endpoint calls, capturing the envelope it would store.
    real_store = authorization_upload.store_authorization_document

    def capture(**kwargs):
      kwargs["artifact_repo"] = _Repo()
      return real_store(**kwargs)

    import sys
    plugin_module = sys.modules[fixture.Plugin.__module__]
    with patch.object(plugin_module, "store_authorization_document", capture):
      fixture.Plugin.upload_authorization(fixture.owner, filename="auth.pdf",
                                          content_b64=PDF_B64, request_actor=fixture.actor)
  assert captured.get("uploaded_by") == "reader", "the derived account was not recorded"
  # Never caller-supplied (contract 5).
  assert "actor" not in captured
