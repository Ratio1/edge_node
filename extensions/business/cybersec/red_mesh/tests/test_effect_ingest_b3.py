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
from .read_endpoint_fixtures import allow_pentester, as_role, read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  assert_json_response, install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b3-canary"
PDF_B64 = "JVBERi0xLjQK" + "QQ" * 8  # %PDF-1.4 magic plus filler

# RM-084 P2: correlate_suricata_eve runs as `reports:export` in the caller's tenant. The upload
# keeps the actor-only seam until P3 gives it `authorization:upload`.
CORRELATE_FAULTS = (
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
    fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = []
  elif fault == "user":
    as_role(fixture, "tenant_user")
  elif fault == "other_tenant":
    tenant_id = "tn_2f4b7c1e-9a35-4d02-8f61-7c3b5d9e1a4f"
  elif fault == "identity_store":
    fixture.store.fail_hkey = "auth"
  return actor, tenant_id


@pytest.mark.parametrize("fault,status", CORRELATE_FAULTS)
def test_correlate_denials_never_touch_the_job_or_the_shared_status_record(fault, status):
  with read_endpoint_fixture(bound=True) as fixture:
    actor, tenant_id = apply_fault(fixture, fault)
    with patch.object(suricata_correlation, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as shared, \
         patch.object(suricata_correlation, "_write_job_record",
                      side_effect=AssertionError(SECRET)) as write:
      result = fixture.Plugin.correlate_suricata_eve(
        fixture.owner, "job-1", eve_jsonl="{}", request_actor=actor, tenant_id=tenant_id)
    assert result["status_code"] == status and result["success"] is False
    # The status record is node-global and feeds the cooldown policy: a denial must leave the
    # shared record untouched, not merely leave no job trace.
    shared.assert_not_called()
    write.assert_not_called()


def test_correlate_no_longer_reads_the_job_unscoped():
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_admin")
    with patch.object(fixture.owner, "_get_job_from_cstore", create=True,
                      side_effect=AssertionError(SECRET)) as unscoped:
      fixture.Plugin.correlate_suricata_eve(fixture.owner, "job-1", eve_jsonl="{}",
                                            request_actor=fixture.actor, tenant_id=tenant_id)
    unscoped.assert_not_called()


def test_a_write_that_did_not_happen_is_not_reported_as_ok():
  """_write_job_record returns None without writing when the binding guard trips. Reporting ok with
  a summary that was never stored told the caller the opposite of what happened."""
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_admin")
    with patch.object(suricata_correlation, "_write_job_record", return_value=None):
      result = fixture.Plugin.correlate_suricata_eve(
        fixture.owner, "job-1", eve_jsonl='{"timestamp":"2026-01-01T00:00:00Z"}',
        request_actor=fixture.actor, tenant_id=tenant_id)
    assert result.get("status") != "ok"


def test_a_malformed_payload_publishes_a_structured_code_not_prose():
  with read_endpoint_fixture(bound=True) as fixture:
    result = fixture.Plugin.correlate_suricata_eve(
      fixture.owner, "job-1", eve_jsonl="{not-json}", request_actor=fixture.actor,
      tenant_id=as_role(fixture, "tenant_admin"))
  # The line number is useful diagnostics and carries no caller content, so it survives.
  assert result.get("configuration_error") == "invalid_jsonl_line_1", (
    "a rejected payload must be distinguishable from a zero-match correlation")
  assert "correlation" not in result


def test_an_unsafe_parse_message_cannot_reach_the_caller():
  """The allowlist exists so a future raise carrying caller text cannot be published."""
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_admin")
    with patch.object(suricata_correlation, "_parse_eve_jsonl",
                      side_effect=ValueError("boom " + SECRET)):
      result = fixture.Plugin.correlate_suricata_eve(
        fixture.owner, "job-1", eve_jsonl="{}", request_actor=fixture.actor,
        tenant_id=tenant_id)
  assert SECRET not in repr(result)


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("inactive", 404), ("tenant_user", 403), ("none_scope", 404),
  ("missing_tenant", 400),
))
def test_upload_denials_never_reach_storage(fault, status):
  # RM-084 P3: the upload is tenant-scoped under `authorization:upload`, bound to Allow Pentester.
  with read_endpoint_fixture(bound=True, role="tenant_pentester") as fixture:
    account = fixture.store.data[("auth", "reader")]
    actor, tenant_id = fixture.actor, allow_pentester(fixture)
    if fault == "actor": actor = None
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault == "tenant_user": as_role(fixture, "tenant_user")
    elif fault == "none_scope": account["metadata"]["tenant_memberships"] = []
    elif fault == "missing_tenant": tenant_id = None
    import sys
    plugin_module = sys.modules[fixture.Plugin.__module__]
    # Patch the plugin module's binding: it imports the symbol, so patching the service module
    # binds nothing and assert_not_called would be vacuous.
    with patch.object(plugin_module, "store_authorization_document",
                      side_effect=AssertionError(SECRET)) as store:
      result = fixture.Plugin.upload_authorization(
        fixture.owner, filename="auth.pdf", content_b64=PDF_B64, request_actor=actor,
        tenant_id=tenant_id)
    assert result["status_code"] == status
    store.assert_not_called()


def test_the_uploaded_document_records_its_derived_owner():
  """RM-078's deferral becomes a stored fact rather than a plan sentence."""
  captured = {}

  class _Repo:
    def put_json(self, envelope, show_logs=False):
      captured.update(envelope)
      return "doc-cid"

  with read_endpoint_fixture(bound=True, role="tenant_pentester") as fixture:
    tenant_id = allow_pentester(fixture)
    # Patch the service the endpoint calls, capturing the envelope it would store.
    real_store = authorization_upload.store_authorization_document

    def capture(**kwargs):
      kwargs["artifact_repo"] = _Repo()
      return real_store(**kwargs)

    import sys
    plugin_module = sys.modules[fixture.Plugin.__module__]
    with patch.object(plugin_module, "store_authorization_document", capture):
      fixture.Plugin.upload_authorization(fixture.owner, filename="auth.pdf",
                                          content_b64=PDF_B64, request_actor=fixture.actor,
                                          tenant_id=tenant_id)
      stored_tenant = tenant_id
  assert captured.get("uploaded_by") == "reader", "the derived account was not recorded"
  # RM-084 P3: and the tenant that authorized it, which is what binds it to one workspace.
  assert captured.get("tenant_id") == stored_tenant, "the authorizing tenant was not recorded"
  # Never caller-supplied (contract 5).
  assert "actor" not in captured


# --- Over the wire. The plan required these first; shipping without them let a rejected EVE
# --- upload become indistinguishable from a successful zero-match correlation in the operator UI.

@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_a_rejected_payload_is_distinguishable_from_a_zero_match_over_the_wire(
    read_native, response_format):
  """The blocking finding, pinned at the boundary the UI actually reads.

  DetectionCorrelationUpload.tsx checks only res.ok, so if a rejection and a clean correlation
  both arrive as HTTP 200 with no distinguishing field, the operator is told a truncated EVE log
  produced zero matches -- in a tool whose own text says a zero match is not proof of
  non-detection.
  """
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    rejected, calls = assert_json_response(asyncio.run(request(module, "correlate_suricata_eve",
      {"job_id": "job-1", "eve_jsonl": "{not-json}", "request_actor": fixture.actor,
       "tenant_id": as_role(fixture, "tenant_admin")})), 200)
    body = rejected["result"] if response_format == "WRAPPED" else rejected
    assert calls == 1
    assert body.get("configuration_error") == "invalid_jsonl_line_1"
    assert body.get("status") == "error"
    assert "correlation" not in body, "a rejection carried a correlation payload"


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_a_successful_correlation_carries_its_payload_over_the_wire(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    ok, calls = assert_json_response(asyncio.run(request(module, "correlate_suricata_eve",
      {"job_id": "job-1", "eve_jsonl": '{"timestamp":"2026-01-01T00:00:00Z"}',
       "request_actor": fixture.actor, "tenant_id": as_role(fixture, "tenant_admin")})), 200)
    body = ok["result"] if response_format == "WRAPPED" else ok
    assert calls == 1
    assert body.get("status") == "ok"
    assert "correlation" in body, "the payload the operator reads was dropped by the projection"


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_ingest_denials_survive_both_response_formats(read_native, response_format):
  module, _ = read_native
  install(module)
  for endpoint, body in (("correlate_suricata_eve", {"job_id": "job-1", "eve_jsonl": "{}"}),
                         ("upload_authorization", {"filename": "a.pdf", "content_b64": PDF_B64})):
    # Both are tenant-scoped now (P2 the ingest, P3 the upload); a tenant_user holds neither.
    with read_endpoint_fixture(bound=True) as fixture:
      allow_pentester(fixture)
      body = {**body, "tenant_id": as_role(fixture, "tenant_user")}
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, endpoint,
        {**body, "request_actor": fixture.actor})), 403)
      assert calls == 1
      assert result == {"success": False, "error": "forbidden", "status_code": 403}


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_an_upload_failure_publishes_a_typed_code_not_r1fs_prose(read_native, response_format):
  """WRAPPED previously returned the R1FS exception text verbatim at HTTP 200 while RAW
  collapsed it to 503 -- a format divergence as well as a contract-7 leak."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True, role="tenant_pentester") as fixture:
    module.eng = scheduler_comms(fixture, response_format)
    tenant_id = allow_pentester(fixture)
    result, _calls = assert_json_response(asyncio.run(request(module, "upload_authorization",
      {"filename": "a.txt", "content_b64": "bm90LWEtcGRm", "request_actor": fixture.actor,
       "tenant_id": tenant_id})), 200)
    body = result["result"] if response_format == "WRAPPED" else result
    assert body.get("configuration_error") == "bad_mime"
    assert "message" not in body, "exception prose reached the caller"
    assert "error" not in body


@pytest.mark.parametrize("tenant_id", (None, "", "   "))
def test_a_missing_tenant_is_refused_before_admission(tenant_id):
  """RM-084 P2: the ingest has no unscoped half; an omitted selector is a bad request.

  This replaces the snapshot-exclusion case, which asserted the opposite: that a tenant-bound job
  could not be correlated at all."""
  with read_endpoint_fixture(bound=True) as fixture:
    as_role(fixture, "tenant_admin")
    with patch.object(suricata_correlation, "_write_job_record",
                      side_effect=AssertionError(SECRET)) as write:
      result = fixture.Plugin.correlate_suricata_eve(
        fixture.owner, "job-1", eve_jsonl="{}", request_actor=fixture.actor, tenant_id=tenant_id)
    assert result == {"success": False, "error": "invalid_request", "status_code": 400}
    write.assert_not_called()


def test_the_parse_allowlist_guards_the_node_global_status_record():
  """The allowlist's real sink is the shared status record, not the response -- the projection
  drops an unrecognised code from the response anyway, which made the earlier test inert."""
  captured = []
  with read_endpoint_fixture(bound=True) as fixture:
    tenant_id = as_role(fixture, "tenant_admin")
    with patch.object(suricata_correlation, "_parse_eve_jsonl",
                      side_effect=ValueError("boom " + SECRET)), \
         patch.object(suricata_correlation, "record_integration_status",
                      side_effect=lambda *a, **k: captured.append(k.get("error_class"))):
      fixture.Plugin.correlate_suricata_eve(fixture.owner, "job-1", eve_jsonl="{}",
                                            request_actor=fixture.actor, tenant_id=tenant_id)
  assert captured == ["eve_payload_rejected"], captured
  assert all(SECRET not in str(entry) for entry in captured)
