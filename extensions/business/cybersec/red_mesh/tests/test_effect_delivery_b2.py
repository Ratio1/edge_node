"""RM-026 I1b B2: external delivery admission and the returned-failure mechanism.

These endpoints put data on third-party systems, so a failure after a successful persist must never
be reported as "nothing happened" -- a retry would duplicate it. B1 proved a control can be green in
its own suite and inert over HTTP, twice, so the load-bearing tests here go over the wire.
"""
import asyncio
from unittest.mock import patch

import pytest

from extensions.business.cybersec.red_mesh.services import opencti_export, taxii_export
from extensions.business.cybersec.red_mesh.tenancy.effects import EffectState
from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  assert_json_response, install, read_native, request, scheduler_comms,
)

SECRET = "mock-only-b2-canary"
OK_BUNDLE = {"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
             "object_count": 0, "finding_count": 0, "observed_data_count": 0}

DELIVERIES = (
  ("push_to_opencti", opencti_export, {"ENABLED": True, "URL": "https://opencti.test",
                                       "PUSH_MODE": "live", "TOKEN_ENV": "RM_T", "AUTH_MODE": "token",
                                       "MIN_SEVERITY": "LOW"}),
  ("publish_to_taxii", taxii_export, {"ENABLED": True, "SERVER_URL": "https://taxii.test",
                                      "COLLECTION_ID": "c1", "MODE": "taxii_2.1",
                                      "TOKEN_ENV": "RM_T", "AUTH_MODE": "token",
                                      "TIMEOUT_SECONDS": 5}),
)


class _Response:
  """A remote that accepts the connection and then refuses the payload."""

  def __init__(self, status_code):
    self.status_code = status_code
    self.text = "upstream refused"

  def json(self):
    return {}


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("name,service,config", DELIVERIES)
def test_a_delivery_failure_after_a_persist_is_never_reported_as_nothing_happened(
    read_native, response_format, name, service, config):
  """The mechanism this slice exists for, exercised at the HTTP boundary.

  The bundle is on disk before the remote refuses it. Reporting `unavailable` would tell the caller
  nothing happened and invite a retry that duplicates the artifact.
  """
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(service, "_config_error", return_value=None), \
         patch.object(service, "build_stix_bundle", return_value=dict(OK_BUNDLE)), \
         patch.object(service, "_persist_bundle", return_value="artifact-cid"), \
         patch.object(service, "build_auth_provider") as auth, \
         patch.object(service.requests, "post", return_value=_Response(502)):
      auth.return_value.headers.return_value = {}
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, name,
        {"job_id": "job-1", "request_actor": fixture.actor})), 500)
    assert calls == 1
    assert result["error"] == "effect_incomplete", (
      "%s reported a landed persist as %r over %s" % (name, result.get("error"), response_format))
    assert result["effect_state"] in (EffectState.PERSISTED.value, "unknown")
    assert SECRET not in repr(result) and "upstream refused" not in repr(result)


@pytest.mark.parametrize("name,service,config", DELIVERIES)
def test_a_typed_configuration_failure_keeps_its_code_after_a_persist(name, service, config):
  """The round-2 correction: a typed code emitted after a persist must survive.

  Both services persist and only then resolve auth, so a naive "ledger non-NONE -> incomplete" rule
  would destroy the code the panels display.
  """
  from extensions.business.cybersec.red_mesh.services.auth import AuthError
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(service, "_config_error", return_value=None), \
         patch.object(service, "build_stix_bundle", return_value=dict(OK_BUNDLE)), \
         patch.object(service, "_persist_bundle", return_value="artifact-cid"), \
         patch.object(service, "build_auth_provider",
                      side_effect=AuthError("invalid_auth_config")):
      result = getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=fixture.actor)
    assert result.get("configuration_error") == "invalid_auth_config", (
      "%s lost its typed code to the incomplete-effect substitution" % name)


@pytest.mark.parametrize("name,service,config", DELIVERIES)
def test_delivery_endpoints_deny_an_unauthorized_caller_without_effects(name, service, config):
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    with patch.object(service, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as recorder, \
         patch.object(service, "_persist_bundle", side_effect=AssertionError(SECRET)) as persist:
      result = getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=fixture.actor)
    assert result == {"success": False, "error": "forbidden", "status_code": 403}
    recorder.assert_not_called()
    persist.assert_not_called()


def test_a_delivery_failure_publishes_both_the_state_and_the_reason():
  """Neither half is sufficient alone: without the state a retry duplicates a landed effect,
  without the code the panel shows nothing actionable."""
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(opencti_export, "_config_error", return_value=None), \
         patch.object(opencti_export, "build_stix_bundle", return_value=dict(OK_BUNDLE)), \
         patch.object(opencti_export, "_persist_bundle", return_value="artifact-cid"), \
         patch.object(opencti_export, "build_auth_provider") as auth, \
         patch.object(opencti_export.requests, "post", return_value=_Response(502)):
      auth.return_value.headers.return_value = {}
      result = fixture.Plugin.push_to_opencti(fixture.owner, "job-1",
                                              request_actor=fixture.actor)
  assert result["error"] == "effect_incomplete"
  assert result["effect_state"] == EffectState.PERSISTED.value
  assert result["configuration_error"] == "http_502"


def test_the_panel_fields_each_delivery_consumer_reads_survive_the_projection():
  """Pin the projection against its three consumers, as B1's Download-button break taught."""
  from extensions.business.cybersec.red_mesh.tenancy.effects import public_effect_result
  opencti = public_effect_result({"status": "ok", "opencti_file_id": "f1",
                                  "upload_status": "complete", "job_id": "job-1"})
  for field in ("opencti_file_id", "upload_status"):
    assert field in opencti, f"OpenCtiExport.tsx reads {field}"
  taxii = public_effect_result({"status": "ok", "taxii_status_id": "s1", "taxii_status": "complete",
                                "collection_id": "c1", "success_count": 3, "failure_count": 0,
                                "pending_count": 0, "job_id": "job-1"})
  for field in ("taxii_status_id", "taxii_status", "collection_id", "success_count",
                "failure_count", "pending_count"):
    assert field in taxii, f"TaxiiExport.tsx reads {field}"
  misp = public_effect_result({"status": "ok", "findings_exported": 4, "ports_exported": 2,
                               "event_uuid": "u1", "job_id": "job-1"})
  for field in ("findings_exported", "ports_exported"):
    assert field in misp, f"MispExport.tsx reads {field}"
  # redacted_host is deliberately withheld: it is the real hostname (contract 7).
  assert "redacted_host" not in public_effect_result(
    {"status": "ok", "redacted_host": "opencti.internal", "job_id": "job-1"})


# --- MISP: its own seam, because PyMISP is the transport and requests.post does not reach it ---

MISP_CONFIG = {"ENABLED": True, "MISP_URL": "https://misp.test", "MISP_API_KEY": "k",
               "MISP_VERIFY_TLS": False, "TIMEOUT": 5, "MISP_PUBLISH": False,
               "MISP_DISTRIBUTION": 0, "MISP_THREAT_LEVEL": 2, "MISP_ANALYSIS": 2}


@pytest.fixture
def misp_ready(monkeypatch):
  """A MISP export that is configured and whose event builds, so tests reach the transport."""
  from extensions.business.cybersec.red_mesh.services import misp_export
  from pymisp import MISPEvent
  event = MISPEvent()
  event.uuid = "11111111-1111-1111-1111-111111111111"
  monkeypatch.setattr(misp_export, "get_misp_export_config", lambda owner: dict(MISP_CONFIG))
  monkeypatch.setattr(misp_export, "build_misp_event",
                      lambda *a, **k: {"status": "ok", "event": event, "job_id": "job-1",
                                       "pass_nr": 1, "findings_exported": 2, "ports_exported": 1})
  return misp_export


@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_misp_denials_reach_neither_the_server_nor_the_job_record(misp_ready, fault, status):
  """B1's denial matrix, extended to the endpoint the security review found untested."""
  service = misp_ready
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

    with patch.object(service, "PyMISP", side_effect=AssertionError(SECRET)) as transport, \
         patch.object(service, "emit_export_status_event",
                      side_effect=AssertionError(SECRET)) as emit, \
         patch.object(service, "_write_job_record", side_effect=AssertionError(SECRET)) as write:
      result = fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=actor)
    assert result["status_code"] == status and result["success"] is False
    transport.assert_not_called()
    emit.assert_not_called()
    write.assert_not_called()


def test_misp_does_not_reach_the_server_after_the_requester_is_revoked(misp_ready):
  """Contract 4 on the least recoverable endpoint.

  The security review demonstrated a revoked requester's payload reaching the MISP server while the
  identical race against OpenCTI stopped before the outbound call. The window is real: the event
  build spans an archive fetch and several artifact reads.
  """
  service = misp_ready
  with read_endpoint_fixture(bound=False) as fixture:
    def build_then_revoke(*args, **kwargs):
      fixture.store.account("reader", active=False)
      from pymisp import MISPEvent
      event = MISPEvent()
      event.uuid = "22222222-2222-2222-2222-222222222222"
      return {"status": "ok", "event": event, "job_id": "job-1", "pass_nr": 1}

    with patch.object(service, "build_misp_event", build_then_revoke), \
         patch.object(service, "PyMISP", side_effect=AssertionError(SECRET)) as transport:
      result = fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=fixture.actor)
    transport.assert_not_called(), "a revoked requester's payload reached the MISP server"
    assert result["success"] is False


def test_misp_transport_failure_after_an_emission_is_not_reported_as_nothing_happened(misp_ready):
  service = misp_ready
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(service, "PyMISP", side_effect=RuntimeError(SECRET)):
      result = fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=fixture.actor)
  # connection_failed is a typed code, and the prose that could carry the MISP URL is gone.
  assert result.get("configuration_error") == "connection_failed"
  assert SECRET not in repr(result) and "misp.test" not in repr(result)


def test_misp_never_returns_ok_when_the_remote_rejected_everything(misp_ready):
  """The re-export branch assigned the locally held event, making the acceptance check vacuous."""
  service = misp_ready
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.job["misp_export"] = {"event_uuid": "33333333-3333-3333-3333-333333333333"}
    from pymisp import MISPEvent
    existing = MISPEvent()
    existing.uuid = "33333333-3333-3333-3333-333333333333"
    misp = type("_Misp", (), {
      "get_event": lambda self, *a, **k: existing,
      "add_object": lambda self, *a, **k: {"errors": "rejected"},
      "update_event": lambda self, *a, **k: {"errors": "rejected"},
    })()
    with patch.object(service, "PyMISP", return_value=misp):
      result = fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=fixture.actor)
  assert result.get("status") != "ok", "a fully rejected re-export reported success"


@pytest.mark.parametrize("name,service,config", DELIVERIES)
def test_the_pre_outbound_checkpoint_stops_a_revoked_requester(read_native, name, service, config):
  """Contract addition 1, which mutation testing showed had no evidence on any service.

  The account is revoked after admission and after the persist, before the outbound call.
  """
  with read_endpoint_fixture(bound=False) as fixture:
    def persist_then_revoke(owner, bundle):
      fixture.store.account("reader", active=False)
      return "artifact-cid"

    with patch.object(service, "_config_error", return_value=None), \
         patch.object(service, "build_stix_bundle", return_value=dict(OK_BUNDLE)), \
         patch.object(service, "_persist_bundle", persist_then_revoke), \
         patch.object(service, "build_auth_provider") as auth, \
         patch.object(service.requests, "post", side_effect=AssertionError(SECRET)) as post:
      auth.return_value.headers.return_value = {}
      result = getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=fixture.actor)
    post.assert_not_called()
    # The persist landed before the revocation, so the caller must be told so.
    assert result["error"] == "effect_incomplete"
    assert result["effect_state"] == EffectState.PERSISTED.value


@pytest.mark.parametrize("seam", ("entry", "event_build"))
def test_misp_reads_the_job_only_through_the_checked_snapshot(misp_ready, seam):
  """Both MISP scoping seams. Mutation testing showed reverting either left the suite green."""
  service = misp_ready
  with read_endpoint_fixture(bound=False) as fixture:
    if seam == "event_build":
      # Let the real builder run so the second seam is exercised rather than stubbed away.
      from extensions.business.cybersec.red_mesh.services import misp_export as real
      service_build = real.build_misp_event
      with patch.object(service, "build_misp_event", service_build), \
           patch.object(fixture.owner, "_get_job_from_cstore", create=True,
                        side_effect=AssertionError(SECRET)) as unscoped, \
           patch.object(service, "PyMISP", side_effect=RuntimeError("stop-before-transport")):
        fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=fixture.actor)
      unscoped.assert_not_called()
      return
    with patch.object(fixture.owner, "_get_job_from_cstore", create=True,
                      side_effect=AssertionError(SECRET)) as unscoped, \
         patch.object(service, "PyMISP", side_effect=RuntimeError("stop-before-transport")):
      fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=fixture.actor)
    unscoped.assert_not_called()


def test_misp_records_delivery_only_on_an_accepted_event(misp_ready):
  """M5: deleting the DELIVERED record after add_event left the suite green."""
  service = misp_ready
  from pymisp import MISPEvent
  accepted = MISPEvent()
  accepted.uuid = "44444444-4444-4444-4444-444444444444"
  with read_endpoint_fixture(bound=False) as fixture:
    misp = type("_Misp", (), {"add_event": lambda self, *a, **k: accepted,
                              "publish": lambda self, *a, **k: None})()
    with patch.object(service, "PyMISP", return_value=misp), \
         patch.object(service, "_write_job_record", side_effect=RuntimeError(SECRET)):
      result = fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=fixture.actor)
  assert result["error"] == "effect_incomplete"
  assert result["effect_state"] == EffectState.DELIVERED.value, (
    "the event was accepted by the remote but the ledger did not record a delivery")


def test_a_misconfigured_misp_does_not_emit_or_write(misp_ready, monkeypatch):
  """The twin of the disabled branch: both were dead before this slice, so neither may start
  emitting a SOC event and writing the job record now that the path is live."""
  service = misp_ready
  monkeypatch.setattr(service, "get_misp_export_config",
                      lambda owner: {**MISP_CONFIG, "MISP_API_KEY": ""})
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(service, "emit_export_status_event",
                      side_effect=AssertionError(SECRET)) as emit, \
         patch.object(service, "_write_job_record", side_effect=AssertionError(SECRET)) as write:
      result = fixture.Plugin.export_misp(fixture.owner, "job-1", request_actor=fixture.actor)
    emit.assert_not_called()
    write.assert_not_called()
  assert result.get("configuration_error") == "missing_credentials"
