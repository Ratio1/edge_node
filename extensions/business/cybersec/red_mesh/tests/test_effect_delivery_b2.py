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
