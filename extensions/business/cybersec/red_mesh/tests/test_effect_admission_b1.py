"""RM-026 I1b B1: admission, effect state and public projection for persisted-artifact effects.

These four endpoints previously accepted a job id with no requester and read the job through the
unscoped global lookup. Two of them also wrote integration status records on their denial paths,
so probing job ids polluted failure counters that feed cooldown policy.
"""
from unittest.mock import patch

import pytest

from extensions.business.cybersec.red_mesh.services import (
  misp_export, opencti_export, stix_export, taxii_export)
from extensions.business.cybersec.red_mesh.tenancy.effects import EffectState
from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import read_native  # noqa: F401  (pytest fixture)

JOB_EFFECTS = ("dry_run_opencti_export", "dry_run_taxii_export", "export_stix_bundle")
SECRET = "mock-only-b1-canary"


def call(fixture, name, **kwargs):
  return getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=fixture.actor, **kwargs)


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_effects_no_longer_use_the_unscoped_global_job_lookup(name):
  with read_endpoint_fixture(bound=False) as fixture, \
       patch.object(opencti_export, "_config_error", return_value=None), \
       patch.object(taxii_export, "_config_error", return_value=None):
    # Without this the integrations resolve to `disabled` and _prepare_* returns before the job
    # read, so the canary would pass without exercising the scoping it names.
    # create=True because the fixture owner does not define it at all -- which is itself the
    # evidence: the checked path never reaches for it.
    with patch.object(fixture.owner, "_get_job_from_cstore", create=True,
                      side_effect=AssertionError(SECRET)) as unscoped:
      call(fixture, name)
    unscoped.assert_not_called()


@pytest.mark.parametrize("name", JOB_EFFECTS)
@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_are_effect_free_and_write_no_status_record(name, fault, status):
  """The probe-amplification defect: denial paths must not touch integration status."""
  with read_endpoint_fixture(bound=False) as fixture:
    account = fixture.store.data[("auth", "reader")]
    kwargs = {}
    if fault == "actor": kwargs["request_actor"] = None
    elif fault == "deleted": fixture.store.data.pop(("auth", "reader"))
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault == "user": fixture.store.account("reader", role="user")
    elif fault == "memberships": account["metadata"]["tenant_memberships"] = []
    elif fault == "rollout":
      fixture.tenant_store.put("execution_rollout", fixture.owner.cfg_instance_id,
        record={"stage": "draining", "enabled": False})
    elif fault == "identity_store": fixture.store.fail_hkey = "auth"

    with patch.object(opencti_export, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as opencti_record, \
         patch.object(taxii_export, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as taxii_record, \
         patch.object(stix_export, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as stix_record:
      if fault == "actor":
        result = getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=None)
      else:
        result = call(fixture, name)
      assert result["status_code"] == status
      assert result["success"] is False
      for recorder in (opencti_record, taxii_record, stix_record):
        recorder.assert_not_called()


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_a_denied_caller_never_reaches_the_job(name):
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    result = call(fixture, name)
    assert result == {"success": False, "error": "forbidden", "status_code": 403}
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_a_tenant_bound_actor_cannot_reach_a_legacy_effect(name):
  with read_endpoint_fixture(bound=True) as fixture:
    result = call(fixture, name)
    assert result["success"] is False and result["status_code"] in (403, 404)


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_disabled_integration_reports_status_without_the_framework_error_key(name):
  """A dict carrying `error` is mapped to HTTP 503 by the framework, so it must not carry one."""
  with read_endpoint_fixture(bound=False) as fixture:
    result = call(fixture, name)
    assert "error" not in result or result.get("success") is False


def test_a_landed_persist_is_never_reported_as_nothing_happened():
  """Contract 6: an exception after the bundle lands must not read as `unavailable`."""
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG = {"OPENCTI_EXPORT": {"ENABLED": True, "URL": "https://opencti.test",
                                               "TOKEN_ENV": "RM_TEST_OPENCTI_TOKEN"}}
    fixture.owner.config_data = {}

    def persist_then_die(owner, bundle):
      return "artifact-cid"

    with patch.object(opencti_export, "_persist_bundle", persist_then_die), \
         patch.object(opencti_export, "_write_job_record", side_effect=RuntimeError(SECRET)), \
         patch.object(opencti_export, "_prepare_opencti_export",
                      return_value=({"PUSH_MODE": "dry_run", "URL": "https://opencti.test"},
                                    dict(fixture.job),
                                    {"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
                                     "object_count": 0, "finding_count": 0,
                                     "observed_data_count": 0})):
      result = fixture.Plugin.dry_run_opencti_export(fixture.owner, "job-1",
                                                     request_actor=fixture.actor)
    assert result["error"] == "effect_incomplete"
    assert result["effect_state"] == EffectState.PERSISTED.value
    assert result["status_code"] == 500
    assert SECRET not in repr(result)


def test_test_event_export_requires_the_export_authority():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    result = fixture.Plugin.test_event_export(fixture.owner, request_actor=fixture.actor)
    assert result == {"success": False, "error": "forbidden", "status_code": 403}


def test_test_event_export_admits_a_legacy_pentester():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    fixture.store.data[("auth", "reader")]["metadata"]["appRole"] = "pentester"
    result = fixture.Plugin.test_event_export(fixture.owner, request_actor=fixture.actor)
    assert not (result.get("success") is False and result.get("status_code") == 403)


def test_a_delivered_soc_event_is_never_reported_as_nothing_happened():
  """persist=False still emits and mutates the job document: the ledger must know."""
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(stix_export, "build_stix_bundle",
                      return_value={"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
                                    "object_count": 0, "finding_count": 0,
                                    "observed_data_count": 0}), \
         patch.object(stix_export, "emit_export_status_event",
                      return_value={"status": "sent", "integration_id": "wazuh"}), \
         patch.object(stix_export, "_write_job_record", side_effect=RuntimeError(SECRET)):
      result = fixture.Plugin.export_stix_bundle(fixture.owner, "job-1", persist=False,
                                                 request_actor=fixture.actor)
    assert result["error"] == "effect_incomplete"
    assert result["effect_state"] == EffectState.DELIVERED.value
    assert result["status_code"] == 500


def test_an_exception_string_from_a_probe_never_reaches_the_caller():
  """public_effect_result is a whitelist: probe detail carries prose, a host and an env name."""
  from extensions.business.cybersec.red_mesh.tenancy.effects import public_effect_result
  leaked = {"status": "error", "integration_id": "opencti",
            "detail": "basic auth password is not configured (env 'RM_OPENCTI_PASSWORD' unset)",
            "redacted_host": "opencti.internal", "user_email": "svc@example.test"}
  projected = public_effect_result(leaked)
  serialized = repr(projected)
  for secret in ("RM_OPENCTI_PASSWORD", "opencti.internal", "svc@example.test", "basic auth"):
    assert secret not in serialized
  assert projected["status"] == "error"


def test_an_untypeable_outcome_is_not_published_as_success_without_a_reason():
  from extensions.business.cybersec.red_mesh.tenancy.effects import public_effect_result
  # artifact_write_failed became a publishable delivery code in B2, so it now carries a reason
  # rather than a null. The invariant under test is that an outcome never publishes as success
  # without one.
  projected = public_effect_result({"status": "error", "error": "artifact_write_failed",
                                    "job_id": "job-1"})
  assert projected["status"] == "error"
  assert projected["configuration_error"] == "artifact_write_failed"
  untypable = public_effect_result({"status": "error", "error": "something_unmapped",
                                    "job_id": "job-1"})
  assert untypable["status"] == "error" and untypable["configuration_error"] is None


def test_revalidation_denies_before_the_effect_when_the_account_is_deactivated():
  """Contract 4: the account is deactivated between admission and the irreversible step."""
  with read_endpoint_fixture(bound=False) as fixture:
    def deactivate_then_persist(owner, bundle):
      fixture.store.account("reader", active=False)
      return "artifact-cid"

    with patch.object(opencti_export, "_config_error", return_value=None), \
         patch.object(opencti_export, "build_stix_bundle",
                      return_value={"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
                                    "object_count": 0, "finding_count": 0,
                                    "observed_data_count": 0}), \
         patch.object(opencti_export, "_persist_bundle", deactivate_then_persist):
      first = fixture.Plugin.dry_run_opencti_export(fixture.owner, "job-1",
                                                    request_actor=fixture.actor)
    # The checkpoint runs before the persist, so a later deactivation does not retroactively
    # deny; what matters is that a deactivation *before* the checkpoint does.
    assert isinstance(first, dict)
    with read_endpoint_fixture(bound=False) as fresh:
      fresh.store.account("reader", active=False)
      denied = fresh.Plugin.dry_run_opencti_export(fresh.owner, "job-1",
                                                   request_actor=fresh.actor)
      assert denied == {"success": False, "error": "not_found", "status_code": 404}


def test_a_tenant_scoped_effect_is_refused_rather_than_handed_a_raw_snapshot():
  """An operation outside _TENANT_EFFECT_OPERATIONS is refused for a tenant caller before any
  snapshot is read. This used the seam's default operation (reports:export) as the stand-in; the
  RM-026 MVP admitted that one for stop_monitoring, so the stand-in is now reports:view."""
  with read_endpoint_fixture(bound=True) as fixture:
    result = fixture.Plugin._effect_operation(fixture.owner, fixture.actor, "tenant-1",
                                              lambda job, mode, ledger: {"status": "ok"},
                                              job_id="job-1", operation="reports:view")
    assert result == {"success": False, "error": "forbidden", "status_code": 403}


def test_a_skipped_emission_is_not_claimed_as_a_delivery():
  """emit_export_status_event returns {"status": "skipped"} when SOC export is disabled --
  the common configuration. Recording DELIVERED there would claim a packet that never left."""
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(stix_export, "build_stix_bundle",
                      return_value={"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
                                    "object_count": 0, "finding_count": 0,
                                    "observed_data_count": 0}), \
         patch.object(stix_export, "emit_export_status_event",
                      return_value={"status": "skipped", "integration_id": None,
                                    "error": "missing_hmac_secret"}), \
         patch.object(stix_export, "_write_job_record", side_effect=RuntimeError(SECRET)):
      result = fixture.Plugin.export_stix_bundle(fixture.owner, "job-1", persist=False,
                                                 request_actor=fixture.actor)
    assert result["effect_state"] == EffectState.PERSISTED.value
    assert result["effect_state"] != EffectState.DELIVERED.value


@pytest.mark.parametrize("name,module", (
  ("dry_run_opencti_export", "opencti"), ("dry_run_taxii_export", "taxii")))
def test_a_dry_run_that_mutates_the_job_record_never_reports_nothing_happened(name, module):
  """The round-1 fix landed only in export_stix_bundle: both dry runs wrote the job record with
  the ledger still NONE whenever _persist_bundle returned falsy."""
  service = opencti_export if module == "opencti" else taxii_export
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(service, "_config_error", return_value=None), \
         patch.object(service, "build_stix_bundle",
                      return_value={"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
                                    "object_count": 0, "finding_count": 0,
                                    "observed_data_count": 0}), \
         patch.object(service, "_persist_bundle", return_value=None), \
         patch.object(service, "_write_job_record", side_effect=RuntimeError(SECRET)):
      result = getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=fixture.actor)
    assert result["error"] == "effect_incomplete"
    assert result["effect_state"] == EffectState.PERSISTED.value


def test_revalidation_between_admission_and_the_effect_denies_the_effect():
  """Contract 4, discriminating: the account is deactivated AFTER admission and BEFORE the
  irreversible step. Without checkpoint() the export would proceed."""
  with read_endpoint_fixture(bound=False) as fixture:
    landed = []

    def build_then_revoke(owner, job_id, pass_nr=None, checked_job=None):
      # Runs after admission, before the persist checkpoint.
      fixture.store.account("reader", active=False)
      return {"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
              "object_count": 0, "finding_count": 0, "observed_data_count": 0}

    with patch.object(opencti_export, "_config_error", return_value=None), \
         patch.object(opencti_export, "build_stix_bundle", build_then_revoke), \
         patch.object(opencti_export, "_persist_bundle",
                      side_effect=lambda *a, **k: landed.append("persisted") or "cid"):
      result = fixture.Plugin.dry_run_opencti_export(fixture.owner, "job-1",
                                                     request_actor=fixture.actor)
    assert landed == [], "the effect ran after the requester was revoked"
    assert result["success"] is False and result["status_code"] in (404, 500)


def test_every_configuration_code_these_services_emit_is_publishable():
  """Drift guard: the whitelist is a hand-maintained copy, so pin it against the producers.

  Round 2 found it held none of the codes opencti/taxii actually emit, so every real
  misconfiguration was published as an untyped error with configuration_error null.
  """
  import re
  from extensions.business.cybersec.red_mesh.tenancy.effects import _PUBLIC_CONFIGURATION_ERRORS
  emitted = set()
  for module in (opencti_export, taxii_export):
    source = open(module.__file__).read()
    body = source[source.index("def _config_error("):]
    body = body[:body.index("\ndef ", 1)]
    emitted.update(re.findall(r'return "([a-z_]+)"', body))
  # Delivery producers too, not just _config_error. The security review found the whitelist and the
  # producers already out of sync: connection faults returned an exception class name that nothing
  # could publish, so every such failure showed the panels' generic fallback.
  for module in (opencti_export, taxii_export, misp_export):
    source = open(module.__file__).read()
    emitted.update(re.findall(r'"error": "([a-z_]+)"', source))
  # "disabled" is not a configuration error: it short-circuits to a bare {"status": "disabled"}.
  # Not configuration errors: "disabled" short-circuits to a bare status, and the denial codes are
  # mapped to HTTP statuses by _EFFECT_DENIALS rather than published as a reason.
  emitted -= {"disabled", "not_configured", "job_not_found", "unsupported_job_type"}
  missing = emitted - _PUBLIC_CONFIGURATION_ERRORS
  assert not missing, f"config codes these services emit but cannot publish: {sorted(missing)}"


def test_a_typed_incomplete_effect_survives_the_transport_guard():
  """The guard collapses any status outside its map to 503 'unavailable'. A partially landed
  effect must be the exception, or the whole mechanism is inert over real HTTP."""
  from extensions.business.cybersec.red_mesh.tenancy import http_runtime
  import json
  plain = json.loads(http_runtime._read_error_response(500).body)
  assert plain == {"success": False, "error": "unavailable", "status_code": 503}
  for state in ("persisted", "delivered"):
    typed = json.loads(http_runtime._read_error_response(
      500, code="effect_incomplete", effect_state=state).body)
    assert typed == {"success": False, "error": "effect_incomplete",
                     "effect_state": state, "status_code": 500}
  # An unrecognised state must not open a hole.
  spoofed = json.loads(http_runtime._read_error_response(
    500, code="effect_incomplete", effect_state="anything").body)
  assert spoofed["status_code"] == 503


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_an_incomplete_effect_survives_real_http_in_both_response_formats(read_native, response_format):
  """The control must be live in both deployment formats.

  Round 2 found the typed 500 collapsed to 503 because the slice opted its paths into the read
  guard. Round 3 found the fix worked only in WRAPPED: RAW unwraps the dict, so the framework
  reduces the detail to the bare error string and destroys the state. Both rounds were invisible to
  tests that call plugin methods directly, which is why this one goes over the wire.
  """
  import asyncio
  from .test_tenant_read_native import assert_json_response, install, request, scheduler_comms
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    with patch.object(stix_export, "build_stix_bundle",
                      return_value={"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
                                    "object_count": 0, "finding_count": 0,
                                    "observed_data_count": 0}), \
         patch.object(stix_export, "emit_export_status_event",
                      return_value={"status": "sent", "integration_id": "wazuh"}), \
         patch.object(stix_export, "_write_job_record", side_effect=RuntimeError(SECRET)):
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, "export_stix_bundle",
        {"job_id": "job-1", "persist": False, "request_actor": fixture.actor})), 500)
    assert calls == 1
    assert result["error"] == "effect_incomplete", (
      "a landed effect was reported as something else over %s" % response_format)
    assert result["status_code"] == 500
    # RAW cannot carry the state through the framework; the safety-critical half must still survive.
    assert result["effect_state"] in ("delivered", "unknown")
    assert SECRET not in repr(result)


def test_the_fields_each_ui_consumer_reads_survive_the_projection():
  """Pin the whitelist against its consumers.

  Dropping `stix_bundle` broke the STIX Download button and nothing failed. This asserts the
  contract directly so the field-drop regression cannot recur silently.
  """
  from extensions.business.cybersec.red_mesh.tenancy.effects import public_effect_result
  stix = public_effect_result({
    "status": "ok", "stix_bundle": {"type": "bundle"}, "bundle_id": "b1", "artifact_cid": "cid",
    "last_exported_at": "2026-09-14T00:00:00Z", "pass_nr": 1, "object_count": 3,
    "finding_count": 2, "observed_data_count": 1})
  # StixExport.tsx reads exactly these.
  for field in ("status", "stix_bundle", "bundle_id", "artifact_cid", "last_exported_at",
                "pass_nr", "object_count", "finding_count"):
    assert field in stix, f"StixExport.tsx reads {field} and the projection drops it"
  assert stix["stix_bundle"] == {"type": "bundle"}


def test_a_disabled_delivery_is_not_recorded_as_sent():
  """deliver_redmesh_event returns "disabled", never "skipped": gating on the wrong sentinel
  recorded a delivery when nothing left the node."""
  from extensions.business.cybersec.red_mesh.services import integration_status as service
  from extensions.business.cybersec.red_mesh.tenancy.effects import EffectLedger
  ledger = EffectLedger()
  with read_endpoint_fixture(bound=False) as fixture:
    with patch("extensions.business.cybersec.red_mesh.services.log_export.deliver_redmesh_event",
               return_value={"status": "disabled", "error": "disabled"}):
      service.test_event_export(fixture.owner, integration_id="wazuh", ledger=ledger)
  assert ledger.state is EffectState.NONE, "a disabled integration was recorded as delivered"
