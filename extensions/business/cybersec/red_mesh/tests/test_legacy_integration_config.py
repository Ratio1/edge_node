"""Configuration-only legacy integration readiness through real builders and native transport.

The owner chose (2026-09-14, RM-026 I1a.3c.8) to omit unowned historical event IDs and
artifact CIDs from the global integration view while retaining safe configuration and
readiness status. These tests pin that the public path rebuilds from the six real
builders, never reads a stored record, and never publishes a history field -- while the
internal historical producer keeps working for the export policy.
"""
import asyncio
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from unittest.mock import patch

import pytest

from extensions.business.cybersec.red_mesh.services import integration_status as service
from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms


ENDPOINT = "get_integration_status"
SECRET = "mock-only-integration-credential"
INTEGRATION_IDS = {"event_export", "wazuh", "suricata", "stix", "opencti", "taxii"}
PUBLIC_KEYS = {
  "id", "label", "enabled", "configured", "required", "supports_test", "status",
  "destination_type", "destination_label", "redaction_mode", "configuration_error",
}
# Everything the owner decided must not appear in the global view.
HISTORY_KEYS = {
  "last_dry_run_at", "last_success_at", "last_failure_at", "last_error_class",
  "last_event_id", "last_artifact_cid", "first_failure_at", "current_failure_first_at",
  "failure_count", "consecutive_failure_count", "cooldown_until", "retry_after_seconds",
  "integration_status", "config", "redacted_host",
}


@contextmanager
def no_history_or_effects(fixture):
  """No stored history may be read, and nothing may be written, probed or emitted."""
  snapshot = deepcopy((fixture.store.data, fixture.store.jobs, fixture.store.writes, fixture.artifacts))
  del fixture.history_reads[:]
  with ExitStack() as stack:
    effects = [stack.enter_context(patch.object(target, name, create=True,
      side_effect=AssertionError(SECRET))) for target, name in (
        (service, "_load_status_record"), (service, "_merge_record"),
        (service, "_save_status_record"), (service, "build_test_event"),
        (service, "apply_integration_outcome_policy"),
        (fixture.owner, "chainstore_hset"), (fixture.owner, "_get_job_from_cstore"),
        (fixture.owner, "P"), (fixture.owner.r1fs, "add_json"), (fixture.owner.r1fs, "delete"))]
    yield
    for effect in effects:
      effect.assert_not_called()
    # The real store was never asked for the integrations hash at all.
    assert fixture.history_reads == []
    assert (fixture.store.data, fixture.store.jobs, fixture.store.writes, fixture.artifacts) == snapshot


def poison_history(fixture):
  """Serve unowned delivery history from the real store path, and record every read of it."""
  hkey = f"{fixture.owner.cfg_instance_id}:integrations"
  record = {
    "last_event_id": "unowned-event-id",
    "last_artifact_cid": "unowned-artifact-cid",
    "failure_count": 41,
    "consecutive_failure_count": 7,
    "cooldown_until": "2099-01-01T00:00:00Z",
    "last_error_class": "delivery_timeout",
    "integration_status": "cooling_down",
  }
  fixture.history_reads = []
  original = fixture.owner.chainstore_hget

  def get(*, hkey_name=hkey, **kwargs):
    if kwargs.get("hkey") == hkey_name:
      fixture.history_reads.append(kwargs.get("key"))
      return dict(record)
    return original(**kwargs)

  fixture.owner.chainstore_hget = get
  return record


def assert_public_shape(payload):
  assert set(payload) == {"schema_version", "generated_at", "integrations"}
  assert payload["schema_version"] == "1.0.0"
  assert isinstance(payload["generated_at"], str) and payload["generated_at"].endswith("Z")
  assert set(payload["integrations"]) == INTEGRATION_IDS
  for integration_id, item in payload["integrations"].items():
    assert set(item) == PUBLIC_KEYS, integration_id
    assert not (set(item) & HISTORY_KEYS), integration_id
    assert item["id"] == integration_id
    assert item["status"] in {"disabled", "not_configured", "ready"}
    assert item["supports_test"] is (integration_id in {"wazuh", "opencti", "taxii"})
    assert item["required"] is False or integration_id == "wazuh"
    for field in ("enabled", "configured", "required", "supports_test"):
      assert type(item[field]) is bool, (integration_id, field)
    if not item["enabled"]:
      assert item["status"] == "disabled"
    elif item["configured"]:
      assert item["status"] == "ready"
    else:
      assert item["status"] == "not_configured"
    assert item["configuration_error"] is None or item["configuration_error"] in {
      "missing_hmac_secret", "missing_syslog_host", "missing_http_url",
      "missing_token", "missing_credentials", "invalid_auth_config"}


def test_public_projection_omits_history_and_never_reads_a_stored_record():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    poison_history(fixture)
    with no_history_or_effects(fixture):
      payload = fixture.Plugin.get_integration_status(fixture.owner, request_actor=fixture.actor)
    assert_public_shape(payload)
    serialized = repr(payload)
    for leaked in ("unowned-event-id", "unowned-artifact-cid", "cooling_down", "delivery_timeout"):
      assert leaked not in serialized


@pytest.mark.parametrize("role", ("admin", "pentester", "user"))
def test_all_three_legacy_roles_are_admitted(role):
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    fixture.store.account("reader", role=role)
    payload = fixture.Plugin.get_integration_status(fixture.owner, request_actor=fixture.actor)
    assert_public_shape(payload)


def test_internal_historical_producer_is_unchanged():
  """The export policy still needs history; only the public view drops it."""
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    poison_history(fixture)
    internal = service.get_integration_status(fixture.owner)["integrations"]["wazuh"]
    assert HISTORY_KEYS <= set(internal)
    assert internal["last_event_id"] == "unowned-event-id"
    assert internal["last_artifact_cid"] == "unowned-artifact-cid"


def test_enabled_signing_without_secret_reports_configuration_error_not_history():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG = {"EVENT_EXPORT": {"ENABLED": True, "SIGN_PAYLOADS": True,
                                             "HMAC_SECRET_ENV": "REDMESH_ABSENT_SECRET_ENV"}}
    fixture.owner.config_data = {}
    payload = fixture.Plugin.get_integration_status(fixture.owner, request_actor=fixture.actor)
    assert_public_shape(payload)
    item = payload["integrations"]["event_export"]
    assert item["enabled"] is True and item["configured"] is False
    assert item["status"] == "not_configured"
    assert item["configuration_error"] == "missing_hmac_secret"


def test_unknown_builder_error_class_fails_closed_rather_than_publishing_it():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    original = service._STATUS_BUILDERS["stix"]

    def leaking(owner):
      base = original(owner)
      base["last_error_class"] = "delivery_timeout"
      return base

    with patch.dict(service._STATUS_BUILDERS, {"stix": leaking}):
      result = fixture.Plugin.get_integration_status(fixture.owner, request_actor=fixture.actor)
    assert result == {"success": False, "error": "unavailable", "status_code": 503}


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("read_native", (None, "/workspace"), indirect=True)
def test_actual_native_readiness_is_configuration_only(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    poison_history(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    with no_history_or_effects(fixture):
      result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert_public_shape(actual)
    assert calls == 1 and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("null_memberships", 404),
  ("memberships", 403), ("rollout", 403), ("configured", 403),
  ("rollout_missing", 503), ("identity_store", 503),
))
def test_native_admission_denies_before_any_configuration_evaluation(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    poison_history(fixture)
    body = {"request_actor": fixture.actor}
    account = fixture.store.data[("auth", "reader")]
    if fault == "actor": body.pop("request_actor")
    elif fault == "deleted": fixture.store.data.pop(("auth", "reader"))
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault in ("memberships", "null_memberships"):
      account["metadata"]["tenant_memberships"] = [] if fault == "memberships" else None
    elif fault == "rollout":
      fixture.tenant_store.put("execution_rollout", fixture.owner.cfg_instance_id,
        record={"stage": "draining", "enabled": False})
    elif fault == "configured": fixture.owner.cfg_tenant_execution_enabled = True
    elif fault == "rollout_missing":
      fixture.store.data.pop(fixture.tenant_store._location("execution_rollout", (fixture.owner.cfg_instance_id,)))
    elif fault == "identity_store": fixture.store.fail_hkey = "auth"
    # Patch the plugin module's own binding: pentester_api_01 imports the function into
    # its namespace at import time, so patching the service module would be vacuous.
    from extensions.business.cybersec.red_mesh import pentester_api_01
    with no_history_or_effects(fixture), patch.object(pentester_api_01, "get_public_integration_config",
        side_effect=AssertionError(SECRET)) as projection:
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, body)), status)
      assert result == {"success": False, "error": {403: "forbidden", 404: "not_found",
                                                    503: "unavailable"}[status], "status_code": status}
      assert calls == 1 and fixture.artifact_reads == []
      projection.assert_not_called()


def test_repeated_calls_re_admit_against_current_stored_facts():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG, fixture.owner.config_data = {}, {}
    assert_public_shape(fixture.Plugin.get_integration_status(fixture.owner, request_actor=fixture.actor))
    fixture.store.account("reader", active=False)
    assert fixture.Plugin.get_integration_status(fixture.owner, request_actor=fixture.actor) == {
      "success": False, "error": "not_found", "status_code": 404}
