"""Current legacy MISP configuration visibility without jobs, exports or secret disclosure."""
import asyncio
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms
from extensions.business.cybersec.red_mesh.mixins.misp_export import _MispExportMixin


ENDPOINT = "get_misp_export_config_status"
DEFAULT = {"enabled": False, "auto_export": False, "misp_configured": False, "min_severity": "LOW"}
SECRET = "mock-only-misp-key-canary"
URL = "https://mock-only-misp-host.invalid"


def install_config_producer(fixture, config=None):
  """The unchanged real config producer, with all unrelated effects trapped at their boundaries."""
  owner = fixture.owner
  owner.CONFIG = {"MISP_EXPORT": deepcopy(config or {})}
  owner.config_data = {}
  owner.P = MagicMock()
  owner._get_misp_export_config = MagicMock(side_effect=lambda: _MispExportMixin._get_misp_export_config(owner))
  original_get = owner.chainstore_hget
  def read(hkey, key):
    assert hkey != owner.cfg_instance_id, "Forbidden job point-read"
    return original_get(hkey=hkey, key=key)
  owner.chainstore_hget = MagicMock(side_effect=read)
  for name in ("chainstore_hgetall", "chainstore_hset", "_get_job_from_cstore", "_get_job_state_repository",
               "_export_to_misp", "_build_misp_json"):
    setattr(owner, name, MagicMock(side_effect=AssertionError("Forbidden config-read effect: " + name)))
  owner.r1fs.get_json = MagicMock(side_effect=AssertionError("Forbidden artifact read"))


def test_missing_requester_cannot_read_configuration_or_invoke_the_producer():
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    result = getattr(fixture.Plugin, ENDPOINT)(fixture.owner)
    assert result == {"success": False, "error": "not_found", "status_code": 404}
    fixture.owner._get_misp_export_config.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_native_actor_only_config_read_preserves_defaults_and_no_store(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert actual == DEFAULT and calls == 1
    fixture.owner._get_misp_export_config.assert_called_once_with()
    assert not any(row[0] == "list" or row[1] == fixture.owner.cfg_instance_id for row in fixture.store.reads)


INVALID_PRODUCERS = (
  None, [], False, "private", {},
  *({key: value for key, value in DEFAULT.items() if key != field} for field in DEFAULT),
  *({**DEFAULT, field: value} for field in ("enabled", "auto_export", "misp_configured")
    for value in (None, 0, 1, "false", [], {})),
  *({**DEFAULT, "min_severity": value} for value in (None, False, 0, [], {}, "low", "UNKNOWN")),
  *({**DEFAULT, field: SECRET} for field in ("MISP_API_KEY", "MISP_URL", "error", "result", "extra")),
)


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("produced", INVALID_PRODUCERS)
def test_actual_native_rejects_invalid_or_extended_producer_payload_before_wrapping(read_native, response_format, produced):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    fixture.owner._get_misp_export_config.side_effect = lambda: deepcopy(produced)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503} and calls == 1
    assert SECRET not in str(result) and fixture.owner.P.mock_calls == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("role,app_role", (("admin", None), ("user", "pentester"), ("user", None)))
def test_actual_native_preserves_integration_view_for_every_current_legacy_role(read_native, response_format, role, app_role):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role=role)
    if app_role:
      fixture.store.data[("auth", "reader")]["metadata"]["appRole"] = app_role
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 200)
    assert (result["result"] if response_format == "WRAPPED" else result) == DEFAULT and calls == 1
    assert fixture.store.reads[0] == ("get", "auth", "reader")


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("enabled,auto_export,configured", (
  (False, False, False), (False, False, True), (False, True, False), (False, True, True),
  (True, False, False), (True, False, True), (True, True, False), (True, True, True),
))
@pytest.mark.parametrize("severity,expected", (
  ("CRITICAL", "CRITICAL"), ("HIGH", "HIGH"), ("MEDIUM", "MEDIUM"), ("LOW", "LOW"),
  ("INFO", "INFO"), (" info ", "INFO"), ("private-invalid", "LOW"),
))
def test_real_configuration_producer_preserves_independent_flags_and_never_exposes_credentials(
    read_native, response_format, enabled, auto_export, configured, severity, expected):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture, {"ENABLED": enabled, "AUTO_EXPORT": auto_export,
      "MISP_URL": URL, "MISP_API_KEY": SECRET if configured else "", "MIN_SEVERITY": severity})
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert actual == {"enabled": enabled, "auto_export": auto_export,
                      "misp_configured": configured, "min_severity": expected}
    assert calls == 1 and SECRET not in str(result) and URL not in str(result)
    fixture.owner.P.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (
  ("missing_actor", 404), ("missing_account", 404), ("inactive", 404), ("identity_store", 503),
  ("empty_memberships", 403), ("null_memberships", 404), ("malformed_memberships", 404),
  ("platform_membership", 403), ("configured_stage", 403), ("configured_enabled", 403),
  ("stored_stage", 403), ("stored_enabled", 403), ("rollout_store", 503),
  ("missing_rollout", 503), ("malformed_rollout", 503), ("namespace", 503),
))
def test_native_denials_precede_configuration_and_other_effects(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture, {"MISP_URL": URL, "MISP_API_KEY": SECRET})
    body = {"request_actor": fixture.actor}
    rollout_key = fixture.tenant_store._location("execution_rollout", (fixture.owner.cfg_instance_id,))
    if fault == "missing_actor":
      body = {}
    elif fault == "missing_account":
      body["request_actor"] = {"account_id": "missing"}
    elif fault == "inactive":
      fixture.store.account("reader", active=False)
    elif fault == "identity_store":
      fixture.store.fail_hkey = "auth"
    elif fault.endswith("memberships"):
      fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = {
        "empty_memberships": [], "null_memberships": None, "malformed_memberships": "private"}[fault]
    elif fault == "platform_membership":
      fixture.store.account("reader", role="admin", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    elif fault == "configured_stage":
      fixture.owner.cfg_tenant_execution_stage = "draining"
    elif fault == "configured_enabled":
      fixture.owner.cfg_tenant_execution_enabled = True
    elif fault.startswith("stored_"):
      fixture.tenant_store.put("execution_rollout", fixture.owner.cfg_instance_id,
        record={"stage": "draining" if fault == "stored_stage" else "compatibility", "enabled": fault == "stored_enabled"})
    elif fault == "rollout_store":
      fixture.store.fail_hkey = rollout_key[0]
    elif fault == "missing_rollout":
      fixture.store.data.pop(rollout_key)
    elif fault == "malformed_rollout":
      fixture.store.data[rollout_key] = {"stage": SECRET}
    elif fault == "namespace":
      fixture.owner.cfg_tenancy_namespace = None
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, body)), status)
    assert result == {"success": False, "error": {403: "forbidden", 404: "not_found", 503: "unavailable"}[status], "status_code": status}
    assert calls == 1 and fixture.store.writes == writes and SECRET not in str(result)
    fixture.owner._get_misp_export_config.assert_not_called()
    fixture.owner.P.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_configuration_exceptions_are_sanitized_without_logging_secrets(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    fixture.owner._get_misp_export_config.side_effect = RuntimeError(SECRET)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503} and calls == 1
    fixture.owner.P.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("missing", 404), ("inactive", 404), ("member", 403)))
def test_native_request_actor_claims_cannot_override_current_stored_authority(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    if fault == "inactive":
      fixture.store.account("reader", active=False)
    elif fault == "member":
      fixture.store.account("reader", memberships=[])
    claimed_actor = {"account_id": "missing" if fault == "missing" else "reader",
                     "role": "admin", "active": True, "tenant_memberships_present": False}
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": claimed_actor})), status)
    assert result["error"] == ("forbidden" if fault == "member" else "not_found") and calls == 1
    fixture.owner._get_misp_export_config.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_each_request_reauthorizes_after_account_revocation(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 200)
    fixture.store.account("reader", active=False)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 404)
    assert result == {"success": False, "error": "not_found", "status_code": 404} and calls == 1
    fixture.owner._get_misp_export_config.assert_called_once_with()


def test_valid_producer_payload_is_detached_before_publication():
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    payload = dict(DEFAULT)
    fixture.owner._get_misp_export_config.side_effect = lambda: payload
    result = getattr(fixture.Plugin, ENDPOINT)(fixture.owner, request_actor=fixture.actor)
    assert result == DEFAULT
    result["enabled"] = True
    assert payload == DEFAULT


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_deployment_metadata_is_separate_from_exact_producer_keys(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=False) as fixture:
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format, metadata={"server_node_addr": "fixture-node"})
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert all(actual[field] == value for field, value in DEFAULT.items()) and calls == 1
    if response_format == "WRAPPED":
      assert result["server_node_addr"] == "fixture-node"
    else:
      assert result == DEFAULT
