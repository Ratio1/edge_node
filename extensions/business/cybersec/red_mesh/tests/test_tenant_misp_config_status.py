"""Tenant MISP configuration visibility without jobs, exports or secret disclosure (RM-084 P1:
the tenant is required; there is no unscoped half)."""
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
  owner._get_misp_export_config = MagicMock(
    side_effect=lambda tenant_id=None: _MispExportMixin._get_misp_export_config(owner, tenant_id))
  original_get = owner.chainstore_hget
  def read(hkey, key):
    assert hkey != owner.cfg_instance_id, "Forbidden job point-read"
    return original_get(hkey=hkey, key=key)
  owner.chainstore_hget = MagicMock(side_effect=read)
  # _export_to_misp was deleted in RM-026 I1b B2; the canary now names only live attributes.
  for name in ("chainstore_hgetall", "chainstore_hset", "_get_job_from_cstore", "_get_job_state_repository",
               "_build_misp_json"):
    setattr(owner, name, MagicMock(side_effect=AssertionError("Forbidden config-read effect: " + name)))
  owner.r1fs.get_json = MagicMock(side_effect=AssertionError("Forbidden artifact read"))


def test_missing_requester_cannot_read_configuration_or_invoke_the_producer():
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    result = getattr(fixture.Plugin, ENDPOINT)(fixture.owner, tenant_id=fixture.tenant_id)
    assert result == {"success": False, "error": "not_found", "status_code": 404}
    fixture.owner._get_misp_export_config.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_native_tenant_config_read_preserves_defaults_and_no_store(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert actual == DEFAULT and calls == 1
    fixture.owner._get_misp_export_config.assert_called_once_with(fixture.tenant_id)
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
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    fixture.owner._get_misp_export_config.side_effect = lambda tenant_id=None: deepcopy(produced)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503} and calls == 1
    assert SECRET not in str(result) and fixture.owner.P.mock_calls == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("role", ("tenant_admin", "tenant_pentester", "super_tenant_admin"))
def test_actual_native_preserves_integration_view_for_every_export_role(read_native, response_format, role):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = [
      {"role": role, "tenant_id": None if role == "super_tenant_admin" else fixture.tenant_id}]
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
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
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture, {"ENABLED": enabled, "AUTO_EXPORT": auto_export,
      "MISP_URL": URL, "MISP_API_KEY": SECRET if configured else "", "MIN_SEVERITY": severity})
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert actual == {"enabled": enabled, "auto_export": auto_export,
                      "misp_configured": configured, "min_severity": expected}
    assert calls == 1 and SECRET not in str(result) and URL not in str(result)
    fixture.owner.P.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (
  ("missing_actor", 404), ("missing_account", 404), ("inactive", 404), ("identity_store", 503),
  ("empty_memberships", 404), ("null_memberships", 404), ("malformed_memberships", 404),
  ("tenant_user", 403), ("other_tenant", 404), ("missing_tenant", 400), ("blank_tenant", 400),
))
def test_native_denials_precede_configuration_and_other_effects(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture, {"MISP_URL": URL, "MISP_API_KEY": SECRET})
    body = {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
    if fault == "missing_actor":
      body.pop("request_actor")
    elif fault == "missing_account":
      body["request_actor"] = {"account_id": "missing"}
    elif fault == "inactive":
      fixture.store.account("reader", active=False)
    elif fault == "identity_store":
      fixture.store.fail_hkey = "auth"
    elif fault.endswith("memberships"):
      fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = {
        "empty_memberships": [], "null_memberships": None, "malformed_memberships": "private"}[fault]
    elif fault == "tenant_user":
      fixture.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = [
        {"role": "tenant_user", "tenant_id": fixture.tenant_id}]
    elif fault == "other_tenant":
      body["tenant_id"] = "tn_00000000-0000-4000-8000-000000000000"
    elif fault == "missing_tenant":
      body.pop("tenant_id")
    elif fault == "blank_tenant":
      body["tenant_id"] = " "
    writes = list(fixture.store.writes)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, body)), status)
    assert result == {"success": False, "error": {400: "invalid_request", 403: "forbidden", 404: "not_found",
                                                  503: "unavailable"}[status], "status_code": status}
    # A blank selector never reaches the plugin: the strict transport refuses it first.
    assert calls == (0 if fault == "blank_tenant" else 1)
    assert fixture.store.writes == writes and SECRET not in str(result)
    fixture.owner._get_misp_export_config.assert_not_called()
    fixture.owner.P.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_configuration_exceptions_are_sanitized_without_logging_secrets(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    fixture.owner._get_misp_export_config.side_effect = RuntimeError(SECRET)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 503)
    assert result == {"success": False, "error": "unavailable", "status_code": 503} and calls == 1
    fixture.owner.P.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (("missing", 404), ("inactive", 404), ("member", 404)))
def test_native_request_actor_claims_cannot_override_current_stored_authority(read_native, response_format, fault, status):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    if fault == "inactive":
      fixture.store.account("reader", active=False)
    elif fault == "member":
      fixture.store.account("reader", memberships=[])
    claimed_actor = {"account_id": "missing" if fault == "missing" else "reader",
                     "role": "admin", "active": True,
                     "tenant_memberships": [{"role": "super_tenant_admin", "tenant_id": None}]}
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT,
      {"request_actor": claimed_actor, "tenant_id": fixture.tenant_id})), status)
    assert result["error"] == "not_found" and calls == 1
    fixture.owner._get_misp_export_config.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_each_request_reauthorizes_after_account_revocation(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
    fixture.store.account("reader", active=False)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 404)
    assert result == {"success": False, "error": "not_found", "status_code": 404} and calls == 1
    fixture.owner._get_misp_export_config.assert_called_once_with(fixture.tenant_id)


def test_valid_producer_payload_is_detached_before_publication():
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    payload = dict(DEFAULT)
    fixture.owner._get_misp_export_config.side_effect = lambda tenant_id=None: payload
    result = getattr(fixture.Plugin, ENDPOINT)(fixture.owner, request_actor=fixture.actor,
                                               tenant_id=fixture.tenant_id)
    assert result == DEFAULT
    result["enabled"] = True
    assert payload == DEFAULT


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_deployment_metadata_is_separate_from_exact_producer_keys(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_config_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format, metadata={"server_node_addr": "fixture-node"})
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {"request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert all(actual[field] == value for field, value in DEFAULT.items()) and calls == 1
    if response_format == "WRAPPED":
      assert result["server_node_addr"] == "fixture-node"
    else:
      assert result == DEFAULT
