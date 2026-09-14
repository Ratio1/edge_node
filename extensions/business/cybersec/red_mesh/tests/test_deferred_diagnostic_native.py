"""Unscoped public diagnostics deny without consulting domain or provider state."""
import asyncio
from unittest.mock import MagicMock

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms


ENDPOINT = "llm_health"
UNAVAILABLE = {"success": False, "error": "unavailable", "status_code": 503}
SECRET = "mock-only-health-token-canary"
HOST = "mock-only-health-provider.invalid"


class _ForbiddenDiagnosticDomain:
  """Only native response framing may access owner state; every domain access is a trap."""
  def __init__(self):
    self.accesses = []

  def __getattr__(self, name):
    self.accesses.append(name)
    raise AssertionError(f"Forbidden diagnostic access {name}: {HOST} {SECRET}")


def test_public_health_denies_without_invoking_internal_diagnostics():
  with read_endpoint_fixture() as fixture:
    fixture.owner._get_llm_health_status = MagicMock(return_value={"host": HOST, "error": SECRET})
    result = fixture.Plugin.llm_health(fixture.owner)
    assert result == UNAVAILABLE
    fixture.owner._get_llm_health_status.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_native_health_returns_sanitized_unavailable_and_no_store(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture() as fixture:
    fixture.owner._get_llm_health_status = MagicMock(return_value={"host": HOST, "error": SECRET})
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {})), 503)
    assert result == UNAVAILABLE and calls == 1
    fixture.owner._get_llm_health_status.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("read_native", (None, "/workspace"), indirect=True)
@pytest.mark.parametrize("body", (
  {}, {"request_actor": {}}, {"request_actor": {"account_id": "reader"}},
  {"request_actor": {"account_id": "missing"}},
  {"request_actor": {"account_id": "inactive", "role": "admin"}},
  {"request_actor": {"account_id": "tenant-member", "tenant_memberships": []}},
  {"request_actor": {"account_id": None, "untrusted": {"role": "super_tenant_admin"}}},
))
def test_native_accepted_actors_never_resolve_domain_state_or_grant_health(
    read_native, response_format, body, capsys):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture() as fixture:
    # Real dispatcher/on_response retain their normal framing and status logging.
    # Missing domain attributes trap health/config/provider, account/rollout/job reads,
    # audit, storage and diagnostic logging without suppressing transport behavior.
    fixture.owner = _ForbiddenDiagnosticDomain()
    module.eng = scheduler_comms(fixture, response_format, {"server_node_addr": "native-metadata"})
    writes = list(fixture.store.writes)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, body)), 503)
    assert result == UNAVAILABLE and calls == 1
    assert fixture.owner.accesses == []
    assert fixture.store.reads == [] and fixture.store.writes == writes
    assert fixture.artifact_reads == []
    captured = capsys.readouterr()
    output = str(result) + captured.out + captured.err
    assert SECRET not in output and HOST not in output
    assert "[plugin-status] endpoint=llm_health" in captured.out


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("read_native", (None, "/workspace"), indirect=True)
def test_native_invalid_health_transport_is_no_store_without_dispatch_or_redirect(
    read_native, response_format, capsys):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture() as fixture:
    fixture.owner = _ForbiddenDiagnosticDomain()
    module.eng = scheduler_comms(fixture, response_format)

    async def checks():
      invalid_bodies = [None, [], True, 1, "private", {"request_actor": None}]
      invalid_bodies.extend({"request_actor": value} for value in ([], "private", 1, False))
      invalid_bodies.extend({key: "private"} for key in (
        "actor", "tenant_id", "tenantId", "asset_id", "assetId", "job_id", "profile_id",
        "execution_binding", "executionBinding", "extra"))
      for body in invalid_bodies:
        result, calls = assert_json_response(await request(module, ENDPOINT, body), 400)
        assert result == {"success": False, "error": "invalid_request", "status_code": 400}
        assert calls == 0
      for raw in (b'', b'{', b'\xff', b'{"request_actor":{},"request_actor":{}}',
                  b'{"request_actor":{"account_id":"a","account_id":"b"}}',
                  b'{"request_actor":{"value":NaN}}'):
        result, calls = assert_json_response(await request(module, ENDPOINT, raw=raw), 400)
        assert result == {"success": False, "error": "invalid_request", "status_code": 400}
        assert calls == 0
      for query in (b"request_actor=private", b"tenant_id=private", b"job_id=private", b"extra=private"):
        result, calls = assert_json_response(await request(module, ENDPOINT, {}, query=query), 400)
        assert result["error"] == "invalid_request" and calls == 0
      for method in ("GET", "PUT", "DELETE", "HEAD", "OPTIONS"):
        result, calls = assert_json_response(await request(module, ENDPOINT, {}, method=method), 405)
        assert result == {"success": False, "error": "method_not_allowed", "status_code": 405}
        assert calls == 0
      result, calls = assert_json_response(await request(module, ENDPOINT, {}, suffix="/"), 400)
      assert result["error"] == "invalid_request" and calls == 0

    asyncio.run(checks())
    assert module.eng.calls == [] and fixture.owner.accesses == []
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err and HOST not in captured.out + captured.err


def test_public_denial_payload_is_not_shared_between_calls():
  with read_endpoint_fixture() as fixture:
    owner = _ForbiddenDiagnosticDomain()
    result = fixture.Plugin.llm_health(owner, request_actor={"account_id": "reader"})
    result["error"] = "changed by caller"
    assert fixture.Plugin.llm_health(owner) == UNAVAILABLE
    assert owner.accesses == []
