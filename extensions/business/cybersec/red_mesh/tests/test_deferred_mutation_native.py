"""Public triage stays unavailable while its internal persistence service is retained."""
import asyncio
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from unittest.mock import patch

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms


ENDPOINT = "update_finding_triage"
UNAVAILABLE = {"success": False, "error": "unavailable", "status_code": 503}
SECRET = "mock-only-triage-credential-canary"
HOST = "mock-only-triage-soc.invalid"


class _ForbiddenMutationDomain:
  """Native framing sets cfg_response_format; no endpoint/domain attribute may be read."""
  def __init__(self):
    self.accesses = []

  def __getattr__(self, name):
    self.accesses.append(name)
    raise AssertionError(f"Forbidden mutation access {name}: {SECRET} {HOST}")


@contextmanager
def forbidden_effects(fixture):
  from extensions.business.cybersec.red_mesh.services import triage, rulebook_assessment, event_hooks, log_export
  original_owner = fixture.owner

  def snapshot():
    return deepcopy((fixture.store.data, fixture.store.jobs, fixture.store.reads, fixture.store.writes,
      fixture.artifacts, fixture.artifact_reads, list(original_owner._audit_log),
      original_owner.scan_jobs, original_owner.model_test_jobs))

  before = snapshot()
  fixture.owner = _ForbiddenMutationDomain()
  targets = (
    (fixture.Plugin, "_execution_service"), (fixture.Plugin, "_resolve_launch_actor"),
    (triage, "update_finding_triage"), (triage, "_update_finding_triage_locked"),
    (triage, "_job_repo"), (triage, "_artifact_repo"), (triage, "_write_job_record"),
    (triage, "emit_finding_event"), (rulebook_assessment, "_submission_lock"),
    (rulebook_assessment, "list_rulebook_profiles"), (event_hooks, "emit_finding_event"),
    (log_export, "deliver_redmesh_event"), (log_export, "deliver_wazuh_event"),
    (log_export, "_send_http_json"), (log_export, "_send_syslog_json"),
  )
  with ExitStack() as stack:
    effects = [stack.enter_context(patch.object(target, name,
      side_effect=AssertionError(f"Forbidden effect {name}: {SECRET} {HOST}"))) for target, name in targets]
    yield
    # A swallowed exception can also produce503: counters, not status alone, prove containment.
    for effect in effects:
      effect.assert_not_called()
    assert fixture.owner.accesses == []
    assert snapshot() == before


def test_public_triage_denies_without_mutation_input_or_domain_access():
  with read_endpoint_fixture() as fixture:
    with forbidden_effects(fixture):
      assert fixture.Plugin.update_finding_triage(fixture.owner) == UNAVAILABLE


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_native_triage_denial_is_sanitized_and_no_store(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture() as fixture:
    with forbidden_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, {})), 503)
      assert result == UNAVAILABLE and calls == 1


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("read_native", (None, "/workspace"), indirect=True)
@pytest.mark.parametrize("bound", (False, True))
def test_native_accepted_actors_grant_nothing_and_make_no_domain_effects(
    read_native, response_format, bound, capsys):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=bound) as fixture:
    with forbidden_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format, {"server_node_addr": "native-metadata"})

      async def checks():
        for body in ({}, {"request_actor": {}}, {"request_actor": fixture.actor},
            {"request_actor": {"account_id": "missing"}},
            {"request_actor": {"account_id": "forged", "role": "admin"}},
            {"request_actor": {"account_id": "member", "tenant_memberships": []}},
            {"request_actor": {"account_id": "member", "tenant_memberships": [
              {"role": "tenant_admin", "tenant_id": "tenant-1"}]}},
            {"request_actor": {"account_id": None, "role": "super_tenant_admin"}}):
          result, calls = assert_json_response(await request(module, ENDPOINT, body), 503)
          assert result == UNAVAILABLE and calls == 1
          assert SECRET not in str(result) and HOST not in str(result)
      asyncio.run(checks())
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err and HOST not in captured.out + captured.err
    assert "[plugin-status] endpoint=update_finding_triage" in captured.out


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("read_native", (None, "/workspace"), indirect=True)
def test_native_rejects_old_mutation_fields_and_invalid_transport_without_dispatch(
    read_native, response_format, capsys):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture() as fixture:
    with forbidden_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)

      async def checks():
        legacy = {"job_id": "job-1", "finding_id": "finding-1", "status": "accepted_risk",
                  "note": "private", "actor": "forged", "review_at": 123.0}
        invalid = [None, [], True, 1, "private", legacy]
        invalid.extend({"request_actor": value} for value in (None, [], "private", 1, False))
        invalid.extend({key: value} for key, value in legacy.items())
        invalid.extend({"request_actor": fixture.actor, key: value} for key, value in legacy.items())
        invalid.extend({key: "private"} for key in (
          "tenant_id", "tenantId", "asset_id", "assetId", "execution_binding", "executionBinding", "extra"))
        for body in invalid:
          result, calls = assert_json_response(await request(module, ENDPOINT, body), 400)
          assert result == {"success": False, "error": "invalid_request", "status_code": 400}
          assert calls == 0
        for raw in (b'', b'{', b'\xff', b'{"request_actor":{},"request_actor":{}}',
                    b'{"request_actor":{"account_id":"a","account_id":"b"}}',
                    b'{"request_actor":{"value":NaN}}'):
          result, calls = assert_json_response(await request(module, ENDPOINT, raw=raw), 400)
          assert result["error"] == "invalid_request" and calls == 0
        for query in (b"job_id=job-1", b"actor=private", b"tenant_id=private", b"request_actor=private"):
          result, calls = assert_json_response(await request(module, ENDPOINT, {}, query=query), 400)
          assert result["error"] == "invalid_request" and calls == 0
        for method in ("GET", "PUT", "DELETE", "HEAD", "OPTIONS"):
          result, calls = assert_json_response(await request(module, ENDPOINT, legacy, method=method), 405)
          assert result == {"success": False, "error": "method_not_allowed", "status_code": 405}
          assert calls == 0
        result, calls = assert_json_response(await request(module, ENDPOINT, {}, suffix="/"), 400)
        assert result["error"] == "invalid_request" and calls == 0
      asyncio.run(checks())
      assert module.eng.calls == []
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err and HOST not in captured.out + captured.err


def test_public_denials_are_fresh_objects_and_never_mutate_supplied_actor():
  with read_endpoint_fixture() as fixture:
    with forbidden_effects(fixture):
      actor = {"account_id": "reader", "tenant_memberships": []}
      before = deepcopy(actor)
      result = fixture.Plugin.update_finding_triage(fixture.owner, request_actor=actor)
      result["error"] = "caller mutation"
      assert fixture.Plugin.update_finding_triage(fixture.owner, request_actor=actor) == UNAVAILABLE
      assert actor == before
