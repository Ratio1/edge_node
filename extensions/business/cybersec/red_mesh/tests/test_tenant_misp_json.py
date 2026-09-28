"""Checked tenant MISP downloads through genuine producers and native transport (RM-084 P1:
the tenant is required; there is no unscoped half)."""
import asyncio
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_misp_export import _sample_aggregated, _sample_pass_report
from .test_tenant_read_native import assert_json_response, install, read_native, request, scheduler_comms


ENDPOINT = "export_misp_json"
UNAVAILABLE = {"success": False, "error": "unavailable", "status_code": 503}
SECRET = "mock-only-misp-json-credential"


@contextmanager
def no_export_effects(fixture):
  from extensions.business.cybersec.red_mesh.services import misp_export
  snapshot = deepcopy((fixture.store.data, fixture.store.jobs, fixture.store.writes, fixture.artifacts))
  with ExitStack() as stack:
    effects = [stack.enter_context(patch.object(target, name, create=True,
      side_effect=AssertionError(SECRET))) for target, name in (
        (fixture.owner, "chainstore_hset"), (fixture.owner, "_get_job_from_cstore"),
        (fixture.owner.r1fs, "add_json"), (fixture.owner.r1fs, "delete"),
        (misp_export, "PyMISP"), (misp_export, "emit_export_status_event"),
        (misp_export, "_write_job_record"))]
    # A failed read logs its exception class (RM-090) and nothing else: never
    # the message, which can carry target data or a credential.
    log = stack.enter_context(patch.object(fixture.owner, "P", create=True))
    yield
    for effect in effects:
      effect.assert_not_called()
    logged = str(log.call_args_list)
    assert SECRET not in logged and fixture.job.get("target", "\0") not in logged
    assert (fixture.store.data, fixture.store.jobs, fixture.store.writes, fixture.artifacts) == snapshot


@pytest.fixture(autouse=True)
def tenant_destination(monkeypatch):
  """A bound job exports only to its tenant's destination. The stored record is not under test here
  (test_tenant_export_destinations covers it), so the job's tenant resolves to node configuration."""
  from extensions.business.cybersec.red_mesh.services import misp_export
  monkeypatch.setattr(misp_export, "tenant_export_binding",
    lambda owner, job_specs, integration_id: (job_specs["execution_binding"]["tenant_id"], None))


def install_json_producer(fixture, *, enabled=True):
  fixture.owner.CONFIG = {"MISP_EXPORT": {"ENABLED": enabled}}
  fixture.owner.config_data = {}
  fixture.job["job_config_cid"] = "config"
  fixture.artifacts["config"] = deepcopy(fixture.artifacts["archive"]["job_config"])
  fixture.artifacts["pass"] = _sample_pass_report(aggregated_report_cid="aggregate")
  fixture.artifacts["archive"]["passes"] = [deepcopy(fixture.artifacts["pass"])]
  fixture.artifacts["aggregate"].update(_sample_aggregated())


@pytest.mark.parametrize("enabled", (False, True))
@pytest.mark.parametrize("archived", (False, True))
def test_public_download_uses_real_misp_producer_with_checked_job(archived, enabled):
  """The node's ENABLED flag gates push and auto-export, not a download (RM-093)."""
  with read_endpoint_fixture(bound=True, archived=archived) as fixture:
    install_json_producer(fixture, enabled=enabled)
    result = fixture.Plugin.export_misp_json(fixture.owner, "job-1", request_actor=fixture.actor,
                                             tenant_id=fixture.tenant_id)
    assert result["status"] == "ok" and result["job_id"] == "job-1" and result["pass_nr"] == 1
    assert result["findings_exported"] == 3 and result["findings_total"] == 4
    assert result["ports_exported"] == 3
    assert result["misp_event"]["distribution"] == "0"
    assert {tag["name"] for tag in result["misp_event"]["Tag"]} >= {
      "redmesh:job_id=job-1", "redmesh:report_cid=aggregate"}


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_actual_native_json_export_is_checked_and_no_store(read_native, response_format):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture)
    module.eng = scheduler_comms(fixture, response_format)
    result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT,
      {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
    actual = result["result"] if response_format == "WRAPPED" else result
    assert actual["status"] == "ok" and actual["job_id"] == "job-1" and calls == 1


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("read_native", (None, "/workspace"), indirect=True)
@pytest.mark.parametrize("archived", (False, True))
@pytest.mark.parametrize("scan_type", ("network", "graybox"))
def test_native_real_producer_keeps_wire_types_without_writes_or_push(
    read_native, response_format, archived, scan_type):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True, archived=archived) as fixture:
    install_json_producer(fixture)
    for config in (fixture.artifacts["config"], fixture.artifacts["archive"]["job_config"]):
      config["scan_type"] = scan_type
    with no_export_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "pass_nr": 1, "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
      actual = result["result"] if response_format == "WRAPPED" else result
      assert calls == 1 and actual["job_id"] == "job-1" and actual["target"] == "192.0.2.10"
      assert actual["findings_exported"] == 3 and actual["findings_total"] == 4
      event = actual["misp_event"]
      assert (event["distribution"], event["threat_level_id"], event["analysis"]) == ("0", "1", "2")
      assert isinstance(event["Attribute"][0]["to_ids"], bool)
      assert event["Attribute"][0]["data"] is None


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403), ("role_spoof", 403),
  ("memberships", 404), ("null_memberships", 404), ("other_tenant", 404), ("missing_tenant", 400),
  ("identity_store", 503), ("unbound_job", 404), ("missing_job", 404),
))
def test_native_admission_denies_before_config_and_artifacts(read_native, response_format, fault, status):
  from extensions.business.cybersec.red_mesh.mixins import misp_export
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture)
    body = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
    account = fixture.store.data[("auth", "reader")]
    if fault == "actor": body.pop("request_actor")
    elif fault == "deleted": fixture.store.data.pop(("auth", "reader"))
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault in ("user", "role_spoof"):
      account["memberships"] = [{"role": "tenant_user", "tenant_id": fixture.tenant_id}]
      if fault == "role_spoof":
        body["request_actor"] = {"account_id": "reader", "role": "admin",
                                 "tenant_memberships": [{"role": "super_tenant_admin", "tenant_id": None}]}
    elif fault in ("memberships", "null_memberships"):
      account["memberships"] = [] if fault == "memberships" else None
    elif fault == "other_tenant": body["tenant_id"] = "tn_00000000-0000-4000-8000-000000000000"
    elif fault == "missing_tenant": body.pop("tenant_id")
    elif fault == "identity_store": fixture.store.fail_hkey = "auth"
    elif fault == "unbound_job": fixture.job.pop("execution_binding")
    elif fault == "missing_job": fixture.store.jobs.clear()
    with no_export_effects(fixture), patch.object(misp_export, "get_misp_export_config",
        side_effect=AssertionError(SECRET)) as config:
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, body)), status)
      assert result == {"success": False, "error": {400: "invalid_request", 403: "forbidden", 404: "not_found",
                                                    503: "unavailable"}[status], "status_code": status}
      assert calls == 1 and fixture.artifact_reads == []
      config.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("enabled", (False, True))
def test_native_model_family_is_typed400_whatever_the_node_enabled_flag(read_native, response_format, enabled):
  """A download ignores the node's ENABLED flag (RM-093), so the model-family refusal is the
  first and only answer for a model_test job."""
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture, enabled=enabled)
    fixture.job["job_type"] = "model_test"
    with no_export_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 400)
      assert result == {"success": False, "error": "unsupported_job_type", "status_code": 400}
      assert fixture.artifact_reads == []


@pytest.mark.parametrize("archived", (False, True))
@pytest.mark.parametrize("selected,expected", ((1, "first"), (None, "last")))
def test_duplicate_pass_selection_preserves_first_explicit_and_last_omitted(archived, selected, expected):
  with read_endpoint_fixture(bound=True, archived=archived) as fixture:
    install_json_producer(fixture)
    first, last = deepcopy(fixture.artifacts["pass"]), deepcopy(fixture.artifacts["pass"])
    first["quick_summary"], last["quick_summary"] = "first", "last"
    fixture.artifacts["first"], fixture.artifacts["last"] = first, last
    fixture.artifacts["archive"]["passes"] = [first, last]
    fixture.job["pass_reports"] = [{"pass_nr": 1, "report_cid": cid} for cid in ("first", "last")]
    with no_export_effects(fixture):
      result = fixture.Plugin.export_misp_json(fixture.owner, "job-1", selected, fixture.actor,
                                               fixture.tenant_id)
      assert result["status"] == "ok"
      assert next(item["value"] for item in result["misp_event"]["Attribute"] if item.get("type") == "text") == expected


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("location", ("config", "pass", "aggregate"))
@pytest.mark.parametrize("fault", ("missing", "foreign", "binding", "raw", "nan", "infinity", "negative_infinity", "overflow"))
def test_native_artifact_corruption_never_reaches_pymisp_or_effects(read_native, response_format, location, fault):
  from extensions.business.cybersec.red_mesh.services import misp_export
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    install_json_producer(fixture)
    row = fixture.artifacts[location]
    if fault == "missing": fixture.artifacts[location] = None
    elif fault == "foreign": row["job_id"] = "foreign"
    elif fault == "binding": row["execution_binding"] = None
    elif fault == "raw": row["kind"] = "redmesh_model_test_raw_evidence"
    else: row["risk_score"] = {"nan": float("nan"), "infinity": float("inf"), "negative_infinity": -float("inf"), "overflow": 10**400}[fault]
    with no_export_effects(fixture), patch.object(misp_export, "_build_misp_event",
        side_effect=AssertionError(SECRET)) as build:
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 503)
      assert result == UNAVAILABLE
      build.assert_not_called()


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
def test_native_download_without_a_tenant_misp_record_uses_backend_defaults(read_native, response_format, monkeypatch):
  """RM-093 (supersedes the RM-090 typed 409): a download has no destination, so a bound tenant
  without a MISP record still gets its JSON, rendered with the backend defaults (floor LOW,
  distribution 0) and never with the node's values."""
  from extensions.business.cybersec.red_mesh.services import misp_export
  from extensions.business.cybersec.red_mesh.services.config import TENANT_INTEGRATION_NOT_CONFIGURED
  monkeypatch.setattr(misp_export, "tenant_export_binding",
    lambda owner, job_specs, integration_id: (job_specs["execution_binding"]["tenant_id"],
                                              TENANT_INTEGRATION_NOT_CONFIGURED))
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture, enabled=False)
    # Node values that would show if they leaked: a HIGH floor exports 2 of the 4 sample findings.
    fixture.owner.CONFIG["MISP_EXPORT"].update({"MIN_SEVERITY": "HIGH", "MISP_DISTRIBUTION": 3})
    with no_export_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
      actual = result["result"] if response_format == "WRAPPED" else result
      assert actual["status"] == "ok" and actual["job_id"] == "job-1"
      assert actual["findings_exported"] == 3 and actual["findings_total"] == 4
      assert actual["misp_event"]["distribution"] == "0"


def test_a_failed_read_logs_its_exception_class_only():
  from extensions.business.cybersec.red_mesh.services import misp_export
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture)
    with patch.object(misp_export, "build_misp_event", side_effect=RuntimeError(SECRET)), \
         patch.object(fixture.owner, "P", create=True) as log:
      result = fixture.Plugin.export_misp_json(fixture.owner, "job-1", request_actor=fixture.actor,
                                               tenant_id=fixture.tenant_id)
    assert result == UNAVAILABLE
    logged = str(log.call_args_list)
    assert "RuntimeError" in logged and "reports:export" in logged and SECRET not in logged


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault", ("job", "status"))
def test_native_builder_contract_cannot_hide_job_mismatch_or_publish_error_payload(read_native, response_format, fault):
  from extensions.business.cybersec.red_mesh.services import misp_export
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture)
    produced = misp_export.build_misp_event(fixture.owner, "job-1", checked_job=fixture.job, snapshot_mode="tenant_bound")
    if fault == "job": produced["job_id"] = "foreign"
    else: produced = {"status": "error", "error": SECRET}
    with no_export_effects(fixture), patch.object(misp_export, "build_misp_event", return_value=produced):
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 503)
      assert result == UNAVAILABLE and SECRET not in str(result)


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("enabled", (False, True))
@pytest.mark.parametrize("pass_nr", (0, -1))
def test_native_invalid_pass_is_typed400_even_when_disabled(read_native, response_format, enabled, pass_nr):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture, enabled=enabled)
    with no_export_effects(fixture):
      direct = fixture.Plugin.export_misp_json(fixture.owner, "job-1", pass_nr, fixture.actor,
                                               fixture.tenant_id)
      assert direct == {"success": False, "error": "invalid_request", "status_code": 400}
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "pass_nr": pass_nr, "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 400)
      assert result == direct and fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("archived", (False, True))
def test_native_missing_pass_is404_but_missing_referenced_archive_is503(read_native, response_format, archived):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True, archived=archived) as fixture:
    install_json_producer(fixture)
    with no_export_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "pass_nr": 2, "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 404)
      # RM-093: named, so the console says which pass is missing rather than "resource not found".
      assert result == {"success": False, "error": "pass_not_found", "status_code": 404}
    if archived:
      fixture.artifacts["archive"] = None
      with no_export_effects(fixture):
        result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
          {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 503)
        assert result == UNAVAILABLE


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("reference", ("", None))
@pytest.mark.parametrize("pass_nr", (None, 1))
def test_native_existing_pass_with_corrupt_reference_is503(read_native, response_format, reference, pass_nr):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True, archived=False) as fixture:
    install_json_producer(fixture)
    fixture.job["pass_reports"][0]["report_cid"] = reference
    body = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
    if pass_nr is not None:
      body["pass_nr"] = pass_nr
    with no_export_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)
      result, calls = assert_json_response(asyncio.run(request(module, ENDPOINT, body)), 503)
      assert result == UNAVAILABLE and calls == 1
      assert fixture.artifact_reads == []


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("role", ("tenant_admin", "tenant_pentester", "super_tenant_admin"))
def test_native_current_stored_export_roles_and_finite_json_controls(read_native, response_format, role):
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture)
    account = fixture.store.data[("auth", "reader")]
    account["memberships"] = [
      {"role": role, "tenant_id": None if role == "super_tenant_admin" else fixture.tenant_id}]
    fixture.artifacts["pass"]["optional_metadata"] = {"large": 10**100, "flag": True, "text": "nan", "nothing": None}
    with no_export_effects(fixture):
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 200)
      assert (result["result"] if response_format == "WRAPPED" else result)["status"] == "ok"


@pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
@pytest.mark.parametrize("fault", ("pass", "target", "counts", "count_bool", "count_overflow", "job_tag", "report_tag", "duplicate_tag", "nested_job", "ownership", "raw", "nonfinite"))
def test_native_generated_event_contract_rejects_corruption(read_native, response_format, fault):
  from extensions.business.cybersec.red_mesh.services import misp_export
  from fastapi.encoders import jsonable_encoder
  module, _ = read_native
  install(module)
  with read_endpoint_fixture(bound=True) as fixture:
    install_json_producer(fixture)
    produced = misp_export.build_misp_event(fixture.owner, "job-1", checked_job=fixture.job, snapshot_mode="tenant_bound")
    event = jsonable_encoder(produced["event"].to_dict())
    if fault == "pass": produced["pass_nr"] = 0
    elif fault == "target": produced["target"] = None
    elif fault == "counts": produced["findings_exported"] = produced["findings_total"] + 1
    elif fault == "count_bool": produced["ports_exported"] = True
    elif fault == "count_overflow": produced["ports_exported"] = 10**400
    elif fault in ("job_tag", "report_tag"):
      prefix = "redmesh:job_id=" if fault == "job_tag" else "redmesh:report_cid="
      next(tag for tag in event["Tag"] if tag["name"].startswith(prefix))["name"] = prefix + "foreign"
    elif fault == "duplicate_tag": event["Tag"].append({"name": "redmesh:job_id=job-1"})
    else:
      event["optional"] = {"nested_job": {"job_id": "foreign"}, "ownership": {"tenantId": "foreign"},
        "raw": {"raw_evidence_payload": {}}, "nonfinite": {"value": float("nan")}}[fault]
    produced["event"] = MagicMock(to_dict=MagicMock(return_value=event))
    with no_export_effects(fixture), patch.object(misp_export, "build_misp_event", return_value=produced):
      module.eng = scheduler_comms(fixture, response_format)
      result, _ = assert_json_response(asyncio.run(request(module, ENDPOINT,
        {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id})), 503)
      assert result == UNAVAILABLE
