"""RM-093 phase 6: pure JSON downloads with no destination.

`export_stix_json` and `export_siem_events_json` render the same bundle/events a real export would
produce, without ever writing to R1FS, mutating the job record, emitting a SOC event, recording an
integration status, or contacting a destination -- whatever the tenant's OpenCTI/TAXII/Wazuh
records or the node's `ENABLED` flags say.
"""
import asyncio
import json
from copy import deepcopy
from unittest.mock import patch

import pytest

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_exports_scope import second_tenant
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  install, read_native, request, scheduler_comms,
)


def _findings():
  return [
    {"finding_id": "f-1", "title": "Open port 443 (https)", "severity": "MEDIUM"},
    {
      "finding_id": "f-2",
      "title": "Accepted credential: admin:secret123",
      "evidence": "Accepted credential: admin:secret123",
      "severity": "HIGH",
    },
    # A coverage result: a scenario that ran and found nothing (RM-064). SIEM excludes it; STIX does
    # not filter by outcome at all, so it still lands in the bundle as a vulnerability object.
    {"finding_id": "f-3", "title": "Coverage probe ran clean", "severity": "INFO",
     "status": "not_vulnerable"},
  ]


def _install_findings(fixture, findings):
  fixture.artifacts["pass"]["findings"] = findings
  fixture.artifacts["archive"]["passes"][0]["findings"] = deepcopy(findings)


def _forbid_writes(fixture):
  """Any store or R1FS write fails the test; returns the job store as it was, to compare after."""
  def refuse(*_args, **_kwargs):
    raise AssertionError("a JSON download must not write")
  fixture.owner.chainstore_hset = refuse
  fixture.owner.r1fs.add_json = refuse
  fixture.owner.r1fs.add_file = refuse
  return deepcopy(fixture.store.jobs)


class TestStixJsonDownload:

  def test_pure_read_matches_build_stix_bundle_with_no_side_effects(self):
    from extensions.business.cybersec.red_mesh.services import stix_export

    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      _install_findings(fixture, _findings())
      jobs_before = _forbid_writes(fixture)
      captured = {}
      real_build = stix_export.build_stix_bundle

      def spy_build(*args, **kwargs):
        value = real_build(*args, **kwargs)
        captured["value"] = value
        return value

      with patch.object(stix_export, "build_stix_bundle", side_effect=spy_build), \
           patch.object(stix_export, "record_integration_status",
                        side_effect=AssertionError("must not record integration status")), \
           patch.object(stix_export, "_write_job_record",
                        side_effect=AssertionError("must not write the job record")), \
           patch.object(stix_export, "emit_export_status_event",
                        side_effect=AssertionError("must not emit a SOC event")):
        result = fixture.Plugin.export_stix_json(
          fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)

      expected = captured["value"]
      assert result["status"] == "ok"
      assert result["job_id"] == "job-1"
      assert result["pass_nr"] == expected["pass_nr"] == 1
      assert result["bundle_id"] == expected["bundle_id"]
      assert result["object_count"] == expected["object_count"] == len(expected["bundle"]["objects"])
      assert result["finding_count"] == expected["finding_count"] == 3
      assert result["stix_bundle"] == expected["bundle"]
      object_types = {obj["type"] for obj in result["stix_bundle"]["objects"]}
      assert {"marking-definition", "report", "vulnerability"} <= object_types
      assert fixture.artifact_reads  # the pass/aggregate were read; nothing else happened
      assert fixture.store.jobs == jobs_before

  def test_model_test_job_is_refused_before_any_build(self):
    with read_endpoint_fixture(bound=True) as fixture:
      fixture.job["job_type"] = "model_test"
      result = fixture.Plugin.export_stix_json(
        fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)
      assert result == {"success": False, "error": "unsupported_job_type", "status_code": 400}

  def test_invalid_pass_nr_is_typed_400(self):
    with read_endpoint_fixture(bound=True) as fixture:
      for bad in (0, -1, "1"):
        result = fixture.Plugin.export_stix_json(
          fixture.owner, "job-1", bad, fixture.actor, fixture.tenant_id)
        assert result == {"success": False, "error": "invalid_request", "status_code": 400}

  def test_cross_tenant_job_is_denied_like_export_misp_json(self):
    with read_endpoint_fixture(bound=True) as fixture:
      other = second_tenant(fixture)
      result = fixture.Plugin.export_stix_json(fixture.owner, "job-1", None, fixture.actor, other)
      assert result == {"success": False, "error": "not_found", "status_code": 404}


class TestSiemEventsJsonDownload:

  def test_pure_read_masks_credentials_excludes_coverage_no_delivery(self):
    from extensions.business.cybersec.red_mesh.services import event_hooks

    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      _install_findings(fixture, _findings())
      jobs_before = _forbid_writes(fixture)
      with patch.object(event_hooks, "emit_redmesh_event",
                         side_effect=AssertionError("must not deliver")), \
           patch.object(event_hooks, "record_integration_status",
                        side_effect=AssertionError("must not record integration status")):
        result = fixture.Plugin.export_siem_events_json(
          fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)

      assert result["status"] == "ok"
      assert result["job_id"] == "job-1" and result["pass_nr"] == 1
      assert result["schema"] == "redmesh.event.v1"
      # One lifecycle event + two non-coverage findings (the third finding is coverage, excluded).
      assert result["event_count"] == 3 == len(result["events"])
      event_types = [event["event_type"] for event in result["events"]]
      assert event_types == [
        "redmesh.job.pass_completed", "redmesh.finding.created", "redmesh.finding.created"]
      dumped = json.dumps(result)
      assert "secret123" not in dumped
      assert "admin:***" in dumped
      assert fixture.store.jobs == jobs_before

  def test_model_test_job_is_refused_before_any_build(self):
    with read_endpoint_fixture(bound=True) as fixture:
      fixture.job["job_type"] = "model_test"
      result = fixture.Plugin.export_siem_events_json(
        fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)
      assert result == {"success": False, "error": "unsupported_job_type", "status_code": 400}

  def test_invalid_pass_nr_is_typed_400(self):
    with read_endpoint_fixture(bound=True) as fixture:
      for bad in (0, -1, "1"):
        result = fixture.Plugin.export_siem_events_json(
          fixture.owner, "job-1", bad, fixture.actor, fixture.tenant_id)
        assert result == {"success": False, "error": "invalid_request", "status_code": 400}

  def test_cross_tenant_job_is_denied_like_export_misp_json(self):
    with read_endpoint_fixture(bound=True) as fixture:
      other = second_tenant(fixture)
      result = fixture.Plugin.export_siem_events_json(
        fixture.owner, "job-1", None, fixture.actor, other)
      assert result == {"success": False, "error": "not_found", "status_code": 404}


# RM-093 phase 8: a job with nothing to export is a state, not an outage. Before, STIX/SIEM answered
# 200 with an error body (which the console collapsed to "temporarily unavailable") and MISP a bare
# 404 `not_found`.
JSON_DOWNLOADS = ("export_misp_json", "export_stix_json", "export_siem_events_json")
NO_COMPLETED_PASSES = {"success": False, "error": "no_completed_passes", "status_code": 409}
PASS_NOT_FOUND = {"success": False, "error": "pass_not_found", "status_code": 404}


class TestNothingToExport:

  @pytest.mark.parametrize("endpoint", JSON_DOWNLOADS)
  def test_a_running_job_with_no_completed_pass_is_typed_409(self, endpoint):
    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      fixture.job["pass_reports"] = []
      result = getattr(fixture.Plugin, endpoint)(
        fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)
      assert result == NO_COMPLETED_PASSES

  @pytest.mark.parametrize("endpoint", JSON_DOWNLOADS)
  def test_an_archive_with_no_passes_is_typed_409(self, endpoint):
    with read_endpoint_fixture(bound=True, archived=True) as fixture:
      fixture.artifacts["archive"]["passes"] = []
      result = getattr(fixture.Plugin, endpoint)(
        fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)
      assert result == NO_COMPLETED_PASSES

  @pytest.mark.parametrize("archived", (False, True))
  @pytest.mark.parametrize("endpoint", JSON_DOWNLOADS)
  def test_a_pass_that_does_not_exist_is_typed_404(self, endpoint, archived):
    with read_endpoint_fixture(bound=True, archived=archived) as fixture:
      result = getattr(fixture.Plugin, endpoint)(
        fixture.owner, "job-1", 5, fixture.actor, fixture.tenant_id)
      assert result == PASS_NOT_FOUND

  @pytest.mark.parametrize("endpoint", JSON_DOWNLOADS)
  @pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
  def test_the_codes_survive_the_read_guard(self, read_native, endpoint, response_format):
    """The strict transport rebuilds error bodies and keeps only codes registered in
    `_TYPED_READ_ERRORS`; unregistered, both would reach the console as `unavailable`."""
    module, _ = read_native
    install(module)
    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      module.eng = scheduler_comms(fixture, response_format)
      body = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
      status, headers, raw, _calls = asyncio.run(request(module, endpoint, {**body, "pass_nr": 5}))
      assert status == 404, raw
      assert headers[b"cache-control"] == b"no-store"
      assert json.loads(raw)["error"] == "pass_not_found", raw
      fixture.job["pass_reports"] = []
      status, headers, raw, _calls = asyncio.run(request(module, endpoint, body))
      assert status == 409, raw
      assert headers[b"cache-control"] == b"no-store"
      assert json.loads(raw)["error"] == "no_completed_passes", raw


# Push resolves the pass through the same checked resolver, so it answers the same codes. The config
# is forced ENABLED so the refusal is the resolver's, and PyMISP is poisoned: nothing may leave.
def _push_patches():
  from extensions.business.cybersec.red_mesh.services import misp_export

  cfg = {**misp_export.DEFAULT_MISP_EXPORT_CONFIG,
         "ENABLED": True, "MISP_URL": "https://misp.invalid", "MISP_API_KEY": "k"}
  return (
    patch.object(misp_export, "tenant_export_binding", return_value=("tenant", None)),
    patch.object(misp_export, "get_misp_export_config", return_value=cfg),
    patch.object(misp_export, "PyMISP", side_effect=AssertionError("must not contact MISP")),
    patch.object(misp_export, "emit_export_status_event",
                 side_effect=AssertionError("must not emit a SOC event")),
    patch.object(misp_export, "_write_job_record",
                 side_effect=AssertionError("must not write the job record")),
  )


class TestPushWithNothingToExport:

  def _push(self, fixture, pass_nr):
    binding, config, pymisp, emit, write = _push_patches()
    with binding, config, pymisp, emit, write:
      return fixture.Plugin.export_misp(fixture.owner, "job-1", pass_nr, fixture.actor,
                                        fixture.tenant_id)

  def test_a_job_with_no_completed_pass_is_typed_409_and_nothing_happens(self):
    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      fixture.job["pass_reports"] = []
      assert self._push(fixture, None) == NO_COMPLETED_PASSES

  def test_a_pass_that_does_not_exist_is_typed_404_and_nothing_happens(self):
    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      assert self._push(fixture, 5) == PASS_NOT_FOUND

  @pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
  def test_the_codes_survive_the_guard(self, read_native, response_format):
    module, _ = read_native
    install(module)
    binding, config, pymisp, emit, write = _push_patches()
    with read_endpoint_fixture(bound=True, archived=False) as fixture, \
         binding, config, pymisp, emit, write:
      module.eng = scheduler_comms(fixture, response_format)
      body = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
      status, headers, raw, _calls = asyncio.run(request(module, "export_misp", {**body, "pass_nr": 5}))
      assert status == 404, raw
      assert headers[b"cache-control"] == b"no-store"
      assert json.loads(raw)["error"] == "pass_not_found", raw
      fixture.job["pass_reports"] = []
      status, headers, raw, _calls = asyncio.run(request(module, "export_misp", body))
      assert status == 409, raw
      assert headers[b"cache-control"] == b"no-store"
      assert json.loads(raw)["error"] == "no_completed_passes", raw
