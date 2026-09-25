"""RM-093 phase 6: pure JSON downloads with no destination.

`export_stix_json` and `export_siem_events_json` render the same bundle/events a real export would
produce, without ever writing to R1FS, mutating the job record, emitting a SOC event, recording an
integration status, or contacting a destination -- whatever the tenant's OpenCTI/TAXII/Wazuh
records or the node's `ENABLED` flags say.
"""
import json
from copy import deepcopy
from unittest.mock import patch

from .read_endpoint_fixtures import read_endpoint_fixture
from .test_tenant_exports_scope import second_tenant


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


class TestStixJsonDownload:

  def test_pure_read_matches_build_stix_bundle_with_no_side_effects(self):
    from extensions.business.cybersec.red_mesh.services import stix_export

    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      _install_findings(fixture, _findings())
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
