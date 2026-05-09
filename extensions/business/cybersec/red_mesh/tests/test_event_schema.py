import unittest
import uuid
from datetime import datetime

from extensions.business.cybersec.red_mesh.models.event_schema import (
  REDMESH_EVENT_SCHEMA,
  REDMESH_EVENT_SCHEMA_VERSION,
  REQUIRED_EVENT_FIELDS,
  validate_event_dict,
)
from extensions.business.cybersec.red_mesh.services.event_builder import (
  build_attestation_event,
  build_export_status_event,
  build_finding_event,
  build_lifecycle_event,
  build_service_observed_event,
  build_test_event,
)


class TestRedMeshEventSchema(unittest.TestCase):

  def setUp(self):
    self.secret = "tenant-secret-a"
    self.job = {
      "job_id": "job-1",
      "target": "10.0.0.5",
      "job_pass": 2,
      "scan_type": "network",
      "run_mode": "SINGLEPASS",
      "authorized": True,
      "authorization_ref": "QmAuth",
    }

  def assert_valid_event(self, event):
    for field in REQUIRED_EVENT_FIELDS:
      self.assertIn(field, event)
    self.assertEqual(validate_event_dict(event), [])
    uuid.UUID(event["event_id"])
    datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))

  def test_test_event_has_required_contract(self):
    event = build_test_event(
      hmac_secret=self.secret,
      tenant_id="tenant-1",
      environment="devnet",
    )

    self.assert_valid_event(event)
    self.assertEqual(event["schema"], REDMESH_EVENT_SCHEMA)
    self.assertEqual(event["schema_version"], REDMESH_EVENT_SCHEMA_VERSION)
    self.assertEqual(event["event_type"], "redmesh.integration.test")
    self.assertEqual(event["event_outcome"], "success")
    self.assertEqual(event["severity"], "INFO")
    self.assertIn("redmesh", event["labels"])
    self.assertIn("authorized-assessment", event["labels"])

  def test_lifecycle_dedupe_key_is_stable_but_event_id_is_unique(self):
    first = build_lifecycle_event(
      self.job,
      event_type="redmesh.job.started",
      event_action="started",
      hmac_secret=self.secret,
    )
    second = build_lifecycle_event(
      self.job,
      event_type="redmesh.job.started",
      event_action="started",
      hmac_secret=self.secret,
    )

    self.assert_valid_event(first)
    self.assertEqual(first["dedupe_key"], second["dedupe_key"])
    self.assertNotEqual(first["event_id"], second["event_id"])

  def test_service_observation_excludes_raw_banner_and_response(self):
    event = build_service_observed_event(
      self.job,
      service={
        "port": 443,
        "protocol": "https",
        "service_name": "nginx",
        "banner": "nginx/1.22.1 Ubuntu",
        "raw_response": "<html>secret</html>",
      },
      hmac_secret=self.secret,
    )

    self.assert_valid_event(event)
    self.assertEqual(event["event_type"], "redmesh.service.observed")
    self.assertEqual(event["observation"]["port"], 443)
    self.assertEqual(event["observation"]["service_name"], "nginx")
    self.assertIn("banner_hash", event["observation"])
    self.assertNotIn("banner", event["observation"])
    self.assertNotIn("raw_response", event["observation"])

  def test_finding_event_normalizes_invalid_severity_and_strips_evidence(self):
    event = build_finding_event(
      self.job,
      finding={
        "finding_id": "finding-1",
        "title": "Finding",
        "severity": "ultra",
        "confidence": "firm",
        "category": "web",
        "evidence": {"password": "secret-value", "safe": "summary"},
      },
      hmac_secret=self.secret,
    )

    self.assert_valid_event(event)
    self.assertEqual(event["severity"], "INFO")
    self.assertEqual(event["finding"]["severity"], "INFO")
    self.assertEqual(event["finding"]["evidence"], {"safe": "summary"})

  def test_export_status_event_uses_destination_without_secrets(self):
    event = build_export_status_event(
      self.job,
      adapter_type="siem",
      status="completed",
      destination_label="wazuh-prod",
      artifact_refs={"export_manifest_cid": "QmExport"},
      hmac_secret=self.secret,
    )

    self.assert_valid_event(event)
    self.assertEqual(event["event_type"], "redmesh.export.siem.completed")
    self.assertEqual(event["destination"], {"adapter_type": "siem", "label": "wazuh-prod"})
    self.assertEqual(event["artifact_refs"]["export_manifest_cid"], "QmExport")

  def test_attestation_event_keeps_public_tx_metadata_only(self):
    event = build_attestation_event(
      self.job,
      state="submitted",
      network="base-sepolia",
      tx_hash="0xabc",
      hmac_secret=self.secret,
    )

    self.assert_valid_event(event)
    self.assertEqual(event["event_type"], "redmesh.attestation.submitted")
    self.assertEqual(event["attestation"], {
      "network": "base-sepolia",
      "tx_hash": "0xabc",
      "state": "submitted",
    })

  def test_validation_reports_missing_and_invalid_fields(self):
    errors = validate_event_dict({"schema": "bad"})

    self.assertIn("schema must be redmesh.event.v1", errors)
    self.assertTrue(any(error.startswith("missing required field:") for error in errors))


if __name__ == "__main__":
  unittest.main()
