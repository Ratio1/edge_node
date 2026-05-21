import json
import os
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.integration_status import get_integration_status
from extensions.business.cybersec.red_mesh.services.opencti_export import (
  dry_run_opencti_export,
  get_opencti_export_status,
  push_to_opencti,
)
from extensions.business.cybersec.red_mesh.tests.test_stix_export import (
  _FakeArtifactRepo,
  _sample_aggregated,
  _sample_archive,
)


def _owner(opencti_config=None, job_specs=None):
  records = {}
  job_specs = job_specs or {
    "job_id": "job-1",
    "job_status": "FINALIZED",
    "target": "10.0.0.1",
    "job_cid": "archive-cid",
    "job_config_cid": "config-cid",
    "date_created": 1770000000.0,
    "date_completed": 1770000300.0,
  }

  class Owner:
    cfg_instance_id = "tenant-a"
    cfg_ee_node_network = "devnet"
    cfg_stix_export = {
      "ENABLED": True,
      "DEFAULT_TLP": "amber",
      "INCLUDE_OBSERVED_DATA": True,
      "INCLUDE_INDICATORS": "all",
    }
    cfg_opencti_export = {
      "ENABLED": True,
      "URL": "https://opencti.example",
      "TOKEN_ENV": "REDMESH_OPENCTI_TOKEN_TEST",
      "PUSH_MODE": "manual",
      "MIN_SEVERITY": "MEDIUM",
      **(opencti_config or {}),
    }
    config_data = {}
    CONFIG = {}

    def __init__(self):
      self.r1fs = MagicMock()
      self.r1fs.add_json.return_value = "QmOpenCtiBundle"
      self.job_specs = job_specs
      self.messages = []
      self._records = records

    def P(self, msg, **kwargs):
      self.messages.append(msg)

    def _get_job_from_cstore(self, job_id):
      return self.job_specs if job_id == "job-1" else None

    def _get_artifact_repository(self):
      return _FakeArtifactRepo(_sample_archive(), _sample_aggregated(), self)

    def _write_job_record(self, job_id, updated, context=""):
      self.job_specs = updated
      return updated

    def chainstore_hget(self, hkey, key):
      return records.get((hkey, key))

    def chainstore_hset(self, hkey, key, value):
      records[(hkey, key)] = value
      return True

  return Owner()


class _Response:
  def __init__(self, status_code=200, payload=None):
    self.status_code = status_code
    self._payload = payload or {
      "data": {
        "uploadImport": {
          "id": "opencti-file-1",
          "name": "redmesh-stix-job-1.json",
          "uploadStatus": "wait",
        }
      }
    }

  def json(self):
    return self._payload


class TestOpenCtiExport(unittest.TestCase):

  def setUp(self):
    os.environ["REDMESH_OPENCTI_TOKEN_TEST"] = "opencti-secret-token"

  def tearDown(self):
    os.environ.pop("REDMESH_OPENCTI_TOKEN_TEST", None)

  @patch("extensions.business.cybersec.red_mesh.services.opencti_export.requests.post")
  def test_dry_run_persists_bundle_without_network_push(self, post):
    owner = _owner()

    result = dry_run_opencti_export(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["dry_run"])
    self.assertEqual(result["artifact_cid"], "QmOpenCtiBundle")
    self.assertEqual(owner.job_specs["opencti_export"]["status"], "dry_run")
    post.assert_not_called()

    status = get_integration_status(owner)["integrations"]["opencti"]
    self.assertEqual(status["last_artifact_cid"], "QmOpenCtiBundle")
    self.assertIsNotNone(status["last_dry_run_at"])
    self.assertIsNotNone(status["last_success_at"])

  @patch("extensions.business.cybersec.red_mesh.services.opencti_export.emit_export_status_event")
  @patch("extensions.business.cybersec.red_mesh.services.opencti_export.requests.post")
  def test_manual_push_uploads_stix_bundle_with_bearer_auth(self, post, emit_status):
    post.return_value = _Response()
    owner = _owner()

    result = push_to_opencti(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["opencti_file_id"], "opencti-file-1")
    self.assertEqual(result["artifact_cid"], "QmOpenCtiBundle")
    self.assertEqual(result["redacted_host"], "opencti.example")
    self.assertNotIn("secret", json.dumps(result))
    post.assert_called_once()
    _, kwargs = post.call_args
    self.assertEqual(kwargs["headers"], {"Authorization": "Bearer opencti-secret-token"})
    self.assertEqual(kwargs["data"]["map"], json.dumps({"0": ["variables.file"]}))
    self.assertIn("uploadImport", kwargs["data"]["operations"])
    uploaded = kwargs["files"]["0"][1].decode("utf-8")
    self.assertNotIn("10.0.0.1", uploaded)
    self.assertIn('"type": "bundle"', uploaded)
    emit_status.assert_called_once()
    self.assertEqual(emit_status.call_args.kwargs["adapter_type"], "opencti")

  def test_disabled_opencti_does_not_build_or_persist(self):
    owner = _owner({"ENABLED": False})

    result = push_to_opencti(owner, "job-1")

    self.assertEqual(result["status"], "disabled")
    owner.r1fs.add_json.assert_not_called()
    self.assertNotIn("opencti_export", owner.job_specs)

  def test_missing_token_updates_opencti_status_only(self):
    os.environ.pop("REDMESH_OPENCTI_TOKEN_TEST", None)
    owner = _owner()

    result = push_to_opencti(owner, "job-1")

    self.assertEqual(result["status"], "not_configured")
    self.assertEqual(result["error"], "missing_token")
    status = get_integration_status(owner)["integrations"]["opencti"]
    self.assertEqual(status["last_error_class"], "missing_token")
    self.assertIsNone(get_integration_status(owner)["integrations"]["stix"]["last_failure_at"])

  @patch("extensions.business.cybersec.red_mesh.services.opencti_export.requests.post")
  def test_graphql_errors_are_redacted_and_record_failure(self, post):
    post.return_value = _Response(payload={"errors": [{"message": "token exploded"}]})
    owner = _owner()

    result = push_to_opencti(owner, "job-1")

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "graphql_error")
    self.assertNotIn("token exploded", json.dumps(result))
    status = get_integration_status(owner)["integrations"]["opencti"]
    self.assertEqual(status["last_error_class"], "graphql_error")

  @patch("extensions.business.cybersec.red_mesh.services.opencti_export.requests.post")
  def test_get_export_status_reads_job_metadata(self, post):
    post.return_value = _Response()
    owner = _owner()
    push_to_opencti(owner, "job-1")

    result = get_opencti_export_status(owner, "job-1")

    self.assertTrue(result["found"])
    self.assertTrue(result["exported"])
    self.assertEqual(result["opencti_file_id"], "opencti-file-1")


if __name__ == "__main__":
  unittest.main()
