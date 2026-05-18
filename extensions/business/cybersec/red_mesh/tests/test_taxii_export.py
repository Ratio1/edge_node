import json
import os
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.integration_status import get_integration_status
from extensions.business.cybersec.red_mesh.services.taxii_export import (
  STIX_MEDIA_TYPE,
  TAXII_MEDIA_TYPE,
  dry_run_taxii_export,
  get_taxii_export_status,
  publish_to_taxii,
)
from extensions.business.cybersec.red_mesh.tests.test_stix_export import (
  _FakeArtifactRepo,
  _sample_aggregated,
  _sample_archive,
)


def _owner(taxii_config=None, job_specs=None):
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
    cfg_taxii_export = {
      "ENABLED": True,
      "SERVER_URL": "https://taxii.example/api1",
      "TOKEN_ENV": "REDMESH_TAXII_TOKEN_TEST",
      "COLLECTION_ID": "collection-1",
      "MODE": "publish_manual",
      "TIMEOUT_SECONDS": 7,
      **(taxii_config or {}),
    }
    config_data = {}
    CONFIG = {}

    def __init__(self):
      self.r1fs = MagicMock()
      self.r1fs.add_json.return_value = "QmTaxiiBundle"
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
  def __init__(self, status_code=202, payload=None):
    self.status_code = status_code
    self._payload = payload or {
      "id": "taxii-status-1",
      "status": "complete",
      "success_count": 6,
      "failure_count": 0,
      "pending_count": 0,
    }

  def json(self):
    return self._payload


class TestTaxiiExport(unittest.TestCase):

  def setUp(self):
    os.environ["REDMESH_TAXII_TOKEN_TEST"] = "taxii-secret-token"

  def tearDown(self):
    os.environ.pop("REDMESH_TAXII_TOKEN_TEST", None)

  @patch("extensions.business.cybersec.red_mesh.services.taxii_export.requests.post")
  def test_dry_run_persists_bundle_without_network_publish(self, post):
    owner = _owner()

    result = dry_run_taxii_export(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["dry_run"])
    self.assertEqual(result["artifact_cid"], "QmTaxiiBundle")
    self.assertEqual(owner.job_specs["taxii_export"]["status"], "dry_run")
    post.assert_not_called()

    status = get_integration_status(owner)["integrations"]["taxii"]
    self.assertEqual(status["last_artifact_cid"], "QmTaxiiBundle")
    self.assertIsNotNone(status["last_dry_run_at"])
    self.assertIsNotNone(status["last_success_at"])

  @patch("extensions.business.cybersec.red_mesh.services.taxii_export.emit_export_status_event")
  @patch("extensions.business.cybersec.red_mesh.services.taxii_export.requests.post")
  def test_manual_publish_posts_stix_bundle_to_collection_objects_endpoint(self, post, emit_status):
    post.return_value = _Response()
    owner = _owner()

    result = publish_to_taxii(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["taxii_status_id"], "taxii-status-1")
    self.assertEqual(result["artifact_cid"], "QmTaxiiBundle")
    self.assertEqual(result["redacted_host"], "taxii.example")
    self.assertNotIn("secret", json.dumps(result))
    post.assert_called_once()
    args, kwargs = post.call_args
    self.assertEqual(args[0], "https://taxii.example/api1/collections/collection-1/objects/")
    self.assertEqual(kwargs["headers"], {
      "Accept": TAXII_MEDIA_TYPE,
      "Authorization": "Bearer taxii-secret-token",
      "Content-Type": STIX_MEDIA_TYPE,
    })
    self.assertEqual(kwargs["timeout"], 7.0)
    uploaded = kwargs["data"]
    self.assertNotIn("10.0.0.1", uploaded)
    self.assertIn('"type": "bundle"', uploaded)
    emit_status.assert_called_once()
    self.assertEqual(emit_status.call_args.kwargs["adapter_type"], "taxii")

  def test_disabled_taxii_does_not_build_or_persist(self):
    owner = _owner({"ENABLED": False})

    result = publish_to_taxii(owner, "job-1")

    self.assertEqual(result["status"], "disabled")
    owner.r1fs.add_json.assert_not_called()
    self.assertNotIn("taxii_export", owner.job_specs)

  def test_missing_collection_updates_taxii_status_only(self):
    owner = _owner({"COLLECTION_ID": ""})

    result = publish_to_taxii(owner, "job-1")

    self.assertEqual(result["status"], "not_configured")
    self.assertEqual(result["error"], "missing_collection_id")
    status = get_integration_status(owner)["integrations"]["taxii"]
    self.assertEqual(status["last_error_class"], "missing_collection_id")
    self.assertIsNone(get_integration_status(owner)["integrations"]["stix"]["last_failure_at"])

  def test_missing_token_updates_taxii_status_only(self):
    os.environ.pop("REDMESH_TAXII_TOKEN_TEST", None)
    owner = _owner()

    result = publish_to_taxii(owner, "job-1")

    self.assertEqual(result["status"], "not_configured")
    self.assertEqual(result["error"], "missing_token")
    status = get_integration_status(owner)["integrations"]["taxii"]
    self.assertEqual(status["last_error_class"], "missing_token")
    self.assertIsNone(get_integration_status(owner)["integrations"]["opencti"]["last_failure_at"])

  @patch("extensions.business.cybersec.red_mesh.services.taxii_export.requests.post")
  def test_http_errors_are_redacted_and_record_failure(self, post):
    post.return_value = _Response(status_code=422, payload={"message": "token exploded"})
    owner = _owner()

    result = publish_to_taxii(owner, "job-1")

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "http_422")
    self.assertNotIn("token exploded", json.dumps(result))
    status = get_integration_status(owner)["integrations"]["taxii"]
    self.assertEqual(status["last_error_class"], "http_422")

  @patch("extensions.business.cybersec.red_mesh.services.taxii_export.requests.post")
  def test_get_export_status_reads_job_metadata(self, post):
    post.return_value = _Response()
    owner = _owner()
    publish_to_taxii(owner, "job-1")

    result = get_taxii_export_status(owner, "job-1")

    self.assertTrue(result["found"])
    self.assertTrue(result["exported"])
    self.assertEqual(result["taxii_status_id"], "taxii-status-1")

  @patch("extensions.business.cybersec.red_mesh.services.taxii_export.emit_export_status_event")
  @patch("extensions.business.cybersec.red_mesh.services.taxii_export.requests.post")
  def test_basic_auth_mode_emits_basic_header_with_utf8_password(self, post, emit_status):
    import base64
    os.environ["REDMESH_TAXII_PASSWORD_TEST"] = "TaxiiAdmin2026"
    try:
      post.return_value = _Response()
      owner = _owner({
        "AUTH_MODE": "basic",
        "USERNAME": "redmesh",
        "PASSWORD_ENV": "REDMESH_TAXII_PASSWORD_TEST",
      })

      result = publish_to_taxii(owner, "job-1")

      self.assertEqual(result["status"], "ok")
      expected = base64.b64encode(b"redmesh:TaxiiAdmin2026").decode("ascii")
      _, kwargs = post.call_args
      self.assertEqual(kwargs["headers"]["Authorization"], f"Basic {expected}")
      self.assertEqual(kwargs["headers"]["Accept"], TAXII_MEDIA_TYPE)
      self.assertEqual(kwargs["headers"]["Content-Type"], STIX_MEDIA_TYPE)
    finally:
      os.environ.pop("REDMESH_TAXII_PASSWORD_TEST", None)

  def test_basic_auth_missing_password_is_missing_credentials_preflight(self):
    os.environ.pop("REDMESH_TAXII_PASSWORD_TEST", None)
    owner = _owner({
      "AUTH_MODE": "basic",
      "USERNAME": "redmesh",
      "PASSWORD_ENV": "REDMESH_TAXII_PASSWORD_TEST",
    })

    result = publish_to_taxii(owner, "job-1")

    self.assertEqual(result["status"], "not_configured")
    self.assertEqual(result["error"], "missing_credentials")
    owner.r1fs.add_json.assert_not_called()
    status = get_integration_status(owner)["integrations"]["taxii"]
    self.assertEqual(status["last_error_class"], "missing_credentials")


if __name__ == "__main__":
  unittest.main()
