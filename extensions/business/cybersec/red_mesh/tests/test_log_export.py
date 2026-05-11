import os
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.event_builder import build_test_event
from extensions.business.cybersec.red_mesh.services.integration_status import get_integration_status
from extensions.business.cybersec.red_mesh.services.log_export import (
  compute_payload_hmac,
  deliver_wazuh_event,
)


def _owner(wazuh_config=None, event_config=None):
  owner = MagicMock()
  owner.cfg_instance_id = "tenant-a"
  owner.cfg_ee_node_network = "devnet"
  owner.cfg_wazuh_export = {
    "ENABLED": True,
    "MODE": "http",
    "HTTP_URL": "https://wazuh.example/ingest",
    "TIMEOUT_SECONDS": 0.25,
    "RETRY_ATTEMPTS": 0,
    **(wazuh_config or {}),
  }
  owner.cfg_event_export = {
    "SIGN_PAYLOADS": True,
    "HMAC_SECRET_ENV": "REDMESH_EVENT_HMAC_SECRET",
    **(event_config or {}),
  }
  records = {}

  def hget(hkey, key):
    return records.get((hkey, key))

  def hset(hkey, key, value):
    records[(hkey, key)] = value

  owner.chainstore_hget.side_effect = hget
  owner.chainstore_hset.side_effect = hset
  owner._records = records
  return owner


def _event():
  return build_test_event(
    hmac_secret="tenant-secret",
    tenant_id="tenant-a",
    environment="devnet",
  )


class TestLogExport(unittest.TestCase):

  def tearDown(self):
    os.environ.pop("REDMESH_EVENT_HMAC_SECRET", None)
    os.environ.pop("REDMESH_WAZUH_TOKEN", None)

  @patch("extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen")
  def test_http_export_posts_canonical_json_with_signature_and_idempotency_headers(self, urlopen):
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"
    os.environ["REDMESH_WAZUH_TOKEN"] = "bearer-secret"
    response = MagicMock()
    response.__enter__.return_value.status = 202
    urlopen.return_value = response
    owner = _owner()
    event = _event()

    result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "sent")
    self.assertEqual(result["integration_id"], "wazuh")
    self.assertNotIn("bearer-secret", str(result))
    request = urlopen.call_args.args[0]
    expected_signature = compute_payload_hmac(request.data, "signing-secret")
    self.assertEqual(request.full_url, "https://wazuh.example/ingest")
    self.assertEqual(request.get_header("X-redmesh-event-id"), event["event_id"])
    self.assertEqual(request.get_header("X-redmesh-dedupe-key"), event["dedupe_key"])
    self.assertEqual(request.get_header("X-redmesh-signature"), f"sha256={expected_signature}")
    self.assertEqual(request.get_header("Authorization"), "Bearer bearer-secret")

    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertEqual(status["last_event_id"], event["event_id"])
    self.assertIsNotNone(status["last_success_at"])
    self.assertIsNone(status["last_error_class"])

  @patch("extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen")
  def test_http_export_fails_closed_when_signing_secret_is_missing(self, urlopen):
    owner = _owner()
    event = _event()

    result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "missing_hmac_secret")
    urlopen.assert_not_called()
    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertEqual(status["last_error_class"], "missing_hmac_secret")
    self.assertIsNotNone(status["last_failure_at"])

  @patch("extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen")
  def test_http_export_retries_and_persists_redacted_failed_sample(self, urlopen):
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"
    owner = _owner({
      "RETRY_ATTEMPTS": 1,
      "PERSIST_FAILED_PAYLOADS": True,
      "FAILED_PAYLOAD_SAMPLE_BYTES": 4096,
    })
    owner.r1fs.add_json.return_value = "QmFailedPayload"
    urlopen.side_effect = urllib.error.URLError("connection refused")
    event = _event()

    result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["attempts"], 2)
    self.assertEqual(result["error"], "http_unreachable")
    self.assertEqual(result["artifact_cid"], "QmFailedPayload")
    self.assertEqual(urlopen.call_count, 2)
    persisted = owner.r1fs.add_json.call_args.args[0]
    self.assertEqual(persisted["schema"], "redmesh.integration.failed_payload.v1")
    self.assertEqual(persisted["event_id"], event["event_id"])
    self.assertNotIn("198.51.100.10", str(persisted))

    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertEqual(status["last_artifact_cid"], "QmFailedPayload")
    self.assertEqual(status["last_error_class"], "http_unreachable")

  @patch("extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen")
  def test_invalid_event_is_not_delivered(self, urlopen):
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"
    owner = _owner()

    result = deliver_wazuh_event(owner, {"schema": "wrong"})

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "invalid_event")
    self.assertTrue(result["validation_errors"])
    urlopen.assert_not_called()


if __name__ == "__main__":
  unittest.main()
