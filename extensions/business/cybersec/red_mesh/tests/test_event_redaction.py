import json
import unittest

from extensions.business.cybersec.red_mesh.services.event_redaction import (
  contains_sensitive_value,
  redact_event_payload,
  stable_hmac_pseudonym,
  strip_sensitive_fields,
)


class TestRedMeshEventRedaction(unittest.TestCase):

  def test_hmac_pseudonyms_are_stable_and_tenant_scoped(self):
    first = stable_hmac_pseudonym("10.0.0.5", "tenant-a", prefix="target")
    second = stable_hmac_pseudonym("10.0.0.5", "tenant-a", prefix="target")
    other_tenant = stable_hmac_pseudonym("10.0.0.5", "tenant-b", prefix="target")

    self.assertEqual(first, second)
    self.assertNotEqual(first, other_tenant)
    self.assertTrue(first.startswith("target:"))
    self.assertNotIn("10.0.0.5", first)

  def test_strip_sensitive_fields_removes_nested_secrets(self):
    payload = {
      "safe": "value",
      "password": "secret-password",
      "nested": {
        "token": "secret-token",
        "items": [
          {"cookie": "session=secret-cookie", "summary": "ok"},
          {"raw_response": "<html>secret</html>"},
        ],
      },
    }

    cleaned = strip_sensitive_fields(payload)

    self.assertEqual(cleaned["safe"], "value")
    self.assertEqual(cleaned["nested"]["items"][0], {"summary": "ok"})
    serialized = json.dumps(cleaned, sort_keys=True)
    self.assertNotIn("secret-password", serialized)
    self.assertNotIn("secret-token", serialized)
    self.assertNotIn("secret-cookie", serialized)
    self.assertNotIn("<html>secret</html>", serialized)

  def test_redact_event_payload_pseudonymizes_target_and_worker_ips(self):
    event = {
      "target": {
        "type": "host",
        "display": "10.0.0.5",
        "ip": "10.0.0.5",
      },
      "worker": {
        "node_id": "node-a",
        "source_ip": "192.0.2.10",
        "expected_egress_ip": "198.51.100.20",
      },
    }

    redacted = redact_event_payload(event, hmac_secret="tenant-a")

    self.assertIsNone(redacted["target"]["display"])
    self.assertNotIn("ip", redacted["target"])
    self.assertTrue(redacted["target"]["pseudonym"].startswith("target:"))
    self.assertIsNone(redacted["worker"]["source_ip"])
    self.assertIsNone(redacted["worker"]["expected_egress_ip"])
    self.assertTrue(redacted["worker"]["source_ip_pseudonym"].startswith("ip:"))
    self.assertTrue(redacted["worker"]["expected_egress_ip_pseudonym"].startswith("ip:"))
    self.assertFalse(contains_sensitive_value(redacted, ["10.0.0.5", "192.0.2.10", "198.51.100.20"]))

  def test_redact_event_payload_can_keep_internal_soc_display(self):
    event = {
      "target": {
        "type": "host",
        "display": "10.0.0.5",
      },
      "worker": {
        "source_ip": "192.0.2.10",
        "expected_egress_ip": "198.51.100.20",
      },
    }

    redacted = redact_event_payload(
      event,
      hmac_secret="tenant-a",
      include_target_display=True,
      include_worker_source_ip=True,
      include_egress_ip=True,
    )

    self.assertEqual(redacted["target"]["display"], "10.0.0.5")
    self.assertEqual(redacted["worker"]["source_ip"], "192.0.2.10")
    self.assertEqual(redacted["worker"]["expected_egress_ip"], "198.51.100.20")

  def test_redact_event_payload_hashes_banners_and_proves_exclusions(self):
    event = {
      "observation": {
        "port": 443,
        "banner": "nginx/1.22.1",
        "raw_response": "HTTP/1.1 200 OK\r\nsecret",
      },
      "finding": {
        "title": "XSS",
        "exploit_payload": "<script>secret</script>",
      },
      "authorization": "Bearer secret-token",
    }

    redacted = redact_event_payload(event, hmac_secret="tenant-a")

    self.assertIn("banner_hash", redacted["observation"])
    self.assertNotIn("banner", redacted["observation"])
    self.assertNotIn("raw_response", redacted["observation"])
    self.assertNotIn("exploit_payload", redacted["finding"])
    self.assertNotIn("authorization", redacted)
    self.assertEqual(redacted["redaction"]["credentials_excluded"], True)
    self.assertEqual(redacted["redaction"]["tokens_excluded"], True)
    self.assertEqual(redacted["redaction"]["raw_responses_excluded"], True)
    self.assertEqual(redacted["redaction"]["exploit_payloads_excluded"], True)
    self.assertFalse(contains_sensitive_value(redacted, ["secret-token", "<script>secret</script>"]))


if __name__ == "__main__":
  unittest.main()
