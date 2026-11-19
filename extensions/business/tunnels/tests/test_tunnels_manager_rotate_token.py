import base64
import unittest

from extensions.business.tunnels.tests.test_tunnels_manager_cloudflare_errors import (
  _RequestsStub,
  make_plugin,
)


TUNNEL_URL = "https://api.cloudflare.com/client/v4/accounts/account-id/cfd_tunnel/tunnel-id"


def _tunnel_payload():
  return {
    "success": True,
    "result": {
      "id": "tunnel-id",
      "metadata": {
        "alias": "My Tunnel",
        "tunnel_token": "old-token",
        "dns_record_id": "dns-record-id",
        "dns_name": "svc-uuid.ratio1.link",
        "custom_hostnames": [{"id": "ch-id", "hostname": "app.example.com"}],
        "type": "http",
        "creator": "ratio1",
      },
    },
  }


def _rotate(plugin):
  return plugin.rotate_tunnel_token(
    tunnel_id="tunnel-id",
    cloudflare_account_id="account-id",
    cloudflare_api_key="api-key",
  )


class TunnelsManagerRotateTokenTests(unittest.TestCase):

  def test_rotation_sets_secret_saves_token_and_disconnects_connectors(self):
    requests = _RequestsStub(
      get_payloads=[_tunnel_payload(), {"success": True, "result": "new-token"}],
      patch_payloads=[{"success": True, "result": {}}, {"success": True, "result": {}}],
      delete_payloads=[{"success": True, "result": None}],
    )
    plugin = make_plugin(requests)

    result = _rotate(plugin)

    self.assertEqual(result, {"success": True, "tunnel_id": "tunnel-id", "tunnel_token": "new-token"})

    secret_patch, metadata_patch = requests.patches
    self.assertEqual(secret_patch["url"], TUNNEL_URL)
    self.assertEqual(list(secret_patch["json"]), ["tunnel_secret"])
    self.assertEqual(len(base64.b64decode(secret_patch["json"]["tunnel_secret"])), 32)

    self.assertEqual(requests.gets[1]["url"], f"{TUNNEL_URL}/token")

    expected_metadata = _tunnel_payload()["result"]["metadata"]
    expected_metadata["tunnel_token"] = "new-token"
    self.assertEqual(metadata_patch["json"], {"metadata": expected_metadata})

    self.assertEqual([d["url"] for d in requests.deletes], [f"{TUNNEL_URL}/connections"])

  def test_each_rotation_uses_a_new_secret(self):
    secrets_sent = []
    for _ in range(2):
      requests = _RequestsStub(
        get_payloads=[_tunnel_payload(), {"success": True, "result": "new-token"}],
        patch_payloads=[{"success": True, "result": {}}, {"success": True, "result": {}}],
        delete_payloads=[{"success": True, "result": None}],
      )
      _rotate(make_plugin(requests))
      secrets_sent.append(requests.patches[0]["json"]["tunnel_secret"])
    self.assertNotEqual(secrets_sent[0], secrets_sent[1])

  def test_secret_failure_stops_before_touching_metadata_or_connectors(self):
    requests = _RequestsStub(
      get_payloads=[_tunnel_payload()],
      patch_payloads=[{"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}],
    )
    plugin = make_plugin(requests)

    with self.assertRaises(Exception) as ctx:
      _rotate(plugin)

    self.assertIn("Error rotating tunnel secret", str(ctx.exception))
    self.assertIn("Authentication error", str(ctx.exception))
    self.assertEqual(len(requests.patches), 1)
    self.assertEqual(requests.deletes, [])

  def test_metadata_failure_after_rotation_asks_to_rotate_again(self):
    requests = _RequestsStub(
      get_payloads=[_tunnel_payload(), {"success": True, "result": "new-token"}],
      patch_payloads=[
        {"success": True, "result": {}},
        {"success": False, "errors": [{"message": "Invalid tunnel metadata."}]},
      ],
    )
    plugin = make_plugin(requests)

    with self.assertRaises(Exception) as ctx:
      _rotate(plugin)

    message = str(ctx.exception)
    self.assertIn("saving the new token failed. Rotate again", message)
    self.assertIn("Invalid tunnel metadata.", message)
    self.assertNotIn("new-token", message)
    self.assertEqual(requests.deletes, [])

  def test_connection_cleanup_failure_is_reported(self):
    requests = _RequestsStub(
      get_payloads=[_tunnel_payload(), {"success": True, "result": "new-token"}],
      patch_payloads=[{"success": True, "result": {}}, {"success": True, "result": {}}],
      delete_payloads=[{"success": False, "errors": [{"message": "Rate limited"}]}],
    )
    plugin = make_plugin(requests)

    with self.assertRaises(Exception) as ctx:
      _rotate(plugin)

    self.assertIn("disconnecting old connectors failed", str(ctx.exception))


if __name__ == "__main__":
  unittest.main()
