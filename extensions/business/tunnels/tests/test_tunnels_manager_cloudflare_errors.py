import sys
import types
import unittest


_supervisor_module = types.ModuleType("naeural_core.business.default.web_app.supervisor_fast_api_web_app")


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  @classmethod
  def endpoint(cls, **kwargs):
    def decorator(fn):
      return fn
    return decorator


_supervisor_module.SupervisorFastApiWebApp = _BasePluginStub
sys.modules.setdefault(
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app",
  _supervisor_module,
)

from extensions.business.tunnels.tunnels_manager import TunnelsManagerPlugin


class _ResponseStub:

  def __init__(self, payload):
    self.payload = payload

  def json(self):
    return self.payload


class _RequestsStub:

  def __init__(self, *, post_payloads=None, patch_payloads=None, delete_payloads=None):
    self.post_payloads = list(post_payloads or [])
    self.patch_payloads = list(patch_payloads or [])
    self.delete_payloads = list(delete_payloads or [])
    self.posts = []
    self.patches = []
    self.deletes = []

  def post(self, url, headers=None, json=None):
    self.posts.append({"url": url, "headers": headers, "json": json})
    return _ResponseStub(self.post_payloads.pop(0))

  def patch(self, url, headers=None, json=None):
    self.patches.append({"url": url, "headers": headers, "json": json})
    return _ResponseStub(self.patch_payloads.pop(0))

  def delete(self, url, headers=None):
    self.deletes.append({"url": url, "headers": headers})
    return _ResponseStub(self.delete_payloads.pop(0))


def make_plugin(requests):
  plugin = TunnelsManagerPlugin.__new__(TunnelsManagerPlugin)
  plugin.requests = requests
  plugin.cfg_base_cloudflare_url = "https://api.cloudflare.com"
  plugin.cfg_tcp_prefix = "cft"
  plugin.cfg_tcp_proxy_url = "tcp.ratio1.link"
  plugin.uuid = lambda: "uuid-001"
  return plugin


class TunnelsManagerCloudflareErrorTests(unittest.TestCase):

  def test_dns_record_failure_reports_cloudflare_message(self):
    requests = _RequestsStub(
      post_payloads=[
        {
          "success": True,
          "result": {
            "id": "tunnel-id",
            "token": "tunnel-token",
          },
        },
        {
          "success": False,
          "errors": [
            {
              "code": 81057,
              "message": "The record already exists.",
            },
          ],
          "result": None,
        },
      ],
      delete_payloads=[
        {
          "success": True,
          "result": {},
        },
      ],
    )
    plugin = make_plugin(requests)

    with self.assertRaises(Exception) as ctx:
      plugin.new_tunnel(
        alias="My Tunnel",
        cloudflare_account_id="account-id",
        cloudflare_zone_id="zone-id",
        cloudflare_api_key="api-key",
        cloudflare_domain="ratio1.link",
      )

    message = str(ctx.exception)
    self.assertIn("Error creating tunnel DNS record", message)
    self.assertIn("81057", message)
    self.assertIn("The record already exists.", message)
    self.assertNotIn("NoneType", message)
    self.assertEqual(len(requests.deletes), 1)

  def test_metadata_update_failure_reports_cloudflare_message(self):
    requests = _RequestsStub(
      post_payloads=[
        {
          "success": True,
          "result": {
            "id": "tunnel-id",
            "token": "tunnel-token",
          },
        },
        {
          "success": True,
          "result": {
            "id": "dns-record-id",
          },
        },
      ],
      patch_payloads=[
        {
          "success": False,
          "errors": [
            {
              "message": "Invalid tunnel metadata.",
            },
          ],
          "result": None,
        },
      ],
      delete_payloads=[
        {
          "success": True,
          "result": {},
        },
        {
          "success": True,
          "result": {},
        },
      ],
    )
    plugin = make_plugin(requests)

    with self.assertRaises(Exception) as ctx:
      plugin.new_tunnel(
        alias="My Tunnel",
        cloudflare_account_id="account-id",
        cloudflare_zone_id="zone-id",
        cloudflare_api_key="api-key",
        cloudflare_domain="ratio1.link",
      )

    message = str(ctx.exception)
    self.assertIn("Error updating tunnel metadata", message)
    self.assertIn("Invalid tunnel metadata.", message)
    self.assertNotIn("NoneType", message)
    self.assertEqual(len(requests.deletes), 2)


if __name__ == "__main__":
  unittest.main()
