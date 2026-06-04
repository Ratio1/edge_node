import sys
import types
import unittest
from copy import deepcopy


_supervisor_module = types.ModuleType("naeural_core.business.default.web_app.supervisor_fast_api_web_app")


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  def on_init(self):
    return

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

  def __init__(self, *, post_payloads=None, patch_payloads=None, delete_payloads=None, get_payloads=None):
    self.post_payloads = list(post_payloads or [])
    self.patch_payloads = list(patch_payloads or [])
    self.delete_payloads = list(delete_payloads or [])
    self.get_payloads = list(get_payloads or [])
    self.posts = []
    self.patches = []
    self.deletes = []
    self.gets = []

  def post(self, url, headers=None, json=None):
    self.posts.append({"url": url, "headers": headers, "json": json})
    return _ResponseStub(self.post_payloads.pop(0))

  def patch(self, url, headers=None, json=None):
    self.patches.append({"url": url, "headers": headers, "json": json})
    return _ResponseStub(self.patch_payloads.pop(0))

  def delete(self, url, headers=None):
    self.deletes.append({"url": url, "headers": headers})
    return _ResponseStub(self.delete_payloads.pop(0))

  def get(self, url, headers=None):
    self.gets.append({"url": url, "headers": headers})
    return _ResponseStub(self.get_payloads.pop(0))


def make_plugin(requests):
  plugin = TunnelsManagerPlugin.__new__(TunnelsManagerPlugin)
  plugin.requests = requests
  plugin.cfg_base_cloudflare_url = "https://api.cloudflare.com"
  plugin.cfg_tcp_proxy_url = "tcp.ratio1.link"
  plugin.cfg_tcp_routes_hkey = "tcp_routes"
  plugin.cfg_tcp_public_port_range_start = 30000
  plugin.cfg_tcp_public_port_range_end = 30499
  plugin.uuid = lambda: "uuid-001"
  plugin.time = lambda: 1000
  plugin.time_to_str = lambda value: f"time-{value}"
  plugin.deepcopy = deepcopy
  plugin.P = lambda *args, **kwargs: None
  plugin.np = types.SimpleNamespace(random=_RandomStub())
  plugin._chainstore = {}
  plugin._chainstore_hsets = []
  plugin._chainstore_hsyncs = []

  def chainstore_hsync(**kwargs):
    plugin._chainstore_hsyncs.append(kwargs)
    return {"merged_fields": 0}

  def chainstore_hget(hkey, key, **kwargs):
    value = plugin._chainstore.get(hkey, {}).get(str(key))
    return deepcopy(value)

  def chainstore_hset(hkey, key, value, readonly=False, **kwargs):
    plugin._chainstore_hsets.append({"hkey": hkey, "key": str(key), "value": deepcopy(value), "readonly": readonly})
    store = plugin._chainstore.setdefault(hkey, {})
    key = str(key)
    if value is None:
      store.pop(key, None)
      return True
    if readonly and key in store and store[key] != value:
      return False
    store[key] = deepcopy(value)
    return True

  plugin.chainstore_hsync = chainstore_hsync
  plugin.chainstore_hget = chainstore_hget
  plugin.chainstore_hset = chainstore_hset
  return plugin


class _RandomStub:

  def __init__(self, values=None):
    self.values = list(values or [])

  def randint(self, low, high=None):
    if high is None:
      low, high = 0, low
    if self.values:
      return self.values.pop(0)
    return high - 1


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

  def test_tcp_tunnel_creation_allocates_chainstore_route_without_public_cname(self):
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
          "success": True,
          "result": {
            "id": "tunnel-id",
            "metadata": {},
          },
        },
      ],
    )
    plugin = make_plugin(requests)
    plugin.cfg_tcp_public_port_range_start = 30000
    plugin.cfg_tcp_public_port_range_end = 30000

    result = plugin.new_tunnel(
      alias="My TCP Tunnel",
      cloudflare_account_id="account-id",
      cloudflare_zone_id="zone-id",
      cloudflare_api_key="api-key",
      cloudflare_domain="ratio1.link",
      tunnel_type="tcp",
    )

    self.assertEqual(len(requests.posts), 2)
    self.assertEqual(requests.posts[1]["json"]["name"], "uuid-001")
    self.assertEqual(result["tcp_route"]["public_port"], 30000)
    self.assertEqual(result["tcp_route"]["hostname"], "uuid-001.ratio1.link")
    self.assertEqual(result["tcp_public_port"], 30000)
    self.assertEqual(result["tcp_public_host"], "tcp.ratio1.link")
    self.assertEqual(result["tcp_public_endpoint"], "tcp.ratio1.link:30000")
    self.assertEqual(result["metadata"]["alias"], "My TCP Tunnel")
    self.assertEqual(result["metadata"]["dns_name"], "uuid-001.ratio1.link")
    self.assertEqual(plugin.get_tcp_route(30000), "uuid-001.ratio1.link")
    self.assertEqual(requests.patches[0]["json"]["metadata"]["tcp_public_endpoint"], "tcp.ratio1.link:30000")

  def test_tcp_port_allocation_skips_occupied_ports(self):
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
          "success": True,
          "result": {
            "id": "tunnel-id",
            "metadata": {},
          },
        },
      ],
    )
    plugin = make_plugin(requests)
    plugin.cfg_tcp_public_port_range_start = 30000
    plugin.cfg_tcp_public_port_range_end = 30001
    plugin.np.random = _RandomStub([30000, 30001])
    plugin._chainstore[plugin.cfg_tcp_routes_hkey] = {
      "30000": {
        "public_port": 30000,
        "hostname": "used.ratio1.link",
        "tunnel_id": "other-tunnel",
        "enabled": True,
      }
    }

    result = plugin.new_tunnel(
      alias="My TCP Tunnel",
      cloudflare_account_id="account-id",
      cloudflare_zone_id="zone-id",
      cloudflare_api_key="api-key",
      cloudflare_domain="ratio1.link",
      tunnel_type="tcp",
    )

    self.assertEqual(result["tcp_route"]["public_port"], 30001)

  def test_tcp_port_allocation_retries_after_readback_collision(self):
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
          "success": True,
          "result": {
            "id": "tunnel-id",
            "metadata": {},
          },
        },
      ],
    )
    plugin = make_plugin(requests)
    plugin.cfg_tcp_public_port_range_start = 30000
    plugin.cfg_tcp_public_port_range_end = 30001
    plugin.np.random = _RandomStub([30000, 30001])
    original_hset = plugin.chainstore_hset
    hset_calls = []

    def colliding_hset(hkey, key, value, readonly=False, **kwargs):
      hset_calls.append(key)
      if value is not None and key == "30000":
        plugin._chainstore.setdefault(hkey, {})[key] = {
          "public_port": 30000,
          "hostname": "other.ratio1.link",
          "tunnel_id": "other-tunnel",
          "enabled": True,
        }
        return True
      return original_hset(hkey=hkey, key=key, value=value, readonly=readonly, **kwargs)

    plugin.chainstore_hset = colliding_hset

    result = plugin.new_tunnel(
      alias="My TCP Tunnel",
      cloudflare_account_id="account-id",
      cloudflare_zone_id="zone-id",
      cloudflare_api_key="api-key",
      cloudflare_domain="ratio1.link",
      tunnel_type="tcp",
    )

    self.assertEqual(hset_calls[:2], ["30000", "30001"])
    self.assertEqual(result["tcp_route"]["public_port"], 30001)

  def test_tcp_port_allocation_exhaustion_cleans_partial_cloudflare_resources(self):
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
    plugin.cfg_tcp_public_port_range_start = 30000
    plugin.cfg_tcp_public_port_range_end = 30000
    plugin._chainstore[plugin.cfg_tcp_routes_hkey] = {
      "30000": {
        "public_port": 30000,
        "hostname": "used.ratio1.link",
        "tunnel_id": "other-tunnel",
        "enabled": True,
      }
    }

    with self.assertRaises(Exception) as ctx:
      plugin.new_tunnel(
        alias="My TCP Tunnel",
        cloudflare_account_id="account-id",
        cloudflare_zone_id="zone-id",
        cloudflare_api_key="api-key",
        cloudflare_domain="ratio1.link",
        tunnel_type="tcp",
      )

    self.assertIn("No available TCP public ports", str(ctx.exception))
    self.assertEqual(len(requests.deletes), 2)

  def test_delete_tcp_tunnel_removes_chainstore_route_from_metadata_hint(self):
    requests = _RequestsStub(
      get_payloads=[
        {
          "success": True,
          "result": {
            "id": "tunnel-id",
            "metadata": {
              "dns_record_id": "dns-record-id",
              "custom_hostnames": [],
              "type": "tcp",
              "tcp_public_port": 30000,
            },
          },
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
    plugin._chainstore[plugin.cfg_tcp_routes_hkey] = {
      "30000": {
        "public_port": 30000,
        "public_host": "tcp.ratio1.link",
        "public_endpoint": "tcp.ratio1.link:30000",
        "hostname": "uuid-001.ratio1.link",
        "tunnel_id": "tunnel-id",
        "enabled": True,
      }
    }

    result = plugin.delete_tunnel(
      tunnel_id="tunnel-id",
      cloudflare_account_id="account-id",
      cloudflare_zone_id="zone-id",
      cloudflare_api_key="api-key",
    )

    self.assertTrue(result["success"])
    self.assertNotIn("30000", plugin._chainstore[plugin.cfg_tcp_routes_hkey])
    self.assertEqual(len(requests.deletes), 2)
    self.assertEqual(plugin._chainstore_hsets[-1]["key"], "30000")
    self.assertIsNone(plugin._chainstore_hsets[-1]["value"])

  def test_delete_tcp_tunnel_keeps_chainstore_route_when_cloudflare_delete_fails(self):
    requests = _RequestsStub(
      get_payloads=[
        {
          "success": True,
          "result": {
            "id": "tunnel-id",
            "metadata": {
              "dns_record_id": "dns-record-id",
              "custom_hostnames": [],
              "type": "tcp",
              "tcp_public_port": 30000,
            },
          },
        },
      ],
      delete_payloads=[
        {
          "success": False,
          "errors": ["delete failed"],
        },
      ],
    )
    plugin = make_plugin(requests)
    plugin._chainstore[plugin.cfg_tcp_routes_hkey] = {
      "30000": {
        "public_port": 30000,
        "public_host": "tcp.ratio1.link",
        "public_endpoint": "tcp.ratio1.link:30000",
        "hostname": "uuid-001.ratio1.link",
        "tunnel_id": "tunnel-id",
        "enabled": True,
      }
    }

    with self.assertRaises(Exception) as ctx:
      plugin.delete_tunnel(
        tunnel_id="tunnel-id",
        cloudflare_account_id="account-id",
        cloudflare_zone_id="zone-id",
        cloudflare_api_key="api-key",
      )

    self.assertIn("Error deleting DNS record", str(ctx.exception))
    self.assertIn("30000", plugin._chainstore[plugin.cfg_tcp_routes_hkey])
    delete_writes = [call for call in plugin._chainstore_hsets if call["value"] is None]
    self.assertEqual(delete_writes, [])

  def test_delete_tcp_route_missing_or_owned_by_other_tunnel_is_not_deleted(self):
    requests = _RequestsStub()
    plugin = make_plugin(requests)
    plugin._chainstore[plugin.cfg_tcp_routes_hkey] = {
      "30000": {
        "public_port": 30000,
        "hostname": "other.ratio1.link",
        "tunnel_id": "other-tunnel",
        "enabled": True,
      }
    }

    with self.assertRaises(Exception):
      plugin._delete_tcp_route(public_port=30000, expected_tunnel_id="tunnel-id")

    self.assertEqual(plugin._chainstore[plugin.cfg_tcp_routes_hkey]["30000"]["tunnel_id"], "other-tunnel")
    delete_writes = [call for call in plugin._chainstore_hsets if call["value"] is None]
    self.assertEqual(delete_writes, [])

    self.assertFalse(plugin._delete_tcp_route(public_port=30001, expected_tunnel_id="tunnel-id"))
    delete_writes = [call for call in plugin._chainstore_hsets if call["value"] is None]
    self.assertEqual(delete_writes, [])

  def test_attach_tcp_route_uses_metadata_port_hint(self):
    requests = _RequestsStub()
    plugin = make_plugin(requests)
    plugin._chainstore[plugin.cfg_tcp_routes_hkey] = {
      "30000": {
        "public_port": 30000,
        "public_host": "tcp.ratio1.link",
        "public_endpoint": "tcp.ratio1.link:30000",
        "hostname": "uuid-001.ratio1.link",
        "tunnel_id": "tunnel-id",
        "enabled": True,
      }
    }
    tunnel = {
      "id": "tunnel-id",
      "metadata": {
        "type": "tcp",
        "tcp_public_port": 30000,
      },
    }

    result = plugin._attach_tcp_route_to_tunnel(tunnel)

    self.assertEqual(result["tcp_route"]["hostname"], "uuid-001.ratio1.link")
    self.assertEqual(result["tcp_public_port"], 30000)
    self.assertEqual(result["tcp_public_host"], "tcp.ratio1.link")
    self.assertEqual(result["tcp_public_endpoint"], "tcp.ratio1.link:30000")
    self.assertNotIn("tcp_public_endpoint", result["metadata"])

  def test_attach_tcp_route_does_not_scan_without_matching_metadata_port(self):
    requests = _RequestsStub()
    plugin = make_plugin(requests)
    plugin._chainstore[plugin.cfg_tcp_routes_hkey] = {
      "30000": {
        "public_port": 30000,
        "hostname": "other.ratio1.link",
        "tunnel_id": "other-tunnel",
        "enabled": True,
      },
      "30001": {
        "public_port": 30001,
        "hostname": "uuid-001.ratio1.link",
        "tunnel_id": "tunnel-id",
        "enabled": True,
      },
    }
    tunnel = {
      "id": "tunnel-id",
      "metadata": {
        "type": "tcp",
        "tcp_public_port": 30000,
      },
    }

    result = plugin._attach_tcp_route_to_tunnel(tunnel)

    self.assertNotIn("tcp_route", result)
    self.assertEqual(result["metadata"]["tcp_public_port"], 30000)

  def test_tcp_route_sync_runs_only_on_init_and_process(self):
    requests = _RequestsStub()
    plugin = make_plugin(requests)

    self.assertEqual(TunnelsManagerPlugin.CONFIG["PROCESS_DELAY"], 5 * 60)

    plugin.on_init()

    self.assertEqual(
      [call["hkey"] for call in plugin._chainstore_hsyncs],
      ["tunnels_manager_secrets", plugin.cfg_tcp_routes_hkey],
    )

    plugin.process()

    self.assertEqual(
      [call["hkey"] for call in plugin._chainstore_hsyncs],
      ["tunnels_manager_secrets", plugin.cfg_tcp_routes_hkey, plugin.cfg_tcp_routes_hkey],
    )

  def test_tcp_route_allocation_uses_cached_chainstore_without_sync(self):
    requests = _RequestsStub()
    plugin = make_plugin(requests)

    def failing_hsync(**kwargs):
      raise Exception("sync failed")

    plugin.chainstore_hsync = failing_hsync

    route = plugin._claim_tcp_route(
      tunnel_id="tunnel-id",
      hostname="uuid-001.ratio1.link",
      alias="My TCP Tunnel",
    )

    self.assertEqual(route["public_port"], 30499)
    self.assertEqual(plugin.get_tcp_route(30499), "uuid-001.ratio1.link")

  def test_tcp_alias_creates_origin_hostname_only(self):
    requests = _RequestsStub(
      get_payloads=[
        {
          "success": True,
          "result": {
            "id": "tunnel-id",
            "metadata": {
              "dns_name": "uuid-001.ratio1.link",
              "custom_hostnames": [],
              "type": "tcp",
            },
          },
        },
      ],
      post_payloads=[
        {
          "success": True,
          "result": {
            "id": "alias-record-id",
          },
        },
      ],
      patch_payloads=[
        {
          "success": True,
          "result": {},
        },
      ],
    )
    plugin = make_plugin(requests)

    result = plugin.add_alias(
      tunnel_id="tunnel-id",
      alias="alias.ratio1.link",
      cloudflare_account_id="account-id",
      cloudflare_zone_id="zone-id",
      cloudflare_api_key="api-key",
      cloudflare_domain="ratio1.link",
    )

    self.assertTrue(result["success"])
    self.assertEqual(len(requests.posts), 1)
    self.assertEqual(requests.posts[0]["json"]["name"], "alias.ratio1.link")
    aliases = requests.patches[0]["json"]["metadata"]["aliases"]
    self.assertNotIn("public_id", aliases[0])
    self.assertEqual(aliases[0]["type"], "origin")


if __name__ == "__main__":
  unittest.main()
