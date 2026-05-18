import json
import unittest

from extensions.business.deeploy.tests.support import make_deeploy_plugin


PLUS_HKEY = "plus_preferred_nodes"


def make_preferred_nodes_plugin():
  plugin = make_deeploy_plugin()
  plugin._chainstore = {}
  plugin._chainstore_hset_result = True

  def chainstore_hget(hkey, key):
    return plugin._chainstore.get((hkey, key))

  def chainstore_hset(hkey, key, value):
    if not plugin._chainstore_hset_result:
      return False
    plugin._chainstore[(hkey, key)] = value
    return True

  plugin.chainstore_hget = chainstore_hget
  plugin.chainstore_hset = chainstore_hset
  return plugin


class DeeployPreferredNodesTests(unittest.TestCase):

  def test_load_returns_empty_list_when_not_stored(self):
    plugin = make_preferred_nodes_plugin()

    nodes = plugin.deeploy_load_preferred_nodes({"escrow_owner": "0xOwner"})

    self.assertEqual(nodes, [])

  def test_save_writes_canonical_cstore_payload_keyed_by_escrow_owner(self):
    plugin = make_preferred_nodes_plugin()

    nodes = plugin.deeploy_save_preferred_nodes(
      sender="0xSender",
      auth_result={"escrow_owner": "0xOwner"},
      preferred_nodes=[
        {
          "address": "  0xai_node_alpha  ",
          "alias": "  Alpha Node  ",
          "description": "  primary node  ",
          "createdAt": "2026-05-10T00:00:00.000Z",
          "updatedAt": "2026-05-10T01:00:00.000Z",
        },
      ],
    )

    self.assertEqual(nodes, [{
      "address": "0xai_node_alpha",
      "alias": "Alpha Node",
      "description": "primary node",
      "createdAt": "2026-05-10T00:00:00.000Z",
      "updatedAt": "2026-05-10T01:00:00.000Z",
    }])

    stored = plugin._chainstore[(PLUS_HKEY, "0xowner")]
    self.assertIsInstance(stored, str)
    payload = json.loads(stored)
    self.assertEqual(payload["version"], 1)
    self.assertEqual(payload["updated_by"], "0xSender")
    self.assertEqual(payload["nodes"], nodes)

  def test_load_accepts_legacy_node_without_alias(self):
    plugin = make_preferred_nodes_plugin()
    plugin._chainstore[(PLUS_HKEY, "0xowner")] = json.dumps({
      "version": 1,
      "nodes": [
        {
          "address": "0xai_node_alpha",
          "description": "primary",
        },
      ],
    })

    nodes = plugin.deeploy_load_preferred_nodes({"escrow_owner": "0xOwner"})

    self.assertEqual(nodes[0]["alias"], "0xai_node_alpha")
    self.assertEqual(nodes[0]["description"], "primary")

  def test_save_rejects_invalid_node_address(self):
    plugin = make_preferred_nodes_plugin()

    with self.assertRaisesRegex(ValueError, "Invalid preferred node address"):
      plugin.deeploy_save_preferred_nodes(
        sender="0xSender",
        auth_result={"escrow_owner": "0xOwner"},
        preferred_nodes=[{"address": "0x123", "alias": "Invalid"}],
      )

    self.assertNotIn((PLUS_HKEY, "0xowner"), plugin._chainstore)

  def test_save_rejects_missing_preferred_nodes_payload(self):
    plugin = make_preferred_nodes_plugin()

    with self.assertRaisesRegex(ValueError, "'preferred_nodes' must be a list"):
      plugin.deeploy_save_preferred_nodes(
        sender="0xSender",
        auth_result={"escrow_owner": "0xOwner"},
        preferred_nodes=None,
      )

    self.assertNotIn((PLUS_HKEY, "0xowner"), plugin._chainstore)

  def test_save_raises_when_cstore_write_fails(self):
    plugin = make_preferred_nodes_plugin()
    plugin._chainstore_hset_result = False

    with self.assertRaisesRegex(ValueError, "Failed to save Preferred Nodes"):
      plugin.deeploy_save_preferred_nodes(
        sender="0xSender",
        auth_result={"escrow_owner": "0xOwner"},
        preferred_nodes=[{"address": "0xai_node_alpha", "alias": "Alpha"}],
      )

    self.assertNotIn((PLUS_HKEY, "0xowner"), plugin._chainstore)

  def test_save_rejects_oversize_list(self):
    plugin = make_preferred_nodes_plugin()

    with self.assertRaisesRegex(ValueError, "too many preferred nodes"):
      plugin.deeploy_save_preferred_nodes(
        sender="0xSender",
        auth_result={"escrow_owner": "0xOwner"},
        preferred_nodes=[
          {"address": f"0xai_node_{idx}", "alias": f"Node {idx}"}
          for idx in range(101)
        ],
      )

  def test_plus_level_shim_enables_active_escrow_users(self):
    plugin = make_preferred_nodes_plugin()

    self.assertEqual(
      plugin.get_plus_level_for_escrow(
        sender="0xSender",
        sender_escrow="0xEscrow",
        escrow_owner="0xOwner",
      ),
      1,
    )

  def test_plus_level_uses_available_backend_contract_helper(self):
    plugin = make_preferred_nodes_plugin()
    plugin.bc = type("BCStub", (), {
      "get_csp_plus_level": lambda self, escrow_address: 0,
    })()

    self.assertEqual(
      plugin.get_plus_level_for_escrow(
        sender="0xSender",
        sender_escrow="0xEscrow",
        escrow_owner="0xOwner",
      ),
      0,
    )


if __name__ == "__main__":
  unittest.main()
