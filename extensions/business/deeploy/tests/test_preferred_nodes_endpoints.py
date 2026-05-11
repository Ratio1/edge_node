import json
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

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_STATUS
from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin


class _InputsStub(dict):
  def __getattr__(self, item):
    try:
      return self[item]
    except KeyError as exc:
      raise AttributeError(item) from exc


def make_endpoint_plugin():
  plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
  plugin._chainstore = {}
  plugin.cfg_deeploy_verbose = 0
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  plugin._get_response = lambda dct_data: dct_data
  plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("0xSender", _InputsStub(request))
  plugin.deeploy_get_auth_result = lambda inputs: {
    DEEPLOY_KEYS.SENDER: "0xSender",
    DEEPLOY_KEYS.SENDER_ESCROW: "0xEscrow",
    DEEPLOY_KEYS.ESCROW_OWNER: "0xOwner",
  }
  plugin.chainstore_hget = lambda hkey, key: plugin._chainstore.get((hkey, key))

  def chainstore_hset(hkey, key, value):
    plugin._chainstore[(hkey, key)] = value
    return True

  plugin.chainstore_hset = chainstore_hset
  return plugin


class DeeployPreferredNodesEndpointTests(unittest.TestCase):

  def test_get_preferred_nodes_returns_empty_list(self):
    plugin = make_endpoint_plugin()

    res = plugin.get_preferred_nodes({"nonce": "0x1"})

    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(res[DEEPLOY_KEYS.PLUS_LEVEL], 1)
    self.assertEqual(res[DEEPLOY_KEYS.PREFERRED_NODES], [])
    self.assertEqual(res[DEEPLOY_KEYS.AUTH][DEEPLOY_KEYS.ESCROW_OWNER], "0xOwner")

  def test_save_preferred_nodes_persists_normalized_nodes(self):
    plugin = make_endpoint_plugin()

    res = plugin.save_preferred_nodes({
      "nonce": "0x1",
      "preferred_nodes": [
        {
          "address": "  0xai_node_alpha  ",
          "alias": "  Alpha  ",
        },
      ],
    })

    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(res[DEEPLOY_KEYS.PREFERRED_NODES][0]["alias"], "Alpha")
    stored = json.loads(plugin._chainstore[("plus_preferred_nodes", "0xowner")])
    self.assertEqual(stored["nodes"], res[DEEPLOY_KEYS.PREFERRED_NODES])

  def test_save_preferred_nodes_rejects_missing_payload(self):
    plugin = make_endpoint_plugin()

    res = plugin.save_preferred_nodes({"nonce": "0x1"})

    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.FAIL)
    self.assertIn("'preferred_nodes' is required", res[DEEPLOY_KEYS.ERROR])
    self.assertNotIn(("plus_preferred_nodes", "0xowner"), plugin._chainstore)

  def test_get_preferred_nodes_rejects_plus_level_zero(self):
    plugin = make_endpoint_plugin()
    plugin.get_plus_level_for_escrow = lambda sender, sender_escrow, escrow_owner: 0

    res = plugin.get_preferred_nodes({"nonce": "0x1"})

    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.FAIL)
    self.assertIn("Plus+", res[DEEPLOY_KEYS.ERROR])


if __name__ == "__main__":
  unittest.main()
