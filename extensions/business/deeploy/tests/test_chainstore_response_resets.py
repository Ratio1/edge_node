import unittest

from extensions.business.deeploy.tests.support import make_deeploy_plugin


class DeeployChainstoreResponseResetTests(unittest.TestCase):

  def _make_plugin(self, seed_nodes=None, selected_seed=None):
    plugin = make_deeploy_plugin()
    plugin.ee_addr = "initiating-oracle"
    plugin.seed_nodes = seed_nodes or ["seed-oracle-1", "seed-oracle-2"]
    plugin.selected_seed = selected_seed or plugin.seed_nodes[0]
    plugin.chainstore_calls = []
    plugin._get_chainstore_response_seed_nodes = lambda: plugin.seed_nodes

    def select_seed(seed_peers):
      plugin.seed_selection_input = list(seed_peers)
      if plugin.selected_seed in seed_peers:
        return plugin.selected_seed
      return seed_peers[0] if seed_peers else None

    def chainstore_set(*args, **kwargs):
      plugin.chainstore_calls.append((args, kwargs))
      return True

    plugin._select_chainstore_response_seed_peer = select_seed
    plugin.chainstore_set = chainstore_set
    return plugin

  def test_reset_chainstore_response_keys_targets_one_seed_oracle_only(self):
    plugin = self._make_plugin(selected_seed="seed-oracle-2")

    result = plugin._reset_chainstore_response_keys({
      "target-chainstore-peer": ["response-key-1", "response-key-2"],
    })

    self.assertEqual(result, {
      "target-chainstore-peer": ["response-key-1", "response-key-2"],
    })
    self.assertEqual(len(plugin.chainstore_calls), 2)
    for args, kwargs in plugin.chainstore_calls:
      self.assertEqual(args[1], None)
      self.assertEqual(kwargs["extra_peers"], ["seed-oracle-2"])
      self.assertEqual(kwargs["include_default_peers"], False)
      self.assertEqual(kwargs["include_configured_peers"], False)
      self.assertEqual(kwargs["debug"], True)

  def test_reset_peer_selection_excludes_current_oracle_when_possible(self):
    plugin = self._make_plugin(
      seed_nodes=["initiating-oracle", "seed-oracle-2"],
      selected_seed="seed-oracle-2",
    )

    peers = plugin._get_chainstore_response_local_reset_peers()

    self.assertEqual(peers, ["seed-oracle-2"])
    self.assertEqual(plugin.seed_selection_input, ["seed-oracle-2"])

  def test_reset_chainstore_response_keys_does_not_use_chainstore_peer_addresses(self):
    plugin = self._make_plugin(selected_seed="seed-oracle-1")

    plugin._reset_chainstore_response_keys({
      "app-chainstore-peer-1": ["response-key-1"],
      "app-chainstore-peer-2": ["response-key-2"],
    })

    for _, kwargs in plugin.chainstore_calls:
      self.assertEqual(kwargs["extra_peers"], ["seed-oracle-1"])
      self.assertNotIn("app-chainstore-peer-1", kwargs["extra_peers"])
      self.assertNotIn("app-chainstore-peer-2", kwargs["extra_peers"])


if __name__ == "__main__":
  unittest.main()
