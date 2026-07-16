import unittest

from extensions.business.dauth.dauth_mixin import _DauthMixin
from extensions.business.dauth.dauth_registry import (
  dauth_registry_write_kwargs,
  load_dauth_registry_snapshot,
  pipeline_registry_write_kwargs,
)


class _RegistryBCStub:
  address = "node-local"
  eth_address = "0xLOCAL"

  def __init__(self, remote_available=True):
    self.calls = 0
    self.remote_available = remote_available

  def get_eth_dauth_oracles(self):
    self.calls += 1
    return ["0xLOCAL", "0xREMOTE", "0xUNKNOWN"]

  def eth_addr_to_internal_addr(self, eth_address):
    if self.remote_available and eth_address == "0xREMOTE":
      return "node-remote"
    return None


class _ProtocolOracleBCStub:
  def get_eth_oracles(self):
    return ["0xOracleA", "0xOracleB"]


class _DauthStub(_DauthMixin):
  def __init__(self):
    self._dauth_registry_internal_peers = ["dauth-a", "dauth-b"]
    self.writes = []

  def chainstore_hset(self, **kwargs):
    self.writes.append(kwargs)
    return True


class DauthSecretRoutingTests(unittest.TestCase):
  def test_registry_snapshot_uses_one_rpc_and_maps_every_known_peer(self):
    class _Plugin:
      bc = _RegistryBCStub()

    peers, eth_oracles = load_dauth_registry_snapshot(_Plugin())

    self.assertEqual(_Plugin.bc.calls, 1)
    self.assertEqual(peers, ["node-local", "node-remote"])
    self.assertEqual(eth_oracles, ["0xLOCAL", "0xREMOTE", "0xUNKNOWN"])

  def test_routing_refreshes_internal_mappings_without_another_rpc(self):
    class _Plugin:
      bc = _RegistryBCStub(remote_available=False)

    plugin = _Plugin()
    peers, eth_oracles = load_dauth_registry_snapshot(plugin)
    plugin._dauth_registry_eth_oracles = eth_oracles
    plugin._dauth_registry_internal_peers = peers
    plugin.bc.remote_available = True

    routing = dauth_registry_write_kwargs(plugin)

    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(routing["extra_peers"], ["node-local", "node-remote"])

  def test_secret_storage_targets_only_cached_dauth_registry_peers(self):
    plugin = _DauthStub()

    plugin._save_dauth_job_secret_bundle(
      "7",
      {"job_id": "7", "job_secrets": {}},
    )

    write = plugin.writes[0]
    self.assertEqual(write["extra_peers"], ["dauth-a", "dauth-b"])
    self.assertFalse(write["include_default_peers"])
    self.assertFalse(write["include_configured_peers"])

  def test_explicit_peer_builders_support_non_manager_callers(self):
    plugin = object()

    secret_routing = dauth_registry_write_kwargs(plugin, peers=["dauth-a"])
    pipeline_routing = pipeline_registry_write_kwargs(plugin, peers=["dauth-a"])

    self.assertEqual(secret_routing["extra_peers"], ["dauth-a"])
    self.assertFalse(secret_routing["include_default_peers"])
    self.assertFalse(secret_routing["include_configured_peers"])
    self.assertEqual(pipeline_routing["extra_peers"], ["dauth-a"])
    self.assertTrue(pipeline_routing["include_default_peers"])
    self.assertTrue(pipeline_routing["include_configured_peers"])

  def test_secret_storage_fails_without_startup_cached_peers(self):
    plugin = _DauthStub()
    plugin._dauth_registry_internal_peers = []

    with self.assertRaisesRegex(ValueError, "not cached"):
      plugin._save_dauth_job_secret_bundle(
        "7",
        {"job_id": "7", "job_secrets": {}},
      )

    self.assertEqual(plugin.writes, [])

  def test_all_protocol_oracles_remain_authorized_writers(self):
    plugin = _DauthStub()
    plugin.bc = _ProtocolOracleBCStub()

    self.assertTrue(plugin._is_protocol_oracle_eth("0xoraclea"))
    self.assertTrue(plugin._is_protocol_oracle_eth("0xOracleB"))
    self.assertFalse(plugin._is_protocol_oracle_eth("0xNotOracle"))


if __name__ == "__main__":
  unittest.main()
