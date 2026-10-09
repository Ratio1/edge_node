"""RM-126: the deployment's node directory and the two reads that carry it."""
import unittest
from unittest.mock import patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from .contract_fixture import contract_terms, install_contract
from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy.deployment_nodes import MISSING_ID, named_entry, node_directory


class FakeNetmon:
  """Answers like `NetworkMonitor`: an alias or `MISSING_ID`, and a tag list."""
  def __init__(self, nodes):
    self.nodes = nodes
    self.asked = []

  def network_node_eeid(self, addr):
    self.asked.append(addr)
    return self.nodes.get(addr, {}).get("alias", MISSING_ID)

  def get_network_node_tags(self, addr):
    return self.nodes.get(addr, {}).get("tags", [])


class BrokenNetmon:
  def network_node_eeid(self, addr):
    raise RuntimeError("netmon down")

  def get_network_node_tags(self, addr):
    raise RuntimeError("netmon down")


NETMON = FakeNetmon({
  "0xai_rm3": {"alias": "rm3", "tags": ["KYB", "DC:google", "CT:BE", 7]},
  "0xai_rm4": {"alias": MISSING_ID, "tags": "CT:BE"},
})


class TestNodeDirectory(unittest.TestCase):
  def test_names_a_seen_peer_and_keeps_only_string_tags(self):
    self.assertEqual(node_directory(NETMON, ["0xai_rm3"]),
                     {"0xai_rm3": {"alias": "rm3", "tags": ["KYB", "DC:google", "CT:BE"]}})

  def test_an_unseen_peer_a_missing_monitor_and_a_failing_one_name_nothing(self):
    unseen = {"alias": None, "tags": []}
    self.assertEqual(node_directory(NETMON, ["0xai_rm4", "0xai_new"]), {"0xai_rm4": unseen, "0xai_new": unseen})
    self.assertEqual(node_directory(None, ["0xai_rm3"]), {"0xai_rm3": unseen})
    self.assertEqual(node_directory(BrokenNetmon(), ["0xai_rm3"]), {"0xai_rm3": unseen})

  def test_keeps_the_given_order_and_passes_addresses_as_they_are(self):
    netmon = FakeNetmon({})
    self.assertEqual(list(node_directory(netmon, ["0xai_b", "0xai_a"])), ["0xai_b", "0xai_a"])
    self.assertEqual(netmon.asked, ["0xai_b", "0xai_a"])

  def test_named_entry_sanitizes_a_malformed_directory(self):
    unseen = {"alias": None, "tags": []}
    self.assertEqual(named_entry({}, "x"), unseen)
    self.assertEqual(named_entry(None, "x"), unseen)
    self.assertEqual(named_entry({"x": "rm3"}, "x"), unseen)
    self.assertEqual(named_entry({"x": {"alias": "", "tags": None}}, "x"), unseen)
    self.assertEqual(named_entry({"x": {"alias": 3, "tags": ["a", 1]}}, "x"), {"alias": None, "tags": ["a"]})


class TestDeploymentNodeReads(unittest.TestCase):
  def setUp(self):
    self.env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    self.env.start()
    self.addCleanup(self.env.stop)
    self.owner = FakeAdministrationStore()
    self.store = CstoreTenantAdministrationStore(self.owner, "deployment")
    self.peers = ["0xai_rm4", "0xai_rm3"]
    self.netmon = NETMON
    self.service = TenantAdministrationService(
      CstoreAuthAccountReader(self.owner), self.store,
      configured_peers_reader=lambda: self.peers,
      node_directory_reader=lambda addresses: node_directory(self.netmon, addresses))
    self.actor = {"account_id": "creator"}

  def create_tenant(self):
    request = str(uuid4())
    prepared = self.service.prepare_tenant(self.actor, request, "one", "one", "initial", **contract_terms())
    self.assertTrue(prepared["success"], prepared)
    tenant = prepared["data"]["tenantId"]
    self.owner.grant("initial", tenant)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])
    return tenant

  def test_lists_the_configured_peers_in_configured_order_with_names(self):
    self.assertEqual(self.service.list_deployment_nodes(self.actor), {"success": True, "status_code": 200, "data": {
      "nodes": [{"nodeAddress": "0xai_rm4", "alias": None, "tags": []},
                {"nodeAddress": "0xai_rm3", "alias": "rm3", "tags": ["KYB", "DC:google", "CT:BE"]}]}})

  def test_only_a_full_portfolio_super_tenant_admin_reads_the_list(self):
    tenant = self.create_tenant()
    self.owner.account("pentester", memberships=[{"role": "super_pentester", "tenant_id": tenant}])
    for account in ("initial", "pentester", "nobody"):
      result = self.service.list_deployment_nodes({"account_id": account})
      self.assertFalse(result["success"], account)
      self.assertNotIn("nodes", result)
      self.assertNotIn("0xai_rm3", str(result))

  def test_a_malformed_or_failing_configuration_is_unavailable_and_an_empty_one_lists_nothing(self):
    for peers in ("0xai_rm3", ["bad address"], None):
      self.peers = peers
      self.assertEqual(self.service.list_deployment_nodes(self.actor)["status_code"], 503, peers)
    def explode():
      raise RuntimeError("config")
    self.service.configured_peers_reader = explode
    self.assertEqual(self.service.list_deployment_nodes(self.actor)["status_code"], 503)
    self.service.configured_peers_reader = lambda: []
    self.assertEqual(self.service.list_deployment_nodes(self.actor)["data"], {"nodes": []})

  def test_a_missing_or_failing_directory_names_nothing_but_never_fails_the_read(self):
    def explode(addresses):
      raise RuntimeError("netmon")
    for reader in (None, explode, lambda addresses: "not a dict"):
      self.service.node_directory_reader = reader
      self.assertEqual(self.service.list_deployment_nodes(self.actor)["data"]["nodes"],
                       [{"nodeAddress": "0xai_rm4", "alias": None, "tags": []},
                        {"nodeAddress": "0xai_rm3", "alias": None, "tags": []}])

  def test_the_tenants_own_rows_carry_the_same_names(self):
    tenant = self.create_tenant()
    for address in self.peers:
      self.assertTrue(self.service.set_tenant_node_assignment(self.actor, tenant, address, True)["success"])
    rows = self.service.get_tenant_nodes({"account_id": "initial"}, tenant)["data"]["nodes"]
    self.assertEqual(rows, [
      {"nodeAddress": "0xai_rm3", "mode": "shared", "state": "assigned", "alias": "rm3", "tags": ["KYB", "DC:google", "CT:BE"]},
      {"nodeAddress": "0xai_rm4", "mode": "shared", "state": "assigned", "alias": None, "tags": []}])
    self.service.node_directory_reader = None
    rows = self.service.get_tenant_nodes({"account_id": "initial"}, tenant)["data"]["nodes"]
    self.assertEqual([row["alias"] for row in rows], [None, None])


class TestDeploymentNodesPlugin(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    environment.start()
    self.addCleanup(environment.stop)
    self.storage = FakeAdministrationStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.cfg_chainstore_peers = ["0xai_rm3", "0xai_rm4"]
    self.plugin.cfg_instance_id = "pentester-api-01"
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.storage, name))
    self.actor = {"account_id": "creator"}

  def test_the_endpoint_names_the_peers_from_the_network_monitor(self):
    self.plugin.netmon = NETMON
    self.assertEqual(self.plugin.list_deployment_nodes(self.actor)["data"]["nodes"], [
      {"nodeAddress": "0xai_rm3", "alias": "rm3", "tags": ["KYB", "DC:google", "CT:BE"]},
      {"nodeAddress": "0xai_rm4", "alias": None, "tags": []}])

  def test_without_a_network_monitor_the_endpoint_still_lists_the_peers(self):
    self.assertEqual([node["alias"] for node in self.plugin.list_deployment_nodes(self.actor)["data"]["nodes"]],
                     [None, None])

  def test_the_endpoint_refuses_a_tenant_admin(self):
    request = str(uuid4())
    result = self.plugin.prepare_tenant(self.actor, request, "one", "one", "initial", **install_contract(self.plugin, ref="doc-one"))
    self.assertTrue(result["success"], result)
    self.storage.grant("initial", result["data"]["tenantId"])
    self.assertTrue(self.plugin.activate_tenant(self.actor, request)["success"])
    denied = self.plugin.list_deployment_nodes({"account_id": "initial"})
    self.assertEqual((denied["success"], denied["status_code"]), (False, 403))
