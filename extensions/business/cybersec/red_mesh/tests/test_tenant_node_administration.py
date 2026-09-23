"""Tenant assignment administration through real policy and CStore adapters."""
import json
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError


def assignment_location(*ids):
  # Independent contract fixture: do not derive physical corruption keys from the adapter.
  return ('["redmesh","tenancy",1,"deployment"]',
          json.dumps(["tenant_node", "deployment", *ids], separators=(",", ":")))


class TestTenantNodeAdministration(unittest.TestCase):
  def setUp(self):
    self.env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    self.env.start()
    self.addCleanup(self.env.stop)
    self.owner = FakeAdministrationStore()
    self.store = CstoreTenantAdministrationStore(self.owner, "deployment")
    self.peers = ["Node-B", "Node-A"]
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.owner), self.store,
                                              configured_peers_reader=lambda: self.peers)
    self.actor = {"account_id": "creator"}
    self.tenant = self.create_tenant("one")

  def create_tenant(self, domain):
    request = str(uuid4())
    # RM-083: an account belongs to one tenant, so each further tenant gets its own initial admin.
    admin = "initial" if domain == "one" else f"initial-{domain}"
    if admin != "initial":
      self.owner.account(admin)
    prepared = self.service.prepare_tenant(self.actor, request, domain, domain, admin)
    self.assertTrue(prepared["success"], prepared)
    tenant = prepared["data"]["tenantId"]
    self.owner.grant(admin, tenant)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])
    return tenant

  def test_assignment_roundtrip_returns_only_sorted_active_nodes_and_scoped_hint(self):
    self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["data"],
                     {"tenantId": self.tenant, "nodes": [], "canManageAssignments": True})
    for address in self.peers:
      result = self.service.set_tenant_node_assignment(self.actor, self.tenant, address, True)
      self.assertEqual(result["data"], {"tenantId": self.tenant, "nodeAddress": address, "active": True})
    self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["data"]["nodes"],
                     [{"nodeAddress": "Node-A"}, {"nodeAddress": "Node-B"}])
    self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-B", False)
    view = self.service.get_tenant_nodes({"account_id": "initial"}, self.tenant)["data"]
    self.assertEqual(view, {"tenantId": self.tenant, "nodes": [{"nodeAddress": "Node-A"}],
                            "canManageAssignments": False})

  def test_activation_requires_lazy_valid_current_config_even_on_retry(self):
    result = self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
    self.assertTrue(result["success"])
    before = len(self.owner.writes)
    for peers, status in (([], 400), (["node-a"], 400), (None, 503), ("Node-A", 503),
                           ([None], 503), (["Node-A", "bad address"], 503)):
      with self.subTest(peers=peers):
        self.peers = peers
        result = self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
        self.assertEqual(result["status_code"], status)
        self.assertNotIn("Node-A", str(result))
        self.assertEqual(len(self.owner.writes), before)
    def broken_config():
      raise RuntimeError("private peer list")
    self.service.configured_peers_reader = broken_config
    self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True),
                     {"success": False, "status": "error", "status_code": 503, "error": "unavailable"})
    self.assertTrue(self.service.get_tenant_nodes(self.actor, self.tenant)["success"])
    self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", False)["success"])
    self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "never-assigned", False)["status_code"], 404)

  def test_corrupt_assignment_rejected_by_point_read_write_and_enumeration_including_inactive(self):
    self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
    location = assignment_location(self.tenant, "Node-A")
    good = self.store.get("tenant_node", self.tenant, "Node-A")
    for changes in ({"tenant_id": "foreign"}, {"node_address": "Node-B"}, {"active": 0},
                    {"changed_by": None}, {"changed_by": " Creator "}, {"changed_at": None},
                    {"changed_at": "2026-09-10"}, {"changed_at": "2026-09-10T00:00:00+01:00"},
                    {"active": False, "changed_by": {}}, {"changed_at": "private corrupt value"}):
      with self.subTest(changes=changes):
        bad = {**good, **changes}
        self.owner.data[location] = bad
        before = len(self.owner.writes)
        with self.assertRaises(TenantStoreError):
          self.store.get("tenant_node", self.tenant, "Node-A")
        with self.assertRaises(TenantStoreError):
          self.store.put("tenant_node", self.tenant, "Node-A", record=bad)
        self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["status_code"], 503)
        self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)["status_code"], 503)
        self.assertEqual(len(self.owner.writes), before)
    self.owner.data[location] = good

  def test_enumeration_filters_foreign_corruption_before_validating_local_fields(self):
    other = self.create_tenant("other")
    self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
    hkey, _ = assignment_location(self.tenant, "Node-A")
    for field in (["tenant_node", "deployment", other, None],
                  ["tenant_node", "foreign", self.tenant, None]):
      # Noncanonical whitespace, malformed IDs and payload are foreign to this projection.
      self.owner.data[(hkey, json.dumps(field))] = "private corrupt data"
    expected = [{"nodeAddress": "Node-A"}]
    self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["data"]["nodes"], expected)
    for ids in ((self.tenant,), (self.tenant, "Node-B", "extra"), (self.tenant, None)):
      with self.subTest(ids=ids):
        location = (hkey, json.dumps(["tenant_node", "deployment", *ids], separators=(",", ":")))
        self.owner.data[location] = {"schemaVersion": 1, "namespace": "deployment",
                                     "kind": "tenant_node", "ids": list(ids)}
        self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["status_code"], 503)
        del self.owner.data[location]
    noncanonical = (hkey, json.dumps(["tenant_node", "deployment", self.tenant, "Node-B"]))
    self.owner.data[noncanonical] = "corrupt"
    self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["status_code"], 503)
    # A canonical target mutation neither enumerates nor silently repairs another physical row.
    self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-B", True)["success"])
    self.assertEqual(self.owner.data[noncanonical], "corrupt")
    self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["status_code"], 503)

  def test_exact_address_and_literal_bool_validation_does_not_read_config_or_write(self):
    invalid_addresses = (None, 1, [], {}, "", " node", "node ", "a\nb", "a\x00b", "a\x7fb",
                         "a\x85b", "a\x9fb", "a\u00a0b", "a\u1680b", "a\u2003b", "a\u2028b",
                         "a\u202fb", "a\u3000b", "a\ufeffb", "\U0001f600" * 257)
    reader = Mock(side_effect=AssertionError("Invalid input must not inspect config"))
    self.service.configured_peers_reader = reader
    before = len(self.owner.writes)
    for address, active in [(value, True) for value in invalid_addresses] + [
        ("Node-A", value) for value in (0, 1, "true", "false", None, [], {})]:
      with self.subTest(address=address, active=active):
        self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, address, active)["status_code"], 400)
    reader.assert_not_called()
    self.assertEqual(len(self.owner.writes), before)
    supplementary = "\U0001f600" * 256
    self.service.configured_peers_reader = lambda: [supplementary, "n", "NODE"]
    for address in (supplementary, "n", "NODE"):
      self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, address, True)["success"])
    self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "node", True)["status_code"], 400)

  def test_each_named_role_and_mixed_scope_reauthorization_precedes_config(self):
    other = self.create_tenant("other")
    roles = ("super_tenant_admin", "super_pentester", "tenant_admin", "tenant_pentester", "tenant_user")
    for role in roles:
      with self.subTest(role=role):
        scope = None if role == "super_tenant_admin" else self.tenant
        self.owner.account("member", memberships=[{"role": role, "tenant_id": scope}])
        member = {"account_id": "member", "role": "admin", "tenant_id": other}
        reader = Mock(return_value=self.peers)
        self.service.configured_peers_reader = reader
        view = self.service.get_tenant_nodes(member, self.tenant)
        self.assertEqual(view["data"]["canManageAssignments"], role == "super_tenant_admin")
        reader.assert_not_called()
        before = len(self.owner.writes)
        result = self.service.set_tenant_node_assignment(member, self.tenant, "Node-A", True)
        self.assertEqual(result["status_code"], 200 if role == "super_tenant_admin" else 403)
        if role != "super_tenant_admin":
          reader.assert_not_called()
          self.assertEqual(len(self.owner.writes), before)
    # RM-083: a mixed-scope account is denied as a whole.
    self.owner.account("member", memberships=[{"role": "tenant_user", "tenant_id": self.tenant},
                                               {"role": "super_tenant_admin", "tenant_id": None}])
    reader = Mock(side_effect=AssertionError("Denied request must not inspect config"))
    self.service.configured_peers_reader = reader
    self.assertEqual(self.service.set_tenant_node_assignment(member, self.tenant, "Node-A", True)["status_code"], 404)
    self.owner.account("member", memberships=[{"role": "super_tenant_admin", "tenant_id": other}])
    self.assertEqual(self.service.get_tenant_nodes(member, self.tenant)["status_code"], 404)
    self.assertEqual(self.service.set_tenant_node_assignment(member, self.tenant, "Node-A", False)["status_code"], 404)
    self.owner.account("member", active=False, memberships=[{"role": "super_tenant_admin", "tenant_id": self.tenant}])
    self.assertFalse(self.service.set_tenant_node_assignment(member, self.tenant, "Node-A", False)["success"])
    reader.assert_not_called()

  def test_retry_preserves_attribution_and_unknown_fields_but_changes_are_attributed(self):
    self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
    row = self.store.get("tenant_node", self.tenant, "Node-A")
    row["future_binding"] = {"version": 2}
    self.store.put("tenant_node", self.tenant, "Node-A", record=row)
    before = len(self.owner.writes)
    self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)["success"])
    self.assertEqual(len(self.owner.writes), before)
    self.assertEqual(self.store.get("tenant_node", self.tenant, "Node-A"), row)
    self.owner.account("second", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.assertTrue(self.service.set_tenant_node_assignment({"account_id": "second"}, self.tenant, "Node-A", False)["success"])
    changed = self.store.get("tenant_node", self.tenant, "Node-A")
    self.assertEqual(changed["changed_by"], "second")
    self.assertEqual(changed["future_binding"], row["future_binding"])
    before = len(self.owner.writes)
    self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", False)["success"])
    self.assertEqual(len(self.owner.writes), before)
    self.assertEqual(self.store.get("tenant_node", self.tenant, "Node-A"), changed)

  def test_before_after_and_unverified_writes_return_unavailable_and_retry_reconciles(self):
    for after in (False, True):
      with self.subTest(after=after):
        address = "after" if after else "before"
        self.peers.append(address)
        self.owner.fail_write = len(self.owner.writes) + 1
        self.owner.fail_after_write = after
        result = self.service.set_tenant_node_assignment(self.actor, self.tenant, address, True)
        self.assertEqual(result, {"success": False, "status": "error", "status_code": 503, "error": "unavailable"})
        row = self.store.get("tenant_node", self.tenant, address)
        self.assertEqual(row is not None, after)
        before = len(self.owner.writes)
        self.owner.fail_write = None
        self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, address, True)["success"])
        self.assertEqual(len(self.owner.writes), before if after else before + 1)
    self.owner.noop = True
    self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)["status_code"], 503)
    self.owner.noop = False
    for acknowledgement in (False, None, 1):
      with self.subTest(acknowledgement=acknowledgement):
        with patch.object(self.owner, "chainstore_hset", return_value=acknowledgement):
          self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)["status_code"], 503)

  def test_two_serving_owners_observe_shared_overlapping_assignments_without_other_nodes(self):
    other = self.create_tenant("other")
    for tenant, address in ((self.tenant, "Node-A"), (other, "Node-A"), (other, "Node-B")):
      self.assertTrue(self.service.set_tenant_node_assignment(self.actor, tenant, address, True)["success"])
    second_owner = FakeAdministrationStore()
    second_owner.data = self.owner.data
    second_service = TenantAdministrationService(CstoreAuthAccountReader(second_owner),
      CstoreTenantAdministrationStore(second_owner, "deployment"))
    for tenant in (self.tenant, other):
      self.assertEqual(second_service.get_tenant_nodes(self.actor, tenant),
                       self.service.get_tenant_nodes(self.actor, tenant))
    self.assertTrue(second_service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", False)["success"])
    self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["data"]["nodes"], [])
    self.assertEqual(len(self.service.get_tenant_nodes(self.actor, other)["data"]["nodes"]), 2)

  def test_enumeration_bound_read_failures_and_pending_publication_fail_closed(self):
    with patch("extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration.MAX_ENUMERATED_RECORDS", 0):
      self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["status_code"], 503)
    with patch.object(self.owner, "chainstore_hgetall", side_effect=RuntimeError("private storage")):
      self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["status_code"], 503)
    with patch.object(self.owner, "chainstore_hget", side_effect=RuntimeError("private storage")):
      self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)["status_code"], 503)
    self.owner.account("initial-pending")
    pending = self.service.prepare_tenant(self.actor, str(uuid4()), "Pending", "pending",
                                          "initial-pending")["data"]["tenantId"]
    self.assertEqual(self.service.get_tenant_nodes(self.actor, pending)["status_code"], 404)
    self.assertEqual(self.service.set_tenant_node_assignment(self.actor, pending, "Node-A", True)["status_code"], 404)

  def test_assignment_envelope_and_physical_ids_are_bound_on_get_put_and_list(self):
    self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
    good = self.store.get("tenant_node", self.tenant, "Node-A")
    location = assignment_location(self.tenant, "Node-A")
    for changes in ({"schemaVersion": True}, {"schemaVersion": 2}, {"namespace": "foreign"},
                    {"kind": "tenant"}, {"ids": [self.tenant, "Node-B"]}):
      with self.subTest(changes=changes):
        bad = {**good, **changes}
        self.owner.data[location] = bad
        with self.assertRaises(TenantStoreError):
          self.store.get("tenant_node", self.tenant, "Node-A")
        with self.assertRaises(TenantStoreError):
          self.store.put("tenant_node", self.tenant, "Node-A", record=bad)
        with self.assertRaises(TenantStoreError):
          self.store.list_node_assignments(self.tenant)
    self.owner.data[location] = good
    for ids in ((self.tenant,), (self.tenant, "Node-B", "extra"), (self.tenant, "bad\ufeffaddress")):
      with self.subTest(ids=ids):
        bad = {**good, "ids": list(ids), "node_address": ids[-1]}
        bad_location = assignment_location(*ids)
        self.owner.data[bad_location] = bad
        with self.assertRaises(TenantStoreError):
          self.store.get("tenant_node", *ids)
        with self.assertRaises(TenantStoreError):
          self.store.put("tenant_node", *ids, record=bad)
        with self.assertRaises(TenantStoreError):
          self.store.list_node_assignments(self.tenant)
        del self.owner.data[bad_location]
    for raw in ("private malformed json", [], 0):
      with self.subTest(raw=raw):
        self.owner.data[location] = raw
        self.assertEqual(self.service.get_tenant_nodes(self.actor, self.tenant)["status_code"], 503)
        self.assertEqual(self.service.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", False)["status_code"], 503)
