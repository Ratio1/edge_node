"""Administration persistence against the real CStore adapter and a fake external store."""
import copy
import json
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import (
  CstoreTenantAdministrationStore,
)
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_tenant import CstoreTenantReader
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError


class Store:
  def __init__(self):
    self.records = {}
    self.write_result = True
    self.write_noop = False

  def chainstore_hget(self, hkey, key):
    return copy.deepcopy(self.records.get((hkey, key)))

  def chainstore_hset(self, hkey, key, value):
    if not self.write_noop:
      self.records[hkey, key] = copy.deepcopy(value)
    return self.write_result

  def chainstore_hgetall(self, hkey):
    return {key: copy.deepcopy(value) for (scope, key), value in self.records.items()
            if scope == hkey}


class TestAdministrationStore(unittest.TestCase):
  def test_published_tenant_round_trips_through_existing_policy_reader(self):
    owner = Store()
    store = CstoreTenantAdministrationStore(owner, "deployment-a")
    store.put("tenant", "tn_a", record={"tenant_id": "tn_a", "active": True,
                                      "allow_pentester": False})
    row = store.get("tenant", "tn_a")
    self.assertEqual(row, {"schemaVersion": 1, "namespace": "deployment-a",
                          "kind": "tenant", "ids": ["tn_a"], "tenant_id": "tn_a",
                          "active": True, "allow_pentester": False})
    self.assertFalse(CstoreTenantReader(owner, "deployment-a")
                     .get_tenant_policy("tn_a").allow_pentester)

  def test_list_omits_pending_foundation_and_other_namespace_rows(self):
    owner = Store()
    store = CstoreTenantAdministrationStore(owner, "deployment-a")
    store.put("tenant", "tn_a", record={"tenant_id": "tn_a", "active": True,
                                      "allow_pentester": False})
    store.put("tenant", "tn_pending", record={"tenant_id": "tn_pending", "active": False,
                                            "allow_pentester": False})
    store.put("receipt", "alice", "request", record={"tenant_id": "tn_pending"})
    hkey = '["redmesh","tenancy",1,"deployment-a"]'
    owner.records[hkey, '["tenant","deployment-a","old"]'] = {
      "schemaVersion": 1, "namespace": "deployment-a", "tenant_id": "old",
      "active": True, "allow_pentester": False,
    }
    owner.records[hkey, '["tenant","deployment-b","other"]'] = {"secret": "other"}
    self.assertEqual([row["tenant_id"] for row in store.list_tenants()], ["tn_a"])

  def test_asset_count_uses_only_strict_active_same_tenant_projections(self):
    owner = Store()
    hkey = '["redmesh","tenancy",1,"deployment-a"]'
    for tenant, asset, active in (("tn_a", "one", True), ("tn_a", "two", False),
                                  ("tn_b", "other", True)):
      owner.records[hkey, json.dumps(["asset", "deployment-a", tenant, asset],
                                    separators=(",", ":"))] = {
        "schemaVersion": 1, "namespace": "deployment-a", "tenant_id": tenant,
        "asset_id": asset, "active": active,
      }
    store = CstoreTenantAdministrationStore(owner, "deployment-a")
    self.assertEqual(store.count_assets("tn_a"), 1)
    owner.records[hkey, '["asset","deployment-a","tn_a","bad"]'] = {
      "schemaVersion": 1, "namespace": "deployment-a", "tenant_id": "tn_b",
      "asset_id": "bad", "active": True,
    }
    with self.assertRaises(TenantStoreError):
      store.count_assets("tn_a")

  def test_every_observable_write_failure_denies_even_when_data_was_mutated(self):
    for result, noop in ((False, False), (None, False), (1, False), (True, True)):
      with self.subTest(result=result, noop=noop):
        owner = Store()
        owner.write_result, owner.write_noop = result, noop
        store = CstoreTenantAdministrationStore(owner, "deployment-a")
        with self.assertRaises(TenantStoreError):
          store.put("receipt", "alice", "request", record={"state": "pending"})

  def test_readback_must_preserve_boolean_type_not_just_python_equality(self):
    owner = Store()
    original_get = owner.chainstore_hget
    def corrupt_read(hkey, key):
      row = original_get(hkey, key)
      if row is not None:
        row["active"] = 1
      return row
    owner.chainstore_hget = corrupt_read
    with self.assertRaises(TenantStoreError):
      CstoreTenantAdministrationStore(owner, "deployment-a").put(
        "tenant", "tn_a", record={"tenant_id": "tn_a", "active": True,
                                 "allow_pentester": False})

  def test_corrupt_existing_records_never_become_absence_or_foundation_rows(self):
    owner = Store()
    hkey, key = '["redmesh","tenancy",1,"deployment-a"]', '["tenant","deployment-a","tn_a"]'
    store = CstoreTenantAdministrationStore(owner, "deployment-a")
    self.assertIsNone(store.get("tenant", "tn_a"))
    for raw in ("null", "broken-json", {}, [], {"schemaVersion": True},
                {"schemaVersion": 1, "namespace": "deployment-b", "kind": "tenant",
                 "ids": ["tn_a"], "tenant_id": "tn_a"}):
      with self.subTest(raw=raw):
        owner.records[hkey, key] = raw
        with self.assertRaises(TenantStoreError):
          store.get("tenant", "tn_a")
        with self.assertRaises(TenantStoreError):
          store.list_tenants()

  def test_equivalent_but_noncanonical_field_keys_do_not_duplicate_list_entries(self):
    owner = Store()
    store = CstoreTenantAdministrationStore(owner, "deployment-a")
    store.put("tenant", "tn_a", record={"tenant_id": "tn_a", "active": True,
                                      "allow_pentester": False})
    hkey = '["redmesh","tenancy",1,"deployment-a"]'
    owner.records[hkey, '["tenant", "deployment-a", "tn_a"]'] = store.get("tenant", "tn_a")
    with self.assertRaises(TenantStoreError):
      store.list_tenants()

  def test_missing_namespace_and_conflicting_envelope_prevent_writes(self):
    owner = Store()
    for namespace, record in (("", {}), (None, {}),
                              ("deployment-a", {"namespace": "deployment-b"}),
                              ("deployment-a", {"schemaVersion": True}),
                              ("deployment-a", {"ids": ["bob", "request"]})):
      with self.subTest(namespace=namespace, record=record):
        with self.assertRaises(TenantStoreError):
          CstoreTenantAdministrationStore(owner, namespace).put(
            "receipt", "alice", "request", record=record)
    self.assertEqual(owner.records, {})

  def test_enumeration_never_truncates_and_surfaced_storage_errors_are_typed(self):
    owner = Store()
    store = CstoreTenantAdministrationStore(owner, "deployment-a")
    store.put("receipt", "alice", "request", record={})
    with patch("extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration."
               "MAX_ENUMERATED_RECORDS", 0):
      with self.assertRaises(TenantStoreError):
        store.list_tenants()
      with self.assertRaises(TenantStoreError):
        store.count_assets("tn_a")
    with patch.object(owner, "chainstore_hgetall", return_value=None):
      with self.assertRaises(TenantStoreError):
        store.list_tenants()
    with patch.object(owner, "chainstore_hget", side_effect=RuntimeError("private")):
      with self.assertRaisesRegex(TenantStoreError, "^Tenant storage cannot be read$"):
        store.get("receipt", "alice", "request")
    with patch.object(owner, "chainstore_hset", side_effect=RuntimeError("private")):
      with self.assertRaisesRegex(TenantStoreError, "^Tenant storage write could not be verified$"):
        store.put("receipt", "alice", "request", record={})
