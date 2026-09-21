"""Real readers and policy against a fake external CStore; no live tenant records."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
  AUTH_HKEY_ENV,
  CstoreAuthAccountReader,
)
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_tenant import CstoreTenantReader
from extensions.business.cybersec.red_mesh.tenancy.policy import PolicyDecision, TenantPolicyContext
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.resolution import TenantAuthorizationService

from .test_account_record_v1 import record


TENANT_HKEY = '["redmesh","tenancy",1,"deployment-a"]'
# Real tenant ids: the v1 account record refuses a membership naming anything else (RM-084 P6).
T = "tn_12345678-1234-4234-8234-123456789abc"
T2 = "tn_87654321-4321-4321-8321-cba987654321"


def _key(*parts):
  return json.dumps(list(parts), separators=(",", ":"))


TENANT_KEY = _key("tenant", "deployment-a", T)
ASSET_KEY = _key("asset", "deployment-a", T, "asset-1")


class FakeStore:
  def __init__(self):
    self.data = {
      ("test-auth", "operator"): record("operator", memberships=[
        {"role": "tenant_pentester", "tenant_id": T},
      ]),
      (TENANT_HKEY, TENANT_KEY): {"schemaVersion": 1, "namespace": "deployment-a", "tenant_id": T,
                                "active": True, "allow_pentester": True},
      (TENANT_HKEY, ASSET_KEY): {"schemaVersion": 1, "namespace": "deployment-a", "tenant_id": T,
                               "asset_id": "asset-1", "active": True},
    }
    self.reads = []
    self.fail_on = None

  def hget(self, *, hkey, key):
    self.reads.append((hkey, key))
    if (hkey, key) == self.fail_on:
      raise RuntimeError("private storage diagnostic must not leave the boundary")
    return self.data.get((hkey, key))


def service(store, namespace="deployment-a"):
  owner = SimpleNamespace(chainstore_hget=store.hget)
  return TenantAuthorizationService(CstoreAuthAccountReader(owner), CstoreTenantReader(owner, namespace))


class TestTenantResolution(unittest.TestCase):
  def setUp(self):
    self.env = patch.dict("os.environ", {AUTH_HKEY_ENV: "test-auth"})
    self.env.start()
    self.addCleanup(self.env.stop)

  def test_task_context_comes_from_stored_identity_tenant_and_asset(self):
    store = FakeStore()
    store.data[(TENANT_HKEY, TENANT_KEY)] = json.dumps(store.data[(TENANT_HKEY, TENANT_KEY)])
    context, decision = service(store).authorize(
      {"account_id": " OPERATOR "}, "tasks:launch", T, asset_ids=["asset-1"],
    )
    self.assertEqual(decision, PolicyDecision(True, 200, None))
    self.assertEqual(context.account.account_id, "operator")
    self.assertEqual(context.tenant, TenantPolicyContext(T, True, True))
    self.assertEqual(context.asset_ids, ("asset-1",))
    self.assertEqual(store.reads, [("test-auth", "operator"), (TENANT_HKEY, TENANT_KEY),
                                  (TENANT_HKEY, ASSET_KEY)])

  def test_scope_is_checked_before_any_tenant_or_asset_read(self):
    store = FakeStore()
    context, decision = service(store).authorize(
      {"account_id": "operator", "role": "super_tenant_admin", "tenant_id": T2, "scope": "*"},
      "tasks:launch", T2, asset_ids=["asset-1"],
    )
    self.assertIsNone(context)
    self.assertEqual(decision, PolicyDecision(False, 404, "not_found"))
    self.assertEqual(store.reads, [("test-auth", "operator")])

  def test_real_tenant_then_role_are_checked_before_asset_reads(self):
    for tenant_exists in (False, True):
      with self.subTest(tenant_exists=tenant_exists):
        store = FakeStore()
        store.data[("test-auth", "operator")]["memberships"][0]["role"] = "tenant_user"
        if not tenant_exists:
          del store.data[(TENANT_HKEY, TENANT_KEY)]
        context, decision = service(store).authorize({"account_id": "operator"}, "tasks:launch", T,
                                                   asset_ids=["asset-1"])
        self.assertIsNone(context)
        self.assertEqual(decision, PolicyDecision(False, 403, "forbidden") if tenant_exists
                         else PolicyDecision(False, 404, "not_found"))
        self.assertEqual(store.reads, [("test-auth", "operator"), (TENANT_HKEY, TENANT_KEY)])

  def test_surfaced_failures_release_no_context_or_private_diagnostics(self):
    for failed in (("test-auth", "operator"), (TENANT_HKEY, TENANT_KEY), (TENANT_HKEY, ASSET_KEY)):
      with self.subTest(failed=failed):
        store = FakeStore()
        store.fail_on = failed
        self.assertEqual(service(store).authorize({"account_id": "operator"}, "tasks:launch", T,
                                                 asset_ids=["asset-1"]),
                         (None, PolicyDecision(False, 503, "unavailable")))

  def test_misconfigured_namespace_fails_closed_without_storage_access(self):
    for namespace in (None, "", " ", True, [], {}):
      with self.subTest(namespace=namespace):
        store = FakeStore()
        self.assertEqual(service(store, namespace).authorize({"account_id": "operator"}, "reports:view", T),
                         (None, PolicyDecision(False, 503, "unavailable")))
        self.assertEqual(store.reads, [("test-auth", "operator")])

  def test_non_task_context_never_labels_caller_asset_ids_as_validated(self):
    store = FakeStore()
    context, decision = service(store).authorize({"account_id": "operator"}, "reports:view", T,
                                               asset_ids=["not-checked", {"tenant_id": T2}])
    self.assertTrue(decision.allowed)
    self.assertEqual(context.asset_ids, ())
    self.assertEqual(store.reads, [("test-auth", "operator"), (TENANT_HKEY, TENANT_KEY)])

  def test_malformed_task_selectors_deny_before_asset_reads(self):
    for ids in (None, "asset-1", {}, [], [None], [1], [""], [" "], ["asset-1", {"owner": T}]):
      with self.subTest(ids=ids):
        store = FakeStore()
        self.assertEqual(service(store).authorize({"account_id": "operator"}, "tasks:launch", T, asset_ids=ids),
                         (None, PolicyDecision(False, 404, "not_found")))
        self.assertEqual(store.reads, [("test-auth", "operator"), (TENANT_HKEY, TENANT_KEY)])

  def test_task_selectors_are_snapshotted_before_storage_callbacks(self):
    store = FakeStore()
    ids = ["asset-1"]
    original_read = store.hget

    def mutating_read(**kwargs):
      if kwargs["key"] == ASSET_KEY:
        ids[0] = "foreign-asset"
      return original_read(**kwargs)

    store.hget = mutating_read
    context, decision = service(store).authorize({"account_id": "operator"}, "tasks:launch", T, asset_ids=ids)
    self.assertTrue(decision.allowed)
    self.assertEqual(context.asset_ids, ("asset-1",))

  def test_each_call_rereads_membership_tenant_flag_and_asset(self):
    store = FakeStore()
    resolver = service(store)
    actor = {"account_id": "operator", "allow_pentester": True, "role": "super_tenant_admin"}

    def authorize():
      return resolver.authorize(actor, "tasks:update", T, asset_ids=("asset-1",))

    self.assertTrue(authorize()[1].allowed)
    store.data[(TENANT_HKEY, TENANT_KEY)]["allow_pentester"] = False
    self.assertEqual(authorize(), (None, PolicyDecision(False, 403, "pentesting_disabled")))
    store.data[(TENANT_HKEY, ASSET_KEY)]["tenant_id"] = T2
    self.assertEqual(authorize(), (None, PolicyDecision(False, 404, "not_found")))
    store.data[("test-auth", "operator")]["memberships"] = []
    store.reads.clear()
    self.assertEqual(authorize(), (None, PolicyDecision(False, 404, "not_found")))
    self.assertEqual(store.reads, [("test-auth", "operator")])
    del store.data[("test-auth", "operator")]
    self.assertEqual(authorize(), (None, PolicyDecision(False, 404, "not_found")))

  def test_invalid_or_silently_unavailable_facts_never_release_context(self):
    # Core can swallow a failed read as None: this must deny, but cannot promise a 503.
    for key in (TENANT_KEY, ASSET_KEY):
      for change in (None, {"active": False}, {"namespace": "other"}, {"tenant_id": T2}):
        with self.subTest(key=key, change=change):
          store = FakeStore()
          store.data[(TENANT_HKEY, key)] = (None if change is None
                                          else {**store.data[(TENANT_HKEY, key)], **change})
          self.assertEqual(service(store).authorize({"account_id": "operator"}, "tasks:launch", T,
                                                   asset_ids=["asset-1"]),
                           (None, PolicyDecision(False, 404, "not_found")))

  def test_one_valid_asset_does_not_authorize_a_missing_second_asset(self):
    store = FakeStore()
    self.assertEqual(service(store).authorize({"account_id": "operator"}, "tasks:update", T,
                                             asset_ids=["asset-1", "missing"]),
                     (None, PolicyDecision(False, 404, "not_found")))


class TestTenantReadBoundary(unittest.TestCase):
  def test_full_field_keys_isolate_namespaces_even_when_hkey_hashes_collide(self):
    # Model a core hkey-prefix collision: both logical hashes share a bucket, but field keys survive.
    fields = {
      _key("tenant", "deployment-a", T): {"schemaVersion": 1, "namespace": "deployment-a",
                                          "tenant_id": T, "active": True, "allow_pentester": False},
      _key("tenant", "deployment-b", T): {"schemaVersion": 1, "namespace": "deployment-b",
                                          "tenant_id": T, "active": True, "allow_pentester": True},
      _key("asset", "deployment-a", T, "asset-1"): {"schemaVersion": 1, "namespace": "deployment-a",
                                                   "tenant_id": T, "asset_id": "asset-1", "active": True},
    }
    owner = SimpleNamespace(chainstore_hget=lambda *, hkey, key: fields.get(key))
    reader_a = CstoreTenantReader(owner, "deployment-a")
    reader_b = CstoreTenantReader(owner, "deployment-b")
    self.assertEqual(reader_a.get_tenant_policy(T), TenantPolicyContext(T, True, False))
    self.assertEqual(reader_b.get_tenant_policy(T), TenantPolicyContext(T, True, True))
    self.assertEqual(reader_a.get_asset_owner(T, "asset-1"), T)
    self.assertIsNone(reader_b.get_asset_owner(T, "asset-1"))

  def test_delimiter_bearing_identifiers_have_unambiguous_exact_keys(self):
    store = FakeStore()
    selectors = [("x:y", "z", T), ("x", "y:z", T), ("x", "y", "z:a"),
                 ('x\",\"y', "z", T)]
    for namespace, tenant, asset in selectors:
      CstoreTenantReader(SimpleNamespace(chainstore_hget=store.hget), namespace).get_asset_owner(tenant, asset)
    self.assertEqual(len({key for _, key in store.reads}), len(selectors))
    for (namespace, tenant, asset), (hkey, key) in zip(selectors, store.reads):
      self.assertEqual(json.loads(hkey), ["redmesh", "tenancy", 1, namespace])
      self.assertEqual(json.loads(key), ["asset", namespace, tenant, asset])

  def test_missing_projection_does_not_fall_back_to_legacy_or_unscoped_keys(self):
    store = FakeStore()
    row = store.data.pop((TENANT_HKEY, TENANT_KEY))
    store.data[("inst:tenants", T)] = row
    store.data[(TENANT_HKEY, T)] = row
    self.assertIsNone(CstoreTenantReader(SimpleNamespace(chainstore_hget=store.hget), "deployment-a")
                      .get_tenant_policy(T))
    self.assertEqual(store.reads, [(TENANT_HKEY, TENANT_KEY)])

  def test_surfaced_adapter_error_is_typed(self):
    store = FakeStore()
    store.fail_on = (TENANT_HKEY, TENANT_KEY)
    reader = CstoreTenantReader(SimpleNamespace(chainstore_hget=store.hget), "deployment-a")
    with self.assertRaises(TenantStoreError):
      reader.get_tenant_policy(T)

  def test_invalid_selectors_never_read_storage(self):
    store = FakeStore()
    reader = CstoreTenantReader(SimpleNamespace(chainstore_hget=store.hget), "deployment-a")
    for selector in (None, "", " ", True, 1, [], {}):
      with self.subTest(selector=selector):
        self.assertIsNone(reader.get_tenant_policy(selector))
        self.assertIsNone(reader.get_asset_owner(selector, "asset-1"))
        self.assertIsNone(reader.get_asset_owner(T, selector))
    self.assertEqual(store.reads, [])

  def test_tenant_projection_rejects_malformed_version_type_and_identity_bindings(self):
    original = FakeStore().data[(TENANT_HKEY, TENANT_KEY)]
    rows = [None, "null", "[]", "{", b"\xff", [], True, 1]
    for field, values in {
      "schemaVersion": (None, 0, 2, True, 1.0, "1"),
      "namespace": (None, "deployment-b"), "tenant_id": (None, T2),
      "active": (None, False, 1, "true"), "allow_pentester": (None, 1, "false"),
    }.items():
      for value in values:
        rows.append({**original, field: value})
      rows.append({k: v for k, v in original.items() if k != field})
    for row in rows:
      with self.subTest(row=row):
        store = FakeStore()
        store.data[(TENANT_HKEY, TENANT_KEY)] = row
        self.assertIsNone(CstoreTenantReader(SimpleNamespace(chainstore_hget=store.hget), "deployment-a")
                          .get_tenant_policy(T))

  def test_asset_projection_requires_exact_active_namespace_tenant_and_asset(self):
    original = FakeStore().data[(TENANT_HKEY, ASSET_KEY)]
    rows = [None, "null", "[]", "{", b"\xff", [], True, 1]
    for field, values in {
      "schemaVersion": (None, 0, 2, True, 1.0, "1"),
      "namespace": (None, "deployment-b"), "tenant_id": (None, T2),
      "asset_id": (None, "asset-2"), "active": (None, False, 1, "true"),
    }.items():
      for value in values:
        rows.append({**original, field: value})
      rows.append({k: v for k, v in original.items() if k != field})
    for row in rows:
      with self.subTest(row=row):
        store = FakeStore()
        store.data[(TENANT_HKEY, ASSET_KEY)] = row
        self.assertIsNone(CstoreTenantReader(SimpleNamespace(chainstore_hget=store.hget), "deployment-a")
                          .get_asset_owner(T, "asset-1"))

  def test_bytes_json_and_dict_records_produce_same_valid_projection(self):
    for encode in (lambda row: row, json.dumps, lambda row: json.dumps(row).encode()):
      store = FakeStore()
      for key in ((TENANT_HKEY, TENANT_KEY), (TENANT_HKEY, ASSET_KEY)):
        store.data[key] = encode(store.data[key])
      reader = CstoreTenantReader(SimpleNamespace(chainstore_hget=store.hget), "deployment-a")
      self.assertEqual(reader.get_tenant_policy(T), TenantPolicyContext(T, True, True))
      self.assertEqual(reader.get_asset_owner(T, "asset-1"), T)
