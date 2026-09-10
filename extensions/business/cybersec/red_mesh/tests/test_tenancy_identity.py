"""Actor resolution and the minimal cstore-auth reader (RM-075 Phase 2)."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
  AUTH_HKEY_ENV,
  CstoreAuthAccountReader,
)
from extensions.business.cybersec.red_mesh.tenancy.identity import (
  AccountView,
  IdentityStoreError,
  TenantMembership,
  canonical_account_id,
  resolve_actor,
)

HKEY = "app_x:auth"


class _Store:
  def __init__(self, records):
    self.records = records
    self.calls = []

  def hget(self, hkey, key, token=None, debug=False):
    self.calls.append((hkey, key))
    return self.records.get(key)


def _reader(records):
  store = _Store(records)
  return CstoreAuthAccountReader(SimpleNamespace(chainstore_hget=store.hget)), store


def _record(role="user", metadata=None, schema_version=None):
  rec = {"type": "simple", "password": None, "role": role, "metadata": metadata or {},
         "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z"}
  if schema_version is not None:
    rec["schemaVersion"] = schema_version
  return rec


class _StubReader:
  def __init__(self, view=None, error=None):
    self.view, self.error = view, error

  def get_account(self, account_id):
    if self.error:
      raise self.error
    return self.view


class TestCanonicalAccountId(unittest.TestCase):
  def test_mirrors_navigator_canonicalisation(self):
    self.assertEqual(canonical_account_id("  Ops.User "), "ops.user")
    self.assertIsNone(canonical_account_id(""))
    self.assertIsNone(canonical_account_id("bad id"))
    self.assertIsNone(canonical_account_id(None))
    self.assertIsNone(canonical_account_id({"account_id": "x"}))


class TestResolveActor(unittest.TestCase):
  def test_missing_or_malformed_actor_is_not_found(self):
    for actor in (None, "a1", {}, {"account_id": ""}, {"account_id": "no spaces"}):
      view, err = resolve_actor(actor, _StubReader(AccountView("a1", "user", None, True)))
      self.assertIsNone(view, actor)
      self.assertEqual(err["status_code"], 404, actor)
      self.assertEqual(err["error_class"], "actor_not_found", actor)

  def test_unknown_account_is_the_same_not_found(self):
    view, err = resolve_actor({"account_id": "ghost"}, _StubReader(None))
    self.assertIsNone(view)
    self.assertEqual(err["status_code"], 404)

  def test_inactive_account_is_the_same_not_found(self):
    view, err = resolve_actor({"account_id": "a1"}, _StubReader(AccountView("a1", "user", None, False)))
    self.assertIsNone(view)
    self.assertEqual(err["status_code"], 404)

  def test_store_failure_fails_closed_as_503(self):
    view, err = resolve_actor({"account_id": "a1"}, _StubReader(error=IdentityStoreError("down")))
    self.assertIsNone(view)
    self.assertEqual(err["status_code"], 503)
    self.assertEqual(err["error_class"], "identity_store_unavailable")

  def test_roles_come_from_the_store_never_the_request(self):
    stored = AccountView("a1", "user", "pentester", True)
    view, err = resolve_actor({"account_id": "A1", "role": "admin", "appRole": "admin"}, _StubReader(stored))
    self.assertIsNone(err)
    self.assertEqual(view, stored)
    self.assertEqual(view.created_by, ("a1", "a1"))


class TestCstoreAuthAccountReader(unittest.TestCase):
  def test_memberships_keep_roles_bound_to_their_tenants(self):
    reader, _ = _reader({"a1": json.dumps(_record(role="admin", metadata={"tenant_memberships": [
      {"role": "super_tenant_admin", "tenant_id": "tenant-a"},
      {"role": "tenant_user", "tenant_id": "tenant-b"},
    ]}))})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      view, error = resolve_actor({"account_id": "a1", "tenant_id": "other"}, reader)
    self.assertIsNone(error)
    self.assertEqual([(m.role, m.tenant_id) for m in view.tenant_memberships], [
      ("super_tenant_admin", "tenant-a"), ("tenant_user", "tenant-b"),
    ])
    self.assertEqual(view.created_by, ("a1", "a1"))

  def test_missing_hkey_fails_closed(self):
    reader, store = _reader({"a1": _record()})
    with patch.dict("os.environ", {}, clear=True):
      with self.assertRaises(IdentityStoreError):
        reader.get_account("a1")
    self.assertEqual(store.calls, [])

  def test_all_normal_membership_roles_preserve_explicit_scope(self):
    pairs = [
      ("super_tenant_admin", None), ("super_pentester", None),
      ("super_tenant_admin", "tenant-a"), ("super_pentester", "tenant-a"),
      ("tenant_admin", "tenant-a"), ("tenant_pentester", "tenant-a"),
      ("tenant_user", "tenant-a"),
    ]
    for role, tenant_id in pairs:
      with self.subTest(role=role, tenant_id=tenant_id):
        reader, _ = _reader({"a1": _record(metadata={"tenant_memberships": [
          {"role": role, "tenant_id": tenant_id},
        ]})})
        with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
          view = reader.get_account("a1")
        self.assertEqual(view.tenant_memberships, (TenantMembership(role, tenant_id),))

  def test_only_absent_memberships_on_legacy_admin_enable_compatibility(self):
    reader, _ = _reader({
      "legacy": _record(role="admin"),
      "revoked": _record(role="admin", metadata={"tenant_memberships": []}),
      "ordinary": _record(),
    })
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      legacy = reader.get_account("legacy")
      self.assertEqual(reader.get_account("revoked").tenant_memberships, ())
      self.assertEqual(reader.get_account("ordinary").tenant_memberships, ())
    self.assertEqual([(m.role, m.tenant_id) for m in legacy.tenant_memberships], [
      ("super_tenant_admin", None),
    ])

  def test_reads_dict_and_json_string_records(self):
    reader, store = _reader({"a1": _record(role="admin"), "a2": json.dumps(_record(metadata={"appRole": "pentester"}))})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      a1 = reader.get_account("a1")
      a2 = reader.get_account("a2")
    self.assertEqual(a1, AccountView("a1", "admin", None, True,
                                    (TenantMembership("super_tenant_admin", None),)))
    self.assertEqual(a2, AccountView("a2", "user", "pentester", True))
    self.assertEqual(store.calls, [(HKEY, "a1"), (HKEY, "a2")])

  def test_malformed_explicit_memberships_deny_instead_of_restoring_admin(self):
    valid = {"role": "tenant_user", "tenant_id": "tenant-a"}
    invalid_values = (
      None, "admin", {}, 42, [None], [{}],
      [{"role": "super_tenant_admin"}],
      [{"tenant_id": "tenant-a"}],
      [{"role": "unknown", "tenant_id": "tenant-a"}],
      [{"role": [], "tenant_id": "tenant-a"}],
      [{"role": "ratio1_deployer", "tenant_id": None}],
      [{"role": "tenant_user", "tenant_id": None}],
      [{"role": "tenant_user", "tenant_id": 1}],
      [{"role": "tenant_user", "tenant_id": "  "}],
      [valid, {"role": "super_tenant_admin"}],
    )
    for memberships in invalid_values:
      with self.subTest(memberships=memberships):
        reader, _ = _reader({"a1": _record(role="admin", metadata={
          "tenant_memberships": memberships,
        })})
        with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
          view, error = resolve_actor({"account_id": "a1"}, reader)
        self.assertIsNone(view)
        self.assertEqual(error["status_code"], 404)
        self.assertEqual(error["error_class"], "actor_not_found")

  def test_absent_and_tombstoned_are_none(self):
    reader, _ = _reader({"gone": "null"})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      self.assertIsNone(reader.get_account("missing"))
      self.assertIsNone(reader.get_account("gone"))

  def test_malformed_metadata_is_not_coerced_into_legacy_admin_authority(self):
    for metadata in (None, [], "{}", True, 0):
      with self.subTest(metadata=metadata):
        record = _record(role="admin")
        record["metadata"] = metadata
        reader, _ = _reader({"a1": record})
        with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
          view, error = resolve_actor({"account_id": "a1"}, reader)
        self.assertIsNone(view)
        self.assertEqual(error["status_code"], 404)

  def test_absent_metadata_keeps_legacy_compatibility(self):
    record = _record(role="admin")
    del record["metadata"]
    reader, _ = _reader({"a1": record})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      view = reader.get_account("a1")
    self.assertEqual(view.tenant_memberships, (TenantMembership("super_tenant_admin", None),))

  def test_deleting_state_is_not_active(self):
    reader, _ = _reader({"a1": _record(metadata={"navigatorAccountState": "deleting"})})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      view = reader.get_account("a1")
    self.assertFalse(view.active)

  def test_schema_version_absent_is_accepted_and_unknown_present_fails_closed(self):
    reader, _ = _reader({
      "v0": _record(),
      "v1": _record(schema_version=1),
      "v9": _record(schema_version=9),
      "junk": "{not json",
      "list": json.dumps([1, 2]),
    })
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      self.assertIsNotNone(reader.get_account("v0"))
      self.assertIsNotNone(reader.get_account("v1"))
      self.assertIsNone(reader.get_account("v9"))
      self.assertIsNone(reader.get_account("junk"))
      self.assertIsNone(reader.get_account("list"))

  def test_store_exception_becomes_identity_store_error(self):
    def boom(hkey, key, token=None, debug=False):
      raise ConnectionError("cstore down")

    reader = CstoreAuthAccountReader(SimpleNamespace(chainstore_hget=boom))
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      with self.assertRaises(IdentityStoreError):
        reader.get_account("a1")

  def test_schema_version_requires_a_supported_integer_not_a_bool_or_container(self):
    for version in ([], {}, True, False, 1.0, 0.0, "1", None):
      with self.subTest(version=version):
        record = _record()
        record["schemaVersion"] = version
        reader, _ = _reader({"a1": record})
        with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
          self.assertIsNone(reader.get_account("a1"))
    for version in (0, 1):
      with self.subTest(version=version):
        reader, _ = _reader({"a1": _record(schema_version=version)})
        with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
          self.assertIsNotNone(reader.get_account("a1"))


if __name__ == "__main__":
  unittest.main()
