"""The v1 account record, read server-side (RM-084 P6).

The Navigator writes these records and this parses them, so the property that matters is not "valid
records parse" -- it is that the two sides agree on which records are valid. A record one side
accepts and the other refuses is an account that exists for authentication and not for authorization,
or the reverse; the canonical fixture `account-record.v1.json` is what they agree through.
"""
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.account_record import (
  SCHEMA_VERSION,
  TOMBSTONE,
  parse_account_record,
)
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
ACCOUNT = "ops.user"
GEN = "2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d"
T1 = "tn_12345678-1234-4234-8234-123456789abc"
T2 = "tn_87654321-4321-4321-8321-cba987654321"


def record(account_id=ACCOUNT, *, memberships=None, state="active", generation=GEN, **overrides):
  value = {
    "schemaVersion": SCHEMA_VERSION,
    "accountId": account_id,
    "state": state,
    "generation": generation,
    "password": {"algo": "argon2id", "v": 19, "m": 65536, "t": 3, "p": 1, "len": 32,
                 "salt": "c2FsdHNhbHRzYWx0c2FsdA==",
                 "hash": "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g="},
    "memberships": memberships if memberships is not None else [],
    "createdAt": "2026-01-01T00:00:00.000Z", "createdBy": "@bootstrap",
    "updatedAt": "2026-01-01T00:00:00.000Z", "updatedBy": "@bootstrap",
    "passwordChangedAt": "2026-01-01T00:00:00.000Z",
  }
  value.update(overrides)
  return value


class _Store:
  def __init__(self, records):
    self.records = records
    self.calls = []

  def hget(self, hkey, key, token=None, debug=False):
    self.calls.append((hkey, key))
    return self.records.get(key)

  def hgetall(self, hkey, token=None, debug=False):
    return dict(self.records)


def reader(records):
  store = _Store(records)
  return CstoreAuthAccountReader(SimpleNamespace(
    chainstore_hget=store.hget, chainstore_hgetall=store.hgetall)), store


class TestParseAccountRecord(unittest.TestCase):
  def test_a_valid_record_yields_state_generation_and_memberships(self):
    parsed = parse_account_record(record(memberships=[{"role": "tenant_admin", "tenant_id": T1}]), ACCOUNT)
    self.assertEqual(parsed, ("active", GEN, (("tenant_admin", T1),)))

  def test_accepts_a_json_string_and_an_empty_membership_list(self):
    parsed = parse_account_record(json.dumps(record()), ACCOUNT)
    self.assertEqual(parsed, ("active", GEN, ()))

  def test_absent_and_tombstoned_records_are_indistinguishable_from_malformed(self):
    # A caller that could tell these apart could enumerate which account names exist.
    for raw in (None, TOMBSTONE, "null", "{not json", "", []):
      with self.subTest(raw=raw):
        self.assertIsNone(parse_account_record(raw, ACCOUNT))

  def test_a_record_filed_under_another_account_is_refused(self):
    self.assertIsNone(parse_account_record(record("someone.else"), ACCOUNT))

  def test_an_unknown_key_is_refused_rather_than_ignored(self):
    value = record()
    value["appRole"] = "pentester"
    self.assertIsNone(parse_account_record(value, ACCOUNT))

  def test_only_schema_version_one_is_read(self):
    for version in (0, 2, "1", None, True, 1.0, [], {}):
      with self.subTest(version=version):
        value = record()
        value["schemaVersion"] = version
        self.assertIsNone(parse_account_record(value, ACCOUNT))

  def test_the_pre_cutover_library_record_is_refused_outright(self):
    legacy = {"type": "simple", "password": None, "role": "admin",
              "metadata": {"appRole": "pentester", "tenant_memberships": [],
                           "navigatorAccountState": "active"},
              "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z"}
    self.assertIsNone(parse_account_record(legacy, ACCOUNT))
    self.assertIsNone(parse_account_record(json.dumps(legacy), ACCOUNT))

  def test_required_fields_must_be_present_and_well_typed(self):
    for mutate in (lambda v: v.pop("updatedBy"),
                   lambda v: v.update(state="suspended"),
                   lambda v: v.update(state=["active"]),
                   lambda v: v.update(state={"active": True}),
                   lambda v: v.update(generation="   "),
                   lambda v: v.update(generation=None),
                   lambda v: v.update(createdBy="")):
      with self.subTest(mutate=mutate):
        value = record()
        mutate(value)
        self.assertIsNone(parse_account_record(value, ACCOUNT))

  def test_a_state_stamp_needs_both_halves(self):
    self.assertIsNone(parse_account_record(record(stateChangedAt="2026-02-01T00:00:00.000Z"), ACCOUNT))
    self.assertIsNone(parse_account_record(record(stateChangedBy="admin"), ACCOUNT))
    self.assertIsNotNone(parse_account_record(
      record(stateChangedAt="2026-02-01T00:00:00.000Z", stateChangedBy="admin"), ACCOUNT))

  def test_membership_rows_fail_closed(self):
    for memberships in ([{"role": "ratio1_deployer", "tenant_id": None}],
                        [{"role": "tenant_admin", "tenant_id": None}],
                        [{"role": "tenant_admin", "tenant_id": "  "}],
                        [{"role": "tenant_admin", "tenant_id": T1, "implicit": True}],
                        [{"role": "tenant_admin"}],
                        [{"role": "super_tenant_admin", "tenant_id": T1}],
                        [{"role": "tenant_admin", "tenant_id": T1},
                         {"role": "tenant_user", "tenant_id": T2}],
                        [{"role": "super_pentester", "tenant_id": None},
                         {"role": "tenant_user", "tenant_id": T1}],
                        "not-a-list"):
      with self.subTest(memberships=memberships):
        self.assertIsNone(parse_account_record(record(memberships=memberships), ACCOUNT))

  def test_stored_password_parameters_are_bounded(self):
    for mutate in (lambda p: p.update(algo="scrypt"),
                   lambda p: p.update(v=16),
                   lambda p: p.update(m=4_000_000),
                   lambda p: p.update(t=True),
                   lambda p: p.update(len=16),
                   lambda p: p.pop("salt")):
      with self.subTest(mutate=mutate):
        value = record()
        mutate(value["password"])
        self.assertIsNone(parse_account_record(value, ACCOUNT))


class TestCanonicalAccountId(unittest.TestCase):
  def test_mirrors_the_navigator_rule(self):
    self.assertEqual(canonical_account_id("  Ops.User "), "ops.user")
    for value in ("", "ab", "a" * 65, "bad id", ".leading", "-leading", "_leading", None, 7):
      with self.subTest(value=value):
        self.assertIsNone(canonical_account_id(value))


class TestCstoreAuthAccountReader(unittest.TestCase):
  def test_reads_a_record_into_an_account_view(self):
    read, store = reader({ACCOUNT: record(memberships=[{"role": "tenant_admin", "tenant_id": T1}])})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      view = read.get_account(ACCOUNT)
    self.assertEqual(view.account_id, ACCOUNT)
    self.assertTrue(view.active)
    self.assertEqual(view.state, "active")
    self.assertEqual(view.account_generation, GEN)
    self.assertEqual(view.tenant_memberships, (TenantMembership("tenant_admin", T1),))
    self.assertEqual(store.calls, [(HKEY, ACCOUNT)])

  def test_carries_no_account_role_at_all(self):
    read, _ = reader({ACCOUNT: record()})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      view = read.get_account(ACCOUNT)
    self.assertFalse(hasattr(view, "role"))
    self.assertFalse(hasattr(view, "app_role"))
    self.assertFalse(hasattr(view, "tenant_memberships_present"))

  def test_a_deactivated_or_deleting_account_is_not_active(self):
    for state in ("deactivated", "deleting"):
      with self.subTest(state=state):
        read, _ = reader({ACCOUNT: record(state=state,
                                          stateChangedAt="2026-02-01T00:00:00.000Z",
                                          stateChangedBy="admin")})
        with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
          view = read.get_account(ACCOUNT)
        self.assertIsNotNone(view)
        self.assertFalse(view.active)
        self.assertEqual(view.state, state)

  def test_absent_tombstoned_and_malformed_all_read_as_no_account(self):
    read, _ = reader({"gone": TOMBSTONE, "broken": {"schemaVersion": 99}})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      for key in ("missing", "gone", "broken"):
        with self.subTest(key=key):
          self.assertIsNone(read.get_account(key))

  def test_an_admin_account_with_no_memberships_grants_nothing(self):
    # The legacy bridge used to derive a full-portfolio Super-Tenant Admin here, from a stored
    # `role: admin`. There is no role to derive from, and an empty list holds nothing.
    read, _ = reader({ACCOUNT: record(memberships=[])})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      self.assertEqual(read.get_account(ACCOUNT).tenant_memberships, ())

  def test_enumeration_returns_only_readable_records_under_canonical_ids(self):
    read, _ = reader({ACCOUNT: record(), "gone": TOMBSTONE, "broken": {"schemaVersion": 99},
                      "NotCanonical": record("NotCanonical")})
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      views = read.list_accounts()
    self.assertEqual([view.account_id for view in views], [ACCOUNT])

  def test_a_missing_hkey_fails_closed(self):
    read, _ = reader({ACCOUNT: record()})
    with patch.dict("os.environ", {}, clear=True):
      with self.assertRaises(IdentityStoreError):
        read.get_account(ACCOUNT)

  def test_a_store_failure_is_an_error_not_an_absent_account(self):
    def explode(hkey, key, token=None, debug=False):
      raise RuntimeError("chain store unreachable")
    read = CstoreAuthAccountReader(SimpleNamespace(chainstore_hget=explode))
    with patch.dict("os.environ", {AUTH_HKEY_ENV: HKEY}, clear=True):
      with self.assertRaises(IdentityStoreError):
        read.get_account(ACCOUNT)


class _StubReader:
  def __init__(self, view=None, error=None):
    self.view, self.error = view, error
    self.asked = []

  def get_account(self, account_id):
    self.asked.append(account_id)
    if self.error:
      raise self.error
    return self.view


class TestResolveActor(unittest.TestCase):
  """The forwarded `actor` names an account; everything else about the caller is read from the store."""

  def test_resolves_the_named_account_and_canonicalises_it(self):
    view = AccountView(ACCOUNT, True, tenant_memberships=(TenantMembership("tenant_admin", T1),))
    stub = _StubReader(view)
    resolved, denial = resolve_actor({"account_id": "  Ops.User "}, stub)
    self.assertIsNone(denial)
    self.assertIs(resolved, view)
    self.assertEqual(stub.asked, [ACCOUNT])

  def test_nothing_in_the_request_is_an_authorization_input(self):
    # A request claiming a role gets whatever the store says, and the claim is not even read.
    view = AccountView(ACCOUNT, True, tenant_memberships=())
    resolved, denial = resolve_actor(
      {"account_id": ACCOUNT, "role": "super_tenant_admin", "tenant_memberships":
        [{"role": "super_tenant_admin", "tenant_id": None}]}, _StubReader(view))
    self.assertIsNone(denial)
    self.assertEqual(resolved.tenant_memberships, ())

  def test_an_unknown_or_inactive_account_is_the_same_not_found(self):
    for view in (None, AccountView(ACCOUNT, False, state="deactivated")):
      with self.subTest(view=view):
        _, denial = resolve_actor({"account_id": ACCOUNT}, _StubReader(view))
        self.assertEqual((denial["status_code"], denial["error"]), (404, "not_found"))

  def test_a_malformed_actor_field_is_not_found(self):
    for actor in (None, "ops.user", {}, {"account_id": ""}, {"account_id": "bad id"}):
      with self.subTest(actor=actor):
        _, denial = resolve_actor(actor, _StubReader(AccountView(ACCOUNT, True)))
        self.assertEqual(denial["status_code"], 404)

  def test_a_store_outage_is_503_rather_than_not_found(self):
    """An outage must not read as "no such account": that would sign out a working deployment."""
    _, denial = resolve_actor({"account_id": ACCOUNT},
                              _StubReader(error=IdentityStoreError("unreachable")))
    self.assertEqual((denial["status_code"], denial["error"]), (503, "unavailable"))


if __name__ == "__main__":
  unittest.main()
