"""Account incarnation and safe member enumeration from raw external CStore records."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
  AUTH_HKEY_ENV, CstoreAuthAccountReader,
)
from extensions.business.cybersec.red_mesh.tenancy.identity import IdentityStoreError

from .test_account_record_v1 import GEN, T1, record


class TestAccountEnumeration(unittest.TestCase):
  def test_account_generation_is_the_records_own(self):
    # RM-084 P6: the v1 record always carries its generation. There is no derived "legacy:<created>"
    # incarnation any more, and a record without one is not a record.
    missing = record("missing")
    missing.pop("generation")
    records = {"explicit": record("explicit", generation=GEN), "missing": missing}
    reader = CstoreAuthAccountReader(SimpleNamespace(
      chainstore_hget=lambda hkey, key: records.get(key)))
    with patch.dict("os.environ", {AUTH_HKEY_ENV: "accounts"}):
      self.assertEqual(reader.get_account("explicit").account_generation, GEN)
      self.assertIsNone(reader.get_account("missing"))

  def test_enumeration_returns_only_valid_canonical_projections_without_secrets(self):
    alice = record("alice", generation=GEN, memberships=[{"role": "tenant_admin", "tenant_id": T1}])
    deleting = record("deleting", state="deleting", stateChangedAt="2026-01-02T00:00:00.000Z",
                      stateChangedBy="admin.user")
    unknown_key = record("carol")
    unknown_key["unrelated"] = "private"
    records = {
      "alice": alice, "deleting": deleting, "carol": unknown_key,
      "Alice": record("Alice"), "bad id": record("bad id"),
      "tombstone": "null", "malformed": {"metadata": None},
    }
    reader = CstoreAuthAccountReader(SimpleNamespace(chainstore_hgetall=lambda hkey: records))
    with patch.dict("os.environ", {AUTH_HKEY_ENV: "accounts"}):
      views = reader.list_accounts()
    self.assertEqual([view.account_id for view in views], ["alice", "deleting"])
    self.assertEqual(views[0].account_generation, GEN)
    self.assertFalse(views[1].active)
    self.assertNotIn(alice["password"]["hash"], repr(views))
    self.assertNotIn("private", repr(views))

  def test_enumeration_fails_instead_of_truncating_or_masking_storage_failure(self):
    owner = SimpleNamespace(chainstore_hgetall=lambda hkey: {"alice": {"metadata": {}}})
    reader = CstoreAuthAccountReader(owner)
    with patch.dict("os.environ", {AUTH_HKEY_ENV: "accounts"}):
      with patch("extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity."
                 "MAX_ENUMERATED_ACCOUNTS", 0):
        with self.assertRaises(IdentityStoreError):
          reader.list_accounts()
      for value in (None, [], "broken"):
        with self.subTest(value=value), patch.object(owner, "chainstore_hgetall", return_value=value):
          with self.assertRaises(IdentityStoreError):
            reader.list_accounts()
      with patch.object(owner, "chainstore_hgetall", side_effect=RuntimeError("private")):
        with self.assertRaisesRegex(IdentityStoreError, "^Account storage cannot be enumerated$"):
          reader.list_accounts()
    with patch.dict("os.environ", {}, clear=True):
      with self.assertRaises(IdentityStoreError):
        reader.list_accounts()
