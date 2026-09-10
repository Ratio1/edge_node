"""Account incarnation and safe member enumeration from raw external CStore records."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
  AUTH_HKEY_ENV, CstoreAuthAccountReader,
)
from extensions.business.cybersec.red_mesh.tenancy.identity import IdentityStoreError


class TestAccountEnumeration(unittest.TestCase):
  def test_account_generation_tracks_explicit_and_legacy_incarnations(self):
    records = {
      "explicit": {"role": "user", "metadata": {"navigatorAccountGeneration": "generation-1"},
                   "createdAt": "2026-01-01"},
      "legacy": {"role": "user", "metadata": {}, "createdAt": "2025-01-01"},
      "missing": {"role": "user", "metadata": {}},
    }
    reader = CstoreAuthAccountReader(SimpleNamespace(
      chainstore_hget=lambda hkey, key: records.get(key)))
    with patch.dict("os.environ", {AUTH_HKEY_ENV: "accounts"}):
      self.assertEqual(reader.get_account("explicit").account_generation, "generation-1")
      self.assertEqual(reader.get_account("legacy").account_generation, "legacy:2025-01-01")
      self.assertIsNone(reader.get_account("missing").account_generation)

  def test_enumeration_returns_only_valid_canonical_projections_without_secrets(self):
    records = {
      "alice": {"role": "user", "password": "never-project", "metadata": {
        "navigatorAccountGeneration": "g1", "unrelated": "private",
        "tenant_memberships": [{"role": "tenant_admin", "tenant_id": "tn_a"}],
      }},
      "deleting": {"metadata": {"navigatorAccountState": "deleting"}},
      "Alice": {"role": "admin"}, "bad id": {"role": "admin"},
      "tombstone": "null", "malformed": {"metadata": None},
    }
    reader = CstoreAuthAccountReader(SimpleNamespace(chainstore_hgetall=lambda hkey: records))
    with patch.dict("os.environ", {AUTH_HKEY_ENV: "accounts"}):
      views = reader.list_accounts()
    self.assertEqual([view.account_id for view in views], ["alice", "deleting"])
    self.assertEqual(views[0].account_generation, "g1")
    self.assertFalse(views[1].active)
    self.assertNotIn("never-project", repr(views))
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
