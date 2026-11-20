import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy import account_hkey, tenancy_namespace
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy.identity import IdentityStoreError


class TenancyNamespaceTests(unittest.TestCase):

  def test_namespace_is_the_stripped_stream_id(self):
    self.assertEqual(tenancy_namespace(SimpleNamespace(_stream_id=" app-1 ")), "app-1")

  def test_config_value_is_ignored(self):
    owner = SimpleNamespace(_stream_id="app-1", cfg_tenancy_namespace="other", TENANCY_NAMESPACE="other")
    self.assertEqual(tenancy_namespace(owner), "app-1")

  def test_empty_missing_or_non_string_is_unavailable(self):
    for owner in (SimpleNamespace(_stream_id=""), SimpleNamespace(_stream_id="  "),
                  SimpleNamespace(_stream_id=None), SimpleNamespace(_stream_id=7), SimpleNamespace()):
      with self.subTest(owner=owner):
        self.assertIsNone(tenancy_namespace(owner))

  def test_account_hkey_is_the_stream_id_and_ignores_the_env_var(self):
    owner = SimpleNamespace(_stream_id=" app-1 ", cfg_env={"R1EN_CSTORE_AUTH_HKEY": "env-hkey"})
    with patch.dict(os.environ, {"R1EN_CSTORE_AUTH_HKEY": "process-hkey"}):
      self.assertEqual(account_hkey(owner), "app-1:auth")
      self.assertEqual(CstoreAuthAccountReader(owner)._hkey(), "app-1:auth")

  def test_empty_stream_id_makes_the_account_store_unavailable(self):
    owner = SimpleNamespace(_stream_id="", cfg_env={"R1EN_CSTORE_AUTH_HKEY": "env-hkey"})
    with patch.dict(os.environ, {"R1EN_CSTORE_AUTH_HKEY": "process-hkey"}):
      self.assertIsNone(account_hkey(owner))
      with self.assertRaises(IdentityStoreError):
        CstoreAuthAccountReader(owner)._hkey()


if __name__ == "__main__":
  unittest.main()
