import unittest
from types import SimpleNamespace

from extensions.business.cybersec.red_mesh.tenancy import tenancy_namespace


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


if __name__ == "__main__":
  unittest.main()
