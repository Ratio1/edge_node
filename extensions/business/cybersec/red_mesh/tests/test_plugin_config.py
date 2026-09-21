"""Pins the plugin's source-default configuration that the deployment boundary relies on.

The RedMesh plugin HTTP API is a private-network service (hub ADR 0001, RM-075 Phase 1): the
node's network policy is its security boundary. That boundary assumes the plugin does not open a
tunnel by itself, so the *source default* for ``TUNNEL_ENGINE_ENABLED`` must stay ``False``. The
framework's own default is ``True``.

This test pins the source default only. A deploy-time instance config overrides any ``_CONFIG``
key, so the *deployed* value is an operator invariant verified by the ``redmesh-boundary-check``
runbook, not by this test.
"""
import unittest

from .conftest import mock_plugin_modules


class TestPluginSourceDefaults(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh import pentester_api_01

    cls.config = pentester_api_01._CONFIG

  def test_tunnel_engine_is_disabled_in_the_source_default(self):
    # Explicit presence matters: an absent key would inherit the framework's ``True``.
    self.assertIn("TUNNEL_ENGINE_ENABLED", self.config)
    self.assertIs(self.config["TUNNEL_ENGINE_ENABLED"], False)

  def test_port_is_left_to_the_framework(self):
    # ``PORT: None`` means the framework draws a port from 30000-32500 on every start. The
    # boundary runbook and any firewall rule must therefore be range- or interface-scoped,
    # never pinned to a port. If someone pins a port here, the runbook's assumptions change.
    self.assertIn("PORT", self.config)
    self.assertIsNone(self.config["PORT"])

  def test_tenancy_namespace_is_unbound_by_default(self):
    # The namespace is the only tenancy precondition. The former TENANT_ADMINISTRATION_ENABLED flag
    # gated the endpoints that create tenants and assets, which every launch now requires, so a
    # deployment with it off could sign in and do nothing; it was removed on 2026-09-21.
    self.assertIsNone(self.config["TENANCY_NAMESPACE"])
    self.assertNotIn("TENANT_ADMINISTRATION_ENABLED", self.config)


if __name__ == "__main__":
  unittest.main()
