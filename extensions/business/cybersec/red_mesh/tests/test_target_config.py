"""Tests for GrayboxTargetConfig and typed endpoint models."""

import unittest

from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig,
  IdorEndpoint,
  AdminEndpoint,
  WorkflowEndpoint,
  SsrfEndpoint,
  AccessControlConfig,
  MisconfigConfig,
  InjectionConfig,
  BusinessLogicConfig,
  DiscoveryConfig,
  COMMON_CSRF_FIELDS,
)
from extensions.business.cybersec.red_mesh.constants import (
  ScanType,
  GRAYBOX_PROBE_REGISTRY,
)


class TestGrayboxTargetConfig(unittest.TestCase):

  def test_defaults(self):
    """All sections empty by default, login_path is /auth/login/."""
    cfg = GrayboxTargetConfig()
    self.assertEqual(cfg.login_path, "/auth/login/")
    self.assertEqual(cfg.logout_path, "/auth/logout/")
    self.assertEqual(cfg.username_field, "username")
    self.assertEqual(cfg.password_field, "password")
    self.assertEqual(cfg.csrf_field, "")
    self.assertEqual(cfg.access_control.idor_endpoints, [])
    self.assertEqual(cfg.access_control.admin_endpoints, [])
    self.assertEqual(cfg.injection.ssrf_endpoints, [])
    self.assertEqual(cfg.business_logic.workflow_endpoints, [])
    self.assertEqual(cfg.discovery.max_pages, 50)
    self.assertEqual(cfg.discovery.max_depth, 3)

  def test_from_dict_roundtrip(self):
    """Round-trip to_dict/from_dict with sectioned format."""
    cfg = GrayboxTargetConfig(
      access_control=AccessControlConfig(
        idor_endpoints=[IdorEndpoint(path="/api/records/{id}/", test_ids=[1, 2, 3])],
        admin_endpoints=[AdminEndpoint(path="/api/admin/export/")],
      ),
      injection=InjectionConfig(
        ssrf_endpoints=[SsrfEndpoint(path="/api/fetch/", param="url")],
      ),
      business_logic=BusinessLogicConfig(
        workflow_endpoints=[WorkflowEndpoint(path="/api/pay/", method="POST")],
      ),
      discovery=DiscoveryConfig(scope_prefix="/api/", max_pages=100),
      login_path="/login/",
      csrf_field="csrf_token",
    )
    d = cfg.to_dict()
    restored = GrayboxTargetConfig.from_dict(d)
    self.assertEqual(restored.login_path, "/login/")
    self.assertEqual(restored.csrf_field, "csrf_token")
    self.assertEqual(len(restored.access_control.idor_endpoints), 1)
    self.assertEqual(restored.access_control.idor_endpoints[0].path, "/api/records/{id}/")
    self.assertEqual(restored.access_control.idor_endpoints[0].test_ids, [1, 2, 3])
    self.assertEqual(restored.injection.ssrf_endpoints[0].param, "url")
    self.assertEqual(restored.discovery.scope_prefix, "/api/")
    self.assertEqual(restored.discovery.max_pages, 100)

  def test_from_dict_ignores_unknown(self):
    """Extra keys in dict don't raise."""
    cfg = GrayboxTargetConfig.from_dict({"unknown_key": "value", "nested": {"foo": 1}})
    self.assertEqual(cfg.login_path, "/auth/login/")

  def test_from_dict_empty(self):
    """Empty dict produces all defaults."""
    cfg = GrayboxTargetConfig.from_dict({})
    self.assertEqual(cfg.login_path, "/auth/login/")
    self.assertEqual(cfg.access_control.idor_endpoints, [])


class TestTypedEndpoints(unittest.TestCase):

  def test_idor_endpoint_from_dict(self):
    """IdorEndpoint constructs from dict correctly."""
    ep = IdorEndpoint.from_dict({"path": "/api/records/{id}/", "test_ids": [5, 10]})
    self.assertEqual(ep.path, "/api/records/{id}/")
    self.assertEqual(ep.test_ids, [5, 10])
    self.assertEqual(ep.owner_field, "owner")
    self.assertEqual(ep.id_param, "id")

  def test_idor_endpoint_missing_path(self):
    """IdorEndpoint raises on missing required 'path' field."""
    with self.assertRaises(KeyError):
      IdorEndpoint.from_dict({"test_ids": [1, 2]})

  def test_admin_endpoint_defaults(self):
    """AdminEndpoint defaults method to GET."""
    ep = AdminEndpoint.from_dict({"path": "/admin/"})
    self.assertEqual(ep.method, "GET")
    self.assertEqual(ep.content_markers, [])

  def test_workflow_endpoint_from_dict(self):
    """WorkflowEndpoint constructs correctly."""
    ep = WorkflowEndpoint.from_dict({
      "path": "/api/pay/",
      "method": "POST",
      "expected_guard": "403",
    })
    self.assertEqual(ep.path, "/api/pay/")
    self.assertEqual(ep.method, "POST")
    self.assertEqual(ep.expected_guard, "403")

  def test_ssrf_endpoint_defaults(self):
    """SsrfEndpoint defaults param to 'url'."""
    ep = SsrfEndpoint.from_dict({"path": "/api/fetch/"})
    self.assertEqual(ep.param, "url")

  def test_sections_independent(self):
    """Adding to one section doesn't affect others."""
    cfg = GrayboxTargetConfig(
      access_control=AccessControlConfig(
        idor_endpoints=[IdorEndpoint(path="/a/")],
      ),
    )
    self.assertEqual(len(cfg.access_control.idor_endpoints), 1)
    self.assertEqual(cfg.injection.ssrf_endpoints, [])
    self.assertEqual(cfg.business_logic.workflow_endpoints, [])

  def test_misconfig_default_paths(self):
    """MisconfigConfig has sensible default debug paths."""
    cfg = MisconfigConfig()
    self.assertIn("/.env", cfg.debug_paths)
    self.assertIn("/actuator", cfg.debug_paths)

  def test_discovery_config_from_dict(self):
    """DiscoveryConfig round-trips correctly."""
    dc = DiscoveryConfig.from_dict({"scope_prefix": "/app/", "max_pages": 25, "max_depth": 5})
    self.assertEqual(dc.scope_prefix, "/app/")
    self.assertEqual(dc.max_pages, 25)
    self.assertEqual(dc.max_depth, 5)


class TestScanTypeEnum(unittest.TestCase):

  def test_scan_type_values(self):
    """ScanType.WEBAPP == 'webapp', ScanType.NETWORK == 'network'."""
    self.assertEqual(ScanType.WEBAPP, "webapp")
    self.assertEqual(ScanType.NETWORK, "network")
    self.assertEqual(ScanType.WEBAPP.value, "webapp")

  def test_scan_type_is_str(self):
    """ScanType members are strings (str, Enum)."""
    self.assertIsInstance(ScanType.WEBAPP, str)
    self.assertIsInstance(ScanType.NETWORK, str)


class TestProbeRegistry(unittest.TestCase):

  def test_registry_structure(self):
    """All entries have 'key' and 'cls' fields."""
    for entry in GRAYBOX_PROBE_REGISTRY:
      self.assertIn("key", entry, f"Missing 'key' in registry entry: {entry}")
      self.assertIn("cls", entry, f"Missing 'cls' in registry entry: {entry}")

  def test_registry_keys_only(self):
    """Registry entries have exactly 'key' and 'cls' — capabilities live on probe class."""
    for entry in GRAYBOX_PROBE_REGISTRY:
      self.assertEqual(set(entry.keys()), {"key", "cls"},
        f"Registry entry has extra keys: {entry}")

  def test_registry_has_expected_probes(self):
    """Registry includes access_control, misconfig, injection, business_logic."""
    keys = [e["key"] for e in GRAYBOX_PROBE_REGISTRY]
    self.assertIn("_graybox_access_control", keys)
    self.assertIn("_graybox_misconfig", keys)
    self.assertIn("_graybox_injection", keys)
    self.assertIn("_graybox_business_logic", keys)


class TestCsrfFields(unittest.TestCase):

  def test_common_csrf_fields(self):
    """COMMON_CSRF_FIELDS contains Django, Flask, Rails, Spring, Laravel."""
    self.assertIn("csrfmiddlewaretoken", COMMON_CSRF_FIELDS)
    self.assertIn("csrf_token", COMMON_CSRF_FIELDS)
    self.assertIn("authenticity_token", COMMON_CSRF_FIELDS)
    self.assertIn("_csrf", COMMON_CSRF_FIELDS)
    self.assertIn("_token", COMMON_CSRF_FIELDS)


if __name__ == '__main__':
  unittest.main()
