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
  ApiObjectEndpoint,
  ApiPropertyEndpoint,
  ApiFunctionEndpoint,
  ApiResourceEndpoint,
  ApiBusinessFlow,
  ApiTokenEndpoint,
  ApiInventoryPaths,
  ApiSecurityConfig,
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
    """Registry includes all legacy + five OWASP API Top 10 probe families."""
    keys = [e["key"] for e in GRAYBOX_PROBE_REGISTRY]
    # Legacy (Web Top 10)
    self.assertIn("_graybox_access_control", keys)
    self.assertIn("_graybox_misconfig", keys)
    self.assertIn("_graybox_injection", keys)
    self.assertIn("_graybox_business_logic", keys)
    # OWASP API Top 10 2023 (Subphase 1.3)
    self.assertIn("_graybox_api_access", keys)
    self.assertIn("_graybox_api_auth", keys)
    self.assertIn("_graybox_api_data", keys)
    self.assertIn("_graybox_api_config", keys)
    self.assertIn("_graybox_api_abuse", keys)

  def test_api_family_classes_importable(self):
    """Each new API family resolves via its module-relative dotted path."""
    import importlib
    api_keys = (
      "_graybox_api_access", "_graybox_api_auth", "_graybox_api_data",
      "_graybox_api_config", "_graybox_api_abuse",
    )
    by_key = {e["key"]: e for e in GRAYBOX_PROBE_REGISTRY}
    pkg = "extensions.business.cybersec.red_mesh.graybox.probes"
    for key in api_keys:
      with self.subTest(key=key):
        entry = by_key[key]
        module_name, class_name = entry["cls"].split(".", 1)
        mod = importlib.import_module(f"{pkg}.{module_name}")
        cls = getattr(mod, class_name)
        # ProbeBase capability flags present and probe is non-stateful by default.
        self.assertTrue(cls.requires_auth)
        self.assertFalse(cls.is_stateful)
        # run() returns iterable (skeleton returns self.findings == [])
        # Instantiation requires a context; we only verify class import here.


class TestCsrfFields(unittest.TestCase):

  def test_common_csrf_fields(self):
    """COMMON_CSRF_FIELDS contains Django, Flask, Rails, Spring, Laravel."""
    self.assertIn("csrfmiddlewaretoken", COMMON_CSRF_FIELDS)
    self.assertIn("csrf_token", COMMON_CSRF_FIELDS)
    self.assertIn("authenticity_token", COMMON_CSRF_FIELDS)
    self.assertIn("_csrf", COMMON_CSRF_FIELDS)
    self.assertIn("_token", COMMON_CSRF_FIELDS)


class TestApiSecurityConfig(unittest.TestCase):
  """Round-trip + defaults for the OWASP API Top 10 sub-models (Subphase 1.1)."""

  # ── ApiObjectEndpoint ──────────────────────────────────────────────────
  def test_api_object_endpoint_defaults(self):
    ep = ApiObjectEndpoint.from_dict({"path": "/api/records/{id}/"})
    self.assertEqual(ep.path, "/api/records/{id}/")
    self.assertEqual(ep.test_ids, [1, 2])
    self.assertEqual(ep.owner_field, "owner")
    self.assertEqual(ep.id_param, "id")
    self.assertEqual(ep.tenant_field, "")

  def test_api_object_endpoint_full(self):
    ep = ApiObjectEndpoint.from_dict({
      "path": "/api/orgs/{org}/users/{id}/",
      "test_ids": [5, 7, 11],
      "owner_field": "user_id",
      "id_param": "uid",
      "tenant_field": "org_id",
    })
    self.assertEqual(ep.test_ids, [5, 7, 11])
    self.assertEqual(ep.tenant_field, "org_id")

  def test_api_object_endpoint_missing_path(self):
    with self.assertRaises(KeyError):
      ApiObjectEndpoint.from_dict({"test_ids": [1]})

  # ── ApiPropertyEndpoint ────────────────────────────────────────────────
  def test_api_property_endpoint_defaults(self):
    ep = ApiPropertyEndpoint.from_dict({"path": "/api/profile/{id}/"})
    self.assertEqual(ep.method_read, "GET")
    self.assertEqual(ep.method_write, "PATCH")
    self.assertEqual(ep.test_id, 1)

  # ── ApiFunctionEndpoint ────────────────────────────────────────────────
  def test_api_function_endpoint_defaults(self):
    ep = ApiFunctionEndpoint.from_dict({"path": "/api/admin/users/"})
    self.assertEqual(ep.method, "GET")
    self.assertEqual(ep.privilege, "admin")
    self.assertEqual(ep.revert_path, "")
    self.assertEqual(ep.revert_body, {})

  def test_api_function_endpoint_with_revert(self):
    ep = ApiFunctionEndpoint.from_dict({
      "path": "/api/admin/users/{uid}/promote/",
      "method": "POST",
      "revert_path": "/api/admin/users/{uid}/demote/",
      "revert_body": {"reason": "test"},
    })
    self.assertEqual(ep.revert_path, "/api/admin/users/{uid}/demote/")
    self.assertEqual(ep.revert_body, {"reason": "test"})

  # ── ApiResourceEndpoint ────────────────────────────────────────────────
  def test_api_resource_endpoint_defaults(self):
    ep = ApiResourceEndpoint.from_dict({"path": "/api/records/"})
    self.assertEqual(ep.limit_param, "limit")
    self.assertEqual(ep.baseline_limit, 10)
    self.assertEqual(ep.abuse_limit, 999_999)
    self.assertFalse(ep.rate_limit_expected)

  # ── ApiBusinessFlow ────────────────────────────────────────────────────
  def test_api_business_flow_defaults(self):
    bf = ApiBusinessFlow.from_dict({"path": "/api/auth/signup/"})
    self.assertEqual(bf.method, "POST")
    self.assertEqual(bf.flow_name, "signup")
    self.assertEqual(bf.body_template, {})

  # ── ApiTokenEndpoint ───────────────────────────────────────────────────
  def test_api_token_endpoint_defaults(self):
    tok = ApiTokenEndpoint.from_dict({})
    self.assertEqual(tok.token_path, "")
    self.assertEqual(tok.protected_path, "")
    self.assertEqual(tok.logout_path, "")
    # Defaults include at least the obvious weak-secret entries
    self.assertIn("secret", tok.weak_secret_candidates)
    self.assertIn("changeme", tok.weak_secret_candidates)

  def test_api_token_endpoint_custom_wordlist(self):
    tok = ApiTokenEndpoint.from_dict({
      "token_path": "/api/token/",
      "protected_path": "/api/me/",
      "logout_path": "/api/auth/logout/",
      "weak_secret_candidates": ["a", "b"],
    })
    self.assertEqual(tok.weak_secret_candidates, ["a", "b"])

  # ── ApiInventoryPaths ──────────────────────────────────────────────────
  def test_api_inventory_paths_defaults(self):
    inv = ApiInventoryPaths.from_dict({})
    self.assertIn("/openapi.json", inv.openapi_candidates)
    self.assertIn("/swagger.json", inv.openapi_candidates)
    self.assertEqual(inv.current_version, "")
    self.assertEqual(inv.deprecated_paths, [])

  # ── ApiSecurityConfig wrapper ──────────────────────────────────────────
  def test_api_security_config_defaults(self):
    cfg = ApiSecurityConfig.from_dict({})
    self.assertEqual(cfg.object_endpoints, [])
    self.assertEqual(cfg.function_endpoints, [])
    self.assertEqual(cfg.business_flows, [])
    # Default SSRF body fields populated
    self.assertIn("url", cfg.ssrf_body_fields)
    self.assertIn("webhook", cfg.ssrf_body_fields)
    # Default tampering fields populated
    self.assertIn("is_admin", cfg.tampering_fields)
    # Default debug paths populated
    self.assertIn("/api/debug", cfg.debug_path_candidates)

  def test_api_security_config_full_roundtrip(self):
    """Populated payload survives from_dict cleanly."""
    payload = {
      "object_endpoints": [
        {"path": "/api/records/{id}/", "test_ids": [1, 2], "tenant_field": "tenant_id"},
      ],
      "property_endpoints": [
        {"path": "/api/profile/{id}/", "method_write": "PUT", "test_id": 42},
      ],
      "function_endpoints": [
        {"path": "/api/admin/users/{uid}/promote/",
         "method": "POST", "privilege": "admin",
         "revert_path": "/api/admin/users/{uid}/demote/"},
      ],
      "resource_endpoints": [
        {"path": "/api/records/list/", "abuse_limit": 50000,
         "rate_limit_expected": True},
      ],
      "business_flows": [
        {"path": "/api/auth/signup/", "flow_name": "signup",
         "body_template": {"username": "x", "email": "x@x"}},
      ],
      "token_endpoints": {
        "token_path": "/api/token/",
        "protected_path": "/api/me/",
        "logout_path": "/api/auth/logout/",
      },
      "inventory_paths": {
        "current_version": "/api/v2/",
        "canonical_probe_path": "/api/v2/records/1/",
        "deprecated_paths": ["/api/v1/legacy/"],
      },
      "sensitive_field_patterns": ["custom_*_secret"],
      "ssrf_body_fields": ["redirect_uri"],
    }
    cfg = ApiSecurityConfig.from_dict(payload)
    self.assertEqual(len(cfg.object_endpoints), 1)
    self.assertEqual(cfg.object_endpoints[0].tenant_field, "tenant_id")
    self.assertEqual(cfg.property_endpoints[0].method_write, "PUT")
    self.assertEqual(cfg.function_endpoints[0].revert_path, "/api/admin/users/{uid}/demote/")
    self.assertTrue(cfg.resource_endpoints[0].rate_limit_expected)
    self.assertEqual(cfg.business_flows[0].body_template, {"username": "x", "email": "x@x"})
    self.assertEqual(cfg.token_endpoints.logout_path, "/api/auth/logout/")
    self.assertEqual(cfg.inventory_paths.canonical_probe_path, "/api/v2/records/1/")
    self.assertEqual(cfg.sensitive_field_patterns, ["custom_*_secret"])
    # Explicit override replaces, not merges
    self.assertEqual(cfg.ssrf_body_fields, ["redirect_uri"])

  # ── GrayboxTargetConfig wiring ─────────────────────────────────────────
  def test_target_config_includes_api_security_default(self):
    cfg = GrayboxTargetConfig.from_dict({})
    self.assertIsInstance(cfg.api_security, ApiSecurityConfig)
    self.assertEqual(cfg.api_security.object_endpoints, [])

  def test_target_config_propagates_api_security_payload(self):
    cfg = GrayboxTargetConfig.from_dict({
      "api_security": {
        "object_endpoints": [{"path": "/api/x/{id}/"}],
      },
    })
    self.assertEqual(len(cfg.api_security.object_endpoints), 1)
    self.assertEqual(cfg.api_security.object_endpoints[0].path, "/api/x/{id}/")

  def test_target_config_missing_required_path_raises(self):
    """Missing required `path` should raise (mirrors IdorEndpoint contract)."""
    with self.assertRaises(KeyError):
      GrayboxTargetConfig.from_dict({
        "api_security": {"object_endpoints": [{"test_ids": [1]}]},
      })


if __name__ == '__main__':
  unittest.main()
