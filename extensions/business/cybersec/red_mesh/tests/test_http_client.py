import ast
from pathlib import Path
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.http_client import (
  GrayboxHttpClient,
  GrayboxScopeError,
  path_in_scope,
  validate_target_config_paths,
)


class TestGrayboxHttpClient(unittest.TestCase):

  def _session(self, response=None):
    session = MagicMock()
    resp = response or MagicMock(status_code=200, headers={})
    session.request.return_value = resp
    return session

  def test_path_prefix_matching_is_segment_aware(self):
    self.assertTrue(path_in_scope("/api/public/users", "/api/public/"))
    self.assertFalse(path_in_scope("/api/publicity", "/api/public/"))

  def test_blocks_cross_host_without_sending_request(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      allowlist=["/api/public/"],
    )
    session = self._session()

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "GET", "https://evil.example/api/public/")

    session.request.assert_not_called()

  def test_blocks_encoded_traversal_without_sending_request(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      allowlist=["/api/public/"],
    )
    session = self._session()

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "GET", "/api/public/%2e%2e/admin/")

    session.request.assert_not_called()

  def test_blocks_publicity_when_public_scope_authorized(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      allowlist=["/api/public/"],
    )
    session = self._session()

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "GET", "/api/publicity")

    session.request.assert_not_called()

  def test_allows_in_scope_templated_launch_path(self):
    errors = validate_target_config_paths(
      "https://api.example.com",
      {
        "login_path": "/api/public/login/",
        "logout_path": "/api/public/logout/",
        "api_security": {
          "object_endpoints": [
            {"path": "/api/public/users/{id}/"},
          ],
        },
      },
      ["/api/public/"],
    )
    self.assertEqual(errors, [])

  def test_blocks_out_of_scope_launch_path(self):
    errors = validate_target_config_paths(
      "https://api.example.com",
      {
        "login_path": "/api/public/login/",
        "logout_path": "/api/public/logout/",
        "api_security": {
          "function_endpoints": [
            {"path": "/admin/export-users/"},
          ],
        },
      },
      ["/api/public/"],
    )
    self.assertTrue(errors)
    self.assertIn("outside authorized scope", errors[0])

  def test_probe_modules_do_not_call_requests_directly(self):
    root = Path("extensions/business/cybersec/red_mesh/graybox/probes")
    forbidden = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
    violations = []
    for path in sorted(root.glob("*.py")):
      tree = ast.parse(path.read_text(), filename=str(path))
      for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
          continue
        func = node.func
        if (
          isinstance(func, ast.Attribute)
          and isinstance(func.value, ast.Name)
          and func.value.id == "requests"
          and func.attr in forbidden
        ):
          violations.append(f"{path}:{node.lineno}: requests.{func.attr}")
    self.assertEqual(violations, [])


if __name__ == "__main__":
  unittest.main()
