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

  def test_post_redirect_302_converts_to_get_and_drops_body(self):
    """Browser-equivalent 302 handling — Django form-login redirect target
    must not receive the original POST body, or the redirected request
    fails CSRF on the new view (the bug behind official_login_failed)."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/auth/", "/dashboard/"],
    )
    session = MagicMock()
    redirect_resp = MagicMock(
      status_code=302, headers={"Location": "/dashboard/"},
    )
    final_resp = MagicMock(status_code=200, headers={})
    session.request.side_effect = [redirect_resp, final_resp]

    result = client.request(
      session, "POST", "/auth/login/",
      data={"username": "admin", "password": "secret",
            "csrfmiddlewaretoken": "tok"},
      allow_redirects=True,
    )

    self.assertIs(result, final_resp)
    self.assertEqual(session.request.call_count, 2)
    first_call = session.request.call_args_list[0]
    self.assertEqual(first_call.args[0], "POST")
    self.assertIn("login", first_call.args[1])
    self.assertIn("data", first_call.kwargs)

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "GET")
    self.assertIn("dashboard", second_call.args[1])
    self.assertNotIn("data", second_call.kwargs)
    self.assertNotIn("json", second_call.kwargs)

  def test_post_redirect_301_converts_to_get_and_drops_body(self):
    """301 from POST is also browser-equivalent GET (matches `requests`)."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/old/", "/new/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=301, headers={"Location": "/new/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/old/", data={"k": "v"}, allow_redirects=True,
    )

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "GET")
    self.assertNotIn("data", second_call.kwargs)

  def test_post_redirect_307_preserves_method_and_body(self):
    """307 (and 308) explicitly preserve method + body per RFC 7231."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/api/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=307, headers={"Location": "/api/v2/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/api/v1/", data={"k": "v"}, allow_redirects=True,
    )

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "POST")
    self.assertEqual(second_call.kwargs.get("data"), {"k": "v"})

  def test_post_redirect_303_still_converts(self):
    """Pre-existing 303 conversion path must keep working (regression guard)."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/api/", "/done/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=303, headers={"Location": "/done/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/api/", data={"k": "v"}, allow_redirects=True,
    )

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "GET")
    self.assertNotIn("data", second_call.kwargs)

  def test_head_on_302_stays_head(self):
    """HEAD is idempotent + has no body; preserve method on redirect."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/a/", "/b/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=302, headers={"Location": "/b/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(session, "HEAD", "/a/", allow_redirects=True)

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "HEAD")

  def test_302_without_location_returns_redirect_response(self):
    """No Location header → don't loop; return the redirect response as-is."""
    client = GrayboxHttpClient("https://target.local", allowlist=["/a/"])
    session = MagicMock()
    bad_redirect = MagicMock(status_code=302, headers={})
    session.request.return_value = bad_redirect

    result = client.request(session, "POST", "/a/", allow_redirects=True)

    self.assertIs(result, bad_redirect)
    self.assertEqual(session.request.call_count, 1)

  def test_302_to_out_of_scope_location_raises_scope_error(self):
    """Redirect to a path outside the allowlist must abort, not silently follow."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/auth/"],
    )
    session = MagicMock()
    session.request.return_value = MagicMock(
      status_code=302, headers={"Location": "/admin/secret/"},
    )

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "POST", "/auth/login/", allow_redirects=True)

  def test_redirect_loop_caps_at_five_hops(self):
    """A pathological redirect chain stops after 5 hops, returning the last response."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/loop/"],
    )
    session = MagicMock()
    session.request.return_value = MagicMock(
      status_code=302, headers={"Location": "/loop/"},
    )

    result = client.request(
      session, "POST", "/loop/", data={"k": "v"}, allow_redirects=True,
    )

    self.assertEqual(result.status_code, 302)
    self.assertEqual(session.request.call_count, 5)

  def test_chained_302_then_302_after_post_settles_on_get(self):
    """POST→302→GET; subsequent 302→GET stays GET (method conversion is sticky)."""
    client = GrayboxHttpClient(
      "https://target.local",
      allowlist=["/a/", "/b/", "/c/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=302, headers={"Location": "/b/"}),
      MagicMock(status_code=302, headers={"Location": "/c/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/a/", data={"k": "v"}, allow_redirects=True,
    )

    self.assertEqual(session.request.call_args_list[0].args[0], "POST")
    self.assertEqual(session.request.call_args_list[1].args[0], "GET")
    self.assertNotIn("data", session.request.call_args_list[1].kwargs)
    self.assertEqual(session.request.call_args_list[2].args[0], "GET")

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
