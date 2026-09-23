import ast
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import requests

from extensions.business.cybersec.red_mesh.graybox.http_client import (
  GrayboxHttpClient,
  GrayboxScopeError,
  normalize_request_url,
  path_in_scope,
  validate_target_config_paths,
)
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.execution import ExecutionBinding


class RecordingAdapter(requests.adapters.BaseAdapter):
  """Only the HTTP transport is fake; requests still prepares every request."""

  def __init__(self, replies=()):
    self.sent = []
    self.replies = list(replies)

  def send(self, request, **kwargs):
    self.sent.append(request)
    response = requests.Response()
    response.status_code, response.headers = (
      self.replies.pop(0) if self.replies else (200, {})
    )
    response.url = request.url
    response.request = request
    response._content = b"ok"
    response.connection = self
    return response

  def close(self):
    pass


class TestBoundGrayboxHttpClient(unittest.TestCase):

  def _binding(self, target=None):
    target = target or {"kind": "webapp", "url": "https://target.example/api/public",
                        "allowedPathPrefix": "/api/public"}
    return ExecutionBinding({
      "schema_version": 1, "namespace": "deployment",
      "tenant_id": "tn_11111111-1111-4111-8111-111111111111",
      "asset_id": "as_22222222-2222-4222-8222-222222222222",
      "asset_target": target, "asset_target_digest": canonical_digest(target),
      "actor_id": "actor", "actor_generation": "generation-1",
      "node_failure_policy": "stop", "original_launcher": "node-a",
      "participant_order": ["node-a"],
    })

  def _client(self, **kwargs):
    return GrayboxHttpClient(
      "https://target.example/api/public", execution_binding=self._binding(),
      **kwargs,
    )

  def _session(self, replies=()):
    session = requests.Session()
    session.trust_env = False
    adapter = RecordingAdapter(replies)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    self.addCleanup(session.close)
    return session, adapter

  def test_bound_target_restricts_a_broader_legacy_allowlist(self):
    client = self._client(allowlist=["/"])
    session, transport = self._session()

    with self.assertRaises(GrayboxScopeError):
      client.wrap_session(session).get("/admin")

    self.assertEqual(transport.sent, [])

  def test_preparation_cannot_retarget_an_in_scope_request(self):
    client = self._client(allowlist=["/"])
    session, transport = self._session()

    def retarget(request):
      request.url = "https://target.example/admin"
      return request

    with self.assertRaises(GrayboxScopeError):
      client.wrap_session(session).get("/api/public/users", auth=retarget)

    self.assertEqual(transport.sent, [])

  def test_bound_host_header_cannot_route_to_another_origin(self):
    session, transport = self._session()
    scoped = self._client().wrap_session(session)

    with self.assertRaises(GrayboxScopeError):
      scoped.get("/api/public/users", headers={"Host": "foreign.example"})

    self.assertEqual(transport.sent, [])

  def test_bound_duplicate_host_headers_deny_before_preparation_collapses_them(self):
    headers = {"Host": "target.example", "hOsT": "target.example"}
    for source in ("request", "session", "auth"):
      with self.subTest(source=source):
        session, transport = self._session()
        scoped = self._client().wrap_session(session)
        kwargs = {}
        if source == "request":
          kwargs["headers"] = headers
        elif source == "session":
          session.headers = headers
        else:
          def duplicate(request):
            request.headers = headers
            return request
          kwargs["auth"] = duplicate
        with self.assertRaises(GrayboxScopeError):
          scoped.get("/api/public/users", **kwargs)
        self.assertEqual(transport.sent, [])

  def test_auth_cannot_hide_a_host_override_in_non_string_header_names(self):
    session, transport = self._session()
    scoped = self._client().wrap_session(session)
    def retarget(request):
      request.headers = {b"Host": "foreign.example"}
      return request

    with self.assertRaises(GrayboxScopeError):
      scoped.get("/api/public/users", auth=retarget)

    self.assertEqual(transport.sent, [])

  def test_bound_host_authority_accepts_only_equivalent_case_ports_and_ip_forms(self):
    for origin, accepted, rejected in (
      ("https://target.example", ("target.example", "TARGET.EXAMPLE", "target.example:443"),
       ("target.example:80", "target.example:8443", "foreign.example")),
      ("http://target.example", ("target.example", "TARGET.EXAMPLE:80"), ("target.example:443",)),
      ("https://target.example:8443", ("TARGET.EXAMPLE:8443",), ("target.example", "target.example:443")),
      ("https://192.0.2.1", ("192.0.2.1", "192.0.2.1:443"), ("192.0.2.2", "192.0.2.01")),
      ("https://[2001:db8::1]", ("[2001:db8::1]", "[2001:0DB8:0:0:0:0:0:1]:443"),
       ("[2001:db8::2]", "2001:db8::1", "[2001:db8::1]:80")),
    ):
      target = {"kind": "webapp", "url": origin + "/api/public", "allowedPathPrefix": "/api/public"}
      for host in (*accepted, *rejected):
        with self.subTest(origin=origin, host=host):
          session, transport = self._session()
          scoped = GrayboxHttpClient(target["url"], execution_binding=self._binding(target)).wrap_session(session)
          if host in accepted:
            scoped.get("/api/public/users", headers={"hOsT": host})
            self.assertEqual(len(transport.sent), 1)
            self.assertEqual(transport.sent[0].headers["Host"], host)
          else:
            with self.assertRaises(GrayboxScopeError):
              scoped.get("/api/public/users", headers={"hOsT": host})
            self.assertEqual(transport.sent, [])

  def test_bound_host_headers_deny_ambiguous_authorities_and_names(self):
    for headers in (
      {"Host": ""}, {"Host": None}, {"Host": "target.example."},
      {"Host": "target.example:0443"}, {"Host": "target.example/other"},
      {"Host": "target.example,foreign.example"}, {"Host": "user@target.example"},
      {"Host": "target.example\t"}, {"Host ": "target.example"}, {b"Host": "target.example"},
    ):
      with self.subTest(headers=headers):
        session, transport = self._session()
        with self.assertRaises(GrayboxScopeError):
          self._client().wrap_session(session).get("/api/public/users", headers=headers)
        self.assertEqual(transport.sent, [])

  def test_auth_retry_redirect_and_exhausted_cleanup_cannot_override_host(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    for effect in ("auth", "retry", "redirect", "cleanup"):
      with self.subTest(effect=effect):
        session, transport = self._session([(302, {"Location": "/api/public/done"})])
        scoped = self._client(request_budget=RequestBudget(remaining=0, total=1)).wrap_session(session)
        kwargs = {"budget_exempt": True}
        if effect == "auth":
          def retarget(request):
            request.headers["Host"] = "foreign.example"
            return request
          kwargs["auth"] = retarget
        elif effect == "retry":
          def retry(response, **kwargs):
            request = response.request.copy()
            request.headers["Host"] = "foreign.example"
            return response.connection.send(request, **kwargs)
          kwargs["hooks"] = {"response": retry}
        elif effect == "redirect":
          def retarget_next(response, **kwargs):
            session.headers["Host"] = "foreign.example"
            return response
          kwargs.update(hooks={"response": retarget_next}, allow_redirects=True)
        else:
          kwargs["headers"] = {"Host": "foreign.example"}
        with self.assertRaises(GrayboxScopeError):
          scoped.post("/api/public/revert", **kwargs)
        self.assertEqual(len(transport.sent), 1 if effect in ("retry", "redirect") else 0)

  def test_real_auth_lifecycle_cannot_inject_a_foreign_gateway_host(self):
    from extensions.business.cybersec.red_mesh.graybox.auth import AuthManager
    from extensions.business.cybersec.red_mesh.graybox.models import GrayboxTargetConfig
    config = GrayboxTargetConfig.from_dict({
      "login_path": "/api/public/login", "logout_path": "/api/public/logout",
      "api_security": {"gateway_auth": {"auth_type": "api_key", "api_key_header_name": "Host"}},
    })
    client = self._client(target_config=config, gateway_api_key="foreign.example")
    auth = AuthManager("https://target.example/api/public", config, http_client=client)
    transport = RecordingAdapter()
    with patch.object(requests.adapters.HTTPAdapter, "send", side_effect=transport.send):
      self.assertIsNotNone(auth.preflight_check())
      self.assertIsNone(auth.try_credentials("fixture-user", "fixture-password"))
      auth.official_session = auth.make_anonymous_session()
      auth.cleanup()
    self.assertEqual(transport.sent, [])

  def test_redirect_rechecks_duplicate_host_inputs_after_response_hooks(self):
    session, transport = self._session([(302, {"Location": "/api/public/done"})])
    def duplicate_next(response, **kwargs):
      session.headers = {"Host": "target.example", "host": "target.example"}
      return response
    with self.assertRaises(GrayboxScopeError):
      self._client().wrap_session(session).get("/api/public/start", allow_redirects=True,
        hooks={"response": duplicate_next})
    self.assertEqual(len(transport.sent), 1)

  def test_unbound_host_override_keeps_legacy_behavior(self):
    session, transport = self._session()
    GrayboxHttpClient("https://target.example").wrap_session(session).get(
      "/api/public/users", headers={"Host": "foreign.example"},
    )
    self.assertEqual(transport.sent[0].headers["Host"], "foreign.example")

  def test_bound_session_cannot_send_an_unchecked_prepared_request(self):
    session, transport = self._session()
    scoped = self._client(allowlist=["/"]).wrap_session(session)
    prepared = requests.Request("GET", "https://foreign.example/admin").prepare()

    with self.assertRaises(GrayboxScopeError):
      scoped.send(prepared, allow_redirects=True)

    self.assertEqual(transport.sent, [])

  def test_entering_a_bound_session_cannot_return_the_raw_session(self):
    session, transport = self._session()
    scoped = self._client(allowlist=["/"]).wrap_session(session)
    entered = scoped.__enter__()
    with self.assertRaises(GrayboxScopeError):
      entered.get("https://foreign.example/admin")
    self.assertEqual(transport.sent, [])

  def test_wrapping_a_legacy_session_cannot_drop_the_binding(self):
    session, transport = self._session()
    legacy = GrayboxHttpClient("https://target.example", allowlist=["/"])
    scoped = self._client(allowlist=["/"]).wrap_session(legacy.wrap_session(session))

    with self.assertRaises(GrayboxScopeError):
      scoped.get("/admin")
    self.assertEqual(transport.sent, [])

    scoped.get("/api/public/users")
    self.assertEqual([request.url for request in transport.sent],
                     ["https://target.example/api/public/users"])

  def test_bound_session_does_not_expose_raw_transport_effects(self):
    prepared = requests.Request("GET", "https://foreign.example/admin").prepare()
    response = requests.Response()
    response.status_code = 302
    response.url = "https://target.example/api/public/start"
    response.headers = {"Location": "https://foreign.example/admin"}
    response._content = b""
    for effect in (
      lambda scoped: scoped.get_adapter(prepared.url).send(prepared),
      lambda scoped: scoped.adapters["https://"].send(prepared),
      lambda scoped: list(scoped.resolve_redirects(response, prepared)),
    ):
      with self.subTest(effect=effect):
        session, transport = self._session()
        scoped = self._client().wrap_session(session)
        with self.assertRaises(GrayboxScopeError):
          effect(scoped)
        self.assertEqual(transport.sent, [])

  def test_relative_redirect_uses_the_preceding_request_url(self):
    session, transport = self._session([
      (302, {"Location": "next"}),
      (302, {"Location": "../done"}),
      (200, {}),
    ])
    self._client(allowlist=["/"]).wrap_session(session).get(
      "/api/public/flow/start", allow_redirects=True,
    )
    self.assertEqual([request.url for request in transport.sent], [
      "https://target.example/api/public/flow/start",
      "https://target.example/api/public/flow/next",
      "https://target.example/api/public/done",
    ])

  def test_worker_passes_the_saved_binding_to_its_real_http_client(self):
    from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxLocalWorker
    from extensions.business.cybersec.red_mesh.models import JobConfig
    config = JobConfig.from_dict({
      "target": "target.example", "target_url": "https://target.example/api/public",
      "start_port": 443, "end_port": 443, "scan_type": "webapp",
      "target_allowlist": ["/"], "execution_binding": self._binding().to_dict(),
    })
    worker = GrayboxLocalWorker(MagicMock(), "bound-job", config.target_url, config)
    session, transport = self._session()

    with self.assertRaises(GrayboxScopeError):
      worker.http_client.wrap_session(session).get("/admin", budget_exempt=True)

    self.assertEqual(transport.sent, [])

  def test_mutable_options_and_binding_projections_cannot_widen_scope(self):
    from extensions.business.cybersec.red_mesh.graybox.models import GrayboxTargetConfig
    binding = self._binding().to_dict()
    allowlist = ["/"]
    target_config = GrayboxTargetConfig.from_dict({"discovery": {"scope_prefix": "/"}})
    client = GrayboxHttpClient(
      "https://target.example/api/public", execution_binding=binding,
      allowlist=allowlist, target_config=target_config,
    )
    binding["asset_target"]["allowedPathPrefix"] = "/"
    binding["asset_target"]["url"] = "https://foreign.example/"
    allowlist.append("https://foreign.example/")
    client.scopes[:] = ["/"]
    client.target_url = "https://foreign.example"
    session, transport = self._session()
    with self.assertRaises(GrayboxScopeError):
      client.wrap_session(session).get("/api/public/users")
    self.assertEqual(transport.sent, [])

  def test_bound_and_legacy_path_scopes_are_both_required(self):
    session, transport = self._session()
    scoped = self._client(allowlist=["/api/public/read"]).wrap_session(session)
    with self.assertRaises(GrayboxScopeError):
      scoped.get("/api/public/write")
    scoped.get("/api/public/read/42?name=alice%20smith")
    self.assertEqual([request.url for request in transport.sent],
                     ["https://target.example/api/public/read/42?name=alice%20smith"])

  def test_bound_request_and_cleanup_deny_ambiguous_or_foreign_targets(self):
    for path in (
      "/api/publicity", "/api/private", "../private", "/api/public/%2e%2e/private",
      "/api/public/%25252e%25252e/private", "/api/public/%5c../private",
      "https://foreign.example/api/public", "http://target.example/api/public",
      "https://target.example:8443/api/public", "//foreign.example/api/public",
    ):
      for cleanup in (False, True):
        with self.subTest(path=path, cleanup=cleanup):
          session, transport = self._session()
          scoped = self._client(allowlist=["/"]).wrap_session(session)
          with self.assertRaises(GrayboxScopeError):
            scoped.post(path, budget_exempt=cleanup)
          self.assertEqual(transport.sent, [])

  def test_redirects_cannot_leave_binding_even_for_exhausted_cleanup(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    for location in ("/admin/revert", "/api/publicity", "https://foreign.example/",
                     "../private", "%2e%2e/private"):
      with self.subTest(location=location):
        session, transport = self._session([(302, {"Location": location})])
        budget = RequestBudget(remaining=0, total=1)
        scoped = self._client(allowlist=["/"], request_budget=budget).wrap_session(session)
        with self.assertRaises(GrayboxScopeError):
          scoped.post("/api/public/revert", allow_redirects=True, budget_exempt=True)
        self.assertEqual([request.url for request in transport.sent],
                         ["https://target.example/api/public/revert"])
        self.assertEqual(budget.remaining, 0)

  def test_bound_cleanup_can_finish_in_scope_after_budget_exhaustion(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    session, transport = self._session([(302, {"Location": "done"}), (200, {})])
    scoped = self._client(request_budget=RequestBudget(remaining=0, total=1)).wrap_session(session)
    response = scoped.post("/api/public/revert", allow_redirects=True, budget_exempt=True)
    self.assertEqual(response.status_code, 200)
    self.assertEqual([request.url for request in transport.sent],
                     ["https://target.example/api/public/revert", "https://target.example/api/public/done"])

  def test_prepared_url_and_auth_retry_use_the_same_bound_target(self):
    for url in ("https://foreign.example/api/public", "https://target.example/api/publicity",
                "https://target.example/api/public/%252e%252e/private"):
      with self.subTest(url=url):
        session, transport = self._session()
        scoped = self._client(allowlist=["/"]).wrap_session(session)
        def retarget(request):
          request.url = url
          return request
        with self.assertRaises(GrayboxScopeError):
          scoped.get("/api/public/start", auth=retarget)
        self.assertEqual(transport.sent, [])

        def retry(response, **kwargs):
          request = response.request.copy()
          request.url = url
          return response.connection.send(request, **kwargs)
        with self.assertRaises(GrayboxScopeError):
          scoped.get("/api/public/start", hooks={"response": retry})
        self.assertEqual([request.url for request in transport.sent],
                         ["https://target.example/api/public/start"])

  def test_real_login_preflight_and_logout_deny_out_of_scope_effects(self):
    from extensions.business.cybersec.red_mesh.graybox.auth import AuthManager
    from extensions.business.cybersec.red_mesh.graybox.models import GrayboxTargetConfig
    for origin in ("https://target.example", "https://foreign.example"):
      with self.subTest(origin=origin):
        config = GrayboxTargetConfig.from_dict({
          "login_path": "/admin/login", "logout_path": "/admin/logout",
        })
        auth = AuthManager(origin, config, http_client=self._client(allowlist=["/"]))
        transport = RecordingAdapter()
        with patch.object(requests.adapters.HTTPAdapter, "send", side_effect=transport.send):
          self.assertIsNotNone(auth.preflight_check())
          self.assertIsNone(auth.try_credentials("fixture-user", "fixture-password"))
          auth.official_session = auth.make_anonymous_session()
          auth.cleanup()
        self.assertEqual(transport.sent, [])


class TestGrayboxHttpClient(unittest.TestCase):

  def _session(self, response=None):
    session = MagicMock()
    resp = response or MagicMock(status_code=200, headers={})
    session.request.return_value = resp
    return session

  def test_legacy_rewrapping_preserves_the_existing_session_scope(self):
    session = self._session()
    original = GrayboxHttpClient("https://original.example", allowlist=["/api/"])
    another = GrayboxHttpClient("https://another.example")
    another.wrap_session(original.wrap_session(session)).get("/api/users")
    self.assertEqual(session.request.call_args.args[1], "https://original.example/api/users")

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

  def test_a_followed_chain_reports_the_hops_it_consumed(self):
    """`response.history` must carry the redirect chain this client resolved.

    We follow redirects one `allow_redirects=False` hop at a time so every hop
    re-enters `validate_url`. `requests` populates `history` only for chains it
    followed itself, so without an explicit assignment the attribute is
    permanently empty and every caller reading it concludes no redirect
    happened — which is how the login-form check in `_is_login_success` came to
    reject every authenticated session reached via a redirect.
    """
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/a/", "/b/", "/c/"],
    )
    session = MagicMock()
    first = MagicMock(status_code=302, headers={"Location": "/b/"})
    second = MagicMock(status_code=302, headers={"Location": "/c/"})
    final = MagicMock(status_code=200, headers={})
    session.request.side_effect = [first, second, final]

    result = client.request(session, "GET", "/a/", allow_redirects=True)

    self.assertIs(result, final)
    self.assertEqual(list(result.history), [first, second])

  def test_a_call_that_was_not_redirected_reports_an_empty_chain(self):
    """No redirect means no history — the same answer `requests` gives."""
    client = GrayboxHttpClient("https://target.local", allowlist=["/a/"])
    session = MagicMock()
    final = MagicMock(status_code=200, headers={})
    session.request.side_effect = [final]

    result = client.request(session, "GET", "/a/", allow_redirects=True)

    self.assertEqual(list(result.history), [])

  def test_a_chain_cut_short_by_the_budget_still_reports_its_hops(self):
    """Budget exhaustion returns the last response we did fetch, chain intact."""
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    client = GrayboxHttpClient(
      "https://target.local",
      allowlist=["/a/", "/b/", "/c/"],
      # The probe already paid for hop 0, so nothing is left for the redirect.
      request_budget=RequestBudget(remaining=0, total=1),
    )
    session = MagicMock()
    first = MagicMock(status_code=302, headers={"Location": "/b/"})
    session.request.side_effect = [first]

    result = client.request(session, "GET", "/a/", allow_redirects=True)

    self.assertIs(result, first)
    self.assertEqual(list(result.history), [])

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


class TestRequestUrlBasePathMatrix(unittest.TestCase):
  """
  Base path x link type. `normalize_request_url` resolved every relative link
  against the *origin*, discarding any base path in the target URL, while
  `discovery.py:181` resolved the same link with `urljoin` against the base.
  One link therefore produced two different URLs depending on which path
  handled it.

  Measured before the fix: 10 of 24 combinations diverged, and every one of them
  was a target carrying a base path. Scanning `https://host/app`, a relative
  link `users` was requested at `https://host/users` — which 404s, so the probe
  reports "not vulnerable" for an endpoint it never reached. A false-negative
  generator, invisible whenever the test target is a bare host, which is why it
  survived.

  Root-relative links (`/users`) must stay origin-relative; that is RFC 3986 and
  those cases were already correct.
  """

  BASES = ("https://h", "https://h/", "https://h/app", "https://h/app/")

  # (link, expected path for a bare-origin base, expected path under /app)
  LINKS = (
    ("users", "/users", "/app/users"),
    ("./users", "/users", "/app/users"),
    ("sub/users", "/sub/users", "/app/sub/users"),
    ("users?q=1", "/users?q=1", "/app/users?q=1"),
    # Root-relative and absolute forms ignore the base path, by spec.
    ("/users", "/users", "/users"),
    ("https://h/users", "/users", "/users"),
  )

  def test_a_relative_link_resolves_against_the_targets_base_path(self):
    for base in self.BASES:
      has_base_path = "/app" in base
      for link, bare_expected, app_expected in self.LINKS:
        expected = app_expected if has_base_path else bare_expected
        with self.subTest(base=base, link=link):
          self.assertEqual(
            normalize_request_url(base, link),
            f"https://h{expected}",
          )

  # (link, expected path for a bare-origin base, expected path under /app).
  # A parent-relative link is ordinary RFC 3986 resolution and `discovery.py`
  # produces them routinely. Treating a literal `..` as an attack rejected them
  # outright, so the probe reported "not vulnerable" for an endpoint it had
  # refused to request — the same false-negative class the base-path fix above
  # exists to remove, arrived at from the other direction.
  PARENT_LINKS = (
    ("../users", "/users", "/users"),
    ("../../users", "/users", "/users"),
    ("a/../b", "/b", "/app/b"),
    ("./../x", "/x", "/x"),
  )

  def test_a_parent_relative_link_resolves_rather_than_being_refused(self):
    for base in self.BASES:
      has_base_path = "/app" in base
      for link, bare_expected, app_expected in self.PARENT_LINKS:
        expected = app_expected if has_base_path else bare_expected
        with self.subTest(base=base, link=link):
          self.assertEqual(
            normalize_request_url(base, link),
            f"https://h{expected}",
          )

  def test_traversal_past_the_root_clamps_on_origin_instead_of_escaping(self):
    # The property that makes allowing `..` safe: it cannot change the netloc,
    # which is what enforces scope. `urljoin` clamps at the origin root.
    self.assertEqual(
      normalize_request_url("https://h/app/", "../../../../etc/passwd"),
      "https://h/etc/passwd",
    )

  def test_encoded_traversal_is_still_refused(self):
    # These survive `urljoin` untouched and reach the server as a literal
    # payload for it to decode. Following a discovered link never needs them.
    for hostile in ("%2e%2e/users", "..%2fusers", "%252e%252e/users",
                    "%2E%2E/users", "a/%2e%2e/b"):
      for base in self.BASES:
        with self.subTest(base=base, link=hostile):
          with self.assertRaises(GrayboxScopeError):
            normalize_request_url(base, hostile)

  def test_cross_origin_is_still_refused(self):
    for base in self.BASES:
      for hostile in ("https://evil.test/users", "http://h/users", "https://h:8443/users"):
        with self.subTest(base=base, link=hostile):
          with self.assertRaises(GrayboxScopeError):
            normalize_request_url(base, hostile)

  def test_the_base_path_was_never_the_scope_boundary(self):
    """`..` and `/` are two spellings of the same reach, and `/` was always allowed.

    A root-relative link left the base path unconditionally — `/etc/passwd` from
    a `https://h/app` target resolved and was requested. Refusing `../etc/passwd`
    while permitting `/etc/passwd` did not constrain anything; it only made the
    two spellings disagree, and rejected the one `discovery.py` emits. What
    actually bounds a scan by path is the allowlist, enforced in
    `GrayboxHttpClient.request` against `path_in_scope`.
    """
    self.assertEqual(
      normalize_request_url("https://h/app", "../../etc/passwd"),
      normalize_request_url("https://h/app", "/etc/passwd"),
    )

  def test_the_allowlist_is_what_refuses_a_path_outside_the_scan_scope(self):
    from extensions.business.cybersec.red_mesh.graybox.http_client import (
      path_in_scope, path_scopes_from_allowlist,
    )
    scopes = path_scopes_from_allowlist("https://h/app", ["https://h/app"])
    self.assertTrue(scopes, "no path scope was derived from the allowlist")
    self.assertTrue(any(path_in_scope("/app/users", scope) for scope in scopes))
    self.assertFalse(any(path_in_scope("/etc/passwd", scope) for scope in scopes))


class TestRedirectHopBudgetAccounting(unittest.TestCase):
  """
  A probe consults the shared budget once per logical call, then
  `GrayboxHttpClient.request` follows up to five redirects — each a real HTTP
  request that nobody counted. Measured: one redirecting call issued 5 requests
  against a single consume, so `budget_remaining` over-reported by 4 and the cap
  that exists to stop the scanner DoSing a target could be exceeded five-fold by
  a target that simply redirects.

  Only the *extra* hops are charged here. The probe's own consume covers the
  first request, so charging it again would double-count every ordinary call.
  """

  def _redirecting_session(self, hops):
    calls = {"n": 0}
    def fake_request(method, url, **kwargs):
      calls["n"] += 1
      resp = MagicMock()
      if calls["n"] <= hops:
        resp.status_code = 302
        resp.headers = {"Location": f"/hop{calls['n']}"}
      else:
        resp.status_code = 200
        resp.headers = {}
      return resp
    session = MagicMock()
    session.request.side_effect = fake_request
    return session, calls

  def test_every_redirect_hop_is_charged_to_the_budget(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=10, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=4)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    # 5 real requests: the first plus 4 hops. The probe would have consumed the
    # first, so the client charges the 4 extra.
    self.assertEqual(calls["n"], 5)
    self.assertEqual(budget.remaining, 10 - 4)

  def test_a_chain_stops_when_the_budget_runs_out(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=2, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=4)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    # First request, then only as many hops as the budget covers.
    self.assertEqual(calls["n"], 3)
    self.assertEqual(budget.remaining, 0)
    self.assertGreaterEqual(budget.exhausted_count, 1)

  def test_a_non_redirecting_call_is_not_charged(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=10, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=0)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    self.assertEqual(calls["n"], 1)
    self.assertEqual(budget.remaining, 10, "the probe already paid for this one")

  def test_the_cleanup_path_is_exempt(self):
    # Budget exhaustion must never prevent a revert, which is the existing
    # contract of ProbeBase.cleanup_budget.
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=0, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=2)
    client.request(session, "GET", "https://h/revert", allow_redirects=True,
                   budget_exempt=True)
    self.assertEqual(calls["n"], 3, "a revert was blocked by an exhausted budget")

  def test_it_works_without_a_budget_configured(self):
    client = GrayboxHttpClient("https://h", allowlist=["h"])
    session, calls = self._redirecting_session(hops=2)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    self.assertEqual(calls["n"], 3)


if __name__ == "__main__":
  unittest.main()
