import base64
import json
import os
import threading
import time
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services.auth import (
  AuthConfigError,
  AuthError,
  BasicAuthProvider,
  StaticBearerProvider,
  WazuhJwtProvider,
  build_auth_provider,
)
from extensions.business.cybersec.red_mesh.services.auth.wazuh_jwt import (
  _b64url_decode_padded,
  _extract_exp,
  _purge_cache_for_tests,
)


def _make_jwt(exp_seconds_from_now: float = 900.0, *, drop_padding: bool = False) -> str:
  header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode("ascii")
  payload_obj = {"sub": "wazuh-wui", "exp": int(time.time() + exp_seconds_from_now)}
  payload_raw = json.dumps(payload_obj).encode("utf-8")
  payload_b64 = base64.urlsafe_b64encode(payload_raw)
  if drop_padding:
    payload_b64 = payload_b64.rstrip(b"=")
  # Signature is irrelevant — we don't verify; we just need the structural shape.
  return f"{header}.{payload_b64.decode('ascii')}.signature-not-verified"


class _FakeResponse:
  def __init__(self, body: bytes, status: int = 200):
    self._body = body
    self.status = status

  def __enter__(self):
    return self

  def __exit__(self, *_):
    return False

  def read(self):
    return self._body

  def getcode(self):
    return self.status


class _FakeHttpPost:
  """Records calls and returns canned responses; raises if exhausted."""

  def __init__(self, responses):
    self._responses = list(responses)
    self.calls = []
    self.lock = threading.Lock()

  def __call__(self, request, timeout=None):
    with self.lock:
      self.calls.append({"url": request.full_url, "headers": dict(request.header_items())})
      if not self._responses:
        raise AssertionError("no canned responses left for http_post")
      response = self._responses.pop(0)
    return response


class StaticBearerProviderTests(unittest.TestCase):
  def test_env_present_emits_bearer(self):
    provider = StaticBearerProvider(token_env="UNIT_TEST_TOKEN")
    with patch.dict(os.environ, {"UNIT_TEST_TOKEN": "abc.def"}):
      self.assertEqual(provider.headers(), {"Authorization": "Bearer abc.def"})

  def test_env_missing_returns_empty(self):
    provider = StaticBearerProvider(token_env="UNIT_TEST_MISSING")
    with patch.dict(os.environ, {}, clear=False):
      os.environ.pop("UNIT_TEST_MISSING", None)
      self.assertEqual(provider.headers(), {})

  def test_token_env_empty_returns_empty(self):
    provider = StaticBearerProvider(token_env="")
    self.assertEqual(provider.headers(), {})

  def test_invalidate_is_noop(self):
    provider = StaticBearerProvider(token_env="UNIT_TEST_TOKEN")
    provider.invalidate()
    provider.invalidate()  # idempotent

  def test_repr_does_not_leak_token(self):
    provider = StaticBearerProvider(token_env="UNIT_TEST_TOKEN")
    with patch.dict(os.environ, {"UNIT_TEST_TOKEN": "secret-value"}):
      self.assertNotIn("secret-value", repr(provider))


class BasicAuthProviderTests(unittest.TestCase):
  def test_canonical_basic_header(self):
    provider = BasicAuthProvider(username="redmesh", password_env="UNIT_TAXII_PW")
    with patch.dict(os.environ, {"UNIT_TAXII_PW": "TaxiiAdmin2026"}):
      expected = base64.b64encode(b"redmesh:TaxiiAdmin2026").decode("ascii")
      self.assertEqual(provider.headers(), {"Authorization": f"Basic {expected}"})

  def test_password_with_colon_round_trips(self):
    provider = BasicAuthProvider(username="user", password_env="UNIT_TAXII_PW")
    with patch.dict(os.environ, {"UNIT_TAXII_PW": "pa:ss:wo:rd"}):
      header = provider.headers()["Authorization"]
      self.assertTrue(header.startswith("Basic "))
      decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
      # The username has no colon; first colon separates user from password.
      user, _, password = decoded.partition(":")
      self.assertEqual(user, "user")
      self.assertEqual(password, "pa:ss:wo:rd")

  def test_non_ascii_password_utf8(self):
    provider = BasicAuthProvider(username="usr", password_env="UNIT_TAXII_PW")
    with patch.dict(os.environ, {"UNIT_TAXII_PW": "pässwörd-π"}):
      header = provider.headers()["Authorization"]
      decoded = base64.b64decode(header.split(" ", 1)[1])
      self.assertEqual(decoded, "usr:pässwörd-π".encode("utf-8"))

  def test_missing_username_raises(self):
    provider = BasicAuthProvider(username="", password_env="UNIT_TAXII_PW")
    with patch.dict(os.environ, {"UNIT_TAXII_PW": "secret"}):
      with self.assertRaises(AuthError):
        provider.headers()

  def test_missing_password_env_raises(self):
    provider = BasicAuthProvider(username="u", password_env="UNIT_TAXII_MISSING")
    os.environ.pop("UNIT_TAXII_MISSING", None)
    with self.assertRaises(AuthError):
      provider.headers()


class WazuhJwtProviderTests(unittest.TestCase):
  def setUp(self):
    _purge_cache_for_tests()
    os.environ["UNIT_WAZUH_PW"] = "WazuhApi2026!"

  def tearDown(self):
    _purge_cache_for_tests()
    os.environ.pop("UNIT_WAZUH_PW", None)

  def _provider(self, http_post, **overrides):
    kwargs = dict(
      login_url="https://wazuh.example",
      username="wazuh-wui",
      password_env="UNIT_WAZUH_PW",
      timeout_seconds=1.0,
      http_post=http_post,
    )
    kwargs.update(overrides)
    return WazuhJwtProvider(**kwargs)

  def test_first_headers_call_logs_in(self):
    jwt = _make_jwt()
    http = _FakeHttpPost([_FakeResponse(jwt.encode("utf-8"))])
    provider = self._provider(http)
    self.assertEqual(provider.headers(), {"Authorization": f"Bearer {jwt}"})
    self.assertEqual(len(http.calls), 1)
    self.assertIn("/security/user/authenticate", http.calls[0]["url"])

  def test_second_call_within_ttl_hits_cache(self):
    jwt = _make_jwt()
    http = _FakeHttpPost([_FakeResponse(jwt.encode("utf-8"))])
    provider = self._provider(http)
    provider.headers()
    provider.headers()
    self.assertEqual(len(http.calls), 1)

  def test_invalidate_forces_relogin(self):
    jwt1 = _make_jwt()
    jwt2 = _make_jwt()
    http = _FakeHttpPost([
      _FakeResponse(jwt1.encode("utf-8")),
      _FakeResponse(jwt2.encode("utf-8")),
    ])
    provider = self._provider(http)
    provider.headers()
    provider.invalidate()
    headers = provider.headers()
    self.assertEqual(headers["Authorization"], f"Bearer {jwt2}")
    self.assertEqual(len(http.calls), 2)

  def test_expired_jwt_triggers_refresh(self):
    # exp is in the past — provider must immediately treat as expired.
    expired = _make_jwt(exp_seconds_from_now=-3600)
    fresh = _make_jwt(exp_seconds_from_now=900)
    http = _FakeHttpPost([
      _FakeResponse(expired.encode("utf-8")),
      _FakeResponse(fresh.encode("utf-8")),
    ])
    provider = self._provider(http)
    provider.headers()  # caches the expired token (login #1)
    headers = provider.headers()  # detects expiry → login #2
    self.assertEqual(headers["Authorization"], f"Bearer {fresh}")
    self.assertEqual(len(http.calls), 2)

  def test_jwt_without_padding_parses(self):
    jwt = _make_jwt(drop_padding=True)
    self.assertIsNotNone(_extract_exp(jwt))
    http = _FakeHttpPost([_FakeResponse(jwt.encode("utf-8"))])
    provider = self._provider(http)
    self.assertEqual(provider.headers()["Authorization"], f"Bearer {jwt}")

  def test_concurrent_callers_trigger_single_login(self):
    jwt = _make_jwt()
    http = _FakeHttpPost([_FakeResponse(jwt.encode("utf-8"))])
    provider = self._provider(http)

    barrier = threading.Barrier(8)
    results = []
    results_lock = threading.Lock()

    def worker():
      barrier.wait()
      headers = provider.headers()
      with results_lock:
        results.append(headers)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
      t.start()
    for t in threads:
      t.join(timeout=5.0)
    self.assertEqual(len(results), 8)
    self.assertEqual(len(http.calls), 1, "double-checked locking failed: extra login round-trips")
    for headers in results:
      self.assertEqual(headers, {"Authorization": f"Bearer {jwt}"})

  def test_module_cache_shared_across_provider_instances(self):
    jwt = _make_jwt()
    http = _FakeHttpPost([_FakeResponse(jwt.encode("utf-8"))])

    p1 = self._provider(http)
    p1.headers()

    # A second provider with the same (login_url, username) — even with a
    # fresh http_post stub — should reuse the cached entry without calling
    # the new stub at all.
    fresh_http = _FakeHttpPost([])  # would raise if called
    p2 = self._provider(fresh_http)
    headers = p2.headers()
    self.assertEqual(headers, {"Authorization": f"Bearer {jwt}"})
    self.assertEqual(len(fresh_http.calls), 0)

  def test_login_endpoint_5xx_raises_auth_error(self):
    http = _FakeHttpPost([_FakeResponse(b"server down", status=503)])
    provider = self._provider(http)
    with self.assertRaises(AuthError):
      provider.headers()

  def test_login_response_not_jwt_raises(self):
    http = _FakeHttpPost([_FakeResponse(b"not-a-jwt")])
    provider = self._provider(http)
    with self.assertRaises(AuthError):
      provider.headers()

  def test_json_login_response_extracts_data_token(self):
    jwt = _make_jwt()
    body = json.dumps({"data": {"token": jwt}}).encode("utf-8")
    http = _FakeHttpPost([_FakeResponse(body)])
    provider = self._provider(http)
    self.assertEqual(provider.headers()["Authorization"], f"Bearer {jwt}")

  def test_ttl_override_short_circuits_exp(self):
    jwt = _make_jwt(exp_seconds_from_now=900)
    http = _FakeHttpPost([_FakeResponse(jwt.encode("utf-8"))])
    provider = self._provider(http, ttl_override_s=0.1)
    provider.headers()
    time.sleep(0.2)
    # Cache entry exists but its ttl_override-derived expiry has passed,
    # plus the 60s safety margin will treat it as expired immediately on
    # any call. Verify by invalidating + checking a fresh provider with the
    # same key needs another response.
    # (The safety margin means override TTLs < 60s effectively force a
    # login every call, which is the intended fail-safe behavior.)
    http._responses.append(_FakeResponse(jwt.encode("utf-8")))
    provider.headers()
    self.assertEqual(len(http.calls), 2)

  def test_missing_password_env_raises(self):
    os.environ.pop("UNIT_WAZUH_PW", None)
    http = _FakeHttpPost([])
    provider = self._provider(http)
    with self.assertRaises(AuthError):
      provider.headers()
    self.assertEqual(len(http.calls), 0)

  def test_b64url_decode_padding_helper(self):
    raw = b'{"a":1,"b":"hello"}'
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    self.assertEqual(_b64url_decode_padded(encoded), raw)


class InlineCredentialTests(unittest.TestCase):
  """Cover the inline TOKEN / PASSWORD path (the MISP_API_KEY-style pattern
  where secrets live directly in the config block, not behind env-var
  indirection)."""

  def test_static_inline_token_overrides_env(self):
    with patch.dict(os.environ, {"UNIT_TOKEN": "env-value"}):
      provider = StaticBearerProvider(token_env="UNIT_TOKEN", token="inline-value")
      self.assertEqual(provider.headers(), {"Authorization": "Bearer inline-value"})

  def test_static_inline_token_only(self):
    provider = StaticBearerProvider(token_env="", token="inline-only")
    self.assertEqual(provider.headers(), {"Authorization": "Bearer inline-only"})

  def test_static_falls_back_to_env_when_inline_empty(self):
    with patch.dict(os.environ, {"UNIT_TOKEN": "from-env"}):
      provider = StaticBearerProvider(token_env="UNIT_TOKEN", token="")
      self.assertEqual(provider.headers(), {"Authorization": "Bearer from-env"})

  def test_static_repr_does_not_leak_inline_token(self):
    provider = StaticBearerProvider(token_env="", token="super-secret-value")
    rendered = repr(provider)
    self.assertIn("inline_token_set=True", rendered)
    self.assertNotIn("super-secret-value", rendered)

  def test_basic_inline_password_overrides_env(self):
    import base64
    with patch.dict(os.environ, {"UNIT_PW": "env-password"}):
      provider = BasicAuthProvider(username="u", password_env="UNIT_PW", password="inline-password")
      header = provider.headers()["Authorization"]
      decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
      self.assertEqual(decoded, "u:inline-password")

  def test_basic_inline_password_only(self):
    import base64
    provider = BasicAuthProvider(username="redmesh", password_env="", password="TaxiiAdmin2026")
    decoded = base64.b64decode(provider.headers()["Authorization"].split(" ", 1)[1])
    self.assertEqual(decoded, b"redmesh:TaxiiAdmin2026")

  def test_basic_repr_does_not_leak_inline_password(self):
    provider = BasicAuthProvider(username="u", password_env="", password="super-secret")
    rendered = repr(provider)
    self.assertIn("inline_password_set=True", rendered)
    self.assertNotIn("super-secret", rendered)

  def test_basic_no_credential_anywhere_raises(self):
    provider = BasicAuthProvider(username="u", password_env="UNIT_MISSING", password="")
    os.environ.pop("UNIT_MISSING", None)
    with self.assertRaises(AuthError):
      provider.headers()

  def test_factory_passes_inline_credentials(self):
    provider = build_auth_provider({
      "AUTH_MODE": "basic",
      "USERNAME": "redmesh",
      "PASSWORD": "TaxiiAdmin2026",
    })
    import base64
    header = provider.headers()["Authorization"]
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
    self.assertEqual(decoded, "redmesh:TaxiiAdmin2026")

  def test_factory_passes_inline_token(self):
    provider = build_auth_provider({
      "AUTH_MODE": "static",
      "TOKEN": "uuid-inline",
    })
    self.assertEqual(provider.headers(), {"Authorization": "Bearer uuid-inline"})

  def test_factory_passes_inline_wazuh_jwt_password(self):
    provider = build_auth_provider({
      "AUTH_MODE": "wazuh_jwt",
      "LOGIN_URL": "https://wazuh.example",
      "USERNAME": "wazuh-wui",
      "PASSWORD": "inline-wazuh-pw",
    })
    # Verify the inline password reached the provider — we test the resolver
    # directly rather than triggering a real login.
    self.assertEqual(provider._resolve_password(), "inline-wazuh-pw")


class CredentialsMissingTests(unittest.TestCase):
  def test_static_with_inline_token_is_complete(self):
    from extensions.business.cybersec.red_mesh.services.auth import credentials_missing
    self.assertIsNone(credentials_missing({"AUTH_MODE": "static", "TOKEN": "uuid"}))

  def test_static_with_env_token_present_is_complete(self):
    from extensions.business.cybersec.red_mesh.services.auth import credentials_missing
    with patch.dict(os.environ, {"UNIT_T": "x"}):
      self.assertIsNone(credentials_missing({"AUTH_MODE": "static", "TOKEN_ENV": "UNIT_T"}))

  def test_static_with_nothing_returns_missing_token(self):
    from extensions.business.cybersec.red_mesh.services.auth import credentials_missing
    self.assertEqual(
      credentials_missing({"AUTH_MODE": "static", "TOKEN_ENV": "UNIT_MISSING"}),
      "missing_token",
    )

  def test_basic_with_inline_password_is_complete(self):
    from extensions.business.cybersec.red_mesh.services.auth import credentials_missing
    self.assertIsNone(credentials_missing({
      "AUTH_MODE": "basic",
      "USERNAME": "u",
      "PASSWORD": "pw",
    }))

  def test_basic_missing_username_even_with_inline_password(self):
    from extensions.business.cybersec.red_mesh.services.auth import credentials_missing
    self.assertEqual(
      credentials_missing({"AUTH_MODE": "basic", "PASSWORD": "pw"}),
      "missing_credentials",
    )

  def test_wazuh_jwt_with_inline_password_is_complete(self):
    from extensions.business.cybersec.red_mesh.services.auth import credentials_missing
    self.assertIsNone(credentials_missing({
      "AUTH_MODE": "wazuh_jwt",
      "USERNAME": "wazuh-wui",
      "PASSWORD": "pw",
    }))


class BuildAuthProviderTests(unittest.TestCase):
  def test_defaults_to_static(self):
    provider = build_auth_provider({"TOKEN_ENV": "REDMESH_OPENCTI_TOKEN"})
    self.assertIsInstance(provider, StaticBearerProvider)

  def test_basic_factory(self):
    provider = build_auth_provider({
      "AUTH_MODE": "basic",
      "USERNAME": "u",
      "PASSWORD_ENV": "PW",
    })
    self.assertIsInstance(provider, BasicAuthProvider)

  def test_wazuh_jwt_factory_with_login_url(self):
    provider = build_auth_provider({
      "AUTH_MODE": "wazuh_jwt",
      "LOGIN_URL": "https://wazuh.example",
      "USERNAME": "wazuh-wui",
      "PASSWORD_ENV": "REDMESH_WAZUH_PASSWORD",
    })
    self.assertIsInstance(provider, WazuhJwtProvider)
    self.assertEqual(provider.login_url, "https://wazuh.example")

  def test_wazuh_jwt_falls_back_to_http_url_origin(self):
    provider = build_auth_provider({
      "AUTH_MODE": "wazuh_jwt",
      "HTTP_URL": "https://wazuh-api.example/events/v1",
      "USERNAME": "wazuh-wui",
      "PASSWORD_ENV": "PW",
    })
    self.assertEqual(provider.login_url, "https://wazuh-api.example")

  def test_wazuh_jwt_without_url_raises(self):
    with self.assertRaises(AuthConfigError):
      build_auth_provider({
        "AUTH_MODE": "wazuh_jwt",
        "USERNAME": "u",
        "PASSWORD_ENV": "PW",
      })

  def test_unknown_mode_raises(self):
    with self.assertRaises(AuthConfigError):
      build_auth_provider({"AUTH_MODE": "oauth2"})

  def test_non_dict_raises(self):
    with self.assertRaises(AuthConfigError):
      build_auth_provider(None)


if __name__ == "__main__":
  unittest.main()
