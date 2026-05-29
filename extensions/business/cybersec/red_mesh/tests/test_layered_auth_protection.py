"""Layered graybox gateway/app auth protection tests."""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.http_client import GrayboxHttpClient
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiSecurityConfig,
  AuthDescriptor,
  GatewayAuthDescriptor,
  GrayboxTargetConfig,
)


def _target_config(gateway_auth):
  return GrayboxTargetConfig(
    api_security=ApiSecurityConfig(gateway_auth=gateway_auth),
  )


class TestProtectedGatewayLayer(unittest.TestCase):

  def _session(self):
    session = MagicMock()
    session.request.return_value = MagicMock(status_code=200, headers={})
    return session

  def test_gateway_header_overrides_per_request_header(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      target_config=_target_config(GatewayAuthDescriptor(
        auth_type="api_key",
        api_key_header_name="X-Gateway-Key",
      )),
      gateway_api_key="REAL-GATEWAY-KEY",
    )
    session = self._session()

    client.request(
      session,
      "GET",
      "/api/users",
      headers={"X-Gateway-Key": "PROBE-OVERRIDE", "X-Probe": "1"},
    )

    headers = session.request.call_args.kwargs["headers"]
    self.assertEqual(headers["X-Gateway-Key"], "REAL-GATEWAY-KEY")
    self.assertEqual(headers["X-Probe"], "1")
    self.assertNotIn("PROBE-OVERRIDE", str(headers))

  def test_gateway_query_param_overrides_per_request_param(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      target_config=_target_config(GatewayAuthDescriptor(
        auth_type="api_key",
        api_key_location="query",
        api_key_query_param="gateway_key",
      )),
      gateway_api_key="REAL-GATEWAY-KEY",
    )
    session = self._session()

    client.request(
      session,
      "GET",
      "/api/users",
      params={"gateway_key": "PROBE-OVERRIDE", "page": "2"},
    )

    params = session.request.call_args.kwargs["params"]
    self.assertEqual(params["gateway_key"], "REAL-GATEWAY-KEY")
    self.assertEqual(params["page"], "2")
    self.assertNotIn("PROBE-OVERRIDE", str(params))

  def test_gateway_query_param_removes_tampered_url_query_value(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      target_config=_target_config(GatewayAuthDescriptor(
        auth_type="api_key",
        api_key_location="query",
        api_key_query_param="gateway_key",
      )),
      gateway_api_key="REAL-GATEWAY-KEY",
    )
    session = self._session()

    client.request(
      session,
      "GET",
      "/api/users?gateway_key=PROBE-OVERRIDE&page=2",
    )

    requested_url = session.request.call_args.args[1]
    params = session.request.call_args.kwargs["params"]
    self.assertEqual(requested_url, "https://api.example.com/api/users?page=2")
    self.assertEqual(params["gateway_key"], "REAL-GATEWAY-KEY")
    self.assertNotIn("PROBE-OVERRIDE", requested_url)
    self.assertNotIn("PROBE-OVERRIDE", str(params))

  def test_gateway_header_is_reapplied_on_redirect_follow_up(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      allowlist=["/api/", "/login/"],
      target_config=_target_config(GatewayAuthDescriptor(
        auth_type="bearer",
        bearer_token_header_name="X-Gateway-Authorization",
        bearer_scheme="Bearer",
      )),
      gateway_bearer_token="GATEWAY-BEARER",
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=302, headers={"Location": "/login/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session,
      "POST",
      "/api/login",
      headers={"X-Gateway-Authorization": "tampered"},
      allow_redirects=True,
    )

    for call in session.request.call_args_list:
      headers = call.kwargs["headers"]
      self.assertEqual(
        headers["X-Gateway-Authorization"],
        "Bearer GATEWAY-BEARER",
      )


class TestLayeredAuthSessionComposition(unittest.TestCase):

  def test_app_bearer_session_keeps_gateway_header_at_request_boundary(self):
    cfg = GrayboxTargetConfig(
      api_security=ApiSecurityConfig(
        auth=AuthDescriptor(
          auth_type="bearer",
          authenticated_probe_path="/api/me",
        ),
        gateway_auth=GatewayAuthDescriptor(
          auth_type="api_key",
          api_key_header_name="X-Gateway-Key",
        ),
      ),
    )
    client = GrayboxHttpClient(
      "https://api.example.com",
      target_config=cfg,
      gateway_api_key="GATEWAY-KEY",
    )
    raw_session = MagicMock()
    raw_session.headers = {"Authorization": "Bearer APP-TOKEN"}
    raw_session.params = {}
    raw_session.request.return_value = MagicMock(status_code=200, headers={})
    session = client.wrap_session(raw_session)

    session.get("/api/me", headers={"X-Gateway-Key": "tampered"})

    headers = raw_session.request.call_args.kwargs["headers"]
    self.assertEqual(raw_session.headers["Authorization"], "Bearer APP-TOKEN")
    self.assertEqual(headers["X-Gateway-Key"], "GATEWAY-KEY")
    self.assertNotIn("tampered", str(headers))

  def test_regular_app_session_keeps_own_auth_and_gateway_header(self):
    cfg = GrayboxTargetConfig(
      api_security=ApiSecurityConfig(
        auth=AuthDescriptor(
          auth_type="bearer",
          authenticated_probe_path="/api/me",
        ),
        gateway_auth=GatewayAuthDescriptor(
          auth_type="api_key",
          api_key_header_name="X-Gateway-Key",
        ),
      ),
    )
    client = GrayboxHttpClient(
      "https://api.example.com",
      target_config=cfg,
      gateway_api_key="GATEWAY-KEY",
    )
    raw_session = MagicMock()
    raw_session.headers = {"Authorization": "Bearer REGULAR-TOKEN"}
    raw_session.params = {}
    raw_session.request.return_value = MagicMock(status_code=200, headers={})
    session = client.wrap_session(raw_session)

    session.get("/api/me")

    self.assertEqual(raw_session.headers["Authorization"], "Bearer REGULAR-TOKEN")
    self.assertEqual(
      raw_session.request.call_args.kwargs["headers"]["X-Gateway-Key"],
      "GATEWAY-KEY",
    )


if __name__ == "__main__":
  unittest.main()
