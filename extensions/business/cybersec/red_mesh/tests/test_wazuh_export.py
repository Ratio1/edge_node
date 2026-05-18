import json
import os
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.event_builder import build_test_event
from extensions.business.cybersec.red_mesh.services.integration_status import (
  get_integration_status,
  test_event_export as build_integration_test_event,
)
from extensions.business.cybersec.red_mesh.services.log_export import (
  WAZUH_EVENT_GROUPS,
  build_wazuh_decoder_rules_example,
  deliver_wazuh_event,
  format_syslog_json_line,
)


def _owner(wazuh_config=None, event_config=None):
  owner = MagicMock()
  owner.cfg_instance_id = "tenant-a"
  owner.cfg_ee_node_network = "devnet"
  owner.cfg_wazuh_export = {
    "ENABLED": True,
    "MODE": "syslog",
    "SYSLOG_HOST": "127.0.0.1",
    "SYSLOG_PORT": 5514,
    "TIMEOUT_SECONDS": 0.25,
    "RETRY_ATTEMPTS": 0,
    **(wazuh_config or {}),
  }
  owner.cfg_event_export = {
    "SIGN_PAYLOADS": True,
    "HMAC_SECRET_ENV": "REDMESH_EVENT_HMAC_SECRET",
    **(event_config or {}),
  }
  records = {}

  def hget(hkey, key):
    return records.get((hkey, key))

  def hset(hkey, key, value):
    records[(hkey, key)] = value

  owner.chainstore_hget.side_effect = hget
  owner.chainstore_hset.side_effect = hset
  owner._records = records
  return owner


def _event():
  return build_test_event(
    hmac_secret="tenant-secret",
    tenant_id="tenant-a",
    environment="devnet",
  )


class TestWazuhExport(unittest.TestCase):

  def tearDown(self):
    os.environ.pop("REDMESH_EVENT_HMAC_SECRET", None)

  @patch("extensions.business.cybersec.red_mesh.services.log_export.socket.socket")
  def test_syslog_export_emits_one_signed_single_line_json_event(self, socket_factory):
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"
    sock = MagicMock()
    socket_factory.return_value.__enter__.return_value = sock
    owner = _owner()
    event = _event()

    result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "sent")
    sock.settimeout.assert_called_once_with(0.25)
    sent_payload, destination = sock.sendto.call_args.args
    self.assertEqual(destination, ("127.0.0.1", 5514))
    wire = sent_payload.decode("utf-8")
    self.assertEqual(wire.count("\n"), 1)
    payload = json.loads(wire.strip())
    self.assertEqual(payload["schema"], "redmesh.event.v1")
    self.assertEqual(payload["event_id"], event["event_id"])
    self.assertEqual(payload["redmesh_idempotency_key"], event["dedupe_key"])
    self.assertTrue(payload["redmesh_signature"].startswith("sha256="))

  def test_format_syslog_json_line_has_no_embedded_newline(self):
    line = format_syslog_json_line(_event(), signature="abc123")

    self.assertNotIn("\n", line)
    payload = json.loads(line)
    self.assertEqual(payload["redmesh_signature"], "sha256=abc123")
    self.assertEqual(payload["redmesh_idempotency_key"], payload["dedupe_key"])

  @patch("extensions.business.cybersec.red_mesh.services.log_export.socket.socket")
  def test_disabled_export_records_failure_without_sending(self, socket_factory):
    owner = _owner({"ENABLED": False})
    event = _event()

    result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "disabled")
    self.assertEqual(result["error"], "disabled")
    socket_factory.assert_not_called()
    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertFalse(status["enabled"])
    self.assertEqual(status["last_error_class"], "disabled")

  @patch("extensions.business.cybersec.red_mesh.services.log_export.socket.socket")
  def test_wazuh_test_event_endpoint_performs_dry_run_delivery(self, socket_factory):
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"
    sock = MagicMock()
    socket_factory.return_value.__enter__.return_value = sock
    owner = _owner()

    result = build_integration_test_event(owner, integration_id="wazuh")

    self.assertEqual(result["status"], "sent")
    self.assertEqual(result["integration_id"], "wazuh")
    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertIsNotNone(status["last_dry_run_at"])
    self.assertIsNotNone(status["last_success_at"])
    self.assertEqual(status["last_event_id"], result["event_id"])

  def test_wazuh_decoder_rules_cover_required_event_groups(self):
    example = build_wazuh_decoder_rules_example()
    rule_groups = {rule["group"] for rule in example["rules"]}

    self.assertEqual(set(WAZUH_EVENT_GROUPS), rule_groups)
    self.assertIn("redmesh.lifecycle", rule_groups)
    self.assertIn("redmesh.service_observation", rule_groups)
    self.assertIn("redmesh.finding", rule_groups)
    self.assertIn("redmesh.export", rule_groups)
    self.assertIn("redmesh.attestation", rule_groups)
    self.assertIn("redmesh.correlation", rule_groups)


def _http_owner(extra=None):
  config = {
    "ENABLED": True,
    "MODE": "http",
    "HTTP_URL": "https://wazuh.example/events",
    "AUTH_MODE": "static",
    "TOKEN_ENV": "REDMESH_WAZUH_TOKEN",
    "TIMEOUT_SECONDS": 0.25,
    "RETRY_ATTEMPTS": 1,
  }
  config.update(extra or {})
  return _owner(wazuh_config=config)


class TestWazuhHttpExportAuth(unittest.TestCase):
  """Covers the http delivery path now that it dispatches through an
  AuthProvider, with retry-on-401 and AuthError short-circuit."""

  def setUp(self):
    from extensions.business.cybersec.red_mesh.services.auth.wazuh_jwt import (
      _purge_cache_for_tests,
    )
    _purge_cache_for_tests()
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"

  def tearDown(self):
    for key in (
      "REDMESH_EVENT_HMAC_SECRET",
      "REDMESH_WAZUH_TOKEN",
      "REDMESH_WAZUH_PASSWORD",
    ):
      os.environ.pop(key, None)

  def test_static_token_path_emits_bearer_and_sends(self):
    os.environ["REDMESH_WAZUH_TOKEN"] = "static-bearer"
    owner = _http_owner()
    event = _event()

    captured = {}

    def fake_urlopen(request, timeout=None):
      captured["headers"] = dict(request.header_items())
      captured["url"] = request.full_url
      mock_resp = MagicMock()
      mock_resp.__enter__ = lambda s: s
      mock_resp.__exit__ = lambda *a: False
      mock_resp.status = 200
      return mock_resp

    with patch(
      "extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen",
      side_effect=fake_urlopen,
    ):
      result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "sent")
    self.assertEqual(captured["url"], "https://wazuh.example/events")
    self.assertEqual(captured["headers"]["Authorization"], "Bearer static-bearer")

  def test_jwt_refresh_on_401_retries_once_within_same_attempt_budget(self):
    import base64
    import json as _json
    import time as _time

    os.environ["REDMESH_WAZUH_PASSWORD"] = "pw"

    def make_jwt():
      header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
      payload = base64.urlsafe_b64encode(
        _json.dumps({"exp": int(_time.time() + 900)}).encode()
      ).rstrip(b"=").decode()
      return f"{header}.{payload}.sig"

    jwt_tokens = [make_jwt(), make_jwt()]
    login_calls = []
    event_calls = []

    def fake_urlopen(request, timeout=None):
      mock_resp = MagicMock()
      mock_resp.__enter__ = lambda s: s
      mock_resp.__exit__ = lambda *a: False
      if "/security/user/authenticate" in request.full_url:
        login_calls.append(request.full_url)
        mock_resp.status = 200
        mock_resp.read = lambda: jwt_tokens[len(login_calls) - 1].encode()
        return mock_resp
      event_calls.append(request.full_url)
      if len(event_calls) == 1:
        raise urllib_error_HTTPError(request.full_url, 401, "Unauthorized")
      mock_resp.status = 200
      return mock_resp

    owner = _http_owner({
      "AUTH_MODE": "wazuh_jwt",
      "USERNAME": "wazuh-wui",
      "PASSWORD_ENV": "REDMESH_WAZUH_PASSWORD",
      "LOGIN_URL": "https://wazuh.example",
      "RETRY_ATTEMPTS": 1,
    })
    event = _event()

    # Both log_export and wazuh_jwt look up urllib.request.urlopen each
    # call, so patching the underlying module attribute covers both.
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
      result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "sent")
    self.assertEqual(result["attempts"], 1, "401-driven refresh must not consume an attempt slot")
    self.assertEqual(len(event_calls), 2, "expected one POST, one 401 + retry")
    self.assertEqual(len(login_calls), 2, "expected re-login after 401")

  def test_403_does_not_trigger_refresh(self):
    os.environ["REDMESH_WAZUH_TOKEN"] = "forbidden-token"
    owner = _http_owner({"RETRY_ATTEMPTS": 0})
    event = _event()
    event_call_count = {"n": 0}

    def fake_urlopen(request, timeout=None):
      event_call_count["n"] += 1
      raise urllib_error_HTTPError(request.full_url, 403, "Forbidden")

    with patch(
      "extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen",
      side_effect=fake_urlopen,
    ):
      result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "http_403")
    self.assertEqual(event_call_count["n"], 1, "403 must not be retried via refresh")

  def test_auth_error_short_circuits_retry_loop(self):
    # AUTH_MODE=wazuh_jwt without USERNAME -> AuthConfigError at provider
    # build time -> recorded as invalid_auth_config without any POST attempt.
    owner = _http_owner({
      "AUTH_MODE": "wazuh_jwt",
      "USERNAME": "",
      "LOGIN_URL": "https://wazuh.example",
      "RETRY_ATTEMPTS": 3,
    })
    event = _event()
    event_call_count = {"n": 0}

    def fake_urlopen(request, timeout=None):
      event_call_count["n"] += 1
      mock_resp = MagicMock()
      mock_resp.__enter__ = lambda s: s
      mock_resp.__exit__ = lambda *a: False
      mock_resp.status = 200
      return mock_resp

    # An empty USERNAME falls through provider build (USERNAME has no
    # validation in the factory) and surfaces lazily during the first
    # headers() call as an AuthError. The retry loop must break, not loop.
    os.environ["REDMESH_WAZUH_PASSWORD"] = "pw"
    with patch(
      "extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen",
      side_effect=fake_urlopen,
    ):
      result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "invalid_auth_config")
    self.assertEqual(event_call_count["n"], 0, "AuthError must skip transport attempts entirely")


def urllib_error_HTTPError(url, code, msg):
  import urllib.error
  return urllib.error.HTTPError(url, code, msg, hdrs=None, fp=None)


class TestWazuhApiModeEnvelope(unittest.TestCase):
  """The wazuh_api MODE wraps payloads to match Wazuh manager
  `POST /events` which expects `{"events": ["<json-string>"]}`."""

  def setUp(self):
    from extensions.business.cybersec.red_mesh.services.auth.wazuh_jwt import (
      _purge_cache_for_tests,
    )
    _purge_cache_for_tests()
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"

  def tearDown(self):
    for key in ("REDMESH_EVENT_HMAC_SECRET", "REDMESH_WAZUH_TOKEN"):
      os.environ.pop(key, None)

  def test_wazuh_api_mode_wraps_payload_in_events_envelope(self):
    os.environ["REDMESH_WAZUH_TOKEN"] = "static-bearer"
    owner = _owner(wazuh_config={
      "ENABLED": True,
      "MODE": "wazuh_api",
      "HTTP_URL": "https://wazuh-api.example/events",
      "AUTH_MODE": "static",
      "TOKEN_ENV": "REDMESH_WAZUH_TOKEN",
      "TIMEOUT_SECONDS": 0.25,
      "RETRY_ATTEMPTS": 0,
    })
    event = _event()

    captured = {}

    def fake_urlopen(request, timeout=None):
      captured["url"] = request.full_url
      captured["body"] = request.data
      mock_resp = MagicMock()
      mock_resp.__enter__ = lambda s: s
      mock_resp.__exit__ = lambda *a: False
      mock_resp.status = 200
      return mock_resp

    with patch(
      "extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen",
      side_effect=fake_urlopen,
    ):
      result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "sent")
    self.assertEqual(captured["url"], "https://wazuh-api.example/events")
    body = json.loads(captured["body"])
    self.assertEqual(list(body.keys()), ["events"])
    self.assertEqual(len(body["events"]), 1)
    # The single envelope element is the original event JSON as a string.
    inner = json.loads(body["events"][0])
    self.assertEqual(inner["event_id"], event["event_id"])
    self.assertEqual(inner["schema"], "redmesh.event.v1")

  def test_http_mode_keeps_raw_json_payload(self):
    os.environ["REDMESH_WAZUH_TOKEN"] = "static-bearer"
    owner = _owner(wazuh_config={
      "ENABLED": True,
      "MODE": "http",
      "HTTP_URL": "https://generic-siem.example/ingest",
      "AUTH_MODE": "static",
      "TOKEN_ENV": "REDMESH_WAZUH_TOKEN",
      "TIMEOUT_SECONDS": 0.25,
      "RETRY_ATTEMPTS": 0,
    })
    event = _event()
    captured = {}

    def fake_urlopen(request, timeout=None):
      captured["body"] = request.data
      mock_resp = MagicMock()
      mock_resp.__enter__ = lambda s: s
      mock_resp.__exit__ = lambda *a: False
      mock_resp.status = 200
      return mock_resp

    with patch(
      "extensions.business.cybersec.red_mesh.services.log_export.urllib.request.urlopen",
      side_effect=fake_urlopen,
    ):
      deliver_wazuh_event(owner, event)

    body = json.loads(captured["body"])
    # Regression: http mode must NOT add the events envelope.
    self.assertNotIn("events", body)
    self.assertEqual(body["event_id"], event["event_id"])


if __name__ == "__main__":
  unittest.main()
