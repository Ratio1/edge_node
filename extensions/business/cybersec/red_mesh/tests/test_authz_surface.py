"""The endpoint-tier deny-by-default surface (RM-075 Phase 2).

Enumerates the plugin exactly the way the framework does - ``inspect.getmembers`` filtered by
``__endpoint__`` (fast_api_web_app.py) - and pins, for every endpoint:

* ``require_token=True`` (framework rejects a missing bearer before dispatch);
* ``token`` as the first parameter (the framework raises ``ValueError`` at plugin init otherwise -
  a boot failure this suite must catch before a node does);
* the ``@channel_token_required`` value check, proven per endpoint by calling it with a wrong
  token against a MagicMock plugin and asserting the denial came back and the body touched nothing.
"""
import inspect
import unittest
from unittest.mock import MagicMock, patch

from .conftest import TEST_CHANNEL_TOKEN, mock_plugin_modules

EXPECTED_ENDPOINTS = 52


def _endpoints(plugin_cls):
  found = {}
  for name, member in inspect.getmembers(plugin_cls, predicate=inspect.isfunction):
    if getattr(member, "__endpoint__", False):
      found[name] = member
  return found


class TestAuthzSurface(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    from extensions.business.cybersec.red_mesh.tenancy.channel import is_channel_guarded

    cls.Plugin = PentesterApi01Plugin
    cls.is_channel_guarded = staticmethod(is_channel_guarded)
    cls.endpoints = _endpoints(PentesterApi01Plugin)

  def test_the_surface_is_the_size_we_think_it_is(self):
    # A new endpoint must be added here consciously, not silently.
    self.assertEqual(len(self.endpoints), EXPECTED_ENDPOINTS, sorted(self.endpoints))

  def test_every_endpoint_requires_the_bearer(self):
    missing = sorted(n for n, fn in self.endpoints.items() if not getattr(fn, "__require_token__", False))
    self.assertEqual(missing, [])

  def test_every_endpoint_has_token_first_or_the_plugin_cannot_boot(self):
    # Mirrors fast_api_web_app.py registration: all_params[0] must be 'token' under require_token.
    bad = []
    for name, fn in self.endpoints.items():
      params = [p.name for p in inspect.signature(fn).parameters.values()
                if p.kind is not inspect.Parameter.VAR_KEYWORD]
      if params[:2] != ["self", "token"]:
        bad.append((name, params[:3]))
    self.assertEqual(bad, [])

  def test_every_endpoint_is_channel_guarded(self):
    unguarded = sorted(n for n, fn in self.endpoints.items() if not self.is_channel_guarded(fn))
    self.assertEqual(unguarded, [])

  def test_wrong_token_is_denied_before_any_body_runs(self):
    for name, fn in self.endpoints.items():
      with self.subTest(endpoint=name):
        plugin = MagicMock()
        with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
          result = fn(plugin, "not-the-channel-token")
        self.assertEqual(result["status_code"], 403, name)
        self.assertEqual(result["error_class"], "backend_auth_invalid", name)
        # The body of every endpoint starts by touching the plugin (self.*); a denial must not.
        self.assertEqual(plugin.method_calls, [], name)
        self.assertNotIn(TEST_CHANNEL_TOKEN, str(result), name)

  def test_missing_token_is_401_and_unconfigured_deployment_fails_closed(self):
    fn = self.endpoints["get_capability_status"]
    with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
      self.assertEqual(fn(MagicMock(), "")["status_code"], 401)
    with patch.dict("os.environ", {}, clear=True):
      self.assertEqual(fn(MagicMock(), TEST_CHANNEL_TOKEN)["error_class"], "backend_auth_unavailable")

  def test_launch_endpoints_deny_a_missing_or_unknown_actor_before_launching(self):
    from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView

    for name in ("launch_network_scan", "launch_webapp_scan", "launch_test", "launch_model_test"):
      with self.subTest(endpoint=name):
        plugin = MagicMock()
        plugin._resolve_launch_actor = lambda actor=None: (None, {"status_code": 404, "error_class": "actor_not_found"})
        with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
          result = self.endpoints[name](plugin, TEST_CHANNEL_TOKEN)
        self.assertEqual(result["status_code"], 404, name)

        # And a resolved actor overrides whatever created_by_* the request carried.
        seen = {}
        plugin = MagicMock()
        plugin._resolve_launch_actor = lambda actor=None: (AccountView("ops.user", "admin", None, True), None)
        target = {
          "launch_network_scan": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_network_scan",
          "launch_webapp_scan": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_webapp_scan",
          "launch_test": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_test",
          "launch_model_test": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_model_test",
        }[name]
        with patch(target, side_effect=lambda self_, **kw: seen.update(kw) or {"ok": True}), \
             patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
          self.endpoints[name](plugin, TEST_CHANNEL_TOKEN, created_by_name="spoofed", created_by_id="spoofed")
        self.assertEqual((seen.get("created_by_name"), seen.get("created_by_id")), ("ops.user", "ops.user"), name)

  def test_the_production_actor_seam_reads_the_account_store(self):
    # The seam resolves through cstore-auth; a MagicMock store yields "not found", never "allowed".
    plugin = MagicMock()
    with patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "app:auth"}):
      view, err = self.Plugin._resolve_launch_actor(plugin, {"account_id": "someone"})
    self.assertIsNone(view)
    self.assertEqual(err["status_code"], 404)


if __name__ == "__main__":
  unittest.main()
