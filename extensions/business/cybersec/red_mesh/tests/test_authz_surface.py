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

  def test_launch_endpoints_reject_explicitly_non_active_stored_accounts(self):
    for name in ("launch_network_scan", "launch_webapp_scan", "launch_test", "launch_model_test"):
      for state in (None, "deleting", "", False, 0, [], {}):
        with self.subTest(endpoint=name, state=state):
          plugin = object.__new__(self.Plugin)
          plugin.chainstore_hget = MagicMock(return_value={
            "type": "simple", "role": "user", "metadata": {"navigatorAccountState": state},
          })
          target = f"extensions.business.cybersec.red_mesh.pentester_api_01.{name}"
          with patch(target, return_value={"unexpected_launch": True}) as launch, \
               patch.dict("os.environ", {
                 "REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN,
                 "R1EN_CSTORE_AUTH_HKEY": "app:auth",
               }):
            result = self.endpoints[name](plugin, TEST_CHANNEL_TOKEN, actor={"account_id": "ops.user"})
          self.assertEqual(result.get("status_code"), 404)
          self.assertEqual(result.get("error_class"), "actor_not_found")
          launch.assert_not_called()



class TestInternalCallersDoNotReenterEndpoints(unittest.TestCase):
  """Endpoint methods take `token` first and run the channel guard; code inside the plugin must
  call the module-level implementations instead. Review round 1 found three such re-entries that
  the surface test above cannot see (it enumerates decorators, not callers)."""

  ENDPOINT_HOSTS = ("pentester_api_01.py", "services", "mixins", "api_mixins", "worker")

  def test_no_plugin_code_calls_an_endpoint_method(self):
    import pathlib
    import re

    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    names = "|".join(sorted(_endpoints(PentesterApi01Plugin)))
    pattern = re.compile(r"\b(owner|self|plugin)\.(%s)\s*\(" % names)
    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
      rel = path.relative_to(root)
      if rel.parts[0] == "tests" or not (rel.parts[0] in self.ENDPOINT_HOSTS or str(rel) in self.ENDPOINT_HOSTS):
        continue
      for lineno, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line) and not line.lstrip().startswith(("def ", "#")):
          offenders.append(f"{rel}:{lineno}: {line.strip()}")
    self.assertEqual(offenders, [])

  def test_launch_test_compat_shim_reaches_the_module_launcher_with_attribution(self):
    from extensions.business.cybersec.red_mesh.services import launch_api
    from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView

    plugin = MagicMock()
    plugin._resolve_launch_actor = lambda actor=None: (AccountView("ops.user", "admin", None, True), None)
    seen = {}
    with patch.object(launch_api, "launch_network_scan", side_effect=lambda owner, **kw: seen.update(kw) or {"ok": True}), \
         patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
      result = self.Plugin.launch_test(
        plugin, TEST_CHANNEL_TOKEN, target="example.com", scan_type="network", authorized=True,
        actor={"account_id": "ops.user"},
      )
    self.assertEqual(result, {"ok": True})
    self.assertEqual((seen.get("created_by_name"), seen.get("created_by_id")), ("ops.user", "ops.user"))

  @classmethod
  def setUpClass(cls):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin


if __name__ == "__main__":
  unittest.main()
