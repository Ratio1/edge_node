import inspect
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  def __init__(self, **kwargs):
    self.cfg_debug = kwargs.get("DEBUG", False)
    self.bc = SimpleNamespace(address="0xADDR", eth_address="0xETH")
    self._now = 0.0
    self.messages = []

  @staticmethod
  def endpoint(method="get", require_token=False):
    def decorator(func):
      # Mark like FastApiWebAppPlugin.endpoint so endpoint discovery works.
      func.__endpoint__ = True
      func.__http_method__ = method
      func.__require_token__ = require_token
      return func

    return decorator

  def on_init(self):
    return None

  def P(self, msg, *args, **kwargs):  # pylint: disable=unused-argument
    self.messages.append(msg)

  def time(self):
    return self._now


def _load_plugin_class():
  source_path = ROOT / "extensions" / "business" / "cstore" / "cstore_manager_api.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin\n",
    "",
  )
  namespace = {"BasePlugin": _FakeBasePlugin, "__name__": "loaded_cstore_manager_api"}
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["CstoreManagerApiPlugin"]


CstoreManagerApiPlugin = _load_plugin_class()


class CstoreManagerApiPluginTests(unittest.TestCase):
  def _make_plugin(self, *, debug=False, nth=50):
    plugin = CstoreManagerApiPlugin()
    plugin.cfg_debug = debug
    plugin.cfg_force_debug_each_nth_api_call = nth
    plugin.calls = []

    def _record_hsync(**kwargs):
      plugin.calls.append(kwargs)
      return {"hkey": kwargs["hkey"], "source_peer": "peer-1", "merged_fields": 2}

    plugin.chainstore_hsync = _record_hsync
    return plugin

  def test_hsync_preserves_default_peer_selection_when_peers_are_omitted(self):
    plugin = self._make_plugin()

    result = plugin.hsync(hkey="players")

    self.assertEqual(
      result,
      {"hkey": "players", "source_peer": "peer-1", "merged_fields": 2},
    )
    self.assertEqual(
      plugin.calls,
      [{"hkey": "players", "debug": False, "extra_peers": None}],
    )

  def test_hsync_forwards_explicit_chainstore_peers(self):
    plugin = self._make_plugin()

    plugin.hsync(hkey="players", chainstore_peers=["peer-a", "peer-b"])

    self.assertEqual(
      plugin.calls,
      [{"hkey": "players", "debug": False, "extra_peers": ["peer-a", "peer-b"]}],
    )

  def test_default_config_disables_debug_and_forces_periodic_summary(self):
    self.assertFalse(CstoreManagerApiPlugin.CONFIG["DEBUG"])
    self.assertEqual(CstoreManagerApiPlugin.CONFIG["FORCE_DEBUG_EACH_NTH_API_CALL"], 50)

  def test_forced_summary_emits_at_threshold_and_resets_window(self):
    plugin = self._make_plugin(nth=2)

    def _record_get(**kwargs):
      plugin.calls.append(kwargs)
      plugin._now += 0.25
      return "value"

    plugin.chainstore_get = _record_get

    plugin.get("run:one")
    self.assertEqual(plugin.messages, [])

    plugin.get("run:two")
    self.assertEqual(len(plugin.messages), 1)
    self.assertIn("CStore API usage summary", plugin.messages[0])
    self.assertIn("calls=2", plugin.messages[0])
    self.assertIn("get[count=2", plugin.messages[0])
    self.assertIn("targets=run(2)", plugin.messages[0])

    plugin.get("ack:peer-a")
    self.assertEqual(len(plugin.messages), 1)

    plugin.get("ack:peer-b")
    self.assertEqual(len(plugin.messages), 2)
    self.assertIn("calls=2", plugin.messages[1])
    self.assertIn("targets=ack(2)", plugin.messages[1])

  def test_debug_mode_keeps_direct_debug_logs_and_skips_forced_summary(self):
    plugin = self._make_plugin(debug=True, nth=1)

    def _record_get(**kwargs):
      plugin.calls.append(kwargs)
      plugin._now += 0.10
      return "value"

    plugin.chainstore_get = _record_get

    plugin.get("run:one")

    self.assertEqual(plugin.calls, [{"key": "run:one", "debug": True}])
    self.assertEqual(len(plugin.messages), 1)
    self.assertIn("[DEBUG] CStore get took", plugin.messages[0])
    self.assertNotIn("CStore API usage summary", plugin.messages[0])


def _core_hash_key(hkey, key):
  """The composed key the node's own chainstore_hset writes, computed by naeural_core."""
  from naeural_core.business.base.base_plugin_biz_api import _BasePluginAPIMixin
  from naeural_core.utils.plugins_base.plugin_base_utils import _UtilsBaseMixin
  composer = type("_Composer", (_BasePluginAPIMixin, _UtilsBaseMixin), {})
  return composer._BasePluginAPIMixin__hset_key(composer.__new__(composer), hkey, key)


SECRET, DEEPLOY, APP = "DAUTH_JOB_SECRET_REVISIONS", "DEEPLOY_DEPLOYED_JOBS", "app:demo"
STORE_METHODS = ("chainstore_set", "chainstore_get", "chainstore_hset", "chainstore_hget",
                 "chainstore_hgetall", "chainstore_hsync")


def _endpoint_args(endpoint, namespace):
  """Arguments that make `endpoint` touch `namespace`; flat endpoints use the composed hash key."""
  field = "7|op:deploy"
  raw_key = "app:demo:counter" if namespace == APP else _core_hash_key(namespace, field)
  return {
    "get_status": {},
    "set": {"key": raw_key, "value": "v"},
    "get": {"key": raw_key},
    "hset": {"hkey": namespace, "key": field, "value": "v"},
    "hget": {"hkey": namespace, "key": field},
    "hgetall": {"hkey": namespace},
    "hsync": {"hkey": namespace},
  }[endpoint]


def _expected_denied(endpoint, namespace):
  if endpoint == "get_status" or namespace == APP:
    return False
  if namespace == SECRET:
    return True
  return endpoint in ("set", "hset", "hsync")  # DEEPLOY_: read-only


class CstoreManagerApiPolicyTests(unittest.TestCase):
  def _plugin(self, token=None, env=None):
    plugin = CstoreManagerApiPlugin()
    plugin.cfg_debug = False
    plugin.cfg_force_debug_each_nth_api_call = 0
    plugin.cfg_api_token = token
    plugin.store_calls = []
    for name in STORE_METHODS:
      setattr(plugin, name, lambda _name=name, **kwargs: plugin.store_calls.append(_name) or {"ok": _name})
    with patch.dict(os.environ, {"EE_CSTORE_API_TOKEN": env} if env else {}, clear=False):
      if not env:
        os.environ.pop("EE_CSTORE_API_TOKEN", None)
      plugin.on_init()
    return plugin

  def test_policy_matrix_for_every_endpoint_namespace_and_token_mode(self):
    for token_mode in ("unset", "set", "wrong", "missing"):
      for endpoint in ("get_status", "set", "get", "hset", "hget", "hgetall", "hsync"):
        for namespace in (SECRET, DEEPLOY, APP):
          with self.subTest(token=token_mode, endpoint=endpoint, namespace=namespace):
            plugin = self._plugin(token=None if token_mode == "unset" else "s3cret")
            kwargs = _endpoint_args(endpoint, namespace)
            if token_mode == "unset":
              result = getattr(plugin, endpoint)(**kwargs)
            else:
              presented = {"set": "s3cret", "wrong": "other", "missing": None}[token_mode]
              result = getattr(plugin, endpoint)(presented, **kwargs)
            if token_mode in ("wrong", "missing"):
              self.assertEqual(result, {"error": "Unauthorized token", "status_code": 401})
              self.assertEqual(plugin.store_calls, [])
            elif _expected_denied(endpoint, namespace):
              self.assertEqual(result["status_code"], 403)
              self.assertIn("Namespace", result["error"])
              self.assertEqual(plugin.store_calls, [])
            else:
              self.assertNotIn("status_code", result if isinstance(result, dict) else {})
              self.assertEqual(len(plugin.store_calls), 0 if endpoint == "get_status" else 1)

  def test_raw_composed_keys_of_secret_namespaces_are_named_in_the_denial(self):
    plugin = self._plugin()
    for namespace in ("DAUTH_JOB_SECRETS", SECRET):
      raw_key = _core_hash_key(namespace, "7")
      self.assertIn(namespace, plugin.get(key=raw_key)["error"])
      self.assertIn(namespace, plugin.set(key=raw_key, value={"x": 1})["error"])
    self.assertEqual(plugin.store_calls, [])

  def test_denials_are_logged_once_per_endpoint_and_namespace_per_minute(self):
    plugin = self._plugin()
    for _ in range(3):
      plugin.hgetall(hkey=SECRET)
    plugin.hset(hkey=DEEPLOY, key="7", value="secret-looking-value")
    self.assertEqual(len([m for m in plugin.messages if "denied" in m]), 2)
    plugin._now += 60
    plugin.hgetall(hkey=SECRET)
    denials = [m for m in plugin.messages if "denied" in m]
    self.assertEqual(len(denials), 3)
    self.assertNotIn("secret-looking-value", " ".join(plugin.messages))

  def test_operator_can_relax_and_extend_the_lists(self):
    plugin = self._plugin()
    plugin.cfg_denied_hkeys = []
    plugin.cfg_write_denied_hkey_prefixes = ["DEEPLOY_", "DAUTH_", "TENANT_"]
    self.assertEqual(plugin.hgetall(hkey=SECRET), {"ok": "chainstore_hgetall"})
    self.assertEqual(plugin.hset(hkey="TENANT_x", key="k", value=1)["status_code"], 403)

  def test_token_wrapping_keeps_the_route_parameters(self):
    for env in (False, True):
      plugin = self._plugin(token=None if env else "s3cret", env="s3cret" if env else None)
      for name in ("get_status", "set", "get", "hset", "hget", "hgetall", "hsync"):
        method = getattr(plugin, name)
        original = inspect.signature(getattr(CstoreManagerApiPlugin, name))
        self.assertTrue(method.__require_token__)
        self.assertEqual(list(inspect.signature(method).parameters),
                         ["token"] + list(original.parameters)[1:])
    plain = self._plugin()
    self.assertFalse(plain.get.__require_token__)
    self.assertEqual(list(inspect.signature(plain.get).parameters), ["key"])

  def test_ordinary_application_usage_is_unchanged_by_default(self):
    plugin = self._plugin()
    self.assertEqual(plugin.hget(hkey="ratio1:backend:offline_nodes_notifier:v1", key="0xabc"),
                     {"ok": "chainstore_hget"})
    self.assertEqual(plugin.hgetall(hkey=DEEPLOY), {"ok": "chainstore_hgetall"})
    self.assertEqual(plugin.set(key="run:slot-1", value=1), {"ok": "chainstore_set"})
    self.assertEqual(plugin.get_status()["ok"], True)


if __name__ == "__main__":
  unittest.main()
