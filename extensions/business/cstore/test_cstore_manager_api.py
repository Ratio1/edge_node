import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  def __init__(self, **kwargs):
    self.cfg_debug = kwargs.get("DEBUG", False)
    self.bc = SimpleNamespace(address="0xADDR", eth_address="0xETH")
    self._now = 0.0
    self.messages = []

  @staticmethod
  def endpoint(method="get", require_token=False):  # pylint: disable=unused-argument
    def decorator(func):
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


if __name__ == "__main__":
  unittest.main()
