# base64: the field part of the composed raw key of a hash record, built as the core builds it.
import base64
# hashlib: the SHA-256 part of that composed key.
import hashlib
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  """
  Stand-in for the web-app base the plugin is loaded on.

  Provides what the plugin uses from its base without a node: the endpoint decorator, the clock, the log and the
  string hash that composes the index of a hash key.

  Parameters
  ----------
  **kwargs
    Plugin configuration; only ``DEBUG`` is read.

  Returns
  -------
  _FakeBasePlugin
    The base, with ``messages`` holding the log lines.

  Examples
  --------
  >>> _FakeBasePlugin(DEBUG=True).cfg_debug
  True
  """
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

  def get_hash(self, str_data, length=None, algorithm='md5'):
    """
    Hash a string as the core plugin utilities do.

    Mirrors ``get_hash`` of naeural_core's plugin base utilities, which the plugin uses to compose the index of a
    hash key.

    Parameters
    ----------
    str_data : str
      The string to hash.
    length : int, optional
      Number of leading hex characters to keep. Default is None (all).
    algorithm : str, optional
      ``'md5'`` or ``'sha256'``. Default is ``'md5'``.

    Returns
    -------
    str
      The hex digest, cut to ``length`` characters when given.

    Examples
    --------
    >>> _FakeBasePlugin().get_hash("DEEPLOY_DEPLOYED_JOBS", algorithm="sha256", length=10) == (
    ...   hashlib.sha256(b"DEEPLOY_DEPLOYED_JOBS").hexdigest()[:10])
    True
    """
    # The digest of the UTF-8 bytes with the requested algorithm, cut to the requested length.
    return hashlib.new(algorithm, str_data.encode("utf-8")).hexdigest()[:length]


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


# The hash keys the node's own plugins write, as found in the edge node and core plugins.
SYSTEM_HKEYS = [
  "DAUTH_JOB_SECRETS", "DAUTH_JOB_SECRET_REVISIONS", "DAUTH_REVOKED_UNLICENSED_NODES", "DAUTH_REQUESTS",
  "DEEPLOY_DEPLOYED_JOBS", "DEEPLOY_OPERATIONS", "DEEPLOY_NODE_OPERATIONS", "DEEPLOY_REQUESTS",
  "NODE_KEY_ROTATIONS", "tunnels_manager_secrets", "tunnels_manager_tcp_routes", "CHAINSTORE_SYNC",
  "plus_preferred_nodes", "chain_dist_monitor",
  "inference_api:capacity:default", "inference_api:req:default", "inference_api:res:default",
]
# The hash key a first-party backend client uses through this API, and an arbitrary application one.
APP_HKEYS = ["ratio1:backend:offline_nodes_notifier:v1", "my-app:players"]
# A value that must never reach the log.
SECRET_VALUE = "value-that-must-not-be-logged"


def _composed_key(hkey, field):
  """
  Build the raw key under which chainstore_hset stores one hash field.

  Mirrors the composition in naeural_core's base plugin API: "hs:", the first 10 hex characters of the
  SHA-256 of the hash key, ":", then the URL-safe Base64 of the field.

  Parameters
  ----------
  hkey : str
    Hash namespace.
  field : str
    Field name within the hash.

  Returns
  -------
  str
    The composed raw key.

  Examples
  --------
  >>> _composed_key("DEEPLOY_DEPLOYED_JOBS", "7").startswith("hs:")
  True
  """
  # The hash part of the composed key: the first 10 hex characters of the SHA-256 of the hash key.
  digest = hashlib.sha256(hkey.encode("utf-8")).hexdigest()[:10]
  # The field part: its URL-safe Base64 form.
  return "hs:{}:{}".format(digest, base64.urlsafe_b64encode(field.encode("utf-8")).decode("ascii"))


def _make_store_plugin():
  """
  Build the plugin over a fake chain store that records every call and every log line.

  Returns
  -------
  CstoreManagerApiPlugin
    Plugin with ``calls`` (list of ``(operation, kwargs)``), ``logged`` (list of ``(message, color)``) and
    the six ``chainstore_*`` operations replaced by recorders over a dict.

  Examples
  --------
  >>> plugin = _make_store_plugin()
  >>> plugin.set(key="app:counter", value=1)
  True
  >>> plugin.calls[0][0]
  'set'
  """
  # The plugin class under test, built without a node.
  plugin = CstoreManagerApiPlugin()
  # Debug off and the periodic summary every 50 calls: the node defaults.
  plugin.cfg_debug, plugin.cfg_force_debug_each_nth_api_call = False, 50
  # The recorded store calls, the recorded log lines, and one dict holding flat keys and hash fields.
  plugin.calls, plugin.logged, store = [], [], {}
  # Keep each log line with its color, so a test can check the red refusal line.
  plugin.P = lambda msg, *args, **kwargs: plugin.logged.append((msg, kwargs.get("color")))
  # How each fake chain-store operation answers, from the dict.
  answers = {
    "set": lambda kw: store.__setitem__(kw["key"], kw["value"]) or True,
    "get": lambda kw: store.get(kw["key"]),
    "hset": lambda kw: store.__setitem__((kw["hkey"], kw["key"]), kw["value"]) or True,
    "hget": lambda kw: store.get((kw["hkey"], kw["key"])),
    "hgetall": lambda kw: {k[1]: v for k, v in store.items() if isinstance(k, tuple) and k[0] == kw["hkey"]},
    "hsync": lambda kw: {"hkey": kw["hkey"], "source_peer": "peer-1"},
  }
  # Install each fake operation: it records the call as the endpoint made it, then answers.
  for operation, answer in answers.items():
    # Bind this operation's name and answer through default arguments.
    setattr(plugin, "chainstore_" + operation,
            lambda op=operation, ans=answer, **kw: plugin.calls.append((op, kw)) or ans(kw))
  # The plugin, ready for the endpoints.
  return plugin


class CstoreManagerApiNamespaceTests(unittest.TestCase):
  """The six data endpoints refuse the namespaces the node's own plugins keep and serve every other one."""

  def test_every_data_endpoint_refuses_a_system_namespace(self):
    """Each of the six data endpoints refuses each system hash key: 403 error answer, store untouched,
    one red log line with the endpoint and the namespace and without the value."""
    # Every system hash key, on each of the six data endpoints.
    for hkey in SYSTEM_HKEYS:
      # The six requests, the writes carrying a value that must not reach the log.
      requests = {
        "set": lambda p: p.set(key=hkey, value=SECRET_VALUE),
        "get": lambda p: p.get(key=hkey),
        "hset": lambda p: p.hset(hkey=hkey, key="field", value=SECRET_VALUE),
        "hget": lambda p: p.hget(hkey=hkey, key="field"),
        "hgetall": lambda p: p.hgetall(hkey=hkey),
        "hsync": lambda p: p.hsync(hkey=hkey),
      }
      # One case per endpoint.
      for endpoint, request in requests.items():
        # Name the case in a failure report.
        with self.subTest(hkey=hkey, endpoint=endpoint):
          # A fresh plugin per request, so the calls and log lines checked are this request's only.
          plugin = _make_store_plugin()
          # Send the request.
          result = request(plugin)
          # The error answer, with 403 and the namespace named, and the store never called.
          self.assertEqual((result["status_code"], result["logged"], hkey in result["error"], plugin.calls),
                           (403, True, True, []))
          # Exactly one log line.
          [(line, color)] = plugin.logged
          # It is red, names the endpoint and the namespace, and never the value.
          self.assertEqual((color, endpoint in line, hkey in line, SECRET_VALUE in line), ("r", True, True, False))

  def test_plain_get_and_set_refuse_a_raw_key_in_the_composed_hash_form(self):
    """A raw key in the composed form of a hash record cannot be read or written through get or set."""
    # Two system hashes and the first-party application hash.
    for hkey in ["DEEPLOY_DEPLOYED_JOBS", "tunnels_manager_secrets", APP_HKEYS[0]]:
      # The raw key under which chainstore_hset stores field "7" of this hash.
      raw_key = _composed_key(hkey, "7")
      # The raw key on each plain endpoint.
      for endpoint in ("get", "set"):
        # Name the case in a failure report.
        with self.subTest(hkey=hkey, endpoint=endpoint):
          # A fresh plugin per request.
          plugin = _make_store_plugin()
          # The raw key on the plain endpoint.
          result = plugin.get(key=raw_key) if endpoint == "get" else plugin.set(key=raw_key, value=SECRET_VALUE)
          # Refused with 403 before the store is called.
          self.assertEqual((result["status_code"], plugin.calls), (403, []))
          # Exactly one log line.
          [(line, color)] = plugin.logged
          # It is red and never names the value.
          self.assertEqual((color, SECRET_VALUE in line), ("r", False))

  def test_a_hash_key_with_the_index_of_a_system_hash_key_is_refused(self):
    """An application hash key whose index equals that of a system hash key is refused on the four hash
    endpoints, while the same name as a raw key on plain get and set still reaches the store."""
    # The application name made to share an index with each system hash key in turn.
    app_hkey = APP_HKEYS[1]
    # Every system hash key the node's plugins use.
    for system_hkey in SYSTEM_HKEYS:
      # The four hash requests on the application name.
      requests = {
        "hset": lambda p: p.hset(hkey=app_hkey, key="field", value=SECRET_VALUE),
        "hget": lambda p: p.hget(hkey=app_hkey, key="field"),
        "hgetall": lambda p: p.hgetall(hkey=app_hkey),
        "hsync": lambda p: p.hsync(hkey=app_hkey),
      }
      # One case per hash endpoint.
      for endpoint, request in requests.items():
        # Name the case in a failure report.
        with self.subTest(system_hkey=system_hkey, endpoint=endpoint):
          # A fresh plugin per request.
          plugin = _make_store_plugin()
          # The fake base's hash, kept to answer for every other name.
          real_hash = plugin.get_hash
          # Hash the application name as the system hash key, so the two share an index.
          plugin.get_hash = lambda s, **kw: real_hash(system_hkey if s == app_hkey else s, **kw)
          # The 403 error answer naming the application name, the store never called, and one red log line.
          self.assertEqual(
            (request(plugin), plugin.calls, [color for _, color in plugin.logged]),
            ({"error": f"Namespace '{app_hkey}' is reserved for the node's plugins.", "status_code": 403,
              "logged": True}, [], ["r"]),
          )
    # A plugin whose application name shares the index of the Deeploy jobs hash.
    plugin = _make_store_plugin()
    # The fake base's hash, kept to answer for every other name.
    real_hash = plugin.get_hash
    # Hash the application name as the Deeploy jobs hash key.
    plugin.get_hash = lambda s, **kw: real_hash("DEEPLOY_DEPLOYED_JOBS" if s == app_hkey else s, **kw)
    # As a raw key the name addresses no hash record: plain set and get reach the store.
    self.assertEqual((plugin.set(key=app_hkey, value=1), plugin.get(key=app_hkey)), (True, 1))

  def test_the_refusal_log_line_holds_at_most_64_characters_of_the_namespace(self):
    """A refused namespace longer than 64 characters is cut to its first 64 in the log line."""
    # A system-prefixed hash key of 1000 characters.
    hkey = "DEEPLOY_" + "x" * 992
    # A fresh plugin.
    plugin = _make_store_plugin()
    # Refused.
    self.assertEqual(plugin.hget(hkey=hkey, key="field")["status_code"], 403)
    # Exactly one log line.
    [(line, _)] = plugin.logged
    # It holds the first 64 characters of the hash key and not the 65th.
    self.assertEqual((hkey[:64] in line, hkey[:65] in line), (True, False))

  def test_application_namespaces_work_on_every_endpoint_as_before(self):
    """The first-party backend key and an arbitrary application key reach the store on every endpoint,
    with the same arguments and answers as before, and no log line."""
    # The first-party backend hash key and an arbitrary application one.
    for hkey in APP_HKEYS:
      # Name the case in a failure report.
      with self.subTest(hkey=hkey):
        # A fresh plugin over an empty store.
        plugin = _make_store_plugin()
        # The status call the backend client makes first.
        self.assertEqual(plugin.get_status(), {"ok": True, "message": "CStore Manager API is running."})
        # The application name as a raw key on plain set and get.
        self.assertEqual((plugin.set(key=hkey, value={"n": 1}), plugin.get(key=hkey)), (True, {"n": 1}))
        # The application name as a hash key on hset, hget and hgetall.
        self.assertEqual(
          (plugin.hset(hkey=hkey, key="node-1", value={"seen": 1}), plugin.hget(hkey=hkey, key="node-1"),
           plugin.hgetall(hkey=hkey)),
          (True, {"seen": 1}, {"node-1": {"seen": 1}}),
        )
        # The application name on hsync.
        self.assertEqual(plugin.hsync(hkey=hkey), {"hkey": hkey, "source_peer": "peer-1"})
        # The store saw each request with the arguments the endpoints always passed.
        self.assertEqual(plugin.calls, [
          ("set", {"key": hkey, "value": {"n": 1}, "debug": False, "extra_peers": []}),
          ("get", {"key": hkey, "debug": False}),
          ("hset", {"hkey": hkey, "key": "node-1", "value": {"seen": 1}, "debug": False, "extra_peers": []}),
          ("hget", {"hkey": hkey, "key": "node-1", "debug": False}),
          ("hgetall", {"hkey": hkey, "debug": False}),
          ("hsync", {"hkey": hkey, "debug": False, "extra_peers": None}),
        ])
        # No log line: nothing was refused.
        self.assertEqual(plugin.logged, [])


if __name__ == "__main__":
  unittest.main()
