"""The TCP route lookup answers "not found" for a port with no route and logs who asked."""
# The test framework.
import unittest

# The plugin class as the other tunnels tests load it: on their stand-in base class when these tests
# run by themselves, on the real one when another test loaded it first. Both work here.
from extensions.business.tunnels.tests.test_tunnels_manager_cloudflare_errors import TunnelsManagerPlugin


# The address the stand-in reports for the caller; a documentation address, not a real host.
CLIENT_IP = "203.0.113.7"
# The name of the chain-store hash the stand-in keeps its routes in.
ROUTES_HKEY = "tcp_routes"


def _lookup_plugin(routes=None):
  """
  Build a tunnels manager that can answer route lookups and records what it logs.

  Parameters
  ----------
  routes : dict, optional
    {port text: route record} to put in the route registry.

  Returns
  -------
  tuple
    `(plugin, lines)`: the plugin stand-in and the list that receives `(text, color)` of every log call.
  """
  # Only what a lookup reads is set, so the stand-in does not depend on which base class is loaded.
  plugin = TunnelsManagerPlugin.__new__(TunnelsManagerPlugin)
  # The name of the chain-store hash that holds the routes.
  plugin.cfg_tcp_routes_hkey = ROUTES_HKEY
  # A copy, so a test's dictionary is not shared with the stand-in.
  stored = dict(routes or {})
  # The local replica of the route registry: one record per port, keyed by the port as text.
  plugin.chainstore_hget = lambda hkey, key: stored.get(str(key)) if hkey == ROUTES_HKEY else None
  # The log lines of the stand-in, in the order they are written.
  lines = []
  # Every log call is kept with its colour: a red line is also copied to the error log.
  plugin.P = lambda text, *args, **kwargs: lines.append((text, kwargs.get("color")))
  # The address the web app holds for the request being handled.
  plugin.get_request_client_ip = lambda: CLIENT_IP
  # The stand-in and the list its log calls fill.
  return plugin, lines


class TcpRouteLookupTests(unittest.TestCase):

  def test_port_with_no_route_is_answered_404_and_the_caller_is_logged(self):
    """A lookup of an unregistered port returns a 404 answer instead of raising, with one plain line naming port and caller."""
    # A registry with no route at all.
    plugin, lines = _lookup_plugin()
    # The lookup of a valid port nobody registered: before, this raised.
    answer = plugin.get_tcp_route(30007)
    # The web app turns `status_code` of a returned dictionary into the HTTP status, with no traceback.
    self.assertEqual(answer, {"error": "No TCP route found for port 30007", "status_code": 404})
    # One line, not coloured, so it stays out of the error log.
    self.assertEqual(lines, [(f"No TCP route for port 30007, asked by {CLIENT_IP}", None)])

  def test_disabled_route_is_answered_like_a_missing_one(self):
    """A route that exists but is disabled gives the same 404 answer and never its hostname."""
    # One stored route, switched off.
    plugin, lines = _lookup_plugin({"30010": {"hostname": "app-1.example.org", "enabled": False}})
    # The lookup of that port.
    answer = plugin.get_tcp_route(30010)
    # The answer of a missing route, word for word.
    self.assertEqual(answer, {"error": "No TCP route found for port 30010", "status_code": 404})
    # The miss is logged once.
    self.assertEqual(len(lines), 1)
    # Neither the answer nor the line gives away the hostname of the disabled route.
    self.assertNotIn("app-1.example.org", str(answer) + lines[0][0])

  def test_route_is_answered_with_its_hostname_and_no_log_line(self):
    """A lookup that finds a route returns the hostname as before and logs nothing."""
    # One stored route with no `enabled` field: a route is enabled unless it says otherwise.
    plugin, lines = _lookup_plugin({"30010": {"hostname": "app-1.example.org"}})
    # The answer is the hostname itself, not a dictionary.
    self.assertEqual(plugin.get_tcp_route(30010), "app-1.example.org")
    # A hit writes no line: only misses are logged.
    self.assertEqual(lines, [])

  def test_route_without_a_hostname_still_raises(self):
    """A stored route with no hostname is a broken record and stays an error, not a 404."""
    # An enabled route whose record lacks the hostname; the log lines are not read here.
    plugin, _ = _lookup_plugin({"30010": {"enabled": True}})
    # The lookup raises and its text names the port and what is missing.
    with self.assertRaisesRegex(Exception, "TCP route for port 30010 has no hostname"):
      # The lookup of the broken record.
      plugin.get_tcp_route(30010)

  def test_invalid_port_still_raises(self):
    """A port that is not a port number is refused by validation as before, not answered as a missing route."""
    # A registry with no route at all.
    plugin, lines = _lookup_plugin()
    # A number above the port range, zero and a text that is not a number.
    for port in (70000, 0, "abc"):
      # Each value reports on its own.
      with self.subTest(port=port):
        # Validation raises before the registry is read.
        with self.assertRaisesRegex(Exception, "Invalid TCP public port"):
          # The lookup of the invalid port.
          plugin.get_tcp_route(port)
    # An invalid port is not logged as a missing route.
    self.assertEqual(lines, [])


if __name__ == "__main__":
  # Run this file's tests when it is started as a script.
  unittest.main()
