"""The TCP route lookup answers "not found" for a port with no route and logs who asked."""
import unittest

# The plugin class as the other tunnels tests load it: on their stand-in base class when these tests
# run by themselves, on the real one when another test loaded it first. Both work here.
from extensions.business.tunnels.tests.test_tunnels_manager_cloudflare_errors import TunnelsManagerPlugin


CLIENT_IP = "203.0.113.7"
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
  lines = []
  # Every log call is kept with its colour: a red line is also copied to the error log.
  plugin.P = lambda text, *args, **kwargs: lines.append((text, kwargs.get("color")))
  # The address the web app holds for the request being handled.
  plugin.get_request_client_ip = lambda: CLIENT_IP
  return plugin, lines


class TcpRouteLookupTests(unittest.TestCase):

  def test_port_with_no_route_is_answered_404_and_the_caller_is_logged(self):
    """A lookup of an unregistered port returns a 404 answer instead of raising, with one plain line naming port and caller."""
    plugin, lines = _lookup_plugin()
    answer = plugin.get_tcp_route(30007)
    # The web app turns `status_code` of a returned dictionary into the HTTP status, with no traceback.
    self.assertEqual(answer, {"error": "No TCP route found for port 30007", "status_code": 404})
    # One line, not coloured, so it stays out of the error log.
    self.assertEqual(lines, [(f"No TCP route for port 30007, asked by {CLIENT_IP}", None)])

  def test_disabled_route_is_answered_like_a_missing_one(self):
    """A route that exists but is disabled gives the same 404 answer and never its hostname."""
    plugin, lines = _lookup_plugin({"30010": {"hostname": "app-1.example.org", "enabled": False}})
    answer = plugin.get_tcp_route(30010)
    self.assertEqual(answer, {"error": "No TCP route found for port 30010", "status_code": 404})
    self.assertEqual(len(lines), 1)
    self.assertNotIn("app-1.example.org", str(answer) + lines[0][0])

  def test_route_is_answered_with_its_hostname_and_no_log_line(self):
    """A lookup that finds a route returns the hostname as before and logs nothing."""
    plugin, lines = _lookup_plugin({"30010": {"hostname": "app-1.example.org"}})
    self.assertEqual(plugin.get_tcp_route(30010), "app-1.example.org")
    self.assertEqual(lines, [])

  def test_route_without_a_hostname_still_raises(self):
    """A stored route with no hostname is a broken record and stays an error, not a 404."""
    plugin, _ = _lookup_plugin({"30010": {"enabled": True}})
    with self.assertRaisesRegex(Exception, "TCP route for port 30010 has no hostname"):
      plugin.get_tcp_route(30010)

  def test_invalid_port_still_raises(self):
    """A port that is not a port number is refused by validation as before, not answered as a missing route."""
    plugin, lines = _lookup_plugin()
    for port in (70000, 0, "abc"):
      with self.subTest(port=port):
        with self.assertRaisesRegex(Exception, "Invalid TCP public port"):
          plugin.get_tcp_route(port)
    self.assertEqual(lines, [])


if __name__ == "__main__":
  unittest.main()
