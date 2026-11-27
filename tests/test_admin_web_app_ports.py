"""The admin web apps that the service tunnels reach listen on fixed local ports."""
# The test framework.
import unittest

# The configuration of the chain-store API, one of the three apps whose port was already fixed.
from extensions.business.cstore.cstore_manager_api import _CONFIG as CSTORE_CONFIG
# The dAuth manager, one of the five apps that get a fixed port.
from extensions.business.dauth.dauth_manager import DauthManagerPlugin
# The Deeploy manager API, the second of the five.
from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin
# The release download app, the third of the five.
from extensions.business.downloads_webapp.naeural_release_app import NaeuralReleaseAppPlugin
# The liveness API, the fourth of the five.
from extensions.business.liveness.liveness_api import LivenessApiPlugin
# The oracle API, the fifth of the five.
from extensions.business.oracle_management.oracle_api import OracleApiPlugin
# The configuration of the R1FS API, whose port was already fixed.
from extensions.business.r1fs.r1fs_manager_api import _CONFIG as R1FS_CONFIG
# The configuration of the tunnels manager, whose port was already fixed.
from extensions.business.tunnels.tunnels_manager import _CONFIG as TUNNELS_CONFIG


# The port each of the five apps has had on every node so far: with numpy's generator seeded
# with 0 these were the values every node drew, in this start order.
PINNED_PORTS = {
  DeeployManagerApiPlugin: 31653,
  OracleApiPlugin: 30835,
  NaeuralReleaseAppPlugin: 30763,
  DauthManagerPlugin: 31731,
  LivenessApiPlugin: 31033,
}
# The three admin apps whose port was already fixed.
ALREADY_PINNED = (CSTORE_CONFIG["PORT"], R1FS_CONFIG["PORT"], TUNNELS_CONFIG["PORT"])


class AdminWebAppPortTests(unittest.TestCase):

  def test_each_admin_web_app_keeps_the_port_it_has_today(self):
    """Each of the five plugins has its port as a default, so the port no longer depends on a random draw."""
    # Every plugin class with the port it must keep.
    for plugin_class, port in PINNED_PORTS.items():
      # Each plugin reports on its own.
      with self.subTest(plugin=plugin_class.__name__):
        # The class default is what an admin instance with no PORT in its own configuration gets.
        self.assertEqual(plugin_class.CONFIG["PORT"], port)

  def test_fixed_admin_ports_do_not_collide(self):
    """The five ports and the three fixed before are eight different valid port numbers."""
    # The five class defaults, then the three ports fixed before.
    ports = [plugin_class.CONFIG["PORT"] for plugin_class in PINNED_PORTS] + list(ALREADY_PINNED)
    # A repeated port would leave the second app waiting forever for the first one to free it.
    self.assertEqual(len(set(ports)), 8)
    # Each of the eight is checked as a port number.
    for port in ports:
      # Each port reports on its own.
      with self.subTest(port=port):
        # The web app base class accepts only an int between 0 and 65535 as a configured port.
        self.assertIsInstance(port, int)
        # A port an app can listen on: above 0 and at most 65535.
        self.assertTrue(0 < port <= 65535)


if __name__ == "__main__":
  # Run this file's tests when it is started as a script.
  unittest.main()
