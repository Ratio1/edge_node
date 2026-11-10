import unittest

from constants import ADMIN_PIPELINE


class ReleaseAppAdminConfigTests(unittest.TestCase):

  def test_release_app_runs_process_every_5s_instead_of_every_lap(self):
    # On non-oracle nodes the app is disabled and never starts uvicorn, so the idle
    # wait does not cover it; PROCESS_DELAY turns its ~27 laps/s into cheap postpone checks.
    self.assertEqual(ADMIN_PIPELINE["NAEURAL_RELEASE_APP"]["PROCESS_DELAY"], 5)


if __name__ == "__main__":
  unittest.main()
