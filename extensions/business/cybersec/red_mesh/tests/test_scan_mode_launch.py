"""Launch-layer scan_mode validation and capability refusal (RM-094 phase 1)."""

import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import launch_api


class ResolveNetworkScanModeTests(unittest.TestCase):
  def test_default_is_connect(self):
    mode, err = launch_api.resolve_network_scan_mode("")
    self.assertIsNone(err)
    self.assertEqual(mode, "connect")

  def test_none_is_connect(self):
    mode, err = launch_api.resolve_network_scan_mode(None)
    self.assertIsNone(err)
    self.assertEqual(mode, "connect")

  def test_connect_passes_without_raw_socket(self):
    with patch.object(launch_api, "_raw_socket_available", return_value=False):
      mode, err = launch_api.resolve_network_scan_mode("connect")
    self.assertIsNone(err)
    self.assertEqual(mode, "connect")

  def test_unknown_mode_rejected(self):
    mode, err = launch_api.resolve_network_scan_mode("ack")
    self.assertIsNone(mode)
    self.assertEqual(err["error"], "validation_error")

  def test_syn_refused_when_raw_socket_missing(self):
    with patch.object(launch_api, "_raw_socket_available", return_value=False):
      mode, err = launch_api.resolve_network_scan_mode("syn")
    self.assertIsNone(mode)
    self.assertEqual(err["error"], "scan_mode_unavailable")

  def test_syn_allowed_when_raw_socket_present(self):
    with patch.object(launch_api, "_raw_socket_available", return_value=True):
      mode, err = launch_api.resolve_network_scan_mode("SYN")
    self.assertIsNone(err)
    self.assertEqual(mode, "syn")


if __name__ == "__main__":
  unittest.main()
