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


class CheckAuthorizedScanModeTests(unittest.TestCase):
  def test_none_authorization_is_ungated(self):
    # A non-tenant / legacy launch passes None and is not gated.
    self.assertIsNone(launch_api.check_authorized_scan_mode("syn", None))

  def test_mode_in_list_allowed(self):
    self.assertIsNone(launch_api.check_authorized_scan_mode("syn", ["connect", "syn"]))

  def test_mode_outside_list_refused(self):
    err = launch_api.check_authorized_scan_mode("syn", ["connect"])
    self.assertEqual(err["error"], "scan_mode_not_authorized")
    self.assertEqual(err["status_code"], 400)
    self.assertEqual(err["authorized_scan_modes"], ["connect"])


class ResolveNetworkScanModeAuthorizationTests(unittest.TestCase):
  def test_authorized_mode_passes(self):
    with patch.object(launch_api, "_raw_socket_available", return_value=True):
      mode, err = launch_api.resolve_network_scan_mode("syn", authorized_scan_modes=["connect", "syn"])
    self.assertIsNone(err)
    self.assertEqual(mode, "syn")

  def test_unauthorized_syn_refused_before_capability(self):
    # Authorization precedes the raw-socket probe: an unauthorized syn is
    # scan_mode_not_authorized even on a node that could never run it.
    with patch.object(launch_api, "_raw_socket_available", return_value=False):
      mode, err = launch_api.resolve_network_scan_mode("syn", authorized_scan_modes=["connect"])
    self.assertIsNone(mode)
    self.assertEqual(err["error"], "scan_mode_not_authorized")

  def test_unauthorized_connect_refused(self):
    # A syn-only engagement refuses a connect request (e.g. the /launch_test
    # default, which always sends connect). The gate applies uniformly.
    mode, err = launch_api.resolve_network_scan_mode("connect", authorized_scan_modes=["syn"])
    self.assertIsNone(mode)
    self.assertEqual(err["error"], "scan_mode_not_authorized")

  def test_validation_precedes_authorization(self):
    # An unknown mode is a validation_error before any authorization check.
    mode, err = launch_api.resolve_network_scan_mode("ack", authorized_scan_modes=["connect"])
    self.assertIsNone(mode)
    self.assertEqual(err["error"], "validation_error")

  def test_default_none_authorization_ungated(self):
    # Omitting authorized_scan_modes keeps phase-1 behavior (no authz gate).
    with patch.object(launch_api, "_raw_socket_available", return_value=True):
      mode, err = launch_api.resolve_network_scan_mode("syn")
    self.assertIsNone(err)
    self.assertEqual(mode, "syn")


if __name__ == "__main__":
  unittest.main()
