import unittest

from extensions.business.cybersec.red_mesh.connection_metrics import (
  detect_connection_signals,
  merge_connection_windows,
)
from extensions.business.cybersec.red_mesh.mixins.live_progress import _LiveProgressMixin
from extensions.business.cybersec.red_mesh.worker.metrics_collector import MetricsCollector


def _window(index, responsive_count, attempts=5, success_rate=None):
  if success_rate is None:
    success_rate = responsive_count / attempts
  return {
    "window_start": index * 60.0,
    "window_end": (index + 1) * 60.0,
    "success_rate": success_rate,
    "attempts": attempts,
    "responsive_count": responsive_count,
    "response_rate": responsive_count / attempts,
  }


class TestConnectionWindows(unittest.TestCase):

  def test_refused_and_reset_are_responsive_but_not_connected(self):
    collector = MetricsCollector()
    collector._connection_log = [
      (100.0, "connected"),
      (101.0, "refused"),
      (102.0, "reset"),
      (103.0, "timeout"),
      (104.0, "error"),
    ]

    windows = collector._compute_success_windows()

    self.assertEqual(windows, [{
      "window_start": 0.0,
      "window_end": 60.0,
      "success_rate": 0.2,
      "attempts": 5,
      "responsive_count": 3,
      "response_rate": 0.6,
    }])
    self.assertFalse(detect_connection_signals(windows)["blocking_detected"])

  def test_single_connection_still_produces_a_window(self):
    collector = MetricsCollector()
    collector._connection_log = [(100.0, "refused")]

    self.assertEqual(collector._compute_success_windows()[0]["attempts"], 1)

  def test_closed_ports_remain_responsive_across_windows(self):
    collector = MetricsCollector()
    collector._connection_log = (
      [(100.0 + index, "refused") for index in range(5)]
      + [(160.0 + index, "reset") for index in range(5)]
    )

    windows = collector._compute_success_windows()
    signals = detect_connection_signals(windows)

    self.assertEqual([window["success_rate"] for window in windows], [0.0, 0.0])
    self.assertEqual([window["response_rate"] for window in windows], [1.0, 1.0])
    self.assertFalse(signals["blocking_detected"])

  def test_blocking_requires_qualified_high_to_low_response_transition(self):
    windows = [
      _window(0, 4),
      _window(1, 0, attempts=2),  # Unqualified evidence is ignored.
      _window(2, 1),
    ]

    signals = detect_connection_signals(windows)

    self.assertTrue(signals["blocking_detected"])
    self.assertFalse(signals["rate_limiting_detected"])

  def test_insufficient_samples_never_raise_a_signal(self):
    windows = [
      _window(0, 4, attempts=4),
      _window(1, 0, attempts=4),
      _window(2, 4, attempts=4),
      _window(3, 1, attempts=4),
    ]

    self.assertEqual(detect_connection_signals(windows), {
      "rate_limiting_detected": False,
      "blocking_detected": False,
    })

  def test_optional_response_rate_can_supply_missing_responsive_count(self):
    windows = [
      {"attempts": 5, "response_rate": 0.8},
      {"attempts": 5, "response_rate": 0.2},
    ]

    self.assertTrue(detect_connection_signals(windows)["blocking_detected"])

  def test_throttling_uses_attempt_weighted_first_and_last_pairs(self):
    windows = [
      _window(0, 5, attempts=5),
      _window(1, 15, attempts=15),
      _window(2, 5, attempts=5),
      _window(3, 40, attempts=100),
    ]

    signals = detect_connection_signals(windows)

    self.assertTrue(signals["rate_limiting_detected"])
    self.assertFalse(signals["blocking_detected"])

  def test_throttling_requires_four_qualified_windows(self):
    windows = [_window(0, 5), _window(1, 5), _window(2, 3)]

    self.assertFalse(detect_connection_signals(windows)["rate_limiting_detected"])

  def test_blocking_threshold_is_not_reported_as_throttling(self):
    windows = [_window(0, 5), _window(1, 5), _window(2, 1), _window(3, 1)]

    signals = detect_connection_signals(windows)

    self.assertTrue(signals["blocking_detected"])
    self.assertFalse(signals["rate_limiting_detected"])


class TestConnectionWindowMerge(unittest.TestCase):

  def test_aligned_windows_sum_counts_and_recompute_signals(self):
    worker_one = {
      "success_rate_over_time": [_window(0, 5), _window(1, 0)],
      "blocking_detected": True,
    }
    worker_two = {
      "success_rate_over_time": [_window(0, 0), _window(1, 5)],
      "blocking_detected": False,
    }

    merged = _LiveProgressMixin._merge_worker_metrics([worker_one, worker_two])
    windows = merged["success_rate_over_time"]

    self.assertEqual([window["attempts"] for window in windows], [10, 10])
    self.assertEqual([window["responsive_count"] for window in windows], [5, 5])
    self.assertEqual([window["response_rate"] for window in windows], [0.5, 0.5])
    self.assertFalse(merged["blocking_detected"])
    self.assertFalse(merged["rate_limiting_detected"])

  def test_legacy_windows_remain_visible_but_cannot_raise_a_signal(self):
    legacy_windows = [
      {"window_start": 0.0, "window_end": 60.0, "success_rate": 1.0},
      {"window_start": 60.0, "window_end": 120.0, "success_rate": 0.0},
    ]

    merged = merge_connection_windows([{
      "success_rate_over_time": legacy_windows,
      "blocking_detected": True,
    }])

    self.assertEqual(merged, legacy_windows)
    self.assertFalse(detect_connection_signals(merged)["blocking_detected"])


if __name__ == "__main__":
  unittest.main()
