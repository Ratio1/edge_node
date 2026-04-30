"""Phase 4 of PR 388 remediation — live progress + merge order.

Covers:
  - Audit #6: webapp scans no longer report "done" prematurely while
    weak-auth is still pending.
  - Audit #7: probe-breakdown merge is commutative over worker order,
    including prefixed failures (failed:auth_refresh, failed:timeout)
    and skipped variants.
  - Aborted scans short-circuit to "done" so live progress does not
    linger in a stale phase.
  - Required worker parameter: forgotten call sites fail loudly.
"""

import unittest
from itertools import permutations, product
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.mixins.live_progress import (
  _thread_phase, _LiveProgressMixin,
)
from extensions.business.cybersec.red_mesh.graybox.models import (
  GrayboxCredentialSet,
)


def _mk_worker(weak_candidates=None, excluded_features=None):
  """Build a minimal worker object with a job_config the phase
  resolver can read."""
  worker = MagicMock()
  worker.job_config = MagicMock()
  worker.job_config.weak_candidates = weak_candidates or []
  worker.job_config.excluded_features = excluded_features or []
  worker.job_config.official_username = "admin"
  worker.job_config.official_password = "secret"
  worker.job_config.regular_username = ""
  worker.job_config.regular_password = ""
  worker.job_config.max_weak_attempts = 5
  return worker


class TestThreadPhaseWebapp(unittest.TestCase):

  def test_graybox_probes_done_with_weak_auth_pending(self):
    """Audit #6: probes completed + weak-auth configured -> "weak_auth",
    not "done". Weak-auth hasn't run yet.
    """
    worker = _mk_worker(weak_candidates=["admin:admin"])
    state = {
      "scan_type": "webapp",
      "completed_tests": ["graybox_probes"],
    }
    self.assertEqual(_thread_phase(state, worker), "weak_auth")

  def test_graybox_probes_done_with_weak_auth_finished(self):
    worker = _mk_worker(weak_candidates=["admin:admin"])
    state = {
      "scan_type": "webapp",
      "completed_tests": ["graybox_probes", "graybox_weak_auth"],
    }
    self.assertEqual(_thread_phase(state, worker), "done")

  def test_graybox_probes_done_with_weak_auth_excluded(self):
    """Weak-auth feature explicitly excluded -> "done" after probes."""
    worker = _mk_worker(
      weak_candidates=["admin:admin"],
      excluded_features=["_graybox_weak_auth"],
    )
    state = {
      "scan_type": "webapp",
      "completed_tests": ["graybox_probes"],
    }
    self.assertEqual(_thread_phase(state, worker), "done")

  def test_graybox_probes_done_with_no_weak_candidates(self):
    """No weak candidates configured -> nothing to do, "done"."""
    worker = _mk_worker(weak_candidates=[])
    state = {
      "scan_type": "webapp",
      "completed_tests": ["graybox_probes"],
    }
    self.assertEqual(_thread_phase(state, worker), "done")

  def test_aborted_state_short_circuits_to_done(self):
    """Audit #1 + Phase 1: aborted scans return "done" regardless of
    completed_tests so live progress does not linger in a stuck
    phase forever.
    """
    worker = _mk_worker()
    state = {
      "scan_type": "webapp",
      "completed_tests": [],
      "aborted": True,
      "abort_reason": "unauthorized target",
      "abort_phase": "preflight",
    }
    self.assertEqual(_thread_phase(state, worker), "done")

  def test_intermediate_phases_unchanged(self):
    worker = _mk_worker()
    self.assertEqual(
      _thread_phase({"scan_type": "webapp", "completed_tests": []}, worker),
      "preflight",
    )
    self.assertEqual(
      _thread_phase({"scan_type": "webapp",
                     "completed_tests": ["graybox_auth"]}, worker),
      "discovery",
    )
    self.assertEqual(
      _thread_phase({"scan_type": "webapp",
                     "completed_tests": ["graybox_auth",
                                         "graybox_discovery"]}, worker),
      "graybox_probes",
    )

  def test_missing_worker_argument_raises(self):
    """No default on `worker` — forgotten call sites fail loudly."""
    with self.assertRaises(TypeError):
      _thread_phase({"scan_type": "webapp", "completed_tests": []})


class TestThreadPhaseNetwork(unittest.TestCase):

  def test_network_path_ignores_worker_job_config(self):
    """Network-scan path doesn't need job_config; a MagicMock worker
    still works."""
    worker = MagicMock()
    worker.job_config = None
    self.assertEqual(
      _thread_phase({"scan_type": "network", "completed_tests": []}, worker),
      "port_scan",
    )
    self.assertEqual(
      _thread_phase(
        {"scan_type": "network",
         "completed_tests": ["correlation_completed"]}, worker),
      "done",
    )


class TestWeakAuthEnabled(unittest.TestCase):

  def test_weak_auth_enabled_predicate(self):
    cfg = MagicMock()
    cfg.weak_candidates = ["admin:admin"]
    cfg.excluded_features = []
    cfg.official_username = "admin"
    cfg.official_password = "secret"
    cfg.regular_username = ""
    cfg.regular_password = ""
    cfg.max_weak_attempts = 5
    self.assertTrue(GrayboxCredentialSet.weak_auth_enabled(cfg))

  def test_weak_auth_disabled_when_excluded(self):
    cfg = MagicMock()
    cfg.weak_candidates = ["admin:admin"]
    cfg.excluded_features = ["_graybox_weak_auth"]
    cfg.official_username = "admin"
    cfg.official_password = "secret"
    cfg.regular_username = ""
    cfg.regular_password = ""
    cfg.max_weak_attempts = 5
    self.assertFalse(GrayboxCredentialSet.weak_auth_enabled(cfg))

  def test_weak_auth_disabled_when_no_candidates(self):
    cfg = MagicMock()
    cfg.weak_candidates = []
    cfg.excluded_features = []
    cfg.official_username = "admin"
    cfg.official_password = "secret"
    cfg.regular_username = ""
    cfg.regular_password = ""
    cfg.max_weak_attempts = 5
    self.assertFalse(GrayboxCredentialSet.weak_auth_enabled(cfg))


class TestProbeBreakdownMergeOrderIndependence(unittest.TestCase):

  STATUSES = (
    "completed",
    "skipped",
    "skipped:disabled",
    "skipped:stateful_disabled",
    "failed",
    "failed:auth_refresh",
    "failed:timeout",
  )

  @staticmethod
  def _mk(value):
    return {"probe_breakdown": {"k": value}}

  def test_merge_is_commutative_over_all_permutations(self):
    """Enumerate combinations of 3 workers over the fixed status
    alphabet. For every combination, assert that all permutations
    produce the same merged result. 7^3 = 343 combos × 6
    permutations = 2058 merges.
    """
    for combo in product(self.STATUSES, repeat=3):
      results = {
        _LiveProgressMixin._merge_worker_metrics(
          [self._mk(v) for v in perm]
        )["probe_breakdown"]["k"]
        for perm in permutations(combo)
      }
      self.assertEqual(
        len(results), 1,
        f"Non-commutative merge for combo {combo}: {results}",
      )

  def test_failed_beats_failed_prefixed(self):
    """Bare 'failed' is worse than 'failed:timeout' — bare wins."""
    result = _LiveProgressMixin._merge_worker_metrics([
      self._mk("failed"), self._mk("failed:timeout"),
    ])["probe_breakdown"]["k"]
    self.assertEqual(result, "failed")

  def test_failed_prefixed_alphabetical_tiebreak(self):
    """Two failed:* statuses — lexicographically smaller wins."""
    result = _LiveProgressMixin._merge_worker_metrics([
      self._mk("failed:auth_refresh"), self._mk("failed:timeout"),
    ])["probe_breakdown"]["k"]
    self.assertEqual(result, "failed:auth_refresh")

  def test_failed_prefixed_beats_completed(self):
    """Audit #7: failed:auth_refresh must override completed.
    Previously the merge only matched v == 'failed', so the prefixed
    failure lost to a neighbor's completed status.
    """
    result = _LiveProgressMixin._merge_worker_metrics([
      self._mk("completed"), self._mk("failed:auth_refresh"),
    ])["probe_breakdown"]["k"]
    self.assertEqual(result, "failed:auth_refresh")

  def test_skipped_variants_are_order_independent(self):
    """skipped:a + skipped:b picks the smaller alphabetically; both
    permutations produce the same answer.
    """
    result_ab = _LiveProgressMixin._merge_worker_metrics([
      self._mk("skipped:disabled"),
      self._mk("skipped:stateful_disabled"),
    ])["probe_breakdown"]["k"]
    result_ba = _LiveProgressMixin._merge_worker_metrics([
      self._mk("skipped:stateful_disabled"),
      self._mk("skipped:disabled"),
    ])["probe_breakdown"]["k"]
    self.assertEqual(result_ab, result_ba)
    self.assertEqual(result_ab, "skipped:disabled")

  def test_skipped_beats_completed(self):
    result = _LiveProgressMixin._merge_worker_metrics([
      self._mk("completed"), self._mk("skipped:disabled"),
    ])["probe_breakdown"]["k"]
    self.assertEqual(result, "skipped:disabled")


if __name__ == '__main__':
  unittest.main()
