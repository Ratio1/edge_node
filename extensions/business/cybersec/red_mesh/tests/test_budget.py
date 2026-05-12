"""OWASP API Top 10 — Subphase 1.7 commit #6.

`RequestBudget` exhaustion + shared-state semantics. Verifies the
budget enforces the per-scan cap correctly, including the concurrent
case (two probe instances sharing one budget never exceed the cap).
"""

from __future__ import annotations

import threading
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase


class TestRequestBudgetSequential(unittest.TestCase):

  def test_consume_within_budget(self):
    b = RequestBudget(remaining=5, total=5)
    self.assertTrue(b.consume())
    self.assertTrue(b.consume(2))
    self.assertEqual(b.remaining, 2)
    self.assertEqual(b.exhausted_count, 0)

  def test_consume_exhausts(self):
    b = RequestBudget(remaining=2, total=2)
    self.assertTrue(b.consume())
    self.assertTrue(b.consume())
    self.assertFalse(b.consume())
    self.assertEqual(b.exhausted_count, 1)
    self.assertFalse(b.consume(5))
    self.assertEqual(b.exhausted_count, 2)
    # Already-exhausted budget never goes negative.
    self.assertEqual(b.remaining, 0)

  def test_consume_too_many_at_once(self):
    """Single call asking for more than remaining is refused atomically."""
    b = RequestBudget(remaining=3, total=3)
    self.assertFalse(b.consume(5))
    self.assertEqual(b.remaining, 3)
    self.assertEqual(b.exhausted_count, 1)

  def test_snapshot_shape(self):
    b = RequestBudget(remaining=10, total=10)
    b.consume(3)
    b.consume(20)  # exhausted
    snap = b.snapshot()
    self.assertEqual(snap, {"remaining": 7, "total": 10, "exhausted_count": 1})


class TestRequestBudgetConcurrent(unittest.TestCase):

  def test_concurrent_consumers_never_exceed_total(self):
    """Two threads racing to consume must collectively decrement
    exactly `total` requests — no double-spend, no underflow."""
    b = RequestBudget(remaining=100, total=100)
    success_count = [0, 0]

    def worker(idx):
      while b.consume():
        success_count[idx] += 1

    t1 = threading.Thread(target=worker, args=(0,))
    t2 = threading.Thread(target=worker, args=(1,))
    t1.start(); t2.start()
    t1.join(); t2.join()

    self.assertEqual(success_count[0] + success_count[1], 100)
    self.assertEqual(b.remaining, 0)
    self.assertGreater(b.exhausted_count, 0)


class TestProbeBaseBudgetHelper(unittest.TestCase):

  def _make_probe_with_budget(self, total):
    budget = RequestBudget(remaining=total, total=total)

    class _Probe(ProbeBase):
      def run(self):
        return self.findings

    p = _Probe(
      target_url="http://x", auth_manager=MagicMock(),
      target_config=MagicMock(), safety=MagicMock(),
      request_budget=budget,
    )
    return p, budget

  def test_budget_helper_consumes(self):
    p, budget = self._make_probe_with_budget(2)
    self.assertTrue(p.budget())
    self.assertTrue(p.budget())
    self.assertFalse(p.budget())
    self.assertEqual(budget.exhausted_count, 1)

  def test_budget_helper_no_budget_always_true(self):
    """ProbeBase without a budget (legacy callers) should never block."""
    class _Probe(ProbeBase):
      def run(self):
        return self.findings

    p = _Probe(
      target_url="http://x", auth_manager=MagicMock(),
      target_config=MagicMock(), safety=MagicMock(),
    )
    for _ in range(100):
      self.assertTrue(p.budget())


class TestRequestBudgetSharedAcrossProbes(unittest.TestCase):
  """Two probe instances share one budget — total consumption never exceeds cap."""

  def test_two_probes_share_one_budget(self):
    budget = RequestBudget(remaining=5, total=5)

    class _Probe(ProbeBase):
      def run(self):
        return self.findings

    p1 = _Probe(
      target_url="http://x", auth_manager=MagicMock(),
      target_config=MagicMock(), safety=MagicMock(),
      request_budget=budget,
    )
    p2 = _Probe(
      target_url="http://x", auth_manager=MagicMock(),
      target_config=MagicMock(), safety=MagicMock(),
      request_budget=budget,
    )

    self.assertTrue(p1.budget())
    self.assertTrue(p2.budget())
    self.assertTrue(p1.budget())
    self.assertTrue(p2.budget())
    self.assertTrue(p1.budget())
    # Five total — next call from either probe fails.
    self.assertFalse(p1.budget())
    self.assertFalse(p2.budget())
    self.assertEqual(budget.remaining, 0)


if __name__ == "__main__":
  unittest.main()
