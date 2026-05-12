"""Per-scan request budget for graybox probes.

`RequestBudget` is a small mutable object shared by reference across
every probe instance in a single scan. It enforces a global request cap
so a misconfigured ``target_config`` (e.g., 200 endpoints across 5
families) cannot DoS the target or the scanner.

Design (Subphase 1.7 of the API Top 10 plan):
- `GrayboxProbeContext` is `frozen=True`, so it cannot itself hold the
  counter. The frozen context instead holds a *reference* to a single
  RequestBudget shared across all probes.
- Probes consult the budget via `ProbeBase.budget()` before each HTTP
  request. When exhausted, probes emit `inconclusive` with reason
  ``budget_exhausted`` rather than skipping silently.
- `consume()` is thread-safe (`threading.Lock`) so future parallel
  dispatch cannot double-spend.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class RequestBudget:
  """Shared mutable request budget.

  Fields:
    remaining: requests not yet consumed.
    total: original budget (for reporting).
    exhausted_count: number of `consume()` calls that returned False
      because the budget was empty. Surfaced in worker metrics so
      operators can see whether a scan was budget-bound.

  ``_lock`` guards the check-then-decrement to avoid a race when probes
  share the budget across threads (v1 dispatch is single-threaded but
  the lock costs nothing and makes future parallelisation safe).
  """
  remaining: int
  total: int
  exhausted_count: int = 0
  _lock: threading.Lock = field(default_factory=threading.Lock,
                                  init=False, repr=False, compare=False)

  def consume(self, n: int = 1) -> bool:
    """Decrement by ``n`` if available; return False (and bump
    ``exhausted_count``) when the budget can't cover the request."""
    with self._lock:
      if self.remaining < n:
        self.exhausted_count += 1
        return False
      self.remaining -= n
      return True

  def snapshot(self) -> dict:
    """Return a JSON-friendly snapshot for worker outcome / metrics."""
    return {
      "remaining": self.remaining,
      "total": self.total,
      "exhausted_count": self.exhausted_count,
    }
