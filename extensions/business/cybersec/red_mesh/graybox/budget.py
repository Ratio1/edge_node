"""Per-scan request budget for graybox probes.

`RequestBudget` is a small mutable object shared by reference across
every probe instance in a single scan. It enforces a global request cap
so a misconfigured ``target_config`` (e.g., 200 endpoints across 5
families) cannot DoS the target or the scanner.

Design (Subphase 1.7 of the API Top 10 plan):
- `GrayboxProbeContext` is `frozen=True`, so it cannot itself hold the
  counter. The frozen context instead holds a *reference* to a single
  RequestBudget shared across all probes.
- `GrayboxHttpClient.request` is the only place the budget is consumed: it
  charges every hop it issues, including the first. A refused hop raises
  `RequestBudgetExhausted` and sends nothing; `ProbeBase._run_guarded` turns
  a refusal during a run into `inconclusive` / ``budget_exhausted``.
  Probes only *peek* (`ProbeBase.budget_available`) to skip a burst early.
- Requests that undo a change (rollbacks) are exempt from the refusal: they
  are still charged, so `remaining` may go negative (the honest overdraft).
- `consume()` is thread-safe (`threading.Lock`) so future parallel
  dispatch cannot double-spend.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


class RequestRefused(RuntimeError):
  """A request was refused (and not sent); `reason` names why (budget_exhausted | target_throttled)."""

  reason = "refused"

  def __init__(self, message=None):
    super().__init__(message or self.reason)


class RequestBudgetExhausted(RequestRefused):
  """A request was refused (and not sent) because the scan budget is spent."""

  reason = "budget_exhausted"


class TargetThrottled(RequestRefused):
  """A request was refused (and not sent) because the target keeps throttling (breaker open)."""

  reason = "target_throttled"


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

  def consume(self, n: int = 1, exempt: bool = False) -> bool:
    """Decrement by ``n`` if available; return False (and bump
    ``exhausted_count``) when the budget can't cover the request.

    ``exempt`` (rollback traffic) always succeeds and still charges, so
    ``remaining`` can go below zero."""
    if n <= 0:
      raise ValueError("RequestBudget.consume requires n > 0")
    with self._lock:
      if exempt:
        self.remaining -= n
        return True
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
