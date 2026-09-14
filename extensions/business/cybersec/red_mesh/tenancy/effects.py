"""Effect state for operations that change something (RM-026 I1b, contract 6).

`_read_operation` ends in a blanket `except Exception -> 503 unavailable`. That is correct for a
read: if the read failed, nothing happened. It is wrong for an effect, because `unavailable` claims
nothing happened about an operation that may have already written a bundle to R1FS or delivered it
to a third-party system. A caller that reads `unavailable` and retries would duplicate the effect.

The state cannot ride the return value: a service that raises after persisting returns nothing, and
the wrapper would see only the exception -- precisely the case this exists for. So the ledger is
passed *into* the service and mutated as effects land, and stays readable after a raise.
"""
from __future__ import annotations

from enum import Enum


class EffectState(Enum):
  """What has irreversibly happened so far. Ordered weakest to strongest."""

  NONE = "none"
  PERSISTED = "persisted"
  DELIVERED = "delivered"


_RANK = {EffectState.NONE: 0, EffectState.PERSISTED: 1, EffectState.DELIVERED: 2}


class EffectLedger:
  """Records landed effects. Monotonic: a state is never downgraded.

  Downgrading would let a late "nothing happened" erase the memory of a bundle already on disk,
  which is the exact falsehood this type exists to prevent.
  """

  __slots__ = ("_state",)

  def __init__(self):
    self._state = EffectState.NONE

  @property
  def state(self) -> EffectState:
    return self._state

  def record(self, state: EffectState) -> None:
    if not isinstance(state, EffectState):
      raise TypeError("effect state must be an EffectState")
    if _RANK[state] > _RANK[self._state]:
      self._state = state


def classify_effect_failure(state: EffectState) -> dict:
  """Map a failed effect to a response that does not lie about what happened.

  Only NONE may report `unavailable`, because only NONE means the operation left no trace.
  Anything else returns a distinct typed error so a caller does not blindly retry into a
  duplicate. The state is the only detail published: no exception text, no identifiers.
  """
  if not isinstance(state, EffectState):
    raise TypeError("effect state must be an EffectState")
  if state is EffectState.NONE:
    return {"success": False, "error": "unavailable", "status_code": 503}
  return {
    "success": False,
    "error": "effect_incomplete",
    "effect_state": state.value,
    "status_code": 500,
  }
