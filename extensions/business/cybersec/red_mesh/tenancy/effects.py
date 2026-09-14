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


# Public projection for effect results (RM-026 I1b).
#
# The plugin framework treats any returned dict carrying an `error` key as a plugin error and maps
# it to HTTP 503, so a perfectly ordinary "this integration is disabled" outcome would reach the
# caller as a server failure. `export_misp_json` already avoids this by returning a bare
# {"status": "disabled"}. These effects do the same, and carry configuration codes under
# `configuration_error` -- the same field name the integration readiness view uses -- so a typed
# code is still available without colliding with the framework's error convention.

_EFFECT_DENIALS = {
  "job_not_found": (404, "not_found"),
  "unsupported_job_type": (400, "unsupported_job_type"),
}


def public_effect_result(result):
  """Strip prose and avoid the framework's `error` convention, preserving the outcome."""
  if not isinstance(result, dict):
    return {"success": False, "error": "unavailable", "status_code": 503}
  # Already a typed denial from the admission layer: pass through untouched.
  if result.get("success") is False and "status_code" in result:
    return result
  status = result.get("status")
  error = result.get("error")
  if status == "disabled":
    return {"status": "disabled"}
  if isinstance(error, str) and error in _EFFECT_DENIALS:
    status_code, code = _EFFECT_DENIALS[error]
    return {"success": False, "error": code, "status_code": status_code}
  projected = {key: value for key, value in result.items() if key != "error"}
  if status == "not_configured" and isinstance(error, str):
    projected["configuration_error"] = error
  elif isinstance(error, str) and status not in (None, "ok", "dry_run"):
    # An unexpected outcome string must not travel as prose.
    projected["configuration_error"] = None
    projected["status"] = "error"
  return projected
