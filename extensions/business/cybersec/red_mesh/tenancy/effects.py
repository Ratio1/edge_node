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

  __slots__ = ("_state", "_on_checkpoint")

  def __init__(self, on_checkpoint=None):
    self._state = EffectState.NONE
    self._on_checkpoint = on_checkpoint

  def checkpoint(self):
    """Revalidate immediately before an irreversible step (contract 4).

    Services call this at each named seam. The callback re-resolves the requester and re-checks
    the job binding, and raises if either has changed since admission -- an account deactivated or
    a rollout closed mid-operation must not get the effect. When no callback is installed (a direct
    internal caller) this is a no-op, so internal paths are unaffected.
    """
    if self._on_checkpoint is not None:
      self._on_checkpoint()

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


# Fields an effect result may publish. A whitelist, not a blacklist: stripping only `error` let
# probe_opencti/probe_taxii's `detail: str(exc)` -- which carries exception prose, the configured
# host and an env var name -- travel to the browser at HTTP 200. get_public_integration_config
# already whitelists; this now matches it.
_PUBLIC_EFFECT_FIELDS = frozenset({
  "status", "dry_run", "job_id", "pass_nr", "integration_id", "bundle_id", "artifact_cid",
  "object_count", "finding_count", "observed_data_count", "destination_label", "schema_version",
  "generated_at", "persisted", "configuration_error",
})

_PUBLIC_CONFIGURATION_ERRORS = frozenset({
  "missing_hmac_secret", "missing_syslog_host", "missing_http_url",
  "missing_token", "missing_credentials", "invalid_auth_config",
})


def public_effect_result(result):
  """Publish only whitelisted fields, and never the framework's `error` key.

  The plugin framework maps any returned dict carrying `error` to HTTP 503, so an ordinary
  "integration disabled" outcome would reach the caller as a server failure. Typed configuration
  codes travel as `configuration_error`, validated against the same set the readiness view uses;
  anything else is dropped rather than published as prose.
  """
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
  projected = {key: value for key, value in result.items() if key in _PUBLIC_EFFECT_FIELDS}
  if isinstance(error, str):
    projected["configuration_error"] = error if error in _PUBLIC_CONFIGURATION_ERRORS else None
    if projected["configuration_error"] is None:
      # An outcome we cannot type must not be published as success with no reason.
      projected["status"] = "error"
  return projected
