"""The effect ledger and _effect_operation: contract 6 of RM-026 I1b.

`_read_operation` ends in a blanket `except Exception -> 503 unavailable`. For a read that is
correct. For an effect it asserts "nothing happened" about an operation that may have already
persisted a bundle or delivered it off-node. These tests pin the distinction, and in particular
that the state is observable **when the service raises** -- the case the whole mechanism exists
for, and the one a return-value-carried state cannot express.
"""
import pytest

from extensions.business.cybersec.red_mesh.tenancy.effects import (
  EffectLedger, EffectState, classify_effect_failure,
)


def test_a_fresh_ledger_has_landed_nothing():
  assert EffectLedger().state is EffectState.NONE


def test_states_advance_and_never_regress():
  ledger = EffectLedger()
  ledger.record(EffectState.PERSISTED)
  assert ledger.state is EffectState.PERSISTED
  # A later weaker record must not erase a stronger one: once a bundle is on disk,
  # a subsequent "nothing happened" is a lie.
  ledger.record(EffectState.NONE)
  assert ledger.state is EffectState.PERSISTED
  ledger.record(EffectState.DELIVERED)
  assert ledger.state is EffectState.DELIVERED
  ledger.record(EffectState.PERSISTED)
  assert ledger.state is EffectState.DELIVERED


def test_the_ledger_is_readable_after_the_service_raises():
  """The load-bearing property: a return value cannot carry state out of a raise."""
  ledger = EffectLedger()

  def service(ledger):
    ledger.record(EffectState.PERSISTED)
    raise RuntimeError("outbound failed after the bundle landed")

  with pytest.raises(RuntimeError):
    service(ledger)
  assert ledger.state is EffectState.PERSISTED


def test_nothing_landed_is_the_only_safe_unavailable():
  assert classify_effect_failure(EffectState.NONE) == {
    "success": False, "error": "unavailable", "status_code": 503}


@pytest.mark.parametrize("state", (EffectState.PERSISTED, EffectState.DELIVERED))
def test_a_landed_effect_is_never_reported_as_unavailable(state):
  result = classify_effect_failure(state)
  assert result["error"] == "effect_incomplete"
  assert result["status_code"] == 500
  assert result["effect_state"] == state.value
  # 503 invites a retry; a retry after a landed effect duplicates it.
  assert result["status_code"] != 503


def test_classification_carries_no_detail_beyond_the_state():
  for state in EffectState:
    assert set(classify_effect_failure(state)) <= {
      "success", "error", "status_code", "effect_state"}
