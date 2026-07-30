"""Tests for the EdgeGuard-isolated queued-result-alignment fix.

Mirrors the scenario the shared-base test used before the fix was moved out of
``BaseInferenceApiPlugin.process()``: a startup backlog where an empty
``warmup_request`` placeholder occupies input index 0 and a real completion
lands at index 1. The alignment must attribute each completion to its own
input.
"""
import unittest

from extensions.business.cybersec.edgeguard.edgeguard_inference_alignment import (
  align_inputs_to_inferences,
  EdgeGuardAlignmentMixin as _EdgeGuardAlignmentMixin,
)


class AlignInputsToInferencesTests(unittest.TestCase):
  def test_backlog_pairs_each_input_with_its_own_inference(self):
    data_by_index = {
      0: {"slot": "startup-placeholder"},
      1: {"slot": "completed-request"},
    }
    inferences_by_model = {
      "engine": [
        {"IS_VALID": False, "text": ""},
        {"IS_VALID": True, "REQUEST_ID": "req-live", "text": "MATCH (n) RETURN n"},
      ],
    }
    groups = align_inputs_to_inferences(data_by_index, inferences_by_model)
    self.assertEqual(len(groups), 2)
    # index 0 -> placeholder input paired with the invalid index-0 inference
    self.assertEqual(groups[0][0][0]["IS_VALID"], False)
    self.assertEqual(groups[0][1], [{"slot": "startup-placeholder"}])
    # index 1 -> completed input paired with the real index-1 completion
    self.assertEqual(groups[1][0][0]["REQUEST_ID"], "req-live")
    self.assertEqual(groups[1][1], [{"slot": "completed-request"}])

  def test_multiple_models_are_aligned_per_input(self):
    groups = align_inputs_to_inferences(
      {0: {"in": "a"}, 1: {"in": "b"}},
      {"m1": [{"i": "a1"}, {"i": "b1"}], "m2": [{"i": "a2"}, {"i": "b2"}]},
    )
    self.assertEqual(groups[0][0], [{"i": "a1"}, {"i": "a2"}])
    self.assertEqual(groups[0][1], [{"in": "a"}, {"in": "a"}])
    self.assertEqual(groups[1][0], [{"i": "b1"}, {"i": "b2"}])

  def test_missing_inference_for_an_input_is_skipped_not_misaligned(self):
    # A model that only produced index 0 must not lend it to input index 1.
    groups = align_inputs_to_inferences(
      {0: {"in": "a"}, 1: {"in": "b"}},
      {"m1": [{"i": "a1"}]},
    )
    self.assertEqual(groups[0][0], [{"i": "a1"}])
    self.assertEqual(groups[1][0], [])  # no inference for index 1 -> empty, not "a1"

  def test_unexpected_shapes_signal_fallback(self):
    self.assertIsNone(align_inputs_to_inferences([], []))
    self.assertIsNone(align_inputs_to_inferences({0: {}}, ["not-a-dict"]))


class _Recorder:
  """Stands in for the base ``handle_inferences`` (mixin) in the MRO."""

  def __init__(self):
    self.calls = []

  def handle_inferences(self, inferences=None, data=None):
    self.calls.append((inferences, data))


class _Subject(_EdgeGuardAlignmentMixin, _Recorder):
  def __init__(self, datas, infs):
    _Recorder.__init__(self)
    self._datas = datas
    self._infs = infs

  def dataapi_struct_datas(self):
    return self._datas

  def dataapi_struct_datas_inferences(self):
    return self._infs


class HandleInferencesOverrideTests(unittest.TestCase):
  def test_override_delegates_one_aligned_super_call_per_input(self):
    subject = _Subject(
      {0: {"slot": "placeholder"}, 1: {"slot": "live"}},
      {"engine": [{"IS_VALID": False}, {"IS_VALID": True, "REQUEST_ID": "req-live"}]},
    )
    # base.process() would pass the misaligned args; the override ignores them.
    subject.handle_inferences(inferences=[{"IS_VALID": False}], data={0: {}, 1: {}})
    self.assertEqual(len(subject.calls), 2)
    self.assertEqual(subject.calls[0], ([{"IS_VALID": False}], [{"slot": "placeholder"}]))
    self.assertEqual(subject.calls[1][0][0]["REQUEST_ID"], "req-live")
    self.assertEqual(subject.calls[1][1], [{"slot": "live"}])

  def test_override_falls_back_when_shapes_unexpected(self):
    subject = _Subject([], [])
    subject.handle_inferences(inferences=[{"x": 1}], data=[{"y": 2}])
    self.assertEqual(subject.calls, [([{"x": 1}], [{"y": 2}])])


if __name__ == "__main__":
  unittest.main()
