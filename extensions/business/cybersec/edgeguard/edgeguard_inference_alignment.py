"""Queued-result alignment for EdgeGuard inference workers (dependency-free).

Pure logic + a mixin, kept out of ``edgeguard_llm_inference_api.py`` so it can be
unit-tested without importing the full inference/``naeural_core`` plugin stack.

Context: the serving process seeds a ``warmup_request`` placeholder at queue
index 0. During a startup backlog several struct-data inputs drain in one
``BaseInferenceApiPlugin.process()`` iteration, but the base loop pairs the full
input dict with only index-0's inference list, so a real completion landing at a
later index is mis-attributed (this caused EGM-046's 600s generation timeout).
This module re-pairs each input with its own per-model inferences by index —
exactly what the reverted base change (``d3114ff``) did — but scoped to
EdgeGuard workers via the ``EDGEGUARD_LLM_INFERENCE_API`` signature.
"""


def align_inputs_to_inferences(data_by_index, inferences_by_model):
  """Pair every queued struct-data input with its own per-model inferences.

  ``data_by_index`` is ``{int_index: input_data}`` (all queued inputs) and
  ``inferences_by_model`` is ``{model_name: [inference_per_input, ...]}``.
  Returns a list of ``(aligned_inferences, aligned_data)`` groups — one per
  input index — where ``aligned_data`` repeats that input once per model
  inference (matching ``_BaseAgentMixin.handle_inferences``'s positional
  ``data[idx]`` consumption). Returns ``None`` when the shapes are not the
  expected dicts, signalling the caller to fall back to default handling.
  """
  if not (isinstance(data_by_index, dict) and isinstance(inferences_by_model, dict)):
    return None
  groups = []
  for data_index, input_data in data_by_index.items():
    aligned_inferences = [
      model_inferences[data_index]
      for model_inferences in inferences_by_model.values()
      if isinstance(model_inferences, (list, tuple)) and data_index < len(model_inferences)
    ]
    groups.append((aligned_inferences, [input_data] * len(aligned_inferences)))
  return groups


class EdgeGuardAlignmentMixin:
  """Re-aligns inputs to inferences before delegating to the base handler.

  A mixin (composed ahead of ``LLMInferenceApiPlugin`` in the MRO) so the
  override can be unit-tested against a plain recording parent without loading
  the full plugin stack.

  Why ``handle_inferences`` and not ``process()``: ``process()`` is the sole
  caller of ``handle_inferences`` in this hierarchy and also drives capacity /
  mailbox / reconcile / persistence work; overriding it would duplicate ~15
  lines of unrelated orchestration and drift from the base. Overriding
  ``handle_inferences`` re-derives the alignment locally and delegates each
  aligned group to ``super()`` (``_BaseAgentMixin.handle_inferences``).
  """

  def handle_inferences(self, inferences=None, data=None):
    groups = align_inputs_to_inferences(
      self.dataapi_struct_datas(),
      self.dataapi_struct_datas_inferences(),
    )
    if groups is None:
      # Unexpected shape: preserve the base contract with whatever the caller passed.
      return super().handle_inferences(inferences=inferences, data=data)
    for aligned_inferences, aligned_data in groups:
      super().handle_inferences(inferences=aligned_inferences, data=aligned_data)
    return
