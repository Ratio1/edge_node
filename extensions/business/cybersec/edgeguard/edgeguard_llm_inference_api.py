"""EdgeGuard-specific LLM inference plugin.

Isolates the queued-result-alignment fix (previously committed to the shared
``BaseInferenceApiPlugin.process()`` as ``d3114ff``) into an EdgeGuard-owned
subclass, so the shared ``base_inference_api.py`` / ``LLMInferenceApiPlugin``
stay at ``origin/develop`` and only workers pointed at the
``EDGEGUARD_LLM_INFERENCE_API`` signature get the aligned behaviour. The
alignment logic lives in ``edgeguard_inference_alignment`` (dependency-free,
unit-tested); this module just wires it onto the LLM plugin.
"""

from extensions.business.edge_inference_api.llm_inference_api import LLMInferenceApiPlugin as BasePlugin
from extensions.business.cybersec.edgeguard.edgeguard_inference_alignment import EdgeGuardAlignmentMixin


_CONFIG = {
  **BasePlugin.CONFIG,
  "SIGNATURE": "EDGEGUARD_LLM_INFERENCE_API",
  "VALIDATION_RULES": {
    **BasePlugin.CONFIG.get("VALIDATION_RULES", {}),
  },
}


class EdgeGuardLLMInferenceApiPlugin(EdgeGuardAlignmentMixin, BasePlugin):
  """LLM inference plugin for EdgeGuard workers with the queued-result
  alignment fix carried locally (base + shared LLM plugin untouched)."""
  CONFIG = _CONFIG
