"""
PRIVACY_FILTER_INFERENCE_API Plugin

Dedicated inference API for the `openai/privacy-filter` model.

This plugin reuses the generic text-classifier request lifecycle and validation,
but exposes a dedicated engine binding and a privacy-filter specific result
shape for token/span findings.
"""

from typing import Any, Dict

from extensions.business.edge_inference_api.text_classifier_inference_api import (
  _CONFIG as BASE_TEXT_CLASSIFIER_CONFIG,
  TextClassifierInferenceApiPlugin,
)


__VER__ = "0.1.0"


_CONFIG = {
  **BASE_TEXT_CLASSIFIER_CONFIG,
  "AI_ENGINE": "privacy_filter",
  "API_TITLE": "Privacy Filter Inference API",
  "API_SUMMARY": "Local privacy-filter API for sensitive span detection.",
}


class PrivacyFilterInferenceApiPlugin(TextClassifierInferenceApiPlugin):
  CONFIG = _CONFIG

  def _build_result_from_inference(  # pylint: disable=arguments-differ
    self,
    request_id: str,
    inference: Dict[str, Any],
    metadata: Dict[str, Any],
    request_data: Dict[str, Any],
  ):
    """Build the public privacy-filter response from serving output.

    Parameters
    ----------
    request_id : str
      API request identifier.
    inference : dict
      Serving output payload.
    metadata : dict
      Request metadata supplied by the caller.
    request_data : dict
      Persisted request state.

    Returns
    -------
    dict
      Completed privacy-filter response containing findings and optional
      redacted/censored text fields.

    Raises
    ------
    ValueError
      If no inference result is available.
    """
    if inference is None:
      raise ValueError("No inference result available.")
    if not isinstance(inference, dict):
      return {
        "status": "completed",
        "request_id": request_id,
        "text": request_data.get("parameters", {}).get("text"),
        "findings": inference,
        "metadata": metadata or request_data.get("metadata") or {},
      }

    model_output = inference.get("result", inference)
    text = inference.get("TEXT", request_data.get("parameters", {}).get("text"))
    result_payload = {
      "status": "completed",
      "request_id": request_id,
      "text": text,
      "findings": model_output,
      "metadata": metadata or request_data.get("metadata") or {},
    }
    if "REDACTED_TEXT" in inference:
      result_payload["redacted_text"] = inference["REDACTED_TEXT"]
    if "CENSORED_TEXT" in inference:
      result_payload["censored_text"] = inference["CENSORED_TEXT"]
    if "DETECTED_ENTITY_GROUPS" in inference:
      result_payload["detected_entity_groups"] = inference["DETECTED_ENTITY_GROUPS"]
    if "FINDINGS_COUNT" in inference:
      result_payload["findings_count"] = inference["FINDINGS_COUNT"]
    if "MODEL_NAME" in inference:
      result_payload["model_name"] = inference["MODEL_NAME"]
    if "TOKENIZER_NAME" in inference:
      result_payload["tokenizer_name"] = inference["TOKENIZER_NAME"]
    if "PIPELINE_TASK" in inference:
      result_payload["pipeline_task"] = inference["PIPELINE_TASK"]
    return result_payload
