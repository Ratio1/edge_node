"""
Dedicated serving process for `openai/privacy-filter`.

This serving is tailored to the privacy-filter span-detection contract:
- token-classification pipeline
- aggregated entity spans rather than per-token labels
- redaction-friendly post-processing metadata
"""

from extensions.serving.default_inference.nlp.th_hf_model_base import (
  _CONFIG as BASE_HF_MODEL_CONFIG,
  ThHfModelBase,
)


__VER__ = "0.1.0"


_CONFIG = {
  **BASE_HF_MODEL_CONFIG,
  "MODEL_NAME": "openai/privacy-filter",
  "PIPELINE_TASK": "token-classification",
  "TRUST_REMOTE_CODE": False,
  "EXPECTED_AI_ENGINES": ["privacy_filter"],
  "MAX_LENGTH": None,
  "INFERENCE_KWARGS": {
    "aggregation_strategy": "simple",
  },
}


FIXED_CENSOR_SIZE = 4


class ThPrivacyFilter(ThHfModelBase):
  CONFIG = _CONFIG

  def _extract_struct_payload(self, payload):
    """Extract the structured payload used by the privacy filter.

    Parameters
    ----------
    payload : dict or Any
        Raw serving payload.

    Returns
    -------
    dict or None
        Structured payload dictionary, or `None` when the payload cannot be
        interpreted.
    """
    if not isinstance(payload, dict):
      return None
    struct_payload = payload.get(self.cfg_picked_input)
    if isinstance(struct_payload, list) and len(struct_payload) == 1 and isinstance(struct_payload[0], dict):
      return struct_payload[0]
    if isinstance(struct_payload, dict):
      return struct_payload
    return payload if isinstance(payload, dict) else None

  def _extract_request_id(self, payload, struct_payload):
    """Extract the request id from structured or raw payload data.

    Parameters
    ----------
    payload : dict or Any
        Raw serving payload.
    struct_payload : dict or Any
        Structured payload extracted from the raw payload.

    Returns
    -------
    Any or None
        First configured request id value found in either map.
    """
    candidate_maps = [struct_payload, payload]
    keys = self.cfg_request_id_keys or []
    for data in candidate_maps:
      if not isinstance(data, dict):
        continue
      for key in keys:
        if key in data and data[key] is not None:
          return data[key]
    return None

  def _extract_text(self, payload):
    """Extract text input from a serving payload.

    Parameters
    ----------
    payload : dict or Any
        Raw serving payload.

    Returns
    -------
    tuple[str, dict]
        Trimmed text and the structured payload that contained it.

    Raises
    ------
    ValueError
        If no structured payload or non-empty text field is available.
    """
    struct_payload = self._extract_struct_payload(payload)
    if not isinstance(struct_payload, dict):
      raise ValueError("Privacy-filter serving expects STRUCT_DATA to be a dictionary payload.")
    keys = self.cfg_text_keys or []
    for key in keys:
      value = struct_payload.get(key)
      if isinstance(value, str) and len(value.strip()) > 0:
        return value.strip(), struct_payload
    raise ValueError(f"Could not find any non-empty text field in STRUCT_DATA. Checked keys: {keys}")

  def _prepare_payloads(self, inputs):
    """Prepare privacy-filter payloads and preserve ignored positions.

    Parameters
    ----------
    inputs : dict
        Serving-process input dictionary containing the `DATA` payload list.

    Returns
    -------
    list[dict]
        Prepared payload descriptors. Invalid or non-targeted payloads are kept
        in position with `ignored=True` so output cardinality remains stable.
    """
    payloads = inputs.get("DATA", [])
    prepared_payloads = []
    for payload in payloads:
      struct_payload = self._extract_struct_payload(payload)
      if not self._payload_matches_current_serving(struct_payload):
        prepared_payloads.append({
          "payload": payload,
          "struct_payload": struct_payload,
          "ignored": True,
        })
        continue
      try:
        text, struct_payload = self._extract_text(payload)
      except Exception as exc:
        self.P(f"[ThPrivacyFilter] Skipping invalid payload: {exc}", color="r")
        prepared_payloads.append({
          "payload": payload,
          "struct_payload": struct_payload,
          "ignored": True,
          "error": str(exc),
        })
        continue
      prepared_payloads.append({
        "payload": payload,
        "struct_payload": struct_payload,
        "text": text,
        "request_id": self._extract_request_id(payload=payload, struct_payload=struct_payload),
        "ignored": False,
      })
    return prepared_payloads

  def pre_process(self, inputs):
    """Prepare raw serving inputs for privacy-filter inference.

    Parameters
    ----------
    inputs : dict
        Raw serving inputs.

    Returns
    -------
    list[dict] or None
        Prepared payload descriptors, or `None` when no payloads were provided.
    """
    prepared_payloads = self._prepare_payloads(inputs)
    if not prepared_payloads:
      return None
    return prepared_payloads

  def predict(self, preprocessed_inputs):
    """Run privacy span detection for all non-ignored payloads.

    Parameters
    ----------
    preprocessed_inputs : list[dict] or None
        Payload descriptors produced by `pre_process`.

    Returns
    -------
    dict or None
        Dictionary with original payload descriptors and raw model outputs, or
        `None` when there is no work to run.
    """
    if preprocessed_inputs is None:
      return None
    texts = [item["text"] for item in preprocessed_inputs if not item.get("ignored")]
    inference_kwargs = dict(self.cfg_inference_kwargs or {})
    if self.cfg_max_length is not None:
      inference_kwargs = {
        "truncation": True,
        "max_length": self.cfg_max_length,
        **inference_kwargs,
      }
    outputs = [] if not texts else self.classifier(texts, **inference_kwargs)
    return {
      "payloads": preprocessed_inputs,
      "outputs": outputs,
    }

  def _is_privacy_span(self, item):
    """Return whether an item looks like a privacy-filter span.

    Parameters
    ----------
    item : Any
        Candidate pipeline output item.

    Returns
    -------
    bool
        `True` when the item has common span fields emitted by
        token-classification pipelines.
    """
    return isinstance(item, dict) and any(
      key in item for key in ("entity_group", "entity", "start", "end", "score", "word")
    )

  def _normalize_outputs(self, outputs, expected_count):
    """Normalize privacy-filter outputs to one list per active payload.

    Parameters
    ----------
    outputs : Any
        Raw token-classification pipeline output.
    expected_count : int
        Number of non-ignored payloads.

    Returns
    -------
    list
        Output list aligned with active payloads.

    Raises
    ------
    ValueError
        If the pipeline output cardinality does not match the active payload
        count.
    """
    if expected_count == 0:
      return []
    if expected_count == 1:
      if isinstance(outputs, list):
        if len(outputs) == 0:
          return [[]]
        if all(self._is_privacy_span(item) for item in outputs):
          return [outputs]
        if len(outputs) == 1 and isinstance(outputs[0], list):
          return outputs
      return [outputs]
    if not isinstance(outputs, list):
      raise ValueError(
        f"Privacy-filter pipeline returned a scalar output for {expected_count} payloads."
      )
    if len(outputs) != expected_count:
      raise ValueError(
        f"Privacy-filter pipeline returned {len(outputs)} outputs for {expected_count} payloads."
      )
    return outputs

  def _extract_span_label(self, span):
    """Extract the entity label from a privacy span.

    Parameters
    ----------
    span : dict or Any
        Privacy span emitted by the pipeline.

    Returns
    -------
    str or None
        Entity group or entity label.
    """
    if not isinstance(span, dict):
      return None
    return span.get("entity_group") or span.get("entity")

  def _redact_text(self, text, findings):
    """Replace detected spans with entity-label placeholders.

    Parameters
    ----------
    text : str
        Original input text.
    findings : list
        Privacy spans containing `start` and `end` offsets.

    Returns
    -------
    str
        Redacted text. Invalid spans are ignored.
    """
    if not isinstance(text, str) or not isinstance(findings, list) or len(findings) == 0:
      return text
    redacted = text
    sortable_findings = [
      span for span in findings
      if isinstance(span, dict)
      and isinstance(span.get("start"), int)
      and isinstance(span.get("end"), int)
      and span["start"] >= 0
      and span["end"] >= span["start"]
    ]
    for span in sorted(sortable_findings, key=lambda item: item["start"], reverse=True):
      label = self._extract_span_label(span) or "redacted"
      placeholder = f"[{str(label).upper()}]"
      redacted = redacted[:span["start"]] + placeholder + redacted[span["end"]:]
    return redacted

  def _censor_text(self, text, findings):
    """Replace detected spans with fixed-width censor markers.

    Parameters
    ----------
    text : str
        Original input text.
    findings : list
        Privacy spans containing `start` and `end` offsets.

    Returns
    -------
    str
        Censored text. Invalid spans are ignored.
    """
    if not isinstance(text, str) or not isinstance(findings, list) or len(findings) == 0:
      return text
    censored = text
    sortable_findings = [
      span for span in findings
      if isinstance(span, dict)
      and isinstance(span.get("start"), int)
      and isinstance(span.get("end"), int)
      and span["start"] >= 0
      and span["end"] >= span["start"]
    ]
    for span in sorted(sortable_findings, key=lambda item: item["start"], reverse=True):
      replacement = "*" * FIXED_CENSOR_SIZE
      censored = censored[:span["start"]] + replacement + censored[span["end"]:]
    return censored

  def post_process(self, predictions):
    """Convert privacy-filter predictions into serving-process outputs.

    Parameters
    ----------
    predictions : dict or None
        Prediction dictionary returned by `predict`.

    Returns
    -------
    list
        Serving-process output list containing findings, redacted text,
        censored text, and detected entity labels.
    """
    if not predictions:
      return []
    active_payloads = [payload_info for payload_info in predictions["payloads"] if not payload_info.get("ignored")]
    normalized_outputs = self._normalize_outputs(
      outputs=predictions["outputs"],
      expected_count=len(active_payloads),
    )
    output_iter = iter(normalized_outputs)
    decoded = []
    additional_metadata = self.get_additional_metadata()
    for payload_info in predictions["payloads"]:
      if payload_info.get("ignored"):
        decoded.append([])
        continue
      findings = next(output_iter)
      findings = findings if isinstance(findings, list) else [findings]
      detected_labels = []
      serving_target = None
      if isinstance(payload_info.get("struct_payload"), dict):
        serving_target = payload_info["struct_payload"].get("__SERVING_TARGET__")
      for span in findings:
        label = self._extract_span_label(span)
        if label is not None and label not in detected_labels:
          detected_labels.append(label)
      decoded.append({
        "REQUEST_ID": payload_info["request_id"],
        "TEXT": payload_info["text"],
        "result": findings,
        "SERVING_TARGET": serving_target,
        "REDACTED_TEXT": self._redact_text(payload_info["text"], findings),
        "CENSORED_TEXT": self._censor_text(payload_info["text"], findings),
        "DETECTED_ENTITY_GROUPS": detected_labels,
        "FINDINGS_COUNT": len(findings),
        **additional_metadata,
      })
    return decoded
