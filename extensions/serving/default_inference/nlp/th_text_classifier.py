"""
Generic Transformers-native text-classifier serving process.

The model is loaded directly from Hugging Face through the Transformers
pipeline API. This keeps the serving surface minimal and makes custom
remote-code models usable by specifying only the Hugging Face model id.
"""

from extensions.serving.default_inference.nlp.th_hf_model_base import (
  _CONFIG as BASE_HF_MODEL_CONFIG,
  ThHfModelBase,
)


__VER__ = "0.1.0"


_CONFIG = {
  **BASE_HF_MODEL_CONFIG,
  "EXPECTED_AI_ENGINES": ["text_classifier"],
  "VALIDATION_RULES": {
    **BASE_HF_MODEL_CONFIG["VALIDATION_RULES"],
  },
}


class ThTextClassifier(ThHfModelBase):
  CONFIG = _CONFIG

  def _extract_struct_payload(self, payload):
    """Extract the structured payload used by the classifier.

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
      raise ValueError("Text-classifier serving expects STRUCT_DATA to be a dictionary payload.")
    keys = self.cfg_text_keys or []
    for key in keys:
      value = struct_payload.get(key)
      if isinstance(value, str) and len(value.strip()) > 0:
        return value.strip(), struct_payload
    raise ValueError(f"Could not find any non-empty text field in STRUCT_DATA. Checked keys: {keys}")

  def _prepare_payloads(self, inputs):
    """Prepare serving payloads and mark irrelevant inputs as ignored.

    Parameters
    ----------
    inputs : dict
        Serving-process input dictionary containing the `DATA` payload list.

    Returns
    -------
    list[dict]
        Prepared payload descriptors. Invalid or non-targeted payloads are kept
        in position with `ignored=True` so output cardinality remains stable.

    Notes
    -----
    TODO: better check if a payload is not relevant.
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
        self.P(f"[ThTextClassifier] Skipping invalid payload: {exc}", color="r")
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
    """Prepare raw serving inputs for model inference.

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
    """Run text classification for all non-ignored payloads.

    Parameters
    ----------
    preprocessed_inputs : list[dict] or None
        Payload descriptors produced by `pre_process`.

    Returns
    -------
    dict or None
        Dictionary with original payload descriptors and raw model outputs, or
        `None` when there is no work to run.

    Notes
    -----
    Some custom remote-code pipelines are not robust to batched `list[str]`
    calls but still work for single-text inference. Those failures fall back to
    sequential execution rather than crashing the serving process.
    """
    if preprocessed_inputs is None:
      return None
    texts = [item["text"] for item in preprocessed_inputs if not item.get("ignored")]
    inference_kwargs = {
      "truncation": True,
      "max_length": self.cfg_max_length,
      **dict(self.cfg_inference_kwargs or {}),
    }
    outputs = []
    if texts:
      try:
        outputs = self.classifier(texts, **inference_kwargs)
      except AttributeError as exc:
        if "framework" not in str(exc):
          raise
        outputs = [
          self.classifier(text, **inference_kwargs)
          for text in texts
        ]
    return {
      "payloads": preprocessed_inputs,
      "outputs": outputs,
    }

  def _normalize_outputs(self, outputs, expected_count):
    """Normalize model outputs to one output per active payload.

    Parameters
    ----------
    outputs : Any
        Raw pipeline output.
    expected_count : int
        Number of non-ignored payloads.

    Returns
    -------
    list
        Output list with length equal to `expected_count`.

    Raises
    ------
    ValueError
        If the pipeline output cardinality does not match the active payload
        count.
    """
    if expected_count == 0:
      return []
    if expected_count == 1:
      return [outputs]
    if isinstance(outputs, list):
      if len(outputs) != expected_count:
        raise ValueError(
          f"Pipeline returned {len(outputs)} outputs for {expected_count} payloads."
        )
      return outputs
    raise ValueError(
      f"Pipeline returned a scalar output for {expected_count} payloads."
    )

  def _default_decode_outputs(self, outputs, payloads):
    """Decode raw model outputs into the serving response contract.

    Parameters
    ----------
    outputs : Any
        Raw pipeline output.
    payloads : list[dict]
        Prepared payload descriptors, including ignored placeholders.

    Returns
    -------
    list
        Decoded results aligned with the prepared payload list.
    """
    active_payloads = [payload_info for payload_info in payloads if not payload_info.get("ignored")]
    normalized_outputs = self._normalize_outputs(outputs, len(active_payloads))
    output_iter = iter(normalized_outputs)
    decoded = []
    additional_metadata = self.get_additional_metadata()
    for payload_info in payloads:
      if payload_info.get("ignored"):
        decoded.append([])
        continue
      model_output = next(output_iter)
      serving_target = None
      if isinstance(payload_info.get("struct_payload"), dict):
        serving_target = payload_info["struct_payload"].get("__SERVING_TARGET__")
      decoded.append({
        "REQUEST_ID": payload_info["request_id"],
        "TEXT": payload_info["text"],
        "result": model_output,
        "SERVING_TARGET": serving_target,
        **additional_metadata,
      })
    return decoded

  def post_process(self, predictions):
    """Convert model predictions into serving-process outputs.

    Parameters
    ----------
    predictions : dict or None
        Prediction dictionary returned by `predict`.

    Returns
    -------
    list
        Serving-process output list.
    """
    if not predictions:
      return []
    return self._default_decode_outputs(
      outputs=predictions["outputs"],
      payloads=predictions["payloads"],
    )
