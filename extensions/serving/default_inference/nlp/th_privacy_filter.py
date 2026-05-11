"""
Dedicated serving process for `openai/privacy-filter`.

This serving is tailored to the privacy-filter span-detection contract:
- token-classification pipeline
- aggregated entity spans rather than per-token labels
- redaction-friendly post-processing metadata
"""

import json
import math

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
PRIVACY_FILTER_ONNX_RUNTIME_KEY = "onnx_fp32"
PRIVACY_FILTER_ONNX_MODEL_FILE = "onnx/model.onnx"
PRIVACY_FILTER_VITERBI_FILE = "viterbi_calibration.json"


class ThPrivacyFilter(ThHfModelBase):
  CONFIG = _CONFIG

  def _get_hf_onnx_fallback_manifest(self):
    """Declare the public HF ONNX layout when no artifact manifest exists."""
    if self.get_model_name() != "openai/privacy-filter":
      return None
    return {
      "model_key": "openai_privacy_filter",
      "source_repo_id": "openai/privacy-filter",
      "pipeline_task": "token-classification",
      "runtimes": {
        PRIVACY_FILTER_ONNX_RUNTIME_KEY: {
          "runtime": "onnxruntime",
          "entrypoint": "onnxruntime.InferenceSession",
          "pipeline_task": "token-classification",
          "model": PRIVACY_FILTER_ONNX_MODEL_FILE,
          "decoder_type": "privacy_filter_span_decoder",
          "files": [
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
            PRIVACY_FILTER_VITERBI_FILE,
            PRIVACY_FILTER_ONNX_MODEL_FILE,
            "onnx/model.onnx_data",
            "onnx/model.onnx_data_1",
            "onnx/model.onnx_data_2",
          ],
          "recommended_allow_patterns": [
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
            PRIVACY_FILTER_VITERBI_FILE,
            PRIVACY_FILTER_ONNX_MODEL_FILE,
            "onnx/model.onnx_data",
            "onnx/model.onnx_data_1",
            "onnx/model.onnx_data_2",
          ],
          "providers": ["CPUExecutionProvider"],
        },
      },
    }

  def _get_hf_onnx_artifact_schema(self, model_dir, manifest, runtime_config):
    """Build a local schema for the privacy-filter ONNX artifacts."""
    if runtime_config.get("decoder_type") != "privacy_filter_span_decoder":
      return super()._get_hf_onnx_artifact_schema(
        model_dir=model_dir,
        manifest=manifest,
        runtime_config=runtime_config,
      )
    config_path = self._resolve_hf_snapshot_path(model_dir=model_dir, file_path="config.json")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    calibration = {}
    calibration_path = self._resolve_hf_snapshot_path(
      model_dir=model_dir,
      file_path=PRIVACY_FILTER_VITERBI_FILE,
    )
    if calibration_path.exists():
      calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
    return {
      "inputs": [
        {"name": "input_ids", "dtype": "int64"},
        {"name": "attention_mask", "dtype": "int64"},
      ],
      "outputs": [{"name": "logits"}],
      "output_order": ["logits"],
      "id2label": config.get("id2label", {}),
      "tokenizer_kwargs": {"return_offsets_mapping": True},
      "viterbi_calibration": calibration,
    }

  def _get_hf_onnx_artifact_decoder(self, model_dir, manifest, runtime_config):
    """Use the local privacy-filter decoder instead of remote Python code."""
    if runtime_config.get("decoder_type") == "privacy_filter_span_decoder":
      return self._decode_privacy_filter_onnx_outputs
    return super()._get_hf_onnx_artifact_decoder(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
    )

  def _to_plain_list(self, value):
    """Convert tensors/arrays to plain Python lists for decoder logic."""
    if hasattr(value, "tolist"):
      return value.tolist()
    return value

  def _first_batch_item(self, value):
    """Return the first batch element from a tensor-like value."""
    value = self._to_plain_list(value)
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
      return value[0]
    return value

  def _get_tokenizer_field(self, tokenizer_output, field_name):
    if not hasattr(tokenizer_output, "get"):
      return None
    return self._first_batch_item(tokenizer_output.get(field_name))

  def _get_privacy_filter_id2label(self, schema):
    raw_id2label = schema.get("id2label") if isinstance(schema, dict) else None
    if not isinstance(raw_id2label, dict) or len(raw_id2label) == 0:
      raise ValueError("Privacy-filter ONNX schema must provide id2label.")
    labels_by_id = {
      int(label_id): label
      for label_id, label in raw_id2label.items()
    }
    return [
      labels_by_id[idx]
      for idx in range(max(labels_by_id) + 1)
    ]

  def _split_privacy_filter_label(self, label):
    if not isinstance(label, str) or label == "O":
      return "O", None
    if "-" not in label:
      return label, None
    prefix, entity = label.split("-", 1)
    return prefix, entity

  def _get_privacy_filter_transition_biases(self, schema):
    calibration = schema.get("viterbi_calibration") if isinstance(schema, dict) else None
    operating_points = calibration.get("operating_points") if isinstance(calibration, dict) else None
    default_point = operating_points.get("default") if isinstance(operating_points, dict) else None
    biases = default_point.get("biases") if isinstance(default_point, dict) else None
    return biases if isinstance(biases, dict) else {}

  def _privacy_filter_transition_is_valid(self, previous_label, current_label):
    current_prefix, current_entity = self._split_privacy_filter_label(current_label)
    previous_prefix, previous_entity = self._split_privacy_filter_label(previous_label)
    if previous_label is None:
      return current_prefix in {"O", "B", "S"}
    if previous_prefix in {"O", "E", "S"}:
      return current_prefix in {"O", "B", "S"}
    if previous_prefix in {"B", "I"}:
      return current_prefix in {"I", "E"} and current_entity == previous_entity
    return False

  def _privacy_filter_terminal_is_valid(self, label):
    prefix, _entity = self._split_privacy_filter_label(label)
    return prefix in {"O", "E", "S"}

  def _privacy_filter_transition_bias(self, previous_label, current_label, biases):
    if previous_label is None:
      return 0.0
    previous_prefix, previous_entity = self._split_privacy_filter_label(previous_label)
    current_prefix, current_entity = self._split_privacy_filter_label(current_label)
    if previous_prefix == "O" and current_prefix == "O":
      return float(biases.get("transition_bias_background_stay", 0.0))
    if previous_prefix == "O" and current_prefix in {"B", "S"}:
      return float(biases.get("transition_bias_background_to_start", 0.0))
    if previous_prefix in {"E", "S"} and current_prefix == "O":
      return float(biases.get("transition_bias_end_to_background", 0.0))
    if previous_prefix in {"E", "S"} and current_prefix in {"B", "S"}:
      return float(biases.get("transition_bias_end_to_start", 0.0))
    if (
      previous_prefix in {"B", "I"}
      and current_prefix == "I"
      and current_entity == previous_entity
    ):
      return float(biases.get("transition_bias_inside_to_continue", 0.0))
    if (
      previous_prefix in {"B", "I"}
      and current_prefix == "E"
      and current_entity == previous_entity
    ):
      return float(biases.get("transition_bias_inside_to_end", 0.0))
    return 0.0

  def _softmax(self, values):
    if not values:
      return []
    max_value = max(values)
    exps = [math.exp(value - max_value) for value in values]
    total = sum(exps)
    if total == 0:
      return [0.0 for _ in values]
    return [value / total for value in exps]

  def _decode_privacy_filter_label_ids(self, logits, labels, offsets, attention_mask, schema):
    """Run constrained BIOES Viterbi decoding over token logits."""
    o_label_id = labels.index("O") if "O" in labels else 0
    biases = self._get_privacy_filter_transition_biases(schema)
    previous_scores = None
    backpointers = []
    selected_probabilities = []
    probabilities_by_token = []
    invalid_score = -1e9
    for token_idx, token_logits in enumerate(logits):
      token_logits = [float(value) for value in token_logits]
      probabilities_by_token.append(self._softmax(token_logits))
      is_content_token = True
      if attention_mask is not None and token_idx < len(attention_mask):
        is_content_token = bool(attention_mask[token_idx])
      if offsets is not None and token_idx < len(offsets):
        start, end = offsets[token_idx]
        if int(start) == int(end):
          is_content_token = False
      if not is_content_token:
        token_logits = [
          0.0 if label_idx == o_label_id else invalid_score
          for label_idx, _label in enumerate(labels)
        ]
      current_scores = []
      current_backpointers = []
      for label_idx, label in enumerate(labels):
        emission_score = token_logits[label_idx]
        if previous_scores is None:
          if self._privacy_filter_transition_is_valid(None, label):
            current_scores.append(emission_score)
            current_backpointers.append(None)
          else:
            current_scores.append(invalid_score)
            current_backpointers.append(None)
          continue
        best_score = invalid_score
        best_previous_idx = 0
        for previous_idx, previous_label in enumerate(labels):
          if not self._privacy_filter_transition_is_valid(previous_label, label):
            continue
          score = (
            previous_scores[previous_idx]
            + self._privacy_filter_transition_bias(previous_label, label, biases)
            + emission_score
          )
          if score > best_score:
            best_score = score
            best_previous_idx = previous_idx
        current_scores.append(best_score)
        current_backpointers.append(best_previous_idx)
      previous_scores = current_scores
      backpointers.append(current_backpointers)
    if not previous_scores:
      return [], []
    terminal_scores = [
      score if self._privacy_filter_terminal_is_valid(labels[idx]) else invalid_score
      for idx, score in enumerate(previous_scores)
    ]
    if max(terminal_scores) > invalid_score:
      previous_scores = terminal_scores
    best_label_idx = max(range(len(previous_scores)), key=lambda idx: previous_scores[idx])
    label_ids = []
    for token_idx in range(len(backpointers) - 1, -1, -1):
      label_ids.append(best_label_idx)
      previous_idx = backpointers[token_idx][best_label_idx]
      best_label_idx = previous_idx if previous_idx is not None else o_label_id
    label_ids.reverse()
    for token_idx, label_idx in enumerate(label_ids):
      probabilities = probabilities_by_token[token_idx]
      selected_probabilities.append(probabilities[label_idx] if label_idx < len(probabilities) else 0.0)
    return label_ids, selected_probabilities

  def _build_privacy_filter_spans(self, text, labels, label_ids, probabilities, offsets):
    spans = []
    current_span = None
    for token_idx, label_id in enumerate(label_ids):
      if offsets is None or token_idx >= len(offsets):
        continue
      start, end = offsets[token_idx]
      start = int(start)
      end = int(end)
      if start == end:
        continue
      label = labels[label_id]
      prefix, entity = self._split_privacy_filter_label(label)
      token_score = probabilities[token_idx] if token_idx < len(probabilities) else 0.0
      if prefix == "O":
        if current_span is not None:
          spans.append(current_span)
          current_span = None
        continue
      if prefix == "S":
        if current_span is not None:
          spans.append(current_span)
          current_span = None
        spans.append({
          "entity_group": entity,
          "entity": entity,
          "score": token_score,
          "word": text[start:end],
          "start": start,
          "end": end,
        })
        continue
      if prefix == "B" or current_span is None or current_span["entity_group"] != entity:
        if current_span is not None:
          spans.append(current_span)
        current_span = {
          "entity_group": entity,
          "entity": entity,
          "score": token_score,
          "word": text[start:end],
          "start": start,
          "end": end,
          "_scores": [token_score],
        }
        if prefix == "E":
          current_span["_scores"].append(token_score)
          current_span["end"] = end
          current_span["word"] = text[current_span["start"]:current_span["end"]]
          spans.append(current_span)
          current_span = None
        continue
      current_span["end"] = end
      current_span["word"] = text[current_span["start"]:current_span["end"]]
      current_span["_scores"].append(token_score)
      current_span["score"] = sum(current_span["_scores"]) / len(current_span["_scores"])
      if prefix == "E":
        spans.append(current_span)
        current_span = None
    if current_span is not None:
      spans.append(current_span)
    for span in spans:
      span.pop("_scores", None)
    return spans

  def _decode_privacy_filter_onnx_outputs(self, outputs, schema, text=None, tokenizer_output=None, **kwargs):
    """Decode ONNX token logits into privacy-filter span dictionaries."""
    logits = outputs.get("logits") if isinstance(outputs, dict) else None
    if logits is None and isinstance(outputs, dict) and outputs:
      logits = next(iter(outputs.values()))
    logits = self._first_batch_item(logits)
    if not isinstance(logits, list):
      raise ValueError("Privacy-filter ONNX decoder expected logits output.")
    offsets = self._get_tokenizer_field(tokenizer_output, "offset_mapping")
    if offsets is None:
      raise ValueError("Privacy-filter ONNX decoder requires tokenizer offset_mapping.")
    attention_mask = self._get_tokenizer_field(tokenizer_output, "attention_mask")
    labels = self._get_privacy_filter_id2label(schema)
    label_ids, probabilities = self._decode_privacy_filter_label_ids(
      logits=logits,
      labels=labels,
      offsets=offsets,
      attention_mask=attention_mask,
      schema=schema,
    )
    return self._build_privacy_filter_spans(
      text=text or "",
      labels=labels,
      label_ids=label_ids,
      probabilities=probabilities,
      offsets=offsets,
    )

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
      # Fixed-width replacement intentionally avoids leaking original span lengths.
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
