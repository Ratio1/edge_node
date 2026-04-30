"""
TEXT_CLASSIFIER_INFERENCE_API Plugin

Production-Grade Text Classification Inference API

This plugin exposes a hardened, FastAPI-powered interface for generic text
classification workloads. It reuses the BaseInferenceApi request lifecycle
while tailoring validation and response shaping for text inputs.

Highlights
- Loopback-only surface paired with local clients
- Request tracking, persistence, auth, and rate limiting from BaseInferenceApi
- Generic text payload validation and metadata normalization
- Balanced execution support through BaseInferenceApi
- Raw classifier output preserved in the final response payload
"""

from typing import Any, Dict, Optional

from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin


__VER__ = "0.1.0"


_CONFIG = {
  **BasePlugin.CONFIG,
  "AI_ENGINE": "text_classifier",
  "API_TITLE": "Text Classifier Inference API",
  "API_SUMMARY": "Local text classification API for paired clients.",
  "REQUEST_TIMEOUT": 240,
  "MIN_TEXT_LENGTH": 1,

  "VALIDATION_RULES": {
    **BasePlugin.CONFIG["VALIDATION_RULES"],
    "MIN_TEXT_LENGTH": {
      "DESCRIPTION": "Minimum input text length after trimming whitespace.",
      "TYPE": "int",
      "MIN_VAL": 1,
      "MAX_VAL": 100000,
    },
    "REQUEST_TIMEOUT": {
      "DESCRIPTION": "Timeout for PostponedRequest polling (seconds)",
      "TYPE": "int",
      "MIN_VAL": 30,
      "MAX_VAL": 600,
    },
  },
}


class TextClassifierInferenceApiPlugin(BasePlugin):
  CONFIG = _CONFIG

  def _get_startup_ai_engine_params(self):
    """Return startup parameters configured for the paired serving engine.

    Returns
    -------
    dict
      Startup AI engine parameters, or an empty dict when unset/invalid.
    """
    params = getattr(self, "cfg_startup_ai_engine_params", None)
    return params if isinstance(params, dict) else {}

  def _build_serving_target(self):
    """Build serving-target metadata for loopback payload routing.

    Returns
    -------
    dict
      Target metadata containing the AI engine and optional model instance or
      model name constraints.
    """
    startup_params = self._get_startup_ai_engine_params()
    target = {
      "INFERENCE_REQUEST": True,
      "AI_ENGINE": self.cfg_ai_engine,
    }
    if startup_params.get("MODEL_INSTANCE_ID") is not None:
      target["MODEL_INSTANCE_ID"] = startup_params["MODEL_INSTANCE_ID"]
    if startup_params.get("MODEL_NAME") is not None:
      target["MODEL_NAME"] = startup_params["MODEL_NAME"]
    return target

  """VALIDATION"""
  if True:
    def check_predict_params(
      self,
      text: str,
      metadata: Optional[Dict[str, Any]] = None,
      **kwargs
    ):
      """
      Validate input parameters for text-classification requests.

      Parameters
      ----------
      text : str
        Raw text to classify.
      metadata : dict or None, optional
        Optional metadata accompanying the request.
      **kwargs
        Additional parameters ignored by validation.

      Returns
      -------
      str or None
        Error message when validation fails, otherwise None.
      """
      if not isinstance(text, str) or len(text.strip()) < self.cfg_min_text_length:
        return (
          "Invalid or missing text. "
          f"Expecting non-empty content with at least {self.cfg_min_text_length} character(s)."
        )
      if metadata is not None and not isinstance(metadata, dict):
        return "`metadata` must be a dictionary when provided."
      return None

    def process_predict_params(
      self,
      text: str,
      metadata: Optional[Dict[str, Any]] = None,
      **kwargs
    ):
      """
      Normalize and forward parameters for request registration.

      Parameters
      ----------
      text : str
        Raw text to classify.
      metadata : dict or None, optional
        Optional metadata accompanying the request.
      **kwargs
        Additional parameters to propagate downstream.

      Returns
      -------
      dict
        Processed parameters ready for dispatch to the inference engine.
      """
      cleaned_metadata = metadata or {}
      return {
        "text": text.strip(),
        "metadata": cleaned_metadata,
        "request_type": "classification",
        **{k: v for k, v in kwargs.items() if k != "metadata"},
      }

    def compute_payload_kwargs_from_predict_params(
      self,
      request_id: str,
      request_data: Dict[str, Any],
    ):
      """
      Build payload keyword arguments for text-classification inference.

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      request_data : dict
        Stored request record containing processed parameters.

      Returns
      -------
      dict
        Payload fields including text, metadata, and submission info.
      """
      params = request_data["parameters"]
      submitted_at = request_data["created_at"]
      metadata = params.get("metadata") or request_data.get("metadata") or {}
      struct_payload = {
        "text": params["text"],
        "request_id": request_id,
        "metadata": metadata,
        "__SERVING_TARGET__": self._build_serving_target(),
      }
      return {
        "request_id": request_id,
        "metadata": metadata,
        "type": params.get("request_type", "classification"),
        "submitted_at": submitted_at,
        "STRUCT_DATA": struct_payload,
      }
  """END VALIDATION"""

  """API ENDPOINTS"""
  if True:
    @BasePlugin.endpoint(method="GET")
    def list_results(self, limit: int = 50, include_pending: bool = False):
      """
      List recent request results with optional pending entries.

      Parameters
      ----------
      limit : int, optional
        Maximum number of results to return (bounded to 1..100).
      include_pending : bool, optional
        Whether to include still-pending requests in the output.

      Returns
      -------
      dict
        Summary of results and metadata for each tracked request.
      """
      limit = min(max(1, limit), 100)
      results = []
      for request_id, request_data in self._requests.items():
        status = request_data.get("status")
        if (not include_pending) and status == self.STATUS_PENDING:
          continue
        entry = {
          "request_id": request_id,
          "type": request_data.get("parameters", {}).get("request_type", "classification"),
          "status": status,
          "submitted_at": request_data.get("created_at"),
          "metadata": request_data.get("metadata") or {},
        }
        if status != self.STATUS_PENDING and request_data.get("result") is not None:
          entry["result"] = request_data["result"]
        if request_data.get("error") is not None:
          entry["error"] = request_data["error"]
        results.append(entry)
      results.sort(key=lambda item: item.get("submitted_at", 0), reverse=True)
      results = results[:limit]
      return {
        "total_results": len(results),
        "limit": limit,
        "include_pending": include_pending,
        "results": results,
      }

    # Override only to attach balanced endpoint metadata to the inherited handler.
    @BasePlugin.balanced_endpoint
    @BasePlugin.endpoint(method="POST")
    def predict(
      self,
      text: str = "",
      metadata: Optional[Dict[str, Any]] = None,
      authorization: Optional[str] = None,
      **kwargs
    ):
      """
      Synchronous text-classification prediction endpoint.

      Parameters
      ----------
      text : str, optional
        Text to classify.
      metadata : dict or None, optional
        Optional metadata accompanying the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Result payload for synchronous processing or an error message.
      """
      return super(TextClassifierInferenceApiPlugin, self).predict(
        text=text,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )

    # Override only to attach balanced endpoint metadata to the inherited handler.
    @BasePlugin.balanced_endpoint
    @BasePlugin.endpoint(method="POST")
    def predict_async(
      self,
      text: str = "",
      metadata: Optional[Dict[str, Any]] = None,
      authorization: Optional[str] = None,
      **kwargs
    ):
      """
      Asynchronous text-classification prediction endpoint.

      Parameters
      ----------
      text : str, optional
        Text to classify.
      metadata : dict or None, optional
        Optional metadata accompanying the request.
      authorization : str or None, optional
        Bearer token used for authentication.
      **kwargs
        Extra parameters forwarded to the base handler.

      Returns
      -------
      dict
        Tracking payload for asynchronous processing or an error message.
      """
      return super(TextClassifierInferenceApiPlugin, self).predict_async(
        text=text,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )
  """END API ENDPOINTS"""

  """INFERENCE HANDLING"""
  if True:
    def _mark_request_failure(self, request_id: str, error_message: str):
      """
      Mark a tracked request as failed and record error details.
      """
      request_data = self._requests.get(request_id)
      if request_data is None:
        return
      if request_data.get("status") != self.STATUS_PENDING:
        return
      self.P(f"Request {request_id} failed: {error_message}")
      now_ts = self.time()
      request_data["status"] = self.STATUS_FAILED
      request_data["error"] = error_message
      request_data["result"] = {
        "status": "error",
        "error": error_message,
        "request_id": request_id,
      }
      self._annotate_result_with_node_roles(
        result_payload=request_data["result"],
        request_data=request_data,
      )
      request_data["finished_at"] = now_ts
      request_data["updated_at"] = now_ts
      self._metrics["requests_failed"] += 1
      self._decrement_active_requests()
      return

    def _mark_request_completed(
      self,
      request_id: str,
      request_data: Dict[str, Any],
      inference_payload: Dict[str, Any],
      metadata: Dict[str, Any],
    ):
      """
      Mark a tracked request as completed with the provided inference payload.
      """
      now_ts = self.time()
      request_data["status"] = self.STATUS_COMPLETED
      request_data["finished_at"] = now_ts
      request_data["updated_at"] = now_ts
      request_data["result"] = inference_payload
      self._annotate_result_with_node_roles(
        result_payload=request_data["result"],
        request_data=request_data,
      )
      self._metrics["requests_completed"] += 1
      self._decrement_active_requests()
      return

    def _extract_request_id(self, payload: Optional[Dict[str, Any]], inference: Any):
      """
      Extract a request identifier from payload or inference data.
      """
      request_id = self._get_payload_field(payload, "request_id") if payload else None
      if request_id is None and isinstance(inference, dict):
        request_id = self._get_payload_field(inference, "request_id")
      if request_id is None and isinstance(inference, dict):
        request_id = self._get_payload_field(inference, "REQUEST_ID")
      return request_id

    def _build_result_from_inference(
      self,
      request_id: str,
      inference: Dict[str, Any],
      metadata: Dict[str, Any],
      request_data: Dict[str, Any],
    ):
      """
      Construct a result payload from inference output and metadata.
      """
      if inference is None:
        raise ValueError("No inference result available.")
      if not isinstance(inference, dict):
        return {
          "status": "completed",
          "request_id": request_id,
          "text": request_data.get("parameters", {}).get("text"),
          "classification": inference,
          "metadata": metadata or request_data.get("metadata") or {},
        }

      model_output = inference.get("result", inference)
      text = inference.get("TEXT", request_data.get("parameters", {}).get("text"))
      result_payload = {
        "status": "completed",
        "request_id": request_id,
        "text": text,
        "classification": model_output,
        "metadata": metadata or request_data.get("metadata") or {},
      }
      if "MODEL_NAME" in inference:
        result_payload["model_name"] = inference["MODEL_NAME"]
      if "TOKENIZER_NAME" in inference:
        result_payload["tokenizer_name"] = inference["TOKENIZER_NAME"]
      if "PIPELINE_TASK" in inference:
        result_payload["pipeline_task"] = inference["PIPELINE_TASK"]
      return result_payload

    def handle_inference_for_request(
      self,
      request_id: str,
      inference: Any,
      metadata: Dict[str, Any]
    ):
      """
      Handle inference output for a specific tracked request.
      """
      if request_id not in self._requests:
        self.Pd(f"Received inference for unknown request_id {request_id}.")
        return
      request_data = self._requests[request_id]
      if request_data.get("status") != self.STATUS_PENDING:
        return
      if inference is None:
        self._mark_request_failure(request_id, "No inference result available.")
        return
      try:
        result_payload = self._build_result_from_inference(
          request_id=request_id,
          inference=inference,
          metadata=metadata,
          request_data=request_data,
        )
      except Exception as exc:
        self._mark_request_failure(request_id, str(exc))
        return
      self._mark_request_completed(
        request_id=request_id,
        request_data=request_data,
        inference_payload=result_payload,
        metadata=metadata,
      )
      return

    def handle_inferences(self, inferences, data=None):
      """
      Process incoming inferences and map them back to pending requests.
      """
      payloads = data if data is not None else self.dataapi_struct_datas(full=False, as_list=True) or []
      inferences = inferences or []

      if not payloads and not inferences:
        return

      payload_list = self._iter_struct_payloads(payloads)
      primary_payload = payload_list[0] if payload_list else None
      owned_payloads = self._build_owned_payloads_by_request_id(payloads)
      for idx, inference in enumerate(inferences):
        request_id = self._extract_request_id(None, inference)
        if request_id is None:
          request_id = self._extract_request_id(primary_payload, None)
        if request_id is None:
          self.Pd(f"No request_id found in inference at index {idx}, skipping.")
          continue
        payload = owned_payloads.get(request_id)
        metadata = self._get_payload_field(payload, "metadata", {}) if payload else {}
        self.handle_inference_for_request(
          request_id=request_id,
          inference=inference,
          metadata=metadata or {},
        )
      return
  """END INFERENCE HANDLING"""
