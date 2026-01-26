"""
SD_INFERENCE_API Plugin

Production-Grade Structured Data Inference API

This plugin exposes a hardened, FastAPI-powered interface for structured-data
workloads. It reuses the BaseInferenceApi request lifecycle while tailoring
validation and response shaping for general-purpose tabular/JSON inference.

Highlights
- Loopback-only surface paired with local clients
- Request tracking, persistence, auth, and rate limiting from BaseInferenceApi
- Structured payload validation and metadata normalization
- Mapping of struct_data payloads and inferences back to requests
"""

from typing import Any, Dict, Optional

from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin


__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,
  "API_TITLE": "Structured Data Inference API",
  "API_SUMMARY": "Local structured-data analysis API for paired clients.",
  "REQUEST_TIMEOUT": 240,
  "MIN_STRUCT_DATA_FIELDS": 1,

  "VALIDATION_RULES": {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
    "MIN_STRUCT_DATA_FIELDS": {
      "DESCRIPTION": "Minimum number of top-level fields required in struct_data.",
      "TYPE": "int",
      "MIN_VAL": 1,
      "MAX_VAL": 10000,
    },
    'REQUEST_TIMEOUT': {
      'DESCRIPTION': 'Timeout for PostponedRequest polling (seconds)',
      'TYPE': 'int',
      'MIN_VAL': 30,
      'MAX_VAL': 600,
    },
  },
}


class SdInferenceApiPlugin(BasePlugin):
  CONFIG = _CONFIG

  def _normalize_struct_data(self, struct_data: Any):
    """
    Normalize and validate struct_data input shape.

    Parameters
    ----------
    struct_data : Any
      Incoming structured data payload.

    Returns
    -------
    tuple
      (normalized_struct_data, error_message). error_message is None when valid.
    """
    if isinstance(struct_data, dict):
      if len(struct_data) < self.cfg_min_struct_data_fields:
        return None, (
          f"`struct_data` must contain at least {self.cfg_min_struct_data_fields} fields."
        )
      return struct_data, None
    if isinstance(struct_data, list):
      if not struct_data:
        return None, "`struct_data` list must not be empty."
      if not all(isinstance(item, dict) for item in struct_data):
        return None, "`struct_data` list items must all be dictionaries."
      return struct_data, None
    return None, "`struct_data` must be a dictionary or list of dictionaries."

  """VALIDATION"""
  if True:
    def check_predict_params(
      self,
      struct_data: Any,
      metadata: Optional[Dict[str, Any]] = None,
      **kwargs
    ):
      """
      Validate input parameters for structured-data prediction requests.

      Parameters
      ----------
      struct_data : Any
        Structured payload (dict or list of dicts).
      metadata : dict or None, optional
        Optional metadata accompanying the request.
      **kwargs
        Additional parameters ignored by validation.

      Returns
      -------
      str or None
        Error message when validation fails, otherwise None.
      """
      _, err = self._normalize_struct_data(struct_data)
      if err:
        return err
      if metadata is not None and not isinstance(metadata, dict):
        return "`metadata` must be a dictionary when provided."
      return None

    def process_predict_params(
      self,
      struct_data: Any,
      metadata: Optional[Dict[str, Any]] = None,
      **kwargs
    ):
      """
      Normalize and forward parameters for request registration.

      Parameters
      ----------
      struct_data : Any
        Structured payload (dict or list of dicts).
      metadata : dict or None, optional
        Optional metadata accompanying the request.
      **kwargs
        Additional parameters to propagate downstream.

      Returns
      -------
      dict
        Processed parameters ready for dispatch to the inference engine.
      """
      normalized_struct, _ = self._normalize_struct_data(struct_data)
      cleaned_metadata = metadata or {}
      return {
        'struct_data': normalized_struct,
        'metadata': cleaned_metadata,
        'request_type': 'prediction',
        **{k: v for k, v in kwargs.items() if k not in {'metadata'}},
      }

    def compute_payload_kwargs_from_predict_params(
      self,
      request_id: str,
      request_data: Dict[str, Any],
    ):
      """
      Build payload keyword arguments for structured-data inference.

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      request_data : dict
        Stored request record containing processed parameters.

      Returns
      -------
      dict
        Payload fields including struct_data, metadata, and submission info.
      """
      params = request_data['parameters']
      submitted_at = request_data['created_at']
      metadata = params.get('metadata') or request_data.get('metadata') or {}
      return {
        'request_id': request_id,
        'struct_data': params['struct_data'],
        'metadata': metadata,
        'type': params.get('request_type', 'prediction'),
        'submitted_at': submitted_at,
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
        status = request_data.get('status')
        if (not include_pending) and status == self.STATUS_PENDING:
          continue
        entry = {
          'request_id': request_id,
          'type': request_data.get('parameters', {}).get('request_type', 'prediction'),
          'status': status,
          'submitted_at': request_data.get('created_at'),
          'metadata': request_data.get('metadata') or {},
        }
        if status != self.STATUS_PENDING and request_data.get('result') is not None:
          entry['result'] = request_data['result']
        if request_data.get('error') is not None:
          entry['error'] = request_data['error']
        results.append(entry)
      results.sort(key=lambda item: item.get('submitted_at', 0), reverse=True)
      results = results[:limit]
      return {
        "total_results": len(results),
        "limit": limit,
        "include_pending": include_pending,
        "results": results
      }

    @BasePlugin.endpoint(method="POST")
    def predict(
        self,
        struct_data: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Synchronous structured-data prediction endpoint.

      Parameters
      ----------
      struct_data : Any, optional
        Structured payload (dict or list of dicts) to analyze.
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
      return super(SdInferenceApiPlugin, self).predict(
        struct_data=struct_data,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )

    @BasePlugin.endpoint(method="POST")
    def predict_async(
        self,
        struct_data: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Asynchronous structured-data prediction endpoint.

      Parameters
      ----------
      struct_data : Any, optional
        Structured payload (dict or list of dicts) to analyze.
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
      return super(SdInferenceApiPlugin, self).predict_async(
        struct_data=struct_data,
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

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      error_message : str
        Description of the failure encountered.

      Returns
      -------
      None
        Updates request status and metrics in place.
      """
      request_data = self._requests.get(request_id)
      if request_data is None:
        return
      if request_data.get('status') != self.STATUS_PENDING:
        return
      self.P(f"Request {request_id} failed: {error_message}")
      now_ts = self.time()
      request_data['status'] = self.STATUS_FAILED
      request_data['error'] = error_message
      request_data['result'] = {
        'status': 'error',
        'error': error_message,
        'request_id': request_id,
      }
      request_data['finished_at'] = now_ts
      request_data['updated_at'] = now_ts
      self._metrics['requests_failed'] += 1
      self._metrics['requests_active'] -= 1
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

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      request_data : dict
        Stored request record to update.
      inference_payload : dict
        Result payload constructed from the inference output.
      metadata : dict
        Metadata associated with the request.

      Returns
      -------
      None
        Updates request status and metrics in place.
      """
      now_ts = self.time()
      request_data['status'] = self.STATUS_COMPLETED
      request_data['finished_at'] = now_ts
      request_data['updated_at'] = now_ts
      request_data['result'] = inference_payload
      self._metrics['requests_completed'] += 1
      self._metrics['requests_active'] -= 1
      return

    def _extract_request_id(self, payload: Optional[Dict[str, Any]], inference: Any):
      """
      Extract a request identifier from payload or inference data.

      Parameters
      ----------
      payload : dict or None
        Structured data payload, if available.
      inference : Any
        Inference result that may contain identifiers.

      Returns
      -------
      str or None
        Extracted request ID when present, otherwise None.
      """
      request_id = self._get_payload_field(payload, 'request_id') if payload else None
      if request_id is None and isinstance(inference, dict):
        request_id = self._get_payload_field(inference, 'request_id')
      if request_id is None and isinstance(inference, dict):
        request_id = self._get_payload_field(inference, 'REQUEST_ID')
      return request_id

    def _build_result_from_inference(
      self,
      request_id: str,
      inference: Dict[str, Any],
      metadata: Dict[str, Any],
      request_data: Dict[str, Any]
    ):
      """
      Construct a result payload from inference output and metadata.

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      inference : dict
        Inference result data.
      metadata : dict
        Metadata to include in the response.
      request_data : dict
        Stored request record for reference.

      Returns
      -------
      dict
        Structured result payload including prediction and auxiliary details.

      Raises
      ------
      ValueError
        If the inference result format is invalid.
      RuntimeError
        When the inference indicates an error status.
      """
      if not isinstance(inference, dict):
        raise ValueError("Invalid inference result format.")
      inference_data = inference.get('data', inference)
      status = inference_data.get('status', inference.get('status', 'completed'))
      if status == 'error':
        err_msg = inference_data.get('error', 'Unknown error')
        raise RuntimeError(err_msg)

      prediction = inference_data.get('prediction', inference_data.get('result'))
      result_payload = {
        'status': 'completed',
        'request_id': request_id,
        'prediction': prediction,
        'metadata': metadata or request_data.get('metadata') or {},
        'processed_at': inference_data.get('processed_at', self.time()),
        'processor_version': inference_data.get('processor_version', 'unknown'),
      }
      if 'model_name' in inference_data:
        result_payload['model_name'] = inference_data['model_name']
      if 'scores' in inference_data:
        result_payload['scores'] = inference_data['scores']
      if 'probabilities' in inference_data:
        result_payload['probabilities'] = inference_data['probabilities']
      return result_payload

    def handle_inference_for_request(
      self,
      request_id: str,
      inference: Any,
      metadata: Dict[str, Any]
    ):
      """
      Handle inference output for a specific tracked request.

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      inference : Any
        Inference payload to process.
      metadata : dict
        Metadata associated with the request.

      Returns
      -------
      None
        Updates request tracking based on inference success or failure.
      """
      if request_id not in self._requests:
        self.Pd(f"Received inference for unknown request_id {request_id}.")
        return
      request_data = self._requests[request_id]
      if request_data.get('status') != self.STATUS_PENDING:
        return
      if inference is None:
        self._mark_request_failure(request_id, "No inference result available.")
        return
      try:
        result_payload = self._build_result_from_inference(
          request_id=request_id,
          inference=inference,
          metadata=metadata,
          request_data=request_data
        )
      except Exception as exc:
        self._mark_request_failure(request_id, str(exc))
        return
      self._mark_request_completed(
        request_id=request_id,
        request_data=request_data,
        inference_payload=result_payload,
        metadata=metadata
      )
      return

    def handle_inferences(self, inferences, data=None):
      """
      Process incoming inferences and map them back to pending requests.

      Parameters
      ----------
      inferences : list or Any
        Inference outputs from the serving pipeline.
      data : list or Any, optional
        Optional data payloads paired with inferences.

      Returns
      -------
      None
        Iterates over incoming results and updates tracked requests.
      """
      payloads = data if isinstance(data, list) else self.dataapi_struct_datas(full=False, as_list=True) or []
      inferences = inferences or []

      if not payloads and not inferences:
        return

      max_len = max(len(payloads), len(inferences))
      for idx in range(max_len):
        payload = payloads[idx] if idx < len(payloads) else None
        inference = inferences[idx] if idx < len(inferences) else None
        request_id = self._extract_request_id(payload, inference)
        if request_id is None:
          self.Pd(f"No request_id found for index {idx}, skipping.")
          continue
        metadata = self._get_payload_field(payload, 'metadata', {}) if payload else {}
        self.handle_inference_for_request(
          request_id=request_id,
          inference=inference,
          metadata=metadata or {}
        )
      return
  """END INFERENCE HANDLING"""
