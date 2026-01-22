"""
CV_INFERENCE_API Plugin

Production-Grade Computer Vision Inference API

This plugin exposes a hardened, FastAPI-powered interface for
computer-vision workloads. It reuses the BaseInferenceApi request lifecycle
while tailoring validation and response shaping for image analysis.

Highlights
- Loopback-only surface paired with local third-party applications that use it
- Request tracking, persistence, auth, and rate limiting from BaseInferenceApi
- Base64 payload validation and metadata normalization for serving plugins
- Structured mapping of struct_data payloads and inferences back to requests
"""

from typing import Any, Dict, Optional

from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin


__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,
  "API_TITLE": "CV Inference API",
  "API_SUMMARY": "Local image analysis API",
  "REQUEST_TIMEOUT": 240,
  "MIN_IMAGE_DATA_LENGTH": 100,
  "VALIDATION_RULES": {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
    "MIN_IMAGE_DATA_LENGTH": {
      "DESCRIPTION": "Minimum base64 payload length used for coarse validation.",
      "TYPE": "int",
      "MIN_VAL": 10,
      "MAX_VAL": 1_000_000,
    },
    'REQUEST_TIMEOUT': {
      'DESCRIPTION': 'Timeout for PostponedRequest polling (seconds)',
      'TYPE': 'int',
      'MIN_VAL': 30,
      'MAX_VAL': 600,
    },
  },
}


class CvInferenceApiPlugin(BasePlugin):
  CONFIG = _CONFIG

  def _get_payload_field(self, data: dict, key: str, default=None):
    """
    Retrieve a value from payload data using case-insensitive lookup.

    Parameters
    ----------
    data : dict
      Payload dictionary to search.
    key : str
      Target key to retrieve (case-insensitive).
    default : Any, optional
      Fallback value when the key is not present.

    Returns
    -------
    Any
      Matched value from the payload or the provided default.
    """
    if not isinstance(data, dict):
      return default
    if key in data:
      return data[key]
    key_upper = key.upper()
    if key_upper in data:
      return data[key_upper]
    return default

  """VALIDATION"""
  if True:
    def check_predict_params(
      self,
      image_data: str,
      metadata: Optional[Dict[str, Any]] = None,
      **kwargs
    ):
      """
      Validate input parameters for image prediction requests.

      Parameters
      ----------
      image_data : str
        Base64-encoded image string.
      metadata : dict or None, optional
        Optional metadata accompanying the request.
      **kwargs
        Additional parameters ignored by validation.

      Returns
      -------
      str or None
        Error message when validation fails, otherwise None.
      """
      if not isinstance(image_data, str) or len(image_data) < self.cfg_min_image_data_length:
        return (
          "Invalid or missing image data. "
          f"Expecting base64 content with at least {self.cfg_min_image_data_length} characters."
        )
      if metadata is not None and not isinstance(metadata, dict):
        return "`metadata` must be a dictionary when provided."
      return None

    def process_predict_params(
      self,
      image_data: str,
      metadata: Optional[Dict[str, Any]] = None,
      **kwargs
    ):
      """
      Normalize and forward parameters for request registration.

      Parameters
      ----------
      image_data : str
        Base64-encoded image string.
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
        'image_data': image_data,
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
      Build payload keyword arguments for Computer Vision inference.

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      request_data : dict
        Stored request record containing processed parameters.

      Returns
      -------
      dict
        Payload fields including image data, metadata, and submission info.
      """
      params = request_data['parameters']
      submitted_at = request_data['created_at']
      metadata = params.get('metadata') or request_data.get('metadata') or {}
      return {
        'request_id': request_id,
        'image_data': params['image_data'],
        'metadata': metadata,
        'type': params.get('request_type', 'prediction'),
        'submitted_at': submitted_at,
      }
  """END VALIDATION"""

  """API ENDPOINTS"""
  if True:
    @BasePlugin.endpoint(method="GET")
    def status(self):
      """
      Status endpoint summarizing API state.

      Returns
      -------
      dict
        Basic service info plus counts of pending and completed requests.
      """
      pending = len([
        rid for rid, data in self._requests.items()
        if data.get('status') == self.STATUS_PENDING
      ])
      completed = len([
        rid for rid, data in self._requests.items()
        if data.get('status') == self.STATUS_COMPLETED
      ])
      return {
        "status": self.get_status(),
        "service": "Image Analysis",
        "version": __VER__,
        "stream_id": self.get_stream_id(),
        "plugin": self.get_signature(),
        "instance_id": self.get_instance_id(),
        "total_requests": len(self._requests),
        "pending_requests": pending,
        "completed_requests": completed,
        "uptime_seconds": self.get_alive_time(),
      }

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
        image_data: str = '',
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Synchronous Computer Vision prediction endpoint.

      Parameters
      ----------
      image_data : str, optional
        Base64-encoded image string to analyze.
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
      return super(CvInferenceApiPlugin, self).predict(
        image_data=image_data,
        metadata=metadata,
        authorization=authorization,
        **kwargs
      )

    @BasePlugin.endpoint(method="POST")
    def predict_async(
        self,
        image_data: str = '',
        metadata: Optional[Dict[str, Any]] = None,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Asynchronous Computer Vision prediction endpoint.

      Parameters
      ----------
      image_data : str, optional
        Base64-encoded image string to analyze.
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
      return super(CvInferenceApiPlugin, self).predict_async(
        image_data=image_data,
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
        Structured result payload including analysis and image details.

      Raises
      ------
      ValueError
        If the inference result format is invalid.
      RuntimeError
        When the inference indicates an error status.
      """
      return {
        'request_id': request_id,
        'inference': inference,
        'metadata': metadata or request_data.get('metadata') or {},
      }

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
