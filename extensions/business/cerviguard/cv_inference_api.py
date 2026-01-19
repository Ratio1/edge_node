"""
CV_INFERENCE_API Plugin

Production-Grade CerviGuard Inference API

This plugin exposes a hardened, FastAPI-powered interface for CerviGuard
computer-vision workloads. It reuses the BaseInferenceApi request lifecycle
while tailoring validation and response shaping for image analysis.

Highlights
- Loopback-only surface paired with local CerviGuard clients
- Request tracking, persistence, auth, and rate limiting from BaseInferenceApi
- Base64 payload validation and metadata normalization for serving plugins
- Structured mapping of struct_data payloads and inferences back to requests
"""

from typing import Any, Dict, Optional

from extensions.business.inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin


__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,
  "AI_ENGINE": "CERVIGUARD_IMAGE_ANALYZER",
  "API_TITLE": "CerviGuard CV Inference API",
  "API_SUMMARY": "Local image analysis API for CerviGuard clients.",
  "REQUEST_TIMEOUT": 240,
  "MIN_IMAGE_DATA_LENGTH": 100,
  "ALLOW_ANONYMOUS_ACCESS": True,
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
      request_type: str = 'prediction',
      **kwargs
    ):
      if not isinstance(image_data, str) or len(image_data) < self.cfg_min_image_data_length:
        return (
          "Invalid or missing image data. "
          f"Expecting base64 content with at least {self.cfg_min_image_data_length} characters."
        )
      if metadata is not None and not isinstance(metadata, dict):
        return "`metadata` must be a dictionary when provided."
      if request_type is not None and not isinstance(request_type, str):
        return "`request_type` must be a string when provided."
      return None

    def process_predict_params(
      self,
      image_data: str,
      metadata: Optional[Dict[str, Any]] = None,
      request_type: str = 'prediction',
      **kwargs
    ):
      cleaned_metadata = metadata or {}
      normalized_type = (request_type or 'prediction').strip() or 'prediction'
      return {
        'image_data': image_data,
        'metadata': cleaned_metadata,
        'request_type': normalized_type,
        **{k: v for k, v in kwargs.items() if k not in {'metadata'}},
      }

    def compute_payload_kwargs_from_predict_params(
      self,
      request_id: str,
      request_data: Dict[str, Any],
    ):
      params = request_data['parameters']
      submitted_at = request_data['created_at']
      metadata = params.get('metadata') or request_data.get('metadata') or {}
      return {
        'request_id': request_id,
        'REQUEST_ID': request_id,
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
        "service": "CerviGuard Image Analysis",
        "version": __VER__,
        "stream_id": self.get_stream_id(),
        "instance_id": self.get_instance_id(),
        "total_requests": len(self._requests),
        "pending_requests": pending,
        "completed_requests": completed,
        "uptime_seconds": self.get_alive_time(),
      }

    @BasePlugin.endpoint(method="GET")
    def list_results(self, limit: int = 50, include_pending: bool = False):
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
  """END API ENDPOINTS"""

  """INFERENCE HANDLING"""
  if True:
    def _validate_analysis(self, analysis: dict) -> dict:
      safe_defaults = {
        'tz_type': 'Type 1',
        'lesion_assessment': 'none',
        'lesion_summary': 'Analysis unavailable',
        'risk_score': 0,
        'image_quality': 'unknown',
        'image_quality_sufficient': True
      }
      if not isinstance(analysis, dict):
        return safe_defaults

      validated = {}

      tz_type = analysis.get('tz_type', safe_defaults['tz_type'])
      if tz_type not in ['Type 0', 'Type 1', 'Type 2', 'Type 3']:
        tz_type = safe_defaults['tz_type']
      validated['tz_type'] = tz_type

      lesion_assessment = analysis.get('lesion_assessment', safe_defaults['lesion_assessment'])
      if lesion_assessment not in ['none', 'low', 'moderate', 'high']:
        lesion_assessment = safe_defaults['lesion_assessment']
      validated['lesion_assessment'] = lesion_assessment

      lesion_summary = analysis.get('lesion_summary', safe_defaults['lesion_summary'])
      if not isinstance(lesion_summary, str):
        lesion_summary = safe_defaults['lesion_summary']
      validated['lesion_summary'] = lesion_summary

      risk_score = analysis.get('risk_score', safe_defaults['risk_score'])
      try:
        risk_score = int(risk_score)
        if risk_score < 0 or risk_score > 100:
          risk_score = max(0, min(100, risk_score))
      except (TypeError, ValueError):
        risk_score = safe_defaults['risk_score']
      validated['risk_score'] = risk_score

      image_quality = analysis.get('image_quality', safe_defaults['image_quality'])
      if not isinstance(image_quality, str):
        image_quality = safe_defaults['image_quality']
      validated['image_quality'] = image_quality

      image_quality_sufficient = analysis.get(
        'image_quality_sufficient',
        safe_defaults['image_quality_sufficient']
      )
      if not isinstance(image_quality_sufficient, bool):
        image_quality_sufficient = safe_defaults['image_quality_sufficient']
      validated['image_quality_sufficient'] = image_quality_sufficient
      return validated

    def _mark_request_failure(self, request_id: str, error_message: str):
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
      now_ts = self.time()
      request_data['status'] = self.STATUS_COMPLETED
      request_data['finished_at'] = now_ts
      request_data['updated_at'] = now_ts
      request_data['result'] = inference_payload
      self._metrics['requests_completed'] += 1
      self._metrics['requests_active'] -= 1
      return

    def _extract_request_id(self, payload: Optional[Dict[str, Any]], inference: Any):
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
      if not isinstance(inference, dict):
        raise ValueError("Invalid inference result format.")
      inference_data = inference.get('data', inference)
      status = inference_data.get('status', inference.get('status', 'completed'))
      if status == 'error':
        err_msg = inference_data.get('error', 'Unknown error')
        raise RuntimeError(err_msg)

      analysis = self._validate_analysis(inference_data.get('analysis', {}))
      image_info = inference_data.get('image_info', {})
      result_payload = {
        'status': 'completed',
        'request_id': request_id,
        'analysis': analysis,
        'image_info': image_info,
        'processed_at': inference_data.get('processed_at', self.time()),
        'processor_version': inference_data.get('processor_version', 'unknown'),
        'metadata': metadata or request_data.get('metadata') or {},
      }
      if 'model_name' in inference_data:
        result_payload['model_name'] = inference_data['model_name']
      return result_payload

    def handle_inference_for_request(
      self,
      request_id: str,
      inference: Any,
      metadata: Dict[str, Any]
    ):
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
