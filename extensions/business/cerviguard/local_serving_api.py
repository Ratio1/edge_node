"""
LOCAL_SERVING_API Plugin

This plugin creates a FastAPI server for local-only access (localhost) that works with
a loopback data capture pipeline. It uses the PostponedRequest pattern for async processing.

Key Features:
- Loopback mode: Outputs return to DCT queue for processing
- PostponedRequest pattern: Server-side polling, no manual client polling
- No token authentication (localhost only)
- Designed for CerviGuard image analysis

Available Endpoints:
- POST /predict - Submit image for analysis (returns result via PostponedRequest)
- GET /list_results - Get all processed image results
- GET /status - Get system status and statistics
- GET /health - Health check

Example pipeline configuration:
{
  "NAME": "cerviguard_loopback",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "LOCAL_SERVING_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "cerviguard_api_01"
        }
      ]
    }
  ]
}
"""

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin
from naeural_core.utils.fastapi_utils import PostponedRequest

__VER__ = '0.1.0'

_CONFIG = {
  **FastApiWebAppPlugin.CONFIG,

  # Loopback mode - outputs go back to the DCT queue instead of downstream
  'IS_LOOPBACK_PLUGIN': True,

  # Server configuration
  'PORT': 5082,
  'TUNNEL_ENGINE_ENABLED': False,  # Localhost only

  # API metadata
  'API_TITLE': 'CerviGuard Local Serving API',
  'API_SUMMARY': 'Local image analysis API with PostponedRequest pattern',
  'API_DESCRIPTION': 'FastAPI server for cervical image analysis using loopback pipeline and PostponedRequest pattern',

  # Response format
  'RESPONSE_FORMAT': 'WRAPPED',
  'LOG_REQUESTS': True,

  # Processing configuration
  'PROCESS_DELAY': 0,
  'REQUEST_TIMEOUT': 240,  # seconds - timeout for PostponedRequest polling

  # AI Engine for image processing
  'AI_ENGINE': 'CERVIGUARD_IMAGE_ANALYZER',

  'VALIDATION_RULES': {
    **FastApiWebAppPlugin.CONFIG['VALIDATION_RULES'],
    'REQUEST_TIMEOUT': {
      'DESCRIPTION': 'Timeout for PostponedRequest polling (seconds)',
      'TYPE': 'int',
      'MIN_VAL': 30,
      'MAX_VAL': 600,
    },
  },
}


class LocalServingApiPlugin(FastApiWebAppPlugin):
  """
  LOCAL_SERVING_API Plugin

  A FastAPI plugin designed for localhost-only access with loopback data capture.
  This plugin:
  - Does NOT require token authentication (localhost only)
  - Routes outputs back to the loopback DCT queue (IS_LOOPBACK_PLUGIN = True)
  - Provides simple REST endpoints for data processing
  - Works with Loopback data capture type pipelines
  """

  CONFIG = _CONFIG

  def on_init(self):
    super(LocalServingApiPlugin, self).on_init()
    # Initialize request tracking
    self.__requests = {}  # Track active requests (PostponedRequest pattern)
    self._data_buffer = []  # Simple activity log for monitoring

    self.P("Local Serving API initialized - Loopback + PostponedRequest mode", color='g')
    self.P(f"  Endpoints: /predict, /list_results, /status, /health", color='g')
    self.P(f"  AI Engine: {self.cfg_ai_engine}", color='g')
    self.P(f"  Loopback key: loopback_dct_{self._stream_id}", color='g')
    return

  def _get_payload_field(self, data: dict, key: str, default=None):
    if not isinstance(data, dict):
      return default
    if key in data:
      return data[key]
    key_upper = key.upper()
    if key_upper in data:
      return data[key_upper]
    return default

  # ========== POSTPONED REQUEST METHODS ==========

  def register_predict_request(self, image_data: str, metadata: dict = None, request_type: str = 'prediction'):
    """
    Register a new prediction request and add it to the loopback queue.

    Parameters
    ----------
    image_data : str
        Base64 encoded image data
    metadata : dict, optional
        Additional metadata for the request
    request_type : str
        Type of prediction request (default: 'prediction')

    Returns
    -------
    str
        The request ID
    """
    request_id = self.uuid()
    start_time = self.time()

    # Register the request in the tracking dictionary
    self.__requests[request_id] = {
      'request_id': request_id,
      'start_time': start_time,
      'last_request_time': start_time,
      'finished': False,
      'timeout': self.cfg_request_timeout,
      'type': request_type,
      'metadata': metadata or {},
    }

    # Track in buffer for monitoring
    self._data_buffer.append({
      'request_id': request_id,
      'type': request_type,
      'submitted_at': start_time,
      'metadata': metadata or {}
    })

    # Send to loopback queue via add_payload_by_fields
    # Because IS_LOOPBACK_PLUGIN=True, this writes to loopback_dct_{stream_id} queue
    self.add_payload_by_fields(
      request_id=request_id,
      image_data=image_data,
      metadata=metadata or {},
      type=request_type,
      submitted_at=start_time
    )

    self.P(f"[Predict] Registered request {request_id} and added to loopback queue", color='g')

    return request_id

  def solve_postponed_predict_request(self, request_id: str):
    """
    Solver method for postponed prediction requests.

    This method is called repeatedly by the FastAPI framework until the request
    is finished or times out.

    Parameters
    ----------
    request_id : str
        The request ID to check

    Returns
    -------
    dict or PostponedRequest
        Returns result dict if finished, or PostponedRequest to continue polling
    """
    if request_id not in self.__requests:
      return {
        'status': 'error',
        'error': 'Request ID not found',
        'request_id': request_id
      }

    request = self.__requests[request_id]
    start_time = request['start_time']
    timeout = request['timeout']

    # Check if request is finished
    if request['finished']:
      result = request.get('result', {})
      self.P(f"[Predict] Request {request_id} completed, returning result", color='g')
      return result

    # Check if request has timed out
    if self.time() - start_time > timeout:
      error_result = {
        'status': 'error',
        'error': 'Request timed out',
        'request_id': request_id,
        'timeout': timeout
      }
      request['result'] = error_result
      request['finished'] = True
      self.P(f"[Predict] Request {request_id} timed out after {timeout}s", color='r')
      return error_result

    # Request still processing - return PostponedRequest to continue polling
    return self.create_postponed_request(
      solver_method=self.solve_postponed_predict_request,
      method_kwargs={'request_id': request_id}
    )

  # ========== API ENDPOINTS ==========

  @FastApiWebAppPlugin.endpoint(method="get")
  def health(self):
    """
    Health check endpoint
    Returns server status and basic info
    """
    return {
      "status": "healthy",
      "plugin": "LOCAL_SERVING_API",
      "version": __VER__,
      "stream_id": self._stream_id,
      "instance_id": self.get_instance_id(),
      "loopback_enabled": self.cfg_is_loopback_plugin,
      "uptime_seconds": self.time() - self.start_time if hasattr(self, 'start_time') else 0,
    }

  @FastApiWebAppPlugin.endpoint(method="get")
  def status(self):
    """
    Get current system status and statistics
    """
    pending = len([
      req_id for req_id, req_data in self.__requests.items()
      if not req_data.get('finished', False)
    ])
    completed = len([
      req_id for req_id, req_data in self.__requests.items()
      if req_data.get('finished', False)
    ])
    return {
      "status": "online",
      "service": "CerviGuard Image Analysis",
      "version": __VER__,
      "stream_id": self._stream_id,
      "instance_id": self.get_instance_id(),
      "total_requests": len(self.__requests),
      "pending_requests": pending,
      "completed_requests": completed,
      "uptime_seconds": self.time() - self.start_time if hasattr(self, 'start_time') else 0,
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def predict(self, image_data: str, metadata: dict = None):
    """
    Simple /predict endpoint for image analysis using PostponedRequest pattern

    This endpoint uses the PostponedRequest pattern to handle async processing:
    1. Receives base64 image
    2. Registers request and adds to loopback queue
    3. Returns PostponedRequest that framework polls automatically
    4. Serving plugin processes the image in the background
    5. When complete, result is returned to client

    Parameters
    ----------
    image_data : str
        Base64 encoded image (supports data URLs)
    metadata : dict, optional
        Additional metadata

    Returns
    -------
    dict or PostponedRequest
        Either immediate error or PostponedRequest for async processing
    """
    self.P(f"[Predict] Received image prediction request", color='b')

    # Validate image data
    if not image_data or len(image_data) < 100:
      return {
        "status": "error",
        "error": "Invalid or missing image data",
        "message": "Image data must be base64 encoded"
      }

    # Register the request and add to loopback queue
    request_id = self.register_predict_request(
      image_data=image_data,
      metadata=metadata,
      request_type='prediction'
    )

    # Return PostponedRequest - framework will poll solve_postponed_predict_request()
    return self.solve_postponed_predict_request(request_id=request_id)


  @FastApiWebAppPlugin.endpoint(method="get")
  def list_results(self, limit: int = 50, include_pending: bool = False):
    """
    Get all processed image results

    Parameters
    ----------
    limit : int
        Maximum number of results to return (default: 50, max: 100)
    include_pending : bool
        Whether to include pending requests (default: False)

    Returns
    -------
    dict
        List of all processed results with metadata
    """
    # Limit validation
    limit = min(max(1, limit), 100)

    results_list = []
    for req_id, req_data in self.__requests.items():
      is_finished = req_data.get('finished', False)

      # Skip pending if not requested
      if not include_pending and not is_finished:
        continue

      result_item = {
        'request_id': req_id,
        'type': req_data.get('type', 'unknown'),
        'status': 'completed' if is_finished else 'processing',
        'submitted_at': req_data.get('start_time'),
        'metadata': req_data.get('metadata', {}),
      }

      # Add result if finished
      if is_finished:
        result_item['result'] = req_data.get('result', {})

      results_list.append(result_item)

    # Sort by submission time (most recent first)
    results_list.sort(key=lambda x: x.get('submitted_at', 0), reverse=True)

    # Apply limit
    results_list = results_list[:limit]

    return {
      "total_results": len(results_list),
      "limit": limit,
      "include_pending": include_pending,
      "results": results_list
    }

  def process(self):
    """
    Main process loop:
    1. Read struct_data from pipeline (contains image requests from loopback)
    2. Read inferences from serving plugin (which has already processed them)
    3. Match inferences to requests by index
    4. Mark requests as finished for PostponedRequest polling
    """
    self._cleanup_old_requests()
    self._maybe_trim_buffer()

    # Read struct_data from pipeline (raw payloads)
    payloads = self.dataapi_struct_datas(full=False, as_list=True)
    if not payloads:
      return None

    # Read inferences that serving plugin already produced
    # The serving plugin processes the data automatically via the pipeline
    inferences = self.dataapi_struct_data_inferences(how='list')

    if not inferences:
      self.P(f"No inferences available for {len(payloads)} payload(s)", color='y')
      return None

    self.P(f"Processing {len(payloads)} payload(s) with {len(inferences)} inference(s)", color='b')

    # Match payloads with inferences (they should be in same order)
    for idx, payload in enumerate(payloads):
      inference = inferences[idx] if idx < len(inferences) else None
      self._process_loopback_payload(payload, inference)

    return None

  def _process_loopback_payload(self, payload, inference):
    """
    Process a single payload from loopback queue with its corresponding inference:
    1. Extract request info from payload
    2. Extract inference result from serving plugin
    3. Mark request as finished in __requests dict

    Parameters
    ----------
    payload : dict
        The original payload with request_id, image_data, metadata
    inference : dict
        The inference result from the serving plugin (already processed)
    """
    if not isinstance(payload, dict):
      return

    # Extract request info from payload
    request_id = self._get_payload_field(payload, 'request_id')
    metadata = self._get_payload_field(payload, 'metadata', {}) or {}

    if not request_id:
      self.P("Received payload without request_id, ignoring", color='y')
      return

    # Check if this request is tracked
    if request_id not in self.__requests:
      self.P(f"Request {request_id} not found in tracked requests, ignoring", color='y')
      return

    if inference is None:
      self.P(f"No inference available for request {request_id}", color='y')
      self._mark_request_error(request_id, 'No inference result available')
      return

    self.P(f"[CerviGuard] Processing inference for request {request_id}", color='b')

    try:
      # The serving plugin returns inferences in a specific format
      # For cerviguard_analyzer, it returns: {'status': 'completed', 'data': {...}}

      if not isinstance(inference, dict):
        self.P(f"Unexpected inference format: {type(inference)}", color='r')
        self._mark_request_error(request_id, 'Invalid inference result format')
        return

      # Extract the inference data
      # Inference can be the result dict directly or wrapped
      inference_data = inference.get('data', inference) if 'data' in inference else inference

      # Check status
      status = inference_data.get('status', 'unknown')

      if status == 'error':
        error_msg = inference_data.get('error', 'Unknown error')
        self._mark_request_error(request_id, error_msg)
        return

      # Success - extract image info and analysis
      image_info = inference_data.get('image_info', {})
      analysis = inference_data.get('analysis', {})

      # Validate and provide safe defaults for analysis fields
      validated_analysis = self._validate_analysis(analysis)

      # Include image_info in analysis
      validated_analysis['image_info'] = image_info

      final_result = {
        'status': 'completed',
        'request_id': request_id,
        'analysis': validated_analysis,
        'processed_at': inference_data.get('processed_at', self.time()),
        'processor_version': inference_data.get('processor_version', 'unknown'),
        'metadata': metadata,
      }

      # Mark request as finished with result
      self.__requests[request_id]['result'] = final_result
      self.__requests[request_id]['finished'] = True

      self.P(f"[CerviGuard] Marked request {request_id} as finished", color='g')

    except Exception as e:
      self.P(f"Error processing request {request_id}: {e}", color='r')
      import traceback
      self.P(traceback.format_exc(), color='r')
      self._mark_request_error(request_id, f'Processing error: {str(e)}')

    return

  def _validate_analysis(self, analysis: dict) -> dict:
    """
    Validate and sanitize analysis data, providing safe defaults.

    Parameters
    ----------
    analysis : dict
        Analysis data from serving plugin

    Returns
    -------
    dict
        Validated analysis with all required fields
    """
    # Define safe defaults
    safe_defaults = {
      'tz_type': 'Type 1',
      'lesion_assessment': 'none',
      'lesion_summary': 'Analysis unavailable',
      'risk_score': 0,
      'image_quality': 'unknown',
      'image_quality_sufficient': True
    }

    if not isinstance(analysis, dict):
      self.P("Analysis data is not a dict, using defaults", color='y')
      return safe_defaults

    # Validate each field
    validated = {}

    # Validate tz_type (must be "Type 1", "Type 2", or "Type 3")
    tz_type = analysis.get('tz_type', safe_defaults['tz_type'])
    if tz_type not in ['Type 1', 'Type 2', 'Type 3']:
      self.P(f"Invalid tz_type: {tz_type}, using default", color='y')
      tz_type = safe_defaults['tz_type']
    validated['tz_type'] = tz_type

    # Validate lesion_assessment (must be "none", "low", "moderate", or "high")
    lesion_assessment = analysis.get('lesion_assessment', safe_defaults['lesion_assessment'])
    if lesion_assessment not in ['none', 'low', 'moderate', 'high']:
      self.P(f"Invalid lesion_assessment: {lesion_assessment}, using default", color='y')
      lesion_assessment = safe_defaults['lesion_assessment']
    validated['lesion_assessment'] = lesion_assessment

    # Validate lesion_summary (must be string)
    lesion_summary = analysis.get('lesion_summary', safe_defaults['lesion_summary'])
    if not isinstance(lesion_summary, str):
      self.P(f"Invalid lesion_summary type: {type(lesion_summary)}, using default", color='y')
      lesion_summary = safe_defaults['lesion_summary']
    validated['lesion_summary'] = lesion_summary

    # Validate risk_score (must be int 0-100)
    risk_score = analysis.get('risk_score', safe_defaults['risk_score'])
    try:
      risk_score = int(risk_score)
      if risk_score < 0 or risk_score > 100:
        self.P(f"risk_score out of range: {risk_score}, clamping to 0-100", color='y')
        risk_score = max(0, min(100, risk_score))
    except (TypeError, ValueError):
      self.P(f"Invalid risk_score: {risk_score}, using default", color='y')
      risk_score = safe_defaults['risk_score']
    validated['risk_score'] = risk_score

    # Validate image_quality (must be string)
    image_quality = analysis.get('image_quality', safe_defaults['image_quality'])
    if not isinstance(image_quality, str):
      self.P(f"Invalid image_quality type: {type(image_quality)}, using default", color='y')
      image_quality = safe_defaults['image_quality']
    validated['image_quality'] = image_quality

    # Validate image_quality_sufficient (must be boolean)
    image_quality_sufficient = analysis.get('image_quality_sufficient', safe_defaults['image_quality_sufficient'])
    if not isinstance(image_quality_sufficient, bool):
      self.P(f"Invalid image_quality_sufficient type: {type(image_quality_sufficient)}, using default", color='y')
      image_quality_sufficient = safe_defaults['image_quality_sufficient']
    validated['image_quality_sufficient'] = image_quality_sufficient

    return validated

  def _mark_request_error(self, request_id: str, error_message: str):
    """Mark a request as finished with an error"""
    self.P(f"[CerviGuard] Marking request {request_id} as error: {error_message}", color='r')

    error_result = {
      'status': 'error',
      'error': error_message,
      'request_id': request_id,
      'processed_at': self.time(),
    }

    if request_id in self.__requests:
      self.__requests[request_id]['result'] = error_result
      self.__requests[request_id]['finished'] = True
    return

  def _cleanup_old_requests(self):
    """Clean up old finished requests to prevent memory buildup"""
    now = self.time()
    # Clean up requests older than 1 hour
    max_age = 3600
    expired = [
      req_id for req_id, req_data in self.__requests.items()
      if req_data.get('finished', False) and (now - req_data.get('start_time', now)) > max_age
    ]
    for req_id in expired:
      del self.__requests[req_id]
    if expired:
      self.P(f"[CerviGuard] Cleaned up {len(expired)} old finished requests", color='y')
    return

  def _maybe_trim_buffer(self):
    if len(self._data_buffer) > 100:
      self._data_buffer = self._data_buffer[-100:]
    return
