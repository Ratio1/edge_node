"""
LOCAL_SERVING_API Plugin

This plugin creates a FastAPI server for local-only access (localhost) that works with
a loopback data capture pipeline. It provides a simple API interface without token authentication,
suitable for internal/localhost-only services.

Example pipeline configuration:
{
  "NAME": "local_api_demo",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "LOCAL_SERVING_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "local_api_01"
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

  # Mark this as a loopback plugin - outputs go back to the DCT queue instead of downstream
  'IS_LOOPBACK_PLUGIN': True,

  'PORT': 5082,
  # Disable tunnel/ngrok since this is localhost only
  'TUNNEL_ENGINE_ENABLED': False,

  # API metadata
  'API_TITLE': 'Local Serving API',
  'API_SUMMARY': 'Local-only FastAPI server for internal services',
  'API_DESCRIPTION': 'A FastAPI server accessible only via localhost without token authentication',

  # Response format - can be WRAPPED or RAW
  'RESPONSE_FORMAT': 'WRAPPED',

  # Enable request logging for debugging
  'LOG_REQUESTS': True,

  # Process delay
  'PROCESS_DELAY': 0,
  'RESULT_CACHE_TTL': 300,
  'REQUEST_TIMEOUT': 240,  # seconds - timeout for postponed requests

  # AI Engine configuration for image analysis
  'AI_ENGINE': 'CERVIGUARD_IMAGE_ANALYZER',  # Serving plugin to use

  'VALIDATION_RULES': {
    **FastApiWebAppPlugin.CONFIG['VALIDATION_RULES'],
    'RESULT_CACHE_TTL': {
      'DESCRIPTION': 'How long to keep results in cache (seconds)',
      'TYPE': 'int',
      'MIN_VAL': 60,
      'MAX_VAL': 3600,
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
    # Initialize instance variables
    self._request_counter = 0
    self._data_buffer = []
    self.__requests = {}  # Track active requests (PostponedRequest pattern)
    self.P("Local Serving API initialized - Loopback mode enabled", color='g')
    self.P(f"  Server accessible only on localhost (no tunnel)", color='g')
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

  # ========== MOCKUP ENDPOINTS ==========

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
    Get current status and statistics
    """
    return {
      "request_count": self._request_counter,
      "buffer_size": len(self._data_buffer),
      "stream_id": self._stream_id,
      "instance_id": self.get_instance_id(),
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def process_data(self, data: dict):
    """
    Process arbitrary data and send it to the loopback queue

    Parameters
    ----------
    data : dict
        The data to process

    Returns
    -------
    dict
        Processing result
    """
    self._request_counter += 1
    request_id = self._request_counter

    self.P(f"Processing data request #{request_id}")

    # Add to buffer
    self._data_buffer.append({
      "request_id": request_id,
      "data": data,
      "timestamp": self.time()
    })

    # Send to loopback queue via add_payload_by_fields
    # This will automatically write to the loopback DCT queue because IS_LOOPBACK_PLUGIN=True
    self.add_payload_by_fields(
      request_id=request_id,
      input_data=data,
      processed_at=self.time(),
      source="local_serving_api"
    )

    return {
      "request_id": request_id,
      "status": "processed",
      "message": "Data sent to loopback queue"
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def process_image(self, image_data: str, metadata: dict = None):
    """
    Process image data (base64 encoded) and send to loopback

    Parameters
    ----------
    image_data : str
        Base64 encoded image data
    metadata : dict, optional
        Additional metadata for the image

    Returns
    -------
    dict
        Processing result
    """
    self._request_counter += 1
    request_id = self._request_counter

    self.P(f"Processing image request #{request_id}")

    # In a real implementation, you would decode the base64 image
    # For this mockup, we just log it

    payload = {
      "request_id": request_id,
      "image_size": len(image_data) if image_data else 0,
      "metadata": metadata or {},
      "processed_at": self.time(),
      "source": "local_serving_api_image"
    }

    # Send to loopback queue
    self.add_payload_by_fields(**payload)

    return {
      "request_id": request_id,
      "status": "image_processed",
      "message": "Image data sent to loopback queue"
    }

  # ========== CERVIGUARD WAR ENDPOINTS ==========

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


  @FastApiWebAppPlugin.endpoint(method="post")
  def cerviguard_submit_image(self, image_data: str, metadata: dict = None):
    """
    CerviGuard WAR: Submit cervical image for analysis using PostponedRequest pattern

    This endpoint is specifically designed for the CerviGuard WAR application.
    It accepts a base64-encoded image and uses PostponedRequest for async processing.

    Parameters
    ----------
    image_data : str
        Base64 encoded cervical image (supports data URLs)
    metadata : dict, optional
        Additional metadata (patient_id, capture_date, etc.)

    Returns
    -------
    dict or PostponedRequest
        Either immediate error or PostponedRequest for async processing
    """
    self.P(f"[CerviGuard] Received cervical image submission", color='b')

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
      request_type='cervical_analysis'
    )

    # Return PostponedRequest - framework will poll solve_postponed_predict_request()
    return self.solve_postponed_predict_request(request_id=request_id)

  #
  @FastApiWebAppPlugin.endpoint(method="get")
  def cerviguard_status(self):
    """
    CerviGuard WAR: Get system status
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
      "total_requests": len(self.__requests),
      "pending_requests": pending,
      "completed_requests": completed,
      "uptime_seconds": self.time() - self.start_time if hasattr(self, 'start_time') else 0,
    }

  @FastApiWebAppPlugin.endpoint(method="get")
  def get_buffer(self, limit: int = 10):
    """
    Get recent data from the buffer

    Parameters
    ----------
    limit : int
        Maximum number of items to return (default: 10)

    Returns
    -------
    dict
        Buffer contents
    """
    return {
      "buffer_size": len(self._data_buffer),
      "limit": limit,
      "items": self._data_buffer[-limit:] if self._data_buffer else []
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def clear_buffer(self):
    """
    Clear the internal data buffer

    Returns
    -------
    dict
        Clear operation result
    """
    prev_size = len(self._data_buffer)
    self._data_buffer = []

    return {
      "status": "cleared",
      "previous_size": prev_size,
      "message": f"Cleared {prev_size} items from buffer"
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def batch_process(self, items: list):
    """
    Process a batch of items

    Parameters
    ----------
    items : list
        List of items to process

    Returns
    -------
    dict
        Batch processing result
    """
    if not isinstance(items, list):
      return {
        "error": "items must be a list",
        "status": "failed"
      }

    batch_id = self.uuid()
    self._request_counter += len(items)

    # Process each item and send to loopback
    for idx, item in enumerate(items):
      self.add_payload_by_fields(
        batch_id=batch_id,
        item_index=idx,
        item_data=item,
        processed_at=self.time(),
        source="local_serving_api_batch"
      )

    return {
      "batch_id": batch_id,
      "items_processed": len(items),
      "status": "batch_completed",
      "message": f"Processed {len(items)} items and sent to loopback queue"
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
      # For CERVIGUARD_IMAGE_ANALYZER, it returns: {'status': 'completed', 'data': {...}}

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

      # Success - extract image info
      image_info = inference_data.get('image_info', {})

      final_result = {
        'status': 'completed',
        'request_id': request_id,
        'image_info': image_info,
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
