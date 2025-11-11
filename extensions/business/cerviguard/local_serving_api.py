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
from extensions.business.cerviguard.cerviguard_constants import (
  REQUEST_PAYLOAD_TYPE,
  RESULT_PAYLOAD_TYPE,
)

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
    self._results_cache = {}
    self._last_result_cleanup = self.time()
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
    Simple /predict endpoint for image analysis

    Simplified endpoint that accepts an image and returns a request ID.
    This is the main endpoint for the cerviguard flow:
    1. Receives base64 image
    2. Adds to loopback queue via add_payload_by_fields
    3. Serving plugin processes the image
    4. Results cached for polling

    Parameters
    ----------
    image_data : str
        Base64 encoded image (supports data URLs)
    metadata : dict, optional
        Additional metadata

    Returns
    -------
    dict
        Request ID and status for polling
    """
    # Generate unique request ID
    request_id = self.uuid()

    self.P(f"[Predict] Received image, request_id: {request_id}", color='b')

    # Validate image data
    if not image_data or len(image_data) < 100:
      return {
        "status": "error",
        "error": "Invalid or missing image data",
        "message": "Image data must be base64 encoded"
      }

    # Track request
    self._data_buffer.append({
      "request_id": request_id,
      "type": "prediction",
      "submitted_at": self.time(),
      "metadata": metadata or {}
    })

    # STEP 3: Send to loopback queue via add_payload_by_fields
    # Because IS_LOOPBACK_PLUGIN=True, this writes to loopback_dct_{stream_id} queue
    self.add_payload_by_fields(
      payload_type=REQUEST_PAYLOAD_TYPE,
      request_id=request_id,
      image_data=image_data,
      metadata=metadata or {},
      type="prediction",
      submitted_at=self.time()
    )

    self.P(f"[Predict] Image added to loopback queue: {request_id}", color='g')

    return {
      "status": "submitted",
      "request_id": request_id,
      "message": "Image queued for analysis",
      "poll_endpoint": f"/get_result?request_id={request_id}"
    }

  @FastApiWebAppPlugin.endpoint(method="get")
  def get_result(self, request_id: str):
    """
    Get prediction result for /predict endpoint

    Poll this endpoint to retrieve the processing result.
    """
    if not request_id:
      return {
        "status": "error",
        "error": "Missing request_id parameter"
      }

    self.P(f"[Predict] Result requested for: {request_id}", color='b')

    result = self._results_cache.get(request_id)

    if result is None:
      submitted = any(
        item.get('request_id') == request_id
        for item in self._data_buffer
      )

      if submitted:
        return {
          "status": "processing",
          "request_id": request_id,
          "message": "Image is still being processed, please poll again"
        }
      else:
        return {
          "status": "not_found",
          "request_id": request_id,
          "error": "Request ID not found"
        }

    self.P(f"[Predict] Returning result for: {request_id}", color='g')

    return {
      "status": "completed",
      "request_id": request_id,
      "result": result['result']
    }

  @FastApiWebAppPlugin.endpoint(method="post")
  def cerviguard_submit_image(self, image_data: str, metadata: dict = None):
    """
    CerviGuard WAR: Submit cervical image for analysis

    This endpoint is specifically designed for the CerviGuard WAR application.
    It accepts a base64-encoded image, assigns a request ID, and queues it
    for processing via the loopback mechanism.

    Parameters
    ----------
    image_data : str
        Base64 encoded cervical image (supports data URLs)
    metadata : dict, optional
        Additional metadata (patient_id, capture_date, etc.)

    Returns
    -------
    dict
        Request ID and status for polling
    """
    # Generate unique request ID
    request_id = self.uuid()

    self.P(f"[CerviGuard] Received image submission, request_id: {request_id}", color='b')

    # Validate image data
    if not image_data or len(image_data) < 100:
      return {
        "status": "error",
        "error": "Invalid or missing image data",
        "message": "Image data must be base64 encoded"
      }

    # Track request
    self._data_buffer.append({
      "request_id": request_id,
      "type": "cervical_analysis",
      "submitted_at": self.time(),
      "metadata": metadata or {}
    })

    # Send to loopback queue
    # This will be picked up by CerviguardImageProcessorPlugin
    self.add_payload_by_fields(
      payload_type=REQUEST_PAYLOAD_TYPE,
      request_id=request_id,
      image_data=image_data,
      metadata=metadata or {},
      type="cervical_analysis",
      submitted_at=self.time()
    )

    self.P(f"[CerviGuard] Image queued for processing: {request_id}", color='g')

    return {
      "status": "submitted",
      "request_id": request_id,
      "message": "Image queued for analysis",
      "poll_endpoint": f"/cerviguard_get_result?request_id={request_id}"
    }

  @FastApiWebAppPlugin.endpoint(method="get")
  def cerviguard_get_result(self, request_id: str):
    """
    CerviGuard WAR: Get image analysis result

    Poll this endpoint to retrieve the processing result for a submitted image.
    """
    if not request_id:
      return {
        "status": "error",
        "error": "Missing request_id parameter"
      }

    self.P(f"[CerviGuard] Result requested for: {request_id}", color='b')

    result = self._results_cache.get(request_id)

    if result is None:
      submitted = any(
        item.get('request_id') == request_id
        for item in self._data_buffer
      )

      if submitted:
        return {
          "status": "processing",
          "request_id": request_id,
          "message": "Image is still being processed, please poll again"
        }
      else:
        return {
          "status": "not_found",
          "request_id": request_id,
          "error": "Request ID not found"
        }

    self.P(f"[CerviGuard] Returning result for: {request_id}", color='g')

    return {
      "status": "completed",
      "request_id": request_id,
      "result": result['result']
    }
  #
  @FastApiWebAppPlugin.endpoint(method="get")
  def cerviguard_status(self):
    """
    CerviGuard WAR: Get system status
    """
    pending = len([
      item for item in self._data_buffer
      if item.get('request_id') not in self._results_cache
    ])
    return {
      "status": "online",
      "service": "CerviGuard Image Analysis",
      "version": __VER__,
      "total_requests": self._request_counter,
      "pending_requests": pending,
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
    4. Cache results for retrieval via API
    """
    self._cleanup_result_cache()
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
    1. Check if it's a REQUEST_PAYLOAD_TYPE
    2. Extract inference result from serving plugin
    3. Cache result for API retrieval

    Parameters
    ----------
    payload : dict
        The original payload with request_id, image_data, metadata
    inference : dict
        The inference result from the serving plugin (already processed)
    """
    if not isinstance(payload, dict):
      return

    payload_type = self._get_payload_field(payload, 'payload_type')
    if payload_type != REQUEST_PAYLOAD_TYPE:
      # Not a request we should process
      return

    # Extract request info from payload
    request_id = self._get_payload_field(payload, 'request_id')
    metadata = self._get_payload_field(payload, 'metadata', {}) or {}

    if not request_id:
      self.P("Received payload without request_id, ignoring", color='y')
      return

    if inference is None:
      self.P(f"No inference available for request {request_id}", color='y')
      self._cache_error_result(request_id, 'No inference result available')
      return

    self.P(f"[CerviGuard] Processing inference for request {request_id}", color='b')

    try:
      # The serving plugin returns inferences in a specific format
      # For CERVIGUARD_IMAGE_ANALYZER, it returns: {'status': 'completed', 'data': {...}}

      if not isinstance(inference, dict):
        self.P(f"Unexpected inference format: {type(inference)}", color='r')
        self._cache_error_result(request_id, 'Invalid inference result format')
        return

      # Extract the inference data
      # Inference can be the result dict directly or wrapped
      inference_data = inference.get('data', inference) if 'data' in inference else inference

      # Check status
      status = inference_data.get('status', 'unknown')

      if status == 'error':
        error_msg = inference_data.get('error', 'Unknown error')
        self._cache_error_result(request_id, error_msg)
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

      # Cache the result
      self._results_cache[request_id] = {
        'result': final_result,
        'stored_at': self.time(),
      }

      self.P(f"[CerviGuard] Cached result for request {request_id}", color='g')

    except Exception as e:
      self.P(f"Error processing request {request_id}: {e}", color='r')
      import traceback
      self.P(traceback.format_exc(), color='r')
      self._cache_error_result(request_id, f'Processing error: {str(e)}')

    return

  def _cache_error_result(self, request_id: str, error_message: str):
    """Cache an error result for a request"""
    self.P(f"[CerviGuard] Caching error for request {request_id}: {error_message}", color='r')

    error_result = {
      'status': 'error',
      'error': error_message,
      'request_id': request_id,
      'processed_at': self.time(),
    }

    self._results_cache[request_id] = {
      'result': error_result,
      'stored_at': self.time(),
    }
    return

  def _cleanup_result_cache(self):
    now = self.time()
    if now - self._last_result_cleanup < 60:
      return
    self._last_result_cleanup = now

    ttl = self.cfg_result_cache_ttl
    expired = [
      req_id for req_id, data in self._results_cache.items()
      if now - data['stored_at'] > ttl
    ]
    for req_id in expired:
      del self._results_cache[req_id]
    if expired:
      self.P(f"[CerviGuard] Cleaned {len(expired)} cached results", color='y')
    return

  def _maybe_trim_buffer(self):
    if len(self._data_buffer) > 100:
      self._data_buffer = self._data_buffer[-100:]
    return
