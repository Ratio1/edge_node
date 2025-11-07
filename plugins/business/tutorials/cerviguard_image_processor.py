"""
CerviGuard Image Processor Plugin

Processes payloads that enter the loopback queue (pushed by LOCAL_SERVING_API)
and emits structured result payloads back into that same queue. The API plugin
can then pick up the results via the standard Data API, so no shared-memory
access is required between plugins.
"""

from naeural_core.business.base import BasePluginExecutor as BasePlugin
from extensions.business.tutorials.cerviguard_constants import (
  REQUEST_PAYLOAD_TYPE,
  RESULT_PAYLOAD_TYPE,
)

__VER__ = '0.2.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'ALLOW_EMPTY_INPUTS': True,
  'PROCESS_DELAY': 0.1,  # Fast processing for responsiveness
  'IS_LOOPBACK_PLUGIN': True,  # Results are pushed back into the queue

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class CerviguardImageProcessorPlugin(BasePlugin):
  """
  Image processor plugin for CerviGuard WAR application.

  Reads images from loopback queue, processes them (currently just dimensions),
  and emits result payloads back into the same queue.
  """

  CONFIG = _CONFIG

  def on_init(self):
    super(CerviguardImageProcessorPlugin, self).on_init()
    self._processed_count = 0
    self.P("CerviGuard Image Processor initialized", color='g')
    self.P("  Ready to process images from loopback queue", color='g')
    return

  def _decode_base64_image(self, image_data: str):
    """
    Decode base64 encoded image to a numpy array (returns None on failure).
    """
    try:
      # Handle data URL format (data:image/png;base64,...)
      if ',' in image_data:
        image_data = image_data.split(',', 1)[1]

      img_bytes = self.base64_to_bytes(image_data)
      img = self.PIL.Image.open(self.BytesIO(img_bytes))
      img_array = self.np.array(img)
      return img_array
    except Exception as e:
      self.P(f"Error decoding image: {e}", color='r')
      return None

  def _process_image_dimensions(self, img_array, request_id: str, metadata: dict) -> dict:
    """
    Process image to extract dimensions (current implementation)

    In the future, this will call the CerviGuard AI model for analysis

    Parameters
    ----------
    img_array : np.ndarray
        Image as numpy array
    request_id : str
        Unique request identifier
    metadata : dict
        Additional metadata from request

    Returns
    -------
    dict
        Processing results
    """
    if img_array is None or len(img_array.shape) < 2:
      return {
        'status': 'error',
        'error': 'Invalid image data'
      }

    # Extract dimensions
    height, width = img_array.shape[:2]
    channels = img_array.shape[2] if len(img_array.shape) > 2 else 1

    # Calculate size info
    total_pixels = height * width
    size_mb = img_array.nbytes / (1024 * 1024)

    # Prepare result
    result = {
      'status': 'completed',
      'request_id': request_id,
      'image_info': {
        'width': int(width),
        'height': int(height),
        'channels': int(channels),
        'total_pixels': int(total_pixels),
        'size_mb': round(size_mb, 3),
        'dtype': str(img_array.dtype),
        'shape': list(img_array.shape),
      },
      'processed_at': self.time(),
      'processor_version': __VER__,
      'metadata': metadata,
    }

    # TODO: Future enhancement - call AI model
    # if self.has_ai_engine():
    #   ai_results = self.predict(img_array)
    #   result['ai_analysis'] = ai_results

    return result

  def _get_payload_field(self, data: dict, key: str, default=None):
    if key in data:
      return data[key]
    key_upper = key.upper()
    if key_upper in data:
      return data[key_upper]
    return default

  def process(self):
    """
    Main processing loop - reads from loopback queue and processes images.
    """
    payloads = self.dataapi_struct_datas(full=False, as_list=True)

    if not payloads:
      # No data to process
      return None

    self.P(f"Retrieved {len(payloads)} payload(s) from loopback queue", color='b')

    for payload in payloads:
      if not isinstance(payload, dict):
        self.P(f"Skipping non-dict payload from loopback: {payload}", color='y')
        continue
      self._process_payload(payload)

    return None


  def _process_payload(self, data: dict):
    """
    Handle a single payload emitted through the loopback queue.
    """
    payload_type = self._get_payload_field(data, 'payload_type')
    if payload_type != REQUEST_PAYLOAD_TYPE:
      self.P(f"Ignoring payload type '{payload_type}'", color='c')
      return

    # Extract request info
    request_id = self._get_payload_field(data, 'request_id')
    image_data = self._get_payload_field(data, 'image_data')
    metadata = self._get_payload_field(data, 'metadata', {}) or {}

    if not request_id:
      self.P("Received data without request_id, ignoring", color='y')
      return

    if not image_data:
      self._emit_error(request_id, 'Missing image data')
      return

    self.P(f"Processing request {request_id} (keys={list(data.keys())})", color='b')

    # Decode image
    img_array = self._decode_base64_image(image_data)

    if img_array is None:
      self._emit_error(request_id, 'Failed to decode image')
      return

    # Process image (get dimensions, later AI analysis)
    result = self._process_image_dimensions(img_array, request_id, metadata)

    # Emit result payload back into loopback queue
    self.add_payload_by_fields(
      payload_type=RESULT_PAYLOAD_TYPE,
      request_id=request_id,
      result=result,
    )

    self._processed_count += 1
    self.P(f"Completed processing request {request_id} (total: {self._processed_count})", color='g')
    return

  def _emit_error(self, request_id, message):
    self.P(f"Request {request_id} failed: {message}", color='r')
    error_payload = {
      'status': 'error',
      'error': message,
      'request_id': request_id,
    }
    self.add_payload_by_fields(
      payload_type=RESULT_PAYLOAD_TYPE,
      request_id=request_id,
      result=error_payload,
    )
    return
