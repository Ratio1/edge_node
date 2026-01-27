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

from extensions.business.edge_inference_api.cv_inference_api import CvInferenceApiPlugin as BasePlugin

__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  # Server configuration
  'PORT': 5082,

  # API metadata
  'API_TITLE': 'CerviGuard Local Serving API',
  'API_SUMMARY': 'Local image analysis API for CerviGuard',
  'API_DESCRIPTION': 'FastAPI server for cervical image analysis',

  # AI Engine for image processing
  'AI_ENGINE': 'CERVIGUARD_IMAGE_ANALYZER',

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class CerviguardApiPlugin(BasePlugin):
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

  def _build_result_from_inference(
    self,
    request_id: str,
    inference: dict,
    metadata: dict,
    request_data: dict
  ):
    """
    Construct a result payload from inference output and metadata.

    Parameters
    ----------
    request_id : str
      Identifier of the tracked request.
    inference : dict
      Inference result data from cerviguard_image_analyzer.
    metadata : dict
      Metadata to include in the response.
    request_data : dict
      Stored request record for reference.

    Returns
    -------
    dict
      Structured result payload with lesion and transformation zone predictions.

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

    # Extract analysis from serving plugin (contains lesion and transformation_zone)
    analysis = inference_data.get('analysis', {})
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

    return result_payload
