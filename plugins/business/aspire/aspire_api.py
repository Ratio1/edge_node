"""
ASPIRE_API Plugin

Production-Grade Autism Spectrum Disorder Screening API

This plugin exposes a hardened, FastAPI-powered interface for the Aspire
autism screening workloads. It reuses the SdInferenceApiPlugin request lifecycle
while tailoring validation and response shaping for clinical structured data.

Highlights
- Loopback-only surface paired with local Aspire clients
- Request tracking, persistence, auth, and rate limiting from BaseInferenceApi
- Structured payload validation for 8 clinical input fields
- Mapping of struct_data payloads and inferences back to requests
"""

from extensions.business.edge_inference_api.sd_inference_api import SdInferenceApiPlugin as BasePlugin

__VER__ = '0.1.0'

# Required input fields for ASD screening
REQUIRED_FIELDS = [
  'developmental_milestones',
  'iq_dq',
  'intellectual_disability',
  'language_disorder',
  'language_development',
  'dysmorphism',
  'behaviour_disorder',
  'neurological_exam',
]

# Valid values for categorical fields
VALID_VALUES = {
  'developmental_milestones': ['N', 'G', 'M', 'C'],
  'intellectual_disability': ['N', 'F70.0', 'F71', 'F72'],
  'language_disorder': ['N', 'Y'],
  'language_development': ['N', 'delay', 'A'],
  'dysmorphism': ['NO', 'Y'],
  'behaviour_disorder': ['N', 'Y'],
}

_CONFIG = {
  **BasePlugin.CONFIG,

  # Server configuration
  'PORT': 5083,

  # API metadata
  'API_TITLE': 'Aspire ASD Screening API',
  'API_SUMMARY': 'Local structured-data API for autism spectrum disorder screening',
  'API_DESCRIPTION': 'FastAPI server for ASD risk assessment using clinical features',

  # AI Engine for data processing
  'AI_ENGINE': 'ASPIRE_ANALYZER',

  # Require all 8 fields
  'MIN_STRUCT_DATA_FIELDS': 8,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class AspireApiPlugin(BasePlugin):
  """
  ASPIRE_API Plugin

  A FastAPI plugin for autism spectrum disorder screening.
  This plugin:
  - Validates 8 clinical input fields
  - Routes requests to the AspireAnalyzer serving plugin
  - Returns structured predictions with risk levels
  - Works with Loopback data capture type pipelines
  """

  CONFIG = _CONFIG

  def _validate_field_value(self, field_name, value):
    """
    Validate a single field value against allowed values.

    Parameters
    ----------
    field_name : str
      Name of the field to validate.
    value : Any
      Value to validate.

    Returns
    -------
    str or None
      Error message if invalid, None if valid.
    """
    if field_name == 'iq_dq':
      try:
        iq_val = float(value)
        if iq_val < 20 or iq_val > 150:
          return f"'iq_dq' must be between 20 and 150, got {value}"
      except (TypeError, ValueError):
        return f"'iq_dq' must be a numeric value, got '{value}'"
      return None

    if field_name == 'neurological_exam':
      if not isinstance(value, str) or len(str(value).strip()) == 0:
        return f"'neurological_exam' must be a non-empty string ('N' for normal or description)"
      return None

    if field_name in VALID_VALUES:
      valid = VALID_VALUES[field_name]
      if value not in valid:
        return f"'{field_name}' must be one of {valid}, got '{value}'"
      return None

    return None

  def check_predict_params(
    self,
    struct_data,
    metadata=None,
    **kwargs
  ):
    """
    Validate input parameters for ASD screening requests.

    Parameters
    ----------
    struct_data : Any
      Structured payload with clinical features.
    metadata : dict or None, optional
      Optional metadata accompanying the request.
    **kwargs
      Additional parameters ignored by validation.

    Returns
    -------
    str or None
      Error message when validation fails, otherwise None.
    """
    # First, run parent validation
    base_error = super().check_predict_params(struct_data, metadata, **kwargs)
    if base_error:
      return base_error

    # Ensure struct_data is a dict (not a list for this API)
    if isinstance(struct_data, list):
      return "For ASD screening, 'struct_data' must be a single dictionary, not a list."

    if not isinstance(struct_data, dict):
      return "'struct_data' must be a dictionary containing clinical features."

    # Check all required fields are present
    missing_fields = [f for f in REQUIRED_FIELDS if f not in struct_data]
    if missing_fields:
      return f"Missing required fields: {', '.join(missing_fields)}"

    # Validate each field value
    for field_name in REQUIRED_FIELDS:
      error = self._validate_field_value(field_name, struct_data.get(field_name))
      if error:
        return error

    return None

  def _build_result_from_inference(
    self,
    request_id,
    inference,
    metadata,
    request_data
  ):
    """
    Construct a result payload from inference output and metadata.

    Parameters
    ----------
    request_id : str
      Identifier of the tracked request.
    inference : dict
      Inference result data from aspire_analyzer.
    metadata : dict
      Metadata to include in the response.
    request_data : dict
      Stored request record for reference.

    Returns
    -------
    dict
      Structured result payload with ASD prediction and risk assessment.

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
      # Return structured error response
      error_payload = {
        'status': 'error',
        'request_id': request_id,
        'error': inference_data.get('error', inference.get('error', 'Unknown error')),
        'error_code': inference_data.get('error_code', inference.get('error_code', 'PROCESSING_ERROR')),
        'error_type': inference_data.get('error_type', inference.get('error_type', 'processing')),
        'error_message': inference_data.get('error_message', inference.get('error_message', 'An error occurred during processing.')),
        'processed_at': inference_data.get('processed_at', self.time()),
        'processor_version': inference_data.get('processor_version', 'unknown'),
        'metadata': metadata or request_data.get('metadata') or {},
      }
      return error_payload

    # Extract prediction results from serving plugin
    result_payload = {
      'status': 'completed',
      'request_id': request_id,
      'prediction': inference_data.get('prediction'),
      'probability': inference_data.get('probability'),
      'confidence': inference_data.get('confidence'),
      'risk_level': inference_data.get('risk_level'),
      'input_summary': inference_data.get('input_summary', {}),
      'processed_at': inference_data.get('processed_at', self.time()),
      'processor_version': inference_data.get('processor_version', 'unknown'),
      'metadata': metadata or request_data.get('metadata') or {},
    }

    return result_payload
