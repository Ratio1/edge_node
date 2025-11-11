"""
CerviGuard Image Analyzer - Serving Plugin

A serving plugin that analyzes cervical images from base64 encoded data.
Currently extracts image dimensions and properties as a mockup for future
AI-based cervical cancer detection models.

This serving plugin runs in an isolated process and provides:
- Base64 image decoding
- Image dimension extraction
- Format and color space analysis
- Future placeholder for AI model inference

Usage in pipeline:
{
  "PLUGINS": [
    {
      "SIGNATURE": "A_SIMPLE_PLUGIN",
      "INSTANCES": [
        {
          "INSTANCE_ID": "cerviguard_01",
          "AI_ENGINE": "CERVIGUARD_IMAGE_ANALYZER"
        }
      ]
    }
  ]
}
"""

from naeural_core.serving.base import ModelServingProcess as BaseServingProcess

import base64
from PIL import Image
from io import BytesIO

__VER__ = '0.1.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  # Accept STRUCT_DATA input (base64 encoded images)
  "PICKED_INPUT": "STRUCT_DATA",

  # Allow running without input for initialization
  "RUNS_ON_EMPTY_INPUT": False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class CerviguardImageAnalyzer(BaseServingProcess):
  """
  Serving plugin for CerviGuard cervical image analysis.

  Processes base64 encoded images and extracts dimensional and
  color information. Designed to be extended with AI models for
  cervical cancer detection.
  """

  CONFIG = _CONFIG

  def on_init(self):
    """
    Initialize the serving plugin.
    Called once during startup.
    """
    super(CerviguardImageAnalyzer, self).on_init()
    self._processed_count = 0
    self.P("CerviGuard Image Analyzer initialized", color='g')
    self.P(f"  Version: {__VER__}", color='g')
    self.P(f"  Accepts STRUCT_DATA input (base64 images)", color='g')
    return

  def _decode_base64_image(self, image_data):
    """
    Decode base64 encoded image to numpy array.

    Parameters
    ----------
    image_data : str or dict
        Base64 encoded image string or dict containing 'image_data' key

    Returns
    -------
    np.ndarray or None
        Decoded image as numpy array, or None if decoding fails
    """
    try:
      # Handle dict input with 'image_data' key
      if isinstance(image_data, dict):
        if 'image_data' in image_data:
          image_data = image_data['image_data']
        elif 'IMAGE_DATA' in image_data:
          image_data = image_data['IMAGE_DATA']
        else:
          self.P("Dict input missing 'image_data' key", color='r')
          return None

      # Handle data URL format (data:image/png;base64,...)
      if isinstance(image_data, str) and ',' in image_data:
        image_data = image_data.split(',', 1)[1]

      # Decode base64 to bytes
      img_bytes = base64.b64decode(image_data)

      # Convert to PIL Image
      img = Image.open(BytesIO(img_bytes))

      # Convert to numpy array
      img_array = self.np.array(img)

      return img_array
    except Exception as e:
      self.P(f"Error decoding image: {e}", color='r')
      return None

  def _extract_image_info(self, img_array):
    """
    Extract comprehensive information from image array.

    Parameters
    ----------
    img_array : np.ndarray
        Image as numpy array

    Returns
    -------
    dict
        Dictionary with image properties
    """
    if img_array is None or len(img_array.shape) < 2:
      return {
        'error': 'Invalid image data',
        'valid': False
      }

    # Extract basic dimensions
    height, width = img_array.shape[:2]
    channels = img_array.shape[2] if len(img_array.shape) > 2 else 1

    # Calculate size info
    total_pixels = height * width
    size_mb = img_array.nbytes / (1024 * 1024)

    result = {
      'valid': True,
      'width': int(width),
      'height': int(height),
      'channels': int(channels),
      'total_pixels': int(total_pixels),
      'size_mb': round(size_mb, 3),
      'dtype': str(img_array.dtype),
      'shape': list(img_array.shape),
    }

    # Add color information for RGB images
    if channels >= 3:
      result['color_info'] = {
        'mean_r': float(img_array[:, :, 0].mean()),
        'mean_g': float(img_array[:, :, 1].mean()),
        'mean_b': float(img_array[:, :, 2].mean()),
        'std_r': float(img_array[:, :, 0].std()),
        'std_g': float(img_array[:, :, 1].std()),
        'std_b': float(img_array[:, :, 2].std()),
      }

    # Add quality assessment
    result['quality_info'] = {
      'resolution_category': self._categorize_resolution(width, height),
      'aspect_ratio': round(width / height, 3) if height > 0 else 0,
      'is_square': abs(width - height) < 10,
    }

    return result

  def _categorize_resolution(self, width, height):
    """
    Categorize image resolution for quality assessment.

    Parameters
    ----------
    width : int
        Image width in pixels
    height : int
        Image height in pixels

    Returns
    -------
    str
        Resolution category
    """
    total_pixels = width * height

    if total_pixels < 100000:  # < 0.1 MP
      return 'very_low'
    elif total_pixels < 500000:  # < 0.5 MP
      return 'low'
    elif total_pixels < 2000000:  # < 2 MP
      return 'medium'
    elif total_pixels < 5000000:  # < 5 MP
      return 'high'
    else:
      return 'very_high'

  def _pre_process(self, inputs):
    """
    Pre-process inputs: decode base64 images to numpy arrays.

    Parameters
    ----------
    inputs : dict
        Input dictionary with 'DATA' key containing list of base64 images

    Returns
    -------
    list
        List of decoded image arrays
    """
    lst_inputs = inputs.get('DATA', [])
    serving_params = inputs.get('SERVING_PARAMS', [])

    self.P(f"Pre-processing {len(lst_inputs)} input(s)", color='b')

    # DEBUG: Log what we received
    for i, inp in enumerate(lst_inputs):
      if isinstance(inp, dict):
        self.P(f"  Input #{i} keys: {list(inp.keys())}", color='y')
      else:
        self.P(f"  Input #{i} type: {type(inp)}", color='y')

    preprocessed = []
    for i, inp in enumerate(lst_inputs):
      # Get serving params for this specific input
      params = serving_params[i] if i < len(serving_params) else {}

      # Decode the base64 image
      img_array = self._decode_base64_image(inp)

      preprocessed.append({
        'image': img_array,
        'params': params,
        'index': i,
      })

    return preprocessed

  def _predict(self, inputs):
    """
    Main prediction: extract image information.

    In the future, this will call the actual AI model for cervical
    cancer detection.

    Parameters
    ----------
    inputs : list
        List of preprocessed inputs (decoded images)

    Returns
    -------
    list
        List of analysis results
    """
    self._processed_count += 1

    results = []
    for inp_data in inputs:
      img_array = inp_data['image']
      params = inp_data['params']
      idx = inp_data['index']

      if img_array is None:
        results.append({
          'index': idx,
          'error': 'Failed to decode image',
          'valid': False
        })
        continue

      # Extract image information
      image_info = self._extract_image_info(img_array)

      # Add processing metadata
      result = {
        'index': idx,
        'image_info': image_info,
        'processed_at': self.time(),
        'processor_version': __VER__,
        'model_name': 'cerviguard_image_analyzer',
        'iteration': self._processed_count,
      }

      # TODO: Future enhancement - call AI model for cervical cancer detection
      # if self.has_ai_model():
      #   ai_prediction = self.run_ai_model(img_array)
      #   result['ai_analysis'] = ai_prediction
      #   result['risk_level'] = ai_prediction['risk_level']
      #   result['confidence'] = ai_prediction['confidence']

      results.append(result)

    return results

  def _post_process(self, preds):
    """
    Post-process predictions: format for output.

    Parameters
    ----------
    preds : list
        List of prediction results

    Returns
    -------
    list
        Formatted results ready for return
    """
    self.P(f"Post-processing {len(preds)} result(s)", color='b')

    formatted_results = []
    for pred in preds:
      # Format the result for output
      formatted = {
        'status': 'completed' if pred.get('image_info', {}).get('valid', False) else 'error',
        'data': pred,
      }

      # Add error message if present
      if 'error' in pred:
        formatted['error'] = pred['error']

      formatted_results.append(formatted)

    return formatted_results
