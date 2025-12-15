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
          "AI_ENGINE": "cerviguard_analyzer"
        }
      ]
    }
  ]
}
"""

import base64
from io import BytesIO
from PIL import Image

from naeural_core.serving.base import ModelServingProcess as BaseServingProcess

__VER__ = '0.1.2'

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
    self.rng = self.np.random.default_rng()
    self.base_risks = {'none': 10, 'low': 30, 'moderate': 55, 'high': 75}
    self.tz_descriptions = {
      'Type 0': 'Type 0 transformation zone (normal-appearing cervix, no visible lesions).',
      'Type 1': 'Type 1 transformation zone (fully ectocervical and fully visible).',
      'Type 2': 'Type 2 transformation zone (partly endocervical but fully visible).',
      'Type 3': 'Type 3 transformation zone (endocervical and not fully visible).'
    }
    self.lesion_text = {
      'none': 'No significant acetowhite or vascular changes seen.',
      'low': 'Minor acetowhite changes with regular vascular patterns; low-grade lesion possible.',
      'moderate': 'Acetowhite epithelium with irregular vessels; moderate-grade lesion suspected.',
      'high': 'Dense acetowhite areas with atypical vessels; high-grade lesion suspected.'
    }
    self.lesion_templates = {
      'Type 3': {
        'none': 'No obvious ectocervical lesions, but assessment is limited because the transformation zone is not fully visible; colposcopy with endocervical evaluation is recommended.',
        'low': 'Subtle acetowhite change seen on the ectocervix; Type 3 zone limits visualization—colposcopy/endocervical sampling advised.',
        'moderate': 'Suspicious acetowhite and vascular changes with a Type 3 zone; colposcopy and endocervical assessment recommended.',
        'high': 'Marked high-grade features with a Type 3 zone; urgent colposcopy with endocervical evaluation recommended.'
      },
      'Type 0': {
        'none': 'No lesions detected; cervix appears normal.',
        'low': 'Minor findings noted, but overall appearance is normal; routine screening advised.',
        'moderate': 'Patchy findings with otherwise normal cervix; consider follow-up colposcopy.',
        'high': 'Focal concerning area despite overall normal appearance; colposcopy recommended.'
      },
      'default': {
        'none': f"{self.lesion_text['none']} Routine screening appropriate.",
        'low': f"{self.lesion_text['low']} Follow-up in 6-12 months recommended.",
        'moderate': f"{self.lesion_text['moderate']} Colposcopy and biopsy recommended.",
        'high': f"{self.lesion_text['high']} Immediate colposcopy and biopsy strongly recommended."
      }
    }
    self.P("CerviGuard Image Analyzer initialized", color='g')
    self.P(f"  Version: {__VER__}", color='g')
    self.P(f"  Accepts STRUCT_DATA input (base64 images)", color='g')

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

  def _generate_cervical_analysis(self, img_array, image_info):
    """
    Generate cervical screening analysis results.

    This is a mock implementation that generates plausible analysis based on
    image characteristics. In production, this would be replaced with actual
    ML model inference for cervical cancer detection.

    Parameters
    ----------
    img_array : np.ndarray
        Image as numpy array
    image_info : dict
        Extracted image information

    Returns
    -------
    dict
        Analysis results with tz_type, lesion_assessment, lesion_summary, and risk_score
    """
    if img_array is None or not image_info.get('valid', False):
      return {
        'tz_type': 'Type 1',
        'lesion_assessment': 'none',
        'lesion_summary': 'Image quality insufficient for analysis',
        'risk_score': 0
      }

    quality_info = image_info.get('quality_info', {})
    resolution_category = quality_info.get('resolution_category', 'unknown')
    image_quality_sufficient = resolution_category not in ['very_low', 'low']

    # Purely random (but internally consistent) lesion and TZ selection
    rng = self.rng

    tz_type = rng.choice(
      ['Type 0', 'Type 1', 'Type 2', 'Type 3'],
      p=[0.2, 0.3, 0.25, 0.25]
    )

    lesion_assessment = rng.choice(
      ['none', 'low', 'moderate', 'high'],
      p=[0.35, 0.3, 0.2, 0.15]
    )

    risk_score = self.base_risks[lesion_assessment]

    img_width = image_info.get('width', 0)
    img_height = image_info.get('height', 0)

    visualization_limited = tz_type == 'Type 3'
    if tz_type == 'Type 3':
      risk_score = max(risk_score, 40)

    if resolution_category in ['very_low', 'low']:
      quality_note = f"Image resolution ({img_width}x{img_height}) limits detailed assessment."
    elif resolution_category == 'medium':
      quality_note = f"Image resolution ({img_width}x{img_height}) is adequate for analysis."
    else:
      quality_note = f"Image resolution ({img_width}x{img_height}) is optimal for analysis."

    if tz_type == 'Type 3':
      lesion_templates = self.lesion_templates['Type 3']
    elif tz_type == 'Type 0':
      lesion_templates = self.lesion_templates['Type 0']
    else:
      lesion_templates = self.lesion_templates['default']

    lesion_summary = " ".join([
      self.tz_descriptions.get(tz_type, tz_type),
      lesion_templates.get(lesion_assessment, self.lesion_text['none']),
      quality_note
    ])

    return {
      'tz_type': tz_type,
      'lesion_assessment': lesion_assessment,
      'lesion_summary': lesion_summary,
      'risk_score': risk_score,
      'image_quality': resolution_category,
      'image_quality_sufficient': image_quality_sufficient,
      'assessment_confidence': 'reduced' if visualization_limited else 'normal'
    }

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

    self.P(f"Pre-processing {len(lst_inputs)} input(s)", color='b')

    # DEBUG: Log what we received
    for i, inp in enumerate(lst_inputs):
      if isinstance(inp, dict):
        self.P(f"  Input #{i} keys: {list(inp.keys())}", color='y')
      else:
        self.P(f"  Input #{i} type: {type(inp)}", color='y')

    preprocessed = []
    for i, inp in enumerate(lst_inputs):
      # Decode the base64 image
      img_array = self._decode_base64_image(inp)

      preprocessed.append({
        'image': img_array,
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

      # Generate cervical screening analysis
      analysis = self._generate_cervical_analysis(img_array, image_info)

      # Add processing metadata
      result = {
        'index': idx,
        'image_info': image_info,
        'analysis': analysis,
        'processed_at': self.time(),
        'processor_version': __VER__,
        'model_name': 'cerviguard_image_analyzer',
        'iteration': self._processed_count,
      }

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
