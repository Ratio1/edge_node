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
import numpy as np
import torch

from naeural_core.serving.base import ModelServingProcess as BaseServingProcess

__VER__ = '0.3.0'


class SimpleImageProcessor:
  """Simple image processor for custom CNN models."""

  def __init__(self, size=(256, 256)):
    self.size = size if isinstance(size, tuple) else (size, size)

  def __call__(self, images, return_tensors="pt"):
    if not isinstance(images, list):
      images = [images]

    processed = []
    for img in images:
      if isinstance(img, np.ndarray):
        img = Image.fromarray(img)

      # Resize to expected size (height, width) -> PIL uses (width, height)
      img = img.resize((self.size[1], self.size[0]), Image.Resampling.BILINEAR)

      # Convert to tensor and normalize to [0, 1]
      img_array = np.array(img).astype(np.float32) / 255.0

      # HWC to CHW
      if img_array.ndim == 3:
        img_array = img_array.transpose(2, 0, 1)

      processed.append(torch.tensor(img_array))

    if return_tensors == "pt":
      return {"pixel_values": torch.stack(processed)}
    return processed

_CONFIG = {
  **BaseServingProcess.CONFIG,

  # Accept STRUCT_DATA input (base64 encoded images)
  "PICKED_INPUT": "STRUCT_DATA",

  # Allow running without input for initialization
  "RUNS_ON_EMPTY_INPUT": False,

  # Image validation settings (uses model_1/ImageNet to detect non-medical images)
  # If ImageNet confidently recognizes an object, it's not a cervical image
  "IMAGE_VALIDATION_ENABLED": True,
  "IMAGE_VALIDATION_CONFIDENCE_THRESHOLD": 0.30,  # 30% - reject if ImageNet is this confident

  # HuggingFace model configurations
  # Model 1: Lightweight ImageNet classifier (MobileNetV2) - used for image validation
  "MODEL_1_NAME": "google/mobilenet_v2_1.0_224",
  "MODEL_1_ENABLED": True,
  "MODEL_1_TYPE": "huggingface",  # "huggingface" or "custom"
  "MODEL_1_CLASS_NAME": None,  # Only needed for custom models

  # Model 2: Custom CerviGuard lesion model
  "MODEL_2_NAME": None,  # e.g., "toderian/cerviguard_lesion"
  "MODEL_2_ENABLED": False,
  "MODEL_2_TYPE": "custom",  # Custom model with model.py
  "MODEL_2_CLASS_NAME": "CervicalCancerCNN",  # Class name in model.py

  # Model 3: Custom CerviGuard transfer zones model
  "MODEL_3_NAME": None,  # e.g., "toderian/cerviguard_transfer_zones"
  "MODEL_3_ENABLED": False,
  "MODEL_3_TYPE": "custom",  # Custom model with model.py
  "MODEL_3_CLASS_NAME": "BaseCNN",  # Class name in model.py

  # HuggingFace token for private models (optional)
  "HF_TOKEN": None,

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

    # Initialize model containers
    self.model_1 = None
    self.model_2 = None
    self.model_3 = None
    self.processor_1 = None
    self.processor_2 = None
    self.processor_3 = None
    self.model_1_type = None
    self.model_2_type = None
    self.model_3_type = None

    # Load HuggingFace models
    self._load_hf_models()

    self.P("CerviGuard Image Analyzer initialized", color='g')
    self.P(f"  Version: {__VER__}", color='g')
    self.P(f"  Accepts STRUCT_DATA input (base64 images)", color='g')
    if self.cfg_image_validation_enabled:
      self.P(f"  Image validation: ENABLED (threshold: {self.cfg_image_validation_confidence_threshold:.0%})", color='g')
    else:
      self.P(f"  Image validation: DISABLED", color='y')

    return

  def _validate_image_content(self, model_1_result):
    """
    Validate image content using ImageNet classification confidence.

    Medical/cervical images confuse ImageNet, resulting in low confidence
    spread across random classes. Real everyday objects (cats, cars, etc.)
    get high confidence classifications.

    Parameters
    ----------
    model_1_result : dict
        Result from model_1 (ImageNet) inference.

    Returns
    -------
    dict
        Validation result with 'valid' bool and 'reason' string.
    """
    if not self.cfg_image_validation_enabled:
      return {'valid': True, 'reason': 'Validation disabled'}

    if model_1_result is None or 'error' in model_1_result:
      return {'valid': True, 'reason': 'ImageNet model not available'}

    top_confidence = model_1_result.get('top_confidence', 0)
    top_label = model_1_result.get('top_label', 'unknown')
    threshold = self.cfg_image_validation_confidence_threshold

    if top_confidence >= threshold:
      return {
        'valid': False,
        'reason': f"Image rejected: ImageNet detected '{top_label}' with {top_confidence:.1%} confidence. "
                  f"This does not appear to be a valid cervical image.",
        'detected_label': top_label,
        'confidence': top_confidence
      }

    return {
      'valid': True,
      'reason': f"Image passed validation (ImageNet confidence {top_confidence:.1%} < {threshold:.0%} threshold)",
      'top_label': top_label,
      'confidence': top_confidence
    }

  def _get_cache_dir(self):
    """Get the cache directory for HuggingFace models."""
    return self.log.get_models_folder()

  def _get_device(self):
    """Get the device for model inference (GPU if available, else CPU)."""
    try:
      import torch as th
      if th.cuda.is_available():
        return th.device('cuda')
      return th.device('cpu')
    except Exception:
      return 'cpu'

  def _load_module_from_path(self, module_name, file_path):
    """Load a Python module from a file path (avoids import caching issues)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

  def _load_standard_hf_model(self, model_name, model_num):
    """Load a standard HuggingFace transformers model."""
    try:
      from transformers import AutoImageProcessor, AutoModelForImageClassification

      cache_dir = self._get_cache_dir()
      hf_token = self.cfg_hf_token

      self.P(f"Loading Model {model_num}: {model_name} (Standard HF)...", color='b')
      self.P(f"  Cache directory: {cache_dir}", color='b')

      # Load the image processor
      processor = AutoImageProcessor.from_pretrained(
        model_name,
        cache_dir=cache_dir,
        token=hf_token,
      )

      # Load the model
      model = AutoModelForImageClassification.from_pretrained(
        model_name,
        cache_dir=cache_dir,
        token=hf_token,
      )

      # Move model to device
      device = self._get_device()
      model = model.to(device)
      model.eval()

      self.P(f"  Model {model_num} loaded successfully on {device}", color='g')
      self.P(f"  Model labels: {len(model.config.id2label)} classes", color='g')

      return model, processor, "huggingface"

    except Exception as e:
      self.P(f"Error loading Model {model_num} ({model_name}): {e}", color='r')
      return None, None, None

  def _load_custom_model(self, model_name, model_num, class_name):
    """
    Load a custom model from HuggingFace with model.py definition.

    Parameters
    ----------
    model_name : str
        HuggingFace model ID (e.g., 'toderian/cerviguard_lesion')
    model_num : int
        Model number (1, 2, or 3) for logging
    class_name : str
        Name of the model class in model.py (e.g., 'CervicalCancerCNN')

    Returns
    -------
    tuple
        (model, processor, model_type) or (None, None, None) if loading fails
    """
    try:
      import torch as th
      import json
      from pathlib import Path
      from huggingface_hub import snapshot_download

      cache_dir = self._get_cache_dir()
      hf_token = self.cfg_hf_token

      self.P(f"Loading Model {model_num}: {model_name} (Custom: {class_name})...", color='b')
      self.P(f"  Cache directory: {cache_dir}", color='b')

      # Download model files
      model_dir = snapshot_download(
        repo_id=model_name,
        cache_dir=cache_dir,
        token=hf_token,
      )
      model_path = Path(model_dir)
      self.P(f"  Downloaded to: {model_dir}", color='b')

      # Load config
      config_path = model_path / "config.json"
      with open(config_path, 'r') as f:
        config = json.load(f)
      self.P(f"  Config model_type: {config.get('model_type', 'unknown')}", color='b')

      # Load the model module dynamically
      model_py = model_path / "model.py"
      if not model_py.exists():
        raise FileNotFoundError(f"model.py not found in {model_path}")

      unique_module_name = f"model_{model_name.replace('/', '_')}"
      model_module = self._load_module_from_path(unique_module_name, model_py)

      # Get the model class
      if not hasattr(model_module, class_name):
        available = [x for x in dir(model_module) if not x.startswith('_')]
        raise AttributeError(f"Class '{class_name}' not found. Available: {available}")

      ModelClass = getattr(model_module, class_name)

      # Check if there's a from_pretrained method
      if hasattr(ModelClass, 'from_pretrained'):
        device = str(self._get_device())
        model = ModelClass.from_pretrained(str(model_path), device=device)
        self.P(f"  Loaded via {class_name}.from_pretrained()", color='g')
      else:
        # Create model and load weights manually
        model_config = config.get('model_config', {})
        if class_name == "CervicalCancerCNN":
          model = ModelClass(config=model_config)
        else:
          model = ModelClass(**model_config)

        # Load weights
        safetensors_path = model_path / 'model.safetensors'
        pytorch_path = model_path / 'pytorch_model.bin'

        if safetensors_path.exists():
          try:
            from safetensors.torch import load_file
            state_dict = load_file(str(safetensors_path))
          except ImportError:
            state_dict = th.load(pytorch_path, map_location='cpu', weights_only=True)
        elif pytorch_path.exists():
          state_dict = th.load(pytorch_path, map_location='cpu', weights_only=True)
        else:
          raise FileNotFoundError("No model weights found")

        model.load_state_dict(state_dict)
        self.P(f"  Loaded weights manually", color='g')

      device = self._get_device()
      model = model.to(device)
      model.eval()

      # Get labels
      id2label = config.get('id2label', {})
      if not id2label and hasattr(ModelClass, 'CLASSES'):
        id2label = ModelClass.CLASSES
      model.id2label = {int(k) if isinstance(k, str) else k: v for k, v in id2label.items()}

      # Get input size from config
      input_size = (256, 256)
      if 'input_size' in config:
        size_config = config['input_size']
        if isinstance(size_config, dict):
          input_size = (int(size_config['height']), int(size_config['width']))
        else:
          input_size = tuple(int(x) for x in size_config)
      elif class_name == "CervicalCancerCNN":
        input_size = (224, 298)

      processor = SimpleImageProcessor(size=input_size)

      self.P(f"  Model {model_num} loaded on {device}, classes: {model.id2label}", color='g')
      return model, processor, "custom"

    except Exception as e:
      self.P(f"Error loading Model {model_num} ({model_name}): {e}", color='r')
      import traceback
      self.P(traceback.format_exc(), color='r')
      return None, None, None

  def _load_single_model(self, model_name, model_num, model_type, class_name=None):
    """
    Load a single model based on its type.

    Parameters
    ----------
    model_name : str
        HuggingFace model ID
    model_num : int
        Model number (1, 2, or 3)
    model_type : str
        "huggingface" for standard HF models, "custom" for custom models
    class_name : str, optional
        Class name for custom models

    Returns
    -------
    tuple
        (model, processor, model_type) or (None, None, None) if loading fails
    """
    if model_type == "huggingface":
      return self._load_standard_hf_model(model_name, model_num)
    else:
      return self._load_custom_model(model_name, model_num, class_name)

  def _load_hf_models(self):
    """
    Load all configured HuggingFace models.
    Models are loaded based on their enabled status in config.
    """
    self.P("=" * 50, color='b')
    self.P("Loading HuggingFace Models...", color='b')
    self.P("=" * 50, color='b')

    # Model 1
    if self.cfg_model_1_enabled and self.cfg_model_1_name:
      self.model_1, self.processor_1, self.model_1_type = self._load_single_model(
        self.cfg_model_1_name,
        model_num=1,
        model_type=self.cfg_model_1_type or "huggingface",
        class_name=self.cfg_model_1_class_name,
      )
    else:
      self.P("Model 1: Disabled or not configured", color='y')
      self.model_1_type = None

    # Model 2
    if self.cfg_model_2_enabled and self.cfg_model_2_name:
      self.model_2, self.processor_2, self.model_2_type = self._load_single_model(
        self.cfg_model_2_name,
        model_num=2,
        model_type=self.cfg_model_2_type or "custom",
        class_name=self.cfg_model_2_class_name,
      )
    else:
      self.P("Model 2: Disabled or not configured", color='y')
      self.model_2_type = None

    # Model 3
    if self.cfg_model_3_enabled and self.cfg_model_3_name:
      self.model_3, self.processor_3, self.model_3_type = self._load_single_model(
        self.cfg_model_3_name,
        model_num=3,
        model_type=self.cfg_model_3_type or "custom",
        class_name=self.cfg_model_3_class_name,
      )
    else:
      self.P("Model 3: Disabled or not configured", color='y')
      self.model_3_type = None

    # Summary
    loaded_count = sum([
      self.model_1 is not None,
      self.model_2 is not None,
      self.model_3 is not None
    ])
    self.P("=" * 50, color='b')
    self.P(f"Model loading complete: {loaded_count}/3 models loaded", color='g')
    self.P("=" * 50, color='b')

    return


  def _run_model_inference(self, img_array, model, processor, model_type, model_name="model"):
    """
    Run inference on a single image using a loaded model.

    Parameters
    ----------
    img_array : np.ndarray
        Image as numpy array (HWC format)
    model : nn.Module
        Loaded model (HuggingFace or custom)
    processor : ImageProcessor
        Image processor (HuggingFace AutoImageProcessor or SimpleImageProcessor)
    model_type : str
        "huggingface" or "custom"
    model_name : str
        Name for logging

    Returns
    -------
    dict
        Inference results with predictions and probabilities
    """
    if model is None or processor is None:
      return {'error': f'{model_name} not loaded'}

    try:
      import torch as th

      # Convert numpy array to PIL Image for processor
      pil_image = Image.fromarray(img_array)

      # Preprocess the image
      inputs = processor(images=pil_image, return_tensors="pt")

      # Move inputs to same device as model
      device = next(model.parameters()).device
      inputs = {k: v.to(device) for k, v in inputs.items()}

      # Run inference - different handling for HuggingFace vs custom models
      with th.no_grad():
        if model_type == "huggingface":
          outputs = model(**inputs)
          logits = outputs.logits
        else:
          # Custom models return logits directly
          logits = model(inputs["pixel_values"])

      # Get predictions
      probabilities = th.nn.functional.softmax(logits, dim=-1)

      # Get top predictions
      top_k = min(5, probabilities.shape[-1])
      top_probs, top_indices = th.topk(probabilities[0], top_k)

      # Get labels based on model type
      if model_type == "huggingface":
        id2label = model.config.id2label
      else:
        id2label = getattr(model, 'id2label', {})

      predictions = []
      for prob, idx in zip(top_probs.cpu().numpy(), top_indices.cpu().numpy()):
        label = id2label.get(int(idx), f"class_{idx}")
        predictions.append({
          'label': label,
          'confidence': float(prob),
          'class_id': int(idx)
        })

      return {
        'predictions': predictions,
        'top_label': predictions[0]['label'] if predictions else None,
        'top_confidence': predictions[0]['confidence'] if predictions else 0.0,
      }

    except Exception as e:
      self.P(f"Error running inference with {model_name}: {e}", color='r')
      import traceback
      self.P(traceback.format_exc(), color='r')
      return {'error': str(e)}

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
    Main prediction: extract image information and run model inference.

    Runs inference using loaded HuggingFace models for cervical
    cancer detection and classification.

    Parameters
    ----------
    inputs : list
        List of preprocessed inputs (decoded images)

    Returns
    -------
    list
        List of analysis results including model predictions
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

      # Step 1: Run ImageNet classifier for image validation (not included in results)
      imagenet_result = None
      if self.model_1 is not None:
        imagenet_result = self._run_model_inference(
          img_array, self.model_1, self.processor_1,
          model_type=self.model_1_type,
          model_name=self.cfg_model_1_name
        )

      # Step 2: Validate image content using ImageNet results
      # If ImageNet confidently recognizes an object, this is not a medical image
      validation = self._validate_image_content(imagenet_result)

      if not validation['valid']:
        self.P(f"Image validation failed: {validation['reason']}", color='r')
        self.Pd(f"Validation result details: {self.json_dumps(validation)}", color='r')
        results.append({
          'index': idx,
          'error': validation['reason'],
          'valid': False,
          'image_info': image_info,
          'processed_at': self.time(),
          'processor_version': __VER__,
        })
        continue

      # Step 3: Image passed validation - run medical analysis models
      model_results = {}

      # Model 2: Custom model (CervicalCancerCNN) - lesion detection
      if self.model_2 is not None:
        model_results['model_2'] = self._run_model_inference(
          img_array, self.model_2, self.processor_2,
          model_type=self.model_2_type,
          model_name=self.cfg_model_2_name
        )

      # Model 3: Custom model (BaseCNN) - transformation zone classification
      if self.model_3 is not None:
        model_results['model_3'] = self._run_model_inference(
          img_array, self.model_3, self.processor_3,
          model_type=self.model_3_type,
          model_name=self.cfg_model_3_name
        )

      # Generate cervical screening analysis
      analysis = self._generate_cervical_analysis(img_array, image_info)

      self.P("=============================================")
      self.P("=============================================")
      self.P(f"Processed input index: {idx}", color='g')
      self.P(f"Image validation: {validation}", color='g')
      self.P(f"Image info: {image_info}", color='g')
      self.P(f"Analysis: {analysis}", color='g')
      self.P(f"Model results: {self.json_dumps(model_results)}", color='g')
      self.P("=============================================")
      # Add processing metadata
      result = {
        'index': idx,
        'image_info': image_info,
        'validation': validation,
        'analysis': analysis,
        'model_inference': model_results,
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
