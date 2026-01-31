"""
Aspire Analyzer - Serving Plugin

A serving plugin that analyzes structured patient data for autism spectrum
disorder (ASD) risk assessment using the toderian/autism-detector model.

This serving plugin runs in an isolated process and provides:
- Structured data validation for 8 clinical input fields
- Feature preprocessing using joblib preprocessor
- Neural network inference for ASD probability prediction
- Risk level classification based on prediction confidence

Usage in pipeline:
{
  "PLUGINS": [
    {
      "SIGNATURE": "ASPIRE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "aspire_01",
          "AI_ENGINE": "aspire_analyzer"
        }
      ]
    }
  ]
}
"""

import json
from pathlib import Path

import numpy as np
import torch

from naeural_core.serving.base import ModelServingProcess as BaseServingProcess

__VER__ = '0.1.0'

# Valid values for categorical fields
VALID_DEVELOPMENTAL_MILESTONES = ['N', 'G', 'M', 'C']
VALID_INTELLECTUAL_DISABILITY = ['N', 'F70.0', 'F71', 'F72']
VALID_LANGUAGE_DISORDER = ['N', 'Y']
VALID_LANGUAGE_DEVELOPMENT = ['N', 'delay', 'A']
VALID_DYSMORPHISM = ['NO', 'Y']
VALID_BEHAVIOUR_DISORDER = ['N', 'Y']

# Required input fields
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

_CONFIG = {
  **BaseServingProcess.CONFIG,

  # Accept STRUCT_DATA input (JSON structured data)
  "PICKED_INPUT": "STRUCT_DATA",

  # Do not run on empty input
  "RUNS_ON_EMPTY_INPUT": False,

  # HuggingFace model configuration
  "MODEL_NAME": "toderian/autism-detector",
  "MODEL_ENABLED": True,

  # HuggingFace token for private models (optional)
  "HF_TOKEN": None,

  # Risk level thresholds
  "RISK_THRESHOLD_HIGH": 0.7,
  "RISK_THRESHOLD_MEDIUM": 0.4,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class AspireAnalyzer(BaseServingProcess):
  """
  Serving plugin for Aspire autism spectrum disorder screening.

  Processes structured patient data containing 8 clinical features
  and returns ASD risk assessment using a trained neural network.
  """

  CONFIG = _CONFIG

  def on_init(self):
    """
    Initialize the serving plugin.
    Called once during startup.
    """
    super(AspireAnalyzer, self).on_init()
    self._processed_count = 0

    # Initialize model containers
    self.model = None
    self.preprocessor = None
    self.config = None
    self.id2label = {0: 'Healthy', 1: 'ASD'}

    # Load the model
    self._load_model()

    self.P("Aspire Analyzer initialized", color='g')
    self.P(f"  Version: {__VER__}", color='g')
    self.P(f"  Accepts STRUCT_DATA input (8 clinical fields)", color='g')
    self.P(f"  Required fields: {', '.join(REQUIRED_FIELDS)}", color='g')

    return

  def _get_cache_dir(self):
    """Get the cache directory for HuggingFace models."""
    return self.log.get_models_folder()

  def _get_device(self):
    """Get the device for model inference (GPU if available, else CPU)."""
    try:
      if torch.cuda.is_available():
        return torch.device('cuda')
      return torch.device('cpu')
    except Exception:
      return torch.device('cpu')

  def _load_model(self):
    """
    Load the autism-detector model from HuggingFace.

    Downloads and loads:
    - TorchScript model (autism_detector_traced.pt)
    - Preprocessor (preprocessor.joblib)
    - Configuration (config.json)
    """
    if not self.cfg_model_enabled or not self.cfg_model_name:
      self.P("Model loading disabled or not configured", color='y')
      return

    try:
      import joblib
      from huggingface_hub import snapshot_download

      cache_dir = self._get_cache_dir()
      hf_token = self.cfg_hf_token

      self.P("=" * 50, color='b')
      self.P(f"Loading Model: {self.cfg_model_name}...", color='b')
      self.P(f"  Cache directory: {cache_dir}", color='b')
      self.P("=" * 50, color='b')

      # Download model files
      model_dir = snapshot_download(
        repo_id=self.cfg_model_name,
        cache_dir=cache_dir,
        token=hf_token,
      )
      model_path = Path(model_dir)
      self.P(f"  Downloaded to: {model_dir}", color='b')

      # Load config
      config_path = model_path / "config.json"
      if config_path.exists():
        with open(config_path, 'r') as f:
          self.config = json.load(f)
        self.P(f"  Config loaded: {self.config.get('model_type', 'unknown')}", color='b')

        # Update id2label if available in config
        if 'id2label' in self.config:
          self.id2label = {int(k): v for k, v in self.config['id2label'].items()}

      # Load preprocessor
      preprocessor_path = model_path / "preprocessor.joblib"
      if preprocessor_path.exists():
        self.preprocessor = joblib.load(preprocessor_path)
        self.P(f"  Preprocessor loaded", color='g')
      else:
        self.P(f"  WARNING: preprocessor.joblib not found", color='r')

      # Load model - prefer TorchScript
      device = self._get_device()
      traced_path = model_path / "autism_detector_traced.pt"
      pytorch_path = model_path / "pytorch_model.bin"
      safetensors_path = model_path / "model.safetensors"

      if traced_path.exists():
        self.model = torch.jit.load(str(traced_path), map_location=device)
        self.P(f"  Loaded TorchScript model", color='g')
      elif safetensors_path.exists() or pytorch_path.exists():
        # Load model class from model.py
        self.model = self._load_model_from_weights(model_path, device)
      else:
        raise FileNotFoundError("No model weights found (traced.pt, safetensors, or bin)")

      self.model.eval()
      self.P(f"  Model loaded successfully on {device}", color='g')
      self.P(f"  Labels: {self.id2label}", color='g')
      self.P("=" * 50, color='b')

    except Exception as e:
      self.P(f"Error loading model: {e}", color='r')
      import traceback
      self.P(traceback.format_exc(), color='r')
      self.model = None
      self.preprocessor = None

    return

  def _load_model_from_weights(self, model_path, device):
    """
    Load model from weights file using model.py definition.

    Parameters
    ----------
    model_path : Path
        Path to the model directory
    device : torch.device
        Device to load the model on

    Returns
    -------
    nn.Module
        Loaded model
    """
    import importlib.util

    # Load model.py
    model_py = model_path / "model.py"
    if not model_py.exists():
      raise FileNotFoundError(f"model.py not found in {model_path}")

    spec = importlib.util.spec_from_file_location("autism_model", model_py)
    model_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model_module)

    # Find model class
    model_class = None
    for name in ['AutismDetector', 'AutismClassifier', 'Model']:
      if hasattr(model_module, name):
        model_class = getattr(model_module, name)
        break

    if model_class is None:
      # Try to find any class that looks like a model
      for name in dir(model_module):
        obj = getattr(model_module, name)
        if isinstance(obj, type) and issubclass(obj, torch.nn.Module) and obj != torch.nn.Module:
          model_class = obj
          break

    if model_class is None:
      raise ValueError("No model class found in model.py")

    # Instantiate model
    model_config = self.config.get('model_config', {}) if self.config else {}
    model = model_class(**model_config) if model_config else model_class()

    # Load weights
    safetensors_path = model_path / "model.safetensors"
    pytorch_path = model_path / "pytorch_model.bin"

    if safetensors_path.exists():
      try:
        from safetensors.torch import load_file
        state_dict = load_file(str(safetensors_path))
      except ImportError:
        state_dict = torch.load(pytorch_path, map_location='cpu', weights_only=True)
    else:
      state_dict = torch.load(pytorch_path, map_location='cpu', weights_only=True)

    model.load_state_dict(state_dict)
    model = model.to(device)

    return model

  def _validate_input(self, struct_data):
    """
    Validate the input structured data contains all required fields
    with valid values.

    Parameters
    ----------
    struct_data : dict
        Input data with clinical features

    Returns
    -------
    dict
        Validation result with 'valid' bool and 'errors' list
    """
    errors = []

    if not isinstance(struct_data, dict):
      return {'valid': False, 'errors': ['Input must be a dictionary']}

    # Check required fields
    for field in REQUIRED_FIELDS:
      if field not in struct_data:
        errors.append(f"Missing required field: '{field}'")

    if errors:
      return {'valid': False, 'errors': errors}

    # Validate field values
    dm = struct_data.get('developmental_milestones')
    if dm not in VALID_DEVELOPMENTAL_MILESTONES:
      errors.append(
        f"Invalid 'developmental_milestones': '{dm}'. "
        f"Must be one of {VALID_DEVELOPMENTAL_MILESTONES}"
      )

    iq = struct_data.get('iq_dq')
    try:
      iq_val = float(iq)
      if iq_val < 20 or iq_val > 150:
        errors.append(f"Invalid 'iq_dq': {iq}. Must be between 20 and 150")
    except (TypeError, ValueError):
      errors.append(f"Invalid 'iq_dq': '{iq}'. Must be a numeric value")

    id_val = struct_data.get('intellectual_disability')
    if id_val not in VALID_INTELLECTUAL_DISABILITY:
      errors.append(
        f"Invalid 'intellectual_disability': '{id_val}'. "
        f"Must be one of {VALID_INTELLECTUAL_DISABILITY}"
      )

    ld = struct_data.get('language_disorder')
    if ld not in VALID_LANGUAGE_DISORDER:
      errors.append(
        f"Invalid 'language_disorder': '{ld}'. "
        f"Must be one of {VALID_LANGUAGE_DISORDER}"
      )

    ldev = struct_data.get('language_development')
    if ldev not in VALID_LANGUAGE_DEVELOPMENT:
      errors.append(
        f"Invalid 'language_development': '{ldev}'. "
        f"Must be one of {VALID_LANGUAGE_DEVELOPMENT}"
      )

    dys = struct_data.get('dysmorphism')
    if dys not in VALID_DYSMORPHISM:
      errors.append(
        f"Invalid 'dysmorphism': '{dys}'. "
        f"Must be one of {VALID_DYSMORPHISM}"
      )

    bd = struct_data.get('behaviour_disorder')
    if bd not in VALID_BEHAVIOUR_DISORDER:
      errors.append(
        f"Invalid 'behaviour_disorder': '{bd}'. "
        f"Must be one of {VALID_BEHAVIOUR_DISORDER}"
      )

    ne = struct_data.get('neurological_exam')
    if not isinstance(ne, str) or len(ne.strip()) == 0:
      errors.append(
        f"Invalid 'neurological_exam': must be a non-empty string "
        f"('N' for normal or description of abnormality)"
      )

    if errors:
      return {'valid': False, 'errors': errors}

    return {'valid': True, 'errors': []}

  def _get_risk_level(self, probability):
    """
    Determine risk level based on ASD probability.

    Parameters
    ----------
    probability : float
        ASD probability (0-1)

    Returns
    -------
    str
        Risk level: 'low', 'medium', or 'high'
    """
    if probability >= self.cfg_risk_threshold_high:
      return 'high'
    elif probability >= self.cfg_risk_threshold_medium:
      return 'medium'
    else:
      return 'low'

  def _run_inference(self, struct_data):
    """
    Run model inference on validated input data.

    Parameters
    ----------
    struct_data : dict
        Validated input data with clinical features

    Returns
    -------
    dict
        Inference result with prediction, probability, confidence
    """
    if self.model is None:
      return {'error': 'Model not loaded'}

    try:
      # Prepare input features in correct order
      features = {
        'developmental_milestones': struct_data['developmental_milestones'],
        'iq_dq': float(struct_data['iq_dq']),
        'intellectual_disability': struct_data['intellectual_disability'],
        'language_disorder': struct_data['language_disorder'],
        'language_development': struct_data['language_development'],
        'dysmorphism': struct_data['dysmorphism'],
        'behaviour_disorder': struct_data['behaviour_disorder'],
        'neurological_exam': struct_data['neurological_exam'],
      }

      # Apply preprocessor if available
      if self.preprocessor is not None:
        # Convert to DataFrame-like format for preprocessor
        import pandas as pd
        df = pd.DataFrame([features])
        processed = self.preprocessor.transform(df)
        input_tensor = torch.tensor(processed, dtype=torch.float32)
      else:
        # Manual encoding if no preprocessor
        input_tensor = self._manual_encode(features)

      # Move to device
      device = next(self.model.parameters()).device
      input_tensor = input_tensor.to(device)

      # Run inference
      with torch.no_grad():
        output = self.model(input_tensor)

        # Handle different output formats
        if output.shape[-1] == 1:
          # Sigmoid output (binary probability)
          probability = torch.sigmoid(output).item()
        else:
          # Softmax output (class probabilities)
          probs = torch.softmax(output, dim=-1)
          probability = probs[0, 1].item()  # ASD class probability

      # Determine prediction
      prediction_idx = 1 if probability >= 0.5 else 0
      prediction = self.id2label.get(prediction_idx, f'class_{prediction_idx}')

      # Calculate confidence (distance from decision boundary)
      confidence = abs(probability - 0.5) * 2  # Scale to 0-1

      return {
        'prediction': prediction,
        'prediction_idx': prediction_idx,
        'probability': float(probability),
        'confidence': float(confidence),
        'risk_level': self._get_risk_level(probability),
      }

    except Exception as e:
      self.P(f"Error during inference: {e}", color='r')
      import traceback
      self.P(traceback.format_exc(), color='r')
      return {'error': str(e)}

  def _manual_encode(self, features):
    """
    Manually encode features if preprocessor is not available.
    This is a fallback and may not match the trained preprocessor exactly.

    Parameters
    ----------
    features : dict
        Input features

    Returns
    -------
    torch.Tensor
        Encoded feature tensor
    """
    # Simple encoding - this should match the preprocessor's encoding
    encoded = []

    # developmental_milestones: N=0, G=1, M=2, C=3
    dm_map = {'N': 0, 'G': 1, 'M': 2, 'C': 3}
    encoded.append(dm_map.get(features['developmental_milestones'], 0))

    # iq_dq: normalize to 0-1 range (20-150)
    iq_normalized = (features['iq_dq'] - 20) / 130
    encoded.append(iq_normalized)

    # intellectual_disability: N=0, F70.0=1, F71=2, F72=3
    id_map = {'N': 0, 'F70.0': 1, 'F71': 2, 'F72': 3}
    encoded.append(id_map.get(features['intellectual_disability'], 0))

    # language_disorder: N=0, Y=1
    ld_map = {'N': 0, 'Y': 1}
    encoded.append(ld_map.get(features['language_disorder'], 0))

    # language_development: N=0, delay=1, A=2
    ldev_map = {'N': 0, 'delay': 1, 'A': 2}
    encoded.append(ldev_map.get(features['language_development'], 0))

    # dysmorphism: NO=0, Y=1
    dys_map = {'NO': 0, 'Y': 1}
    encoded.append(dys_map.get(features['dysmorphism'], 0))

    # behaviour_disorder: N=0, Y=1
    bd_map = {'N': 0, 'Y': 1}
    encoded.append(bd_map.get(features['behaviour_disorder'], 0))

    # neurological_exam: N=0, other=1
    ne_val = 0 if features['neurological_exam'].upper() == 'N' else 1
    encoded.append(ne_val)

    return torch.tensor([encoded], dtype=torch.float32)

  def _pre_process(self, inputs):
    """
    Pre-process inputs: extract and validate structured data.

    Parameters
    ----------
    inputs : dict
        Input dictionary with 'DATA' key containing list of struct_data

    Returns
    -------
    list
        List of validated input data
    """
    lst_inputs = inputs.get('DATA', [])

    self.P(f"Pre-processing {len(lst_inputs)} input(s)", color='b')

    preprocessed = []
    for i, inp in enumerate(lst_inputs):
      if isinstance(inp, dict):
        self.P(f"  Input #{i} keys: {list(inp.keys())}", color='y')
      else:
        self.P(f"  Input #{i} type: {type(inp)}", color='y')

      preprocessed.append({
        'struct_data': inp,
        'index': i,
      })

    return preprocessed

  def _predict(self, inputs):
    """
    Main prediction: validate input and run model inference.

    Parameters
    ----------
    inputs : list
        List of preprocessed inputs (struct_data dicts)

    Returns
    -------
    list
        List of analysis results including predictions
    """
    self._processed_count += 1

    results = []
    for inp_data in inputs:
      struct_data = inp_data['struct_data']
      idx = inp_data['index']

      # Validate input
      validation = self._validate_input(struct_data)

      if not validation['valid']:
        error_msg = "; ".join(validation['errors'])
        self.P(f"Input validation failed: {error_msg}", color='r')
        results.append({
          'index': idx,
          'error': error_msg,
          'valid': False,
          'processed_at': self.time(),
          'processor_version': __VER__,
        })
        continue

      # Run inference
      inference_result = self._run_inference(struct_data)

      if 'error' in inference_result:
        results.append({
          'index': idx,
          'error': inference_result['error'],
          'valid': False,
          'processed_at': self.time(),
          'processor_version': __VER__,
        })
        continue

      # Build successful result
      result = {
        'index': idx,
        'prediction': inference_result['prediction'],
        'probability': inference_result['probability'],
        'confidence': inference_result['confidence'],
        'risk_level': inference_result['risk_level'],
        'input_summary': {k: struct_data[k] for k in REQUIRED_FIELDS},
        'processed_at': self.time(),
        'processor_version': __VER__,
      }

      self.P("=" * 50)
      self.P(f"Processed input index: {idx}", color='g')
      self.P(f"Prediction: {inference_result['prediction']}", color='g')
      self.P(f"Probability: {inference_result['probability']:.2%}", color='g')
      self.P(f"Risk Level: {inference_result['risk_level']}", color='g')
      self.P("=" * 50)

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
      has_error = 'error' in pred

      if has_error:
        status = 'error'
      else:
        status = 'completed'

      formatted = {
        'status': status,
        'data': pred,
      }

      if has_error:
        error_msg = pred['error']
        formatted['error'] = error_msg
        formatted['error_code'] = 'VALIDATION_ERROR' if 'Missing' in error_msg or 'Invalid' in error_msg else 'PROCESSING_ERROR'
        formatted['error_type'] = 'validation' if formatted['error_code'] == 'VALIDATION_ERROR' else 'processing'
        formatted['error_message'] = error_msg

      formatted_results.append(formatted)

    return formatted_results
