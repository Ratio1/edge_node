"""
Shared Hugging Face pipeline-serving base for text-oriented models.

This base centralizes model/tokenizer resolution, HF auth, device selection,
and pipeline bootstrap so model-specific subclasses only need to implement
input/output handling.
"""

import torch as th

from transformers import BitsAndBytesConfig, pipeline as hf_pipeline

from naeural_core.serving.base.base_serving_process import ModelServingProcess as BaseServingProcess


__VER__ = "0.1.0"


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "PICKED_INPUT": "STRUCT_DATA",
  "MAX_WAIT_TIME": 60,
  "MODEL_NAME": None,
  "TOKENIZER_NAME": None,
  "PIPELINE_TASK": None,
  "TEXT_KEYS": ["text", "email_text", "content", "request", "body"],
  "REQUEST_ID_KEYS": ["request_id", "REQUEST_ID"],
  "MAX_LENGTH": 512,
  "MODEL_WEIGHTS_SIZE": None,
  "HF_TOKEN": None,
  "DEVICE": None,
  "TRUST_REMOTE_CODE": True,
  "EXPECTED_AI_ENGINES": None,
  "PIPELINE_KWARGS": {},
  "INFERENCE_KWARGS": {},
  "WARMUP_ENABLED": True,
  "WARMUP_TEXT": "Warmup request.",
  "WARMUP_INFERENCE_KWARGS": {},
  "RUNS_ON_EMPTY_INPUT": False,
  "VALIDATION_RULES": {
    **BaseServingProcess.CONFIG["VALIDATION_RULES"],
  },
}


class ThHfModelBase(BaseServingProcess):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    """Initialize shared Hugging Face serving state.

    Parameters
    ----------
    **kwargs
        Keyword arguments forwarded to the base serving process.
    """
    self.classifier = None
    self.device = None
    super(ThHfModelBase, self).__init__(**kwargs)
    return

  @property
  def hf_token(self):
    """Return the Hugging Face token from config or environment.

    Returns
    -------
    str or None
        Configured token, `EE_HF_TOKEN`, or `None` when authentication is not
        configured.
    """
    return self.cfg_hf_token or self.os_environ.get("EE_HF_TOKEN")

  def get_model_name(self):
    """Return the configured Hugging Face model id.

    Returns
    -------
    str or None
        Value of `MODEL_NAME`.
    """
    return self.cfg_model_name

  def get_tokenizer_name(self):
    """Return the tokenizer id used by the pipeline.

    Returns
    -------
    str or None
        Explicit `TOKENIZER_NAME` when set, otherwise the model id.
    """
    return self.cfg_tokenizer_name or self.get_model_name()

  def get_pipeline_task(self):
    """Return the configured Transformers pipeline task.

    Returns
    -------
    str or None
        Value of `PIPELINE_TASK`.
    """
    return self.cfg_pipeline_task

  @property
  def cache_dir(self):
    """Return the local cache directory for Hugging Face artifacts.

    Returns
    -------
    str
        Model cache folder managed by the serving logger.
    """
    return self.log.get_models_folder()

  def get_expected_ai_engines(self):
    """Return normalized AI engine identifiers accepted by this serving.

    Returns
    -------
    list[str]
        Lowercase engine identifiers. An empty list means no engine-name
        restriction is applied by the serving-target filter.
    """
    expected = self.cfg_expected_ai_engines
    if expected is None:
      return []
    if isinstance(expected, str):
      return [expected.lower()]
    if isinstance(expected, (list, tuple, set)):
      return [
        engine.lower() for engine in expected
        if isinstance(engine, str) and len(engine.strip()) > 0
      ]
    return []

  @property
  def has_gpu(self):
    """Return whether the resolved pipeline device is a CUDA device.

    Returns
    -------
    bool
        `True` when `self.device` points to a non-negative CUDA index.
    """
    return self.device is not None and self.device >= 0

  def _resolve_pipeline_device(self):
    """Resolve the Transformers pipeline device from config and hardware.

    Returns
    -------
    int
        CUDA device index, or `-1` for CPU execution.
    """
    configured = self.cfg_device
    if isinstance(configured, int):
      return configured
    if isinstance(configured, str) and len(configured.strip()) > 0:
      configured = configured.strip().lower()
      if configured == "cpu":
        return -1
      if configured.startswith("cuda"):
        if ":" in configured:
          suffix = configured.split(":", 1)[1]
          if suffix.isdigit():
            return int(suffix)
        return 0
      if configured.isdigit():
        return int(configured)
    if th.cuda.is_available():
      return 0
    return -1

  def build_pipeline_kwargs(self):
    """Build extra keyword arguments for `transformers.pipeline`.

    Returns
    -------
    dict
        Copy of configured pipeline keyword arguments.
    """
    return dict(self.cfg_pipeline_kwargs or {})

  def build_inference_kwargs(self):
    """Build keyword arguments passed to each pipeline inference call.

    Returns
    -------
    dict
        Inference keyword arguments, including truncation settings when
        `MAX_LENGTH` is configured.
    """
    inference_kwargs = dict(self.cfg_inference_kwargs or {})
    if self.cfg_max_length is not None:
      inference_kwargs = {
        "truncation": True,
        "max_length": self.cfg_max_length,
        **inference_kwargs,
      }
    return inference_kwargs

  def get_warmup_text(self):
    """Return the configured warmup text when startup warmup is enabled.

    Returns
    -------
    str or None
        Trimmed warmup text, or `None` when it is blank or invalid.
    """
    warmup_text = self.cfg_warmup_text
    if isinstance(warmup_text, str) and len(warmup_text.strip()) > 0:
      return warmup_text.strip()
    return None

  def build_warmup_inference_kwargs(self):
    """Build keyword arguments used by the startup warmup call.

    Returns
    -------
    dict
        Normal inference keyword arguments overlaid with
        `WARMUP_INFERENCE_KWARGS`.
    """
    return {
      **self.build_inference_kwargs(),
      **dict(self.cfg_warmup_inference_kwargs or {}),
    }

  def _get_device_map(self):
    """Return the model-loading device map for helper configuration.

    Returns
    -------
    str
        `"cpu"` for CPU serving, otherwise `"auto"`.
    """
    return "cpu" if self.device == -1 else "auto"

  def _get_model_load_config(self):
    """Resolve model-loading and quantization parameters.

    Returns
    -------
    tuple[dict, dict or None]
        Model-loading parameters and optional quantization parameters produced
        by the shared model-load configuration helper.
    """
    return self.log.get_model_load_config(
      model_name=self.get_model_name(),
      token=self.hf_token,
      has_gpu=self.has_gpu,
      weights_size=self.cfg_model_weights_size,
      device_map=self._get_device_map(),
      cache_dir=self.cache_dir,
    )

  def _normalize_pipeline_runtime_contract(self):
    """Patch known gaps in custom remote-code pipeline initialization.

    Notes
    -----
    Some custom remote-code pipelines assume the standard Transformers
    `Pipeline` contract but forget to initialize `framework`. These serving
    processes run through PyTorch, so the missing value is defaulted to `pt`.
    """
    if self.classifier is None:
      return
    framework = getattr(self.classifier, "framework", None)
    if framework is None:
      self.classifier.framework = "pt"
    return

  def _run_startup_warmup(self):
    """Run an optional warmup inference after pipeline creation.

    Notes
    -----
    Warmup is intentionally skipped when the pipeline is missing, disabled, or
    configured with an empty warmup text.
    """
    if not self.cfg_warmup_enabled or self.classifier is None:
      return
    warmup_text = self.get_warmup_text()
    if warmup_text is None:
      return
    warmup_started_at = self.time()
    self.P(
      f"Running startup warmup for {self.get_model_name()} on device {self.device}...",
      color="y",
    )
    self.classifier(
      warmup_text,
      **self.build_warmup_inference_kwargs(),
    )
    self.P(
      "Startup warmup completed in {:.3f}s".format(self.time() - warmup_started_at),
      color="g",
    )
    return

  def startup(self):
    """Load the Hugging Face pipeline and prepare it for inference.

    Raises
    ------
    ValueError
        If `MODEL_NAME` is not configured.
    """
    model_name = self.get_model_name()
    if not model_name:
      raise ValueError(f"{self.__class__.__name__} serving requires MODEL_NAME.")

    self.device = self._resolve_pipeline_device()
    model_load_params, quantization_params = self._get_model_load_config()
    pipeline_kwargs = self.build_pipeline_kwargs()
    model_kwargs = {
      **dict(model_load_params or {}),
      **dict(pipeline_kwargs.pop("model_kwargs", {}) or {}),
    }
    token = model_kwargs.pop("token", self.hf_token)
    if "torch_dtype" in model_kwargs and "dtype" not in model_kwargs:
      model_kwargs["dtype"] = model_kwargs.pop("torch_dtype")
    if "cache_dir" not in model_kwargs:
      model_kwargs["cache_dir"] = self.cache_dir
    if quantization_params is not None:
      model_kwargs["quantization_config"] = BitsAndBytesConfig(**quantization_params)

    self.classifier = hf_pipeline(
      task=self.get_pipeline_task() or None,
      model=model_name,
      tokenizer=self.get_tokenizer_name(),
      token=token,
      trust_remote_code=bool(self.cfg_trust_remote_code),
      device=self.device,
      model_kwargs=model_kwargs,
      **pipeline_kwargs,
    )
    self._normalize_pipeline_runtime_contract()
    self._run_startup_warmup()
    return

  def get_additional_metadata(self):
    """Return model metadata attached to decoded predictions.

    Returns
    -------
    dict
        Model name, tokenizer name, and pipeline task metadata.
    """
    pipeline_task = getattr(self.classifier, "task", None) if self.classifier is not None else None
    return {
      "MODEL_NAME": self.get_model_name(),
      "TOKENIZER_NAME": self.get_tokenizer_name(),
      "PIPELINE_TASK": pipeline_task or self.get_pipeline_task(),
    }

  def _extract_serving_target(self, struct_payload):
    """Extract the reserved serving-target metadata from a payload.

    Parameters
    ----------
    struct_payload : dict or Any
        Structured payload candidate.

    Returns
    -------
    dict or None
        Serving-target metadata when present and well formed.
    """
    if not isinstance(struct_payload, dict):
      return None
    target = struct_payload.get("__SERVING_TARGET__")
    return target if isinstance(target, dict) else None

  def _payload_matches_current_serving(self, struct_payload):
    """Return whether a payload is intended for this serving process.

    Parameters
    ----------
    struct_payload : dict or Any
        Structured payload candidate containing optional serving-target
        metadata.

    Returns
    -------
    bool
        `True` when the payload is an inference request and matches the
        configured engine, model instance, and model name constraints.
    """
    target = self._extract_serving_target(struct_payload)
    if not isinstance(target, dict):
      return False
    if target.get("INFERENCE_REQUEST") is not True:
      return False

    expected_ai_engines = self.get_expected_ai_engines()
    target_ai_engine = target.get("AI_ENGINE")
    if expected_ai_engines:
      if not isinstance(target_ai_engine, str) or target_ai_engine.lower() not in expected_ai_engines:
        return False

    current_instance_id = self.cfg_model_instance_id
    target_instance_id = target.get("MODEL_INSTANCE_ID")
    if target_instance_id is not None and current_instance_id is not None:
      if str(target_instance_id) != str(current_instance_id):
        return False

    current_model_name = self.get_model_name()
    target_model_name = target.get("MODEL_NAME")
    if target_model_name is not None and current_model_name is not None:
      if str(target_model_name) != str(current_model_name):
        return False

    return True
