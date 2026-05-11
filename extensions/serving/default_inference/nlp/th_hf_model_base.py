"""
Shared Hugging Face pipeline-serving base for text-oriented models.

This base centralizes model/tokenizer resolution, HF auth, device selection,
and pipeline bootstrap so model-specific subclasses only need to implement
input/output handling.
"""

import importlib.util
import inspect
import json
from pathlib import Path, PurePosixPath

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
  "MODEL_REVISION": None,
  "HF_RUNTIME": "auto",
  "HF_ARTIFACT_MANIFEST": "artifact_manifest.json",
  "HF_ONNX_RUNTIME_KEY": "onnx_fp32",
  "HF_ONNX_ALLOW_PATTERNS": None,
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


class HfOnnxArtifactPipeline:
  """Callable adapter that exposes an ONNX artifact as a pipeline-like object."""

  def __init__(
    self,
    repo_id,
    runtime_key,
    runtime_config,
    tokenizer,
    session,
    schema,
    decoder,
    task=None,
    max_length=None,
  ):
    self.repo_id = repo_id
    self.runtime_key = runtime_key
    self.runtime_config = runtime_config or {}
    self.tokenizer = tokenizer
    self.session = session
    self.schema = schema or {}
    self.decoder = decoder
    self.task = task
    self.framework = "onnxruntime"
    self.max_length = max_length
    return

  def __call__(self, texts, **kwargs):
    """Run one or more text inputs through the ONNX artifact."""
    is_single_text = isinstance(texts, str)
    text_items = [texts] if is_single_text else list(texts or [])
    results = [
      self._run_single_text(text=text, inference_kwargs=kwargs)
      for text in text_items
    ]
    return results[0] if is_single_text or len(results) == 1 else results

  def _get_max_length(self, inference_kwargs):
    max_length = inference_kwargs.get("max_length")
    if max_length is not None:
      return max_length
    if self.max_length is not None:
      return self.max_length
    schema_max_length = self.schema.get("max_length")
    return schema_max_length if schema_max_length is not None else None

  def _tokenize(self, text, inference_kwargs):
    tokenize_kwargs = {
      "return_tensors": "np",
      "truncation": bool(inference_kwargs.get("truncation", True)),
    }
    for source in (self.schema, self.runtime_config):
      extra_tokenize_kwargs = source.get("tokenizer_kwargs") if isinstance(source, dict) else None
      if isinstance(extra_tokenize_kwargs, dict):
        tokenize_kwargs.update(extra_tokenize_kwargs)
    max_length = self._get_max_length(inference_kwargs)
    if max_length is not None:
      tokenize_kwargs["max_length"] = max_length
    if "padding" in inference_kwargs:
      tokenize_kwargs["padding"] = inference_kwargs["padding"]
    return self.tokenizer(text, **tokenize_kwargs)

  def _input_specs(self):
    inputs = self.schema.get("inputs")
    if isinstance(inputs, list):
      return inputs
    if isinstance(inputs, dict):
      return [
        {"name": name, **(spec if isinstance(spec, dict) else {})}
        for name, spec in inputs.items()
      ]
    return [
      {"name": "input_ids", "dtype": "int64"},
      {"name": "attention_mask", "dtype": "int64"},
    ]

  def _output_names(self):
    output_names = self.runtime_config.get("output_names")
    if isinstance(output_names, list) and output_names:
      return output_names
    output_order = self.schema.get("output_order")
    if isinstance(output_order, list) and output_order:
      return output_order
    outputs = self.schema.get("outputs")
    if isinstance(outputs, list):
      names = []
      for output in outputs:
        if isinstance(output, dict) and output.get("name"):
          names.append(output["name"])
        elif isinstance(output, str):
          names.append(output)
      if names:
        return names
    if hasattr(self.session, "get_outputs"):
      session_output_names = [
        output.name for output in self.session.get_outputs()
        if getattr(output, "name", None)
      ]
      if session_output_names:
        return session_output_names
    return None

  def _prepare_session_inputs(self, encoded):
    session_inputs = {}
    for input_spec in self._input_specs():
      if isinstance(input_spec, dict):
        input_name = input_spec.get("name")
        dtype = input_spec.get("dtype")
      else:
        input_name = str(input_spec)
        dtype = None
      if not input_name or input_name not in encoded:
        continue
      value = encoded[input_name]
      if dtype is not None and hasattr(value, "astype"):
        value = value.astype(dtype)
      session_inputs[input_name] = value
    if not session_inputs and hasattr(encoded, "items"):
      session_inputs = dict(encoded.items())
    return session_inputs

  def _build_output_map(self, raw_outputs, output_names):
    if output_names is None:
      output_names = [f"output_{idx}" for idx in range(len(raw_outputs))]
    return {
      output_name: output_value
      for output_name, output_value in zip(output_names, raw_outputs)
    }

  def _call_decoder(self, outputs_by_name, text, encoded, inference_kwargs):
    if self.decoder is None:
      return outputs_by_name
    decoder_kwargs = {
      **dict(inference_kwargs or {}),
      "runtime": self.runtime_key,
      "runtime_key": self.runtime_key,
      "text": text,
      "repo_id": self.repo_id,
      "tokenizer_output": encoded,
      "encoded": encoded,
      "inference_kwargs": dict(inference_kwargs or {}),
    }
    try:
      signature = inspect.signature(self.decoder)
      accepts_var_kwargs = any(
        param.kind == inspect.Parameter.VAR_KEYWORD
        for param in signature.parameters.values()
      )
      if not accepts_var_kwargs:
        decoder_kwargs = {
          key: value for key, value in decoder_kwargs.items()
          if key in signature.parameters
        }
    except (TypeError, ValueError):
      pass
    return self.decoder(outputs_by_name, self.schema, **decoder_kwargs)

  def _run_single_text(self, text, inference_kwargs):
    encoded = self._tokenize(text=text, inference_kwargs=inference_kwargs)
    session_inputs = self._prepare_session_inputs(encoded)
    output_names = self._output_names()
    raw_outputs = self.session.run(output_names, session_inputs)
    outputs_by_name = self._build_output_map(raw_outputs, output_names)
    return self._call_decoder(
      outputs_by_name=outputs_by_name,
      text=text,
      encoded=encoded,
      inference_kwargs=inference_kwargs,
    )


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
    self.hf_runtime = "pt"
    self.hf_runtime_config = {}
    self.hf_artifact_manifest = None
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

  def get_model_revision(self):
    """Return the optional Hugging Face model revision.

    Returns
    -------
    str or None
        Configured `MODEL_REVISION`, or `None` when unset.
    """
    return getattr(self, "cfg_model_revision", None)

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

  def _requested_hf_runtime(self):
    """Return the normalized requested HF runtime selector."""
    requested = getattr(self, "cfg_hf_runtime", "auto")
    if requested is None:
      return "auto"
    requested = str(requested).strip().lower()
    if requested in {"", "auto"}:
      return "auto"
    if requested in {"pt", "torch", "pytorch", "transformers"}:
      return "pt"
    if requested == "onnx":
      return "onnx"
    return requested

  def _should_load_hf_artifact_manifest(self, requested_runtime):
    """Return whether startup needs the HF artifact manifest."""
    if requested_runtime == "pt":
      return False
    if requested_runtime == "auto":
      return self.device == -1
    return True

  def _download_hf_artifact_file(self, filename):
    """Download one HF artifact file and return its local path."""
    from huggingface_hub import hf_hub_download

    return hf_hub_download(
      repo_id=self.get_model_name(),
      filename=filename,
      revision=self.get_model_revision(),
      token=self.hf_token,
      cache_dir=self.cache_dir,
      repo_type="model",
    )

  def _get_hf_onnx_fallback_manifest(self):
    """Return a subclass-provided ONNX manifest when the repo has no manifest.

    This hook lets dedicated serving classes support standard HF ONNX layouts
    without requiring remote Python artifact code or model-specific logic in
    the shared base class.
    """
    return None

  def _load_hf_artifact_manifest(self):
    """Load the optional artifact manifest from the configured HF model repo."""
    manifest_name = getattr(self, "cfg_hf_artifact_manifest", None)
    if not manifest_name:
      return self._get_hf_onnx_fallback_manifest()
    try:
      manifest_path = self._download_hf_artifact_file(manifest_name)
      return json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except Exception as exc:
      fallback_manifest = self._get_hf_onnx_fallback_manifest()
      if isinstance(fallback_manifest, dict):
        self.P(
          f"HF artifact manifest {manifest_name} not available for {self.get_model_name()}; "
          "using subclass ONNX fallback manifest.",
          color="y",
        )
        return fallback_manifest
      if self._requested_hf_runtime() != "auto":
        raise
      self.P(
        f"HF artifact manifest {manifest_name} not available for {self.get_model_name()}: {exc}",
        color="y",
      )
      return None

  def _get_hf_manifest_runtimes(self, manifest):
    """Extract runtime definitions from an artifact manifest."""
    if not isinstance(manifest, dict):
      return {}
    runtimes = manifest.get("runtimes")
    return runtimes if isinstance(runtimes, dict) else {}

  def _runtime_is_onnx(self, runtime_key, runtime_config):
    """Return whether a manifest runtime is backed by ONNX Runtime."""
    runtime_config = runtime_config or {}
    runtime_name = str(runtime_config.get("runtime", "")).lower()
    entrypoint = str(runtime_config.get("entrypoint", "")).lower()
    runtime_key = str(runtime_key or "").lower()
    return (
      "onnxruntime" in runtime_name
      or "onnxruntime" in entrypoint
      or runtime_key.startswith("onnx")
    )

  def _resolve_hf_onnx_runtime_key(self, runtimes):
    """Find the preferred ONNX runtime key from manifest runtimes."""
    preferred = getattr(self, "cfg_hf_onnx_runtime_key", None)
    if preferred in runtimes and self._runtime_is_onnx(preferred, runtimes[preferred]):
      return preferred
    for runtime_key, runtime_config in runtimes.items():
      if self._runtime_is_onnx(runtime_key, runtime_config):
        return runtime_key
    return None

  def _select_hf_runtime(self, manifest):
    """Select the runtime to load for this startup."""
    requested_runtime = self._requested_hf_runtime()
    runtimes = self._get_hf_manifest_runtimes(manifest)
    if requested_runtime == "pt":
      return "pt", runtimes.get("pt", {})
    if requested_runtime == "auto":
      if self.device == -1:
        runtime_key = self._resolve_hf_onnx_runtime_key(runtimes)
        if runtime_key is not None:
          return runtime_key, runtimes[runtime_key]
      return "pt", runtimes.get("pt", {})
    if requested_runtime in runtimes:
      return requested_runtime, runtimes[requested_runtime]
    if requested_runtime == "onnx":
      runtime_key = self._resolve_hf_onnx_runtime_key(runtimes)
      if runtime_key is not None:
        return runtime_key, runtimes[runtime_key]
    manifest_name = getattr(self, "cfg_hf_artifact_manifest", "artifact_manifest.json")
    raise ValueError(
      f"HF runtime {requested_runtime!r} is not declared in {manifest_name!r} for {self.get_model_name()}."
    )

  def _blocked_hf_weight_pattern(self, pattern):
    """Return whether a download pattern could pull framework weight files."""
    pattern = str(pattern)
    blocked_suffixes = (
      ".safetensors",
      ".bin",
      ".h5",
      ".msgpack",
    )
    blocked_wildcards = ("*", "**/*", "*.safetensors", "*.bin", "*.h5", "*.msgpack")
    blocked_directory_globs = pattern.endswith("/*") or pattern.endswith("/**")
    return pattern.endswith(blocked_suffixes) or pattern in blocked_wildcards or blocked_directory_globs

  def _build_hf_runtime_allow_patterns(self, runtime_config):
    """Build safe HF snapshot allow-patterns for an ONNX runtime."""
    configured_patterns = getattr(self, "cfg_hf_onnx_allow_patterns", None)
    if configured_patterns:
      patterns = configured_patterns
    else:
      patterns = []
      for source_patterns in (
        runtime_config.get("recommended_allow_patterns"),
        runtime_config.get("files"),
        [runtime_config.get("model")] if runtime_config.get("model") else None,
      ):
        if not source_patterns:
          continue
        if isinstance(source_patterns, str):
          source_patterns = [source_patterns]
        patterns.extend(source_patterns)
      if not patterns:
        patterns = [
          "*.onnx",
          "**/*.onnx",
          "*.json",
          "*.py",
          "*.txt",
          "*.model",
          "*.tiktoken",
        ]
    if isinstance(patterns, str):
      patterns = [patterns]
    safe_patterns = []
    for pattern in patterns or []:
      if not pattern or self._blocked_hf_weight_pattern(pattern):
        continue
      if pattern not in safe_patterns:
        safe_patterns.append(pattern)
    if not safe_patterns:
      raise ValueError("HF ONNX runtime download has no safe allow patterns.")
    return safe_patterns

  def _download_hf_runtime_snapshot(self, runtime_key, runtime_config, allow_patterns):
    """Download the minimal HF snapshot needed for a selected runtime."""
    from huggingface_hub import snapshot_download

    self.P(
      f"Downloading HF runtime {runtime_key} artifacts for {self.get_model_name()}...",
      color="y",
    )
    return snapshot_download(
      repo_id=self.get_model_name(),
      revision=self.get_model_revision(),
      token=self.hf_token,
      cache_dir=self.cache_dir,
      allow_patterns=allow_patterns,
      repo_type="model",
    )

  def _runtime_file_list(self, runtime_config):
    files = runtime_config.get("files") if isinstance(runtime_config, dict) else None
    return files if isinstance(files, list) else []

  def _resolve_hf_snapshot_path(self, model_dir, file_path):
    """Resolve a manifest path while keeping it inside the downloaded snapshot."""
    raw_path = str(file_path)
    path = PurePosixPath(raw_path)
    if path.is_absolute():
      raise ValueError(f"HF artifact path {file_path!r} must be relative to the model snapshot.")
    if ".." in path.parts:
      raise ValueError(f"HF artifact path {file_path!r} escapes the model snapshot.")
    # Hugging Face snapshots commonly symlink files into the shared cache
    # blob store. A resolved containment check would reject valid snapshots,
    # so keep the traversal guard lexical and return the snapshot path itself.
    return Path(model_dir) / Path(*path.parts)

  def _first_manifest_file_with_suffix(self, runtime_config, suffixes):
    """Return the first exact manifest file path ending with any suffix."""
    for file_path in self._runtime_file_list(runtime_config):
      file_path = str(file_path)
      if any(file_path.endswith(suffix) for suffix in suffixes):
        return file_path
    return None

  def _resolve_manifest_file_path(self, model_dir, manifest, runtime_config, keys, suffixes):
    """Resolve a model-repo file path declared directly or inferred by suffix."""
    for key in keys:
      value = runtime_config.get(key) if isinstance(runtime_config, dict) else None
      if value is None and isinstance(manifest, dict):
        value = manifest.get(key)
      if value:
        return self._resolve_hf_snapshot_path(model_dir=model_dir, file_path=value)
    inferred = self._first_manifest_file_with_suffix(runtime_config, suffixes)
    if inferred:
      return self._resolve_hf_snapshot_path(model_dir=model_dir, file_path=inferred)
    return None

  def _load_hf_schema(self, model_dir, manifest, runtime_config):
    """Load the JSON schema declared by the selected HF runtime."""
    inline_schema = runtime_config.get("inline_schema") if isinstance(runtime_config, dict) else None
    if isinstance(inline_schema, dict):
      return inline_schema
    schema_path = self._resolve_manifest_file_path(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
      keys=("schema", "schema_file", "contract_schema"),
      suffixes=("_schema.json", "schema.json"),
    )
    if schema_path is None or not schema_path.exists():
      raise ValueError(f"HF runtime {self.hf_runtime} does not declare a usable schema file.")
    return json.loads(schema_path.read_text(encoding="utf-8"))

  def _runtime_allows_remote_code(self, manifest, runtime_config):
    """Return whether the selected runtime explicitly allows Python artifact code."""
    return isinstance(runtime_config, dict) and bool(runtime_config.get("trust_remote_code"))

  def _runtime_allows_decoder_remote_code(self, manifest, runtime_config):
    """Return whether the selected runtime may execute Python decoder code."""
    # TODO: replace this temporary compatibility path with declarative ONNX
    # decoders (for example multihead_classification_v1) so artifact Python
    # does not execute unless each runtime explicitly opts into remote code.
    # This currently preserves legacy Sentinel ONNX artifacts whose decoder is
    # a reviewed contract file but whose manifest marks the ONNX runtime as
    # trust_remote_code=False because tokenizer/model loading does not need HF
    # remote code. The decoder still executes Python, so this is intentionally
    # gated by global TRUST_REMOTE_CODE and should be removed after repackaging.
    return bool(self.cfg_trust_remote_code)

  def _load_hf_contract_decoder(self, model_dir, manifest, runtime_config):
    """Load the artifact decoder function declared by the selected HF runtime."""
    decoder_path = self._resolve_manifest_file_path(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
      keys=("decoder", "decoder_file", "contract", "contract_file"),
      suffixes=("_contract.py", "contract.py"),
    )
    if decoder_path is None or not decoder_path.exists():
      raise ValueError(f"HF runtime {self.hf_runtime} does not declare a usable contract decoder.")
    if not bool(self.cfg_trust_remote_code) or not self._runtime_allows_decoder_remote_code(
      manifest=manifest,
      runtime_config=runtime_config,
    ):
      raise ValueError(
        "HF ONNX artifact decoder requires TRUST_REMOTE_CODE=True because it executes "
        f"Python code from {decoder_path}."
      )
    module_name = f"hf_artifact_contract_{abs(hash(str(decoder_path)))}"
    spec = importlib.util.spec_from_file_location(module_name, decoder_path)
    if spec is None or spec.loader is None:
      raise ValueError(f"Could not load HF contract decoder from {decoder_path}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    function_name = None
    if isinstance(runtime_config, dict):
      function_name = runtime_config.get("decoder_function")
    if function_name is None and isinstance(manifest, dict):
      function_name = manifest.get("decoder_function")
    if function_name is None and callable(getattr(module, "decode_outputs", None)):
      function_name = "decode_outputs"
    if function_name is None:
      decode_functions = [
        name for name in dir(module)
        if name.startswith("decode_")
        and name.endswith("_outputs")
        and callable(getattr(module, name, None))
      ]
      if len(decode_functions) == 1:
        function_name = decode_functions[0]
    decoder = getattr(module, function_name, None) if function_name else None
    if not callable(decoder):
      raise ValueError(f"Could not resolve a decoder function in {decoder_path}.")
    return decoder

  def _get_hf_onnx_artifact_schema(self, model_dir, manifest, runtime_config):
    """Return the schema used by an ONNX artifact runtime."""
    return self._load_hf_schema(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
    )

  def _get_hf_onnx_artifact_decoder(self, model_dir, manifest, runtime_config):
    """Return the decoder used by an ONNX artifact runtime."""
    return self._load_hf_contract_decoder(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
    )

  def _resolve_hf_onnx_model_path(self, model_dir, runtime_key, runtime_config, schema):
    """Resolve the ONNX model file for the selected runtime."""
    for key in ("model", "model_file", "path"):
      value = runtime_config.get(key) if isinstance(runtime_config, dict) else None
      if value:
        return self._resolve_hf_snapshot_path(model_dir=model_dir, file_path=value)
    models = schema.get("models") if isinstance(schema, dict) else None
    if isinstance(models, dict):
      candidates = [
        runtime_key,
        str(runtime_key).replace("_", "-"),
        str(runtime_key).replace("-", "_"),
      ]
      for candidate in candidates:
        value = models.get(candidate)
        if value:
          if isinstance(value, dict):
            value = value.get("path") or value.get("file") or value.get("model")
          if not value:
            continue
          return self._resolve_hf_snapshot_path(model_dir=model_dir, file_path=value)
    model_file = self._first_manifest_file_with_suffix(runtime_config, (".onnx",))
    if model_file:
      return self._resolve_hf_snapshot_path(model_dir=model_dir, file_path=model_file)
    raise ValueError(f"HF runtime {runtime_key} does not declare an ONNX model file.")

  def _resolve_hf_tokenizer_dir(self, model_dir, manifest, runtime_config, schema):
    """Resolve tokenizer directory for the selected artifact runtime."""
    tokenizer_dir = None
    for source in (runtime_config, schema, manifest):
      if isinstance(source, dict) and source.get("tokenizer_dir"):
        tokenizer_dir = source["tokenizer_dir"]
        break
    return self._resolve_hf_snapshot_path(model_dir=model_dir, file_path=tokenizer_dir or ".")

  def _load_hf_onnx_tokenizer(self, model_dir, runtime_config, manifest=None):
    """Load the tokenizer for an ONNX HF artifact."""
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(
      str(model_dir),
      token=self.hf_token,
      trust_remote_code=bool(self.cfg_trust_remote_code) and self._runtime_allows_remote_code(
        manifest=manifest,
        runtime_config=runtime_config,
      ),
    )

  def _create_hf_onnx_session(self, model_path, providers):
    """Create an ONNX Runtime inference session."""
    import onnxruntime as ort

    return ort.InferenceSession(str(model_path), providers=providers)

  def _build_hf_onnx_artifact_pipeline(self, model_dir, runtime_key, runtime_config, manifest):
    """Build a callable ONNX artifact pipeline from downloaded HF files."""
    schema = self._get_hf_onnx_artifact_schema(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
    )
    decoder = self._get_hf_onnx_artifact_decoder(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
    )
    tokenizer_dir = self._resolve_hf_tokenizer_dir(
      model_dir=model_dir,
      manifest=manifest,
      runtime_config=runtime_config,
      schema=schema,
    )
    tokenizer = self._load_hf_onnx_tokenizer(
      model_dir=tokenizer_dir,
      runtime_config=runtime_config,
      manifest=manifest,
    )
    model_path = self._resolve_hf_onnx_model_path(
      model_dir=model_dir,
      runtime_key=runtime_key,
      runtime_config=runtime_config,
      schema=schema,
    )
    provider = runtime_config.get("provider") or "CPUExecutionProvider"
    providers = runtime_config.get("providers") or [provider]
    session = self._create_hf_onnx_session(
      model_path=model_path,
      providers=providers,
    )
    return HfOnnxArtifactPipeline(
      repo_id=self.get_model_name(),
      runtime_key=runtime_key,
      runtime_config=runtime_config,
      tokenizer=tokenizer,
      session=session,
      schema=schema,
      decoder=decoder,
      task=runtime_config.get("pipeline_task") or manifest.get("pipeline_task") or self.get_pipeline_task(),
      max_length=self.cfg_max_length,
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

  def _startup_transformers_pipeline(self):
    """Load the standard Transformers pipeline runtime."""
    model_name = self.get_model_name()
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
      revision=self.get_model_revision(),
      **pipeline_kwargs,
    )
    self._normalize_pipeline_runtime_contract()
    return

  def _startup_hf_onnx_artifact(self, runtime_key, runtime_config, manifest):
    """Load the selected ONNX artifact runtime from the HF repository."""
    allow_patterns = self._build_hf_runtime_allow_patterns(runtime_config)
    model_dir = self._download_hf_runtime_snapshot(
      runtime_key=runtime_key,
      runtime_config=runtime_config,
      allow_patterns=allow_patterns,
    )
    self.classifier = self._build_hf_onnx_artifact_pipeline(
      model_dir=model_dir,
      runtime_key=runtime_key,
      runtime_config=runtime_config,
      manifest=manifest or {},
    )
    return

  def startup(self):
    """Load the Hugging Face runtime and prepare it for inference.

    Raises
    ------
    ValueError
        If `MODEL_NAME` is not configured.
    """
    model_name = self.get_model_name()
    if not model_name:
      raise ValueError(f"{self.__class__.__name__} serving requires MODEL_NAME.")

    self.device = self._resolve_pipeline_device()
    requested_runtime = self._requested_hf_runtime()
    manifest = None
    if self._should_load_hf_artifact_manifest(requested_runtime=requested_runtime):
      manifest = self._load_hf_artifact_manifest()
    runtime_key, runtime_config = self._select_hf_runtime(manifest=manifest)
    self.hf_runtime = runtime_key
    self.hf_runtime_config = dict(runtime_config or {})
    self.hf_artifact_manifest = manifest if isinstance(manifest, dict) else None

    run_warmup = True
    if self._runtime_is_onnx(runtime_key=runtime_key, runtime_config=runtime_config):
      try:
        self._startup_hf_onnx_artifact(
          runtime_key=runtime_key,
          runtime_config=runtime_config,
          manifest=manifest,
        )
        self._run_startup_warmup()
        run_warmup = False
      except Exception as exc:
        if requested_runtime != "auto":
          raise
        self.P(
          f"HF auto runtime could not start ONNX artifact {runtime_key!r} for "
          f"{self.get_model_name()}: {exc}. Falling back to Transformers/PT.",
          color="y",
        )
        self.hf_runtime = "pt"
        self.hf_runtime_config = {}
        self.hf_artifact_manifest = None
        self._startup_transformers_pipeline()
    else:
      self._startup_transformers_pipeline()
    if run_warmup:
      self._run_startup_warmup()
    return

  def _get_hf_artifact_model_metadata(self):
    """Return model metadata declared by the loaded artifact."""
    metadata = {}
    has_artifact_metadata = False
    for source in (self.hf_artifact_manifest, getattr(self.classifier, "schema", None)):
      if not isinstance(source, dict):
        continue
      for key in (
        "repo_id",
        "repo_key",
        "model_key",
        "model_version",
        "release_channel",
        "release_alias_of",
        "source_repo_id",
      ):
        if key not in metadata and source.get(key) is not None:
          metadata[key] = source[key]
          has_artifact_metadata = True
    if has_artifact_metadata and self.hf_runtime:
      metadata["runtime"] = self.hf_runtime
    return metadata

  def get_additional_metadata(self):
    """Return model metadata attached to decoded predictions.

    Returns
    -------
    dict
        Model name, tokenizer name, and pipeline task metadata.
    """
    pipeline_task = getattr(self.classifier, "task", None) if self.classifier is not None else None
    metadata = {
      "MODEL_NAME": self.get_model_name(),
      "TOKENIZER_NAME": self.get_tokenizer_name(),
      "PIPELINE_TASK": pipeline_task or self.get_pipeline_task(),
      "HF_RUNTIME": self.hf_runtime,
      "RUNTIME": self.hf_runtime_config.get("runtime") or (
        "onnxruntime" if self._runtime_is_onnx(self.hf_runtime, self.hf_runtime_config) else "transformers"
      ),
    }
    model_revision = self.get_model_revision()
    if model_revision is not None:
      metadata["MODEL_REVISION"] = model_revision
    artifact_model_metadata = self._get_hf_artifact_model_metadata()
    if artifact_model_metadata:
      metadata["MODEL"] = artifact_model_metadata
      if artifact_model_metadata.get("model_version") is not None:
        metadata["MODEL_VERSION"] = artifact_model_metadata["model_version"]
    return metadata

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
