"""
TODO: example pipeline with additional explanations
"""
import copy
import hashlib
import importlib.metadata
import os
import re
from fnmatch import fnmatch
from pathlib import Path

from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess
from llama_cpp import Llama, llama_cpp as llama_cpp_lib
from extensions.serving.mixins_llm.llm_utils import LlmCT

__VER__ = "0.1.0"


def source_file_sha256(path):
  digest = hashlib.sha256()
  with open(path, "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


LLAMA_CPP_BASE_MODULE_SHA256 = source_file_sha256(__file__)


MODEL_N_CTX_MIN_VALUE = 512
MODEL_N_CTX_DEFAULT_VALUE = 4096
MODEL_N_BATCH_DEFAULT_VALUE = 512
CONTEXT_WINDOW_ERROR_CODE = "context_window_exceeded"
CONTEXT_WINDOW_ERROR_MESSAGE = "Model context window exceeded."
BENCHMARK_TELEMETRY_KEY = "EDGEGUARD_BENCHMARK_TELEMETRY"
BENCHMARK_RESET_UNAVAILABLE_CODE = "benchmark_reset_unavailable"
BENCHMARK_RESET_FAILED_CODE = "benchmark_reset_failed"
CONTEXT_WINDOW_ERROR_RE = re.compile(
  r"Requested tokens \((\d+)\) exceed context window of (\d+)",
)


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE"        : "cpu",

  "SKIP_ERRORS"           : True,
  "DETERMINISTIC_MODE": False,  # If True, will use deterministic algorithms in PyTorch

  # Possible values of None, 4, 8, 16, 32
  # where None is the default model config.
  "MODEL_WEIGHTS_SIZE"    : None,

  "MODEL_N_CTX": MODEL_N_CTX_DEFAULT_VALUE,

  "MODEL_NAME": None,
  "MODEL_FILENAME": None,
  "MODEL_PATH": None,
  "MODEL_REVISION": None,

  # Format used to compute the prompt for the model
  "CHAT_FORMAT": None,
  # This can cause massive memory overhead.
  # Better used only for strong machines.
  "DRAFT_MODEL": None,
  # None means it will be 0 if no gpu is available and -1 if gpu available
  # TODO: have method for partial moving of the layers depending on the
  #  available VRAM
  "N_GPU_LAYERS": None,
  "N_THREADS": None,

  # Format used by the model when answering requests
  "DEFAULT_RESPONSE_FORMAT": None,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class LlamaCppBaseServingProcess(BaseServingProcess):
  CONFIG = _CONFIG

  @staticmethod
  def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
      for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()

  def _canonical_sha256(self, value):
    encoded = self.json_dumps(
      value,
      ensure_ascii=False,
      allow_nan=False,
      sort_keys=True,
      separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

  @staticmethod
  def _revision_from_loaded_path(path, gguf_sha256):
    parts = Path(path).parts
    if "snapshots" in parts:
      index = parts.index("snapshots")
      if index + 1 < len(parts) and re.fullmatch(r"[0-9a-fA-F]{7,64}", parts[index + 1]):
        return parts[index + 1].lower()
    return f"artifact-sha256:{gguf_sha256}"

  def _loaded_quantization(self, model_filename):
    metadata = getattr(self.model, "metadata", None)
    if isinstance(metadata, dict):
      values = {
        key: metadata[key]
        for key in ("general.file_type", "general.quantization_version")
        if key in metadata and isinstance(metadata[key], (str, int, float, bool))
      }
      if values:
        return values
    match = re.search(r"\.([Qq][0-9][A-Za-z0-9_-]*)\.gguf$", model_filename)
    return {"filename_profile": match.group(1).upper()} if match else {"filename_profile": "unknown"}

  def _llama_cpp_build_identity(self):
    try:
      package_version = importlib.metadata.version("llama-cpp-python")
    except importlib.metadata.PackageNotFoundError:
      package_version = "unavailable"
    system_info = "unavailable"
    system_info_fn = getattr(llama_cpp_lib, "llama_print_system_info", None)
    if callable(system_info_fn):
      try:
        system_info = system_info_fn()
        if isinstance(system_info, bytes):
          system_info = system_info.decode("utf-8", errors="strict")
        else:
          system_info = str(system_info)
      except Exception:
        system_info = "unavailable"
    loaded_library = getattr(llama_cpp_lib, "_lib", None)
    loaded_library_path = getattr(loaded_library, "_name", None)
    if not isinstance(loaded_library_path, str) or not os.path.isfile(loaded_library_path):
      raise RuntimeError("Loaded llama.cpp native library is unavailable for runtime fingerprinting.")
    return {
      "package_version": package_version,
      "build_sha256": self._sha256_file(loaded_library_path),
      "system_info_sha256": hashlib.sha256(system_info.encode("utf-8")).hexdigest(),
    }

  def _opaque_config_sha256(self, value):
    try:
      material = self.json_dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"),
      )
    except (TypeError, ValueError):
      material = f"{type(value).__module__}.{type(value).__qualname__}:{value!r}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

  def _cache_runtime_fingerprint(self, loaded_model_path, model_params):
    gguf_sha256 = self._sha256_file(loaded_model_path)
    build_identity = self._llama_cpp_build_identity()
    model_filename = os.path.basename(loaded_model_path)
    document = {
      "schema_version": "edgeguard.loaded_runtime_fingerprint.v1",
      "gguf_sha256": gguf_sha256,
      "model_revision": self._revision_from_loaded_path(
        loaded_model_path,
        gguf_sha256,
      ),
      "quantization": self._loaded_quantization(model_filename),
      "llama_cpp": build_identity,
      "load_configuration": {
        "n_ctx": model_params["n_ctx"],
        "n_batch": model_params["n_batch"],
        "chat_format": model_params["chat_format"],
        "seed": model_params["seed"],
        "n_gpu_layers": model_params["n_gpu_layers"],
        "n_threads": model_params.get("n_threads"),
        "requested_model_revision": getattr(self, "cfg_model_revision", None),
        "draft_model_config_sha256": self._opaque_config_sha256(model_params.get("draft_model")),
      },
      "generation_defaults": {
        "temperature": getattr(self, "cfg_default_temperature", None),
        "top_p": getattr(self, "cfg_default_top_p", None),
        "max_tokens": getattr(self, "cfg_default_max_tokens", None),
        "repeat_penalty": getattr(self, "cfg_repetition_penalty", None),
        "response_format": self.get_default_response_format(),
      },
    }
    document["fingerprint_sha256"] = self._canonical_sha256(document)
    self._runtime_fingerprint = document

  def get_runtime_fingerprint(self):
    fingerprint = getattr(self, "_runtime_fingerprint", None)
    return copy.deepcopy(fingerprint) if isinstance(fingerprint, dict) else None

  def get_worker_code_identity(self):
    serving_module_sha256 = getattr(type(self), "WORKER_MODULE_SHA256", None)
    if not isinstance(serving_module_sha256, str):
      return None
    return {
      "schema_version": "edgeguard.serving-code-identity.v1",
      "serving_module_sha256": serving_module_sha256,
      "llama_cpp_base_sha256": LLAMA_CPP_BASE_MODULE_SHA256,
    }

  def benchmark_generation_config_sha256(self, predict_kwargs):
    normalized = {
      "temperature": predict_kwargs.get("temperature"),
      "top_p": predict_kwargs.get("top_p"),
      "max_tokens": predict_kwargs.get("max_tokens"),
      "repeat_penalty": predict_kwargs.get("repeat_penalty"),
      "response_format": predict_kwargs.get("response_format"),
    }
    return self._canonical_sha256(normalized)

  def _get_model_path(self):
    model_path = self.cfg_model_path
    if model_path is None:
      return None
    if isinstance(model_path, str):
      model_path = model_path.strip()
      if not model_path:
        return None
    return os.path.abspath(os.path.expanduser(os.fspath(model_path)))

  def _get_model_path_display_name(self, model_path):
    model_name = os.path.basename(model_path.rstrip(os.sep))
    return model_name or "local_gguf_model"

  def _load_tokenizer(self):
    # llama.cpp uses built-in tokenizer
    return

  def get_model_name(self):
    model_path = self._get_model_path()
    if model_path is not None:
      return self._get_model_path_display_name(model_path)
    # endif local model path
    model_id = self.cfg_model_name
    model_filename = self.cfg_model_filename
    if model_id is None or model_filename is None:
      raise ValueError("Either MODEL_PATH or both MODEL_NAME and MODEL_FILENAME must be specified for Llama_cpp models.")
    # endif model id/filename check
    return f"{model_id}/{model_filename}"

  def get_chat_format(self):
    return self.cfg_chat_format

  def get_draft_model(self):
    return self.cfg_draft_model

  def get_n_gpu_layers(self):
    configured_n_gpu_layers = self.cfg_n_gpu_layers
    gpu_info = self.log.gpu_info()
    gpu_available = len(gpu_info) > 0
    gpu_offload_supported = self._llama_supports_gpu_offload()
    # Initially, only CPU is used.
    n_gpu_layers = 0
    if configured_n_gpu_layers is None:
      # AUTO: If gpu is available attempt to move all layers on GPU
      if gpu_available and gpu_offload_supported is False:
        self.P("WARN: GPU detected, but llama-cpp-python was built without GPU offload support. Switching to N_GPU_LAYERS=0.")
      else:
        n_gpu_layers = -1 if gpu_available else 0
    else:
      # CONFIGURED: n_gpu_layers provided => check if valid
      if configured_n_gpu_layers != 0:
        if not gpu_available:
          self.P(f"WARN: N_GPU_LAYERS={configured_n_gpu_layers}, but GPU not available. Switching to N_GPU_LAYERS=0.")
        elif gpu_offload_supported is False:
          self.P(
            f"WARN: N_GPU_LAYERS={configured_n_gpu_layers}, but llama-cpp-python was built without GPU offload support. "
            "Switching to N_GPU_LAYERS=0."
          )
        else:
          n_gpu_layers = configured_n_gpu_layers
      # endif n_gpu_layers provided and not 0
    # endif n_gpu_layers auto
    return n_gpu_layers

  def _llama_supports_gpu_offload(self):
    support_fn = getattr(llama_cpp_lib, 'llama_supports_gpu_offload', None)
    if not callable(support_fn):
      return None
    try:
      return bool(support_fn())
    except Exception as exc:
      self.P(f"WARN: Could not determine llama.cpp GPU offload support: {exc}")
      return None

  def get_default_response_format(self):
    return self.cfg_default_response_format

  def _load_model(self):
    model_path = self._get_model_path()
    model_id = self.cfg_model_name
    model_filename = self.cfg_model_filename
    if model_path is not None:
      model_ref = self._get_model_path_display_name(model_path)
      if not os.path.isfile(model_path):
        raise FileNotFoundError(f"Llama_cpp MODEL_PATH does not exist or is not a file: {model_ref}")
      # endif invalid local path
      safe_model_id = model_ref
    else:
      if model_id is None or model_filename is None:
        raise ValueError("Either MODEL_PATH or both MODEL_NAME and MODEL_FILENAME must be specified for Llama_cpp models.")
      # endif model id/filename check
      model_ref = f"{model_id}/{model_filename}"
      safe_model_id = model_id
    # endif local path

    n_ctx = self.cfg_model_n_ctx
    if not isinstance(n_ctx, (int, float)):
      n_ctx = MODEL_N_CTX_DEFAULT_VALUE
    # endif not int/float
    n_ctx = max(MODEL_N_CTX_MIN_VALUE, int(n_ctx))

    model_params = {
      'n_ctx': n_ctx,
      'seed': self.cfg_generation_seed,
      'n_batch': MODEL_N_BATCH_DEFAULT_VALUE,
      'chat_format': self.get_chat_format(),
      'draft_model': self.get_draft_model(),
      'n_gpu_layers': self.get_n_gpu_layers(),
      'verbose': True,
    }
    n_threads = self.cfg_n_threads
    if isinstance(n_threads, (int, float)) and int(n_threads) > 0:
      model_params['n_threads'] = int(n_threads)
    # endif configured thread count

    if model_path is not None:
      self.P(f"Loading Llama_cpp model from local file '{model_ref}' with parameters: {self.json_dumps(model_params, indent=2)}")
    else:
      self.P(f"Loading Llama_cpp model '{model_id}' from file '{model_filename}' with parameters: {self.json_dumps(model_params, indent=2)}")
    # endif local path

    # This is safe because the _llama_from_pretrained() method will be called
    # synchronously by safe_load_model() and if the first time it fails it will be
    # called a second time.
    # Maybe future TODO: switch to counting the attempts instead of just checking
    # if this is the second call
    first_attempt_done = False
    loaded_model_path = model_path

    def _load_llama_cpp_model():
      nonlocal first_attempt_done, loaded_model_path
      if first_attempt_done:
        # This means, this is the second attempt to load the model.
        # => The first attempt failed, so n_gpu_layers is switched to 0
        if model_params['n_gpu_layers'] != 0:
          self.P(f"Initial model loading attempt failed. Changing n_gpu_layers to 0 for safety.")
          model_params['n_gpu_layers'] = 0
        # endif layers offloaded to GPU
      first_attempt_done = True
      # endif not the first attempt
      if model_path is not None:
        return Llama(
          model_path=model_path,
          **model_params,
        )
      # endif local model path
      try:
        from huggingface_hub import HfApi, hf_hub_download
      except ImportError:
        raise ImportError(
          "Downloading Llama_cpp models from Hugging Face requires the huggingface-hub package. "
          "Install it or configure MODEL_PATH to an existing local GGUF file."
        )
      # endtry

      hf_api = HfApi(token=self.hf_token)
      repo_files = hf_api.list_repo_files(
        repo_id=model_id,
        revision=self.cfg_model_revision,
        token=self.hf_token,
      )
      matching_files = [file for file in repo_files if fnmatch(file, model_filename)]
      if len(matching_files) == 0:
        raise ValueError(
          f"No file found in {model_id} that matches {model_filename}. "
          f"Available files: {self.json_dumps(repo_files)}"
        )
      # endif no matching files
      if len(matching_files) > 1:
        raise ValueError(
          f"Multiple files found in {model_id} that match {model_filename}. "
          f"Matching files: {self.json_dumps(matching_files)}"
        )
      # endif multiple matching files

      matching_file = matching_files[0]
      subfolder_path = Path(matching_file).parent
      subfolder = None if str(subfolder_path) == "." else str(subfolder_path)
      downloaded_model_path = hf_hub_download(
        repo_id=model_id,
        filename=Path(matching_file).name,
        subfolder=subfolder,
        cache_dir=self.cache_dir,
        revision=self.cfg_model_revision,
        token=self.hf_token,
      )
      loaded_model_path = downloaded_model_path
      return Llama(
        model_path=downloaded_model_path,
        **model_params,
      )

    self.model = self.safe_load_model(
      load_model_method=_load_llama_cpp_model,
      model_id=safe_model_id,
      model_str_id=model_ref,
    )
    if loaded_model_path is None or not os.path.isfile(loaded_model_path):
      raise RuntimeError("Loaded GGUF artifact path is unavailable for runtime fingerprinting.")
    self._cache_runtime_fingerprint(loaded_model_path, model_params)
    self.P("Model loaded successfully.")
    return

  def maybe_add_context_to_messages(
      self,
      messages: list[dict],
      context: list or str = None
  ):
    if not isinstance(messages, list):
      self.maybe_exception("messages must be a list of {role, content} dicts")
    # endif messages type check
    if context is not None and isinstance(context, (list, str)) and len(context) > 0:
      if isinstance(context, str):
        context = [context]
      # endif context is str
      context = [c for c in context if isinstance(c, str) and len(c) > 0]
      # endif non-empty chat
    # endif context provided
    valid_messages = all(
      isinstance(m, dict) and LlmCT.ROLE_KEY in m and LlmCT.DATA_KEY in m
      for m in messages
    )
    if not valid_messages:
      msg = f"Each message in `messages` must be a dict with `role` and `content` keys. Invalid messages:\n{messages}"
      self.maybe_exception(msg)
    # endif valid messages
    if not isinstance(context, list) or len(context) == 0:
      return messages
    # endif empty context
    res, last_user_message, system_message = [], None, None
    for message in messages:
      role = message.get(LlmCT.ROLE_KEY, None)
      content = message.get(LlmCT.DATA_KEY, None)
      if role is None or content is None:
        msg = f"Each message in `messages` must have a `role` and `content`. Invalid message:\n{message}"
        self.maybe_exception(msg)
      # endif role/content check
      if role == LlmCT.SYSTEM_ROLE:
        system_message = message
      elif role == LlmCT.REQUEST_ROLE:
        if last_user_message is not None:
          res.append(last_user_message)
        # endif last user message
        last_user_message = message
      elif role == LlmCT.REPLY_ROLE:
        # assistant reply, so a new user message should come after this
        if last_user_message is not None:
          res.append(last_user_message)
          last_user_message = None
        # endif last user message
        res.append(message)
      # endif role check
    # endfor messages
    res = ([system_message] + res) if system_message is not None else res
    if last_user_message is not None:
      last_user_message_text = self.add_context_to_request(
        last_user_message[LlmCT.DATA_KEY],
        context
      )
      last_user_message[LlmCT.DATA_KEY] = last_user_message_text
      res.append(last_user_message)
    # endif last user message
    return res

  def _pre_process(self, inputs):
    lst_inputs = inputs.get('DATA', [])
    self.P(f"[DEBUG_LLM]Received {len(lst_inputs)} inputs for processing")

    predict_kwargs_lst = []
    messages_lst = []
    additional_lst = []
    valid_conditions = []
    process_methods = []
    relevant_input_ids = []
    cnt_total_inputs = len(lst_inputs)

    for i, inp in enumerate(lst_inputs):
      if self.check_relevant_input(inp):
        relevant_input_ids.append(i)
      else:
        continue

      jeeves_content = inp.get("JEEVES_CONTENT")
      jeeves_content = {
        (k.upper() if isinstance(k, str) else k): v
        for k, v in jeeves_content.items()
      }
      request_id = jeeves_content.get(LlmCT.REQUEST_ID, None)
      messages = jeeves_content.get(LlmCT.MESSAGES, [])
      temperature = jeeves_content.get(LlmCT.TEMPERATURE)
      if temperature is None:
        temperature = self.cfg_default_temperature
      top_p = jeeves_content.get(LlmCT.TOP_P) or self.cfg_default_top_p
      max_tokens = jeeves_content.get(LlmCT.MAX_TOKENS) or self.cfg_default_max_tokens
      repetition_penalty = jeeves_content.get("REPETITION_PENALTY", self.cfg_repetition_penalty)
      request_context = jeeves_content.get(LlmCT.CONTEXT, None)
      benchmark_mode = jeeves_content.get(LlmCT.BENCHMARK_MODE, False) is True
      valid_condition = None if benchmark_mode else jeeves_content.get(LlmCT.VALID_CONDITION, None)
      process_method = None if benchmark_mode else jeeves_content.get(LlmCT.PROCESS_METHOD, None)
      response_format = jeeves_content.get(LlmCT.RESPONSE_FORMAT, self.get_default_response_format())
      predict_kwargs = {
        'temperature': temperature,
        'top_p': top_p,
        'max_tokens': max_tokens,
        'repeat_penalty': repetition_penalty,
        'response_format': response_format,
      }
      predict_kwargs = self.process_predict_kwargs(predict_kwargs)
      if not isinstance(messages, list):
        msg = f"Each input must have a list of messages. Received {type(messages)}: {self.shorten_str(inp)}"
        self.maybe_exception(msg)
      # endif messages not list
      processed_messages = self.maybe_add_context_to_messages(
        messages=messages,
        context=request_context
      )
      messages_lst.append(processed_messages)
      predict_kwargs_lst.append(predict_kwargs)
      additional_lst.append({
        LlmCT.REQUEST_ID: request_id,
        LlmCT.BENCHMARK_MODE: benchmark_mode,
      })
      valid_conditions.append(valid_condition)
      process_methods.append(process_method)
    # endfor lst_inputs

    return [
      predict_kwargs_lst,
      messages_lst,
      additional_lst,
      valid_conditions,
      process_methods,
      relevant_input_ids,
      cnt_total_inputs,
    ]

  def _predict(self, preprocessed_batch):
    [
      predict_kwargs_lst,
      messages_lst,
      additional_lst,
      valid_conditions,
      process_methods,
      relevant_input_ids,
      cnt_total_inputs,
    ] = preprocessed_batch

    results = [
      # (idx, valid, process_method, reply, full_output)
      (idx, valid_condition, process_methods[idx], None, None)
      for idx, valid_condition in enumerate(valid_conditions)
    ]
    obj_for_inference = [
      # original index, current index
      (idx, idx) for idx in range(len(valid_conditions))
    ]
    conditions_satisfied = False if len(valid_conditions) > 0 else True
    max_tries = 10
    tries = 0
    while not conditions_satisfied:
      reply_lst = []
      full_output_lst = []
      t0 = self.time()
      timings = []
      total_generated_tokens = 0
      for idx_orig, idx_curr in obj_for_inference:
        messages = messages_lst[idx_orig]
        predict_kwargs = predict_kwargs_lst[idx_orig]
        benchmark_mode = additional_lst[idx_orig].get(LlmCT.BENCHMARK_MODE, False) is True
        generation_config_sha256 = self.benchmark_generation_config_sha256(predict_kwargs)
        t1 = self.time()
        reset_succeeded = False
        reset = getattr(self.model, "reset", None)
        if benchmark_mode and not callable(reset):
          out = {"error": {"code": BENCHMARK_RESET_UNAVAILABLE_CODE}}
        else:
          if benchmark_mode:
            try:
              reset()
              reset_succeeded = True
            except Exception:
              out = {"error": {"code": BENCHMARK_RESET_FAILED_CODE}}
          if not benchmark_mode or reset_succeeded:
            try:
              out = self.model.create_chat_completion(
                messages=messages,
                **predict_kwargs
              )
            except ValueError as exc:
              context_match = CONTEXT_WINDOW_ERROR_RE.search(str(exc))
              if context_match is None:
                raise
              out = {
                "error": {
                  "code": CONTEXT_WINDOW_ERROR_CODE,
                  "message": CONTEXT_WINDOW_ERROR_MESSAGE,
                  "requested_tokens": int(context_match.group(1)),
                  "context_window": int(context_match.group(2)),
                },
              }
        if benchmark_mode and isinstance(out, dict):
          out[BENCHMARK_TELEMETRY_KEY] = {
            "reset_succeeded": reset_succeeded,
            "attempt_count": 1 if reset_succeeded else 0,
            "generation_config_sha256": generation_config_sha256,
          }
        elapsed = self.time() - t1
        timings.append(elapsed)
        inference_error = out.get("error") if isinstance(out, dict) else None
        reply = "" if inference_error else out["choices"][0]["message"]["content"]
        num_tokens_generated = 0 if inference_error else out["usage"]["completion_tokens"]
        total_generated_tokens += num_tokens_generated
        reply_lst.append(reply)
        full_output_lst.append(out)
      # endfor obj_for_inference
      t_total = self.time() - t0
      curr_tps = total_generated_tokens / t_total if t_total > 0 else 0
      self._tps.append(curr_tps)
      self.P(f"Model ran at {curr_tps:.3f} tokens per second")

      invalid_objects = []
      tries += 1
      for idx_orig, idx_curr in obj_for_inference:
        valid_condition = results[idx_orig][1]
        process_method = results[idx_orig][2]
        current_text = reply_lst[idx_curr]
        full_output = full_output_lst[idx_curr]
        if isinstance(full_output, dict) and isinstance(full_output.get("error"), dict):
          results[idx_orig] = (idx_orig, valid_condition, process_method, current_text, full_output)
          continue
        self.P(
          f"Checking condition for object {idx_orig}: "
          f"valid=`{valid_condition}` process=`{process_method}` text_chars={len(current_text)}"
        )
        current_text = self.maybe_process_text(current_text, process_method)
        self.P(f"Processed object {idx_orig}: text_chars={len(current_text)}")
        valid_text = (
            len(current_text) > 0
            and (
                valid_condition is None
                or self.check_condition(current_text, valid_condition)
            )
        )
        benchmark_mode = additional_lst[idx_orig].get(LlmCT.BENCHMARK_MODE, False) is True
        current_condition_satisfied = valid_text or benchmark_mode or (tries >= max_tries)
        if current_condition_satisfied:
          # If the condition is satisfied, we can save the result
          results[idx_orig] = (idx_orig, valid_condition, process_method, current_text, full_output)
        else:
          invalid_objects.append((idx_orig, len(invalid_objects)))
        # endif current condition satisfied
      # endfor obj_for_inference

      if len(invalid_objects) > 0 and tries < max_tries:
        obj_for_inference = invalid_objects
      else:
        conditions_satisfied = True
    # endwhile conditions_satisfied

    text_lst = [text for _, _, _, text, _ in results]
    full_output_lst = [full_output for _, _, _, _, full_output in results]
    dct_result = {
      LlmCT.PRMP: messages_lst,
      LlmCT.TEXT: text_lst,
      LlmCT.ADDITIONAL: additional_lst,
      "RELEVANT_IDS": relevant_input_ids,
      "TOTAL_INPUTS": cnt_total_inputs,
      LlmCT.FULL_OUTPUT: full_output_lst,
    }
    return dct_result

  def _post_process(self, preds_batch):
    # This method can be missing here, but is present in case
    # of future customizations.
    results = super(LlamaCppBaseServingProcess, self)._post_process(preds_batch)
    for result in results:
      full_output = result.get(LlmCT.FULL_OUTPUT) if isinstance(result, dict) else None
      benchmark_telemetry = full_output.get(BENCHMARK_TELEMETRY_KEY) if isinstance(full_output, dict) else None
      if isinstance(benchmark_telemetry, dict):
        result[BENCHMARK_TELEMETRY_KEY] = benchmark_telemetry
      inference_error = full_output.get("error") if isinstance(full_output, dict) else None
      if not isinstance(inference_error, dict):
        continue
      if inference_error.get("code") != CONTEXT_WINDOW_ERROR_CODE:
        continue
      result["IS_VALID"] = False
      result["ERROR_CODE"] = CONTEXT_WINDOW_ERROR_CODE
      result["ERROR"] = CONTEXT_WINDOW_ERROR_MESSAGE
    return results
