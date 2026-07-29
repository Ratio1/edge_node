"""EdgeGuard-specific llama.cpp serving behavior."""

import copy
import hashlib
import importlib.metadata
import os
import re
from fnmatch import fnmatch
from pathlib import Path

from llama_cpp import Llama, llama_cpp as llama_cpp_lib

from extensions.serving.base import base_llm_serving as base_llm_serving_module
from extensions.serving.default_inference.nlp.llama_cpp_base import (
  MODEL_N_BATCH_DEFAULT_VALUE,
  MODEL_N_CTX_DEFAULT_VALUE,
  MODEL_N_CTX_MIN_VALUE,
  LlamaCppBaseServingProcess as BaseServingProcess,
)
from extensions.serving.mixins_llm import llm_utils as llm_utils_module
from extensions.serving.mixins_llm.llm_utils import LlmCT

__VER__ = "0.1.0"


def source_file_sha256(path):
  digest = hashlib.sha256()
  with open(path, "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
      digest.update(chunk)
  return digest.hexdigest()


EDGEGUARD_LLAMA_CPP_BASE_MODULE_SHA256 = source_file_sha256(__file__)
BASE_LLM_SERVING_MODULE_SHA256 = source_file_sha256(base_llm_serving_module.__file__)
LLM_UTILS_MODULE_SHA256 = source_file_sha256(llm_utils_module.__file__)
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

  "MODEL_REVISION": None,
  "EXPECTED_MODEL_SHA256": None,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class LlamaCppEdgeguardBaseServingProcess(BaseServingProcess):
  CONFIG = _CONFIG

  @staticmethod
  def _sha256_file(path):
    return source_file_sha256(path)

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
        "requested_model_revision": self.cfg_model_revision,
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

  def _get_model_path(self):
    """EdgeGuard model identity is always resolved from its pinned HF revision."""
    return None

  def get_worker_code_identity(self):
    serving_module_sha256 = getattr(type(self), "WORKER_MODULE_SHA256", None)
    if not isinstance(serving_module_sha256, str):
      return None
    return {
      "schema_version": "edgeguard.serving-code-identity.v2",
      "serving_module_sha256": serving_module_sha256,
      "llama_cpp_base_sha256": EDGEGUARD_LLAMA_CPP_BASE_MODULE_SHA256,
      "base_llm_serving_sha256": BASE_LLM_SERVING_MODULE_SHA256,
      "llm_utils_sha256": LLM_UTILS_MODULE_SHA256,
    }

  def benchmark_generation_config_sha256(self, predict_kwargs):
    normalized = {
      "temperature": predict_kwargs.get("temperature"),
      "top_p": predict_kwargs.get("top_p"),
      "max_tokens": predict_kwargs.get("max_tokens"),
      "repeat_penalty": predict_kwargs.get("repeat_penalty"),
      "response_format": predict_kwargs.get("response_format"),
      "seed": predict_kwargs.get("seed"),
    }
    return self._canonical_sha256(normalized)

  def _load_model(self):
    model_id = self.cfg_model_name
    model_filename = self.cfg_model_filename
    model_revision = self.cfg_model_revision
    expected_model_sha256 = self.cfg_expected_model_sha256
    if model_id is None or model_filename is None:
      raise ValueError("Both MODEL_NAME and MODEL_FILENAME must be specified for EdgeGuard llama_cpp models.")
    if not isinstance(model_revision, str) or re.fullmatch(r"[0-9a-f]{40}", model_revision) is None:
      raise ValueError("EdgeGuard MODEL_REVISION must be an exact 40-character lowercase commit SHA.")
    if (
      not isinstance(expected_model_sha256, str)
      or re.fullmatch(r"[0-9a-f]{64}", expected_model_sha256) is None
    ):
      raise ValueError("EdgeGuard EXPECTED_MODEL_SHA256 must be a lowercase SHA-256 digest.")

    model_ref = f"{model_id}/{model_filename}"
    n_ctx = self.cfg_model_n_ctx
    if not isinstance(n_ctx, (int, float)):
      n_ctx = MODEL_N_CTX_DEFAULT_VALUE
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

    self.P(
      f"Loading EdgeGuard Llama_cpp model '{model_id}' from file '{model_filename}' "
      f"at revision '{model_revision}' with parameters: {self.json_dumps(model_params, indent=2)}"
    )

    first_attempt_done = False
    loaded_model_path = None

    def _load_llama_cpp_model():
      nonlocal first_attempt_done, loaded_model_path
      if first_attempt_done and model_params['n_gpu_layers'] != 0:
        self.P("Initial model loading attempt failed. Changing n_gpu_layers to 0 for safety.")
        model_params['n_gpu_layers'] = 0
      first_attempt_done = True

      try:
        from huggingface_hub import HfApi, hf_hub_download
      except ImportError:
        raise ImportError(
          "Downloading EdgeGuard llama_cpp models requires the huggingface-hub package."
        )

      hf_api = HfApi(token=self.hf_token)
      repo_files = hf_api.list_repo_files(
        repo_id=model_id,
        revision=model_revision,
        token=self.hf_token,
      )
      matching_files = [file for file in repo_files if fnmatch(file, model_filename)]
      if len(matching_files) == 0:
        raise ValueError(
          f"No file found in {model_id} at revision {model_revision} that matches {model_filename}."
        )
      if len(matching_files) > 1:
        raise ValueError(
          f"Multiple files found in {model_id} at revision {model_revision} that match "
          f"{model_filename}: {self.json_dumps(matching_files)}"
        )

      matching_file = matching_files[0]
      subfolder_path = Path(matching_file).parent
      subfolder = None if str(subfolder_path) == "." else str(subfolder_path)
      downloaded_model_path = hf_hub_download(
        repo_id=model_id,
        filename=Path(matching_file).name,
        subfolder=subfolder,
        cache_dir=self.cache_dir,
        revision=model_revision,
        token=self.hf_token,
      )
      actual_model_sha256 = self._sha256_file(downloaded_model_path)
      if actual_model_sha256 != expected_model_sha256:
        raise RuntimeError(
          "EdgeGuard GGUF SHA-256 mismatch: "
          f"expected {expected_model_sha256}, got {actual_model_sha256}."
        )
      loaded_model_path = os.fspath(downloaded_model_path)
      return Llama(
        model_path=loaded_model_path,
        **model_params,
      )

    self.model = self.safe_load_model(
      load_model_method=_load_llama_cpp_model,
      model_id=model_id,
      model_str_id=model_ref,
    )
    if loaded_model_path is None or not os.path.isfile(loaded_model_path):
      raise RuntimeError("Loaded EdgeGuard GGUF artifact path is unavailable for runtime fingerprinting.")
    self._cache_runtime_fingerprint(loaded_model_path, model_params)
    self.P("Model loaded successfully.")
    return

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
      seed = jeeves_content.get(LlmCT.SEED)
      if seed is None:
        seed = self.cfg_generation_seed
      valid_condition = None if benchmark_mode else jeeves_content.get(LlmCT.VALID_CONDITION, None)
      process_method = None if benchmark_mode else jeeves_content.get(LlmCT.PROCESS_METHOD, None)
      response_format = jeeves_content.get(LlmCT.RESPONSE_FORMAT, self.get_default_response_format())
      predict_kwargs = {
        'temperature': temperature,
        'top_p': top_p,
        'max_tokens': max_tokens,
        'repeat_penalty': repetition_penalty,
        'response_format': response_format,
        'seed': seed,
      }
      predict_kwargs = self.process_predict_kwargs(predict_kwargs)
      if not isinstance(messages, list):
        msg = f"Each input must have a list of messages. Received {type(messages)}: {self.shorten_str(inp)}"
        self.maybe_exception(msg)
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
      (idx, valid_condition, process_methods[idx], None, None)
      for idx, valid_condition in enumerate(valid_conditions)
    ]
    obj_for_inference = [
      (idx, idx) for idx in range(len(valid_conditions))
    ]
    conditions_satisfied = False if len(valid_conditions) > 0 else True
    max_tries = 10
    tries = 0
    while not conditions_satisfied:
      reply_lst = []
      full_output_lst = []
      t0 = self.time()
      total_generated_tokens = 0
      for idx_orig, idx_curr in obj_for_inference:
        messages = messages_lst[idx_orig]
        predict_kwargs = predict_kwargs_lst[idx_orig]
        benchmark_mode = additional_lst[idx_orig].get(LlmCT.BENCHMARK_MODE, False) is True
        generation_config_sha256 = self.benchmark_generation_config_sha256(predict_kwargs)
        reset_ms = None
        generation_ms = None
        reset_succeeded = False
        reset = getattr(self.model, "reset", None)
        if benchmark_mode and not callable(reset):
          out = {"error": {"code": BENCHMARK_RESET_UNAVAILABLE_CODE}}
        else:
          if benchmark_mode:
            try:
              reset_started = self.time()
              reset()
              reset_ms = round((self.time() - reset_started) * 1000, 3)
              reset_succeeded = True
            except Exception:
              reset_ms = round((self.time() - reset_started) * 1000, 3)
              out = {"error": {"code": BENCHMARK_RESET_FAILED_CODE}}
          if not benchmark_mode or reset_succeeded:
            try:
              generation_started = self.time()
              out = self.model.create_chat_completion(
                messages=messages,
                **predict_kwargs
              )
              generation_ms = round((self.time() - generation_started) * 1000, 3)
            except ValueError as exc:
              generation_ms = round((self.time() - generation_started) * 1000, 3)
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
            "effective_generation_config": {
              "temperature": predict_kwargs.get("temperature"),
              "top_p": predict_kwargs.get("top_p"),
              "max_tokens": predict_kwargs.get("max_tokens"),
              "repeat_penalty": predict_kwargs.get("repeat_penalty"),
              "seed": predict_kwargs.get("seed"),
            },
            "reset_ms": reset_ms,
            "generation_ms": generation_ms,
          }
        inference_error = out.get("error") if isinstance(out, dict) else None
        reply = "" if inference_error else out["choices"][0]["message"]["content"]
        num_tokens_generated = 0 if inference_error else out["usage"]["completion_tokens"]
        total_generated_tokens += num_tokens_generated
        reply_lst.append(reply)
        full_output_lst.append(out)
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
          results[idx_orig] = (idx_orig, valid_condition, process_method, current_text, full_output)
        else:
          invalid_objects.append((idx_orig, len(invalid_objects)))

      if len(invalid_objects) > 0 and tries < max_tries:
        obj_for_inference = invalid_objects
      else:
        conditions_satisfied = True

    text_lst = [text for _, _, _, text, _ in results]
    full_output_lst = [full_output for _, _, _, _, full_output in results]
    return {
      LlmCT.PRMP: messages_lst,
      LlmCT.TEXT: text_lst,
      LlmCT.ADDITIONAL: additional_lst,
      "RELEVANT_IDS": relevant_input_ids,
      "TOTAL_INPUTS": cnt_total_inputs,
      LlmCT.FULL_OUTPUT: full_output_lst,
    }

  def _log_batch_text_prediction(self, text_lst):
    self.P(
      f"Found batch text prediction for {len(text_lst)} texts; "
      f"text_chars={[len(text) if isinstance(text, str) else 0 for text in text_lst]}"
    )
    return

  def _post_process(self, preds_batch):
    results = super(LlamaCppEdgeguardBaseServingProcess, self)._post_process(preds_batch)
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
