"""EdgeGuard-specific llama.cpp serving behavior."""

import os
import re
from fnmatch import fnmatch
from pathlib import Path

from llama_cpp import Llama

from extensions.serving.default_inference.nlp.llama_cpp_base import (
  MODEL_N_BATCH_DEFAULT_VALUE,
  MODEL_N_CTX_DEFAULT_VALUE,
  MODEL_N_CTX_MIN_VALUE,
  LlamaCppBaseServingProcess as BaseServingProcess,
  source_file_sha256,
)

__VER__ = "0.1.0"


EDGEGUARD_LLAMA_CPP_BASE_MODULE_SHA256 = source_file_sha256(__file__)


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

  def _get_model_path(self):
    """EdgeGuard model identity is always resolved from its pinned HF revision."""
    return None

  def get_worker_code_identity(self):
    identity = super(LlamaCppEdgeguardBaseServingProcess, self).get_worker_code_identity()
    if not isinstance(identity, dict):
      return None
    identity["llama_cpp_base_sha256"] = EDGEGUARD_LLAMA_CPP_BASE_MODULE_SHA256
    return identity

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
