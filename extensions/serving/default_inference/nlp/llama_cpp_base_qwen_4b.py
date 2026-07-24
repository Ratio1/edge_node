"""Unmodified Qwen3 4B GGUF serving profile for EdgeGuard comparisons."""

from extensions.serving.default_inference.nlp.llama_cpp_base import (
  LlamaCppBaseServingProcess as BaseServingProcess,
  source_file_sha256,
)

__VER__ = '0.1.0.0'
WORKER_MODULE_SHA256 = source_file_sha256(__file__)


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE": "cpu",
  "MODEL_NAME": "MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF",
  "MODEL_FILENAME": "Qwen3-4B-Instruct-2507.Q4_K_M.gguf",
  "MODEL_N_CTX": 4096,
  "N_GPU_LAYERS": 0,
  "N_THREADS": 4,
  "MODEL_INSTANCE_ID": "edgeguard-base-qwen3-4b",
  "DEFAULT_MAX_TOKENS": 512,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class LlamaCppBaseQwen4B(BaseServingProcess):
  CONFIG = _CONFIG
  WORKER_MODULE_SHA256 = WORKER_MODULE_SHA256
