"""CyberSecQwen 4B comparison profile isolated for EdgeGuard."""

from extensions.serving.default_inference.nlp.llama_cpp_edgeguard_base import (
  LlamaCppEdgeguardBaseServingProcess as BaseServingProcess,
  source_file_sha256,
)

__VER__ = '0.1.0.0'
WORKER_MODULE_SHA256 = source_file_sha256(__file__)


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE": "cpu",
  "MODEL_NAME": "mradermacher/CyberSecQwen-4B-GGUF",
  "MODEL_FILENAME": "CyberSecQwen-4B.Q4_K_M.gguf",
  "MODEL_REVISION": "4b369711d408b9fde0efcca155409c072b19a1f6",
  "EXPECTED_MODEL_SHA256": "ac6c98de9919a6891f966f87de6f6b50f7822235bf9c3ab8401ca6a897d02ecc",
  "MODEL_N_CTX": 4096,
  "N_GPU_LAYERS": 0,
  "N_THREADS": 4,
  "MODEL_INSTANCE_ID": "edgeguard-cybersec-qwen-4b",
  "DEFAULT_MAX_TOKENS": 1024,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class LlamaCppEdgeguardCybersecQwen4B(BaseServingProcess):
  CONFIG = _CONFIG
  WORKER_MODULE_SHA256 = WORKER_MODULE_SHA256
