"""EdgeGuard Cypher Qwen3 4B GGUF local serving profile."""

from extensions.serving.default_inference.nlp.llama_cpp_base import LlamaCppBaseServingProcess as BaseServingProcess

__VER__ = '0.1.0.0'


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE": "cpu",
  "MODEL_NAME": "ratio1/edgeguard-cypher-qwen3-4b-v0.5-preview-gguf",
  "MODEL_FILENAME": "edgeguard-cypher-qwen3-4b-v0.5-preview.Q4_K_M.gguf",
  "MODEL_N_CTX": 4096,
  "N_GPU_LAYERS": 0,
  "N_THREADS": 4,
  "MODEL_INSTANCE_ID": "edgeguard-qwen3-4b-cypher",

  # Keep default generations bounded on CPU. The agent only needs one query.
  "DEFAULT_MAX_TOKENS": 512,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class LlamaCppEdgeguardQwen4B(BaseServingProcess):
  CONFIG = _CONFIG
