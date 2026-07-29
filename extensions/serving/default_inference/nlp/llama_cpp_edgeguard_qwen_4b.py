"""EdgeGuard Cypher Qwen3 4B GGUF local serving profile."""

from extensions.serving.default_inference.nlp.llama_cpp_edgeguard_base import (
  LlamaCppEdgeguardBaseServingProcess as BaseServingProcess,
  source_file_sha256,
)

__VER__ = '0.1.0.0'
WORKER_MODULE_SHA256 = source_file_sha256(__file__)


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE": "cpu",
  "MODEL_NAME": "ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf",
  "MODEL_FILENAME": "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf",
  "MODEL_REVISION": "369066092b5eef41c9093474ff7142cc530a853f",
  "EXPECTED_MODEL_SHA256": "7f7ed0f4d3341d36204d17343a07e3b6d99ec135a4ce67da66ad09b8eba2a91b",
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
  WORKER_MODULE_SHA256 = WORKER_MODULE_SHA256
