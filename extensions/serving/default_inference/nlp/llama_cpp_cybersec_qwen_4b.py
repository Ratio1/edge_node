"""
CyberSecQwen 4B GGUF local serving profile.

Initial RMM-002 target:
- CPU-only deployment on roughly 4 cores / 16 GB RAM.
- Q4_K_M GGUF for a practical quality/size balance.
- Dedicated serving process so RedMesh does not rely on a generic llama_cpp alias.
"""

from extensions.serving.default_inference.nlp.llama_cpp_base import LlamaCppBaseServingProcess as BaseServingProcess

__VER__ = '0.1.0.0'


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE": "cpu",
  "MODEL_NAME": "mradermacher/CyberSecQwen-4B-GGUF",
  "MODEL_FILENAME": "CyberSecQwen-4B.Q4_K_M.gguf",
  "MODEL_N_CTX": 4096,
  "N_GPU_LAYERS": 0,
  "MODEL_INSTANCE_ID": "cybersecqwen-4b",

  # Keep default generations bounded on CPU. Callers may request less.
  "DEFAULT_MAX_TOKENS": 1024,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class LlamaCppCybersecQwen4B(BaseServingProcess):
  CONFIG = _CONFIG
