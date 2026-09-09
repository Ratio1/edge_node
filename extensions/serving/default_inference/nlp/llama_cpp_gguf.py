"""Generic GGUF llama.cpp serving profile configured entirely by the pipeline.

This profile carries no model identity. The pipeline supplies the Hub repo,
filename and pinned revision (or a local model path) plus the instance id
through `STARTUP_AI_ENGINE_PARAMS`, so a private or experimental model can be
served without adding its identity to this repository.
"""

from extensions.serving.default_inference.nlp.llama_cpp_base import LlamaCppBaseServingProcess as BaseServingProcess

__VER__ = '0.1.0.0'


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE": "cpu",
  "MODEL_N_CTX": 4096,
  "N_GPU_LAYERS": 0,
  "N_THREADS": 4,
  "DEFAULT_MAX_TOKENS": 512,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },
}


class LlamaCppGguf(BaseServingProcess):
  CONFIG = _CONFIG
