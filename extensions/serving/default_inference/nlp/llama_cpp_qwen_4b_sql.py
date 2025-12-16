"""
Model from https://huggingface.co/mradermacher/Qwen3-4B-SQL-Writer-GGUF
"""

from extensions.serving.default_inference.nlp.llama_cpp_base import LlamaCppBaseServingProcess as BaseServingProcess

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "MODEL_NAME": "mradermacher/Qwen3-4B-SQL-Writer-GGUF",
  "MODEL_FILENAME": "Qwen3-4B-SQL-Writer.Q8_0.gguf",

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class LlamaCppQwen4BSql(BaseServingProcess):
  CONFIG = _CONFIG

  def process_predict_kwargs(self, predict_kwargs: dict):
    predict_kwargs["temperature"] = 0.6
    return predict_kwargs

  def maybe_process_text(self, text: str, process_method: str):
    processed_text = super(LlamaCppQwen4BSql, self).maybe_process_text(text=text, process_method=process_method)
    if '</think>' in text:
      processed_text = processed_text[processed_text.find('</think>')+len('<think>'):]
    # endif thinking in the output
    return processed_text


