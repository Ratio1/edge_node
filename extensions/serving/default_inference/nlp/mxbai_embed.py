from extensions.serving.base.base_doc_emb_serving import BaseDocEmbServing as BaseServingProcess

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "MODEL_NAME": "mixedbread-ai/mxbai-embed-large-v1",

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class MxbaiEmbed(BaseServingProcess):
  CONFIG = _CONFIG
