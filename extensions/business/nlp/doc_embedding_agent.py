from naeural_core.business.base import BasePluginExecutor as BasePlugin
from extensions.business.mixins.nlp_agent_mixin import _NlpAgentMixin, NLP_AGENT_MIXIN_CONFIG

__VER__ = '0.1.0.0'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,
  **NLP_AGENT_MIXIN_CONFIG,

  'MAX_INPUTS_QUEUE_SIZE': 64,

  # our overwritten props
  'AI_ENGINE': "doc_embed",
  "DOC_EMBED_STATUS_PERIOD": 20,
  'ALLOW_EMPTY_INPUTS': True,  # if this is set to true the on-idle will continuously trigger the process

  "DEBUG_MODE": True,

  'CHAINSTORE_RESPONSE_KEY': None,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class DocEmbeddingAgentPlugin(BasePlugin, _NlpAgentMixin):
  CONFIG = _CONFIG

  def on_init(self):
    self.__last_status_time = None
    self.__last_inference_meta = None
    self.__last_contexts = None
    super(DocEmbeddingAgentPlugin, self).on_init()
    return

  def _get_chainstore_response_data(self):
    data = super()._get_chainstore_response_data()
    data.update({
      'ai_engine': self.cfg_ai_engine,
      'doc_embed_status_period': self.cfg_doc_embed_status_period,
      'cached_contexts_count': len(self.__last_contexts or []),
      'has_cached_inference': self.__last_inference_meta is not None,
      'status': 'ready',
    })
    return data

  def send_status(self, inf_meta):
    self.add_payload_by_fields(
      contexts=inf_meta.get('contexts', []),
      model_name=inf_meta.get('model_name', ''),
      doc_embed_is_status=True,
    )
    return

  def load_cache(self):
    cached_data = self.cacheapi_load_json()
    if not cached_data:
      return

    inference_meta = cached_data.get('inference_meta', None)
    if isinstance(inference_meta, dict):
      self.__last_inference_meta = inference_meta
      self.__last_contexts = inference_meta.get('contexts', []) or []
    else:
      self.__last_inference_meta = None
      self.__last_contexts = []
    return

  def get_cache_object(self):
    return {
      'inference_meta': self.__last_inference_meta,
    }

  def check_new_metadata(self):
    current_contexts = self.__last_inference_meta.get('contexts', [])
    if self.__last_contexts != current_contexts:
      self.__last_contexts = current_contexts
      self.cacheapi_save_json(self.get_cache_object())
    return

  def maybe_send_status(self, inf_meta):
    if inf_meta is not None:
      inf_meta_lower = {(k.lower() if isinstance(k, str) else k): v for k, v in inf_meta.items()}
      self.__last_inference_meta = inf_meta_lower
      self.check_new_metadata()
    # endif update last inference meta

    if self.__last_inference_meta is None:
      return
    # endif no inference meta

    if self.__last_status_time is None or self.time() - self.__last_status_time > self.cfg_doc_embed_status_period:
      self.send_status(self.__last_inference_meta)
      self.__last_status_time = self.time()
    # endif time to send status
    return

  def inference_to_response(self, inference, model_name):
    return inference

  def _process(self):
    inf_meta = self.dataapi_inferences_meta().get(self.cfg_ai_engine)
    self.maybe_send_status(inf_meta)
    data = self.dataapi_struct_datas()
    inferences = self.dataapi_struct_data_inferences()
    self.handle_inferences(inferences, data=data)
    return
