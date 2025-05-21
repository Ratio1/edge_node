from naeural_core.business.base import BasePluginExecutor as BasePlugin

__VER__ = '0.1.0.0'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,

  'MAX_INPUTS_QUEUE_SIZE': 64,

  # our overwritten props
  'AI_ENGINE': "doc_embed",
  "DOC_EMBED_STATUS_PERIOD": 20,
  'ALLOW_EMPTY_INPUTS': True,  # if this is set to true the on-idle will continuously trigger the process

  "DEBUG_MODE": True,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class DocEmbeddingAgentPlugin(BasePlugin):
  CONFIG = _CONFIG

  def D(self, msg, **kwargs):
    if self.cfg_debug_mode:
      self.P(msg, **kwargs)
    return

  def on_init(self):
    self.__last_status_time = None
    self.__last_inference_meta = None
    self.__last_contexts = None
    super(DocEmbeddingAgentPlugin, self).on_init()
    return

  def send_status(self, inf_meta):
    self.add_payload_by_fields(
      contexts=inf_meta.get('contexts', []),
      model_name=inf_meta.get('model_name', ''),
      doc_embed_is_status=True,
    )
    return

  def load_cache(self):
    cached_data = self.cacheapi_load_json()
    if cached_data is not None and len(cached_data.keys()) > 0:
      self.__last_inference_meta = cached_data.get('inference_meta', None)
      self.__last_contexts = self.__last_inference_meta.get('contexts', [])
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

  def _process(self):
    data = self.dataapi_struct_data()
    inf_meta = self.dataapi_inferences_meta().get(self.cfg_ai_engine)
    self.maybe_send_status(inf_meta)
    if data is None or len(data) == 0:
      return
    inferences = self.dataapi_struct_data_inferences()
    if isinstance(inferences[0], list):
      return
    self.D(f'[Agent]Processing data: {str(data)[:50]}')
    self.D(f'[Agent]Processing inferences: {str(inferences)[:50]}')
    for inf in inferences:
      self.D(f'[Agent]Processing inference: {inf["REQUEST_ID"]}')
      # For each inference a response payload will be created
      request_id = inf.get('REQUEST_ID')
      request_result = inf
      self.D(f'[Agent]Processing inference: {request_result}')
      self.add_payload_by_fields(
        result=request_result,
        request_id=request_id,
      )
    # endfor inferences
    return
