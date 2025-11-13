NLP_AGENT_MIXIN_CONFIG = {
  'OBJECT_TYPE': [],
  "ALLOW_EMPTY_INPUTS": False,  # if this is set to true the on-idle will be triggered continuously the process
  "DEBUG_MODE": True,

  "VALIDATION_RULES": {
  },
}


class _NlpAgentMixin(object):
  def Pd(self, msg, **kwargs):
    if self.cfg_debug_mode:
      self.P(msg, **kwargs)
    return

  def filter_valid_inferences(self, inferences, return_idxs=False):
    res = []
    idxs = []
    for idx, inf in enumerate(inferences):
      if isinstance(inf, dict) and inf.get("IS_VALID", True):
        res.append(inf)
        idxs.append(idx)
    # endfor inferences
    return res if not return_idxs else (res, idxs)

  def inference_to_response(self, inference, model_name):
    return {
      'REQUEST_ID': inference.get('REQUEST_ID'),
      'MODEL_NAME': model_name,
      'TEXT_RESPONSE': inference.get('text'),
    }

  def handle_inferences(self, inferences, data=None):
    if not isinstance(inferences, list):
      return
    if len(inferences) > 0 and not isinstance(inferences[0], dict):
      return
    model_name = inferences[0].get('MODEL_NAME', None) if len(inferences) > 0 else None
    cnt_initial_inferences = len(inferences)
    inferences, valid_idxs = self.filter_valid_inferences(inferences, return_idxs=True)
    self.Pd(f"Filtered {cnt_initial_inferences} inferences to {len(inferences)} valid inferences.")
    if data is not None:
      filtered_data = [
        data[idx] for idx in valid_idxs
      ]
      if len(filtered_data) > 0:
        self.Pd(f"Received requests: {self.json_dumps(self.shorten_str(filtered_data), indent=2)}")
    # endif data is not None

    for inf in inferences:
      request_id = inf.get('REQUEST_ID', None)
      self.Pd(f"Processing inference for request ID: {request_id}, model: {model_name}")
      request_result = self.inference_to_response(inf, model_name)
      current_payload_kwargs = {
        'result': request_result,
        'request_id': request_id,
      }
      self.add_payload_by_fields(**current_payload_kwargs)
    # endfor inferences
    return

