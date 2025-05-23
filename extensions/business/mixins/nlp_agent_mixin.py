NLP_AGENT_MIXIN_CONFIG = {
  'OBJECT_TYPE': [],
  "ALLOW_EMPTY_INPUTS": False,  # if this is set to true the on-idle will be triggered continuously the process

  "VALIDATION_RULES": {
  },
}


class _NlpAgentMixin(object):
  def compute_and_send_responses(self, inferences):
    model_name = inferences[0].get('MODEL_NAME', None) if len(inferences) > 0 else None
    for inf in inferences:
      request_result = {
        'REQUEST_ID': inf.get('REQUEST_ID'),
        'MODEL_NAME': model_name,
        'TEXT_RESPONSE': inf.get('text'),
      }
      current_payload_kwargs = {
        'result': request_result,
        'request_id': inf.get('REQUEST_ID'),
      }
      self.add_payload_by_fields(**current_payload_kwargs)
    # endfor inferences
    return


