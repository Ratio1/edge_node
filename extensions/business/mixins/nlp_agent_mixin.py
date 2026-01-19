from extensions.business.mixins.base_agent_mixin import BASE_AGENT_MIXIN_CONFIG, _BaseAgentMixin

NLP_AGENT_MIXIN_CONFIG = {
  **BASE_AGENT_MIXIN_CONFIG,
}


class _NlpAgentMixin(_BaseAgentMixin):
  def inference_to_response(self, inference, model_name, input_data):
    return {
      'REQUEST_ID': inference.get('REQUEST_ID'),
      'MODEL_NAME': model_name,
      'TEXT_RESPONSE': inference.get('text'),
    }

