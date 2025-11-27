from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess
from extensions.serving.mixins_llm.llm_utils import LlmCT
import os
from openai import OpenAI

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "MODEL_NAME": "gpt-3.5-turbo",

  "PICKED_INPUT": "STRUCT_DATA",

  "RUNS_ON_EMPTY_INPUT": False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class OpenaiServing(BaseServingProcess):
  def __init__(self, **kwargs):
    self._counter = 0
    super(OpenaiServing, self).__init__(**kwargs)
    return

  def _startup(self):
    api_key = self.cfg_openai_api_key
    if api_key is None:
      self.P(f"Environment variable EE_OPENAI_API_KEY not set. Exiting...")
      return
    self.model = OpenAI(
      api_key=api_key
    )
    self.P(f"Client prepared for inference through external request!")
    return

  def _setup_llm(self):
    # just override this method as the base class has a virtual method that raises an exception
    return

  def _pre_process(self, inputs):
    lst_inputs = inputs.get('DATA', [])
    lst_inputs = self.filter_inputs(lst_inputs)
    if len(lst_inputs) > 0:
      self.P(f"[DEBUG_LLM]Found {len(lst_inputs)} relevant inputs for processing")

    predict_kwargs_lst = []
    context_lst = []
    messages_lst = []
    additional_lst = []

    for i, inp in enumerate(lst_inputs):
      jeeves_content = inp.get("JEEVES_CONTENT")
      jeeves_content = {
        (k.upper() if isinstance(k, str) else k): v
        for k, v in jeeves_content.items()
      }
      request_id = jeeves_content.get(LlmCT.REQUEST_ID, None)
      messages = jeeves_content.get(LlmCT.MESSAGES, [])
      temperature = jeeves_content.get(LlmCT.TEMPERATURE) or self.cfg_default_temperature
      top_p = jeeves_content.get(LlmCT.TOP_P) or self.cfg_default_top_p
      max_tokens = jeeves_content.get(LlmCT.MAX_TOKENS) or self.cfg_default_max_tokens
      request_context = jeeves_content.get(LlmCT.CONTEXT, None)

      predict_kwargs = {
        'temperature': temperature,
        'top_p': top_p,
        # 'max_new_tokens': max_tokens,
      }

      messages_lst.append(messages)
      predict_kwargs_lst.append(predict_kwargs)
      context_lst.append(request_context)
      additional_lst.append({
        LlmCT.REQUEST_ID: request_id,
      })
    # endfor lst_inputs

    if len(messages_lst) == 0:
      return None

    return [messages_lst, context_lst, predict_kwargs_lst, additional_lst]

  def apply_context_to_messages(self, messages: list[dict], context: str) -> list[dict]:
    """
    Apply the context to the messages.
    """
    prev_messages, last_message = messages[:-1], messages[-1]
    if context is not None:
      context_message = {
        LlmCT.ROLE_KEY: LlmCT.REQUEST_ROLE,
        LlmCT.DATA_KEY: f"Context:\n{context}"
      }
      messages = prev_messages + [context_message] + [last_message]
    # endif context provided
    return messages

  def _predict(self, preprocessed_batch):
    if preprocessed_batch is None:
      return None

    messages_lst, context_lst, predict_kwargs_lst, additional_lst = preprocessed_batch
    results = []

    for (
      messages, context, predict_kwargs, additional
    ) in zip(messages_lst, context_lst, predict_kwargs_lst, additional_lst):
      self._counter += 1
      self.P(f"[DEBUG_LLM]Processing request {self._counter} with context {context}")

      messages = self.apply_context_to_messages(
        messages=messages,
        context=context,
      )

      response = self.model.chat.completions.create(
        model=self.get_model_name(),
        messages=messages,
        **predict_kwargs
      )
      self.P(f"[DEBUG_LLM]Response: {response}")

      dct_result = {
        LlmCT.TEXT: response,
        **additional,
        'MODEL_NAME': self.get_model_name(),
      }
      results.append(dct_result)
    # endfor preprocessed_batch

    return results

  def _post_process(self, preds_batch):
    if preds_batch is None:
      return None
    return preds_batch


