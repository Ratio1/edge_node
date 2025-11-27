"""
Model from https://huggingface.co/defog/llama-3-sqlcoder-8b
"""

from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess
from extensions.serving.mixins_llm.llm_utils import LlmCT

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "MODEL_NAME": "defog/llama-3-sqlcoder-8b",

  "PICKED_INPUT": "STRUCT_DATA",
  "RUNS_ON_EMPTY_INPUT": False,
  "DEFAULT_TEMPERATURE": 0.0,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class LlamaSqlcoder(BaseServingProcess):
  CONFIG = _CONFIG

  def generate_prompt(self, user_request, instructions=None):
    res = f"""Generate a SQL DDL statement to answer this request: `{user_request}`
{instructions or ""}

<|eot_id|><|start_header_id|>assistant<|end_header_id|>
The following SQL DDL statement best answers the request `{user_request}`:
```sql
"""
    return res

  def _get_prompt_from_template(self, messages, context=None):
    chat = self.preprocess_messages(messages, context)
    prompt = None
    if len(chat) > 0:
      first_chat = chat[0]
      instructions = None
      if first_chat[LlmCT.ROLE_KEY] == LlmCT.SYSTEM_ROLE:
        instructions = first_chat[LlmCT.DATA_KEY]
        chat = chat[1:]
      # endif system role
      if len(chat) > 0:
        last_message = chat[-1]
        chat = chat[:-1]
        prompt = self.generate_prompt(last_message[LlmCT.DATA_KEY], instructions)
      else:
        # If only system message exists, no processing is needed
        chat = [first_chat]
      # endif non-empty chat
    # endif non-empty chat
    if prompt is None:
      date_string = self.datetime.now(self.timezone.utc).date().isoformat()
      prompt = self.tokenizer.apply_chat_template(
        chat, tokenize=False,
        add_generation_prompt=self.cfg_add_generation_prompt,
        # date_string=date_string,
      )
    # endif prompt is None
    self.P(f"Generated prompt:\n{prompt}")
    return prompt

