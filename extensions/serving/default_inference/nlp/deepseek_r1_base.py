"""
@misc{deepseekai2025deepseekr1incentivizingreasoningcapability,
      title={DeepSeek-R1: Incentivizing Reasoning Capability in LLMs via Reinforcement Learning},
      author={DeepSeek-AI},
      year={2025},
      eprint={2501.12948},
      archivePrefix={arXiv},
      primaryClass={cs.CL},
      url={https://arxiv.org/abs/2501.12948},
}

models:
  deepseek-ai/DeepSeek-R1-Distill-Qwen-7B
  deepseek-ai/DeepSeek-R1-Distill-Qwen-14B
  deepseek-ai/DeepSeek-R1-Distill-Qwen-32B

  deepseek-ai/DeepSeek-R1-Distill-Llama-8B
  deepseek-ai/DeepSeek-R1-Distill-Llama-70B


Testing:
  A. Launch OnDemandTextInput with Explorer
  B. Write custom command (see below)



for DeepSeek-R1 in-filling:
```json
{
  "ACTION" : "PIPELINE_COMMAND",
  "PAYLOAD" : {
    "NAME": "llm_request",
    "PIPELINE_COMMAND" : {
      "STRUCT_DATA" : {
        "request" : "What is the square root of 4?",
        "history" : [
          {
            "request"   : "hello",
            "response"  : "Hello, how can I help you today?"
          }
        ],
        "system_info" : "You are a funny university teacher. Your task is to help students with their learning journey."
      }
    }
  }
}
```
"""

from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "MODEL_NAME": None,
  "DEFAULT_TEMPERATURE": 0.6,

  "PICKED_INPUT": "STRUCT_DATA",
  "RUNS_ON_EMPTY_INPUT": False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class DeepseekR1Base(BaseServingProcess):
  CONFIG = _CONFIG

  def _get_prompt_from_template(self, messages, context=None):
    """
    Combines roles (system/user/assistant) but inlines system instructions
    into the user prompt only—no separate role for 'system'.
    """
    if not isinstance(messages, list):
      self.maybe_exception(f"`messages` must be a list of dicts. Got {type(messages)}")

    # Extract system info if present
    system_content = None
    chat_msgs = []
    for msg in messages:
      role = msg.get('role')
      content = msg.get('content')
      if not role or not isinstance(content, str):
        self.maybe_exception(f"Invalid message: {msg}")
      if role == 'system':
        system_content = content.strip()
      else:
        chat_msgs.append({'role': role, 'content': content.strip()})

    # Build user prompt by inlining system_content at the very start
    if system_content:
      system_block = f"### Instructions:\n{system_content}\n\n"
    else:
      system_block = ""

    # Format chat context/history
    convo = ""
    for msg in chat_msgs:
      convo += f"[{msg['role'].capitalize()}]: {msg['content']}\n\n"

    # Optionally attach external context as before
    if context:
      formatted_ctx = "\n\n".join(f"* Context {i + 1}: {c.strip()}"
                                  for i, c in enumerate(context) if isinstance(c, str) and c.strip())
      if formatted_ctx:
        convo += f"---\nContext data:\n{formatted_ctx}\n---\n"

    # Final assembly: only user prompt
    final_prompt = (
        system_block +
        convo +
        "<think>\n"  # Encourages reasoned output as per guidance
    )

    self.P(f"Constructed prompt for DeepSeek-R1:\n{final_prompt}")
    return final_prompt

  def maybe_process_text(self, text: str, process_method: str):
    """
    Remove the chain of thought and reasoning instructions from the text.
    Parameters
    ----------
    text : str
        the text to process
    process_method : str
        the method to process the text, e.g., "remove_cot"

    Returns
    -------
    res : str
        the processed text
    """
    if "</think>" in text:
      # Remove everything before the closing tag
      text = text.split("</think>")[-1].strip()
    # endif
    # Continue with the base class processing
    return super(DeepseekR1Base, self).maybe_process_text(text, process_method)
