# LLM constants

B_INST, E_INST = "[INST]", "[/INST]"
B_SYS, E_SYS = "<<SYS>>\n", "\n<</SYS>>\n\n"


class LlmCT:
  P_USER_START = B_INST
  P_USER_END = E_INST
  P_ROUND_START = '<s>'
  P_ROUND_END = '</s>'
  P_SYS_START = B_SYS
  P_SYS_END = E_SYS

  HIST = 'history'
  REQ = 'request'
  RES = 'response'
  SYS = 'system_info'
  CTX = 'context'

  PRED = 'prediction'
  TEXT = 'text'
  TKNS = 'tokens'
  PRMP = 'prompt'
  TPS  = 'tps'

  ADDITIONAL = 'ADDITIONAL'
  MESSAGES = 'MESSAGES'
  TEMPERATURE = 'TEMPERATURE'
  TOP_P = 'TOP_P'
  MAX_TOKENS = 'MAX_TOKENS'
  CONTEXT = 'CONTEXT'
  REQUEST_ID = 'REQUEST_ID'
  REQUEST_TYPE = 'REQUEST_TYPE'
  VALID_MASK = 'VALID_MASK'

  # Constants for encoding a prompt using chat templates
  REQUEST_ROLE = 'user'
  REPLY_ROLE = 'assistant'
  SYSTEM_ROLE = 'system'
  ROLE_KEY = 'role'
  DATA_KEY = 'content'

  EE_HF_TOKEN = 'EE_HF_TOKEN'

  LLAMA3_CHAT_TEMPLATE = """{{ bos_token }}
{% if messages[0]['role'] == 'system' %}
    {% set loop_messages = messages[1:] %}
    {% set system_message = '<|start_header_id|>' + 'system' + '<|end_header_id|>\n\n' + messages[0]['content'].strip() + '<|eot_id|>' %}
{% else %}
    {% set loop_messages = messages %}
    {% set system_message = '' %}
{% endif %}

{% for message in loop_messages %}
    {% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}
        {{ raise_exception('Conversation roles must alternate user/assistant/user/assistant/...') }}
    {% endif %}

    {% if loop.index0 == 0 %}
        {{ system_message }}
    {% endif %}

    {{ '<|start_header_id|>' + message['role'] + '<|end_header_id|>\n\n' + message['content'].strip() + '<|eot_id|>' }}

    {% if loop.last and message['role'] == 'user' and add_generation_prompt %}
        {{ '<|start_header_id|>' + 'assistant' + '<|end_header_id|>\n\n' }}
    {% endif %}
{% endfor %}
"""

  MISTRAL_CHAT_TEMPLATE = """{% if messages[0]['role'] == 'system' %}
    {% set loop_messages = messages[1:] %}
    {% set system_message = messages[0]['content'].strip() + '\n\n' %}
{% else %}
    {% set loop_messages = messages %}
    {% set system_message = '' %}
{% endif %}

{{ bos_token }}
{% for message in loop_messages %}
    {% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}
        {{ raise_exception('Conversation roles must alternate user/assistant/user/assistant/...') }}
    {% endif %}

    {% if loop.index0 == 0 %}
        {% set content = system_message + message['content'] %}
    {% else %}
        {% set content = message['content'] %}
    {% endif %}

    {% if message['role'] == 'user' %}
        {{ '[INST] ' + content.strip() + ' [/INST]' }}
    {% elif message['role'] == 'assistant' %}
        {{ ' ' + content.strip() + eos_token }}
    {% endif %}
{% endfor %}
"""

# END LLM constants

