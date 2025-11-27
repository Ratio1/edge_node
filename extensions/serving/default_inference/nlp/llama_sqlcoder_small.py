"""
Model from https://huggingface.co/defog/llama-3-sqlcoder-8b
"""

from extensions.serving.default_inference.nlp.llama_sqlcoder import LlamaSqlcoder as BaseServingProcess
from extensions.serving.mixins_llm.llm_utils import LlmCT

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "MODEL_NAME": "defog/sqlcoder-7b-2",

  "DEFAULT_NUM_BEAMS": 4,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class LlamaSqlcoderSmall(BaseServingProcess):
  CONFIG = _CONFIG

  def generate_prompt(self, user_request, instructions=None):
    instructions_str = f"### Instructions \n{instructions}" if instructions else ""
    res = f"""### Task
Generate a SQL DDL statement to answer [QUESTION]{user_request}[/QUESTION]
{instructions_str}

### Answer
The following SQL DDL statement best answers the request `{user_request}`:

### Database Schema
There is currently NO existing database schema.
You must design the necessary schema objects from scratch
using a single SQL DDL statement that satisfies the question.

### Task
Given that there is currently no existing schema, here is the SQL DDL statement that satisfies [QUESTION]{user_request}[/QUESTION]
[SQL]
"""
    return res

