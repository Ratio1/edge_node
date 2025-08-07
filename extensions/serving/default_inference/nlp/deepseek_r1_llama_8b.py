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

from extensions.serving.default_inference.nlp.deepseek_r1_base import DeepseekR1Base as BaseServingProcess

__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "MODEL_NAME": "deepseek-ai/DeepSeek-R1-Distill-Llama-8B",

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class DeepseekR1Llama8B(BaseServingProcess):
  CONFIG = _CONFIG
