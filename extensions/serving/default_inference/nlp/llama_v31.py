"""
@misc{touvron2023llamaopenefficientfoundation,
      title={LLaMA: Open and Efficient Foundation Language Models},
      author={Hugo Touvron and Thibaut Lavril and Gautier Izacard and Xavier Martinet and Marie-Anne Lachaux and Timothée Lacroix and Baptiste Rozière and Naman Goyal and Eric Hambro and Faisal Azhar and Aurelien Rodriguez and Armand Joulin and Edouard Grave and Guillaume Lample},
      year={2023},
      eprint={2302.13971},
      archivePrefix={arXiv},
      primaryClass={cs.CL},
      url={https://arxiv.org/abs/2302.13971},
}

models:
  meta-llama/Meta-Llama-3.1-8B
  meta-llama/Meta-Llama-3.1-8B-Instruct

  meta-llama/Meta-Llama-3.1-70B
  meta-llama/Meta-Llama-3.1-70B-Instruct


  meta-llama/Meta-Llama-3.1-405B
  meta-llama/Meta-Llama-3.1-405B-FP8
  meta-llama/Meta-Llama-3.1-405B-Instruct
  meta-llama/Meta-Llama-3.1-405B-Instruct-FP8


Testing:
  A. Launch OnDemandTextInput with Explorer
  B. Write custom command (see below)



for llama3.1 in-filling:
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

  "MODEL_NAME": "meta-llama/Meta-Llama-3.1-8B-Instruct",

  "PICKED_INPUT": "STRUCT_DATA",
  "RUNS_ON_EMPTY_INPUT": False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class LlamaV31(BaseServingProcess):

  def _setup_llm(self):
    # just override this method as the base class has a virtual method that raises an exception
    return
