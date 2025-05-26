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

@misc{masala2024vorbecstiromanecsterecipetrain,
      title={"Vorbe\c{s}ti Rom\^ane\c{s}te?" A Recipe to Train Powerful Romanian LLMs with English Instructions},
      author={Mihai Masala and Denis C. Ilie-Ablachim and Alexandru Dima and Dragos Corlatescu and Miruna Zavelca and Ovio Olaru and Simina Terian and Andrei Terian and Marius Leordeanu and Horia Velicu and Marius Popescu and Mihai Dascalu and Traian Rebedea},
      year={2024},
      eprint={2406.18266},
      archivePrefix={arXiv},
      primaryClass={cs.CL},
      url={https://arxiv.org/abs/2406.18266},
}

models:
  pansophic/pansophic-1-preview-LLaMA3.1-8b
  pansophic/pansophic-1-preview-LLaMA3.1-8b-GPTQ
  pansophic/pansophic-1-preview-LLaMA3.1-8b-GGUF

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

  # "MODEL_NAME": "pansophic/pansophic-1-preview-LLaMA3.1-8b",
  "MODEL_NAME": "OpenLLM-Ro/RoLlama3.1-8b-Instruct-DPO",

  "PICKED_INPUT": "STRUCT_DATA",
  "RUNS_ON_EMPTY_INPUT": False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class RoLlamaV31(BaseServingProcess):

  def add_context_to_request(self, request, context):
    return f"{request} - Te rog sa raspunzi luand in considerare si urmatoarele: {context}"

  def _setup_llm(self):
    # just override this method as the base class has a virtual method that raises an exception
    return
