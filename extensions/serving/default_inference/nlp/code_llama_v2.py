"""
@misc{touvron2023llama,
      title={Llama 2: Open Foundation and Fine-Tuned Chat Models}, 
      author={Hugo Touvron and Louis Martin and Kevin Stone and Peter Albert and Amjad Almahairi and Yasmine Babaei and Nikolay Bashlykov and Soumya Batra and Prajjwal Bhargava and Shruti Bhosale and Dan Bikel and Lukas Blecher and Cristian Canton Ferrer and Moya Chen and Guillem Cucurull and David Esiobu and Jude Fernandes and Jeremy Fu and Wenyin Fu and Brian Fuller and Cynthia Gao and Vedanuj Goswami and Naman Goyal and Anthony Hartshorn and Saghar Hosseini and Rui Hou and Hakan Inan and Marcin Kardas and Viktor Kerkez and Madian Khabsa and Isabel Kloumann and Artem Korenev and Punit Singh Koura and Marie-Anne Lachaux and Thibaut Lavril and Jenya Lee and Diana Liskovich and Yinghai Lu and Yuning Mao and Xavier Martinet and Todor Mihaylov and Pushkar Mishra and Igor Molybog and Yixin Nie and Andrew Poulton and Jeremy Reizenstein and Rashi Rungta and Kalyan Saladi and Alan Schelten and Ruan Silva and Eric Michael Smith and Ranjan Subramanian and Xiaoqing Ellen Tan and Binh Tang and Ross Taylor and Adina Williams and Jian Xiang Kuan and Puxin Xu and Zheng Yan and Iliyan Zarov and Yuchen Zhang and Angela Fan and Melanie Kambadur and Sharan Narang and Aurelien Rodriguez and Robert Stojnic and Sergey Edunov and Thomas Scialom},
      year={2023},
      eprint={2307.09288},
      archivePrefix={arXiv},
      primaryClass={cs.CL}
}


@misc{rozière2023code,
      title={Code Llama: Open Foundation Models for Code}, 
      author={Baptiste Rozière and Jonas Gehring and Fabian Gloeckle and Sten Sootla and Itai Gat and Xiaoqing Ellen Tan and Yossi Adi and Jingyu Liu and Tal Remez and Jérémy Rapin and Artyom Kozhevnikov and Ivan Evtimov and Joanna Bitton and Manish Bhatt and Cristian Canton Ferrer and Aaron Grattafiori and Wenhan Xiong and Alexandre Défossez and Jade Copet and Faisal Azhar and Hugo Touvron and Louis Martin and Nicolas Usunier and Thomas Scialom and Gabriel Synnaeve},
      year={2023},
      eprint={2308.12950},
      archivePrefix={arXiv},
      primaryClass={cs.CL}
}


models:
  codellama/CodeLlama-7b-hf
  codellama/CodeLlama-7b-Python-hf
  codellama/CodeLlama-7b-Instruct-hf
  
  codellama/CodeLlama-13b-hf
  codellama/CodeLlama-13b-Python-hf
  codellama/CodeLlama-13b-Instruct-hf
  
  
  codellama/CodeLlama-34b-hf
  codellama/CodeLlama-34b-Python-hf
  codellama/CodeLlama-34b-Instruct-hf    
  

Llama 2 (classic): "meta-llama/Llama-2-7b-chat-hf"




Testing:
  A. Launch OnDemandTextInput with Explorer
  B. Write custom command (see below)
  
  

for code llama in-filling:
```json
{ 
  "ACTION" : "PIPELINE_COMMAND",  
  "PAYLOAD" : {
    "NAME": "code-on-demand",
    "PIPELINE_COMMAND" : {
      "STRUCT_DATA" : {
        "request" : "def hello_world(<FILL>\n\nhello_world()",
        "history" : [
          {
            "request"   : "print('hello",
            "response"  : " world')"            
          }
        ],        
        "system_info" : "You are a funny python programmer assistant. your task is to complete the code you are given. return only the completion, not the whole program."
      }
    }
  }
}
```
TODO:
0. Prepare python SDK script for testing.
1. Run with 16 bit, observe allocation and inference time.
2. Run with 8 bit, observe allocation and inference time.
3. Run with 4 bit, observe allocation and inference time.
"""



from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess


__VER__ = '0.1.0.0'

_CONFIG = {
  **BaseServingProcess.CONFIG,
  
  # this was used before CodeLlamaTokenizer was available in transformers, make sure you use 4.34 or above
  # "MODEL_NAME" : "meta-llama/Llama-2-7b-chat-hf", 
  # end generic tokenizer use
  
  "MODEL_NAME" : "codellama/CodeLlama-7b-Instruct-hf",

  "PICKED_INPUT" : "STRUCT_DATA",
  
  "RUNS_ON_EMPTY_INPUT" : False,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}

class CodeLlamaV2(BaseServingProcess):
  def __init__(self, **kwargs):
    self._counter = 0
    super(CodeLlamaV2, self).__init__(**kwargs)
    return
  
  def _setup_llm(self):
    # just override this method as the base class has a virtual method that raises an exception
    return  
