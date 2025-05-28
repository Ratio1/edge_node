"""
```bibtex
@misc{touvron2023llama,
      title={Llama 2: Open Foundation and Fine-Tuned Chat Models},
      author={Hugo Touvron and Louis Martin and Kevin Stone and Peter Albert and Amjad Almahairi and Yasmine Babaei and Nikolay Bashlykov and Soumya Batra and Prajjwal Bhargava and Shruti Bhosale and Dan Bikel and Lukas Blecher and Cristian Canton Ferrer and Moya Chen and Guillem Cucurull and David Esiobu and Jude Fernandes and Jeremy Fu and Wenyin Fu and Brian Fuller and Cynthia Gao and Vedanuj Goswami and Naman Goyal and Anthony Hartshorn and Saghar Hosseini and Rui Hou and Hakan Inan and Marcin Kardas and Viktor Kerkez and Madian Khabsa and Isabel Kloumann and Artem Korenev and Punit Singh Koura and Marie-Anne Lachaux and Thibaut Lavril and Jenya Lee and Diana Liskovich and Yinghai Lu and Yuning Mao and Xavier Martinet and Todor Mihaylov and Pushkar Mishra and Igor Molybog and Yixin Nie and Andrew Poulton and Jeremy Reizenstein and Rashi Rungta and Kalyan Saladi and Alan Schelten and Ruan Silva and Eric Michael Smith and Ranjan Subramanian and Xiaoqing Ellen Tan and Binh Tang and Ross Taylor and Adina Williams and Jian Xiang Kuan and Puxin Xu and Zheng Yan and Iliyan Zarov and Yuchen Zhang and Angela Fan and Melanie Kambadur and Sharan Narang and Aurelien Rodriguez and Robert Stojnic and Sergey Edunov and Thomas Scialom},
      year={2023},
      eprint={2307.09288},
      archivePrefix={arXiv},
      primaryClass={cs.CL}
}
```

```bibtex
@misc{rozière2023code,
      title={Code Llama: Open Foundation Models for Code},
      author={Baptiste Rozière and Jonas Gehring and Fabian Gloeckle and Sten Sootla and Itai Gat and Xiaoqing Ellen Tan and Yossi Adi and Jingyu Liu and Tal Remez and Jérémy Rapin and Artyom Kozhevnikov and Ivan Evtimov and Joanna Bitton and Manish Bhatt and Cristian Canton Ferrer and Aaron Grattafiori and Wenhan Xiong and Alexandre Défossez and Jade Copet and Faisal Azhar and Hugo Touvron and Louis Martin and Nicolas Usunier and Thomas Scialom and Gabriel Synnaeve},
      year={2023},
      eprint={2308.12950},
      archivePrefix={arXiv},
      primaryClass={cs.CL}
}
```

The inputs of the plugin must be in the following format for simplest payload:
```json
{
  "ACTION" : "PIPELINE_COMMAND",
  "PAYLOAD" :
  {
    "NAME": "llm-on-demand",
    "PIPELINE_COMMAND" :
    {
      "STRUCT_DATA" :
      {
        "request" : "write a hello world program in C++"
      }
    }
  }
}
```

and for history based command:
```json
{
  "ACTION" : "PIPELINE_COMMAND",
  "PAYLOAD" : {
    "NAME": "llm-on-demand",
    "PIPELINE_COMMAND" : {
      "STRUCT_DATA" : [{
        "request" : "return ",
        "history" : [
          {
            "request"   : "print('hello",
            "response"  : " world')"
          }
        ],
        "system_info" : "You are a funny python programmer assistant. your task is to complete the code you are given. return only the completion, not the whole program."
      }]
    }
  }
}
```



"""
"""
TODOs:
- test https://huggingface.co/microsoft/Phi-3.5-mini-instruct
"""
import torch as th
import transformers
import tokenizers
import accelerate


from extensions.serving.mixins_llm import LlmTokenizerMixin, LlmModelMixin
from extensions.serving.mixins_llm.llm_utils import LlmCT

from naeural_core.serving.base import ModelServingProcess as BaseServingProcess

TEST_MODULES = [
  th,
  transformers,
  tokenizers,
  accelerate
]


__VER__ = '0.1.0.2'

_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE"        : "cuda:0",

  "MAX_WAIT_TIME"         : 1000,
  "SERVER_COLLECTOR_TIMEDELTA": 172800,  # 48 hours -> this is done because the llm model is very large and
  # we want to keep it in memory for a long time.

  "PICKED_INPUT"          : "STRUCT_DATA",

  "RUNS_ON_EMPTY_INPUT"   : False,

  "MODEL_NAME"            : None,

  "REPETITION_PENALTY"    : 1.1,

  "ADD_SPECIAL_TOKENS": False,
  "ADD_GENERATION_PROMPT": False,

  "TH_COMPILE"            : False,

  "TH_COMPILE_MODE"       : "max-autotune",

  "USE_FLASH_ATTENTION"   : False,

  "HF_TOKEN": None,

  "DEFAULT_TEMPERATURE" : 0.7,
  "DEFAULT_TOP_P"      : 1,
  "DEFAULT_MAX_TOKENS" : 2048,
  "SKIP_ERRORS"           : True,
  "RELEVANT_SIGNATURES": None,

  "SUPPORTED_REQUEST_TYPES": [
    "LLM"
  ],

  # Possible values of None, 4, 8, 16, 32
  # where None is the default model config.
  "MODEL_WEIGHTS_SIZE"    : None,

  # Number of tokens overlapping when decoding. Used for Prompt lookup decoding.
  # If None, the model will not use Prompt lookup decoding.
  "PROMPT_LOOKUP_NUM_TOKENS": None,
  # To be adjusted in the future
  "HISTORY_LIMIT": 20,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}

"""
TODO:
Make this inherit the ContinuousServingProcess so that it can run in a continuous mode.
1. The model init should be in the continuous process.
2. Payloads should be accumulated in the inputs deque.
2.1. Payloads will be filtered using the `keep_message` method.
2.2. Payloads may not be sent immediately to the inference.
`message_ready` method will be used to check if the payload is ready for inference.
2.3. Payloads will be processed in batches of size `BATCH_SIZE`.

3. After the inference is done, the results will be added in the results deque.
4. Ping payloads will be sent from the DCT in order for the serving to be able to send the results
as fast as possible.
"""

class BaseLlmServing(
  BaseServingProcess,
  LlmTokenizerMixin,
  LlmModelMixin,
):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    self._counter = 0
    self._version_base = __VER__
    self.model = None
    self.tokenizer = None
    self.device = None
    self.__tps = self.deque(maxlen=128)
    self.padding_id = None
    self.processed_requests = set()
    super(BaseLlmServing, self).__init__(**kwargs)
    return

  @property
  def th(self):
    """
    Proxy to the torch module.
    Returns
    -------
    torch module
    """
    return th

  @property
  def hf_token(self):
    env_hf_token = self.os_environ.get(LlmCT.EE_HF_TOKEN, None)
    cfg_hf_token = self.cfg_hf_token
    return cfg_hf_token or env_hf_token


  @property
  def hf_model(self):
    return self.cfg_model_name


  @property
  def cache_dir(self):
    return self.log.get_models_folder()


  @property
  def has_gpu(self):
    return 'cuda' in self.device.type

  def maybe_exception(self, msg, exception_type=None):
    if self.cfg_skip_errors:
      self.P(msg, color='r')
    else:
      if exception_type is not None:
        raise exception_type(msg)
      else:
        raise ValueError(msg)
    return

  def get_local_path(self):
    models_cache = self.log.get_models_folder()
    model_name = 'models/{}'.format(self.cfg_model_name)
    model_subfolder = model_name.replace('/', '--')
    path = self.os_path.join(models_cache, model_subfolder)
    if self.os_path.isdir(path):
      return path
    else:
      return None

  def get_model_disk_size(self):
    path = self.get_local_path()
    if path is None:
      return 0
    else:
      return self.log.get_folder_size(path)[0]


  def _startup(self):
    # check some params that can be re-configured from biz plugins or
    # (lower priority) serving env in config_startup.txt.
    self.P("Preparing LLM serving...")
    if self.hf_token is None:
      self.P("  No HuggingFace token found. Please set it in the environment variable '{}'".format(LlmCT.EE_HF_TOKEN), color='r')
    else:
      obfuscated = self.hf_token[:3] + '*' * (len(self.hf_token) - 6) + self.hf_token[-3:]
      self.P("  Found HuggingFace token '{}'".format(obfuscated))
    #endif no token

    if self.cfg_model_name is None:
      msg = "No model name found. Please set it in config `MODEL_NAME`"
      raise ValueError(msg)
    #endif no model name

    self.P("  Package versions:")
    for module_test in TEST_MODULES:
      self.P("    {} version: {}".format(module_test.__name__, module_test.__version__))
    #endfor each module

    # setup device
    self._setup_device()

    # setup llm tokenizer
    self._load_tokenizer()

    # setup llm model
    self._load_model()

    # specific llama setup
    self._setup_llm()

    # warm up model
    self._warmup()

    return


  def _warmup(self):
    relevant_signature = self.cfg_relevant_signatures[0] if self.cfg_relevant_signatures else None
    payload_path = [
      None,
      None,
      relevant_signature,
      None
    ]
    supported_request_type = self.cfg_supported_request_types[0] if self.cfg_supported_request_types else None
    warmup_request = {
      "JEEVES_CONTENT": {
        LlmCT.REQUEST_TYPE: supported_request_type,
        LlmCT.REQUEST_ID: "warmup_request",
        LlmCT.MESSAGES: [
          {
            LlmCT.ROLE_KEY: LlmCT.SYSTEM_ROLE,
            LlmCT.DATA_KEY: "You are a helpful python assistant. Generate some python code.."
          },
          {
            LlmCT.ROLE_KEY: LlmCT.REQUEST_ROLE,
            LlmCT.DATA_KEY: "hello"
          }
        ],
      },
      self.ct.PAYLOAD_DATA.EE_PAYLOAD_PATH: payload_path
    }
    # Perform a prediction with a batch of one request.
    warmup_inputs_one = {
      "DATA" : [
        warmup_request
      ]
    }
    # TODO: maybe add warmup flag to predict for printing only in case of warmup
    self._predict(self._pre_process(warmup_inputs_one))
    # Perform a prediction with a batch of four requests.
    warmup_inputs_four = {
      "DATA": [
        warmup_request,
        warmup_request,
        warmup_request,
        warmup_request
      ]
    }
    self._predict(self._pre_process(warmup_inputs_four))
    # Maybe include post_process in the warmup to also check
    # the decoding process.
    self.P("LLM finished warmup")

    return


  def _setup_llm(self):
    raise NotImplementedError("Must be implemented in derived class")
    return


  def _setup_device(self):
    # check if GPU is available & log
    gpu_info = self.log.gpu_info()
    if len(gpu_info) == 0:
      self.device = th.device('cpu')
    else:
      # try default device
      # TODO: review method
      self.device = th.device(self.cfg_default_device)
      device_id = self.device.index
      gpu_name = self.log.get_gpu_name(device_id)
      total_mem = self.log.get_gpu_total_mem(device_id)
      free_mem = self.log.get_gpu_free_mem(device_id)
      self.P("Using default device: {}".format(self.device))
      self.P("  GPU Name:      {}".format(gpu_name))
      self.P("  GPU Total mem: {}".format(total_mem))
      self.P("  GPU Free mem:  {}".format(free_mem))

      disk_size = self.get_model_disk_size()
      self.P("  Model size:    {}".format(disk_size))
      if disk_size > free_mem:
        msg = "  => At default 16bit load model will exceed available GPU memory. Caution is adviced."
        self.P(msg, color='r')
      else:
        msg = "  => At default 16bit load model will fit in GPU memory."
        self.P(msg, color='g')
    return


  def _get_device_map(self):
    # TODO: Rewrite to fix for multiple GPUs
    device_map = "auto"
    return device_map

  def _pre_process(self, inputs):
    """
    Pre-process the inputs for the model.
    The expected inputs is a dictionary with the key "DATA" containing a list of
    dictionaries. Each dictionary represents a message received from the network.
    The messages will be passed to the tokenizer to generate the input
    tensors for the model. The input tensors will be padded to the maximum length
    of the input tensors in the batch. The attention mask will be generated
    accordingly.
    Each message should contain the `JEEVES_CONTENT` key with a dictionary
    in the following format:
    {
      "REQUEST_ID": "request_id",
      "MESSAGES": [
        {
          "role": "user",
          "content": "message content"
        },
        {
          "role": "assistant",
          "content": "assistant message content"
        }
      ],
      "TEMPERATURE": 0.7,  # optional
      "TOP_P": 1,  # optional
      "MAX_TOKENS": 512,  # optional
      "CONTEXT": "context",  # optional
    }
    The `REQUEST_ID` is a unique identifier for the request. The `MESSAGES` key
    contains a list of messages in the conversation. The `TEMPERATURE`, `TOP_P`,
    `MAX_TOKENS` and `CONTEXT` keys are optional parameters for the model
    prediction. The `TEMPERATURE` and `TOP_P` keys are used to control the
    randomness of the model output. The `MAX_TOKENS` key is used to limit the
    number of tokens generated by the model. The `CONTEXT` key is used to provide
    additional context for the model. The `REQUEST_ID` and `CONTEXT` keys are
    passed to the `additional_lst` list in the output.

    Parameters
    ----------
    inputs : dict
        The inputs to be pre-processed. The expected format is a dictionary

    Returns
    -------
    res :
      [batch_tokens, attn_mask, predict_kwargs_lst, prompt_lst, additional_lst],
      where:
        - batch_tokens : torch.Tensor
            The input tokens for the model. The shape is (batch_size, max_length).
        - attn_mask : torch.Tensor
            The attention mask for the model. The shape is (batch_size, max_length).
        - predict_kwargs_lst : list
            The list of dictionaries containing the parameters for the model
            prediction. Each dictionary corresponds to an input in the batch.
        - prompt_lst : list
            The list of prompts generated from the input messages. Each prompt
            corresponds to an input in the batch.
        - additional_lst : list
            The list of dictionaries containing additional information for each
            input in the batch. Each dictionary corresponds to an input in the
            batch.
    """
    lst_inputs = inputs.get('DATA', [])
    self.P(f"[DEBUG_LLM]Received {len(lst_inputs)} inputs for processing")

    tokens_lst = []
    predict_kwargs_lst = []
    prompt_lst = []
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
        'max_new_tokens': max_tokens,
      }

      if not isinstance(messages, list):
        msg = f"Each input must have a list of messages. Received {type(messages)}: {self.shorten_str(inp)}"
        self.maybe_exception(msg)
      # endif messages not list

      prompt = self._get_prompt_from_template(
        messages=messages,
        context=request_context
      )
      # Note that we are passing 'pt' in return_tensors to get torch tensors.
      tokens = self.tokenizer.encode(
        prompt,
        add_special_tokens=self.cfg_add_special_tokens,  # False for the majority,
        # Otherwise we would get and extra <bos> at the start.
        # In the case of the pansophic Llama3.1 romanian fine-tuned model, this needs to be True.
        return_tensors='pt'
      ).to(self.device)

      tokens_lst.append(tokens)
      predict_kwargs_lst.append(predict_kwargs)
      prompt_lst.append(prompt)
      additional_lst.append({
        LlmCT.REQUEST_ID: request_id,
      })
    # endfor lst_inputs

    # Build the batch tensor. Ideally we should be calling encode on the
    # list of strings directly, however that seems to failing. Additionally
    # __call__ doesn't actually do the infilling.
    max_tok_len = max([toks.shape[1] for toks in tokens_lst])
    batch_tokens = th.ones((len(tokens_lst), max_tok_len), dtype=th.int64, device=self.device) * self.padding_id
    attn_mask = th.zeros((len(tokens_lst), max_tok_len), dtype=th.int64, device=self.device)
    for i, toks in enumerate(tokens_lst):
      batch_tokens[i,:toks.shape[1]] = toks
      attn_mask[i,:toks.shape[1]] = 1

    self.P(f"Generated tokens batch of shape {batch_tokens.shape}")
    self.P(f"Found attention mask of shape {attn_mask.shape}")
    return [batch_tokens, attn_mask, predict_kwargs_lst, prompt_lst, additional_lst]


  def _predict(self, preprocessed_batch):
    self._counter += 1
    batch_tokens, attn_mask, predict_kwargs_lst, prompt_lst, additional_lst = preprocessed_batch
    # Perform generation using tokens and parameters.
    # Note that it's not appropriate to call the forward function
    # here unless we want to re-implement the wheel (various searching
    # strategies i.e. beam searching etc).
    # TODO: change this to pipeline as it seems is the preferred way.
    # TODO: explore more generation strategies, as this is currently
    # using the greedy strategy.

    # TODO: check how to add additional parameters from predict_kwargs_lst
    model_args = {
      'attention_mask': attn_mask,
      'temperature': self.cfg_default_temperature,
      'top_p': self.cfg_default_top_p,
      'max_new_tokens': self.cfg_default_max_tokens,
      'repetition_penalty': self.cfg_repetition_penalty,
    }
    if self.cfg_prompt_lookup_num_tokens is not None:
      model_args['prompt_lookup_num_tokens'] = int(self.cfg_prompt_lookup_num_tokens)

    self.P(f"Running with following model args:\n{self.json_dumps(model_args, indent=2)}")

    # TODO: test if some gpu mem can be freed after this
    with th.no_grad():
      t0 = self.time()
      # Note that there's no need to set the padding ID since we've passed
      # the appropriate attention mask.
      # TODO: maybe explore assistant_model parameter from
      #  https://huggingface.co/docs/transformers/v4.44.2/en/llm_optims
      yhat = self.model.generate(
        inputs=batch_tokens,
        **model_args
      )
      elapsed = self.time() - t0
    # endwith
    self.P(f'Done inference in {elapsed} seconds')
    yhat = yhat.cpu().numpy()
    batch_tokens = batch_tokens.cpu().numpy()
    self.th_utils.clear_cache()
    # Calculate number of generated token per seconds and add it to __tps
    # in order to track inference performance. Generated padding is not
    # counted since it is an artefact of the batching strategy.
    batch_y_size = batch_tokens.shape[1]
    num_generated_toks = (yhat[:, batch_y_size:] != self.padding_id).astype(self.np.int32).sum().item()
    num_tps = num_generated_toks / elapsed
    self.__tps.append(num_tps)

    self.P("Model ran at {} tokens per second".format(num_tps))

    dct_result = {
      LlmCT.PRED: yhat,
      LlmCT.PRMP: prompt_lst,
      LlmCT.TKNS: batch_tokens,
      LlmCT.TPS: num_tps,
      LlmCT.ADDITIONAL: additional_lst,
    }
    return dct_result


  def _post_process(self, preds_batch):
    if preds_batch is None:
      return []
    result = []
    yhat = preds_batch[LlmCT.PRED]
    prompts = preds_batch[LlmCT.PRMP]
    tokens = preds_batch[LlmCT.TKNS]
    tps = preds_batch[LlmCT.TPS]
    additionals = preds_batch[LlmCT.ADDITIONAL]

    for i, additional in enumerate(additionals):
      self.processed_requests.add(additional[LlmCT.REQUEST_ID])

    # Decode each output in the batch, omitting the input tokens.
    text_lst = self.tokenizer.batch_decode(
      yhat[:,tokens.shape[1]:],
      skip_special_tokens=True
    )

    self.P(f"Found batch text prediction for {len(text_lst)} texts:\n{self.shorten_str(text_lst)}")
    for i, decoded in enumerate(text_lst):
      dct_result = {
        LlmCT.PRED : yhat[i].tolist(),
        LlmCT.PRMP : prompts[i],
        LlmCT.TEXT : decoded,
        LlmCT.TKNS : tokens[i].tolist(),
        LlmCT.TPS  : tps,
        **preds_batch[LlmCT.ADDITIONAL][i],
        # TODO: find a way to send the model metadata to the plugin, other than through the inferences.
        'MODEL_NAME': self.cfg_model_name
      }
      result.append(dct_result)
    return result

