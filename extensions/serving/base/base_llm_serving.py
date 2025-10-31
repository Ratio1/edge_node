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
import re
import os
from sqlfluff.core import Linter # TODO: move sql linter to a child serving process


from extensions.serving.mixins_llm import LlmTokenizerMixin, LlmModelMixin
from extensions.serving.mixins_llm.llm_utils import LlmCT
from extensions.utils.jeeves.jeeves_utils import _JeevesUtilsMixin

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
  "ADD_GENERATION_PROMPT": True,

  "TH_COMPILE"            : False,

  "TH_COMPILE_MODE"       : "max-autotune",

  "USE_FLASH_ATTENTION"   : False,

  "HF_TOKEN": None,

  "DEFAULT_TEMPERATURE" : 0.7,
  "DEFAULT_TOP_P"      : 1,
  "DEFAULT_MAX_TOKENS" : 2048,
  "SKIP_ERRORS"           : True,
  "RELEVANT_SIGNATURES": None,
  "GENERATION_SEED": 42,  # Seed for generation, can be set to None for random seed
  "DETERMINISTIC_MODE": False,  # If True, will use deterministic algorithms in PyTorch

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
  _JeevesUtilsMixin
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

  def get_relevant_signatures(self):
    configured_relevant = self.cfg_relevant_signatures
    if configured_relevant is None:
      configured_relevant = []
    # endif configured_relevant is None
    res = configured_relevant + self.ct.JeevesCt.JEEVES_API_SIGNATURES
    return list(set(res))

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

  def maybe_reseed(self, seed=None):
    """
    Reseed the random number generators if a seed is provided.
    Parameters
    ----------
    seed : int, optional
        The seed to use for reseeding. If None, no reseeding is done.
    """
    if seed is None:
      seed = self.cfg_generation_seed
    # endif seed provided

    if isinstance(seed, int):
      self.th.manual_seed(seed)
      self.np.random.seed(seed)
      if self.th.cuda.is_available():
        self.th.cuda.manual_seed(seed)
        self.th.cuda.manual_seed_all(seed)
      # endif cuda available
    # endif seed is int
    return

  def maybe_enable_deterministic_mode(self):
    if self.cfg_deterministic_mode:
      # cuDNN / TF32 switches -----------------------------------------------
      self.th.backends.cuda.matmul.allow_tf32 = False
      self.th.backends.cudnn.deterministic = True
      self.th.backends.cudnn.benchmark = False

      # Try to request deterministic algos, but *warn* instead of raising ----
      try:
        self.th.use_deterministic_algorithms(True, warn_only=True)
      except TypeError:
        # PyTorch < 2.0 – no warn_only flag.  We have to live without it.
        self.P("'warn_only' flag not supported; some ops may be nondeterministic")
      # endtry

      os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
    return

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

    self.maybe_enable_deterministic_mode()

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
    all_relevant_signatures = self.get_relevant_signatures()
    relevant_signature = all_relevant_signatures[0]
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
        # warmup_request,
        # warmup_request
      ]
    }
    self._predict(self._pre_process(warmup_inputs_four))
    # Maybe include post_process in the warmup to also check
    # the decoding process.
    self.P("LLM finished warmup")

    return


  def _setup_llm(self):
    return


  def _setup_device(self):
    # check if GPU is available & log
    gpu_info = self.log.gpu_info()
    if len(gpu_info) == 0:
      self.device = th.device('cpu')
    else:
      # try default device
      # TODO: review method
      configured_device = self.cfg_default_device
      if configured_device in ["cuda", "gpu"]:
        configured_device = "cuda:0"
      # endif configured_device
      self.device = th.device(configured_device)
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

  def check_relevant_input(self, input_dict: dict):
    inp_payload_path = input_dict.get(self.ct.PAYLOAD_DATA.EE_PAYLOAD_PATH, [None, None, None, None])
    inp_signature = inp_payload_path[2]
    normalized_signature = str(inp_signature).upper() if inp_signature is not None else None

    if normalized_signature not in self.get_relevant_signatures():
      # self.P(f"[DEBUG]Skipping irrelevant signature: {normalized_signature}. Relevant signatures: {self.get_relevant_signatures()}", color='y')
      return False

    jeeves_content = input_dict.get(self.ct.JeevesCt.JEEVES_CONTENT, {})
    # self.P(f"[DEBUG]Extracted jeeves content for relevance check: {self.shorten_str(jeeves_content)}", color='g')
    return self.check_supported_request_type(message_data=jeeves_content)

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
    valid_conditions = []
    process_methods = []
    relevant_input_ids = []
    cnt_total_inputs = len(lst_inputs)

    for i, inp in enumerate(lst_inputs):
      if self.check_relevant_input(inp):
        relevant_input_ids.append(i)
      else:
        continue

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
      repetition_penalty = jeeves_content.get("REPETITION_PENALTY", self.cfg_repetition_penalty)
      request_context = jeeves_content.get(LlmCT.CONTEXT, None)
      valid_condition = jeeves_content.get(LlmCT.VALID_CONDITION, None)
      process_method = jeeves_content.get(LlmCT.PROCESS_METHOD, None)
      predict_kwargs = {
        'temperature': temperature,
        'top_p': top_p,
        'max_new_tokens': max_tokens,
        'repetition_penalty': repetition_penalty,
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
      valid_conditions.append(valid_condition)
      process_methods.append(process_method)
    # endfor lst_inputs

    # Build the batch tensor. Ideally we should be calling encode on the
    # list of strings directly, however that seems to failing. Additionally
    # __call__ doesn't actually do the infilling.
    if len(tokens_lst) > 0:
      max_tok_len = max([toks.shape[1] for toks in tokens_lst])
      batch_tokens = th.ones((len(tokens_lst), max_tok_len), dtype=th.int64, device=self.device) * self.padding_id
      attn_mask = th.zeros((len(tokens_lst), max_tok_len), dtype=th.int64, device=self.device)
    else:
      batch_tokens = th.empty((0, 0), dtype=th.int64, device=self.device)
      attn_mask = th.empty((0, 0), dtype=th.int64, device=self.device)
    for i, toks in enumerate(tokens_lst):
      batch_tokens[i,:toks.shape[1]] = toks
      attn_mask[i,:toks.shape[1]] = 1
    if len(tokens_lst) > 0:
      self.P(f"Generated tokens batch of shape {batch_tokens.shape}")
      self.P(f"Found attention mask of shape {attn_mask.shape}")

    return [
      batch_tokens, attn_mask, predict_kwargs_lst,
      prompt_lst, additional_lst, valid_conditions, process_methods,
      relevant_input_ids, cnt_total_inputs
    ]

  def aggregate_mean(self, values: list):
    """
    Aggregate the values by taking the mean.
    Parameters
    ----------
    values : list
        The list of values to be aggregated.
    Returns
    -------
    float
        The mean of the values.
    """
    if len(values) == 0:
      return 0.0
    return sum(values) / len(values)

  def aggregate_mean_int(self, values: list):
    """
    Aggregate the values by taking the mean and converting to int.
    Parameters
    ----------
    values : list
        The list of values to be aggregated.
    Returns
    -------
    int
        The mean of the values as an integer.
    """
    return int(self.aggregate_mean(values))

  def aggregate_max(self, values: list, default_value=0.0):
    """
    Aggregate the values by taking the maximum.
    Parameters
    ----------
    values : list
        The list of values to be aggregated.
    default_value : any
        The default value to return if the list is empty.
        Defaults to 0.0.
    Returns
    -------
    float
        The maximum of the values.
    """
    if len(values) == 0:
      return default_value
    return max(values)

  def is_valid_sql(self, text: str):
    """
    Check if the text is a valid SQL query.
    Parameters
    ----------
    text : str
        The text to be checked.
    Returns
    -------
    bool
        True if the text is a valid SQL query, False otherwise.
    """
    if len(text) == 0:
      return False
    lnt = Linter(dialect="ansi", rules=())  # rules=() = “no style lint” # TODO: move to on-init in child serving

    linted = lnt.parse_string(text)  # :contentReference[oaicite:0]{index=0}

    if linted.tree is None:
      return False

    # 3) *Any* fatal violation (‘PRS’ = parse, ‘TMP’ = templater) ⇒ invalid.
    fatal = {"PRS", "TMP"}
    has_fatal = any(getattr(v, "rule_code", lambda: None)() in fatal for v in linted.violations)
    if has_fatal:
      # self.P(f"Invalid SQL: {text}", color='r')
      self.P(f"Violations: {linted.violations}", color='r')
    else:
      self.P(f"Valid SQL", color='g')

    return not has_fatal

  def check_condition(self, text: str, valid_condition: str):
    """
    Check if the text satisfies the valid condition.
    Parameters
    ----------
    text : str
        The text to be checked.
    valid_condition : str
        The valid condition to be checked against.
    Returns
    -------
    bool
        True if the text satisfies the valid condition, False otherwise.
    """
    if valid_condition is None or len(valid_condition) == 0:
      return True

    if valid_condition == 'sql':
      return self.is_valid_sql(text)

    try:
      regex = re.compile(valid_condition, re.I | re.X | re.M)
      return bool(regex.fullmatch(text))
    except:
      self.P(f"Invalid regex condition: {valid_condition}", color='r')
    return False

  def extract_sql(self, text: str):
    """
    Extracts an SQL script from LLM output.
    Priority order:
    1. If the string contains '-- BEGIN_DDL' … '-- END_DDL', return that
       block **including** the two marker lines.
    2. Otherwise, if it contains a fenced ```sql … ``` code block, return
       the SQL inside the fence (the back-ticks are *not* included).
    3. If no known delimiter is found, return the original text unchanged.
    Parameters
    ----------
    text : str
        The text to be processed.
    Returns
    -------
    str
        The extracted SQL code or the original text if no SQL code block is found.
    """
    # ── 1. Look for the DDL markers (tolerate optional spaces after “--”)
    ddl_match = re.search(
      rf"(?m)^\s*--\s*BEGIN_DDL\s*$.*?^\s*--\s*END_DDL\s*$",
      text,
      flags=re.DOTALL
    )
    if ddl_match:
      match_without_markers = ddl_match.group(0).replace(
        '-- BEGIN_DDL', ''
      ).replace('-- END_DDL', '').strip()
      return ddl_match.group(0) if len(match_without_markers) > 0 else ""  # include both marker lines if non-empty
    # endif ddl_match

    # ── 2. Look for fenced ```sql … ``` blocks (case-insensitive “sql”)
    fence_match = re.search(
      r"```sql\s*(.*?)\s*```",
      text,
      flags=re.DOTALL | re.IGNORECASE
    )
    if fence_match:
      return fence_match.group(1).strip()  # exclude the back-ticks

    # ── 3. Nothing found → give back the original string
    return text

  def remove_sql_comments(self, text: str):
    lines_without_comments = [
      re.sub(r"--.*$", "", ln) for ln in text.splitlines()
    ]
    return "\n".join([
      ln for ln in lines_without_comments if ln.strip()
    ])

  def maybe_process_text(self, text: str, process_method: str):
    """
    Process the text based on the process method.
    Parameters
    ----------
    text : str
        The text to be processed.
    process_method : str
        The process method to be applied to the text.
    Returns
    -------
    str
        The processed text.
    """
    if process_method is None or len(process_method) == 0:
      return text

    if process_method == 'sql':
      extracted_sql = self.extract_sql(text)
      # TODO: remove this or move to api
      text = self.remove_sql_comments(extracted_sql)
    return text

  def _predict(self, preprocessed_batch):
    self._counter += 1
    [
      batch_tokens, attn_mask, predict_kwargs_lst, prompt_lst,
      additional_lst, valid_conditions, process_methods,
      relevant_input_ids, cnt_total_inputs
    ] = preprocessed_batch
    # Perform generation using tokens and parameters.
    # Note that it's not appropriate to call the forward function
    # here unless we want to re-implement the wheel (various searching
    # strategies i.e. beam searching etc).
    # TODO: change this to pipeline as it seems is the preferred way.
    # TODO: explore more generation strategies, as this is currently
    # using the greedy strategy.

    # if self.cfg_prompt_lookup_num_tokens is not None:
    #   model_args['prompt_lookup_num_tokens'] = int(self.cfg_prompt_lookup_num_tokens)
    generate_kwargs = self.get_model_predict_kwargs(
      attention_mask=attn_mask,
      predict_kwargs_lst=predict_kwargs_lst,
      batch_tokens=batch_tokens,
    )

    generate_str = "\n".join(
      f"{k}={v},"
      for k, v in generate_kwargs.items()
    )
    if generate_kwargs:
      self.P(f"Running with following model args:\n{generate_str}")

    # TODO: test if some gpu mem can be freed after this
    results = [
      # (idx, valid, process_method, tokens, text)
      (idx, valid_condition, process_methods[idx], None, None)
      for idx, valid_condition in enumerate(valid_conditions)
    ]
    obj_for_inference = [
      # original index, current index
      (idx, idx) for idx in range(batch_tokens.shape[0])
    ]
    conditions_satisfied = False if len(valid_conditions) > 0 else True
    max_tries = 10
    tries = 0
    while not conditions_satisfied:
      with th.no_grad():
        self.maybe_reseed()
        t0 = self.time()
        # Note that there's no need to set the padding ID since we've passed
        # the appropriate attention mask.
        # TODO: maybe explore assistant_model parameter from
        #  https://huggingface.co/docs/transformers/v4.44.2/en/llm_optims
        # self.P(f"[DEBUG] batch_tokens shape: {batch_tokens.shape}, ")
        # self.P(f"[DEBUG] attn_mask : {model_args['attention_mask'].shape}")
        yhat = self.model.generate(
          **generate_kwargs
        )
        elapsed = self.time() - t0
      # endwith
      self.P(f'Done inference in {elapsed} seconds')
      yhat = yhat.cpu().numpy()
      np_batch_tokens = batch_tokens.cpu().numpy()
      self.th_utils.clear_cache()

      # Calculate number of generated token per seconds and add it to __tps
      # in order to track inference performance. Generated padding is not
      # counted since it is an artefact of the batching strategy.
      batch_y_size = np_batch_tokens.shape[1]
      num_generated_toks = (yhat[:, batch_y_size:] != self.padding_id).astype(self.np.int32).sum().item()
      num_tps = num_generated_toks / elapsed
      self.__tps.append(num_tps)
      self.P("Model ran at {} tokens per second".format(num_tps))

      # Decode each output in the batch, omitting the input tokens.
      text_lst = self.tokenizer.batch_decode(
        yhat[:, np_batch_tokens.shape[1]:],
        skip_special_tokens=True
      )

      invalid_objects = []
      invalid_tokens = []
      invalid_attn_mask = []
      invalid_predict_kwargs = []
      tries += 1
      for (idx_orig, idx_curr) in obj_for_inference:
        # Get the result for the current index.
        valid_condition = results[idx_orig][1]
        process_method = results[idx_orig][2]
        current_text = text_lst[idx_curr]
        self.P(f"Checking condition for object {idx_orig}:\nvalid:`{valid_condition}`|process:`{process_method}`|text:\n{current_text}")
        current_text = self.maybe_process_text(current_text, process_method)
        self.P(f"Processed text:\n{current_text}")
        if ((len(current_text) > 0 and (valid_condition is None or self.check_condition(current_text, valid_condition)))
            or tries >= max_tries):
          # If the condition is satisfied, we can decode the text.
          tokens = yhat[idx_curr].tolist()
          results[idx_orig] = (idx_orig, valid_condition, process_method, tokens, current_text)
        else:
          invalid_objects.append((idx_orig, len(invalid_objects)))
          invalid_tokens.append(batch_tokens[idx_curr: idx_curr + 1])
          invalid_attn_mask.append(attn_mask[idx_curr: idx_curr + 1])
          invalid_predict_kwargs.append(predict_kwargs_lst[idx_curr])
      # endfor each object in the batch

      if len(invalid_objects) == 0 or tries >= max_tries:
        # If no invalid objects, we can stop the loop.
        conditions_satisfied = True
      else:
        batch_tokens = self.th.cat(invalid_tokens, dim=0)
        attn_mask = self.th.cat(invalid_attn_mask, dim=0)
        # Rebuild the predict_kwargs_lst for the invalid objects.
        generate_kwargs = self.get_model_predict_kwargs(
          attention_mask=attn_mask,
          predict_kwargs_lst=invalid_predict_kwargs,
          batch_tokens=batch_tokens,
        )
        obj_for_inference = invalid_objects
    # endwhile conditions satisfied

    text_lst = [text for _, _, _, _, text in results]

    dct_result = {
      # LlmCT.PRED: yhat,
      LlmCT.PRMP: prompt_lst,
      # LlmCT.TKNS: batch_tokens,
      # LlmCT.TPS: num_tps,
      LlmCT.ADDITIONAL: additional_lst,
      LlmCT.TEXT: text_lst,
      "RELEVANT_IDS": relevant_input_ids,
      "TOTAL_INPUTS": cnt_total_inputs
    }
    return dct_result


  def _post_process(self, preds_batch):
    if preds_batch is None:
      return []
    result = []
    # yhat = preds_batch[LlmCT.PRED]
    prompts = preds_batch[LlmCT.PRMP]
    # tokens = preds_batch[LlmCT.TKNS]
    # tps = preds_batch[LlmCT.TPS]
    additionals = preds_batch[LlmCT.ADDITIONAL]
    text_lst = preds_batch[LlmCT.TEXT]
    relevant_input_ids = preds_batch["RELEVANT_IDS"]
    cnt_total_inputs = preds_batch["TOTAL_INPUTS"]

    for i, additional in enumerate(additionals):
      self.processed_requests.add(additional[LlmCT.REQUEST_ID])

    if len(text_lst) > 0:
      self.P(f"Found batch text prediction for {len(text_lst)} texts:\n{self.shorten_str(text_lst)}")
    for i, decoded in enumerate(text_lst):
      dct_result = {
        "IS_VALID": True,
        # LlmCT.PRED : yhat[i].tolist(),
        LlmCT.PRMP : prompts[i],
        LlmCT.TEXT : decoded,
        # LlmCT.TKNS : tokens[i].tolist(),
        # LlmCT.TPS  : tps,
        **preds_batch[LlmCT.ADDITIONAL][i],
        # TODO: find a way to send the model metadata to the plugin, other than through the inferences.
        'MODEL_NAME': self.cfg_model_name
      }
      result.append(dct_result)
    # endfor each text
    current_text_idx = 0
    final_result = []
    for i in range(cnt_total_inputs):
      if i in relevant_input_ids:
        final_result.append(result[current_text_idx])
        current_text_idx += 1
      else:
        final_result.append({
          "IS_VALID": False,
          LlmCT.TEXT: "",
          LlmCT.PRMP: "",
          'MODEL_NAME': self.cfg_model_name
        })
    # endfor total inputs
    return final_result

