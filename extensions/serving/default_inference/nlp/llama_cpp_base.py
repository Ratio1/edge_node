from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess
from llama_cpp import Llama
from extensions.serving.mixins_llm.llm_utils import LlmCT

__VER__ = "0.1.0"


MODEL_N_CTX_MIN_VALUE = 512
MODEL_N_CTX_DEFAULT_VALUE = 4096
MODEL_N_BATCH_DEFAULT_VALUE = 512


_CONFIG = {
  **BaseServingProcess.CONFIG,

  "DEFAULT_DEVICE"        : "cpu",

  "SKIP_ERRORS"           : True,
  "DETERMINISTIC_MODE": False,  # If True, will use deterministic algorithms in PyTorch

  # Possible values of None, 4, 8, 16, 32
  # where None is the default model config.
  "MODEL_WEIGHTS_SIZE"    : None,

  "MODEL_N_CTX": MODEL_N_CTX_DEFAULT_VALUE,

  "MODEL_NAME": None,
  "MODEL_FILENAME": None,

  'VALIDATION_RULES': {
    **BaseServingProcess.CONFIG['VALIDATION_RULES'],
  },

}


class LlamaCppBaseServingProcess(BaseServingProcess):
  CONFIG = _CONFIG

  def _load_tokenizer(self):
    # llama.cpp uses built-in tokenizer
    return

  def _load_model(self):
    model_id = self.get_model_name()
    model_filename = self.cfg_model_filename

    n_ctx = self.cfg_model_n_ctx
    if not isinstance(n_ctx, (int, float)):
      n_ctx = MODEL_N_CTX_DEFAULT_VALUE
    # endif not int/float
    n_ctx = max(MODEL_N_CTX_MIN_VALUE, int(n_ctx))

    self.P(f"Loading Llama_cpp model '{model_id}' from file '{model_filename}'")

    model_params = {
      'n_ctx': n_ctx,
      'seed': self.cfg_generation_seed,
      'n_batch': MODEL_N_BATCH_DEFAULT_VALUE,
    }

    def _llama_from_pretrained():
      return Llama.from_pretrained(
        repo_id=model_id,
        filename=model_filename,
        cache_dir=self.cache_dir,
        **model_params,
      )

    self.model = self.safe_load_model(
      load_model_method=_llama_from_pretrained,
      model_id=model_id,
      model_str_id=f"{model_id}/{model_filename}",
    )
    self.P("Model loaded successfully.")
    return

  def maybe_add_context_to_messages(
      self,
      messages: list[dict],
      context: list or str = None
  ):
    if not isinstance(messages, list):
      self.maybe_exception("messages must be a list of {role, content} dicts")
    # endif messages type check
    if context is not None and isinstance(context, (list, str)) and len(context) > 0:
      if isinstance(context, str):
        context = [context]
      # endif context is str
      context = [c for c in context if isinstance(c, str) and len(c) > 0]
      # endif non-empty chat
    # endif context provided
    valid_messages = all(
      isinstance(m, dict) and LlmCT.ROLE_KEY in m and LlmCT.DATA_KEY in m
      for m in messages
    )
    if not valid_messages:
      msg = f"Each message in `messages` must be a dict with `role` and `content` keys. Invalid messages:\n{messages}"
      self.maybe_exception(msg)
    # endif valid messages
    if not isinstance(context, list) or len(context) == 0:
      return messages
    # endif empty context
    res, last_user_message, system_message = [], None, None
    for message in messages:
      role = message.get(LlmCT.ROLE_KEY, None)
      content = message.get(LlmCT.DATA_KEY, None)
      if role is None or content is None:
        msg = f"Each message in `messages` must have a `role` and `content`. Invalid message:\n{message}"
        self.maybe_exception(msg)
      # endif role/content check
      if role == LlmCT.SYSTEM_ROLE:
        system_message = message
      elif role == LlmCT.REQUEST_ROLE:
        if last_user_message is not None:
          res.append(last_user_message)
        # endif last user message
        last_user_message = message
      elif role == LlmCT.REPLY_ROLE:
        # assistant reply, so a new user message should come after this
        if last_user_message is not None:
          res.append(last_user_message)
          last_user_message = None
        # endif last user message
        res.append(message)
      # endif role check
    # endfor messages
    res = ([system_message] + res) if system_message is not None else res
    if last_user_message is not None:
      last_user_message_text = self.add_context_to_request(
        last_user_message[LlmCT.DATA_KEY],
        context
      )
      last_user_message[LlmCT.DATA_KEY] = last_user_message_text
      res.append(last_user_message)
    # endif last user message
    return res

  def _pre_process(self, inputs):
    lst_inputs = inputs.get('DATA', [])
    self.P(f"[DEBUG_LLM]Received {len(lst_inputs)} inputs for processing")

    predict_kwargs_lst = []
    messages_lst = []
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
        'max_tokens': max_tokens,
        'repeat_penalty': repetition_penalty,
      }
      predict_kwargs = self.process_predict_kwargs(predict_kwargs)
      if not isinstance(messages, list):
        msg = f"Each input must have a list of messages. Received {type(messages)}: {self.shorten_str(inp)}"
        self.maybe_exception(msg)
      # endif messages not list
      processed_messages = self.maybe_add_context_to_messages(
        messages=messages,
        context=request_context
      )
      messages_lst.append(processed_messages)
      predict_kwargs_lst.append(predict_kwargs)
      additional_lst.append({
        LlmCT.REQUEST_ID: request_id,
      })
      valid_conditions.append(valid_condition)
      process_methods.append(process_method)
    # endfor lst_inputs

    return [
      predict_kwargs_lst,
      messages_lst,
      additional_lst,
      valid_conditions,
      process_methods,
      relevant_input_ids,
      cnt_total_inputs,
    ]

  def _predict(self, preprocessed_batch):
    [
      predict_kwargs_lst,
      messages_lst,
      additional_lst,
      valid_conditions,
      process_methods,
      relevant_input_ids,
      cnt_total_inputs,
    ] = preprocessed_batch

    results = [
      # (idx, valid, process_method, reply)
      (idx, valid_condition, process_methods[idx], None)
      for idx, valid_condition in enumerate(valid_conditions)
    ]
    obj_for_inference = [
      # original index, current index
      (idx, idx) for idx in range(len(valid_conditions))
    ]
    conditions_satisfied = False if len(valid_conditions) > 0 else True
    max_tries = 10
    tries = 0
    while not conditions_satisfied:
      reply_lst = []
      t0 = self.time()
      timings = []
      total_generated_tokens = 0
      for idx_orig, idx_curr in obj_for_inference:
        messages = messages_lst[idx_orig]
        predict_kwargs = predict_kwargs_lst[idx_orig]
        t1 = self.time()
        out = self.model.create_chat_completion(
          messages=messages,
          **predict_kwargs
        )
        elapsed = self.time() - t1
        timings.append(elapsed)
        reply = out["choices"][0]["message"]["content"]
        num_tokens_generated = out["usage"]["completion_tokens"]
        total_generated_tokens += num_tokens_generated
        reply_lst.append(reply)
      # endfor obj_for_inference
      t_total = self.time() - t0
      curr_tps = total_generated_tokens / t_total if t_total > 0 else 0
      self._tps.append(curr_tps)
      self.P(f"Model ran at {curr_tps:.3f} tokens per second")

      invalid_objects = []
      tries += 1
      for idx_orig, idx_curr in obj_for_inference:
        valid_condition = results[idx_orig][1]
        process_method = results[idx_orig][2]
        current_text = reply_lst[idx_curr]
        self.P(f"Checking condition for object {idx_orig}:\nvalid:`{valid_condition}`|process:`{process_method}`|text:\n{current_text}")
        current_text = self.maybe_process_text(current_text, process_method)
        self.P(f"Processed text:\n{current_text}")
        valid_text = (
            len(current_text) > 0
            and (
                valid_condition is None
                or self.check_condition(current_text, valid_condition)
            )
        )
        current_condition_satisfied = valid_text or (tries >= max_tries)
        if current_condition_satisfied:
          # If the condition is satisfied, we can save the result
          results[idx_orig] = (idx_orig, valid_condition, process_method, current_text)
        else:
          invalid_objects.append((idx_orig, len(invalid_objects)))
        # endif current condition satisfied
      # endfor obj_for_inference

      if len(invalid_objects) > 0 and tries < max_tries:
        obj_for_inference = invalid_objects
      else:
        conditions_satisfied = True
    # endwhile conditions_satisfied

    text_lst = [text for _, _, _, text in results]
    dct_result = {
      LlmCT.PRMP: messages_lst,
      LlmCT.TEXT: text_lst,
      LlmCT.ADDITIONAL: additional_lst,
      "RELEVANT_IDS": relevant_input_ids,
      "TOTAL_INPUTS": cnt_total_inputs
    }
    return dct_result

  def _post_process(self, preds_batch):
    # This method can be missing here, but is present in case
    # of future customizations.
    return super(LlamaCppBaseServingProcess, self)._post_process(preds_batch)
