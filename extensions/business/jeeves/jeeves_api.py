import os.path

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin
from naeural_core.business.mixins_libs.network_processor_mixin import _NetworkProcessorMixin
from constants import JeevesCt


_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 15033,
  'ASSETS': 'extensions/business/fastapi/jeeves_api',
  'REQUEST_TIMEOUT': 240,  # seconds
  "MAX_COMMANDS_SENT": 10,
  'R1FS_SLEEP_PERIOD': 5,
  "SAVE_PERIOD": 60 * 5,  # seconds

  'SHORT_TERM_MEMORY_SIZE': 10,

  # !! ONLY FOR TESTING PURPOSES !!
  'SKIP_R1FS_WARMUP': False,

  # Definition of the domains that need additional context
  # along with the context itself.
  # This is a dictionary where the key is the domain name and the value is
  # the context to be used for that domain.
  "PREDEFINED_ADDITIONAL_CONTEXT_DOMAINS": {

  },

  'PREDEFINED_DOMAINS': {
    'telegram_bot_community': {
      'prompt_default': JeevesCt.COMMUNITY_CHATBOT_SYSTEM_PROMPT,
      'prompt': JeevesCt.COMMUNITY_CHATBOT_SYSTEM_PROMPT_PATH,
      "additional_kwargs": {
        "temperature": 0.3
      }
    },
  },

  'PREDEFINED_USER_TOKENS': [],

  "DEFAULT_SYSTEM_PROMPT": JeevesCt.DEFAULT_SYSTEM_PROMPT,

  "JINJA_ARGS": {
    # Done in order for this API to not have user interface.
    'html_files': []
  },
  'DEBUG_LOGS': True,
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class JeevesApiPlugin(BasePlugin, _NetworkProcessorMixin):
  CONFIG = _CONFIG

  def maybe_wait_for_r1fs(self):
    if self.cfg_skip_r1fs_warmup:
      self.P("Skipping R1FS warmup due to testing mode active...", color="yellow", boxed=True)
      return
    start_time = self.time()
    sleep_period = self.cfg_r1fs_sleep_period
    while not self.r1fs.is_ipfs_warmed:
      elapsed = round(self.time() - start_time, 1)
      self.P(f'IPFS is warming up ({elapsed}s passed so far)...', color="yellow")
      self.P(f"Waiting another {sleep_period}s for IPFS to be warmed up...", color="yellow")
      self.sleep(sleep_period)
    # endwhile
    self.P("IPFS is warmed up!", color="green")
    return

  def get_predefined_user_tokens(self):
    return self.cfg_predefined_user_tokens or []

  def on_init(self):
    super(JeevesApiPlugin, self).on_init()
    self.network_processor_init()
    self.__command_payloads = []
    self.__requests = {}
    self.__user_data = {}
    self.__domains_data = {}
    self.last_persistent_save = 0

    predefined_user_tokens = self.get_predefined_user_tokens()
    for user_token in predefined_user_tokens:
      self._create_user_token(user_token=user_token)
    # endfor predefined user tokens

    predefined_domains = self.cfg_predefined_domains or {}
    for domain, domain_data in predefined_domains.items():
      self.maybe_create_domain(
        domain_name=domain,
        domain_prompt=domain_data.get('prompt'),
        domain_prompt_default=domain_data.get('prompt_default'),
        user_token=domain_data.get('user_token'),
        contains_additional_context=domain_data.get('contains_additional_context', False),
        additional_kwargs=domain_data.get('additional_kwargs') or {},
      )
    # endfor predefined domains

    predefined_additional_context_domains = self.cfg_predefined_additional_context_domains or {}
    for domain, domain_data in predefined_additional_context_domains.items():
      self.maybe_create_domain(
        domain_name=domain,
        domain_prompt=domain_data.get('prompt'),
        domain_prompt_default=domain_data.get('prompt_default'),
        user_token=domain_data.get('user_token'),
        contains_additional_context=True,
        additional_kwargs=domain_data.get('additional_kwargs') or {},
      )
    # endfor predefined additional context domains
    self.maybe_load_persistence_data()
    self.maybe_wait_for_r1fs()
    return

  def maybe_persistence_save(self, force: bool = False):
    """
    Save the current state of the Jeeves API to a persistent storage.
    This method is called when the Jeeves API is stopped or restarted.
    """
    if force or self.time() - self.last_persistent_save > self.cfg_save_period:
      self.P("Saving current state to persistent storage...", color="yellow")
      self.cacheapi_save_pickle(
        obj={
          'USER_DATA': self.__user_data,
          'DOMAINS_DATA': self.__domains_data,
          'REQUESTS': self.__requests,
        },
      )
      self.last_persistent_save = self.time()
    # endif force or time passed
    return

  def _create_user_token(
      self, user_token: str = None,
  ):
    # TODO: integrate chainstore for user tokens
    if user_token is None:
      user_token = self.uuid()
      # This is redundant, but we need to make sure that the token is unique.
      while user_token in self.__user_data:
        user_token = self.uuid()
    # endif preexistent user_token
    # endwhile token is not unique
    new_user_data = {
      'creation_time': self.time(),
      'last_access_time': self.time(),
      'n_requests': 0,
      'messages': [],
      'long_term_memory_is_empty': True
    }
    self.__user_data[user_token] = new_user_data
    self.maybe_persistence_save(force=True)
    return user_token

  def __merge_user_data(self, loaded_user_data: dict, in_memory_user_data: dict):
    """
    Merge the loaded user data with the in-memory user data.
    Parameters
    ----------
    loaded_user_data : dict
        The loaded user data from the persistent storage.
    in_memory_user_data : dict
        The in-memory user data from the Jeeves API.

    Returns
    -------
    dict
        The merged user data.
    """
    def choose_min(a, b):
      if a is None:
        return b
      if b is None:
        return a
      return min(a, b)

    def choose_max(a, b):
      if a is None:
        return b
      if b is None:
        return a
      return max(a, b)

    def choose_sum(a, b):
      if a is None:
        return b
      if b is None:
        return a
      return a + b

    merging_methods = {
      'creation_time': choose_min,
      'last_access_time': choose_max,
      'messages': choose_sum,
      'n_requests': choose_sum,
      'long_term_memory_is_empty': choose_min,
    }
    in_memory_user_data = in_memory_user_data or {}
    return {
      k: merging_methods[k](loaded_user_data.get(k), in_memory_user_data.get(k))
      for k in loaded_user_data.keys()
    }

  def maybe_load_persistence_data(self):
    """
    Load the current state of the Jeeves API from a persistent storage.
    """
    saved_data = self.cacheapi_load_pickle()
    if saved_data is not None:
      loaded_user_data = saved_data['USER_DATA']
      loaded_domains_data = saved_data['DOMAINS_DATA']
      loaded_requests = saved_data['REQUESTS']

      for user_token, user_data in loaded_user_data.items():
        self.__user_data[user_token] = self.__merge_user_data(
          loaded_user_data=user_data,
          in_memory_user_data=self.__user_data.get(user_token, {}),
        )
      # endfor user tokens
      for domain, domain_data in loaded_domains_data.items():
        self.__domains_data[domain] = {
          **domain_data,
          **self.__domains_data.get(domain, {}),
        }
      # endfor domains
      for request_id, request_data in loaded_requests.items():
        self.__requests[request_id] = {
          **request_data,
          **self.__requests.get(request_id, {}),
        }
      # endfor requests
    # endif saved_data is not None
    return


  def Pd(self, msg, *args, **kwargs):
    """
    Print debug message.
    """
    if self.cfg_debug_logs:
      self.P(msg, *args, **kwargs)
    return

  def verify_user_token(self, user_token: str):
    """
    Validate the user token.

    Parameters
    ----------
    user_token : str
        The user token to validate.

    Returns
    -------
    bool
        True if the user token is valid, False otherwise.
    """
    # return True
    return user_token in self.__user_data

  def invalid_token_response(self):
    """
    Returns an invalid token response.
    Returns
    -------
    """
    return {
      'error': 'Invalid user token',
      'status': 'error',
    }

  def register_request(self, request_id=None, **kwargs):
    """
    Helper method to register a request from the Jeeves API to different agents.

    Returns
    -------
    str
        The request ID.
    """
    request_data = {
      **kwargs
    }
    if request_id is None:
      request_id = self.uuid()
      request_data = {
        'start_time': self.time(),
        'finished': False,
        'request_id': request_id,
        'timeout': self.cfg_request_timeout,
        **request_data
      }
    else:
      request_data = {
        **self.__requests.get(request_id, {}),
        **request_data
      }
    # endif new request_id
    self.__requests[request_id] = request_data
    # endif new request is being processed
    # TODO: maybe handle `next_request_params`, as it may need removal from the
    #  command to the agent.
    jeeves_content = {
      'REQUEST_ID': request_id,
      **kwargs
    }
    if 'next_request_params' in jeeves_content:
      jeeves_content.pop('next_request_params')
    # endif next_request_params in jeeves_content
    self.__command_payloads.append({
      'JEEVES_CONTENT': jeeves_content
    })
    return request_id

  """SOLVED POSTPONED REQUESTS SECTION"""
  if True:
    def solve_postponed_request(self, request_id):
      """
      Helper method to handle postponed requests.
      This method is called when a request is postponed and needs to be solved.
      It checks if the request is finished or if it has timed out.
      If the request is finished, it returns the result.
      If the request has timed out, it marks the request as finished and returns an error message.
      If the request is not ready, it is further postponed.
      """
      if request_id in self.__requests:
        self.Pd(f"Checking request {request_id}...", color="yellow")
        request = self.__requests[request_id]
        start_time = request['start_time']
        timeout = request['timeout']
        if request['finished']:
          return request['result']
        elif self.time() - start_time > timeout:
          request['result'] = {
            'error': 'Request timed out',
            'request_id': request_id,
          }
          request['finished'] = True
          return request['result']
        # endif
      else:
        self.P(f"Request {request_id} not found in __requests.", color="red")
      # endif
      # Maybe handle case where request_id is not in __requests?
      return self.create_postponed_request(
        solver_method=self.solve_postponed_request,
        method_kwargs={
          'request_id': request_id,
        }
      )
  """END SOLVED POSTPONED REQUESTS SECTION"""

  """RAG SECTION"""
  if True:
    def register_add_documents_request(
        self,
        documents_cid: str,
        context_id: str,
    ):
      """
      Register a request to add documents to the RAG agents' context.

      Parameters
      ----------
      documents_cid : str
          The context ID to which the documents will be added.

      context_id : str
          The context ID to which the documents will be added.

      Returns
      -------
      str
          The request ID.
      """
      return self.register_request(
        request_type='ADD_DOC',
        request_params={
          "documents_cid": documents_cid,
          "context_id": context_id,
        }
      )

    def add_documents(
        self,
        context_id: str,
        documents: list[str],
        documents_cid: str = ""
    ):
      """
      Add one or more documents to the RAG agents' context.

      Parameters
      ----------
      context_id : str
          The context ID to which the documents will be added.

      documents : list[str]
          List of documents to add to the context. Each document should be a string.
          The documents will be added to the context of the user with the given token.

      Returns
      -------

      """
      if len(documents_cid) == 0:
        documents_cid = self.r1fs.add_pickle(
          data={
            'DOCUMENTS': documents,
            'CONTEXT_ID': context_id,
          },
          secret=context_id
        )
        if documents_cid is None:
          msg = f"Failed to add documents to context '{context_id}'"
          return {
            'error': msg,
          }
        # endif documents_cid is None
      # endif documents_cid provided already
      request_id = self.register_add_documents_request(
        documents_cid=documents_cid,
        context_id=context_id,
      )
      return self.solve_postponed_request(request_id=request_id)

    @BasePlugin.endpoint(method='post')
    def add_documents_for_user(
        self,
        user_token: str,
        documents: list[str],
        documents_cid: str = ""
    ):
      """
      Add one or more documents to the RAG agents' context for a specific user.
      Parameters
      ----------
      user_token : str
          The user token to which the documents will be added.
      documents : list[str]
          List of documents to add to the context. Each document should be a string.
          The documents will be added to the context of the user with the given token.

      Returns
      -------

      """
      if not self.verify_user_token(user_token):
        return self.invalid_token_response()
      # endif user token is valid
      return self.add_documents(
        context_id=user_token,
        documents=documents,
        documents_cid=documents_cid
      )

    @BasePlugin.endpoint(method='post')
    def add_documents_for_domain(
        self,
        user_token: str,
        domain: str,
        documents: list[str],
        documents_cid: str = ""
    ):
      """
      Add one or more documents to the RAG agents' context for a specific domain.
      A domain is a specific context that will be accessible to multiple users.

      Parameters
      ----------
      user_token : str
          The user token to which the documents will be added.

      domain : str
          The domain to which the documents will be added.

      documents : list[str]
          List of documents to add to the context. Each document should be a string.
          The documents will be added to the context of the user with the given token.

      Returns
      -------

      """
      if not self.verify_user_token(user_token):
        return self.invalid_token_response()
      # endif user token is valid

      if domain in self.__domains_data:
        self.__domains_data[domain]['contains_additional_context'] = True
      else:
        self.maybe_create_domain(
          domain_name=domain,
          user_token=user_token,
          contains_additional_context=True,
        )
      # endif domain already existent
      return self.add_documents(
        context_id=domain,
        documents=documents,
        documents_cid=documents_cid
      )

    def register_retrieve_documents_request(
        self,
        context_id: str,
        query: str,
        k: int = 5,
        next_request_params: dict = None,
    ):
      """
      Register a request to retrieve documents from the RAG agents' context.
      Parameters
      ----------
      context_id : str
          The context ID from which the documents will be retrieved.
      query : str
          The query to use for retrieving the documents.
      k : int
          The number of documents to retrieve. Default is 5.
      next_request_params : dict
          Additional parameters for the request that needs the result of the
          retrieval. In the case of a simple retrieve action this will be None.
          In case of a retrieval for a chat, this will be the parameters for the
          chat request.

      Returns
      -------
      str
          The request ID.
      """
      return self.register_request(
        request_type='QUERY',
        request_params={
          "context_id": context_id,
          "query": query,
          "k": k,
        },
        next_request_params=next_request_params
      )

    def retrieve_documents_helper(
        self,
        context_id: str,
        query: str,
        k: int = 5,
        next_request_params: dict = None,
    ):
      """
      Retrieve documents from the RAG agents' context based on a query.

      Parameters
      ----------
      context_id : str
          The context ID from which the documents will be retrieved.

      query : str
          The query to use for retrieving the documents.

      k : int
          The number of documents to retrieve. Default is 5.

      next_request_params : dict
          Additional parameters for the request that needs the result of the
          retrieval. In the case of a simple retrieve action this will be None.
          In case of a retrieval for a chat, this will be the parameters for the
          chat request.

      Returns
      -------
      list[str]
          List of documents retrieved from the context. Each document is a string.
      """
      request_id = self.register_retrieve_documents_request(
        context_id=context_id,
        query=query,
        k=k,
        next_request_params=next_request_params,
      )
      return self.solve_postponed_request(request_id=request_id)

    # TODO: this will not be an endpoint, but will be used for debug for now.
    @BasePlugin.endpoint()
    def retrieve_documents(
        self,
        context_id: str,
        query: str,
        k: int = 5,
    ):
      """
      Retrieve documents from the RAG agents' context based on a query.

      Parameters
      ----------
      context_id : str
          The context ID from which the documents will be retrieved.

      query : str
          The query to use for retrieving the documents.

      k : int
          The number of documents to retrieve. Default is 5.

      Returns
      -------
      list[str]
          List of documents retrieved from the context. Each document is a string.
      """
      return self.retrieve_documents_helper(
        context_id=context_id,
        query=query,
        k=k,
        next_request_params=None,  # This is None, because this is a simple retrieve action.
      )

    def messages_to_documents(self, messages: list[dict]):
      return [
        msg.get("content") or ""
        for msg in messages
      ]

    def maybe_short_term_memory_to_long_term_memory(self, user_token: str, use_long_term_memory: bool = True):
      """
      Move the short term memory to the long term memory.
      Parameters
      ----------
      user_token : str
          The user token to use for the API. Default is None.

      use_long_term_memory : bool
          Whether to use the long term memory for the user token. Default is True.

      Returns
      -------
      str
          The request ID.
      """
      current_short_term_memory = self.__user_data[user_token].get('messages') or []
      transfer_threshold = self.cfg_short_term_memory_size // 2
      if len(current_short_term_memory) > self.cfg_short_term_memory_size:
        current_role = current_short_term_memory[transfer_threshold].get('role')
        while transfer_threshold > 0 and current_role != "user":
          transfer_threshold -= 1
          current_role = current_short_term_memory[transfer_threshold].get('role')
        if transfer_threshold == 0:
          return
        self.P(f"Moving {transfer_threshold} messages to short term memory to long term memory for user '{user_token}'")
        first_half = current_short_term_memory[:transfer_threshold]
        second_half = current_short_term_memory[transfer_threshold:]
        self.__user_data[user_token]['messages'] = second_half
        if use_long_term_memory:
          self.add_documents(
            context_id=user_token,
            documents=self.messages_to_documents(first_half),
          )
          self.__user_data[user_token]['long_term_memory_is_empty'] = False
        # endif use long term memory
      return
  """END RAG SECTION"""

  """LLM SECTION"""
  if True:
    def maybe_retrieve_domain_additional_data(
        self, domain: str, query: str = None,
        next_request_params: dict = None,
        user_token: str = None,
        short_term_memory_only: bool = False
    ):
      """
      Retrieve the domain data from the RAG agents' context.
      Parameters
      ----------
      domain : str
          The domain to retrieve data from.

      query : str
          The query to use for retrieving the data. Default is None.
          If not provided, the function will retrieve all documents from the domain.

      next_request_params : dict
          Additional parameters for the request that needs the result of the
          retrieval. In the case of a simple retrieve action this will be None.
          In case of a retrieval for a chat, this will be the parameters for the
          chat request.

      user_token : str
          The user token to use for the API. Default is None.

      short_term_memory_only : bool
          Whether to retrieve only the short term memory for the user token.
          If True, documents retrieval will be used for older messages of the user.

      Returns
      -------
      str
          The domain data.
      """
      # No specific domain is needed.
      if domain is None:
        return None
      # endif domain is None

      if domain == user_token:
        is_long_term_empty = self.__user_data[user_token].get('long_term_memory_is_empty', True)
        if not is_long_term_empty and not short_term_memory_only:
          return self.retrieve_documents_helper(
            context_id=user_token,
            query=query,
            k=5,
            next_request_params=next_request_params,
          )
        # endif long term memory is not empty
      # endif retrieval for long term memory

      # Check if the domain is sufficiently covered by the LLM or if it needs
      # additional data.
      additional_domains = self.cfg_predefined_additional_context_domains or {}
      if domain not in additional_domains:
        return None

      # endif domain not in additional domains
      return self.retrieve_documents_helper(
        context_id=domain,
        query=query,
        k=5,
        next_request_params=next_request_params,
      )

    def register_chat_request(
        self,
        request_id: str = None,
        messages: list[dict] = None,
        user_token: str = None,
        **kwargs
    ):
      """
      Register a chat request with the Jeeves API.
      Parameters
      ----------
      request_id : str
          The request ID to use for the API. Default is None.
      messages : list[dict]
          List of messages to send to the API. Each message should be a dictionary with
          the following keys:
              - role: str
                  The role of the message. Can be 'user', 'assistant', or 'system'.
              - content: str
                  The content of the message.
      user_token : str
          The user token to use for the API. Default is None.
      kwargs : dict
          Additional parameters to send to the API. Default is None.

      Returns
      -------
      str
          The request ID.
      """
      return self.register_request(
        request_id=request_id,
        messages=messages,
        user_token=user_token,
        request_type='LLM',
        **kwargs
      )

    def get_messages_of_user(
        self,
        user_token: str = None,
        message: str = None,
        domain_prompt: str = None,
        **kwargs
    ):
      """
      Get the messages of the user.

      Parameters
      ----------
      user_token : str
          The user token to use for the API. Default is None.
      message : str
          The message to send to the API. Default is None.
      domain_prompt: str
          The system prompt for the following request.
      kwargs : dict
          Additional parameters to send to the API. Default is None.

      Returns
      -------
      list[dict]
          List of messages to send to the API. Each message should be a dictionary with
          the following keys:
              - role: str
                  The role of the message. Can be 'user', 'assistant', or 'system'.
              - content: str
                  The content of the message.
                  
      TODO:
        - Short-term memory must be implemented via ChainStore as the API will 
          be balanced over multiple instances.
          
      """
      res = [
        {
          'role': 'user',
          'content': message,
        }
      ]
      if user_token is not None:
        short_term_messages = self.__user_data[user_token].get('messages')
        if short_term_messages is not None:
          res = short_term_messages + res
        # endif short term messages existent
      # endif user_token provided
      if domain_prompt is not None:
        res += [
          {
            'role': 'system',
            'content': domain_prompt
          }
        ]
      # endif domain prompt provided
      return res

    def get_domain_prompt(
        self,
        user_token: str = None,
        domain: str = None,
        return_additional_kwargs: bool = False,
    ):
      """
      Get the domain prompt for the Jeeves API.

      Parameters
      ----------
      user_token : str
          The user token to use for the API. Default is None.
      domain : str
          The domain to use for the API. Default is None.
      return_additional_kwargs : bool
          Whether to return the additional kwargs for the domain prompt.

      Returns
      -------
      str or tuple
          The domain prompt.
      If return_additional_kwargs is True, returns a tuple with the domain prompt and additional kwargs.
      """
      additional_kwargs = {}
      domain_prompt = self.cfg_default_system_prompt
      if domain is not None and domain in self.__domains_data:
        additional_kwargs = self.__domains_data[domain].get('additional_kwargs') or {}
        domain_prompt = self.__domains_data[domain].get('domain_prompt', None)
      # endif domain is not None
      if isinstance(domain_prompt, str) and domain_prompt.startswith("file://"):
        # This is a path to a file.
        # Remove the "file://" prefix.
        domain_prompt = domain_prompt[7:]  # Remove "file://"
        if os.path.exists(domain_prompt):
          if self.is_path_safe(domain_prompt):
            with open(domain_prompt, 'r', encoding='utf-8') as f:
              domain_prompt = f.read()
          # endif path is safe
        else:
          domain_prompt_default = self.__domains_data.get(domain, {}).get('domain_prompt_default', None)
          if isinstance(domain_prompt_default, str):
            domain_prompt = domain_prompt_default
          # endif domain_prompt_default specified
        # endif domain_prompt is a path and exists
      # endif domain_prompt is a path
      return (domain_prompt, additional_kwargs) if return_additional_kwargs else domain_prompt

    def validate_llm_kwargs(self, **kwargs):
      """
      Validate the LLM kwargs for the Jeeves API.
      This method checks if the provided kwargs are valid for the LLM request.

      Parameters
      ----------
      kwargs : dict
          The kwargs to validate.

      Returns
      -------
      dict
          The validated kwargs.
      """
      valid_kwargs = {}
      supported_kwargs = {
        "temperature": {
          "type": float,
          "min_value": 0.0,
          "max_value": 1.0,
        },
        "top_p": {
          "type": float,
          "min_value": 0.5,
          "max_value": 1.0,
        },
        "max_tokens": {
          "type": int,
          "min_value": 128,  # This is a common minimum for LLMs
          "max_value": 4096,  # This is a common limit for LLMs
        },
        "repetition_penalty": {
          "type": float,
          "min_value": 1.0,
          "max_value": 1.2,
        }
      }
      msg_logs = []
      self.P(f"Received kwargs: {kwargs}")
      for key, value in kwargs.items():
        if key.lower() in supported_kwargs:
          rule = supported_kwargs[key.lower()]
          if isinstance(value, rule["type"]) and \
             (rule.get("min_value") is None or value >= rule["min_value"]) and \
             (rule.get("max_value") is None or value <= rule["max_value"]):
            valid_kwargs[key.lower()] = value
          else:
            msg_logs.append(
              f"Invalid value for {key}: {value}. Expected type {rule['type']} with "
              f"range [{rule.get('min_value', 'N/A')}, {rule.get('max_value', 'N/A')}]."
            )
          # endif value is valid
        else:
          msg_logs.append(f"Unsupported keyword argument: {key}")
        # endif key is supported
      # endfor kwargs
      self.P(f"Valid kwargs: {valid_kwargs}")
      if msg_logs:
        msg_str = "\n".join(msg_logs)
        self.Pd(f"Validation errors: {msg_str}", color="red")
      return valid_kwargs

    @BasePlugin.endpoint(method="post")
    # TODO: change to jeeves_agent_request?
    def query(
        self,
        user_token: str = None,
        message: str = None,
        domain: str = None,
        **kwargs
    ):
      """
      Send a query to the Jeeves API.
      Parameters
      ----------

      user_token : str
          The user token to use for the API. Default is None.
      message : str
          The message to send to the API. Default is None.
      domain : str
          The domain to use for the API. Default is None.
      # TODO: add kwargs (e.g. temperature or function calling)
      kwargs : dict
          Additional parameters to send to the API. Default is None.

      Returns
      -------

      """
      if not self.verify_user_token(user_token):
        return self.invalid_token_response()
      # endif user token is valid
      if message is None:
        return {
          'error': 'Message not provided',
          'status': 'error',
        }
      # endif message is None

      domain_prompt, additional_kwargs = self.get_domain_prompt(
        user_token=user_token,
        domain=domain,
        return_additional_kwargs=True,
      )

      validated_kwargs = self.validate_llm_kwargs(**kwargs)
      additional_kwargs = {
        **additional_kwargs,
        **validated_kwargs
      }

      # Wrap the message
      messages = self.get_messages_of_user(
        # This is None, because this endpoint does not
        # use any conversation history.
        user_token=None,
        message=message,
        domain_prompt=domain_prompt,
        # **kwargs
      )

      postponed_request = self.maybe_retrieve_domain_additional_data(
        domain=domain,
        query=message,
        next_request_params={
          'user_token': user_token,
          'messages': messages,
          'keep_conversation_history': False,
          'use_long_term_memory': False,
          **additional_kwargs,
        }
      )
      # Check if the request needs 
      if postponed_request is not None:
        return postponed_request
      # endif request_id is not None

      request_id = self.register_chat_request(
        messages=messages,
        user_token=user_token,
        keep_conversation_history=False,
        use_long_term_memory=False,
        **additional_kwargs,
      )
      return self.solve_postponed_request(request_id=request_id)

    @BasePlugin.endpoint(method='post')
    def query_debug(
        self,
        user_token: str = None,
        message: str = None,
        domain: str = None,
        system_prompt: str = "",
        temperature: float = 0.7,
        top_p: float = 1.0,
        valid_condition: str = "",
        process_method: str = "",
    ):
      """
      Debug endpoint for the Jeeves API.
      This endpoint is used to test the Jeeves API and should not be used in production.
      It is used to test the query endpoint and should not be used in production.
      """
      if not self.verify_user_token(user_token):
        return self.invalid_token_response()
      # endif user token is valid
      if message is None:
        return {
          'error': 'Message not provided',
          'status': 'error',
        }
      # endif message is None
      domain_prompt, additional_kwargs = self.get_domain_prompt(
        user_token=user_token,
        domain=domain,
        return_additional_kwargs=True,
      ) if len(system_prompt) == 0 else (system_prompt, {})

      messages = self.get_messages_of_user(
        user_token=None,
        message=message,
        domain_prompt=domain_prompt,
      )

      request_kwargs = {
        'messages': messages,
        'user_token': user_token,
        'keep_conversation_history': False,
        'use_long_term_memory': False,
        'temperature': temperature,
        'top_p': top_p,
        'valid_condition': valid_condition,
        'process_method': process_method,
      }
      request_kwargs = {
        k: v or additional_kwargs.get(k)
        for k, v in request_kwargs.items()
      }

      request_id = self.register_chat_request(
        **request_kwargs
      )
      return self.solve_postponed_request(request_id=request_id)

    @BasePlugin.endpoint(method="post")
    def chat(
        self,
        user_token: str = None,
        message: str = None,
        domain: str = None,
        short_term_memory_only: bool = False,
        **kwargs
    ):
      """
      Chat with the Jeeves API.
      This method will keep track of all the user's messages.

      Parameters
      ----------
      user_token : str
          The user token to use for the API. Default is None.
      message : str
          The message to send to the API. Default is None.
      domain : str
          The domain to use for the API. Default is None.
      short_term_memory_only : bool
          Whether to use only the short term memory for the chat. Default is False.
          If True, the chat will not use the long term memory.

      # TODO: add kwargs (e.g. temperature or function calling)
      kwargs

      Returns
      -------

      """
      if not self.verify_user_token(user_token):
        return self.invalid_token_response()
      # endif user token is valid
      if message is None:
        return {
          'error': 'Message not provided',
          'status': 'error',
        }
      # endif message is None

      domain_prompt = self.get_domain_prompt(
        user_token=user_token,
        domain=domain,
        return_additional_kwargs=False
      )

      messages = self.get_messages_of_user(
        user_token=user_token,
        message=message,
        domain_prompt=domain_prompt,
        # **kwargs
      )

      validated_kwargs = self.validate_llm_kwargs(**kwargs)

      # The long term memory for the user conversation will be a domain identified with his
      # user token.
      use_long_term_memory = not short_term_memory_only
      postponed_request = self.maybe_retrieve_domain_additional_data(
        domain=user_token,
        query=message,
        next_request_params={
          'user_token': user_token,
          'messages': messages,
          'keep_conversation_history': True,
          'use_long_term_memory': use_long_term_memory,
          **validated_kwargs,
        },
        user_token=user_token,
        short_term_memory_only=short_term_memory_only,
      )
      # Check if the request needs 
      if postponed_request is not None:
        return postponed_request
      # endif request_id is not None
      
      # TODO: add domain additional data retrieval
      
      request_id = self.register_chat_request(
        messages=messages,
        user_token=user_token,
        keep_conversation_history=True,
        use_long_term_memory=use_long_term_memory,
        **validated_kwargs,
      )
      return self.solve_postponed_request(request_id=request_id)

  """END LLM SECTION"""
  @BasePlugin.endpoint(method='post')
  # TODO: add configurable parameter with preexistent user tokens
  def get_user_token(self, dummy_param: str = None):
    """
    Create a new user token.

    Returns
    -------
    str
        The user token.
    """
    return self._create_user_token()

  def maybe_create_domain(
      self, domain_name: str, domain_prompt: str = None,
      domain_prompt_default: str = None, user_token: str = None,
      contains_additional_context: bool = False,
      additional_kwargs: dict = None
  ):
    if domain_name not in self.__domains_data:
      self.__domains_data[domain_name] = {
        'creation_time': self.time(),
        'last_access_time': self.time(),
        'n_requests': 0,
        'domain_prompt_default': domain_prompt_default,
        'domain_prompt': domain_prompt,
        'domain_name': domain_name,
        'user_token': user_token,
        'contains_additional_context': contains_additional_context,
        'additional_kwargs': additional_kwargs or {},
      }
    else:
      if isinstance(domain_prompt_default, str) and len(domain_prompt_default) > 0:
        self.__domains_data[domain_name]['domain_prompt_default'] = domain_prompt_default
      if domain_prompt is not None:
        self.__domains_data[domain_name]['domain_prompt'] = domain_prompt
      if user_token is not None:
        self.__domains_data[domain_name]['user_token'] = user_token
      if contains_additional_context is not None:
        self.__domains_data[domain_name]['contains_additional_context'] = contains_additional_context
      if additional_kwargs is not None:
        self.__domains_data[domain_name]['additional_kwargs'] = {
          **(self.__domains_data[domain_name].get('additional_kwargs') or {}),
          **additional_kwargs,
        }
    # endif domain already existent
    self.maybe_persistence_save(force=True)
    return domain_name

  @BasePlugin.endpoint(method='post')
  def create_domain(
      self, user_token: str, domain_name: str, domain_prompt: str,
      domain_prompt_default: str = None,
  ):
    """
    Create a new domain.

    Parameters
    ----------

    user_token : str
        The user token to use for the API. Default is None.
    domain_name : str
        The name of the domain to create.
    domain_prompt : str
        The prompt to use for the domain. It can be a string or a path to a file.
    domain_prompt_default : str
        The default prompt to use for the domain in case the domain prompt is a
        path to a file and the file does not exist.
        If not specified, the default prompt will be used in cases mentioned above.

    Returns
    -------
    str
        The domain ID.
    """
    if not self.verify_user_token(user_token):
      return self.invalid_token_response()
    # endif user token is valid
    if domain_name is None:
      return {
        'error': 'Domain name not provided',
        'status': 'error',
      }
    # endif domain name is None
    if domain_prompt is None:
      return {
        'error': 'Domain prompt not provided',
        'status': 'error',
      }
    # endif domain prompt is None
    # TODO: decide if domain should be upgradeable
    if domain_name in self.__domains_data:
      return {
        'error': f"Domain '{domain_name}' already exists",
        'status': 'error',
      }
    
    self.maybe_create_domain(
      domain_name=domain_name,
      domain_prompt=domain_prompt,
      domain_prompt_default=domain_prompt_default,
      user_token=user_token,
    )
    
    return {
      'domain': domain_name,
      'status': 'success',
    }

  def get_domain_data(self, domain_data: dict, include_prompt: bool = False):
    """
    Get the domain data.

    Parameters
    ----------
    domain_data : dict
        The domain data to retrieve. This should be a dictionary containing all the data about the domain.

    include_prompt : bool
        Whether to include the prompt for the domain. Default is False.
        If True, the prompt will be included in the response.

    Returns
    -------
    dict
        The domain data.
    """
    domain_data_keys = [
      'creation_time',
      'domain_name',
    ]
    res = {
      k: domain_data.get(k)
      for k in domain_data_keys
    }
    if include_prompt:
      res['domain_prompt'] = domain_data.get('domain_prompt')
      domain_prompt_default = domain_data.get('domain_prompt_default')
      if domain_prompt_default is not None:
        res['domain_prompt_default'] = domain_prompt_default
      # endif domain_prompt_default is specified
    # endif include prompt
    
    return res

  @BasePlugin.endpoint()
  def get_domains(self, user_token: str = None, include_prompt: bool = False):
    """
    Get the domains for the user.

    Parameters
    ----------
    user_token : str
        The user token to use for the API. Default is None.
    
    include_prompt : bool
        Whether to include the prompts for the domains. Default is False.
        If True, the prompts will be included in the response.

    Returns
    -------
    list[str]
        List of domains for the user.
    """
    if not self.verify_user_token(user_token):
      return self.invalid_token_response()
    # endif user token is valid
    # TODO: maybe filter based on the user_token
    return {
      'domains': [
        self.get_domain_data(domain_data=domain_data, include_prompt=include_prompt)
        for domain_name, domain_data in self.__domains_data.items()
      ]
    }

  """PAYLOAD HANDLERS SECTION"""
  if True:
    @_NetworkProcessorMixin.payload_handler(signature="DOC_EMBEDDING_AGENT")
    def handle_payload_doc_embedding_agent(self, data):
      request_id = data.get('REQUEST_ID', None)
      if request_id is not None:
        if request_id in self.__requests:
          request_data = self.__requests[request_id]
          request_finished = request_data.get('finished', False)
          if request_finished:
            self.Pd(f"Request ID '{request_id}' to DocEmbedding agents already finished.", color="red")
            return
          request_type = request_data.get('request_type', None)
          error_message = (data.get('RESULT') or {}).get('ERROR_MESSAGE')
          if error_message is not None:
            request_data['result'] = {
              'error': error_message,
              'request_id': request_id,
            }
            request_data['finished'] = True
            self.Pd(f"Request ID '{request_id}' to DocEmbedding failed with error: {error_message}", color="red")
            return
          if request_type == 'ADD_DOC':
            request_result = data.get('RESULT') or {}
            request_data['result'] = {
              'elapsed_time': self.time() - request_data['start_time'],
              'request_id': request_id,
              **request_result,
            }
            request_data['finished'] = True
            self.Pd(f"'ADD_DOC' request ID '{request_id}' to DocEmbedding successfully processed.", color="green")
          elif request_type == 'QUERY':
            request_result = data.get('RESULT') or {}
            docs = request_result.get('DOCS', [])

            next_request_params = request_data.get('next_request_params')
            self.P(f"Next request params: {next_request_params}")
            if isinstance(next_request_params, dict):
              # Union of the kwargs in case of overlapping keys
              chat_request_kwargs = {
                self.ct.JeevesCt.REQUEST_ID: request_id,
                **next_request_params,
                self.ct.JeevesCt.CONTEXT: docs,
                **request_result
              }
              # normalize the kwargs
              chat_request_kwargs = {
                (k.lower() if isinstance(k, str) else k): v
                for k, v in chat_request_kwargs.items()
              }
              self.P(f"Continuing with chat request: {chat_request_kwargs}")

              self.register_chat_request(
                **chat_request_kwargs,
              )
            else:
              request_data['result'] = {
                'elapsed_time': self.time() - request_data['start_time'],
                'request_id': request_id,
                'docs': docs,
              }
              request_data['finished'] = True
            # endif request finished or not

            self.Pd(f"'QUERY' request ID '{request_id}' to DocEmbedding successfully processed.", color="green")
          else:
            self.Pd(f"Unknown request type for request ID '{request_id}': '{request_type}'!", color="red")
        else:
          self.Pd(f"Request ID '{request_id}' not found in requests.", color="red")
      else:
        self.Pd(f"`REQUEST_ID` not provided in {data}")
      # endif request_id available
      return

    def get_last_user_message(self, user_messages: list[dict]):
      """
      Get the last user message from the list of user messages.
      Parameters
      ----------
      user_messages : list[dict]
          List of user messages. Each message should be a dictionary with
          the following keys:
              - role: str
                  The role of the message. Can be 'user', 'assistant', or 'system'.
              - content: str
                  The content of the message.

      Returns
      -------
      dict or None
          The last user message or None if not found.
      """
      if user_messages is None:
        return None
      # endif user messages is None
      for message in reversed(user_messages):
        if isinstance(message, dict) and message.get('role') == 'user':
          return message
      # endfor
      return None

    @_NetworkProcessorMixin.payload_handler(signature="LLM_AGENT")
    def handle_payload_llm_agent(self, data):
      request_id = data.get('REQUEST_ID', None)
      if request_id is not None:
        if request_id in self.__requests:
          request_data = self.__requests[request_id]
          request_finished = request_data.get('finished', False)
          if request_finished:
            self.Pd(f"Request ID '{request_id}' to LLM agent already finished.", color="red")
            return
          error_message = (data.get('RESULT') or {}).get('ERROR_MESSAGE')
          if error_message is not None:
            request_data['result'] = {
              'error': error_message,
              'request_id': request_id,
            }
            request_data['finished'] = True
            self.Pd(f"Request ID '{request_id}' to LLM failed with error: {error_message}", color="red")
            return
          text_response = data.get('RESULT', {}).get('TEXT_RESPONSE', "")
          if text_response is not None:
            request_data['result'] = {
              'response': text_response,
              'elapsed_time': self.time() - request_data['start_time'],
              'model_name': data.get('MODEL_NAME', None),
              'request_id': request_id,
            }
            request_data['finished'] = True
            user_token = request_data.get('user_token', None)
            user_messages = request_data.get('messages', [])
            use_long_term_memory = request_data.get('use_long_term_memory', False)
            keep_conversation_history = request_data.get('keep_conversation_history', False)
            self.P(f"Done processing request '{request_id}' for user {user_token} with {use_long_term_memory=}. Response is:\n {text_response}", color="green")
            if keep_conversation_history:
              self.P(f"User messages: {user_messages}")
              last_user_message = self.get_last_user_message(user_messages)
              if last_user_message is not None:
                self.__user_data[user_token]['messages'].append(last_user_message)
              self.__user_data[user_token]['messages'].append({
                'role': 'assistant',
                'content': text_response,
              })
              self.maybe_short_term_memory_to_long_term_memory(user_token, use_long_term_memory=use_long_term_memory)
            # endif request made through /chat endpoint
            self.Pd(f"Request ID '{request_id}' to LLM successfully processed.", color="green")
        else:
          self.Pd(f"Request ID '{request_id}' not found in requests.", color="red")
      else:
        self.Pd(f"`REQUEST_ID` not provided in {data}")
      # endif request_id available
      return
  """END PAYLOAD HANDLERS SECTION"""

  def __maybe_send_command_payloads(self):
    current_commands = self.__command_payloads[:self.cfg_max_commands_sent]
    for payload in current_commands:
      self.Pd(f"Sending command payload: {self.json_dumps(payload)}", color="blue")
      self.add_payload_by_fields(**payload)
    self.__command_payloads = self.__command_payloads[len(current_commands):]
    return

  def _process(self):
    super(JeevesApiPlugin, self)._process()
    self.network_processor_loop()
    self.__maybe_send_command_payloads()
    self.maybe_persistence_save()
    return

