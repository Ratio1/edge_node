from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin
from naeural_core.business.mixins_libs.network_processor_mixin import _NetworkProcessorMixin
from extensions.business.mixins.chainstore_response_mixin import _ChainstoreResponseMixin
from constants import JeevesCt

import os
import shutil
import base64

_CONFIG = {
  **BasePlugin.CONFIG,

  # Optional key for sending plugin lifecycle confirmations to chainstore (set once after init)
  'CHAINSTORE_RESPONSE_KEY': None,

  "MAX_INPUTS_QUEUE_SIZE": 100,

  'PORT': 15033,
  'ASSETS': 'extensions/business/fastapi/jeeves_api',
  'REQUEST_TIMEOUT': 240,  # seconds
  "MAX_COMMANDS_SENT": 10,
  'R1FS_SLEEP_PERIOD': 5,
  "SAVE_PERIOD": 60 * 5,  # seconds

  'SHORT_TERM_MEMORY_SIZE': 20,

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
  "DEFAULT_ASSISTANT_SYSTEM_PROMPT": JeevesCt.GENERAL_ASSISTANT_SYSTEM_PROMPT,

  "JINJA_ARGS": {
    # Done in order for this API to not have user interface.
    'html_files': []
  },
  'DEBUG_LOGS': True,
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class JeevesApiPlugin(BasePlugin, _NetworkProcessorMixin, _ChainstoreResponseMixin):
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

  def get_supported_file_extensions(self):
    return JeevesCt.SUPPORTED_FILE_TYPES

  def _get_chainstore_response_data(self):
    """
    Build Jeeves API-specific response data for chainstore.

    Includes API endpoint information and initialization status.
    """
    # Get base data from mixin
    data = super()._get_chainstore_response_data()

    # Add Jeeves API-specific information
    data.update({
      'api_port': getattr(self, 'cfg_port', None),
      'api_endpoint': f"http://{self.log.get_localhost_ip()}:{self.cfg_port}" if hasattr(self, 'cfg_port') else None,
      'predefined_domains': list(self.cfg_predefined_domains.keys()) if hasattr(self, 'cfg_predefined_domains') and self.cfg_predefined_domains else [],
      'status': 'ready',
    })

    return data

  def on_init(self):
    super(JeevesApiPlugin, self).on_init()

    # Reset chainstore response key at start (signals "initializing")
    self._reset_chainstore_response()

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

    # Send chainstore response at end (signals "ready")
    self._send_chainstore_response()

    return

  def get_requests_persistence_data(self):
    requests_persistence_data = {}

    excluded_fields = [
      'preprocess_request_method', 'compute_request_result_method'
    ]

    for request_id, request_data in self.__requests.items():
      request_steps = request_data.get('request_steps') or []
      request_steps = [
        {
          # Maybe save name of excluded values instead of None?
          k: (v if k not in excluded_fields else None)
          for k, v in step.items()
        }
        for step in request_steps
      ]
      requests_persistence_data[request_id] = {
        **request_data,
        'request_steps': request_steps,
      }
    # endfor requests
    return requests_persistence_data

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
          'REQUESTS': self.get_requests_persistence_data(),
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
      'long_term_memory_is_empty': True,
      'conversations': {},
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

    def choose_merge(a, b):
      if a is None:
        return b
      if b is None:
        return a
      return {
        **a,
        **b,
      }

    merging_methods = {
      'creation_time': choose_min,
      'last_access_time': choose_max,
      'messages': choose_sum,
      'n_requests': choose_sum,
      'long_term_memory_is_empty': choose_min,
      'conversations': choose_merge,
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
      msg = f"[DEBUG] {msg}"
      self.P(msg, *args, **kwargs)
    return

  def deepcopy_request_data_helper(self, data: any):
    """
    Helper method to deepcopy the request data.
    This method is used to deepcopy the request data, except for the callables,
    which are copied by reference.
    Parameters
    ----------
    data : any
        The data to deepcopy.

    Returns
    -------
    any
        The deep copied data.
    """
    if callable(data):
      return data
    elif isinstance(data, dict):
      return {
        k: self.deepcopy_request_data_helper(v)
        for k, v in data.items()
      }
    elif isinstance(data, list):
      return [
        self.deepcopy_request_data_helper(v)
        for v in data
      ]
    elif isinstance(data, set):
      return {
        self.deepcopy_request_data_helper(v)
        for v in data
      }
    elif isinstance(data, tuple):
      return tuple(
        self.deepcopy_request_data_helper(v)
        for v in data
      )
    else:
      try:
        return self.deepcopy(data)
      except Exception as e:
        self.P(f"Failed to deepcopy data '{data}': {e}", color="red")
        return data
    # endif callable

  def deepcopy_request_data(self, request_id: str, default_value=None):
    """
    Deep copy the request data for a given request ID.
    This deepcopy all the fields, except for the callables, which are
    copied by reference.
    Parameters
    ----------
    request_id : str
        The request ID to copy the data for.

    Returns
    -------
    request_data : dict
        The deep copied request data.
    """
    request_data = self.__requests.get(request_id, default_value)
    return self.deepcopy_request_data_helper(request_data)

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

  def register_request(
      self,
      return_request_data: bool = False,
      request_id: str = None,
      **kwargs
  ):
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
      start_time = self.time()
      request_data = {
        'start_time': start_time,
        'last_request_time': start_time,
        'finished': False,
        'request_id': request_id,
        'timeout': self.cfg_request_timeout,
        **request_data
      }
    else:
      request_data = {
        **self.__requests.get(request_id, {}),
        **request_data,
        'last_request_time': self.time(),
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
    if 'next_request_steps' in jeeves_content:
      jeeves_content.pop('next_request_steps')
    # endif next_request_steps in jeeves_content
    self.__command_payloads.append({
      'JEEVES_CONTENT': jeeves_content
    })
    return (request_id, request_data) if return_request_data else request_id

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
        self.Pd(f"Checking request '{request_id}'...", color="yellow")
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
        documents: list[str] = None,
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
          If no documents are provided, the documents_cid must be provided.

      documents_cid : str
          The CID of the documents to add to the context. If not provided,
          the documents will be added to IPFS and the CID will be used.
      Returns
      -------

      """
      if len(documents_cid) == 0:
        if documents is None:
          return {
            'error': 'Either documents or documents_cid must be provided',
          }
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

    def upload_document_helper(
        self,
        file_base64: str = None,
        filename: str = None,
        file_path: str = None,
        body: dict = None,
    ):
      # 1. Retrieve and validate user_token and domain from body
      user_token = body.get('user_token')
      domain = body.get('domain')
      if not self.verify_user_token(user_token):
        return self.invalid_token_response()
      # endif user token is valid
      if not isinstance(domain, str) or len(domain) == 0:
        return {
          'error': 'Domain must be provided and must be a non-empty string.'
        }
      # endif domain is valid

      # 2. Validate file input method
      new_file_path_dir = self.os_path.join(
        self.get_output_folder(), 'j33ves_uploads',
        self.get_signature(), domain
      )
      os.makedirs(new_file_path_dir, exist_ok=True)
      file_content, file_real_path = None, None
      if file_base64 is None and filename is None and file_path is not None:
        file_real_path = file_path
      elif file_base64 is not None and filename is not None and file_path is None:
        file_real_path = self.os_path.join(new_file_path_dir, filename)
        file_content = file_base64
      else:
        return {
          'error': 'Either file_base64 and filename or file_path must be provided, but not both and not none.'
        }
      # endif file input method

      # 3. Check file extension
      file_ext = self.os_path.splitext(file_real_path)[1].lower()
      supported_exts = self.get_supported_file_extensions()
      if file_ext not in supported_exts:
        return {
          'error': f"File extension '{file_ext}' not supported. Supported extensions are: {', '.join(supported_exts)}."
        }
      # endif file extension is supported

      # 4. Save the file (or copy it if file_path was provided since it is a temp file)
      if file_content is not None:
        # The file content is provided as base64 string.
        try:
          file_bytes = base64.b64decode(file_content, validate=True)
        except Exception as e:
          return {
            'error': f"Failed to decode base64 file content: {str(e)}"
          }
        # Save decoded content to file
        with open(file_real_path, 'wb') as f:
          f.write(file_bytes)
      else:
        # The temporary file will be copied to a new location, as the
        # temporary file will be deleted after the request is finished.
        filename = file_real_path.split(self.os_path.sep)[-1]
        new_file_path = self.os_path.join(new_file_path_dir, filename)
        shutil.copy2(file_real_path, new_file_path)
        file_real_path = new_file_path
      # endif file content is provided

      # 5. Add the file to R1FS and get the CID
      file_cid = self.r1fs.add_file(
        file_path=file_real_path,
        secret=domain
      )
      return self.add_documents_for_domain(
        user_token=user_token,
        domain=domain,
        documents_cid=file_cid,
      )

    @BasePlugin.endpoint(method="post")
    def upload_document_for_domain_base64(
        self,
        file_base64: str,
        filename: str,
        body: dict = None,
    ):
      """
      Upload a document to the RAG agents' context for a specific user.
      Same as upload_document_for_domain, but the file is provided as a base64 string.
      Parameters
      ----------
      file_base64 : str
          The file to upload as a base64 string.
      filename : str
          The name of the file to upload.
      body : dict
          The body of the request. Should contain the user_token and domain.

      Returns
      -------

      """
      return self.upload_document_helper(
        file_base64=file_base64,
        filename=filename,
        body=body,
      )

    @BasePlugin.endpoint(method="post", streaming_type="upload")
    def upload_document_for_domain(
        self,
        file_path: str,
        body: dict = None,
    ):
      """
      Upload a document to the RAG agents' context for a specific user.
      Parameters
      ----------
      file_path : str
          The path to the file to upload.
      body : dict
          The body of the request. Should contain the user_token and domain.
      Returns
      -------

      """
      return self.upload_document_helper(
        file_path=file_path,
        body=body,
      )

    @BasePlugin.endpoint(method='post')
    def add_documents_for_user(
        self,
        user_token: str,
        documents: list[str] = None,
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
          If no documents are provided, the documents_cid must be provided.
      documents_cid : str
          The CID of the documents to add to the context. If not provided,
          the documents will be added to IPFS and the CID will be used.
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
        documents: list[str] = None,
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

      documents_cid : str
          The CID of the documents to add to the context. If not provided,
          the documents will be added to IPFS and the CID will be used.
      Returns
      -------

      """
      if not self.verify_user_token(user_token):
        return self.invalid_token_response()
      # endif user token is valid

      if domain in self.__domains_data:
        self.__domains_data[domain]['contains_additional_context'] = True
      else:
        # New domains will use the general assistant system prompt.
        domain_prompt = self.cfg_default_assistant_system_prompt
        self.maybe_create_domain(
          domain_name=domain,
          domain_prompt=domain_prompt,
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
      )

    def retrieve_documents_helper(
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
      request_id = self.register_retrieve_documents_request(
        context_id=context_id,
        query=query,
        k=k,
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
    def get_description_of_chat_step(
        self,
        domain: str,
        user_token: str = None,
        messages: list[dict] = None,
        keep_conversation_history: bool = False,
        use_long_term_memory: bool = False,
        preprocess_request_method: callable = None,
        compute_request_result_method: callable = None,
        extracted_param_names: list = None,
        conversation_id: str = None,
        **kwargs
    ):
      extracted_param_names = extracted_param_names or []
      if not isinstance(extracted_param_names, list):
        extracted_param_names = []
      # endif extracted_param_names is not a list
      extracted_param_names = list(set(extracted_param_names))
      domain_additional_kwargs = self.__domains_data.get(domain, {}).get('additional_kwargs', {})
      domain_additional_tuples = {
        (k, v)
        for k, v in domain_additional_kwargs.items()
      }
      return {
        'preprocess_request_method': preprocess_request_method,
        'compute_request_result_method': compute_request_result_method,
        'request_type': 'LLM',
        'request_param_names': [
          *extracted_param_names,
          ('user_token', user_token),
          ('messages', messages or []),
          ('keep_conversation_history', keep_conversation_history),
          ('use_long_term_memory', use_long_term_memory),
          ('conversation_id', conversation_id),
          *domain_additional_tuples,
          *[
            (k, v) for k, v in kwargs.items()
            if k not in [
              'user_token',
              'messages',
              'keep_conversation_history',
              'use_long_term_memory',
              'additional_kwargs',
            ]
          ]
        ]
      }

    def get_description_of_retrieval_step(
        self,
        domain: str,
        query: str = None,
        user_token: str = None,
        short_term_memory_only: bool = False,
        preprocess_request_method: callable = None,
        compute_request_result_method: callable = None,
        extracted_param_names: list = None,
        explicit_param_names: list = None,
    ):
      """
      Get the description of the retrieval step for a specific RAG agents' context.
      Parameters
      ----------
      domain : str
          The domain to retrieve data from.

      query : str
          The query to use for retrieving the data. Default is None.
          If not provided, the function will retrieve all documents from the domain.

      user_token : str
          The user token to use for the API. Default is None.

      short_term_memory_only : bool
          Whether to retrieve only the short term memory for the user token.
          If True, documents retrieval will be used for older messages of the user.

      preprocess_request_method : callable
          The method to preprocess the request before sending it to the agent.

      compute_request_result_method : callable
          The method to compute the result of the request after receiving it from the agent.

      extracted_param_names : list
          List of parameter names to extract from the request.

      explicit_param_names : list
          List of parameter names to include explicitly in the request.

      Returns
      -------
      res - dict or None
          The description of the retrieval step.
          None if no retrieval is needed.
      """
      if domain is None:
        return None
      # endif domain is None

      processed_extracted_param_names = extracted_param_names or []
      if not isinstance(processed_extracted_param_names, list):
        processed_extracted_param_names = []
      # endif processed_extracted_param_names is not a list
      processed_extracted_param_names = list(set(processed_extracted_param_names))

      explicit_param_names = explicit_param_names or []
      if not isinstance(explicit_param_names, list):
        explicit_param_names = []
      # endif explicit_param_names is not a list
      explicit_param_names = [
        (k, v)
        for k, v in explicit_param_names
        if k not in processed_extracted_param_names
      ]

      result = {
        'preprocess_request_method': preprocess_request_method,
        'compute_request_result_method': compute_request_result_method,
        'request_type': 'QUERY',
        'request_param_names': [
          *processed_extracted_param_names,
          *explicit_param_names,
          ('user_token', user_token),
          ('request_params', {
            'query': query,
            'context_id': domain,
            'k': 5,
          }),
        ]
      }

      if domain == user_token:
        is_long_term_empty = self.__user_data[user_token].get('long_term_memory_is_empty', True)
        if is_long_term_empty or short_term_memory_only:
          result = None
        # endif long term memory is empty
      # endif retrieval for long term memory

      contains_additional_context = self.__domains_data.get(domain, {}).get('contains_additional_context', False)
      if not contains_additional_context:
        result = None
      # endif domain not in additional domains

      return result

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
        if self.os_path.exists(domain_prompt):
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

    def _validate_llm_kwargs(self, **kwargs):
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

    def preprocess_request_method_query(
        self,
        request_data: dict,
    ):
      """
      Method for preprocessing the request before sending it to the LLM agent.
      Parameters
      ----------
      request_data : dict
          The request data from the Jeeves API.

      Returns
      -------
      result_data : dict
          The processed data for the next request that is not already
      """
      domain_context = request_data.get('domain_additional_context', [])
      return {
        self.ct.JeevesCt.CONTEXT: domain_context
        # 'messages', 'user_token' and additional kwargs are already present in request_data.
      }

    def pre_process_chat_request(
        self,
        user_token: str = None,
        message: str = None,
        domain: str = None,
        short_term_memory_only: bool = False,
        is_chat_request: bool = False,
        conversation_id: str = None,
        **kwargs,
    ):
      """
      Helper method for preprocessing both the query and chat endpoints.
      Parameters
      ----------
      user_token : str
          The user token to use for the API. Default is None.
      message : str
          The message to send to the API. Default is None.
      domain : str
          The domain to use for the API. Default is None.
      short_term_memory_only : bool
          Whether to retrieve only the short term memory for the user token.
          If False, documents retrieval will be used in case it is needed.
      is_chat_request : bool
          Whether this is a chat request. In that case, the short-term history
          will be used to check for previous messages. If False, no conversation
          history will be used.
          This is relevant for the message wrapping.
      kwargs : dict
          Additional parameters to send to the API. Default is None.

      Returns
      -------
      result: dict
          A dictionary with the following keys:
          - 'err_response': None or dict
              If an error occurred, this will contain the error response.
              Otherwise, it will be None.
          - 'domain_prompt': str or None
              The domain prompt to use for the request.
          - 'additional_kwargs': dict
              The additional kwargs to use for the request.
          - 'messages': list[dict] or None
              The messages to use for the request.
              None if an error occurred.
      """
      result = {
        'err_response': None,
        'domain_prompt': None,
        'additional_kwargs': {},
        'messages': None,
      }
      if not self.verify_user_token(user_token):
        result['err_response'] = self.invalid_token_response()
        return result
      # endif user token is valid
      if not isinstance(message, str):
        result['err_response'] = {
          'error': 'Message not provided as string',
          'status': 'error',
        }
        return result
      # endif message is None

      if isinstance(conversation_id, str) and self.__user_data[user_token].get(conversation_id) is not None:
        # Detected existing conversation.
        conversation_kwargs = self.__user_data[user_token][conversation_id].get('conversation_kwargs', {})
        domain = domain or conversation_kwargs.get('domain')
        remaining_kwargs = {
          k: v for k, v in conversation_kwargs.items()
          if k != 'domain'
        }
        kwargs = {
          **remaining_kwargs,
          **kwargs,
        }
      # endif existing conversation detected

      domain_prompt, additional_kwargs = self.get_domain_prompt(
        user_token=user_token,
        domain=domain,
        return_additional_kwargs=True,
      )

      validated_kwargs = self._validate_llm_kwargs(**kwargs)
      additional_kwargs = {
        **additional_kwargs,
        **validated_kwargs
      }

      messages = self.get_messages_of_user(
        # In case of non-chat requests, no conversation history is used.
        user_token=user_token if is_chat_request else None,
        message=message,
        domain_prompt=domain_prompt,
      )
      result['additional_kwargs'] = additional_kwargs
      result['messages'] = messages
      return result

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
      processed_request = self.pre_process_chat_request(
        user_token=user_token,
        message=message,
        domain=domain,
        **kwargs,
      )
      if processed_request['err_response'] is not None:
        return processed_request['err_response']

      additional_kwargs = processed_request['additional_kwargs']
      messages = processed_request['messages']

      domain_additional_data_step_description = self.get_description_of_retrieval_step(
        domain=domain,
        query=message,
        user_token=user_token,
        short_term_memory_only=False,
        # optional, since no preprocessing is needed
        preprocess_request_method=None,
        compute_request_result_method=self.compute_request_result_retrieval_domain_additional_data,
      )
      chat_step_description = self.get_description_of_chat_step(
        domain=domain,
        user_token=user_token,
        messages=messages,
        keep_conversation_history=False,
        use_long_term_memory=False,
        preprocess_request_method=self.preprocess_request_method_query,
        compute_request_result_method=self.compute_request_result_chat,
        extracted_param_names=[
          self.ct.JeevesCt.CONTEXT
        ],
        **additional_kwargs
      )

      request_steps = [
        domain_additional_data_step_description,
        chat_step_description,
      ]
      request_steps = [
        step for step in request_steps
        if step is not None
      ]
      postponed_request = self.start_request_steps(
        request_steps=request_steps
      )
      return postponed_request

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

      chat_step_description = self.get_description_of_chat_step(
        domain=domain,
        user_token=user_token,
        messages=messages,
        keep_conversation_history=False,
        use_long_term_memory=False,
        preprocess_request_method=None,
        compute_request_result_method=self.compute_request_result_chat,
        **request_kwargs
      )

      postponed_request = self.start_request_steps(
        request_steps=[chat_step_description]
      )
      return postponed_request

    def compute_request_result_retrieval_long_term_memory(
        self, request_data: dict,
        payload_response: dict,
    ):
      """
      Method for preparing the RAG retrieval request for the long term memory.
      Parameters
      ----------
      request_data : dict
          The request data from the Jeeves API.
      payload_response : dict
          The processed payload from the Document Retrieval agent.

      Returns
      -------
      res : dict
          The processed data for the next request that is not already
          present in the request_data.
      """
      # If this point is reached, that means no error occurred thus far.
      query_data = request_data.get('query_data', {})
      extracted_docs = query_data.get('docs')
      request_data['long_term_memory_context'] = extracted_docs
      return request_data

    def compute_request_result_retrieval_domain_additional_data(
        self, request_data: dict,
        payload_response: dict,
    ):
      """
      Method for preparing the RAG retrieval request for the domain additional data.
      Parameters
      ----------
      request_data : dict
          The request data from the Jeeves API.
      payload_response : dict
          The processed payload from the Document Retrieval agent.

      Returns
      -------
      res : dict
          The processed data for the next request that is not already
          present in the request_data.
      """
      # If this point is reached, that means no error occurred thus far.
      query_data = request_data.get('query_data', {})
      extracted_docs = query_data.get('docs')
      request_data['domain_additional_context'] = extracted_docs
      return request_data

    def preprocess_request_method_chat(
        self,
        request_data: dict,
    ):
      """
      Method for preprocessing the current data before sending it to the LLM agent.
      Parameters
      ----------
      request_data : dict
          The request data gathered thus far.

      Returns
      -------
      result_data : dict
          The processed data for the next request that is not already
          present in the request_data.
      """
      # In the future, both contexts could will merged or included in the messages.
      domain_context = request_data.get('domain_additional_context', [])
      long_term_memory_context = request_data.get('long_term_memory_context', [])
      messages = request_data.get('messages', [])
      return {
        self.ct.JeevesCt.CONTEXT: long_term_memory_context
      }

    def compute_request_result_chat(
        self,
        request_data: dict,
        payload_response: dict,
    ):
      """
      Method for processing the response from the LLM agent.
      Parameters
      ----------
      request_data : dict
          The request data from the Jeeves API.
      payload_response : dict
          The response from the LLM agent.

      Returns
      -------
      result_data : dict
          The processed data for the next request that is not already
          present in the request_data.
      """
      result = None
      reply_data = request_data.get("reply_data", {})
      reply_text = reply_data.get("text", "")
      request_id = request_data.get('request_id', 'N/A')

      if reply_text:
        result = {
          **reply_data,
        }
        user_token = request_data.get('user_token', None)
        user_messages = request_data.get('messages', [])
        use_long_term_memory = request_data.get('use_long_term_memory', False)
        keep_conversation_history = request_data.get('keep_conversation_history', False)
        self.P(
          f"Done processing request '{request_id}' for user {user_token} with {use_long_term_memory=}. Response is:\n {reply_text}",
          color="green"
        )

        conversation_id = request_data.get('conversation_id')
        self.P(f"Extracted conversation ID: `{conversation_id}`")
        message_saved = False
        if isinstance(conversation_id, str):
          conversation_data = self.__user_data[user_token].get("conversations", {}).get(conversation_id)
          if conversation_data:
            self.Pd(f"Adding messages to conversation '{conversation_id}' for user '{user_token}'")
            current_messages = conversation_data.get('messages', [])
            last_user_message = self.get_last_user_message(user_messages)
            if last_user_message is not None:
              current_messages.append(last_user_message)
            # endif last user message
            current_messages.append({
              'role': 'assistant',
              'content': reply_text,
            })
            conversation_data['messages'] = current_messages
            conversation_data['last_access_time'] = self.time()
            conversation_data['n_requests'] += 1
            message_saved = True
            self.__user_data[user_token][conversation_id] = conversation_data
            result['conversation_id'] = conversation_id
          # endif conversation_data exists
        # endif

        if not message_saved and keep_conversation_history:
          self.P(f"User messages: {user_messages}")
          last_user_message = self.get_last_user_message(user_messages)
          if last_user_message is not None:
            self.__user_data[user_token]['messages'].append(last_user_message)
          self.__user_data[user_token]['messages'].append({
            'role': 'assistant',
            'content': reply_text,
          })
          self.maybe_short_term_memory_to_long_term_memory(user_token, use_long_term_memory=use_long_term_memory)
        # endif keep conversation history
      # endif reply_text is not empty
      self.Pd(f"Request ID '{request_id}' to LLM successfully processed.", color="green")

      return {
        "result": result,
      }

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
      processed_request = self.pre_process_chat_request(
        user_token=user_token,
        message=message,
        domain=domain,
        short_term_memory_only=short_term_memory_only,
        is_chat_request=True,
        **kwargs,
      )
      if processed_request['err_response'] is not None:
        return processed_request['err_response']

      additional_kwargs = processed_request['additional_kwargs']
      messages = processed_request['messages']
      # The long term memory for the user conversation will be a domain identified with his
      # user token.
      use_long_term_memory = not short_term_memory_only

      long_term_memory_step_description = self.get_description_of_retrieval_step(
        domain=user_token,
        query=message,
        user_token=user_token,
        short_term_memory_only=short_term_memory_only,
        # optional, since no preprocessing is needed
        preprocess_request_method=None,
        compute_request_result_method=self.compute_request_result_retrieval_long_term_memory,
      )
      domain_additional_data_step_description = self.get_description_of_retrieval_step(
        domain=domain,
        query=message,
        user_token=user_token,
        short_term_memory_only=False,
        # optional, since no preprocessing is needed
        preprocess_request_method=None,
        compute_request_result_method=self.compute_request_result_retrieval_domain_additional_data,
      )
      chat_step_description = self.get_description_of_chat_step(
        domain=domain,
        user_token=user_token,
        messages=messages,
        keep_conversation_history=True,
        use_long_term_memory=use_long_term_memory,
        preprocess_request_method=self.preprocess_request_method_chat,
        compute_request_result_method=self.compute_request_result_chat,
        extracted_param_names=[
          self.ct.JeevesCt.CONTEXT
        ],
        **additional_kwargs
      )

      request_steps = [
        long_term_memory_step_description,
        domain_additional_data_step_description,
        chat_step_description,
      ]
      request_steps = [step for step in request_steps if step is not None]
      postponed_request = self.start_request_steps(
        request_steps=request_steps,
      )
      return postponed_request

    def create_conversation_data(self, conversation_kwargs: dict = None):
      conversation_kwargs = conversation_kwargs or {}
      return {
        'creation_time': self.time(),
        'last_access_time': self.time(),
        'messages': [],
        'n_requests': 0,
        "conversation_kwargs": conversation_kwargs,
      }

    def process_conversation_messages(
        self, conversation_messages: list[dict],
        **kwargs
    ):
      """
      Process the conversation messages if needed.
      By default, this is the identity function.
      Parameters
      ----------
      conversation_messages: list[dict]

      kwargs

      Returns
      -------

      """
      user_replies = []
      last_assistant_message = None
      for msg in conversation_messages:
        msg_content = msg.get("content")
        if not msg_content:
          continue
        if msg.get("role") == "user":
          user_replies.append(msg_content)
        elif msg.get("role") == "assistant":
          # Here, the entire dictionary is used, since it will be wrapped in the same way.
          last_assistant_message = msg
      # endfor conversation messages
      res = []
      if user_replies:
        agg_label = "User messages:"
        res.append({
          "role": "user",
          "content": f"{agg_label}\n\n" + "\n\n---\n\n".join(user_replies)
        })
      # endif existing user replies
      if last_assistant_message:
        res.append(last_assistant_message)
      # endif existing assistant message
      return res

    def maybe_add_conversation_messages(
        self,
        conversation_data: dict,
        messages: list[dict],
        **kwargs
    ):
      """
      Handle the conversation history for the Jeeves API.
      This will merge the registered messages from conversation_data,
      the message(s) from the user, and the system prompt if present.
      Parameters
      ----------
      conversation_data : dict
          The conversation data from a specific conversation of a specific user.
      messages : list[dict]
          The messages to send to the API. This will contain the current user message
          and optionally the system prompt as the last message.


      Returns
      -------
      res : list[dict]
          The messages to send to the API.
      """
      last_message = messages[-1]
      if last_message.get('role') == 'system':
        current_messages = messages[-2:]
      else:
        current_messages = messages[-1:]
      # endif last message is system
      # Here, the conversation messages are already stored in a raw manner.
      conversation_messages = self.deepcopy(conversation_data.get('messages', []))
      self.Pd(f"Extracted conversation messages: {conversation_messages}")
      conversation_messages = self.process_conversation_messages(conversation_messages, **kwargs)
      self.Pd(f"Processed conversation messages: {conversation_messages}")
      conversation_messages += current_messages

      return conversation_messages

    @BasePlugin.endpoint(method="post")
    def conversation(
        self,
        user_token: str = None,
        conversation_id: str = None,
        message: str = None,
        domain: str = None,
        **kwargs
    ):
      """
      Start or continue a conversation with the Jeeves API.
      In case this is a new conversation, the kwargs will be stored for future reference.
      In case this is a continuation of a conversation, if any kwargs are provided,
      they will be used instead of the stored ones, but they will not be stored for future reference.
      Parameters
      ----------
      user_token : str
          The user token to use for the API. Default is None.
      conversation_id : str
          The conversation ID to use for the API. Default is None.
          If None, a new conversation will be started.
      message : str
          The message to send to the API. Default is None.
      domain : str
          The domain to use for the API. Default is None.
      kwargs : dict
          Additional parameters to send to the API. Default is None.

      Returns
      -------

      """
      processed_request = self.pre_process_chat_request(
        user_token=user_token,
        message=message,
        domain=domain,
        conversation_id=conversation_id,
        **kwargs,
      )
      if processed_request['err_response'] is not None:
        return processed_request['err_response']
      # endif error in processing request

      additional_kwargs = processed_request['additional_kwargs']
      messages = processed_request['messages']
      # Handling conversation history
      current_user_conversations_data = self.__user_data[user_token].get('conversations', {})
      if conversation_id is None:
        conversation_id = self.uuid()
        while conversation_id in current_user_conversations_data:
          conversation_id = self.uuid()
        # endwhile conversation_id already existent
      # endif conversation_id not provided
      conversation_data = self.__user_data[user_token].get('conversations', {}).get(conversation_id, {})
      if not conversation_data:
        self.Pd(f"Creating new conversation '{conversation_id}' for user '{user_token}'")
        conversation_kwargs = {
          'domain': domain,
          **additional_kwargs
        }
        self.__user_data[user_token]['conversations'][conversation_id] = self.create_conversation_data(
          conversation_kwargs=conversation_kwargs
        )
        conversation_data = self.__user_data[user_token]['conversations'][conversation_id]
      # endif new conversation
      messages = self.maybe_add_conversation_messages(
        conversation_data=conversation_data,
        messages=messages
      )

      domain_additional_data_step_description = self.get_description_of_retrieval_step(
        domain=domain,
        query=message,
        user_token=user_token,
        short_term_memory_only=False,
        # optional, since no preprocessing is needed
        preprocess_request_method=None,
        compute_request_result_method=self.compute_request_result_retrieval_domain_additional_data,
      )
      chat_step_description = self.get_description_of_chat_step(
        domain=domain,
        user_token=user_token,
        messages=messages,
        keep_conversation_history=False,
        use_long_term_memory=False,
        preprocess_request_method=self.preprocess_request_method_query,
        compute_request_result_method=self.compute_request_result_chat,
        extracted_param_names=[
          self.ct.JeevesCt.CONTEXT
        ],
        conversation_id=conversation_id,
        **additional_kwargs
      )

      request_steps = [
        domain_additional_data_step_description,
        chat_step_description
      ]
      request_steps = [
        step for step in request_steps
        if step is not None
      ]
      postponed_request = self.start_request_steps(
        request_steps=request_steps
      )
      return postponed_request
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

  """REQUEST STEPS SECTION"""
  if True:
    def default_payload_processing_method(self, payload_data: dict):
      return payload_data

    def default_preprocess_request_method(self, request_data: dict):
      """
      The result of this method will be merged with the request data.
      Parameters
      ----------
      request_data : dict
          The request data that contains all the information about the request.

      Returns
      -------
      result_data : dict
          The processed data for the next request that is not already
          present in the request_data.
      """
      return {}

    def default_compute_request_result_method(self, request_data: dict, payload_response: dict):
      """
      The result of this method will be merged with the request data.
      Parameters
      ----------
      request_data : dict
          The request data that contains all the information about the request.
      payload_response : dict
          The response from the worker agent.

      Returns
      -------
      result_data : dict
          The processed data for the next request that is not already
          present in the request_data.
      """
      return {
        **payload_response
      }

    def get_request_step_data_dictionary(self):
      return {
        "step_start_time": None,
        "step_end_time": None,
        "error": None,
      }

    def _validate_and_extract_request_step(
        self,
        request_id: str,
        request_step_idx: int,
        request_data: dict,
        check_if_started: bool = True,
    ):
      """
      Validate and extract the request step from the request data.
      Parameters
      ----------
      request_id : str
          The request ID to validate.
      request_step_idx : int
          The request step index to validate.
      request_data : dict
          The request data that contains the request steps.

      Returns
      -------
      tuple (bool, dict, dict, dict)
          A tuple containing:
          - dict: the extracted request step.
          - dict: the extracted request step data.
          - dict: the request result if the request is already finished or the step has already been started.
      """
      extracted_step = None
      extracted_step_data = None
      is_finished = request_data.get('finished', False)
      request_result = None
      if is_finished:
        self.Pd(f"Request '{request_id}' is already finished.", color="r")
        # If the request is already finished, it should have the 'result' key set.
        # In case it is not set, return a generic error.
        request_result = request_data.get('result', {
          'error': "Error occurred in solving the request.",
        })
        return extracted_step, extracted_step_data, request_result
      # endif request is finished

      request_steps = request_data.get('request_steps', [])
      if len(request_steps) == 0:
        self.Pd(f"Request '{request_id}' has no specific request steps. Will mark as finished")
        # request_result being an empty dict means no error occurred, but
        # no further processing is needed.
        request_result = {
          "result": None
        }
        return extracted_step, extracted_step_data, request_result
      if request_step_idx >= len(request_steps):
        self.Pd(f"Request step index '{request_step_idx}' is out of bounds for request '{request_id}'. Only {len(request_steps)} steps exist.", color="r")
        request_result = {
          'error': f"Request step index '{request_step_idx}' is out of bounds. Only {len(request_steps)} steps exist.",
        }
        return extracted_step, extracted_step_data, request_result
      # endif request step index is out of bounds

      # Extract the current step and its data
      extracted_step = request_steps[request_step_idx]
      request_steps_data = request_data.get('request_steps_data', {})
      current_step_data = request_steps_data.get(str(request_step_idx), {})

      if check_if_started:
        # Check if the current step has already been started
        current_step_start_time = current_step_data.get('step_start_time')
        if current_step_start_time is not None:
          self.Pd(
            f"Request step index '{request_step_idx}' for request '{request_id}' has already been started.",
            color="r"
          )
          request_result = self.solve_postponed_request(request_id=request_id)
        # endif current step has already been started
      # endif check if started
      return extracted_step, current_step_data, request_result

    def start_request_step(
        self,
        request_id: str,
        request_step_idx: int,
    ):
      # Validate the request step.
      request_data = self.deepcopy_request_data(request_id=request_id, default_value={})
      # self.Pd(f"Current request_data:\n{request_data}")
      current_step, current_step_data, result = self._validate_and_extract_request_step(
        request_id=request_id,
        request_step_idx=request_step_idx,
        request_data=request_data
      )
      if result is not None:
        self.__requests[request_id] = {
          **request_data,
          **result,
          'finished': True,
        }
        return result

      # Start processing the current step
      try:
        request_steps_data = request_data.get('request_steps_data', {})
        current_step_data = self.get_request_step_data_dictionary()
        current_step_data['step_start_time'] = self.time()
        request_steps_data[str(request_step_idx)] = current_step_data
        request_data['request_steps_data'] = request_steps_data
        preprocess_request_method = current_step.get('preprocess_request_method', None)
        if not callable(preprocess_request_method):
          preprocess_request_method = self.default_preprocess_request_method
        try:
          result_data = preprocess_request_method(request_data)
        except Exception as e:
          self.Pd(f"Error in custom preprocess request method: {e}\nFallback to default method.", color="r")
          result_data = self.default_preprocess_request_method(request_data)
        # endtry except preprocess_request_method

        result_data = result_data or {}
        request_data = {
          **request_data,
          **result_data,
        }

        current_step_request_param_names = current_step.get('request_param_names', [])
        current_step_request_type = current_step.get('request_type', None)
        log_msg = f"[{request_id}]Processing request step {request_step_idx} of type '{current_step_request_type}' "
        log_msg += f"with param names: {current_step_request_param_names}."
        self.Pd(log_msg)

        # The elements in `request_param_name` can be either strings or tuples.
        # - string means only the parameter name was specified and the value will be retrieved from request_data.
        # - tuple means both the parameter name and its value were specified(the tuple will have to be of length 2).
        current_step_request_kwargs_explicit = {}
        current_step_request_kwargs_extracted = {}
        for param in current_step_request_param_names:
          # If the request parameter is a tuple of length 2, the value
          if isinstance(param, tuple) and len(param) == 2:
            current_step_request_kwargs_explicit[param[0]] = param[1]
          else:
            current_step_request_kwargs_extracted[str(param).lower()] = request_data.get(param)
          # endif
        # endfor current_step_request_param_names
        current_step_request_kwargs = {
          **current_step_request_kwargs_explicit,
          **current_step_request_kwargs_extracted,
          'request_type': current_step_request_type,
          'request_id': request_id,
        }

        self.Pd(f"Request step {request_step_idx} kwargs:\n{current_step_request_kwargs}")

        _, request_data = self.register_request(
          return_request_data=True,
          **current_step_request_kwargs,
        )
      except Exception as e:
        self.Pd(f"Error in handling request step {request_step_idx}: {e}", color="red")
        request_data['result'] = {
          'error': str(e),
          'request_id': request_data.get('request_id', 'unknown'),
        }
        request_data[str(request_step_idx)]['error'] = str(e)
        request_data['finished'] = True
      # endtry except next request steps

      request_data['current_request_step_idx'] = request_step_idx
      self.__requests[request_id] = request_data
      return self.solve_postponed_request(request_id=request_id)

    def start_request_steps(self, request_steps: list, **kwargs):
      request_id = self.uuid()
      start_time = self.time()
      self.__requests[request_id] = {
        "request_id": request_id,
        "start_time": start_time,
        "last_request_time": start_time,
        'finished': False,
        'timeout': self.cfg_request_timeout,
        'request_steps': request_steps,
        'current_request_step_idx': 0,
        'request_steps_data': {},
        **kwargs,
      }

      postponed_request = self.start_request_step(
        request_id=request_id,
        request_step_idx=0,
      )
      return postponed_request

    def resolve_request_step(
        self,
        request_id: str,
        request_data: dict,
        request_step_idx: int,
        payload_response: dict
    ):
      # Validate the request step.
      current_step, current_step_data, result = self._validate_and_extract_request_step(
        request_id=request_id,
        request_step_idx=request_step_idx,
        request_data=request_data,
        check_if_started=False
      )
      if result is not None:
        self.__requests[request_id] = {
          **request_data,
          **result,
          'finished': True,
        }
        return result

      # Process the current step
      try:
        request_steps_data = request_data.get('request_steps_data', {})
        compute_request_result_method = current_step.get('compute_request_result_method', None)
        if not callable(compute_request_result_method):
          compute_request_result_method = self.default_compute_request_result_method
        try:
          result_data = compute_request_result_method(request_data=request_data, payload_response=payload_response)
        except Exception as e:
          self.Pd(f"Error in custom compute request result method: {e}\nFallback to default method.", color="r")
          result_data = self.default_compute_request_result_method(
            request_data=request_data, payload_response=payload_response
          )
        # endtry except compute_request_result_method

        result_data = result_data or {}
        request_data = {
          **request_data,
          **result_data,
        }

        current_time = self.time()
        current_step_data['step_end_time'] = current_time
        request_steps_data[str(request_step_idx)] = current_step_data
        request_data['request_steps_data'] = request_steps_data
      except Exception as e:
        self.Pd(f"Error in handling request `{request_id}` at step {request_step_idx}: {e}", color="red")
        request_data['result'] = {
          'error': str(e),
          'request_id': request_id,
        }
        current_step_data['error'] = str(e)
        current_step_data['step_end_time'] = self.time()
        request_steps_data = request_data.get('request_steps_data', {})
        request_steps_data[str(request_step_idx)] = current_step_data
        request_data['request_steps_data'] = request_steps_data
        request_data['finished'] = True
      # endtry except next request steps

      self.__requests[request_id] = request_data

      is_finished = request_data.get('finished', False)
      request_number_of_steps = len(request_data.get('request_steps', []))
      if request_step_idx == request_number_of_steps - 1:
        is_finished = True
      # endif last step
      request_data['finished'] = is_finished

      self.__requests[request_id] = request_data

      if not is_finished:
        # Move to the next step
        next_request_step_idx = request_step_idx + 1
        return self.start_request_step(
          request_id=request_id,
          request_step_idx=next_request_step_idx,
        )
      return self.solve_postponed_request(request_id=request_id)
  """END REQUEST STEPS SECTION"""

  """PAYLOAD HANDLERS SECTION"""
  if True:
    def handle_payload_helper_doc_embedding(
        self,
        request_id: str,
        request_data: dict,
        payload_data: dict
    ):
      """
      Specific handling of the payload from a DocEmbedding agent.
      Parameters
      ----------
      request_id : str
          The request ID.
      request_data : dict
          The entire request data available thus far.
      payload_data : dict
          The payload data from the DocEmbedding agent.

      Returns
      -------
      res : dict
          The updated request data.
      """
      request_type = request_data.get('request_type', None)
      if request_type is None:
        # If request type is not specified in the request data,
        # try to extract it from the current request step.
        current_request_step_idx = request_data.get('current_request_step_idx', 0)
        request_steps = request_data.get('request_steps', [])
        if current_request_step_idx < len(request_steps):
          request_type = request_steps[current_request_step_idx].get('request_type', None)
      # endif request type is None

      error_message = None
      request_result = payload_data.get('RESULT') or {}
      if request_type == 'ADD_DOC':
        request_data['result'] = {
          **request_result,
          'elapsed_time': self.time() - request_data['last_request_time'],
          'request_id': request_id,
        }
      elif request_type == 'QUERY':
        docs = request_result.get('DOCS', [])
        request_data['query_data'] = {
          'elapsed_time': self.time() - request_data['last_request_time'],
          'request_id': request_id,
          'docs': docs,
        }
      else:
        error_message = f"Unknown request type for request ID '{request_id}': '{request_type}'!"
      # endif request type specific handling

      if error_message is None:
        log_msg = f"`{request_type}` payload from DocEmbedding agent successfully processed for request ID '{request_id}'."
        self.Pd(log_msg, color="g")
      # endif no error

      request_data['error'] = error_message
      return request_data

    def handle_payload_helper_llm(
        self,
        request_id: str,
        request_data: dict,
        payload_data: dict,
    ):
      """
      Specific handling of the payload from an LLM agent.
      Parameters
      ----------
      request_id : str
          The request ID.
      request_data : dict
          The entire request data available thus far.
      payload_data : dict
          The payload data from the LLM agent.

      Returns
      -------
      res : dict
          The updated request data.
      """
      error_message = None
      request_result = payload_data.get('RESULT') or {}
      text_response = request_result.get('TEXT_RESPONSE', "")
      model_name = request_result.get('MODEL_NAME', None)
      if text_response is not None and isinstance(text_response, str):
        request_data['reply_data'] = {
          'elapsed_time': self.time() - request_data['last_request_time'],
          'text': text_response,
          'model_name': model_name,
          # TODO: check if necessary
          'request_id': request_id,
        }
      else:
        error_message = f"Invalid text response from LLM agent for request ID '{request_id}'!"
      # endif text response is valid

      request_data['error'] = error_message
      return request_data

    def handle_payload_helper(
        self,
        data: dict,
        agent_type: str = None,
    ):
      """
      Helper method for handling payloads from agent responses.
      Parameters
      ----------
      data : dict
          The payload data to handle.

      agent_type : str
          The type of agent that sent the payload.

      Returns
      -------
      success : bool
          True if the payload was handled successfully, False otherwise.
      """
      success = False
      request_id = data.get('REQUEST_ID', None)
      # Check if the request ID is valid.
      if isinstance(request_id, str) and len(request_id) > 0:
        # Check if the request ID exists in the requests dictionary.
        if request_id in self.__requests:
          # Extract the request data and copy it to avoid modifying the original data.
          # These copies will be used for all the processing of the request.
          request_data = self.deepcopy_request_data(request_id=request_id, default_value={})
          payload_data = self.deepcopy(data)
          # Check if the request is already finished.
          request_finished = request_data.get('finished', False)
          if request_finished:
            self.Pd(f"Request ID '{request_id}' to {agent_type} agents already finished.", color="red")
            return
          # endif request already finished

          # Check error in current payload.
          # Maybe change the error handling in the future
          # to allow for partial results in case of requests with multiple steps.
          error_message = (data.get('RESULT') or {}).get('ERROR_MESSAGE')
          if error_message is not None:
            request_data['result'] = {
              'error': error_message,
              'request_id': request_id,
            }
            request_data['finished'] = True
            self.Pd(f"Request ID '{request_id}' to {agent_type} failed with error: {error_message}", color="red")
          # endif error message is not None

          # Specific handling for the current agent type.
          try:
            handling_error_message = None
            if agent_type == "DOC_EMBEDDING":
              request_data = self.handle_payload_helper_doc_embedding(
                request_id=request_id,
                request_data=request_data,
                payload_data=payload_data
              )
            elif agent_type == "LLM":
              request_data = self.handle_payload_helper_llm(
                request_id=request_id,
                request_data=request_data,
                payload_data=payload_data
              )
            else:
              handling_error_message = f"Unknown agent type '{agent_type}' for request ID '{request_id}'!"
            # endif agent type specific handling
            if handling_error_message is None:
              # Check if the specific handling set an error in the request data.
              handling_error_message = request_data.get('error', None)
            # endif specific handling finished successfully
          except Exception as e:
            handling_error_message = f"Error in {agent_type} specific payload handling for request ID '{request_id}': {e}"
          # endtry except agent type specific handling

          # Resolve request steps if no error occurred.
          if handling_error_message is None:
            request_step_idx = request_data.get('current_request_step_idx', 0)
            self.resolve_request_step(
              request_id=request_id,
              request_step_idx=request_step_idx,
              payload_response=payload_data,
              request_data=request_data,
            )
            # endif no error in processing next steps
          # endif no error in agent type specific handling
          # Separate check in case of exception in next steps handling.
          else:
            request_data['result'] = {
              'error': handling_error_message,
              'request_id': request_id,
            }
            request_data['finished'] = True
            self.Pd(handling_error_message, color="red")
            # Update the request data in the requests dictionary.
            self.__requests[request_id] = request_data
          # endif handling error message is not None
        else:
          self.Pd(f"Request ID '{request_id}' not found in requests.", color="red")
          # debug_msg = f"Known requests: {list(self.__requests.keys())}"
          # self.Pd(debug_msg, color="red")
        # endif request_id exists
      else:
        self.Pd(f"`REQUEST_ID` not provided in {data}")
      # endif request_id available
      return success

    @_NetworkProcessorMixin.payload_handler(signature="DOC_EMBEDDING_AGENT")
    def handle_payload_doc_embedding_agent(self, data):
      return self.handle_payload_helper(
        data=data,
        agent_type="DOC_EMBEDDING",
      )

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

    @_NetworkProcessorMixin.payload_handler(signature="VLLM_AGENT")
    def handle_payload_vllm_agent(self, data):
      return self.handle_payload_helper(
        data=data,
        agent_type="LLM",
      )

    @_NetworkProcessorMixin.payload_handler(signature="LLM_AGENT")
    def handle_payload_llm_agent(self, data):
      return self.handle_payload_helper(
        data=data,
        agent_type="LLM",
      )
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
