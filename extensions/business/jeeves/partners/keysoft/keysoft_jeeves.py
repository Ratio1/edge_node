from extensions.business.jeeves.jeeves_api import JeevesApiPlugin as BasePlugin
from .keysoft_jeeves_constants import KeysoftJeevesConstants
from extensions.business.jeeves.partners.keysoft.utils.pdf_parser import PDFParser


_CONFIG = {
  **BasePlugin.CONFIG,

  "PREDEFINED_DOMAINS": KeysoftJeevesConstants.PREDEFINED_DOMAINS,
  'SHORT_TERM_MEMORY_SIZE': 60,  # in replies (both user and assistant replies are counted)

  # Semaphore key for paired plugin synchronization (e.g., with CAR containers)
  # When set, this plugin will signal readiness and expose env vars to paired plugins
  "SEMAPHORE": None,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class KeysoftJeevesPlugin(BasePlugin):
  """
  A plugin which handles a Jeeves API web app hosted through FastAPI.

  Supports semaphore-based pairing with Container App Runner plugins via
  the SEMAPHORE configuration key. When configured, exposes API host/port
  as environment variables to paired containers.
  """
  CONFIG = _CONFIG


  def on_init(self):
    super(KeysoftJeevesPlugin, self).on_init()
    self.pdf_parser = PDFParser()
    return


  def _setup_semaphore_env(self):
    """Set semaphore environment variables for paired plugins."""
    port = getattr(self, 'cfg_port', 15033)
    localhost_ip = self.log.get_localhost_ip()
    self.semaphore_set_env('PORT', str(port))
    self.semaphore_set_env('RATIO1_AGENT_ENDPOINT',
      'http://{}:{}/query'.format(localhost_ip, port))
    self.semaphore_set_env('RATIO1_AGENT_UPLOAD_ENDPOINT',
      'http://{}:{}/upload_document_for_domain_base64'.format(localhost_ip, port))
    return


  def on_close(self):
    super(KeysoftJeevesPlugin, self).on_close()
    return


  def get_predefined_user_tokens(self):
    env_predefined_tokens_str = self.os_environ.get("EE_KEYSOFT_JEEVES_TOKENS") or ""
    env_predefined_tokens = [tok.strip() for tok in env_predefined_tokens_str.split(',')]
    env_predefined_tokens = [tok for tok in env_predefined_tokens if tok]

    configured_tokens = super(KeysoftJeevesPlugin, self).get_predefined_user_tokens()

    return env_predefined_tokens + configured_tokens

  # Wrapper method for easier testing of multiple endpoints
  @BasePlugin.endpoint(method="post")
  def query(
      self,
      user_token: str,
      message: str,
      db_schema: str = None,
      domain: str = None,
      conversation_id: str = None,
      request_type: str = "query",
      **kwargs
  ):
    if request_type == "query":
      return super(KeysoftJeevesPlugin, self).query(
        user_token=user_token,
        message=message,
        domain=domain,
        **kwargs
      )
    elif request_type == "ddl_assist":
      return self.ddl_assist(
        user_token=user_token,
        message=message,
        domain=domain,
        **kwargs
      )
    elif request_type == "ddl_expert":
      return self.ddl_expert(
        user_token=user_token,
        message=message,
        domain=domain,
        **kwargs
      )
    elif request_type == "nlsql_query":
      if db_schema is None:
        return {
          "error": "db_schema must be provided for nlsql_query."
        }
      # endif db_schema is None
      return self.nlsql_query(
        user_token=user_token,
        message=message,
        db_schema=db_schema,
        domain=domain,
        **kwargs
      )
    elif request_type == "chat":
      return super(KeysoftJeevesPlugin, self).chat(
        user_token=user_token,
        message=message,
        domain=domain,
        short_term_memory_only=True,
        **kwargs
      )
    elif request_type == "parse_pdf":
      return self.parse_pdf(
        user_token=user_token,
        pdf_base64=message,
      )
    elif request_type == "conversation":
      return super(KeysoftJeevesPlugin, self).conversation(
        user_token=user_token,
        message=message,
        domain=domain,
        conversation_id=conversation_id,
        **kwargs
      )
    # endif request_type is not query, nlsql_query or chat
    return {
      "error": f"Unknown request_type: {request_type}. Supported types are: query, nlsql_query, chat."
    }

  @BasePlugin.endpoint(method="post")
  def parse_pdf(
      self,
      user_token: str,
      pdf_base64: str,
      use_header_template_fallback: bool = False,
  ):
    """
    Parse a PDF file and return its text content.

    Parameters
    ----------
    user_token : str
        The user token to use for the API.
    pdf_base64 : str
        The base64-encoded PDF file content.
    use_header_template_fallback : bool, optional
        Whether to use header template fallback when parsing the PDF. Default is False.

    Returns
    -------
    dict
        A dictionary containing the parsed text or an error message.
    """
    if not self.verify_user_token(user_token):
      return self.invalid_token_response()
    if not isinstance(pdf_base64, str) or not pdf_base64.strip():
      return {
        "error": "pdf_base64 must be a non-empty string."
      }
    # endif pdf_base64 is not a valid string

    try:
      records = self.pdf_parser.pdf_base64_to_dicts(
        pdf_base64=pdf_base64,
        use_header_template_fallback=use_header_template_fallback
      )
      # endif empty content
      return {
        "records": records
      }
    except Exception as e:
      return {
        "error": f"Failed to parse PDF: {str(e)}"
      }
    # endtry

  def compute_request_result_initial_ddl(
        self,
        request_data: dict,
        payload_response: dict,
    ):
    reply_data = request_data.get("reply_data", {})
    reply_text = reply_data.get("text", "")
    request_id = request_data.get('request_id', 'N/A')

    self.Pd(f"Request ID '{request_id} for initial DDL successfully processed")

    return {
      "result_step1": reply_data,
      "initial_ddl": reply_text
    }

  def preprocess_request_method_refine_ddl(
      self,
      request_data: dict
  ):
    user_token = request_data["user_token"]
    refine_domain_prompt = self.get_domain_prompt(
      user_token=user_token,
      domain='refine_ddl',
      return_additional_kwargs=False
    )
    initial_ddl = request_data["initial_ddl"]
    initial_query = request_data["initial_query"]
    current_message = f"""<INITIAL_DDL>
````sql
{initial_ddl.strip()}
````
</INITIAL_DDL>
<USER_REQUEST>
{initial_query.strip()}
</USER_REQUEST>
    """
    messages = self.get_messages_of_user(
      user_token=user_token,
      message=current_message,
      domain_prompt=refine_domain_prompt
    )
    return {
      'messages': messages
    }

  def compute_request_result_refine_ddl(
        self,
        request_data: dict,
        payload_response: dict,
    ):
    result = None
    reply_data = request_data.get("reply_data", {})
    reply_text = reply_data.get("text", "")
    request_id = request_data.get('request_id', 'N/A')
    if reply_text:
      result = {
        **reply_data,
        "result_step1": request_data["result_step1"]
      }
    # endif

    self.Pd(f"Request ID '{request_id} for refine DDL successfully processed")

    return {
      "result": result
    }

  @BasePlugin.endpoint(method="post")
  def ddl_expert(
      self,
      user_token: str,
      message: str,
      domain: str = None,
      **kwargs
  ):
    """
    This endpoint is a custom implementation of /query endpoint.
    Instead of a single step generation of a DDL statement, this endpoint
    will also have a second step of reviewing the generated DDL statement along
    with the initial user request and regenerate a final DDL statement.

    Parameters
    ----------
    user_token : str
        The user token to use for the API.
    message : str
        The message to send to the API.
    domain : str
        The domain to use for the API.
    kwargs : dict
        Additional parameters to send to the API.

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

    # Step 1: Initial DDL generation
    step1_description = self.get_description_of_chat_step(
      domain=domain,
      user_token=user_token,
      messages=messages,
      keep_conversation_history=False,
      use_long_term_memory=False,
      compute_request_result_method=self.compute_request_result_initial_ddl,
      **additional_kwargs,
    )
    # end Step 1
    # Step 2: Review and refine the generated DDL
    step2_description = self.get_description_of_chat_step(
      domain='refine_ddl',
      user_token=user_token,
      # Will be added to the request data after the first step is complete
      messages=None,
      keep_conversation_history=False,
      use_long_term_memory=False,
      preprocess_request_method=self.preprocess_request_method_refine_ddl,
      compute_request_result_method=self.compute_request_result_refine_ddl,
      extracted_param_names=[
        'messages'
      ],
      **additional_kwargs,
    )
    request_steps = [
      step1_description,
      step2_description
    ]
    postponed_request = self.start_request_steps(
      request_steps=request_steps,
      initial_query=message
    )
    return postponed_request

  def preprocess_request_method_ddl_assist(
      self,
      request_data: dict
  ):
    user_token = request_data["user_token"]
    refine_domain_prompt = self.get_domain_prompt(
      user_token=user_token,
      domain='assist_ddl',
      return_additional_kwargs=False
    )
    initial_ddl = request_data["initial_ddl"]
    initial_query = request_data["initial_query"]
    current_message = f"""<INITIAL_DDL>
````sql
{initial_ddl.strip()}
````
</INITIAL_DDL>
<USER_REQUEST>
{initial_query.strip()}
</USER_REQUEST>
        """
    messages = self.get_messages_of_user(
      user_token=user_token,
      message=current_message,
      domain_prompt=refine_domain_prompt
    )
    return {
      'messages': messages
    }

  @BasePlugin.endpoint(method="post")
  def ddl_assist(
      self,
      user_token: str,
      message: str,
      domain: str = None,
      **kwargs
  ):
    """
    This endpoint is a custom implementation of /query endpoint.
    Instead of a single step generation of a DDL statement, this endpoint
    will also have a second step of reviewing the generated DDL statement along
    with the initial user request and generating a refined prompt for the user to
    use in order to get a better DDL statement.
    Parameters
    ----------
    user_token : str
        The user token to use for the API.
    message : str
        The message to send to the API.
    domain : str
        The domain to use for the API.
    kwargs : dict
        Additional parameters to send to the API.

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

    # Step 1: Initial DDL generation
    step1_description = self.get_description_of_chat_step(
      domain=domain,
      user_token=user_token,
      messages=messages,
      keep_conversation_history=False,
      use_long_term_memory=False,
      compute_request_result_method=self.compute_request_result_initial_ddl,
      **additional_kwargs,
    )
    # end Step 1
    # Step 2: Review and refine the user prompt
    step2_description = self.get_description_of_chat_step(
      domain='assist_ddl',
      user_token=user_token,
      # Will be added to the request data after the first step is complete
      messages=None,
      keep_conversation_history=False,
      use_long_term_memory=False,
      preprocess_request_method=self.preprocess_request_method_ddl_assist,
      compute_request_result_method=self.compute_request_result_refine_ddl,
      extracted_param_names=[
        'messages'
      ],
      **additional_kwargs,
    )
    request_steps = [
      step1_description,
      step2_description
    ]
    postponed_request = self.start_request_steps(
      request_steps=request_steps,
      initial_query=message
    )
    return postponed_request

  @BasePlugin.endpoint(method="post")
  def nlsql_query(
      self,
      user_token: str,
      message: str,
      db_schema: str,
      domain: str = None,
      **kwargs
  ):
    """
    Process a natural language SQL query along with the db schema in order to generate a SQL query.
    Parameters
    ----------

    user_token : str
        The user token to use for the API. Default is None.
    message : str
        The message to send to the API. Default is None.
    db_schema : str
        The database schema to use for the query. Default is None.
    domain : str
        The domain to use for the API. Default is None.
    kwargs : dict
        Additional parameters to send to the API. Default is None.

    Returns
    -------

    """
    # The user token will be validated in the .query() method.
    if not isinstance(db_schema, str):
      return {
        "error": "db_schema must be a string."
      }
    # endif db_schema is not a string
    if not isinstance(message, str):
      return {
        "error": "message must be a string."
      }
    # endif message is not a string
    # For future support, we can have the dialect as a parameter, but for now we will use ANSI.
    # dialect = "ansi"
    aggregated_request = f"""
<DB_SCHEMA>
````sql
{db_schema}
````
</DB_SCHEMA>
<USER_REQUEST>
{message.strip()}
</USER_REQUEST>
    """
    return self.query(
      user_token=user_token,
      message=aggregated_request,
      domain=domain,
      **kwargs
    )
