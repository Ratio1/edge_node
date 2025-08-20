from extensions.business.jeeves.jeeves_api import JeevesApiPlugin as BasePlugin
from .keysoft_jeeves_constants import KeysoftJeevesConstants


_CONFIG = {
  **BasePlugin.CONFIG,

  "PREDEFINED_DOMAINS": KeysoftJeevesConstants.PREDEFINED_DOMAINS,
  'SHORT_TERM_MEMORY_SIZE': 60,  # in replies (both user and assistant replies are counted)

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class KeysoftJeevesPlugin(BasePlugin):
  """
  A plugin which handles a Jeeves API web app hosted through FastAPI.
  """

  CONFIG = _CONFIG

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
    # endif request_type is not query, nlsql_query or chat
    return {
      "error": f"Unknown request_type: {request_type}. Supported types are: query, nlsql_query, chat."
    }

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
DB_SCHEMA:
````sql
{db_schema}
````
USER_REQUEST:
{message.strip()}
    """
    return self.query(
      user_token=user_token,
      message=aggregated_request,
      domain=domain,
      **kwargs
    )

