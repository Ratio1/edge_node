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

