from extensions.business.jeeves.jeeves_api import JeevesApiPlugin as BasePlugin
from .keysoft_jeeves_constants import KeysoftJeevesConstants


_CONFIG = {
  **BasePlugin.CONFIG,

  "PREDEFINED_DOMAINS": KeysoftJeevesConstants.PREDEFINED_DOMAINS,

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
