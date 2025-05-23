from naeural_core.data.default.iot.network_listener import NetworkListenerDataCapture as BaseClass
from constants import JeevesCt


_CONFIG = {
  **BaseClass.CONFIG,

  "PATH_FILTER": JeevesCt.AGENT_PATH_FILTER,

  'VALIDATION_RULES': {
    **BaseClass.CONFIG['VALIDATION_RULES'],
  },
}


class JeevesAgentListenerDataCapture(BaseClass):
  CONFIG = _CONFIG

