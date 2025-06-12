from extensions.data.default.iot.jeeves_agent_listener import JeevesAgentListenerDataCapture as BaseClass
from constants import JeevesCt


_CONFIG = {
  **BaseClass.CONFIG,

  "SUPPORTED_REQUEST_TYPES": JeevesCt.LLM_REQUEST_TYPES,  # supported request types, None means all are supported

  'VALIDATION_RULES': {
    **BaseClass.CONFIG['VALIDATION_RULES'],
  },
}


class JeevesLlmAgentListenerDataCapture(BaseClass):
  CONFIG = _CONFIG

