from naeural_core.business.base import BasePluginExecutor


_CONFIG = {
  **BasePluginExecutor.CONFIG,
  "ALLOW_EMPTY_INPUTS": True,
  "PROCESS_DELAY": 1,
  "VALIDATION_RULES": {
    **BasePluginExecutor.CONFIG["VALIDATION_RULES"],
  },
  "CHAINSTORE_RESPONSE_KEY": None,
}


class DeeployTestbedPluginPlugin(BasePluginExecutor):
  CONFIG = _CONFIG

  def process(self):
    payload = self._create_payload(
      data=self.dataapi_struct_data(),
      inferences=self.dataapi_struct_data_inferences(),
    )
    return payload
