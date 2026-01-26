from naeural_core.business.base import BasePluginExecutor as BasePlugin
from naeural_core.business.mixins_libs.nlp_agent_mixin import _NlpAgentMixin, NLP_AGENT_MIXIN_CONFIG

__VER__ = '0.1.0.0'

_CONFIG = {
  # mandatory area
  **BasePlugin.CONFIG,
  **NLP_AGENT_MIXIN_CONFIG,

  # our overwritten props
  'AI_ENGINE'               : "code_generator",
  'PROCESS_DELAY'           : 10,


  'VALIDATION_RULES' : {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
    **NLP_AGENT_MIXIN_CONFIG['VALIDATION_RULES'],
  },  
}


class CodeAssist01Plugin(BasePlugin, _NlpAgentMixin):
  CONFIG = _CONFIG

  def _process(self):
    # we always receive input from the upstream due to the fact that _process
    # is called only when we have input based on ALLOW_EMPTY_INPUTS=False (from NLP_AGENT_MIXIN_CONFIG)
    full_input = self.dataapi_full_input()
    self.Pd("Processing received input: {}".format(full_input))
    str_dump = self.json_dumps(full_input, indent=2)
    self.Pd("Received input from pipeline:\n{}".format(str_dump))
    # endif debug string
    data = self.dataapi_struct_data()
    inferences = self.dataapi_struct_data_inferences()
    return self.compute_response(data, inferences)
