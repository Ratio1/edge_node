from extensions.data.default.jeeves.jeeves_listener import JeevesListenerDataCapture as BaseClass
from constants import JeevesCt


_CONFIG = {
  **BaseClass.CONFIG,

  "PATH_FILTER": JeevesCt.AGENT_PATH_FILTER,
  "PING_PERIOD": 0.5,  # seconds between pings

  'PING_ENABLED': False,  # whether to send ping inputs

  'VALIDATION_RULES': {
    **BaseClass.CONFIG['VALIDATION_RULES'],
  },
}


class JeevesAgentListenerDataCapture(BaseClass):
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(JeevesAgentListenerDataCapture, self).__init__(**kwargs)
    self.last_ping_time = 0
    return

  def add_ping_input(self):
    self._add_inputs(
      [
        self._new_input(struct_data={
          'ping': True
        })
      ]
    )

  def needs_ping(self):
    """
    Check if it's time to send a ping input.
    """
    if not self.cfg_ping_enabled:
      return False
    if self._deque is None or len(self._deque) > 0:
      return False
    return self.time() - self.last_ping_time >= self.cfg_ping_period

  def _run_data_aquisition_step(self):
    """
    Override to of _run_data_aquisition_step to add ping inputs for Jeeves agents.
    """
    super()._run_data_aquisition_step()
    if self.needs_ping():
      # Add a ping input for Jeeves agents
      self.add_ping_input()
      self.last_ping_time = self.time()
    # endif needs_ping
    return
