from naeural_core.data.default.iot.network_listener import NetworkListenerDataCapture as BaseClass
from constants import JeevesCt


_CONFIG = {
  **BaseClass.CONFIG,

  "PATH_FILTER": JeevesCt.AGENT_PATH_FILTER,
  "PING_PERIOD": 0.5,  # seconds between pings

  'PING_ENABLED': False,  # whether to send ping inputs
  "SUPPORTED_REQUEST_TYPES": None,  # supported request types, None means all are supported

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

  def Pd(self, s, color=None, **kwargs):
    """
    Print debug message with Jeeves agent prefix.
    """
    if self.cfg_debug_iot_payloads:
      self.P(s, color=color, **kwargs)
    return

  def _filter_message(self, unfiltered_message: dict):
    """
    Method for checking if the message should be kept or not during the filtering process.
    The checks are based on the following criteria:
    1. The message must be a dictionary.
    2. The message must contain the key "PAYLOAD_PATH" with a list of four elements
    (node address, pipeline name, signature and instance id of the instance the message was
    sent from).
    3. The third element of the "PAYLOAD_PATH" list must be a relevant signature.
    4. The message must contain the key "JEEVES_CONTENT" with a dictionary.
    5. The "JEEVES_CONTENT" dictionary must contain the key "REQUEST_ID" with a string value.
    6. The "REQUEST_ID" must not be in the set of processed requests.

    Parameters
    ----------
    unfiltered_message : dict
      The incoming message to filter.

    Returns
    -------
    filtered_message : dict or None
      The filtered message if it matches the format, otherwise None.
    """
    prefiltered_message = super()._filter_message(unfiltered_message)
    if prefiltered_message is None:
      return None
    if not isinstance(prefiltered_message, dict):
      self.Pd(f"Invalid message format: {self.shorten_str(prefiltered_message)}", color='r')
      return None

    normalized_message = {
      (k.upper() if isinstance(k, str) else k): v
      for k, v in prefiltered_message.items()
    }

    if JeevesCt.JEEVES_CONTENT not in normalized_message:
      self.Pd(
        f"Message does not contain '{JeevesCt.JEEVES_CONTENT}': {self.shorten_str(normalized_message)}",
        color='r'
      )
      return None

    jeeves_content = normalized_message[JeevesCt.JEEVES_CONTENT]
    if not isinstance(jeeves_content, dict):
      self.Pd(f"'{JeevesCt.JEEVES_CONTENT}' not a dict: {type(jeeves_content)}", color='r')
      return None

    normalized_jeeves_content = {
      (k.upper() if isinstance(k, str) else k): v
      for k, v in jeeves_content.items()
    }

    request_id = normalized_jeeves_content.get(JeevesCt.REQUEST_ID)
    if request_id is None or not isinstance(request_id, str):
      self.Pd(
        f"'{JeevesCt.JEEVES_CONTENT}' should contain '{JeevesCt.REQUEST_ID}' with string value. {self.shorten_str(jeeves_content)}",
        color='r'
      )
      return None

    supported_request_types = self.cfg_supported_request_types or []
    if isinstance(supported_request_types, list):
      normalized_supported_request_types = [
        (rt.upper() if isinstance(rt, str) else rt)
        for rt in supported_request_types
      ]
      request_type = normalized_jeeves_content.get(JeevesCt.REQUEST_TYPE, None)
      request_type = request_type.upper() if isinstance(request_type, str) else request_type
      if request_type not in normalized_supported_request_types:
        self.Pd(
          f"Unsupported request type: {request_type}. Supported types: {normalized_supported_request_types}",
          color='r'
        )
        return None
    # endif supported_request_types configured
    return normalized_message

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
