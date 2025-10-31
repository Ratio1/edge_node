from naeural_core.data.default.iot.network_listener import NetworkListenerDataCapture as BaseClass
from extensions.utils.jeeves.jeeves_utils import _JeevesUtilsMixin
from constants import JeevesCt


_CONFIG = {
  **BaseClass.CONFIG,

  "PATH_FILTER": JeevesCt.UNIFIED_PATH_FILTER,
  "SUPPORTED_REQUEST_TYPES": None,  # supported request types, None means all are supported


  'VALIDATION_RULES': {
    **BaseClass.CONFIG['VALIDATION_RULES'],
  },
}


class JeevesListenerDataCapture(BaseClass, _JeevesUtilsMixin):
  CONFIG = _CONFIG

  def Pd(self, s, color=None, **kwargs):
    """
    Print debug message with Jeeves agent prefix.
    """
    if self.cfg_debug_iot_payloads:
      self.P(s, color=color, **kwargs)
    return

  def filter_message_for_agent(self, normalized_message: dict):
    """
    Method for filtering messages intended for Jeeves agent processing.
    This is done after the initial checks from _filter_message.
    The additional checks are based on the following criteria:
    1. The message must contain the key "JEEVES_CONTENT" with a dictionary.
    2. The "JEEVES_CONTENT" dictionary must contain the key "REQUEST_ID" with a string value.
    3. The "REQUEST_ID" must not be in the set of processed requests.
    Parameters
    ----------
    normalized_message : dict
      The incoming message to filter, already normalized by _filter_message.

    Returns
    -------
    filtered_message : dict or None
      The filtered message if it matches the Jeeves agent format, otherwise None.
    """
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

    if not self.check_supported_request_type(message_data=normalized_jeeves_content):
      request_type = normalized_jeeves_content.get(JeevesCt.REQUEST_TYPE, None)
      self.Pd(
        f"Unsupported request type: {request_type}. Supported types: {self.cfg_supported_request_types}",
        color='r'
      )
      return None
    # endif unsupported request type
    return normalized_message

  def check_message_for_agent(self, message: dict) -> bool:
    """
    Method for checking if the message is intended for Jeeves agent processing.
    Parameters
    ----------
    message : dict
      The incoming message to check.

    Returns
    -------
    is_for_agent  : bool
      True if the message is intended for Jeeves agent processing, False otherwise.
    """
    payload_path = message.get(self.ct.PAYLOAD_DATA.EE_PAYLOAD_PATH, [None, None, None, None])
    payload_signature = payload_path[2] if len(payload_path) >= 3 else None

    return payload_signature in JeevesCt.JEEVES_API_SIGNATURES

  def _filter_message(self, unfiltered_message: dict):
    """
    Method for checking if the message should be kept or not during the filtering process.
    The checks are based on the following criteria:
    1. The message must be a dictionary.
    2. The message must contain the key "PAYLOAD_PATH" with a list of four elements
    (node address, pipeline name, signature and instance id of the instance the message was
    sent from).
    3. Depending on the signature in the "PAYLOAD_PATH", the message is either
    intended for Jeeves agent processing or not. If it is, it is further processed
    by filter_message_for_agent.

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

    if self.check_message_for_agent(normalized_message):
      prefiltered_message = self.filter_message_for_agent(normalized_message)
    # endif message for agent
    return prefiltered_message

