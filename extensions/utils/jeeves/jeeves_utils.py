from constants import JeevesCt


class _JeevesUtilsMixin:
  def __init__(self):
    super(_JeevesUtilsMixin, self).__init__()
    return

  def check_supported_request_type(
      self,
      message_data: dict,
  ):
    """
    Method for checking if the message's request type is supported.
    The supported request types are retrieved through self.cfg_supported_request_types.
    If self.cfg_supported_request_types is None, all request types are supported.
    Parameters
    ----------
    message_data : dict
      The incoming message data. It should contain the request type under the key JeevesCt.REQUEST_TYPE.

    Returns
    -------
    res : bool
      True if the request type is supported or if no restrictions are set, False otherwise.
    """
    is_supported = True
    supported_request_types = self.cfg_supported_request_types
    if supported_request_types is not None:
      supported_request_types = supported_request_types or []
      if isinstance(supported_request_types, list):
        normalized_supported_request_types = [
          (rt.upper() if isinstance(rt, str) else rt)
          for rt in supported_request_types
        ]
        normalized_message_data = {
          (k.upper() if isinstance(k, str) else k): v
          for k, v in message_data.items()
        }
        request_type = normalized_message_data.get(JeevesCt.REQUEST_TYPE, None)
        request_type = request_type.upper() if isinstance(request_type, str) else request_type
        if request_type not in normalized_supported_request_types:
          is_supported = False
      # endif supported_request_types is list
    # endif supported_request_types configured
    return is_supported
