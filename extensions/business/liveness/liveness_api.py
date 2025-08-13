
from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.3.3'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  # 'ASSETS': 'plugins/business/fastapi/epoch_manager',
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class LivenessApiPlugin(BasePlugin):
  """
  This plugin is a FastAPI web app that provides endpoints to interact with the
  EpochManager of the Neural Core.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(LivenessApiPlugin, self).__init__(**kwargs)
    return
  

  def on_init(self):
    super(LivenessApiPlugin, self).on_init()

    current_epoch = self.__get_current_epoch()
    self.P("Started {} plugin in epoch {}".format(
      self.__class__.__name__, current_epoch)
    )
    # TODO: Bleo lock it until we `can_serve` it
    return


  def __sign(self, data):
    """
    Sign the given data using the blockchain engine.
    Returns the signature. 
    Use the data param as it will be modified in place.
    """
    signature = self.bc.sign(data, add_data=True, use_digest=True)
    return signature


  def __get_response(self, dct_data: dict, **kwargs):
    """
    Create a response dictionary with the given data.

    Parameters
    ----------
    dct_data : dict
        The data to include in the response - data already prepared 

    Returns
    -------
    dict
        The input dictionary with the following keys added:
        - server_alias: str
            The literal alias of the current node.

        - server_time: str
            The current time in UTC of the current node.

        - server_current_epoch: int
            The current epoch of the current node.

        - server_uptime: str
            The time that the current node has been running.
    """
    str_utc_date = self.datetime.now(self.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    # dct_data['server_id'] = self.node_addr # redundant due to the EE_SENDER
    dct_data['server_alias'] = self.node_id
    dct_data['server_version'] = self.ee_ver
    dct_data['server_time'] = str_utc_date
    dct_data['server_current_epoch'] = self.__get_current_epoch()
    dct_data['server_last_synced_epoch'] = self.__get_synced_epoch()
    dct_data['server_uptime'] = str(self.timedelta(seconds=int(self.time_alive)))
    for k, v in kwargs.items():
      # some filters may be applied to the data
      dct_data[k] = v
    # end for kwargs
    self.__sign(dct_data) # add the signature over full data
    return dct_data

  def __get_current_epoch(self):
    """
    Get the current epoch of the node.

    Returns
    -------
    int
        The current epoch of the node.
    """
    real_epoch = self.netmon.epoch_manager.get_current_epoch()
    return real_epoch  
  
  @BasePlugin.endpoint
  # /get_liveness
  def get_liveness(self, service=None):
    """

    """
    data = {}
    
    response = self.__get_response(data)
    return response
