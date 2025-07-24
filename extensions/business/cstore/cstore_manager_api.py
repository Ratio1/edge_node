from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.2.2'

CHAINSTORE_MANAGER_API_PLUGIN_DEBUG = True

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 31234,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'CSTORE_VERBOSE' : True,
  
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}

DEFAULT_TOKENS = ['admin']

class CstoreManagerApiPlugin(BasePlugin):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for decentralized authentication.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(CstoreManagerApiPlugin, self).__init__(**kwargs)
    return

  def on_init(self):
    super(CstoreManagerApiPlugin, self).on_init()
    my_address = self.bc.address
    my_eth_address = self.bc.eth_address
    self.P("Started {} plugin on {} / {}".format(
      self.__class__.__name__, my_address, my_eth_address,
    ))
    return
  
  def __get_current_epoch(self):
    """
    Get the current epoch of the node.

    Returns
    -------
    int
        The current epoch of the node.
    """
    return self.netmon.epoch_manager.get_current_epoch()
  
   
  
  def __sign(self, data):
    """
    Sign the given data using the blockchain engine.
    Returns the signature. 
    Use the data param as it will be modified in place.
    """
    signature = self.bc.sign(data, add_data=True, use_digest=True)
    return signature

  def __get_response(self, dct_data: dict):
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
    dct_data['server_uptime'] = str(self.timedelta(seconds=int(self.time_alive)))
    self.__sign(dct_data) # add the signature over full data
    return dct_data
  
  
  def __get_keys(self):
    result = []
    _data = self.plugins_shmem.get('__chain_storage', {})
    if isinstance(_data, dict):
      result = list(_data.keys())
    return result


  @BasePlugin.endpoint(method="get", require_token=False) 
  def get_status(self):   # /get_status
    """
    """
    
    data = {
      'keys' : self.__get_keys()
    }
    
    return data



  @BasePlugin.endpoint(method="post", require_token=True)
  def set_value(self, token: str, key : str, value : str):   # first parameter must be named token
    """
    """
    
    if token not in DEFAULT_TOKENS:
      return "Unauthorized token"
    
    value = self.chainstore_set(
      key=key,
      value=value,
      debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG
    )
    
    data = {
      key : value
    }

    return data

  @BasePlugin.endpoint(method="get", require_token=True)
  def get_value(self, token, key: str):  # first parameter must be named token
    """
    """

    if token not in DEFAULT_TOKENS:
      return "Unauthorized token"

    value = self.chainstore_get(key=key, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)

    data = {
      key: value
    }

    return data


  @BasePlugin.endpoint(method="post", require_token=True)
  def hset(self, token, hkey: str, key: str, value : str):  # first parameter must be named token
    """
    """

    if token not in DEFAULT_TOKENS:
      return "Unauthorized token"

    value = self.chainstore_hset(
      hkey=hkey,
      key=key,
      value=value,
      debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG
    )

    data = {
      hkey: {
        key: value
      },
    }

    return data


  @BasePlugin.endpoint(method="get", require_token=True)
  def hget(self, token, hkey: str, key: str):
    """
    """

    if token not in DEFAULT_TOKENS:
      return "Unauthorized token"

    value = self.chainstore_hget(hkey=hkey, key=key, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)

    data = {
      hkey: {
        key: value
      }
    }

    return data


  @BasePlugin.endpoint(method="get", require_token=True)
  def hgetall(self, token, hkey: str):  # first parameter must be named token
    """
    """

    if token not in DEFAULT_TOKENS:
      return "Unauthorized token"

    value = self.chainstore_hgetall(hkey=hkey, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)

    data = {
      hkey: value
    }

    return data

