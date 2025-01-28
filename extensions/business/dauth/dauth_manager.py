"""

EE_HB_CONTAINS_PIPELINES=0
EE_HB_CONTAINS_ACTIVE_PLUGINS=1
EE_EPOCH_MANAGER_DEBUG=1
WHITELIST (oracles)




"""

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.2.2'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'DAUTH_VERBOSE' : True,
  
  # required ENV keys are defined in plugin template and should be added here
  
  "AUTH_ENV_KEYS" : [
  ],
  
  "AUTH_PREDEFINED_KEYS" : {
  },
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class DauthManagerPlugin(BasePlugin):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for decentralized authentication.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(DauthManagerPlugin, self).__init__(**kwargs)
    return

  def on_init(self):
    super(DauthManagerPlugin, self).on_init()
    my_address = self.bc.address
    my_eth_address = self.bc.eth_address
    self.P("Started {} plugin on {} / {}\n - Auth keys: {}\n - Predefined keys: {}".format(
      self.__class__.__name__, my_address, my_eth_address,
      self.cfg_auth_env_keys, self.cfg_auth_predefined_keys)
    )
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
  
  
  def __eth_to_internal(self, eth_node_address):
    return self.netmon.epoch_manager.eth_to_internal(eth_node_address)
  
  
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


  @BasePlugin.endpoint(method="post")
  # /get_auth_data
  def get_auth_data(self, body: dict):
    """
    Receive a request for authentication data from a node and return the data if the request is valid.

    Parameters
    ----------
    {
      "body" : {
        "EE_SENDER" : "sender node address",
        "EE_SIGN" : "sender signature on the message",
        "EE_HASH" : "message hash",
        "nonce" : "some-nonce"
        ... other data
      }      
    }
    
    """
    
    lst_auth_env_keys = self.cfg_auth_env_keys
    dct_auth_predefined_keys = self.cfg_auth_predefined_keys
    
    DAUTH_SUBKEY = self.const.BASE_CT.DAUTH_SUBKEY
    data = {
      DAUTH_SUBKEY : {
        'error' : None,
      },
    }
    
    if self.cfg_dauth_verbose:
      self.P("Received request for auth:\n{}".format(self.json_dumps(body, indent=2)))
    
    verify_data = self.bc.verify(body, return_full_info=True)
    
    if not verify_data.valid:
      data[DAUTH_SUBKEY]['error'] = 'Invalid signature: {}'.format(verify_data.message)
      if self.cfg_dauth_verbose:
        self.P("Verification failed: {}".format(verify_data), color='r')
    else:    
      if self.cfg_dauth_verbose:
        self.P("Verification passed: {}".format(verify_data))
      # check if node_address is allowed
      
      # prepare the env auth data
      for key in lst_auth_env_keys:
        if key.startswith('EE_'):
          data[DAUTH_SUBKEY][key] = self.os_environ.get(key)
      
      # overwrite the predefined keys
      for key in dct_auth_predefined_keys:
        data[DAUTH_SUBKEY][key] = dct_auth_predefined_keys[key]
      
      # self.chainstore_set()
      # record the node_address and the auth data
      
      # return the auth data
    
    response = self.__get_response({
      **data
    })
    return response
