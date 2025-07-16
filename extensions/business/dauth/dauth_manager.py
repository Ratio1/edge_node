"""
dauth_manager.py
================

This module implements the dAuth Manager plugin for the Ratio1e ecosystem. It provides a FastAPI web app
for decentralized authentication. The plugin is responsible for handling authentication requests and
providing authentication data to other nodes in the network using the dAuth protocol mainly defined in the
`extensions/business/dauth/dauth_mixin.py` module.





EE_HB_CONTAINS_PIPELINES=0
EE_HB_CONTAINS_ACTIVE_PLUGINS=1
EE_EPOCH_MANAGER_DEBUG=1
WHITELIST (oracles)




"""

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin
from extensions.business.dauth.dauth_mixin import _DauthMixin

__VER__ = '0.2.2'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'DAUTH_VERBOSE' : False,
  
  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,
  
  # required ENV keys are defined in plugin template and should be added here  
  "AUTH_ENV_KEYS" : [
  ],

  # node-only ENV keys should be added in this list - these are keys that should
  # not get to the non-nodes
  "AUTH_NODE_ENV_KEYS" : [
  ],

  
  "AUTH_PREDEFINED_KEYS" : {
  },
  
  
  "SUPERVISOR_KEYS" : [
    "EE_NGROK_EDGE_LABEL_EPOCH_MANAGER",
    "EE_NGROK_EDGE_LABEL_RELEASE_APP",
    "EE_NGROK_EDGE_LABEL_DAUTH_MANAGER",
    "EE_NGROK_EDGE_LABEL_CSTORE_MANAGER",
    "EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER"
    
    "EE_TUNNEL_ENGINE",

    "EE_CLOUDFLARE_TOKEN_EPOCH_MANAGER",
    "EE_CLOUDFLARE_TOKEN_RELEASE_APP",
    "EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER",
    "EE_CLOUDFLARE_TOKEN_CSTORE_MANAGER",
    "EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER",
  ],
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}



class DauthManagerPlugin(
  BasePlugin,
  _DauthMixin,
  ):
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
    TODO: move __get_response to base as a _get_response method or similar
    
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
    try:
      str_utc_date = self.datetime.now(self.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
      # dct_data['server_id'] = self.node_addr # redundant due to the EE_SENDER
      dct_data['server_alias'] = self.node_id
      dct_data['server_version'] = self.ee_ver
      dct_data['server_time'] = str_utc_date
      dct_data['server_current_epoch'] = self.__get_current_epoch()
      dct_data['server_uptime'] = str(self.timedelta(seconds=int(self.time_alive)))
      self.__sign(dct_data) # add the signature over full data
    except Exception as e:
      self.P("Error in `get_response`: {}".format(e), color='r')
      preexisting_error = dct_data.get('error', "")
      dct_data['error'] = f"{preexisting_error} - {e}"
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
    try:
      data = self.process_dauth_request(body)
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      data = {
        'error' : str(e)
      }
    
    response = self.__get_response({
      **data
    })
    return response
