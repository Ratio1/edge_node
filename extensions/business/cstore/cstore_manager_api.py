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

  @BasePlugin.endpoint(method="post", require_token=False)
  def set(self, key: str, value: str):  
    """
    """

    write_result = self.chainstore_set(
      key=key,
      value=value,
      debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG
    )
    return write_result

  @BasePlugin.endpoint(method="get", require_token=False)
  def get(self, key: str):
    """
    """

    value = self.chainstore_get(key=key, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)
    return value


  @BasePlugin.endpoint(method="post", require_token=False)
  def hset(self, hkey: str, key: str, value: str):  
    """
    """

    write_result = self.chainstore_hset(
      hkey=hkey,
      key=key,
      value=value,
      debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG
    )
    return write_result


  @BasePlugin.endpoint(method="get", require_token=False)
  def hget(self, hkey: str, key: str):
    """
    """

    value = self.chainstore_hget(hkey=hkey, key=key, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)
    return value


  @BasePlugin.endpoint(method="get", require_token=False)
  def hgetall(self, hkey: str):  
    """
    """

    value = self.chainstore_hgetall(hkey=hkey, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)
    return value

