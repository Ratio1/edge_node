from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.2.2'

CHAINSTORE_MANAGER_API_PLUGIN_DEBUG = True

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 31234,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'CSTORE_VERBOSE' : 11,
  
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


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

  def _log_request_response(self, endpoint_name: str, request_data: dict = None, response_data: dict = None):
    """Helper method to log requests and responses when verbose mode is enabled"""
    if hasattr(self, 'cfg_cstore_verbose') and self.cfg_cstore_verbose > 10:
      self.P(f"=== {endpoint_name} ENDPOINT ===", color='y')
      if request_data:
        self.P(f"REQUEST: {self.json.dumps(request_data, indent=2)}", color='c')
      if response_data:
        self.P(f"RESPONSE: {self.json.dumps(response_data, indent=2)}", color='g')
      self.P(f"=== END {endpoint_name} ===", color='y')

   
  def __get_keys(self):
    result = []
    _data = self.plugins_shmem.get('__chain_storage', {})
    if isinstance(_data, dict):
      result = list(_data.keys())
    return result


  @BasePlugin.endpoint(method="get", require_token=False) 
  def get_status(self):   # /get_status
    """
    Get the current status of the chainstore.
    
    Returns:
        dict: A dictionary containing the list of all keys currently stored in the chainstore.
    """
    # Log request
    self._log_request_response("GET_STATUS", request_data={})
    
    data = {
      'keys' : self.__get_keys()
    }
    
    # Log response
    self._log_request_response("GET_STATUS", response_data=data)
    
    return data

  @BasePlugin.endpoint(method="post", require_token=False)
  def set(self, key: str, value: str):  
    """
    Set a key-value pair in the chainstore.
    
    Args:
        key (str): The key to store the value under
        value (str): The value to store
        
    Returns:
        boolean: The result of the write operation
    """
    # Log request
    request_data = {
      'key': key,
      'value': value
    }
    self._log_request_response("SET", request_data=request_data)

    write_result = self.chainstore_set(
      key=key,
      value=value,
      debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG
    )
    
    # Log response
    self._log_request_response("SET", response_data=write_result)
    
    return write_result

  @BasePlugin.endpoint(method="get", require_token=False)
  def get(self, key: str):
    """
    Retrieve a value from the chainstore by key.
    
    Args:
        key (str): The key to retrieve the value for
        
    Returns:
        str: The value associated with the given key, or None if not found
    """
    # Log request
    request_data = {
      'key': key
    }
    self._log_request_response("GET", request_data=request_data)

    value = self.chainstore_get(key=key, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)
    
    # Log response
    self._log_request_response("GET", response_data=value)
    
    return value


  @BasePlugin.endpoint(method="post", require_token=False)
  def hset(self, hkey: str, key: str, value: str):  
    """
    Set a field-value pair within a hash in the chainstore.
    
    Args:
        hkey (str): The hash key (outer key)
        key (str): The field key within the hash
        value (str): The value to store for the field
        
    Returns:
        boolean: The result of the write operation
    """
    # Log request
    request_data = {
      'hkey': hkey,
      'key': key,
      'value': value
    }
    self._log_request_response("HSET", request_data=request_data)

    write_result = self.chainstore_hset(
      hkey=hkey,
      key=key,
      value=value,
      debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG
    )
    
    # Log response
    self._log_request_response("HSET", response_data=write_result)
    
    return write_result


  @BasePlugin.endpoint(method="get", require_token=False)
  def hget(self, hkey: str, key: str):
    """
    Retrieve a field value from a hset in the chainstore.
    
    Args:
        hkey (str): The hash key (outer key)
        key (str): The field key within the hset
        
    Returns:
        str: The value associated with the given field in the hset, or None if not found
    """
    # Log request
    request_data = {
      'hkey': hkey,
      'key': key
    }
    self._log_request_response("HGET", request_data=request_data)

    value = self.chainstore_hget(hkey=hkey, key=key, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)
    
    # Log response
    self._log_request_response("HGET", response_data=value)
    
    return value


  @BasePlugin.endpoint(method="get", require_token=False)
  def hgetall(self, hkey: str):  
    """
    Retrieve all field-value pairs from a hset in the chainstore.
    
    Args:
        hkey (str): The hash key to retrieve all fields for
        
    Returns:
        list: A list containing all hset keys
    """
    # Log request
    request_data = {
      'hkey': hkey
    }
    self._log_request_response("HGETALL", request_data=request_data)

    value = self.chainstore_hgetall(hkey=hkey, debug=CHAINSTORE_MANAGER_API_PLUGIN_DEBUG)
    
    # Log response
    self._log_request_response("HGETALL", response_data=value)
    
    return value

