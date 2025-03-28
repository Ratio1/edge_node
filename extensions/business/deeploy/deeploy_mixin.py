from naeural_core.constants import BASE_CT


DEEPLOY_DEBUG = True

class _DeeployMixin:
  def __init__(self):
    super(_DeeployMixin, self).__init__()    
    return

  def Pd(self, s, *args, **kwargs):
    """
    Print a message to the console.
    """
    if self.cfg_deeploy_verbose:
      s = "[DEPDBG] " + s
      self.P(s, *args, **kwargs)
    return  
  
  
  def __get_emv_types(self, values):
    types = []
    known_types = self.bc.eth_types
    for value in values:
      if isinstance(value, str):        
        if value.startswith("0x") and len(value) == 42  and not value.startswith("0xai_"):
          types.append(known_types.ETH_ADDR)
        else:
          types.append(known_types.ETH_STR)
      elif isinstance(value, int):
        types.append(known_types.ETH_INT)
      elif isinstance(value, list) and isinstance(value[0], str):
        types.append(known_types.ETH_ARRAY_STR)
      elif isinstance(value, list) and isinstance(value[0], int):
        types.append(known_types.ETH_ARRAY_INT)
    return types  
  
  
  def __verify_signature(self, values, signature):
    """
    Verify the signature of the request.
    """
    assert signature is not None, "Missing request signature"
    types = self.__get_emv_types(values)
    if DEEPLOY_DEBUG:
      self.Pd(f"Verifying signature {signature} for {len(values)} vals with types {types}")
    sender = self.bc.eth_verify_message_signature(
      values=values,
      types=types,
      signature=signature,
    )
    return sender
  
  
  def _get_online_apps(self):
    dct_node_pipelines = self.netmon.network_known_configs()
    filtered = {
      node : pipelines for node, pipelines in dct_node_pipelines.items() 
      if self.netmon.network_node_is_online(node)
    }
    result = {
      node : {
        'apps' : pipelines,
        'status' : self.netmon.network_node_status(node),
      } 
      for node, pipelines in filtered.items() 
    }
    return result
  
  
  def deeploy_get_nonce(self, hex_nonce):
    """
    Convert a hex nonce to a timestamp.
    """
    str_nonce = hex_nonce.replace("0x", "")
    try:
      scaled = int(str_nonce, 16)
    except:
      raise ValueError("Nonce is invalid!")
    _time = scaled / 1000
    diff = self.time() - _time
    if diff > 24*60*60:
      raise ValueError("Nonce is expired!")      
    str_timestamp = self.time_to_str(_time)
    return str_timestamp
  
  
  def deeploy_get_inputs(self, request: dict):
    sender = request.get(BASE_CT.BCctbase.ETH_SENDER)
    inputs = self.NestedDotDict(request)    
    self.P(f"Received request from {sender}{': ' + str(inputs) if DEEPLOY_DEBUG else ''}")
    return sender, inputs
  
  
  def deeploy_get_auth_result(self, inputs, sender : str, verified_sender: str):
    result = {
      'auth' : {
        'sender' : sender,
        'verified_sender' : verified_sender,
        'nonce' : self.deeploy_get_nonce(inputs.nonce),
      },
    }
    return result
  
  
  def deeploy_verify_create_request(self, inputs):
    values = [
      inputs.app_name,
      inputs.plugin_signature,
      inputs.nonce,
      inputs.target_nodes,
      inputs.target_nodes_count,
      inputs.app_params.IMAGE,
      inputs.app_params.REGISTRY,
    ]
    
    sender = self.__verify_signature(
      values=values,
      signature=inputs.get(BASE_CT.BCctbase.ETH_SIGN),
    )
    return sender
  
  def deeploy_verify_delete_request(self, inputs):
    values = [
      inputs.app_name,
      inputs.plugin_signature,
      inputs.nonce,
      inputs.target_nodes,
    ]
    sender = self.__verify_signature(
      values=values,
      signature=inputs.get(BASE_CT.BCctbase.ETH_SIGN),
    )
    return sender


  def deeploy_verify_get_apps_request(self, inputs):
    values = [
      inputs.nonce,
    ]

    sender = self.__verify_signature(
      values=values,
      signature=inputs.get(BASE_CT.BCctbase.ETH_SIGN),
    )
    return sender
      