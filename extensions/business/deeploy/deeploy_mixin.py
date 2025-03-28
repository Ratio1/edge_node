from naeural_core.constants import BASE_CT

class _DeeployMixin:
  def __init__(self):
    super(_DeeployMixin, self).__init__()    
    return

  def Pd(self, s, *args, **kwargs):
    """
    Print a message to the console.
    """
    if self.cfg_dauth_verbose:
      s = "[DEPDBG] " + s
      self.P(s, *args, **kwargs)
    return  
  
  
  def deeploy_get_nonce(self, hex_nonce):
    """
    Convert a hex nonce to a timestamp.
    """
    str_nonce = hex_nonce.replace("0x", "")
    result = int(str_nonce, 16)
    str_timestamp = self.time_to_str(result)
    return str_timestamp
  
  
  def deeploy_get_inputs(self, request: dict):
    sender = request.get(BASE_CT.BCctbase.ETH_SENDER)
    inputs = self.NestedDotDict(request)    
    return sender, inputs
  
  
  def deeploy_get_auth_result(self, inputs, sender : str, verified_sender: str):
    result = {
      'auth' : {
        'sender' : sender,
        'verified_sender' : verified_sender,
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
    
    types = [
      self.bc.eth_types.ETH_STR,
      self.bc.eth_types.ETH_STR,
      self.bc.eth_types.ETH_STR,
      self.bc.eth_types.ETH_ARRAY_STR,
      self.bc.eth_types.ETH_INT,
      self.bc.eth_types.ETH_STR,
      self.bc.eth_types.ETH_STR,    
    ]
    
    sender = self.bc.eth_verify_message_signature(
      values=values,
      types=types,
      signature=inputs[self.ct.BASE_CT.BCctbase.ETH_SIGN],
    )
    return sender
  
  def deeploy_verify_delete_request(self, inputs):
    values = [
      inputs.app_name,
      inputs.plugin_signature,
      inputs.nonce,
      inputs.target_nodes,
    ]
    types = [
      self.bc.eth_types.ETH_STR,
      self.bc.eth_types.ETH_STR,
      self.bc.eth_types.ETH_STR,
      self.bc.eth_types.ETH_ARRAY_STR,
    ]
    sender = self.bc.eth_verify_message_signature(
      values=values,
      types=types,
      signature=inputs[self.ct.BASE_CT.BCctbase.ETH_SIGN],
    )
    return sender
  
  def deeploy_verify_get_apps_request(self, inputs):
    values = [
      inputs.nonce,
    ]
    types = [
      self.bc.eth_types.ETH_STR,
    ]
    sender = self.bc.eth_verify_message_signature(
      values=values,
      types=types,
      signature=inputs[self.ct.BASE_CT.BCctbase.ETH_SIGN],
    )
    return sender
      