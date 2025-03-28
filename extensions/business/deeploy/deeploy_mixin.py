

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
  
  
  def _verify_create_request(self, inputs):
    values = [
      inputs.app_name,
      inputs.plugin_signature,
      inputs.nonce,
      inputs.target_nodes,
      inputs.arget_nodes_count,
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
  
  def _verify_delete_request(self, inputs):
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
  
  def _verify_get_apps_request(self, inputs):
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
      