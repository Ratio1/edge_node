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
    """
    if self.cfg_deeploy_verbose:
      full_data = self.netmon.network_known_nodes()
      self.Pd(f"Full data:\n{self.json_dumps(full_data, indent=2)}")
    pipelines = self.netmon.network_known_configs()
    non_admin_pipelines = {
      node : [x for x in pipelines[node] if x['NAME'].lower() != 'admin_pipeline'] 
      for node in pipelines      
    }  
    result = {
      'configs': non_admin_pipelines,
      'details': self.netmon.network_known_apps(),
    }     
    
    """
    result = self.netmon.network_known_apps()
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
      inputs.target_nodes,
      inputs.nonce,
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
      

  def deeploy_prepare_single_plugin_instance(self, inputs):
    """
    Prepare the a single plugin instance for the pipeline creation.
    """
    instance_id = inputs.plugin_signature.upper() + "_INST"
    plugin = {
      self.ct.CONFIG_PLUGIN.K_SIGNATURE : inputs.plugin_signature,
      self.ct.CONFIG_PLUGIN.K_INSTANCES : [
        {
          self.ct.CONFIG_INSTANCE.K_INSTANCE_ID : instance_id,
          **inputs.app_params
        }
      ]
    }
    return plugin
  
  def deeploy_prepare_plugins(self, inputs):    
    """
    Prepare the plugins for the pipeline creation.
    
    OBS: This must be modified in order to support multiple 
    instances if needed
    """
    plugin = self.deeploy_prepare_single_plugin_instance(inputs)
    plugins = [plugin]
    return plugins      