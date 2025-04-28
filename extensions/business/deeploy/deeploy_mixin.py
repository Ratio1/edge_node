from naeural_core.constants import BASE_CT


DEEPLOY_DEBUG = True

MESSAGE_PREFIX = "Please sign this message for Deeploy: "

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


  def __verify_signature(self, payload):
    """
    Verify the signature of the request.
    """
    sender = self.bc.eth_verify_payload_signature(
      payload=payload,
      message_prefix=MESSAGE_PREFIX,
      no_hash=True,
      indent=1,
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

  
  def __check_allowed_wallet(self, inputs):
    sender = inputs.get(BASE_CT.BCctbase.ETH_SENDER)
    eth_nodes = self.bc.get_wallet_nodes(sender)
    if len(eth_nodes) == 0:
      raise ValueError("No nodes found for wallet {}".format(sender))
    eth_oracles = self.bc.get_eth_oracles()
    if len(eth_oracles) == 0:
      raise ValueError("No oracles found - this is a critical issue!")
    oracle_found = False
    wallet_oracles = []
    wallet_nodes = []
    for node in eth_nodes:
      if node in eth_oracles:
        oracle_found = True
        wallet_oracles.append(node)
      else:
        wallet_nodes.append(node)
      #endif 
    #endfor each node
    if not oracle_found:
      raise ValueError("No oracles found for wallet {}".format(sender))
    inputs.wallet_nodes = wallet_nodes
    inputs.wallet_oracles = wallet_oracles
    return inputs

  def __parse_memory(self, mem_str):
    """
    Convert memory string to bytes.
    Args:
        mem_str (str): Memory string in format '512m', '1g', or bytes
    Returns:
        int: Memory in bytes
    """
    if mem_str.endswith('m'):
      return int(mem_str[:-1]) * 1024 * 1024  # MB to bytes
    elif mem_str.endswith('g'):
      return int(mem_str[:-1]) * 1024 * 1024 * 1024  # GB to bytes
    else:
      return int(mem_str)  # assume bytes

  def check_node_resources(self, addr, inputs):
    """
    Check if the node has sufficient resources for the requested deployment.
    Returns:
        dict: {
            'status': bool,  # True if all checks pass, False otherwise
            'details': list, # List of resource issues if any
            'available': dict, # Available resources
            'required': dict  # Required resources
        }
    """
    result = {
        'status': True,
        'details': [],
        'available': {},
        'required': {}
    }
    
    # Get available resources
    avail_mem = self.netmon.network_node_available_memory(addr)  # in bytes
    avail_disk = self.netmon.network_node_available_disk(addr)  # in bytes

    # Get required resources from the request
    required_resources = inputs.app_params.get('CONTAINER_RESOURCES', {})
    required_mem = required_resources.get('memory', '512m')
    required_cpu = required_resources.get('cpu', 1)

    # Store available and required resources
    required_mem_bytes = self.__parse_memory(required_mem)
    # Check memory
    self.Pd("Available memory: {} bytes".format(avail_mem))
    self.Pd("Required memory: {} bytes".format(required_mem_bytes))

    if avail_mem < required_mem_bytes:
      result['available']['memory'] = avail_mem
      result['required']['memory'] = required_mem_bytes

      result['status'] = False
      avail_mem_mb = avail_mem / (1024 * 1024)
      required_mem_mb = result['required']['memory'] / (1024 * 1024)
      result['details'].append({
          'resource': 'Memory',
          'available': avail_mem_mb,
          'required': required_mem_mb,
          'unit': 'MB'
      })

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
    if diff < 0:
      raise ValueError("Nonce is invalid(f)!")
    if diff > 12*60*60:
      raise ValueError("Nonce is expired!")      
    str_timestamp = self.time_to_str(_time)
    return str_timestamp
  
  
  def deeploy_verify_and_get_inputs(self, request: dict):
    sender = request.get(BASE_CT.BCctbase.ETH_SENDER)
    assert self.bc.is_valid_eth_address(sender), f"Invalid sender address: {sender}"
    
    inputs = self.NestedDotDict(request)    
    self.Pd(f"Received request from {sender}{': ' + str(inputs) if DEEPLOY_DEBUG else '.'}")
    
    addr = self.__verify_signature(request)
    if addr.lower() != sender.lower():
      raise ValueError("Invalid signature: recovered {} != {}".format(addr, sender))    
    
    # Check if the sender is allowed to create pipelines
    self.__check_allowed_wallet(inputs)
    
    return sender, inputs
  
  
  def deeploy_get_auth_result(self, inputs):
    sender = inputs.get(BASE_CT.BCctbase.ETH_SENDER)
    result = {
      'sender' : sender,
      'nonce' : self.deeploy_get_nonce(inputs.nonce),
      'sender_oracles' : inputs.wallet_oracles,
      'sender_nodes_count' : len(inputs.wallet_nodes),
      'sender_total_count' : len(inputs.wallet_nodes) + len(inputs.wallet_oracles),
  }
    return result
      

  def deeploy_prepare_single_plugin_instance(self, inputs):
    """
    Prepare the a single plugin instance for the pipeline creation.
    """
    # 10 chars unique id using self.uuid() (inherited from utils)
    instance_id = inputs.plugin_signature.upper()[13] + '_' + self.uuid(6) 
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