from naeural_core.constants import BASE_CT

from extensions.business.deeploy.deeploy_const import DEEPLOY_ERRORS, DEEPLOY_KEYS, DEEPLOY_RESOURCES, DEFAULT_RESOURCES

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
        mem_str (str): Memory string in format '512m', '1g', '1.3g, or bytes
    Returns:
        int: Memory in bytes
    """
    if mem_str.endswith('m'):
      return int(float(mem_str[:-1]) * 1024 * 1024)  # MB to bytes
    elif mem_str.endswith('g'):
      return int(float(mem_str[:-1]) * 1024 * 1024 * 1024)  # GB to bytes
    else:
      return int(float(mem_str))  # assume bytes

  def __check_nodes_availability(self, inputs):
    """
    Check if the target nodes are online and have sufficient resources.
    """
    nodes = []
    for node in inputs.target_nodes:
      addr = self._check_and_maybe_convert_address(node)
      is_online = self.netmon.network_node_is_online(addr)
      if is_online:
        node_resources = self.check_node_resources(addr, inputs)
        if not node_resources['status']:
          error_msg = f"{DEEPLOY_ERRORS.NODERES1}: Node {addr} has insufficient resources:\n"
          for detail in node_resources['details']:
            error_msg += f"- {detail['resource']}: available {detail['available']:.2f}{detail['unit']} < required {detail['required']:.2f}{detail['unit']}\n"
          raise ValueError(error_msg)
        nodes.append(addr)
      else:
        msg = f"{DEEPLOY_ERRORS.NODES1}: Node {addr} is not online"
        raise ValueError(msg)
      # endif is_online
    # endfor each target node check address and status
    return nodes

  def __launch_pipeline_on_nodes(self, nodes, inputs, app_id, app_alias, app_type, sender):
    """
    Launch the pipeline on each node and set CSTORE `response_key`` for the "callback" action
    """
    plugins = self.deeploy_prepare_plugins(inputs)
    response_keys = {}
    for addr in nodes:
      # Nodes to peer with for CHAINSTORE
      nodes_to_peer = [n for n in nodes if n != addr]
      node_plugins = self.deepcopy(plugins)
      
      # Configure chainstore peers and response keys
      for plugin in node_plugins:
        for plugin_instance in plugin[self.ct.CONFIG_PLUGIN.K_INSTANCES]:
          # Configure peers if there are any
          if len(nodes_to_peer) > 0:
            plugin_instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_PEERS] = nodes_to_peer
          # endif
          
          # Configure response keys if needed
          if inputs.chainstore_response:
            response_key = plugin_instance[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID] + '_' + self.uuid(4)
            plugin_instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = response_key
            response_keys[response_key] = addr
          # endif
        # endfor each plugin instance
      # endfor each plugin
  
      msg = ''
      if self.cfg_deeploy_verbose > 1:
        msg = f":\n {self.json_dumps(node_plugins, indent=2)}"
      self.P(f"Starting pipeline '{app_alias}' on {addr}{msg}")
      if addr is not None:
        self.cmdapi_start_pipeline_by_params(
          name=app_id,
          app_alias=app_alias,
          pipeline_type=app_type,
          node_address=addr,
          owner=sender,
          url=inputs.pipeline_input_uri,
          plugins=node_plugins,
        )
      # endif addr is valid
    # endfor each target node
    return response_keys

  def __get_pipeline_responses(self, response_keys, timeout_seconds=90):
    """
    Wait until all the responses are received via CSTORE and compose status response.
    Args:
        response_keys (dict): Dictionary mapping response keys to node addresses
        timeout_seconds (int): Maximum time to wait for responses in seconds
    Returns:
        tuple: (dct_status, str_status) where:
            dct_status: Dictionary of response statuses
            str_status: Overall status ('success', 'timeout', or 'pending')
    """
    dct_status = {}
    str_status = 'pending'
    done = False if len(response_keys) > 0 else True
    start_time = self.time()
    
    while not done:
      current_time = self.time()
      if current_time - start_time > timeout_seconds:
        str_status = 'timeout'
        break
        
      for response_key in response_keys:
        node_addr = response_keys[response_key]
        res = self.chainstore_get(response_key)
        if res is not None:
          dct_status[response_key] = {
            'node': node_addr,
            'details': res
          }
      if len(dct_status) == len(response_keys):
        str_status = 'success'
        done = True
      # end for each response key
    # endwhile cycle until all responses are received
    return dct_status, str_status

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
        DEEPLOY_RESOURCES.STATUS: True,
        DEEPLOY_RESOURCES.DETAILS: [],
        DEEPLOY_RESOURCES.AVAILABLE: {},
        DEEPLOY_RESOURCES.REQUIRED: {}
    }
    
    # Get available resources
    avail_cpu = self.netmon.network_node_get_cpu_avail_cores(addr)
    avail_mem = self.netmon.network_node_available_memory(addr)  # in GB
    avail_mem_bytes = self.__parse_memory(f"{avail_mem}g")
    avail_disk = self.netmon.network_node_available_disk(addr)  # in bytes

    # Get required resources from the request
    required_resources = inputs.app_params.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
    required_mem = required_resources.get(DEEPLOY_RESOURCES.MEMORY, DEFAULT_RESOURCES.MEMORY)
    required_cpu = required_resources.get(DEEPLOY_RESOURCES.CPU, DEFAULT_RESOURCES.CPU)

    required_mem_bytes = self.__parse_memory(required_mem)

    # CPU check
    if avail_cpu < required_cpu:
      result[DEEPLOY_RESOURCES.AVAILABLE][DEEPLOY_RESOURCES.CPU] = avail_cpu
      result[DEEPLOY_RESOURCES.REQUIRED][DEEPLOY_RESOURCES.CPU] = required_cpu

      result[DEEPLOY_RESOURCES.STATUS] = False
      result[DEEPLOY_RESOURCES.DETAILS].append({
          DEEPLOY_RESOURCES.RESOURCE: DEEPLOY_RESOURCES.CPU,
          DEEPLOY_RESOURCES.AVAILABLE_VALUE: avail_cpu,
          DEEPLOY_RESOURCES.REQUIRED_VALUE: required_cpu,
          DEEPLOY_RESOURCES.UNIT: DEEPLOY_RESOURCES.CORES
      })

    # Check memory
    if avail_mem_bytes < required_mem_bytes:
      result[DEEPLOY_RESOURCES.AVAILABLE][DEEPLOY_RESOURCES.MEMORY] = avail_mem_bytes
      result[DEEPLOY_RESOURCES.REQUIRED][DEEPLOY_RESOURCES.MEMORY] = required_mem_bytes

      result[DEEPLOY_RESOURCES.STATUS] = False
      avail_mem_mb = avail_mem_bytes / (1024 * 1024)
      required_mem_mb = result[DEEPLOY_RESOURCES.REQUIRED][DEEPLOY_RESOURCES.MEMORY] / (1024 * 1024)
      result[DEEPLOY_RESOURCES.DETAILS].append({
          DEEPLOY_RESOURCES.RESOURCE: DEEPLOY_RESOURCES.MEMORY,
          DEEPLOY_RESOURCES.AVAILABLE_VALUE: avail_mem_mb,
          DEEPLOY_RESOURCES.REQUIRED_VALUE: required_mem_mb,
          DEEPLOY_RESOURCES.UNIT: DEEPLOY_RESOURCES.MB
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
      DEEPLOY_KEYS.SENDER: sender,
      DEEPLOY_KEYS.NONCE: self.deeploy_get_nonce(inputs.nonce),
      DEEPLOY_KEYS.SENDER_ORACLES: inputs.wallet_oracles,
      DEEPLOY_KEYS.SENDER_NODES_COUNT: len(inputs.wallet_nodes),
      DEEPLOY_KEYS.SENDER_TOTAL_COUNT: len(inputs.wallet_nodes) + len(inputs.wallet_oracles),
    }
    return result
      

  def deeploy_prepare_single_plugin_instance(self, inputs):
    """
    Prepare the a single plugin instance for the pipeline creation.
    """
    # 20 chars unique id using self.uuid() (inherited from utils)
    instance_id = inputs.plugin_signature.upper()[:13] + '_' + self.uuid(6)
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

  def check_and_deploy_pipelines(self, sender, inputs, app_id, app_alias, app_type):
    """
    Validate the inputs and deploy the pipeline on the target nodes.
    """
    # Phase 1: Check if nodes are available
    nodes = self.__check_nodes_availability(inputs)

    if len(nodes) == 0:
      msg = f"{DEEPLOY_ERRORS.NODES2}: No valid nodes provided"
      raise ValueError(msg)

    # Phase 2: Launch the pipeline on each node and set CSTORE `response_key`` for the "callback" action
    response_keys = self.__launch_pipeline_on_nodes(nodes, inputs, app_id, app_alias, app_type, sender)

    # Phase 3: Wait until all the responses are received via CSTORE and compose status response
    dct_status, str_status = self.__get_pipeline_responses(response_keys)

    self.P(f"Pipeline responses: str_status = {str_status} | dct_status = {self.json_dumps(dct_status)}")

    # TODO: we must define failure and success conditions (after initial implementation is done)

    return dct_status, str_status