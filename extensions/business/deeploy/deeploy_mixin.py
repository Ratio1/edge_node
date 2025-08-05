from naeural_core.constants import BASE_CT
from naeural_core.main.net_mon import NetMonCt

from extensions.business.deeploy.deeploy_const import DEEPLOY_ERRORS, DEEPLOY_KEYS, \
  DEEPLOY_STATUS, DEEPLOY_PLUGIN_DATA, DEEPLOY_FORBIDDEN_SIGNATURES

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


  def __check_plugin_signature(self, signature: str):
    """
    Check if an app with the requested signature can be run through deeploy.
    """

    if not signature:
      raise ValueError(
        f"{DEEPLOY_ERRORS.REQUEST1}. Signature not provided."
      )

    if signature in DEEPLOY_FORBIDDEN_SIGNATURES:
      raise ValueError(
        f"{DEEPLOY_ERRORS.REQUEST2}. Signature '{signature}' is not allowed."
      )

    return


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


  def __launch_pipeline_on_nodes(self, nodes, inputs, app_id, app_alias, app_type, sender):
    """
    Launch the pipeline on each node and set CSTORE `response_key`` for the "callback" action
    """
    plugins = self.deeploy_prepare_plugins(inputs)
    project_id = inputs.get(DEEPLOY_KEYS.PROJECT_ID, None)
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
            response_key = plugin_instance[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID] + '_' + self.uuid(8)
            plugin_instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = response_key
            response_keys[response_key] = {
              'addr': addr,
              'instance_id': plugin_instance[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID]
            }
          # endif
        # endfor each plugin instance
      # endfor each plugin
  
      msg = ''
      if self.cfg_deeploy_verbose > 1:
        msg = f":\n {self.json_dumps(node_plugins, indent=2)}"
      self.P(f"Starting pipeline '{app_alias}' on {addr}{msg}")
      if addr is not None:
        dct_deeploy_specs = {
          'job_id': inputs.job_id,
          'project_id': project_id,
          'nr_target_nodes': len(nodes),
          'initial_target_nodes': nodes,
        }
        self.cmdapi_start_pipeline_by_params(
          name=app_id,
          app_alias=app_alias,
          pipeline_type=app_type,
          node_address=addr,
          owner=sender, 
          url=inputs.pipeline_input_uri,
          plugins=node_plugins,
          is_deeployed=True,
          deeploy_specs=dct_deeploy_specs,
        )
      # endif addr is valid
    # endfor each target node
    return response_keys

  def __get_pipeline_responses(self, response_keys, timeout_seconds=300):
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
    str_status = DEEPLOY_STATUS.PENDING
    done = False if len(response_keys) > 0 else True
    start_time = self.time()

    if len(response_keys) == 0:
      str_status = DEEPLOY_STATUS.COMMAND_DELIVERED
      return dct_status, str_status

    while not done:
      current_time = self.time()
      if current_time - start_time > timeout_seconds:
        str_status = DEEPLOY_STATUS.TIMEOUT
        self.P(f"Timeout reached ({timeout_seconds} seconds) while waiting for responses. Current status: {self.json_dumps(dct_status, indent=2)}")
        self.P(f"Response keys: {self.json_dumps(response_keys, indent=2)}")
        break
        
      for response_key in response_keys:
        if response_key in dct_status:
          continue
        node_info = response_keys[response_key]
        node_addr = node_info['addr']
        res = self.chainstore_get(response_key)
        if res is not None:
          self.Pd(f"Received response for {response_key} from {node_addr}: {self.json_dumps(res)}. Node Info: {self.json_dumps(node_info)}")
          dct_status[response_key] = {
            'node': node_addr,
            'details': res,
            'instance_id': node_info['instance_id']
          }
      if len(dct_status) == len(response_keys):
        str_status = DEEPLOY_STATUS.SUCCESS
        done = True
      # end for each response key
    # endwhile cycle until all responses are received
    return dct_status, str_status

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
    
    # Create a copy of the request with default values
    request_with_defaults = {
      DEEPLOY_KEYS.TARGET_NODES: 0,
      DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: 'void',
      DEEPLOY_KEYS.PIPELINE_INPUT_URI: None,
      DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
      DEEPLOY_KEYS.APP_PARAMS: {},
      **request
    }
    
    inputs = self.NestedDotDict(request_with_defaults)    
    self.Pd(f"Received request from {sender}{': ' + str(inputs) if DEEPLOY_DEBUG else '.'}")
    
    addr = self.__verify_signature(request)
    if addr.lower() != sender.lower():
      raise ValueError("Invalid signature: recovered {} != {}".format(addr, sender))    
    
    # Check if the sender is allowed to create pipelines
    self.__check_allowed_wallet(inputs)

    # Check request mandatory fields.
    self.__check_plugin_signature(inputs.plugin_signature)
    
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
      

  def deeploy_check_payment_and_job_owner(self, inputs, sender, debug=False):
    """
    Check if the payment is valid for the given job.
    """
    job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
    if not job_id:
      return False
    # Check if the job is paid
    is_valid = False
    try:
      job = self.bc.get_job_details(job_id=job_id)
      if job:
        job_owner = job.get('escrowOwner', None)
        is_valid = (sender == job_owner) if sender and job_owner else False
        if debug:
          self.P(f"Job {job_id} is paid:\n{self.json_dumps(job, indent=2)}")
      else:
        if debug:
          self.P(f"Job {job_id} is not paid or does not exist.")
      # endif
    except Exception as e:
      self.P(f"Error checking payment for job {job_id}: {e}")
      is_valid = False

    return is_valid

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

  def check_and_deploy_pipelines(self, sender, inputs, app_id, app_alias, app_type, nodes):
    """
    Validate the inputs and deploy the pipeline on the target nodes.
    """
    # Phase 1: Check if nodes are available

    if len(nodes) == 0:
      msg = f"{DEEPLOY_ERRORS.NODES2}: No valid nodes provided"
      raise ValueError(msg)

    # Phase 2: Launch the pipeline on each node and set CSTORE `response_key`` for the "callback" action
    response_keys = self.__launch_pipeline_on_nodes(nodes, inputs, app_id, app_alias, app_type, sender)

    # Phase 3: Wait until all the responses are received via CSTORE and compose status response
    dct_status, str_status = self.__get_pipeline_responses(response_keys, 300)

    self.P(f"Pipeline responses: str_status = {str_status} | dct_status =\n {self.json_dumps(dct_status, indent=2)}")
    
    # if pipelines to not use CHAINSTORE_RESPONSE, we can assume nodes reveived the command (BLIND) - to be modified in native plugins
    # else we consider all good if str_status is SUCCESS

    return dct_status, str_status

  def __discover_plugin_instances(
    self,
    app_id: str,
    target_nodes: list[str] = None,
    plugin_signature: str = None,
    instance_id: str = None
  ):
    """
    Discover the plugin instances for the given app_id and target nodes.
    Returns a list of dictionaries containing infomration about plugin instances.
    """
    apps = self._get_online_apps()

    discovered_plugins = []
    for node, pipelines in apps.items():
      if target_nodes is not None and node not in target_nodes:
        continue
      if app_id in pipelines:
        for current_plugin_signature, plugins_instances in pipelines[app_id][NetMonCt.PLUGINS].items():
          # plugins_instances is a list of dictionaries
          for instance_dict in plugins_instances:
            current_instance_id = instance_dict[NetMonCt.PLUGIN_INSTANCE]
            if current_plugin_signature == plugin_signature and current_instance_id == instance_id:
              # If we find a match by signature and instance_id, add it to the list and break.
              discovered_plugins.append({
                DEEPLOY_PLUGIN_DATA.APP_ID : app_id,
                DEEPLOY_PLUGIN_DATA.INSTANCE_ID : current_instance_id,
                DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE : current_plugin_signature,
                DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE : instance_dict,
                DEEPLOY_PLUGIN_DATA.NODE: node
              })
              break
            if plugin_signature is None and instance_id is None:
              # If no specific signature or instance_id is provided, add all instances
              discovered_plugins.append({
                DEEPLOY_PLUGIN_DATA.APP_ID : app_id,
                DEEPLOY_PLUGIN_DATA.INSTANCE_ID : current_instance_id,
                DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE : current_plugin_signature,
                DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE : instance_dict,
                DEEPLOY_PLUGIN_DATA.NODE: node
              })
          # endfor each instance
        # endfor each plugin signature
      # endif app_id found
    # endfor each node
    return discovered_plugins

  def __send_instance_command_to_targets(self, plugins: list[dict], command: str):
    """
    Send a command to the specified nodes for the given plugin instance.
    """
    for plugin in plugins:
      self.cmdapi_send_instance_command(pipeline=plugin[DEEPLOY_PLUGIN_DATA.APP_ID],
                                        signature=plugin[DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE],
                                        instance_id=plugin[DEEPLOY_PLUGIN_DATA.INSTANCE_ID],
                                        instance_command=command,
                                        node_address=plugin[DEEPLOY_PLUGIN_DATA.NODE])

  def send_instance_command_to_nodes(self, inputs):
    """
    Send a command to the specified nodes for the given plugin instance.
    """
    discovered_plugins = self.__discover_plugin_instances(
      app_id=inputs.app_id,
      target_nodes=inputs.target_nodes,
      plugin_signature=inputs.plugin_signature,
      instance_id=inputs.instance_id
    )
    if len(discovered_plugins) == 0:
      raise ValueError(
        f"{DEEPLOY_ERRORS.PLINST1}: Plugin instance {inputs.plugin_signature} with ID {inputs.instance_id} not found in app {inputs.app_id}")

    self.__send_instance_command_to_targets(plugins=discovered_plugins, command=inputs.instance_command)

    return discovered_plugins

  def discover_and_send_pipeline_command(self, inputs):
    """
    Discover the running pipelines by app_id and send the command to each instance.

    Returns:
        dict: A dictionary containing the discovered pipelines,
              where the keys are node addresses and the values are the pipelines.
    """
    discovered_plugins = self.__discover_plugin_instances(app_id=inputs.app_id)

    if len(discovered_plugins) == 0:
      raise ValueError(
        f"{DEEPLOY_ERRORS.APP1}: App {inputs.app_id} not found on any node")

    self.__send_instance_command_to_targets(discovered_plugins, inputs.instance_command)

    return discovered_plugins
