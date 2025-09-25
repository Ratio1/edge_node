from naeural_core.constants import BASE_CT
from naeural_core.main.net_mon import NetMonCt
from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_ERRORS, DEEPLOY_KEYS, \
  DEEPLOY_STATUS, DEEPLOY_PLUGIN_DATA, DEEPLOY_FORBIDDEN_SIGNATURES, CONTAINER_APP_RUNNER_SIGNATURE, DEEPLOY_RESOURCES

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


  def __verify_signature(self, payload, no_hash=True):
    """
    Verify the signature of the request.
    """
    sender = self.bc.eth_verify_payload_signature(
      payload=payload,
      message_prefix=MESSAGE_PREFIX,
      no_hash=no_hash,
      indent=1,
    )
    return sender


  def _check_plugin_signature(self, signature: str):
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

  def __check_is_oracle(self, inputs):
    sender = inputs.get(BASE_CT.BCctbase.ETH_SENDER)
    eth_oracles = self.bc.get_eth_oracles()
    if len(eth_oracles) == 0:
      raise ValueError("No oracles found - this is a critical issue!")
    if not sender in eth_oracles:
      raise ValueError("Sender {} is not an oracle".format(sender))
    return True

  def __create_pipeline_on_nodes(self, nodes, inputs, app_id, app_alias, app_type, sender):
    """
    Create new pipelines on each node and set CSTORE `response_key` for the "callback" action
    """
    plugins = self.deeploy_prepare_plugins(inputs)
    job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
    project_id = inputs.get(DEEPLOY_KEYS.PROJECT_ID, None)
    job_tags = inputs.get(DEEPLOY_KEYS.JOB_TAGS, [])
    project_name = inputs.get(DEEPLOY_KEYS.PROJECT_NAME, None)
    spare_nodes = inputs.get(DEEPLOY_KEYS.SPARE_NODES, [])
    allow_replication_in_the_wild = inputs.get(DEEPLOY_KEYS.ALLOW_REPLICATION_IN_THE_WILD, False)
    response_keys = {}

    ts = self.time()
    dct_deeploy_specs = {
      DEEPLOY_KEYS.JOB_ID: job_id,
      DEEPLOY_KEYS.PROJECT_ID: project_id,
      DEEPLOY_KEYS.PROJECT_NAME: project_name,
      DEEPLOY_KEYS.NR_TARGET_NODES: len(nodes),
      DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
      DEEPLOY_KEYS.JOB_TAGS: job_tags,
      DEEPLOY_KEYS.DATE_CREATED: ts,
      DEEPLOY_KEYS.DATE_UPDATED: ts,
      DEEPLOY_KEYS.SPARE_NODES: spare_nodes,
      DEEPLOY_KEYS.ALLOW_REPLICATION_IN_THE_WILD: allow_replication_in_the_wild,
    }

    for addr in nodes:
      # Nodes to peer with for CHAINSTORE
      nodes_to_peer = nodes
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
      self.P(f"Creating pipeline '{app_alias}' on {addr}{msg}")
      
      if addr is not None:

        pipeline = self.cmdapi_start_pipeline_by_params(
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

        self.Pd(f"Pipeline started: {self.json_dumps(pipeline, indent=2)}")
        try:
          save_result = self.save_job_pipeline_in_cstore(pipeline, job_id)
          self.P(f"Pipeline saved in CSTORE: {save_result}")
        except Exception as e:
          self.P(f"Error saving pipeline in CSTORE: {e}", color="r")
      # endif addr is valid
    # endfor each target node
    return response_keys

  def __prepare_plugins_for_update(self, inputs, discovered_plugin_instances):
    """
    Prepare plugins for update using discovered instances instead of creating new ones
    """
    # Get the base plugin configuration from inputs
    base_plugin = self.deeploy_prepare_single_plugin_instance(inputs)
    
    # Group discovered instances by node and create plugin instances with proper IDs
    instances_by_node = {}
    for instance in discovered_plugin_instances:
      node = instance.get("NODE")
      instance_id = instance.get("instance_id")
      plugin_signature = instance.get("plugin_signature")
      
      if node not in instances_by_node:
        instances_by_node[node] = []
      
      # Create plugin instance config with discovered instance ID
      plugin_instance_config = self.deepcopy(base_plugin[self.ct.CONFIG_PLUGIN.K_INSTANCES][0])
      plugin_instance_config[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID] = instance_id
      
      # Store the prepared instance directly
      instances_by_node[node].append(plugin_instance_config)
    
    return instances_by_node, base_plugin

  def __update_pipeline_on_nodes(self, nodes, inputs, app_id, app_alias, app_type, sender, discovered_plugin_instances=[]):
    """
    Update existing pipelines on each node and set CSTORE `response_key` for the "callback" action
    """
    response_keys = {}
    
    # Prepare plugins for update using discovered instances
    instances_by_node, base_plugin = self.__prepare_plugins_for_update(inputs, discovered_plugin_instances)
    
    # Get all unique nodes from discovered instances
    all_nodes = list(instances_by_node.keys())
    
    for addr in all_nodes:
      node_plugin_instances = instances_by_node[addr]
      
      # Nodes to peer with for CHAINSTORE
      nodes_to_peer = [n for n in all_nodes if n != addr]
      
      # Configure peers and response keys for each plugin instance
      for plugin_instance in node_plugin_instances:
        instance_id = plugin_instance[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID]
        
        # Configure peers if there are any
        if len(nodes_to_peer) > 0:
          plugin_instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_PEERS] = nodes_to_peer
        
        # Configure response keys if needed
        if inputs.chainstore_response:
          response_key = instance_id + '_' + self.uuid(8)
          plugin_instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = response_key
          response_keys[response_key] = {
            'addr': addr,
            'instance_id': instance_id
          }
      
      # Create plugin structure for this node
      node_plugin = {
        self.ct.CONFIG_PLUGIN.K_SIGNATURE: base_plugin[self.ct.CONFIG_PLUGIN.K_SIGNATURE],
        self.ct.CONFIG_PLUGIN.K_INSTANCES: node_plugin_instances
      }
      
      msg = ''
      if self.cfg_deeploy_verbose > 1:
        msg = f":\n {self.json_dumps([node_plugin], indent=2)}"
      self.P(f"Updating pipeline '{app_alias}' on {addr}{msg}")
      
      if addr is not None:
        # Update each plugin instance on this node
        for plugin_instance in node_plugin_instances:
          instance_id = plugin_instance[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID]
          plugin_signature = node_plugin[self.ct.CONFIG_PLUGIN.K_SIGNATURE]
          self.cmdapi_update_instance_config(
            pipeline=app_id,
            signature=plugin_signature,
            instance_id=instance_id,
            instance_config=plugin_instance,
            node_address=addr,
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

    Async job deeploy:

    1. Oracle A receives launch and sends command then responds with command-hash "X"
       setting `async_status=true` so that the API does NOT return immediately.
       Default async_status=true!
       X must be unique and stored in the pipeline definition (maybe the pipeline name or job_id)
    2. UI checks X via Oracle B
    3. Oracle B checks pipeline status (already received via net-config) via netmon AND looks at
       chainstore-response var from plugin instance and will respond False (not ready yet)
    4. UI again checks X via Oracle C
    5. Oracle C checks pipeline status via netmon AND looks at chainstore-response and sees
       correct status (job status updated from CAR/WAR to CStore)
    6. UI shows success

    """
    dct_status = {}
    str_status = DEEPLOY_STATUS.PENDING
    done = False if len(response_keys) > 0 else True
    start_time = self.time()

    self.Pd("Waiting for responses from nodes...")
    self.Pd(f"Response keys to wait for: {self.json_dumps(response_keys, indent=2)}")

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
  
  
  def deeploy_verify_and_get_inputs(self, request: dict, require_sender_is_oracle: bool = False, no_hash: bool = True):
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
    
    addr = self.__verify_signature(request, no_hash=no_hash)
    if addr.lower() != sender.lower():
      raise ValueError("Invalid signature: recovered {} != {}".format(addr, sender))    
    
    # Check if the sender is allowed to create pipelines
    if require_sender_is_oracle:
      self.__check_is_oracle(inputs)
    else:
      self.__check_allowed_wallet(inputs)
    
    return sender, inputs

  def _validate_request_input_for_signature(self, inputs):
    """
    Validate the request input for the given signature.
    This method checks if the input is valid for the given signature.
    """
    # Check if the plugin signature is valid
    if not inputs.plugin_signature or inputs.plugin_signature == "":
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST3}. Plugin signature not provided.")

    if inputs.plugin_signature == CONTAINER_APP_RUNNER_SIGNATURE:
      # Check that image and container resources are
      app_params = inputs.get(DEEPLOY_KEYS.APP_PARAMS, None)
      if not app_params:
        raise ValueError(f"{DEEPLOY_ERRORS.REQUEST4}. App params not provided for plugin signature {inputs.plugin_signature}.")
      if not app_params.get(DEEPLOY_KEYS.APP_PARAMS_IMAGE):
        raise ValueError(f"{DEEPLOY_ERRORS.REQUEST5}. Image not provided for plugin signature {inputs.plugin_signature}.")
      if not app_params.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES):
        raise ValueError(f"{DEEPLOY_ERRORS.REQUEST6}. Container resources not provided for plugin signature {inputs.plugin_signature}.")
      pass
    return

  def _validate_send_app_command_request(self, inputs):
    """
    Validate the request input for sending an app command.
    Checks if all required fields are present and valid.
    """
    app_id = inputs.get(DEEPLOY_KEYS.APP_ID, None)
    job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)

    if not app_id and not job_id:
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST8}. 'app_id' or 'job_id' should be provided.")

    if not inputs.command or inputs.command == "":
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST9}. 'command' not provided.")

    return


  def _validate_send_instance_command_request(self, inputs):
    """
    Validate the request input for sending an instance command.
    Checks if all required fields are present and valid.
    """
    app_id = inputs.get(DEEPLOY_KEYS.APP_ID, None)
    job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)

    if not app_id and not job_id:
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST8}. 'app_id' or 'job_id' should be provided.")

    if not inputs.target_nodes or len(inputs.target_nodes) == 0:
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST8}. 'target_nodes' are not provided.")

    if not inputs.plugin_signature or inputs.plugin_signature == "":
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST7}. 'plugin_signature' not provided.")

    if not inputs.instance_id or inputs.instance_id == "":
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST10}. 'instance_id' not provided.")

    if not inputs.instance_command or inputs.instance_command == "":
      raise ValueError(f"{DEEPLOY_ERRORS.REQUEST9}. 'instance_command' not provided.")

    return


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
    self.Pd(f"Checking payment for job {job_id} by sender {sender}{' (debug mode)' if debug else ''}")
    if not job_id:
      return False
    # Check if the job is paid
    is_valid = False
    try:
      job = self.bc.get_job_details(job_id=job_id)
      self.Pd(f"Job details: {self.json_dumps(job, indent=2)}")
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

  def check_and_deploy_pipelines(self, sender, inputs, app_id, app_alias, app_type, nodes, discovered_plugin_instances=[], is_create=True):
    """
    Validate the inputs and deploy the pipeline on the target nodes.
    """
    # Phase 1: Check if nodes are available

    if len(nodes) == 0:
      msg = f"{DEEPLOY_ERRORS.NODES2}: No valid nodes provided"
      raise ValueError(msg)

    # Phase 2: Launch the pipeline on each node and set CSTORE `response_key`` for the "callback" action
    if is_create:
      response_keys = self.__create_pipeline_on_nodes(nodes, inputs, app_id, app_alias, app_type, sender)
    else:
      response_keys = self.__update_pipeline_on_nodes(nodes, inputs, app_id, app_alias, app_type, sender, discovered_plugin_instances)

    # Phase 3: Wait until all the responses are received via CSTORE and compose status response
    dct_status, str_status = self.__get_pipeline_responses(response_keys, 300)

    self.P(f"Pipeline responses: str_status = {str_status} | dct_status =\n {self.json_dumps(dct_status, indent=2)}")
    
    # if pipelines to not use CHAINSTORE_RESPONSE, we can assume nodes reveived the command (BLIND) - to be modified in native plugins
    # else we consider all good if str_status is SUCCESS

    return dct_status, str_status

  def _discover_plugin_instances(
    self,
    app_id: str = None,
    job_id: str = None,
    target_nodes: list[str] = None,
    owner: str = None,
    plugin_signature: str = None,
    instance_id: str = None
  ):
    """
    Discover the plugin instances for the given app_id and target nodes.
    Returns a list of dictionaries containing infomration about plugin instances.
    """
    apps = self._get_online_apps(owner=owner, target_nodes=target_nodes)

    discovered_plugins = []
    for node, pipelines in apps.items():
      if target_nodes is not None and node not in target_nodes:
        continue
      # search by job_id
      if job_id is not None:
        for current_pipeline_app_id, pipeline in pipelines.items():
          current_pipeline_deeploy_specs = pipeline.get(NetMonCt.DEEPLOY_SPECS, None)
          current_pipeline_job_id = current_pipeline_deeploy_specs.get(DEEPLOY_KEYS.JOB_ID, None) if current_pipeline_deeploy_specs else None
          if not current_pipeline_job_id or current_pipeline_job_id != job_id:
            continue
          for current_plugin_signature, plugins_instances in pipeline[NetMonCt.PLUGINS].items():
            for instance_dict in plugins_instances:
              current_instance_id = instance_dict[NetMonCt.PLUGIN_INSTANCE]
              if current_plugin_signature == plugin_signature and current_instance_id == instance_id:
                # If we find a match by signature and instance_id, add it to the list and break.
                discovered_plugins.append({
                  DEEPLOY_PLUGIN_DATA.APP_ID: current_pipeline_app_id,
                  DEEPLOY_PLUGIN_DATA.INSTANCE_ID: current_instance_id,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: current_plugin_signature,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: instance_dict,
                  DEEPLOY_PLUGIN_DATA.NODE: node
                })
                break
              if instance_id is None and (plugin_signature is None or plugin_signature == current_plugin_signature):
                # If no specific signature or instance_id is provided, add all instances
                discovered_plugins.append({
                  DEEPLOY_PLUGIN_DATA.APP_ID: current_pipeline_app_id,
                  DEEPLOY_PLUGIN_DATA.INSTANCE_ID: current_instance_id,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: current_plugin_signature,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: instance_dict,
                  DEEPLOY_PLUGIN_DATA.NODE: node
                })
        return discovered_plugins
      # search by app_id
      if app_id is not None and app_id in pipelines:
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
            if instance_id is None and (plugin_signature is None or plugin_signature == current_plugin_signature):
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
    self.Pd("Sending instance command to targets...")
    for plugin in plugins:
      self.Pd(self.json_dumps(plugin))
      self.cmdapi_send_instance_command(pipeline=plugin[DEEPLOY_PLUGIN_DATA.APP_ID],
                                        signature=plugin[DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE],
                                        instance_id=plugin[DEEPLOY_PLUGIN_DATA.INSTANCE_ID],
                                        instance_command=command,
                                        node_address=plugin[DEEPLOY_PLUGIN_DATA.NODE])
    return

  def send_instance_command_to_nodes(self, inputs, owner):
    """
    Send a command to the specified nodes for the given plugin instance.
    """
    discovered_plugins = self._discover_plugin_instances(
      app_id=inputs.app_id,
      owner=owner,
      target_nodes=inputs.target_nodes,
      plugin_signature=inputs.plugin_signature,
      instance_id=inputs.instance_id
    )
    if len(discovered_plugins) == 0:
      raise ValueError(
        f"{DEEPLOY_ERRORS.PLINST1}: Plugin instance {inputs.plugin_signature} with ID {inputs.instance_id} not found in app {inputs.app_id} for owner {owner}.")

    self.__send_instance_command_to_targets(plugins=discovered_plugins, command=inputs.instance_command)

    return discovered_plugins


  def discover_and_send_instance_command(self, inputs, owner):
    """
    Discover the running pipelines by app_id and send the command to each instance.

    Returns:
        dict: A dictionary containing the discovered pipelines,
              where the keys are node addresses and the values are the pipelines.
    """
    app_id = inputs.get(DEEPLOY_KEYS.APP_ID, None)
    job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)

    plugin_signature = inputs.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE, None)
    discovered_plugins = self._discover_plugin_instances(
      app_id=app_id,
      job_id=job_id,
      plugin_signature=plugin_signature,
      owner=owner
    )

    if len(discovered_plugins) == 0:
      raise ValueError(
        f"{DEEPLOY_ERRORS.APP1}: App {inputs.app_id} not found on any node")

    self.__send_instance_command_to_targets(discovered_plugins, inputs.command)

    return discovered_plugins
