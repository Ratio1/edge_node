from naeural_core.constants import BASE_CT
from naeural_core.main.net_mon import NetMonCt
from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_ERRORS, DEEPLOY_KEYS, \
  DEEPLOY_STATUS, DEEPLOY_PLUGIN_DATA, DEEPLOY_FORBIDDEN_SIGNATURES, CONTAINER_APP_RUNNER_SIGNATURE, \
  DEEPLOY_RESOURCES, JOB_TYPE_RESOURCE_SPECS, WORKER_APP_RUNNER_SIGNATURE, JOB_APP_TYPES, JOB_APP_TYPES_ALL

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

  def __create_pipeline_on_nodes(self, nodes, inputs, app_id, app_alias, app_type, sender, job_app_type=None):
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
    response_keys = self.defaultdict(list)

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
    detected_job_app_type = job_app_type or self.deeploy_detect_job_app_type(plugins)
    if detected_job_app_type in JOB_APP_TYPES_ALL:
      dct_deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = detected_job_app_type

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
            response_key = self._generate_chainstore_response_key(plugin_instance[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID])
            plugin_instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = response_key
            response_keys[addr].append(response_key)
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

        self.Pd(f"Pipeline started: {self.json_dumps(pipeline)}")
        try:
          save_result = self.save_job_pipeline_in_cstore(pipeline, job_id)
          self.P(f"Pipeline saved in CSTORE: {save_result}")
        except Exception as e:
          self.P(f"Error saving pipeline in CSTORE: {e}", color="r")
      # endif addr is valid
    # endfor each target node
    return response_keys

  def __update_pipeline_on_nodes(self, nodes, inputs, app_id, app_alias, app_type, sender, discovered_plugin_instances, dct_deeploy_specs = None, job_app_type=None):
    """
    Create new pipelines on each node and set CSTORE `response_key` for the "callback" action
    """

    # for plugin_instan
    job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
    project_id = inputs.get(DEEPLOY_KEYS.PROJECT_ID, None)
    job_tags = inputs.get(DEEPLOY_KEYS.JOB_TAGS, [])
    project_name = inputs.get(DEEPLOY_KEYS.PROJECT_NAME, None)
    spare_nodes = inputs.get(DEEPLOY_KEYS.SPARE_NODES, [])
    allow_replication_in_the_wild = inputs.get(DEEPLOY_KEYS.ALLOW_REPLICATION_IN_THE_WILD, False)
    response_keys = self.defaultdict(list)

    ts = self.time()
    detected_job_app_type = job_app_type
    if not detected_job_app_type:
      plugins_for_detection = self.deeploy_prepare_plugins(inputs)
      detected_job_app_type = self.deeploy_detect_job_app_type(plugins_for_detection)

    if not dct_deeploy_specs:
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
    if detected_job_app_type in JOB_APP_TYPES_ALL:
      dct_deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = detected_job_app_type

    nodes = [node for plugin_instance in discovered_plugin_instances if (node := plugin_instance.get("NODE")) is not None]

    pipeline_to_save = None
    for plugin in discovered_plugin_instances:
      addr = plugin.get("NODE")
      plugins = [self.deeploy_prepare_single_plugin_instance_update(inputs=inputs, instance_id=plugin.get("instance_id"))]

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
            response_key = plugin.get(DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY, self._generate_chainstore_response_key(plugin_instance[self.ct.CONFIG_INSTANCE.K_INSTANCE_ID]))
            plugin_instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = response_key
            response_keys[addr].append(response_key)
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

        self.Pd(f"Pipeline started: {self.json_dumps(pipeline)}")
        pipelin_to_save = pipeline
      # endif addr is valid
    # endfor each target node
    try:
      save_result = self.save_job_pipeline_in_cstore(pipelin_to_save, job_id)
      self.P(f"Pipeline saved in CSTORE: {save_result}")
    except Exception as e:
      self.P(f"Error saving pipeline in CSTORE: {e}", color="r")
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

  def _get_pipeline_responses(self, response_keys, timeout_seconds=300):
    """
    Wait until all the responses are received via CSTORE and compose status response.
    Args:
        response_keys (dict): Dictionary mapping response keys to node addresses
                              {"node_addr": [key1, key2, ...], ...}
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
        
      for node_addr, response_keys_list in response_keys.items():
        for response_key in response_keys_list:
          if response_key in dct_status:
            continue
          res = self.chainstore_get(response_key)
          if res is not None:
            self.Pd(
              f"Received response for {response_key} from {node_addr}: {self.json_dumps(res)}. Node Addr: {node_addr}")
            dct_status[response_key] = {
              'node': node_addr,
              'details': res
            }
      total_response_keys = sum(len(keys) for keys in response_keys.values())
      if len(dct_status) == total_response_keys:
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
      DEEPLOY_KEYS.JOB_APP_TYPE: None,
      DEEPLOY_KEYS.PLUGINS: None,
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

  def _validate_plugin_instance_for_signature(self, signature: str, plugin_instance: dict, index: int = None):
    """
    Validate a plugin instance configuration based on its signature.
    Checks if all required fields for the signature are present.

    Args:
        signature (str): Plugin signature
        plugin_instance (dict): Plugin instance configuration
        index (int, optional): Index in array (for error messages)

    Raises:
        ValueError: If required fields are missing
    """
    index_str = f" at index {index}" if index is not None else ""

    # Type-specific validation
    if signature == CONTAINER_APP_RUNNER_SIGNATURE:
      # Check IMAGE field
      if not plugin_instance.get(DEEPLOY_KEYS.APP_PARAMS_IMAGE):
        raise ValueError(
          f"{DEEPLOY_ERRORS.REQUEST5}. Plugin instance{index_str} with signature '{signature}': 'IMAGE' field is required."
        )

      # Check CONTAINER_RESOURCES field
      if not plugin_instance.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES):
        raise ValueError(
          f"{DEEPLOY_ERRORS.REQUEST6}. Plugin instance{index_str} with signature '{signature}': 'CONTAINER_RESOURCES' field is required."
        )

      # Validate CONTAINER_RESOURCES structure
      resources = plugin_instance.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
      if not isinstance(resources, dict):
        raise ValueError(
          f"{DEEPLOY_ERRORS.REQUEST6}. Plugin instance{index_str} with signature '{signature}': 'CONTAINER_RESOURCES' must be a dictionary."
        )

      # Check required resource fields
      if DEEPLOY_RESOURCES.CPU not in resources:
        raise ValueError(
          f"{DEEPLOY_ERRORS.REQUEST6}. Plugin instance{index_str} with signature '{signature}': 'CONTAINER_RESOURCES.cpu' is required."
        )

      if DEEPLOY_RESOURCES.MEMORY not in resources:
        raise ValueError(
          f"{DEEPLOY_ERRORS.REQUEST6}. Plugin instance{index_str} with signature '{signature}': 'CONTAINER_RESOURCES.memory' is required."
        )

    # Add validation for other plugin types here as needed
    # elif signature == "SOME_OTHER_PLUGIN":
    #   ...

    return True

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

  def _normalize_plugins_input(self, request: dict):
    """
    Normalize plugin input to always use the plugins array format.
    Converts legacy single-plugin format (plugin_signature + app_params) to new multi-plugin format.

    Args:
        request (dict): The request dictionary

    Returns:
        dict: Request with normalized plugins array (simple format: each object is a plugin instance)

    Raises:
        ValueError: If neither plugins array nor legacy format is found
    """
    # Check if already using new format (plugins array)
    if DEEPLOY_KEYS.PLUGINS in request and request[DEEPLOY_KEYS.PLUGINS]:
      return request

    # Try to convert from legacy format
    plugin_signature = request.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)
    app_params = request.get(DEEPLOY_KEYS.APP_PARAMS, {})

    if plugin_signature:
      # Convert legacy format to simplified plugins array
      # Each object in array represents ONE plugin instance with its config
      self.Pd(f"Converting legacy plugin format to plugins array for signature: {plugin_signature}")
      request[DEEPLOY_KEYS.PLUGINS] = [
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: plugin_signature,
          **app_params
        }
      ]
      return request

    # If neither format is present, raise error
    raise ValueError(
      f"{DEEPLOY_ERRORS.REQUEST3}. Neither 'plugins' array nor 'plugin_signature' provided."
    )

  def _validate_plugins_array(self, plugins: list):
    """
    Validate the plugins array structure (simplified format).
    Each object in the array represents a single plugin instance with signature + config.

    Args:
        plugins (list): List of plugin instance configurations

    Raises:
        ValueError: If plugins array structure is invalid
    """
    if not isinstance(plugins, list):
      raise ValueError(
        f"{DEEPLOY_ERRORS.PLUGINS1}. 'plugins' must be an array, got {type(plugins).__name__}."
      )

    if len(plugins) == 0:
      raise ValueError(
        f"{DEEPLOY_ERRORS.PLUGINS1}. 'plugins' array cannot be empty."
      )

    for idx, plugin_instance in enumerate(plugins):
      if not isinstance(plugin_instance, dict):
        raise ValueError(
          f"{DEEPLOY_ERRORS.PLUGINS1}. Plugin instance at index {idx} must be a dictionary, got {type(plugin_instance).__name__}."
        )

      # Check required signature field
      signature = plugin_instance.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)
      if not signature:
        raise ValueError(
          f"{DEEPLOY_ERRORS.PLUGINS2}. Plugin instance at index {idx} missing required field 'signature'."
        )

      # Check signature validity (forbidden signatures, etc)
      self._check_plugin_signature(signature)

      # Validate required fields for this specific plugin signature
      self._validate_plugin_instance_for_signature(signature, plugin_instance, index=idx)

    return True


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

  # TODO: FIXME
  def _format_memory_to_standard(self, memory_value):
    """
    Convert memory value to standard format (string with unit).
    Supports: "4096m", "4g", "4096", 4096

    Args:
        memory_value: Memory value as string or int

    Returns:
        str: Standardized memory string (e.g., "4096m")
    """
    if memory_value is None:
      return None

    # If already a string with unit, return as-is
    if isinstance(memory_value, str):
      if memory_value.endswith(('m', 'M', 'g', 'G', 'k', 'K')):
        return memory_value.lower()
      # String number without unit - assume bytes, convert to MB
      try:
        bytes_value = int(memory_value)
        return f"{bytes_value // (1024 * 1024)}m"
      except ValueError:
        return memory_value

    # If integer, assume bytes and convert to MB
    if isinstance(memory_value, int):
      return f"{memory_value // (1024 * 1024)}m"

    return str(memory_value)

  def _parse_memory_to_mb(self, memory_str):
    """
    Parse memory string to megabytes.

    Args:
        memory_str: Memory value like "4096m", "4g", "128m"

    Returns:
        int: Memory in megabytes
    """
    if memory_str is None:
      return 0

    memory_str = str(memory_str).lower().strip()

    # Extract number and unit
    import re
    match = re.match(r'^(\d+(?:\.\d+)?)\s*([kmg]?)$', memory_str)
    if not match:
      # Try to parse as plain number (assume MB)
      try:
        return int(float(memory_str))
      except ValueError:
        return 0

    value = float(match.group(1))
    unit = match.group(2)

    # Convert to MB
    if unit == 'k':
      return int(value / 1024)
    elif unit == 'm' or unit == '':
      return int(value)
    elif unit == 'g':
      return int(value * 1024)

    return 0

  def _aggregate_container_resources(self, inputs):
    """
    Aggregate container resources across all CONTAINER_APP_RUNNER plugin instances.
    Sums CPU and memory requirements for all container instances.

    Args:
        inputs: Request inputs

    Returns:
        dict: Aggregated resources in format:
          {
            "cpu": <total_cpu>,
            "memory": "<total_memory_mb>m"
          }
    """
    plugins_array = inputs.get(DEEPLOY_KEYS.PLUGINS)

    # For legacy format, use existing app_params
    if not plugins_array:
      app_params = inputs.get(DEEPLOY_KEYS.APP_PARAMS, {})
      return app_params.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})

    total_cpu = 0
    total_memory_mb = 0

    # Iterate through plugins array (simplified format - each object is an instance)
    for plugin_instance in plugins_array:
      signature = plugin_instance.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE, "").upper()

      # Only aggregate for CONTAINER_APP_RUNNER plugins
      if signature == CONTAINER_APP_RUNNER_SIGNATURE:
        resources = plugin_instance.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
        cpu = resources.get(DEEPLOY_RESOURCES.CPU, 0)
        memory = resources.get(DEEPLOY_RESOURCES.MEMORY, "0m")

        total_cpu += cpu
        total_memory_mb += self._parse_memory_to_mb(memory)

    # Return aggregated resources in standard format
    return {
      DEEPLOY_RESOURCES.CPU: total_cpu,
      DEEPLOY_RESOURCES.MEMORY: f"{total_memory_mb}m"
    }
  # TODO: END FIXME

  def deeploy_check_payment_and_job_owner(self, inputs, sender, is_create, debug=False):
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
        start_timestamp = job.get('startTimestamp', None)
        is_valid = (sender == job_owner) if sender and job_owner else False
        if is_create and start_timestamp:
          is_valid = False
        if is_valid:
          job_type = job.get('jobType')
          if job_type is None:
            self.P(f"Job type missing or invalid for job {job_id}. Cannot validate resources.")
            msg = (f"{DEEPLOY_ERRORS.JOB_RESOURCES1}: Job type missing or invalid for job {job_id}.")
            raise ValueError(msg)
          #endif
          expected_resources = JOB_TYPE_RESOURCE_SPECS.get(job_type)
          if expected_resources is None:
            self.P(f"No resource specs configured for job type {job_type}. Cannot validate resources.")
            msg = (f"{DEEPLOY_ERRORS.JOB_RESOURCES2}: No resource specs configured for job type {job_type}.")
            raise ValueError(msg)
          #endif
          if expected_resources:
            job_app_type = inputs.get(DEEPLOY_KEYS.JOB_APP_TYPE)
            if isinstance(job_app_type, str):
              job_app_type = job_app_type.lower()
            if not job_app_type:
              try:
                job_app_type = self.deeploy_detect_job_app_type(self.deeploy_prepare_plugins(inputs))
              except Exception:
                job_app_type = None
            if job_app_type == JOB_APP_TYPES.NATIVE:
              # TODO: Re-enable resource validation for native apps once specs are defined.
              self.Pd(f"Skipping resource validation for native job {job_id}.")
            else:
              # Aggregate container resources across all plugins (for multi-plugin support)
              aggregated_resources = self._aggregate_container_resources(inputs)
              requested_cpu = aggregated_resources.get(DEEPLOY_RESOURCES.CPU)
              requested_memory = aggregated_resources.get(DEEPLOY_RESOURCES.MEMORY)
              expected_cpu = expected_resources.get(DEEPLOY_RESOURCES.CPU)
              expected_memory = expected_resources.get(DEEPLOY_RESOURCES.MEMORY)
              #TODO should also check disk and gpu as soon as they are supported and sent in the request
              # Normalize numeric values before comparison
              try:
                requested_cpu_val = None if requested_cpu is None else float(requested_cpu)
              except (TypeError, ValueError):
                requested_cpu_val = None
              try:
                expected_cpu_val = None if expected_cpu is None else float(expected_cpu)
              except (TypeError, ValueError):
                expected_cpu_val = None
              requested_memory_mb = (
                None if requested_memory is None else self._parse_memory_to_mb(requested_memory)
              )
              expected_memory_mb = (
                None if expected_memory is None else self._parse_memory_to_mb(expected_memory)
              )
              resources_match = (
                requested_cpu_val is not None and
                expected_cpu_val is not None and
                requested_memory_mb is not None and
                expected_memory_mb is not None and
                requested_cpu_val == expected_cpu_val and
                requested_memory_mb == expected_memory_mb
              )
              if not resources_match:
                self.P(
                  f"Requested resources {aggregated_resources} do not match paid resources "
                  f"{expected_resources} for job type {job_type}."
                )
                msg = (f"{DEEPLOY_ERRORS.JOB_RESOURCES3}: Requested resources {aggregated_resources} " +
                       f"do not match paid resources {expected_resources} for job type {job_type}.")
                raise ValueError(msg)
              # endif resources match
          # endif expected resources
        # endif is valid
      else: # job not found
        self.P(f"Job {job_id} not found.")
        is_valid = False
      # endif job found
    except Exception as e:
      self.P(f"Error checking payment for job {job_id}: {e}")
      is_valid = False

    return is_valid

  def deeploy_detect_job_app_type(self, pipeline_plugins):
    """
    Detect the job application type based on the pipeline plugins configuration.
    """
    def extract_instance_confs(instances):
      result = []
      if not instances:
        return result
      for instance in instances:
        if not isinstance(instance, dict):
          continue
        instance_conf = instance.get('instance_conf') if isinstance(instance.get('instance_conf'), dict) else instance
        if instance_conf:
          result.append(instance_conf)
      return result

    normalized_plugins = []

    if isinstance(pipeline_plugins, dict):
      for signature, instances in pipeline_plugins.items():
        normalized_plugins.append((signature, extract_instance_confs(instances)))
    elif isinstance(pipeline_plugins, list):
      for plugin in pipeline_plugins:
        if not isinstance(plugin, dict):
          continue
        signature = plugin.get(self.ct.CONFIG_PLUGIN.K_SIGNATURE)
        instances = plugin.get(self.ct.CONFIG_PLUGIN.K_INSTANCES)
        if signature is None:
          signature = plugin.get("SIGNATURE") or plugin.get("signature")
        if instances is None:
          instances = plugin.get("INSTANCES") or plugin.get("instances")
        if signature is None and len(plugin) == 1:
          signature, instances = next(iter(plugin.items()))
        normalized_plugins.append((signature, extract_instance_confs(instances)))

    normalized_plugins = [
      (signature, instances)
      for signature, instances in normalized_plugins
      if signature
    ]

    plugin_count = len(normalized_plugins)
    # if no plugins were found, we define it as native app. (normally, shouldn't happen)
    if plugin_count == 0:
      return JOB_APP_TYPES.NATIVE

    if plugin_count > 1:
      return JOB_APP_TYPES.NATIVE

    signature, instances = normalized_plugins[0]
    normalized_signature = signature.upper() if isinstance(signature, str) else ''

    if normalized_signature == CONTAINER_APP_RUNNER_SIGNATURE:
      service_keywords = ('postgresql', 'postgres', 'mongo', 'mongodb', 'mysql', 'mssql')
      for instance_conf in instances:
        if not isinstance(instance_conf, dict):
          continue
        image_value = (
          instance_conf.get(DEEPLOY_KEYS.APP_PARAMS_IMAGE)
          or instance_conf.get('IMAGE')
          or instance_conf.get('image')
        )
        if image_value and any(keyword in str(image_value).lower() for keyword in service_keywords):
          return JOB_APP_TYPES.SERVICE
      return JOB_APP_TYPES.GENERIC

    if normalized_signature == WORKER_APP_RUNNER_SIGNATURE:
      return JOB_APP_TYPES.GENERIC

    return JOB_APP_TYPES.NATIVE

  def deeploy_prepare_single_plugin_instance(self, inputs):
    """
    Prepare the a single plugin instance for the pipeline creation.
    """
    instance_id = self._generate_plugin_instance_id(signature=inputs.plugin_signature)
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

  def deeploy_prepare_single_plugin_instance_update(self, inputs, instance_id):
    """
    Prepare the a single plugin instance for the pipeline creation.
    """
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

  def _generate_plugin_instance_id(self, signature: str):
    """
    Generate a unique plugin instance ID based on the plugin signature.
    """
    # 20 chars unique id using self.uuid() (inherited from utils)
    instance_id = signature.upper()[:13] + '_' + self.uuid(6)
    return instance_id

  def _generate_chainstore_response_key(self, instance_id: str):
    """
    Generate a unique chainstore response key based on the plugin instance ID.
    """
    response_key = instance_id + '_' + self.uuid(8)
    return response_key

  def deeploy_prepare_plugins(self, inputs):
    """
    Prepare the plugins for the pipeline creation.
    Converts simplified plugins array format to node-expected format with grouped instances.

    Args:
        inputs: Request inputs containing plugins array (simplified format) or legacy plugin_signature

    Input Format (simplified):
        plugins: [
          {"signature": "PLUGIN_A", "param1": "val1"},
          {"signature": "PLUGIN_B", "param2": "val2"},
          {"signature": "PLUGIN_A", "param1": "val3"}  # another instance
        ]

    Returns:
        list: List of prepared plugins in node format:
          [
            {
              "SIGNATURE": "PLUGIN_A",
              "INSTANCES": [
                {"INSTANCE_ID": "PLUGIN_A_abc123", "param1": "val1"},
                {"INSTANCE_ID": "PLUGIN_A_def456", "param1": "val3"}
              ]
            },
            {
              "SIGNATURE": "PLUGIN_B",
              "INSTANCES": [
                {"INSTANCE_ID": "PLUGIN_B_xyz789", "param2": "val2"}
              ]
            }
          ]
    """
    # Check if using new plugins array format
    plugins_array = inputs.get(DEEPLOY_KEYS.PLUGINS)

    if plugins_array and isinstance(plugins_array, list):
      # Group plugin instances by signature
      plugins_by_signature = {}

      for plugin_instance in plugins_array:
        signature = plugin_instance.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)

        # Extract instance config (everything except 'signature')
        instance_config = {k: v for k, v in plugin_instance.items()
                          if k != DEEPLOY_KEYS.PLUGIN_SIGNATURE}

        # Generate unique instance_id
        instance_id = self._generate_plugin_instance_id(signature=signature)

        # Prepare instance with INSTANCE_ID
        prepared_instance = {
          self.ct.CONFIG_INSTANCE.K_INSTANCE_ID: instance_id,
          **instance_config
        }

        # Group by signature
        if signature not in plugins_by_signature:
          plugins_by_signature[signature] = []
        plugins_by_signature[signature].append(prepared_instance)

      # Convert grouped dict to list format
      prepared_plugins = []
      for signature, instances in plugins_by_signature.items():
        prepared_plugin = {
          self.ct.CONFIG_PLUGIN.K_SIGNATURE: signature,
          self.ct.CONFIG_PLUGIN.K_INSTANCES: instances
        }
        prepared_plugins.append(prepared_plugin)

      return prepared_plugins

    # Legacy single-plugin format - use existing method
    plugin = self.deeploy_prepare_single_plugin_instance(inputs)
    plugins = [plugin]
    return plugins

  def check_and_deploy_pipelines(self, sender, inputs, app_id, app_alias, app_type, update_nodes, new_nodes, discovered_plugin_instances=[], dct_deeploy_specs=None, job_app_type=None):
    """
    Validate the inputs and deploy the pipeline on the target nodes.
    """
    # Phase 1: Check if nodes are available

    if len(update_nodes) == 0 and len(new_nodes) == 0:
      msg = f"{DEEPLOY_ERRORS.NODES2}: No valid nodes provided"
      raise ValueError(msg)

    # Phase 2: Launch the pipeline on each node and set CSTORE `response_key`` for the "callback" action
    response_keys = {}
    if len(update_nodes) > 0:
      update_response_keys = self.__update_pipeline_on_nodes(update_nodes, inputs, app_id, app_alias, app_type, sender, discovered_plugin_instances, dct_deeploy_specs, job_app_type=job_app_type)
      response_keys.update(update_response_keys)
    if len(new_nodes) > 0:
      new_response_keys = self.__create_pipeline_on_nodes(new_nodes, inputs, app_id, app_alias, app_type, sender, job_app_type=job_app_type)
      response_keys.update(new_response_keys)

    # Phase 3: Wait until all the responses are received via CSTORE and compose status response
    dct_status, str_status = self._get_pipeline_responses(response_keys, 300)

    self.P(f"Pipeline responses: str_status = {str_status} | dct_status =\n {self.json_dumps(dct_status, indent=2)}")
    
    # if pipelines to not use CHAINSTORE_RESPONSE, we can assume nodes reveived the command (BLIND) - to be modified in native plugins
    # else we consider all good if str_status is SUCCESS

    return dct_status, str_status

  def scale_up_job(self, new_nodes, update_nodes, job_id, sender, running_apps_for_job):
    """
    Scale up the job workers.
    """

    # todo: get pipeline from R1FS.
    # Prepare updated app pipeline
    base_pipeline = self.get_job_base_pipeline_from_apps(running_apps_for_job)
    create_pipelines, update_pipelines, chainstore_response_keys = (
      self.prepare_create_update_pipelines(base_pipeline,
                                            new_nodes,
                                            update_nodes,
                                            running_apps_for_job))

    self.P(f"Prepared create pipelines: {self.json_dumps(create_pipelines)}")
    self.P(f"Prepared update pipelines: {self.json_dumps(update_pipelines)}")
    self.P(f"Prepared chainstore response keys: {self.json_dumps(chainstore_response_keys)}")

    # RESET chainstore_response_keys here
    try:
      self.P(f"Resetting chainstore keys: {self.json_dumps(chainstore_response_keys)}")
      for node_addr, response_keys in chainstore_response_keys.items():
        for response_key in response_keys:
          self.chainstore_set(response_key, None)
    except Exception as e:
      self.P(f"Error resetting chainstore keys: {e}", color='r')

    # Start pipelines on nodes.
    self._start_create_update_pipelines(create_pipelines=create_pipelines,
                                        update_pipelines=update_pipelines,
                                        sender=sender)

    dct_status, str_status = self._get_pipeline_responses(chainstore_response_keys, 300)

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
      iter_plugins = []
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
              chainstore_key = instance_dict['instance_conf'].get(self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY, None)
              if current_plugin_signature == plugin_signature and current_instance_id == instance_id:
                # If we find a match by signature and instance_id, add it to the list and break.
                iter_plugins.append({
                  DEEPLOY_PLUGIN_DATA.APP_ID: current_pipeline_app_id,
                  DEEPLOY_PLUGIN_DATA.INSTANCE_ID: current_instance_id,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: current_plugin_signature,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: instance_dict,
                  DEEPLOY_PLUGIN_DATA.NODE: node,
                  DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: chainstore_key,
                })
                break
              if instance_id is None and (plugin_signature is None or plugin_signature == current_plugin_signature):
                # If no specific signature or instance_id is provided, add all instances
                iter_plugins.append({
                  DEEPLOY_PLUGIN_DATA.APP_ID: current_pipeline_app_id,
                  DEEPLOY_PLUGIN_DATA.INSTANCE_ID: current_instance_id,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: current_plugin_signature,
                  DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: instance_dict,
                  DEEPLOY_PLUGIN_DATA.NODE: node,
                  DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: chainstore_key,
                })
      # search by app_id
      if len(iter_plugins) > 0:
        discovered_plugins.extend(iter_plugins)
        continue
      if app_id is not None and app_id in pipelines:
        for current_plugin_signature, plugins_instances in pipelines[app_id][NetMonCt.PLUGINS].items():
          # plugins_instances is a list of dictionaries
          for instance_dict in plugins_instances:
            current_instance_id = instance_dict[NetMonCt.PLUGIN_INSTANCE]
            chainstore_key = instance_dict['instance_conf'].get(self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY, None)
            if current_plugin_signature == plugin_signature and current_instance_id == instance_id:
              # If we find a match by signature and instance_id, add it to the list and break.
              iter_plugins.append({
                DEEPLOY_PLUGIN_DATA.APP_ID : app_id,
                DEEPLOY_PLUGIN_DATA.INSTANCE_ID : current_instance_id,
                DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE : current_plugin_signature,
                DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE : instance_dict,
                DEEPLOY_PLUGIN_DATA.NODE: node,
                DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: chainstore_key,
              })
              break
            if instance_id is None and (plugin_signature is None or plugin_signature == current_plugin_signature):
              # If no specific signature or instance_id is provided, add all instances
              iter_plugins.append({
                DEEPLOY_PLUGIN_DATA.APP_ID : app_id,
                DEEPLOY_PLUGIN_DATA.INSTANCE_ID : current_instance_id,
                DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE : current_plugin_signature,
                DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE : instance_dict,
                DEEPLOY_PLUGIN_DATA.NODE: node,
                DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: chainstore_key,
              })
          # endfor each instance
        # endfor each plugin signature
      # endif app_id found
      discovered_plugins.extend(iter_plugins)

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

  def get_job_base_pipeline_from_apps(self, apps):
    """
    Get the base pipeline from the apps.
    - pipeline only for one node has to be processed
    1. Get one pipeline from the apps.
    2. get deeploy_data from pipeline
    3. get plugins
    
    input apps will look like this:
    {
    "0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g": {
      "xxxxxxxxxxxxx_330037f": {
        "initiator": "0xai_AzMjCS6GuOV8Q3O-XvQfkvy9J-9F20M_yCGDzLFOd4mn",
        "owner": "0x311a63B88df90f19cd9bD7D9000B70480d842472",
        "last_config": "2025-09-29 14:51:43.458917",
        "is_deeployed": true,
        "deeploy_specs": {
          "allow_replication_in_the_wild": false,
          "current_target_nodes": [
            "0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"
          ],
          "date_created": 1759157077.267864,
          "date_updated": 1759157077.267864,
          "job_id": 66,
          "job_tags": [],
          "nr_target_nodes": 1,
          "project_id": null,
          "project_name": null,
          "spare_nodes": []
        },
        "plugins": {
          "CONTAINER_APP_RUNNER": [
            {
              "instance": "CONTAINER_APP_77eeea",
              "start": "2025-09-29 14:44:37.844865",
              "last_alive": "2025-09-29 15:04:31.459053",
              "last_error": null,
              "instance_conf": {
                "CHAINSTORE_PEERS": [
                  "0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"
                ],
                "CHAINSTORE_RESPONSE_KEY": "CONTAINER_APP_77eeea_c56bd384",
                "CLOUDFLARE_TOKEN": "",
                "CONTAINER_RESOURCES": {
                  "cpu": 1,
                  "memory": "128m"
                },
                "CR": "docker.io",
                "IMAGE": "tvitalii/ratio1-drive",
                "IMAGE_PULL_POLICY": "always",
                "INSTANCE_ID": "CONTAINER_APP_77eeea",
                "NGROK_USE_API": true,
                "PORT": 3333,
                "RESTART_POLICY": "always",
                "TUNNEL_ENGINE": "cloudflare"
              }
            }
          ]
        }
      }
    }
  }
    
    Returns:
    dict: The base pipeline
    app_id: The app_id of the base pipeline
    deeploy_specs: The deeploy specs of the base pipeline
    plugins: The plugins that run on that pipeline pipeline
      plugins will have the next structure:
       [
        {
          "INSTANCES":[
            {
              "CHAINSTORE_PEERS":[
                "0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"
              ],
              "CHAINSTORE_RESPONSE_KEY":"CONTAINER_APP_bc367a_09e1f1e1",
              "CLOUDFLARE_TOKEN":"",
              "CONTAINER_RESOURCES":{
                "cpu":1,
                "memory":"128m"
              },
              "CR":"docker.io",
              "IMAGE":"tvitalii/ratio1-drive",
              "IMAGE_PULL_POLICY":"always",
              "INSTANCE_ID":"CONTAINER_APP_bc367a",
              "NGROK_USE_API":true,
              "PORT":3333,
              "RESTART_POLICY":"always",
              "TUNNEL_ENGINE":"cloudflare"
            }
          ],
          "SIGNATURE":"CONTAINER_APP_RUNNER"
        }
      ]
    """
    
    if not apps or len(apps) == 0:
      return {}
    
    # 1. Get one pipeline from the apps (get the first node and first app)
    first_node = next(iter(apps.keys()))
    node_pipelines = apps[first_node]
    
    if not node_pipelines or len(node_pipelines) == 0:
      return {}
    
    first_app_id = next(iter(node_pipelines.keys()))
    base_pipeline = node_pipelines[first_app_id]
    
    # 2. Get deeploy_specs from pipeline
    deeploy_specs = base_pipeline.get(NetMonCt.DEEPLOY_SPECS, {})
    
    # 3. Get plugins and transform them to the expected structure
    plugins_data = base_pipeline.get(NetMonCt.PLUGINS, {})
    if isinstance(deeploy_specs, dict):
      current_job_app_type = deeploy_specs.get(DEEPLOY_KEYS.JOB_APP_TYPE)
      if not current_job_app_type:
        detected_job_app_type = self.deeploy_detect_job_app_type(plugins_data)
        if detected_job_app_type in JOB_APP_TYPES_ALL:
          deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = detected_job_app_type
    transformed_plugins = []
    
    for plugin_signature, plugin_instances in plugins_data.items():
      plugin_instances_list = []
      
      for instance_data in plugin_instances:
        # Get the instance configuration and filter out runtime fields
        instance_conf = instance_data.get(NetMonCt.INSTANCE_CONF, {})
        
        # Remove runtime fields that shouldn't be in the output
        filtered_instance_conf = {k: v for k, v in instance_conf.items() 
                                 if k not in [NetMonCt.PLUGIN_INSTANCE, NetMonCt.PLUGIN_START, 
                                             NetMonCt.PLUGIN_LAST_ALIVE, NetMonCt.PLUGIN_LAST_ERROR]}
        
        plugin_instances_list.append(filtered_instance_conf)
      
      # Create the plugin structure with SIGNATURE and INSTANCES
      # todo: use constants
      transformed_plugin = {
        "SIGNATURE": plugin_signature,
        "INSTANCES": plugin_instances_list
      }
      transformed_plugins.append(transformed_plugin)

    # todo: use constants
    return {
      "base_pipeline": base_pipeline,
      "app_id": first_app_id,
      "deeploy_specs": deeploy_specs,
      "plugins": transformed_plugins,
      "pipeline_type": base_pipeline.get("TYPE", "void"),
      "url": base_pipeline.get("URL", None)
    }

  def prepare_create_update_pipelines(self, base_pipeline, new_nodes, update_nodes, running_apps_for_job):
    """
    Prepare the create and update pipelines.
    Running Apps for job example:
    {"0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g":{"xxxxxxxxxxxxx_74524a2":{"deeploy_specs":{"allow_replication_in_the_wild":false,"current_target_nodes":["0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"],"date_created":1759258054.05717,"date_updated":1759258054.05717,"job_id":66,"job_tags":[],"nr_target_nodes":1,"project_id":null,"project_name":null,"spare_nodes":[]},"initiator":"0xai_AzMjCS6GuOV8Q3O-XvQfkvy9J-9F20M_yCGDzLFOd4mn","is_deeployed":true,"last_config":"2025-09-30 21:17:50.119197","owner":"0x311a63B88df90f19cd9bD7D9000B70480d842472","plugins":{"CONTAINER_APP_RUNNER":[{"instance":"CONTAINER_APP_52d2c8","instance_conf":{"CHAINSTORE_PEERS":["0xai_A5UKxpSizb-O-4nE23vog8ioR-kQy64W3iePncYo4Jfc","0xai_Avvuy6USRwVfbbxEG2HPiCz85mSJle3zo2MbDh5kBD-g"],"CHAINSTORE_RESPONSE_KEY":"CONTAINER_APP_52d2c8_4280c161","CLOUDFLARE_TOKEN":"some-test-token","CONTAINER_RESOURCES":{"cpu":1,"memory":"128m"},"CR":"docker.io","ENV":{"env3":3,"env4":4,"upd":"ok1","var1":2222222},"IMAGE":"tvitalii/ratio1-drive","IMAGE_PULL_POLICY":"always","INSTANCE_ID":"CONTAINER_APP_52d2c8","NGROK_USE_API":true,"PORT":3333,"RESTART_POLICY":"always","TUNNEL_ENGINE":"cloudflare"},"last_alive":null,"last_error":null,"start":"2025-09-30 21:53:01.643950"}]}}}}
    """
    self.Pd("Preparing create and update pipelines...")
    self.Pd(f"Base pipeline: {self.json_dumps(base_pipeline)}")
    self.Pd(f"New nodes {type(new_nodes)}: {self.json_dumps(new_nodes)}")
    self.Pd(f"Update nodes{type(update_nodes)}: {self.json_dumps(update_nodes)}")

    chainstore_peers = list(set(new_nodes + update_nodes))
    deeploy_specs = self.deepcopy(base_pipeline[NetMonCt.DEEPLOY_SPECS])
    job_app_type = None
    if isinstance(deeploy_specs, dict):
      job_app_type = deeploy_specs.get(DEEPLOY_KEYS.JOB_APP_TYPE)
      if not job_app_type:
        job_app_type = self.deeploy_detect_job_app_type(base_pipeline.get(NetMonCt.PLUGINS, []))
        if job_app_type in JOB_APP_TYPES_ALL:
          deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = job_app_type
    deeploy_specs[DEEPLOY_KEYS.CURRENT_TARGET_NODES] = chainstore_peers
    deeploy_specs[DEEPLOY_KEYS.DATE_UPDATED] = self.time()

    chainstore_response_keys = self.defaultdict(list)

    # prepare create pipelines:
    create_pipelines = {}
    for node in new_nodes:
      create_pipelines[node] = self.deepcopy(base_pipeline)
      for plugin in create_pipelines[node][NetMonCt.PLUGINS]:
        plugin_signature = plugin["SIGNATURE"]
        plugin_instances = plugin["INSTANCES"]
        for instance in plugin_instances:
          instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_PEERS] = chainstore_peers
          instance_id = self._generate_plugin_instance_id(signature=plugin_signature)
          chainstore_response_key = self._generate_chainstore_response_key(
            instance_id=instance_id)
          instance[self.ct.BIZ_PLUGIN_DATA.INSTANCE_ID] = instance_id
          instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = chainstore_response_key
          chainstore_response_keys[node].append(chainstore_response_key)

    # prepare update pipelines:
    update_pipelines = {}
    for node in update_nodes:
      if node in running_apps_for_job:
        # Get the first app from running_apps_for_job for this node
        node_apps = running_apps_for_job[node]
        app_id = list(node_apps.keys())[0]  # Get the first app_id
        app_data = node_apps[app_id]
        plugins = app_data.get("plugins", {})
        
        update_pipelines[node] = self.deepcopy(base_pipeline)
        for plugin in update_pipelines[node][NetMonCt.PLUGINS]:
          plugin_signature = plugin["SIGNATURE"]
          plugin_instances = plugin["INSTANCES"]
          
          # Get the corresponding plugin instances from running_apps_for_job
          running_plugin_instances = plugins.get(plugin_signature, [])
          
          for i, instance in enumerate(plugin_instances):
            instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_PEERS] = chainstore_peers
            
            # Use instance data from running_apps_for_job if available
            if i < len(running_plugin_instances):
              running_instance = running_plugin_instances[i]
              instance_id = running_instance.get("instance", "")
              instance_conf = running_instance.get("instance_conf", {})
              
              # Use existing instance_id and chainstore_response_key from running app
              instance[self.ct.BIZ_PLUGIN_DATA.INSTANCE_ID] = instance_id
              chainstore_response_key = instance_conf.get(self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY, "")
              
              if not chainstore_response_key or chainstore_response_key == "":
                chainstore_response_key = self._generate_chainstore_response_key(instance_id=instance_id)
                instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = chainstore_response_key
              else:
                instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = chainstore_response_key
            else:
              # Fallback: generate new instance_id if no running instance found
              instance_id = self._generate_plugin_instance_id(signature=plugin_signature)
              chainstore_response_key = self._generate_chainstore_response_key(instance_id=instance_id)
              instance[self.ct.BIZ_PLUGIN_DATA.INSTANCE_ID] = instance_id
              instance[self.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = chainstore_response_key
            
            chainstore_response_keys[node].append(chainstore_response_key)

    return create_pipelines, update_pipelines, chainstore_response_keys

  def _start_create_update_pipelines(self, create_pipelines, update_pipelines, sender):
    """
    Start the create and update pipelines.
    """
    for node, pipeline in create_pipelines.items():
      self.cmdapi_start_pipeline_by_params(
        name=pipeline['app_id'],
        pipeline_type=pipeline['pipeline_type'],
        node_address=node,
        owner=sender, 
        url=pipeline['url'],
        plugins=pipeline['plugins'],
        is_deeployed=True,
        deeploy_specs=pipeline['deeploy_specs'],
      )    
    for node, pipeline in update_pipelines.items():
      # For update pipelines, we need to iterate through the plugins and instances
      for plugin in pipeline['plugins']:
        plugin_signature = plugin['SIGNATURE']
        for instance in plugin['INSTANCES']:
          self.cmdapi_update_instance_config(
            pipeline=pipeline['app_id'],
            signature=plugin_signature,
            instance_id=instance['INSTANCE_ID'],
            instance_config=instance,
            node_address=node,
          )
    return

  def _submit_bc_job_confirmation(self, str_status, dct_status, nodes, job_id, is_confirmable_job):
    """
    Submit the BC job confirmation.

    Args:
        str_status (str): The status of the job.
        dct_status (dict): The status details of the job.
        nodes (list): The nodes that are being confirmed.
        job_id (int): The ID of the job.
        is_confirmable_job (bool): Whether the job is confirmable.

    Returns:
        _type_: _description_
    """
    try:
      if str_status in [DEEPLOY_STATUS.SUCCESS, DEEPLOY_STATUS.COMMAND_DELIVERED]:
        if (dct_status is not None and is_confirmable_job and len(nodes) == len(dct_status)) or not is_confirmable_job:
          eth_nodes = [self.bc.node_addr_to_eth_addr(node) for node in nodes]
          eth_nodes = sorted(eth_nodes)
          self.bc.submit_node_update(
            job_id=job_id,
            nodes=eth_nodes,
          )
        #endif
      #endif
    except Exception as e:
      self.P(f"Error submitting BC job confirmation: {e}")
      return False
    return True

  def check_running_pipelines_and_add_to_r1fs(self):
    self.P(f"Checking running pipelines and adding them to R1FS...")
    running_pipelines = self.netmon.network_known_pipelines()
    listed_job_ids = self.list_all_deployed_jobs_from_cstore()
    netmon_job_ids = {}
    for node, pipelines in running_pipelines.items():
      for pipeline in pipelines:
        deeploy_specs = pipeline.get(ct.CONFIG_STREAM.DEEPLOY_SPECS, None)
        if deeploy_specs:
          job_id = deeploy_specs.get(DEEPLOY_KEYS.JOB_ID, None)
          if job_id in netmon_job_ids or not job_id:
            continue
          netmon_job_ids[job_id] = pipeline
    for netmon_job_id, pipeline in netmon_job_ids.items():
      listed_job_cid = listed_job_ids.get(str(netmon_job_id), None)
      if listed_job_cid and len(listed_job_cid)  == 46:
        continue
      self.save_job_pipeline_in_cstore(pipeline, netmon_job_id)
    
    return netmon_job_ids
  
  def delete_pipeline_from_nodes(self, app_id=None, job_id=None, owner=None):
    discovered_instances = self._discover_plugin_instances(app_id=app_id, job_id=job_id, owner=owner)

    if len(discovered_instances) == 0:
      msg = f"{DEEPLOY_ERRORS.NODES3}: No instances found for provided "
      msg += f"{f'app_id {app_id}' if app_id else f'job_id {job_id}'} and owner '{owner}'."
      raise ValueError(msg)
    #endif
    for instance in discovered_instances:
      self.P(f"Stopping pipeline '{instance[DEEPLOY_PLUGIN_DATA.APP_ID]}' on {instance[DEEPLOY_PLUGIN_DATA.NODE]}")
      self.cmdapi_stop_pipeline(
        node_address=instance[DEEPLOY_PLUGIN_DATA.NODE],
        name=instance[DEEPLOY_PLUGIN_DATA.APP_ID],
      )
    #endfor each target node
    return discovered_instances

  def _get_online_apps(self, owner=None, target_nodes=None, job_id=None):
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
    result = self.netmon.network_known_apps(target_nodes=target_nodes)
    
    # Count nodes and app instances
    node_count = len(result)
    total_pipelines = 0
    
    for node, pipelines in result.items():
      total_pipelines += len(pipelines)
    
    self.Pd(f"Found {node_count} nodes with a total of {total_pipelines} pipelines")
    if owner is not None:
      filtered_result = self.defaultdict(dict)
      for node, apps in result.items():
        for app_name, app_data in apps.items():
          if app_data[NetMonCt.OWNER] != owner:
            continue
          filtered_result[node][app_name] = app_data
      result = filtered_result
    if job_id is not None:
      filtered_result = self.defaultdict(dict)
      for node, apps in result.items():
        for app_name, app_data in apps.items():
          if app_data.get(NetMonCt.DEEPLOY_SPECS, {}).get(DEEPLOY_KEYS.JOB_ID, None) != job_id:
            continue
          filtered_result[node][app_name] = app_data
      result = filtered_result
    return result
