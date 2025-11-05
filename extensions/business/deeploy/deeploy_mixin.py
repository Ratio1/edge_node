from naeural_core.constants import BASE_CT
from naeural_core.main.net_mon import NetMonCt
from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_ERRORS, DEEPLOY_KEYS, \
  DEEPLOY_STATUS, DEEPLOY_PLUGIN_DATA, DEEPLOY_FORBIDDEN_SIGNATURES, CONTAINER_APP_RUNNER_SIGNATURE, \
  DEEPLOY_RESOURCES, JOB_TYPE_RESOURCE_SPECS, WORKER_APP_RUNNER_SIGNATURE, JOB_APP_TYPES, JOB_APP_TYPES_ALL, \
  CONTAINERIZED_APPS_SIGNATURES

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

  def __create_pipeline_on_nodes(self, nodes, inputs, app_id, app_alias, app_type, sender, job_app_type=None, dct_deeploy_specs=None):
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
    pipeline_params = self._extract_pipeline_params(inputs)
    pipeline_kwargs = self._prepare_pipeline_param_kwargs(
      pipeline_params,
      reserved_keys={"app_alias", "owner", "is_deeployed", "deeploy_specs"},
    )
    ts = self.time()
    if dct_deeploy_specs:
      dct_deeploy_specs = self.deepcopy(dct_deeploy_specs)
      dct_deeploy_specs[DEEPLOY_KEYS.DATE_UPDATED] = ts
      if DEEPLOY_KEYS.DATE_CREATED not in dct_deeploy_specs:
        dct_deeploy_specs[DEEPLOY_KEYS.DATE_CREATED] = ts
    else:
      dct_deeploy_specs = {
        DEEPLOY_KEYS.NR_TARGET_NODES: len(nodes),
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
        DEEPLOY_KEYS.JOB_TAGS: job_tags,
        DEEPLOY_KEYS.DATE_CREATED: ts,
        DEEPLOY_KEYS.DATE_UPDATED: ts,
        DEEPLOY_KEYS.SPARE_NODES: spare_nodes,
        DEEPLOY_KEYS.ALLOW_REPLICATION_IN_THE_WILD: allow_replication_in_the_wild,
      }

    if job_id is not None or DEEPLOY_KEYS.JOB_ID not in dct_deeploy_specs:
      dct_deeploy_specs[DEEPLOY_KEYS.JOB_ID] = job_id
    if project_id is not None or DEEPLOY_KEYS.PROJECT_ID not in dct_deeploy_specs:
      dct_deeploy_specs[DEEPLOY_KEYS.PROJECT_ID] = project_id
    if project_name is not None or DEEPLOY_KEYS.PROJECT_NAME not in dct_deeploy_specs:
      dct_deeploy_specs[DEEPLOY_KEYS.PROJECT_NAME] = project_name
    dct_deeploy_specs[DEEPLOY_KEYS.NR_TARGET_NODES] = len(nodes)
    dct_deeploy_specs[DEEPLOY_KEYS.CURRENT_TARGET_NODES] = nodes
    dct_deeploy_specs[DEEPLOY_KEYS.JOB_TAGS] = job_tags
    dct_deeploy_specs[DEEPLOY_KEYS.SPARE_NODES] = spare_nodes
    dct_deeploy_specs[DEEPLOY_KEYS.ALLOW_REPLICATION_IN_THE_WILD] = allow_replication_in_the_wild
    dct_deeploy_specs = self._ensure_deeploy_specs_job_config(
      dct_deeploy_specs,
      pipeline_params=pipeline_params,
    )

    detected_job_app_type = job_app_type or self.deeploy_detect_job_app_type(plugins)
    if detected_job_app_type in JOB_APP_TYPES_ALL:
      dct_deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = detected_job_app_type

    node_plugins_by_addr = {}
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
  
      node_plugins_by_addr[addr] = node_plugins

    prepared_response_keys = self._normalize_chainstore_response_mapping(response_keys)
    merged_chainstore_map = self._normalize_chainstore_response_mapping(
      dct_deeploy_specs.get(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, {})
    )
    if inputs.chainstore_response:
      merged_chainstore_map = self._merge_chainstore_response_keys(
        merged_chainstore_map,
        prepared_response_keys,
      )
      if merged_chainstore_map:
        dct_deeploy_specs[DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS] = self.deepcopy(merged_chainstore_map)
      else:
        dct_deeploy_specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)
    else:
      merged_chainstore_map = {}
      dct_deeploy_specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)

    for addr, node_plugins in node_plugins_by_addr.items():
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
          deeploy_specs=self.deepcopy(dct_deeploy_specs),
          **pipeline_kwargs,
        )

        self.Pd(f"Pipeline started: {self.json_dumps(pipeline)}")
        try:
          save_result = self.save_job_pipeline_in_cstore(pipeline, job_id)
          self.P(f"Pipeline saved in CSTORE: {save_result}")
        except Exception as e:
          self.P(f"Error saving pipeline in CSTORE: {e}", color="r")
      # endif addr is valid
    # endfor each target node

    cleaned_response_keys = prepared_response_keys if inputs.chainstore_response else {}
    return cleaned_response_keys

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
    pipeline_params = self._extract_pipeline_params(inputs)
    pipeline_kwargs = self._prepare_pipeline_param_kwargs(
      pipeline_params,
      reserved_keys={"app_alias", "owner", "is_deeployed", "deeploy_specs"},
    )
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
    else:
      dct_deeploy_specs = self.deepcopy(dct_deeploy_specs)
      dct_deeploy_specs[DEEPLOY_KEYS.DATE_UPDATED] = ts
      if DEEPLOY_KEYS.DATE_CREATED not in dct_deeploy_specs:
        dct_deeploy_specs[DEEPLOY_KEYS.DATE_CREATED] = ts
    if detected_job_app_type in JOB_APP_TYPES_ALL:
      dct_deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = detected_job_app_type
    dct_deeploy_specs = self._ensure_deeploy_specs_job_config(
      dct_deeploy_specs,
      pipeline_params=pipeline_params,
    )

    requested_by_instance_id, requested_by_signature, new_plugin_configs = self._organize_requested_plugins(inputs)

    nodes = []
    plugins_by_node = self.defaultdict(list)
    for plugin in discovered_plugin_instances:
      addr = plugin.get(DEEPLOY_PLUGIN_DATA.NODE)
      if not addr:
        continue

      if addr not in nodes:
        nodes.append(addr)

      signature = plugin.get(DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE)
      normalized_signature = signature.upper() if isinstance(signature, str) else signature

      instance_id = plugin.get(DEEPLOY_PLUGIN_DATA.INSTANCE_ID)
      plugin_config = None

      if instance_id:
        plugin_config = requested_by_instance_id.pop(instance_id, None)
        candidate_list = requested_by_signature.get(normalized_signature, [])
        if plugin_config and candidate_list:
          # Safe to modify list during iteration here because we break immediately after pop
          # This avoids the typical issue of modifying a list while iterating over it
          for idx, candidate in enumerate(candidate_list):
            if candidate is plugin_config:
              candidate_list.pop(idx)
              break
      else:
        candidate_list = requested_by_signature.get(normalized_signature, [])
        for idx, candidate in enumerate(candidate_list):
          candidate_instance_id = candidate.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
          if not candidate_instance_id:
            plugin_config = candidate_list.pop(idx)
            break

      if not plugin_config:
        config_candidates = requested_by_signature.get(normalized_signature, [])
        if config_candidates:
          for idx, candidate in enumerate(config_candidates):
            candidate_instance_id = candidate.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
            if candidate_instance_id:
              plugin_config = config_candidates.pop(idx)
              break

      prepared_plugin = self.deeploy_prepare_single_plugin_instance_update(
        inputs=inputs,
        instance_id=plugin.get(DEEPLOY_PLUGIN_DATA.INSTANCE_ID),
        plugin_signature=signature,
        plugin_config=plugin_config,
        fallback_instance=plugin.get(DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE),
      )

      chainstore_key = plugin.get(DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY)
      if chainstore_key:
        prepared_plugin[DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY] = chainstore_key

      plugins_by_node[addr].append(prepared_plugin)

    unique_nodes = nodes if nodes else []

    if not unique_nodes:
      target_nodes = inputs.get(DEEPLOY_KEYS.TARGET_NODES, []) if hasattr(inputs, 'get') else []
      if not target_nodes and hasattr(inputs, DEEPLOY_KEYS.TARGET_NODES):
        target_nodes = getattr(inputs, DEEPLOY_KEYS.TARGET_NODES)
      if isinstance(target_nodes, list):
        unique_nodes = list(target_nodes)

    if requested_by_instance_id:
      missing_ids = list(requested_by_instance_id.keys())
      raise ValueError(
        f"{DEEPLOY_ERRORS.PLUGINS3}: Unknown plugin instance_id(s) in update request: {missing_ids}"
      )

    if new_plugin_configs:
      if detected_job_app_type != JOB_APP_TYPES.NATIVE:
        raise ValueError(
          f"{DEEPLOY_ERRORS.PLUGINS3}. Adding new plugin instances via update is currently supported only for native apps."
        )
      for addr in unique_nodes:
        for plugin_config in new_plugin_configs:
          plugin_signature = (
            plugin_config.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)
            or plugin_config.get("signature")
          )
          prepared_plugin = self.deeploy_prepare_single_plugin_instance_update(
            inputs=inputs,
            instance_id=None,
            plugin_signature=plugin_signature,
            plugin_config=plugin_config,
            fallback_instance=None,
          )
          plugins_by_node[addr].append(prepared_plugin)

    pipeline_to_save = None
    node_plugins_ready = {}
    for addr, plugins in plugins_by_node.items():
      nodes_to_peer = unique_nodes
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

      node_plugins_ready[addr] = node_plugins

    prepared_response_keys = self._normalize_chainstore_response_mapping(response_keys)
    merged_chainstore_map = self._normalize_chainstore_response_mapping(
      dct_deeploy_specs.get(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, {})
    )
    if inputs.chainstore_response:
      merged_chainstore_map = self._merge_chainstore_response_keys(
        merged_chainstore_map,
        prepared_response_keys,
      )
      if merged_chainstore_map:
        dct_deeploy_specs[DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS] = self.deepcopy(merged_chainstore_map)
      else:
        dct_deeploy_specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)
    else:
      merged_chainstore_map = {}
      dct_deeploy_specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)

    for addr, node_plugins in node_plugins_ready.items():
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
          deeploy_specs=self.deepcopy(dct_deeploy_specs),
          **pipeline_kwargs,
        )

        self.Pd(f"Pipeline started: {self.json_dumps(pipeline)}")
        pipeline[DEEPLOY_KEYS.PIPELINE_PARAMS] = self.deepcopy(pipeline_params)
        pipelin_to_save = pipeline
      # endif addr is valid
    # endfor each target node
    try:
      save_result = self.save_job_pipeline_in_cstore(pipelin_to_save, job_id)
      self.P(f"Pipeline saved in CSTORE: {save_result}")
    except Exception as e:
      self.P(f"Error saving pipeline in CSTORE: {e}", color="r")
    if inputs.chainstore_response:
      if merged_chainstore_map:
        dct_deeploy_specs[DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS] = self.deepcopy(merged_chainstore_map)
      else:
        dct_deeploy_specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)
    else:
      dct_deeploy_specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)

    cleaned_response_keys = prepared_response_keys if inputs.chainstore_response else {}
    return cleaned_response_keys

  def _prepare_updated_deeploy_specs(self, owner, app_id, job_id, discovered_plugin_instances):
    """
    Retrieve existing deeploy_specs and refresh the update timestamp.
    """
    nodes = []
    for instance in discovered_plugin_instances:
      node = instance.get(DEEPLOY_PLUGIN_DATA.NODE)
      if node and node not in nodes:
        nodes.append(node)

    try:
      online_apps = self._get_online_apps(
        owner=owner,
        target_nodes=nodes if nodes else None,
        job_id=job_id,
      )
    except Exception as exc:
      self.Pd(f"Unable to retrieve existing deeploy_specs for update: {exc}", color='r')
      return None

    specs = None
    for node, apps in online_apps.items():
      if app_id and app_id in apps:
        specs = apps[app_id].get(NetMonCt.DEEPLOY_SPECS)
        if specs:
          break
      for pipeline_name, data in apps.items():
        candidate_specs = data.get(NetMonCt.DEEPLOY_SPECS)
        if candidate_specs:
          specs = candidate_specs
          break
      if specs:
        break

    if not specs or not isinstance(specs, dict):
      return None

    refreshed_specs = self.deepcopy(specs)
    refreshed_specs[DEEPLOY_KEYS.DATE_UPDATED] = self.time()
    refreshed_specs = self._ensure_deeploy_specs_job_config(refreshed_specs)
    return refreshed_specs

  def _gather_running_pipeline_context(self, owner, app_id=None, job_id=None):
    """
    Collect information about currently running pipeline instances for a job/app.

    Ensures follow-up operations keep parity with the active deployment state.

    Returns
    -------
    dict
      {
        'discovered_instances': list,
        'nodes': list[str],
        'deeploy_specs': dict | None,
      }
    """
    discovered_instances = self._discover_plugin_instances(app_id=app_id, job_id=job_id, owner=owner)
    nodes = []
    for instance in discovered_instances:
      node_addr = instance.get(DEEPLOY_PLUGIN_DATA.NODE)
      if node_addr and node_addr not in nodes:
        nodes.append(node_addr)

    if not nodes:
      msg = f"{DEEPLOY_ERRORS.NODES3}: No running workers found for provided "
      msg += f"{f'app_id {app_id}' if app_id else f'job_id {job_id}'} and owner '{owner}'."
      raise ValueError(msg)

    deeploy_specs = self._prepare_updated_deeploy_specs(
      owner=owner,
      app_id=app_id,
      job_id=job_id,
      discovered_plugin_instances=discovered_instances,
    )

    return {
      "discovered_instances": discovered_instances,
      "nodes": nodes,
      "deeploy_specs": deeploy_specs,
    }

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
      DEEPLOY_KEYS.PIPELINE_PARAMS: {},
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

  def _ensure_deeploy_specs_job_config(self, deeploy_specs, pipeline_params=None):
    """
    Ensure deeploy_specs contains a job_config section holding pipeline_params.
    """
    if not isinstance(deeploy_specs, dict):
      return deeploy_specs

    specs = self.deepcopy(deeploy_specs)

    job_config = specs.get(DEEPLOY_KEYS.JOB_CONFIG)
    if not isinstance(job_config, dict):
      job_config = {}

    resolved_params = pipeline_params
    if resolved_params is None:
      resolved_params = job_config.get(DEEPLOY_KEYS.PIPELINE_PARAMS)

    if resolved_params is None:
      resolved_params = {}

    if not isinstance(resolved_params, dict):
      self.Pd(
        "Invalid pipeline_params detected while normalizing deeploy_specs; expected a dictionary.",
        color='y'
      )
      resolved_params = {}

    job_config[DEEPLOY_KEYS.PIPELINE_PARAMS] = self.deepcopy(resolved_params)
    specs[DEEPLOY_KEYS.JOB_CONFIG] = job_config
    return specs

  def _normalize_chainstore_response_mapping(self, mapping):
    """
    Return a sanitized node -> [chainstore_key] dictionary.
    """
    normalized = {}
    if not isinstance(mapping, dict):
      return normalized

    for node_addr, raw_value in mapping.items():
      keys = []
      if isinstance(raw_value, (list, tuple, set)):
        keys = [key for key in raw_value if isinstance(key, str) and key]
      elif isinstance(raw_value, str) and raw_value:
        keys = [raw_value]

      if not keys:
        continue

      deduped = list(dict.fromkeys(keys))
      if deduped:
        normalized[node_addr] = deduped

    return normalized

  def _merge_chainstore_response_keys(self, base_mapping, additions):
    """
    Merge node -> [chainstore_key] mappings, returning a new normalized dictionary.
    """
    merged = self._normalize_chainstore_response_mapping(base_mapping)
    extra = self._normalize_chainstore_response_mapping(additions)

    for node_addr, keys in extra.items():
      target = merged.setdefault(node_addr, [])
      for key in keys:
        if key not in target:
          target.append(key)

    return merged

  def _get_pipeline_params_from_deeploy_specs(self, deeploy_specs):
    """
    Retrieve pipeline_params from deeploy_specs, preferring the job_config payload.
    """
    if not isinstance(deeploy_specs, dict):
      return {}

    job_config = deeploy_specs.get(DEEPLOY_KEYS.JOB_CONFIG, {})
    if isinstance(job_config, dict):
      job_config_params = job_config.get(DEEPLOY_KEYS.PIPELINE_PARAMS, {})
      if job_config_params is None:
        job_config_params = {}
      if isinstance(job_config_params, dict):
        return self.deepcopy(job_config_params)
      self.Pd(
        "Invalid pipeline_params found under deeploy_specs.job_config; expected a dictionary.",
        color='y'
      )
    return {}

  def _extract_pipeline_params(self, inputs):
    """
    Return pipeline-level parameters ensuring a dictionary payload.

    Args:
        inputs: The request payload with potential pipeline_params entry.

    Returns:
        dict: Normalized pipeline params dictionary.
    """
    pipeline_params = {}
    try:
      pipeline_params = inputs.get(DEEPLOY_KEYS.PIPELINE_PARAMS, {})
    except Exception:
      if hasattr(inputs, DEEPLOY_KEYS.PIPELINE_PARAMS):
        pipeline_params = getattr(inputs, DEEPLOY_KEYS.PIPELINE_PARAMS)

    if pipeline_params is None:
      pipeline_params = {}

    if not isinstance(pipeline_params, dict):
      raise ValueError(
        f"{DEEPLOY_ERRORS.REQUEST3}. 'pipeline_params' must be a dictionary."
      )

    return pipeline_params

  def _prepare_pipeline_param_kwargs(self, pipeline_params, reserved_keys=None):
    """
    Prepare keyword arguments for pipeline creation based on pipeline_params.

    Args:
        pipeline_params (dict): Raw pipeline params from the request.
        reserved_keys (set[str] | None): Keys that should not be forwarded.

    Returns:
        dict: Filtered kwargs safe to pass into cmdapi_start_pipeline_by_params.
    """
    if not pipeline_params:
      return {}

    if not isinstance(pipeline_params, dict):
      raise ValueError(
        f"{DEEPLOY_ERRORS.REQUEST3}. 'pipeline_params' must be a dictionary."
      )

    reserved = {
      "name",
      "pipeline_type",
      "url",
      "plugins",
    }
    if reserved_keys:
      reserved.update(reserved_keys)

    return {
      key: value
      for key, value in pipeline_params.items()
      if key not in reserved
    }

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
    self.Pd("Aggregating container resources...")
    plugins_array = inputs.get(DEEPLOY_KEYS.PLUGINS)

    # For legacy format, use existing app_params
    if not plugins_array:
      self.Pd("Using legacy format (app_params) for resource aggregation")
      app_params = inputs.get(DEEPLOY_KEYS.APP_PARAMS, {})
      legacy_resources = app_params.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
      self.Pd(f"Legacy resources: {legacy_resources}")
      return legacy_resources

    self.Pd(f"Processing {len(plugins_array)} plugin instances from plugins array")
    total_cpu = 0
    total_memory_mb = 0

    # Iterate through plugins array (simplified format - each object is an instance)
    for idx, plugin_instance in enumerate(plugins_array):
      signature = plugin_instance.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE, "").upper()
      self.Pd(f"Plugin {idx}: signature={signature}")

      # Only aggregate for CONTAINER_APP_RUNNER and WORKER_APP_RUNNER plugins
      if signature in CONTAINERIZED_APPS_SIGNATURES:
        resources = plugin_instance.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
        cpu = resources.get(DEEPLOY_RESOURCES.CPU, 0)
        memory = resources.get(DEEPLOY_RESOURCES.MEMORY, "0m")

        self.Pd(f"  Container resources: cpu={cpu}, memory={memory}")

        total_cpu += cpu
        memory_mb = self._parse_memory_to_mb(memory)
        self.Pd(f"  Parsed memory: {memory_mb}MB")
        total_memory_mb += memory_mb
      else:
        self.Pd(f"  Skipping non-container plugin: {signature}")

    # Return aggregated resources in standard format
    aggregated = {
      DEEPLOY_RESOURCES.CPU: total_cpu,
      DEEPLOY_RESOURCES.MEMORY: f"{total_memory_mb}m"
    }
    self.Pd(f"Aggregated resources: {aggregated}")
    return aggregated

  def _organize_requested_plugins(self, inputs):
    """
    Organize requested plugin configurations by instance_id and signature,
    and separate newly requested plugin instances.
    """
    plugins_by_instance_id = {}
    plugins_by_signature = self.defaultdict(list)
    new_plugin_configs = []

    plugins_array = inputs.get(DEEPLOY_KEYS.PLUGINS)
    if not plugins_array or not isinstance(plugins_array, list):
      return plugins_by_instance_id, plugins_by_signature, new_plugin_configs

    for plugin_instance in plugins_array:
      if not isinstance(plugin_instance, dict):
        continue

      signature = (
        plugin_instance.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)
        or plugin_instance.get("signature")
      )
      if not signature:
        continue

      normalized_signature = signature.upper() if isinstance(signature, str) else signature
      instance_id = (
        plugin_instance.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
        or plugin_instance.get("instance_id")
        or plugin_instance.get(self.ct.CONFIG_INSTANCE.K_INSTANCE_ID)
      )

      plugin_copy = self.deepcopy(plugin_instance)
      legacy_signature_value = plugin_copy.pop("signature", None)
      if DEEPLOY_KEYS.PLUGIN_SIGNATURE not in plugin_copy and legacy_signature_value is not None:
        plugin_copy[DEEPLOY_KEYS.PLUGIN_SIGNATURE] = legacy_signature_value
      plugin_copy[DEEPLOY_KEYS.PLUGIN_SIGNATURE] = plugin_copy.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE, signature)

      if instance_id:
        plugin_copy[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] = instance_id
        plugins_by_instance_id[instance_id] = plugin_copy
      else:
        plugin_copy.pop(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID, None)
        new_plugin_configs.append(plugin_copy)

      plugins_by_signature[normalized_signature].append(plugin_copy)

    return plugins_by_instance_id, plugins_by_signature, new_plugin_configs
  # TODO: END FIXME

  def deeploy_check_payment_and_job_owner(self, inputs, sender, is_create, debug=False):
    """
    Check if the payment is valid for the given job.
    """
    self.Pd(f"=== deeploy_check_payment_and_job_owner ===")
    self.Pd(f"  sender: {sender}")
    self.Pd(f"  is_create: {is_create}")
    self.Pd(f"  debug: {debug}")

    allow_unpaid = inputs.get("allow_unpaid_job", False)
    network = self.bc.get_evm_network()
    self.Pd(f"  allow_unpaid: {allow_unpaid}, network: {network}")

    if allow_unpaid and network == 'devnet':
      self.Pd("  Bypassing payment check: unpaid job allowed on devnet")
      return True

    job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
    self.Pd(f"Checking payment for job {job_id} by sender {sender}{' (debug mode)' if debug else ''}")

    if not job_id:
      self.Pd("  No job_id provided - validation failed")
      return False

    # Check if the job is paid
    self.Pd(f"  Fetching job details for job_id={job_id}...")
    job = self.bc.get_job_details(job_id=job_id)
    self.Pd(f"Job details: {self.json_dumps(job, indent=2)}")

    if not job:
      self.P(f"Job {job_id} not found.")
      self.Pd(f"=== Payment validation result: False ===")
      return False

    job_owner = job.get('escrowOwner', None)
    start_timestamp = job.get('startTimestamp', None)

    self.Pd(f"  Job owner: {job_owner}")
    self.Pd(f"  Start timestamp: {start_timestamp}")

    is_valid = (sender == job_owner) if sender and job_owner else False
    self.Pd(f"  Owner match: {is_valid} (sender={sender}, owner={job_owner})")

    if is_create and start_timestamp:
      self.Pd(f"  Job already started (timestamp={start_timestamp}) but is_create=True - invalidating")
      is_valid = False

    if not is_valid:
      self.Pd(f"=== Payment validation result: {is_valid} ===")
      return is_valid

    # At this point, owner is valid, now validate resources
    job_type = job.get('jobType')
    self.Pd(f"  Job type: {job_type}")

    if job_type is None:
      self.P(f"Job type missing or invalid for job {job_id}. Cannot validate resources.")
      msg = (f"{DEEPLOY_ERRORS.JOB_RESOURCES1}: Job type missing or invalid for job {job_id}.")
      raise ValueError(msg)

    expected_resources = JOB_TYPE_RESOURCE_SPECS.get(job_type)
    self.Pd(f"  Expected resources for job type {job_type}: {expected_resources}")

    if expected_resources is None:
      self.P(f"No resource specs configured for job type {job_type}. Cannot validate resources.")
      msg = (f"{DEEPLOY_ERRORS.JOB_RESOURCES2}: No resource specs configured for job type {job_type}.")
      raise ValueError(msg)

    if expected_resources:
      job_app_type = inputs.get(DEEPLOY_KEYS.JOB_APP_TYPE)
      if isinstance(job_app_type, str):
        job_app_type = job_app_type.lower()

      self.Pd(f"  Job app type from inputs: {job_app_type}")

      if not job_app_type:
        try:
          self.Pd("  Detecting job app type from plugins...")
          job_app_type = self.deeploy_detect_job_app_type(self.deeploy_prepare_plugins(inputs))
          self.Pd(f"  Detected job app type: {job_app_type}")
        except Exception as exc:
          self.Pd(f"  Failed to detect job app type: {exc}")
          job_app_type = None

      if job_app_type == JOB_APP_TYPES.NATIVE:
        # TODO: Re-enable resource validation for native apps once specs are defined.
        self.Pd(f"Skipping resource validation for native job {job_id}.")
      else:
        self.Pd(f"  Validating resources for non-native job (type={job_app_type})...")

        # Aggregate container resources across all plugins (for multi-plugin support)
        aggregated_resources = self._aggregate_container_resources(inputs)
        requested_cpu = aggregated_resources.get(DEEPLOY_RESOURCES.CPU)
        requested_memory = aggregated_resources.get(DEEPLOY_RESOURCES.MEMORY)
        expected_cpu = expected_resources.get(DEEPLOY_RESOURCES.CPU)
        expected_memory = expected_resources.get(DEEPLOY_RESOURCES.MEMORY)

        self.Pd(f"  Requested: cpu={requested_cpu}, memory={requested_memory}")
        self.Pd(f"  Expected: cpu={expected_cpu}, memory={expected_memory}")

        #TODO should also check disk and gpu as soon as they are supported and sent in the request
        # Normalize numeric values before comparison
        try:
          requested_cpu_val = None if requested_cpu is None else float(requested_cpu)
        except (TypeError, ValueError) as e:
          self.Pd(f"  Failed to parse requested CPU: {e}")
          requested_cpu_val = None

        try:
          expected_cpu_val = None if expected_cpu is None else float(expected_cpu)
        except (TypeError, ValueError) as e:
          self.Pd(f"  Failed to parse expected CPU: {e}")
          expected_cpu_val = None

        requested_memory_mb = (
          None if requested_memory is None else self._parse_memory_to_mb(requested_memory)
        )
        expected_memory_mb = (
          None if expected_memory is None else self._parse_memory_to_mb(expected_memory)
        )

        self.Pd(f"  Normalized: requested_cpu={requested_cpu_val}, expected_cpu={expected_cpu_val}")
        self.Pd(f"  Normalized: requested_memory={requested_memory_mb}MB, expected_memory={expected_memory_mb}MB")

        resources_match = (
          requested_cpu_val is not None and
          expected_cpu_val is not None and
          requested_memory_mb is not None and
          expected_memory_mb is not None and
          requested_cpu_val == expected_cpu_val and
          requested_memory_mb == expected_memory_mb
        )

        self.Pd(f"  Resources match: {resources_match}")

        if not resources_match:
          self.P(
            f"Requested resources {aggregated_resources} do not match paid resources "
            f"{expected_resources} for job type {job_type}."
          )
          msg = (f"{DEEPLOY_ERRORS.JOB_RESOURCES3}: Requested resources {aggregated_resources} " +
                 f"do not match paid resources {expected_resources} for job type {job_type}.")
          raise ValueError(msg)
        else:
          self.Pd(f"  Resource validation passed!")

    self.Pd(f"=== Payment validation result: {is_valid} ===")
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

  def deeploy_prepare_single_plugin_instance_update(self, inputs, instance_id, plugin_signature=None, plugin_config=None, fallback_instance=None):
    """
    Prepare the a single plugin instance for the pipeline creation.
    """
    signature = plugin_signature

    if not signature and plugin_config:
      signature = (
        plugin_config.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)
        or plugin_config.get("signature")
      )

    if not signature:
      try:
        signature = inputs.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE, None)
      except Exception:
        signature = None

    if not signature and hasattr(inputs, DEEPLOY_KEYS.PLUGIN_SIGNATURE):
      signature = getattr(inputs, DEEPLOY_KEYS.PLUGIN_SIGNATURE)

    if not signature and fallback_instance and isinstance(fallback_instance, dict):
      signature = (
        fallback_instance.get(self.ct.CONFIG_PLUGIN.K_SIGNATURE)
        or fallback_instance.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)
        or fallback_instance.get("signature")
      )

    if not signature:
      raise ValueError(
        f"{DEEPLOY_ERRORS.REQUEST7}. 'plugin_signature' not provided for update."
      )

    if not instance_id:
      instance_id = self._generate_plugin_instance_id(signature=signature)

    instance_payload = {}

    if plugin_config:
      config_copy = self.deepcopy(plugin_config)
      config_copy.pop(DEEPLOY_KEYS.PLUGIN_SIGNATURE, None)
      config_copy.pop("signature", None)
      instance_payload = config_copy
    else:
      app_params = None
      try:
        app_params = inputs.get(DEEPLOY_KEYS.APP_PARAMS, None)
      except Exception:
        app_params = None

      if not app_params and hasattr(inputs, DEEPLOY_KEYS.APP_PARAMS):
        app_params = getattr(inputs, DEEPLOY_KEYS.APP_PARAMS)

      if app_params and isinstance(app_params, dict):
        instance_payload = self.deepcopy(app_params)
      elif fallback_instance and isinstance(fallback_instance, dict):
        instance_conf = fallback_instance.get("instance_conf")
        if instance_conf and isinstance(instance_conf, dict):
          instance_payload = self.deepcopy(instance_conf)
          instance_payload.pop(self.ct.CONFIG_INSTANCE.K_INSTANCE_ID, None)
          instance_payload.pop(DEEPLOY_KEYS.PLUGIN_SIGNATURE, None)
          instance_payload.pop("signature", None)
        else:
          instance_payload = {}
      else:
        instance_payload = {}

    plugin = {
      self.ct.CONFIG_PLUGIN.K_SIGNATURE: signature,
      self.ct.CONFIG_PLUGIN.K_INSTANCES: [
        {
          self.ct.CONFIG_INSTANCE.K_INSTANCE_ID: instance_id,
          **instance_payload
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

      used_instance_ids = set()

      for plugin_instance in plugins_array:
        signature = plugin_instance.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE)

        # Extract instance config (everything except metadata keys)
        instance_config = {
          k: v for k, v in plugin_instance.items()
          if k not in {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE,
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID,
            self.ct.CONFIG_INSTANCE.K_INSTANCE_ID,
            "signature",
            "instance_id",
          }
        }

        instance_id = (
          plugin_instance.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
          or plugin_instance.get("instance_id")
          or plugin_instance.get(self.ct.CONFIG_INSTANCE.K_INSTANCE_ID)
        )
        if instance_id:
          instance_id = str(instance_id)
        if not instance_id or instance_id in used_instance_ids:
          instance_id = self._generate_plugin_instance_id(signature=signature)
        used_instance_ids.add(instance_id)

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

  def check_and_deploy_pipelines(self, sender, inputs, app_id, app_alias, app_type, update_nodes, new_nodes, discovered_plugin_instances=[], dct_deeploy_specs=None, job_app_type=None, dct_deeploy_specs_create=None):
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
      new_response_keys = self.__create_pipeline_on_nodes(new_nodes, inputs, app_id, app_alias, app_type, sender, job_app_type=job_app_type, dct_deeploy_specs=dct_deeploy_specs_create)
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
    self.P(f"online apps for owner {owner} and target_nodes {target_nodes}: {self.json_dumps(apps)}")
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

    pipeline_params = {}
    if isinstance(deeploy_specs, dict):
      normalized_specs = self._ensure_deeploy_specs_job_config(deeploy_specs)
      pipeline_params = self._get_pipeline_params_from_deeploy_specs(normalized_specs)
      deeploy_specs = normalized_specs

    # todo: use constants
    return {
      "base_pipeline": base_pipeline,
      "app_id": first_app_id,
      "deeploy_specs": deeploy_specs,
      "plugins": transformed_plugins,
      "pipeline_type": base_pipeline.get("TYPE", "void"),
      "url": base_pipeline.get("URL", None),
      "pipeline_params": pipeline_params,
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

    pipeline_params = base_pipeline.get("pipeline_params")
    if not isinstance(pipeline_params, dict):
      pipeline_params = self._get_pipeline_params_from_deeploy_specs(
        base_pipeline.get(NetMonCt.DEEPLOY_SPECS, {})
      )
    if pipeline_params is None:
      pipeline_params = {}
    if not isinstance(pipeline_params, dict):
      self.Pd("Invalid pipeline_params detected in base pipeline; defaulting to empty dict.", color='y')
      pipeline_params = {}
    base_pipeline["pipeline_params"] = self.deepcopy(pipeline_params)

    chainstore_peers = list(set(new_nodes + update_nodes))
    raw_deeploy_specs = base_pipeline.get(NetMonCt.DEEPLOY_SPECS, {})
    deeploy_specs = self.deepcopy(raw_deeploy_specs) if isinstance(raw_deeploy_specs, dict) else {}
    job_app_type = None
    if isinstance(deeploy_specs, dict):
      job_app_type = deeploy_specs.get(DEEPLOY_KEYS.JOB_APP_TYPE)
      if not job_app_type:
        job_app_type = self.deeploy_detect_job_app_type(base_pipeline.get(NetMonCt.PLUGINS, []))
        if job_app_type in JOB_APP_TYPES_ALL:
          deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = job_app_type
    deeploy_specs = self._ensure_deeploy_specs_job_config(
      deeploy_specs,
      pipeline_params=pipeline_params,
    )
    if isinstance(deeploy_specs, dict):
      deeploy_specs[DEEPLOY_KEYS.CURRENT_TARGET_NODES] = chainstore_peers
      deeploy_specs[DEEPLOY_KEYS.DATE_UPDATED] = self.time()
    base_pipeline[NetMonCt.DEEPLOY_SPECS] = self.deepcopy(deeploy_specs)

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

    normalized_existing_map = self._normalize_chainstore_response_mapping(
      deeploy_specs.get(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, {})
    )
    prepared_response_keys = {
      node: [key for key in keys if key]
      for node, keys in chainstore_response_keys.items()
      if any(key for key in keys if key)
    }
    merged_mapping = self._merge_chainstore_response_keys(
      normalized_existing_map,
      prepared_response_keys
    )

    if isinstance(deeploy_specs, dict):
      if merged_mapping:
        deeploy_specs[DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS] = self.deepcopy(merged_mapping)
      else:
        deeploy_specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)
      base_pipeline[NetMonCt.DEEPLOY_SPECS] = self.deepcopy(deeploy_specs)

    for pipeline in create_pipelines.values():
      specs = pipeline.get(NetMonCt.DEEPLOY_SPECS, {})
      if not isinstance(specs, dict):
        continue
      if merged_mapping:
        specs[DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS] = self.deepcopy(merged_mapping)
      else:
        specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)
      pipeline[NetMonCt.DEEPLOY_SPECS] = specs

    for pipeline in update_pipelines.values():
      specs = pipeline.get(NetMonCt.DEEPLOY_SPECS, {})
      if not isinstance(specs, dict):
        continue
      if merged_mapping:
        specs[DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS] = self.deepcopy(merged_mapping)
      else:
        specs.pop(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, None)
      pipeline[NetMonCt.DEEPLOY_SPECS] = specs

    return create_pipelines, update_pipelines, prepared_response_keys

  def _start_create_update_pipelines(self, create_pipelines, update_pipelines, sender):
    """
    Start the create and update pipelines.
    """
    for node, pipeline in create_pipelines.items():
      pipeline_params = pipeline.get('pipeline_params', {})
      if not isinstance(pipeline_params, dict):
        pipeline_params = {}
      pipeline_kwargs = self._prepare_pipeline_param_kwargs(
        pipeline_params,
        reserved_keys={"app_alias", "owner", "is_deeployed", "deeploy_specs"},
      )
      self.cmdapi_start_pipeline_by_params(
        name=pipeline['app_id'],
        pipeline_type=pipeline['pipeline_type'],
        node_address=node,
        owner=sender, 
        url=pipeline.get('url'),
        plugins=pipeline['plugins'],
        is_deeployed=True,
        deeploy_specs=pipeline['deeploy_specs'],
        **pipeline_kwargs,
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
  
  def delete_pipeline_from_nodes(self, app_id=None, job_id=None, owner=None, allow_missing=False, discovered_instances=None):
    if discovered_instances is None:
      discovered_instances = self._discover_plugin_instances(app_id=app_id, job_id=job_id, owner=owner)

    if len(discovered_instances) == 0:
      if allow_missing:
        self.Pd(f"Skipping pipeline stop for job_id={job_id} and owner={owner}", color='y')
        return []
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

  # TODO: REMOVE THIS, once instance_id is coming from ui for instances that have to be updated
  # Maybe add is_new_instance:bool for native apps, that want to add an extra plugin
  def _ensure_plugin_instance_ids(self, inputs, discovered_plugin_instances, owner=None, app_id=None, job_id=None):
    """
    Backfill missing instance_id values for plugin updates using discovered plugin instances.
    """
    try:
      plugins_array = inputs.get(DEEPLOY_KEYS.PLUGINS, None) if hasattr(inputs, 'get') else None
    except Exception:
      plugins_array = None

    if not plugins_array or not isinstance(plugins_array, list):
      return discovered_plugin_instances

    if not discovered_plugin_instances and (app_id or job_id):
      try:
        discovered_plugin_instances = self._discover_plugin_instances(app_id=app_id, job_id=job_id, owner=owner)
      except Exception as exc:
        self.Pd(f"Failed to auto-discover plugin instances for update: {exc}", color='r')
        discovered_plugin_instances = []

    if not discovered_plugin_instances:
      return discovered_plugin_instances

    instance_id_key = ct.BIZ_PLUGIN_DATA.INSTANCE_ID
    chainstore_response_key = ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY
    chainstore_peers_key = ct.BIZ_PLUGIN_DATA.CHAINSTORE_PEERS

    used_instance_ids = set()
    for plugin_entry in plugins_array:
      existing_id = (
        plugin_entry.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
        or plugin_entry.get("instance_id")
        or plugin_entry.get(instance_id_key)
      )
      if existing_id:
        used_instance_ids.add(existing_id)

    discovered_by_signature = self.defaultdict(list)
    for plugin in discovered_plugin_instances:
      signature = plugin.get(DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE)
      instance_id = plugin.get(DEEPLOY_PLUGIN_DATA.INSTANCE_ID)
      if not signature or not instance_id:
        continue
      discovered_by_signature[signature.upper()].append(plugin)

    for signature in discovered_by_signature:
      discovered_by_signature[signature] = sorted(
        discovered_by_signature[signature],
        key=lambda item: item.get(DEEPLOY_PLUGIN_DATA.INSTANCE_ID) or ""
      )

    for plugin_entry in plugins_array:
      current_id = (
        plugin_entry.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
        or plugin_entry.get("instance_id")
        or plugin_entry.get(instance_id_key)
      )
      if current_id:
        continue

      signature = plugin_entry.get(DEEPLOY_KEYS.PLUGIN_SIGNATURE) or plugin_entry.get("signature")
      if not signature:
        continue

      normalized_signature = signature.upper()
      candidates = discovered_by_signature.get(normalized_signature, [])
      if not candidates:
        continue

      match = self._match_native_plugin_candidate(
        plugin_entry,
        candidates,
        used_instance_ids,
        instance_id_key=instance_id_key,
        chainstore_response_key=chainstore_response_key,
        chainstore_peers_key=chainstore_peers_key,
      )

      if not match:
        continue

      matched_instance_id = match.get(DEEPLOY_PLUGIN_DATA.INSTANCE_ID)
      if not matched_instance_id:
        continue

      plugin_entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] = matched_instance_id
      plugin_entry["instance_id"] = matched_instance_id
      used_instance_ids.add(matched_instance_id)

      self.Pd(f"Inferred instance_id '{matched_instance_id}' for plugin '{signature}'.", color='g')

    return discovered_plugin_instances

  def _match_native_plugin_candidate(
    self,
    plugin_entry,
    candidates,
    used_instance_ids,
    instance_id_key,
    chainstore_response_key,
    chainstore_peers_key,
  ):
    """
    Match a plugin update payload without instance_id to an existing discovered instance.
    """
    requested_conf = self._extract_plugin_request_conf(
      plugin_entry,
      instance_id_key=instance_id_key,
      chainstore_response_key=chainstore_response_key,
      chainstore_peers_key=chainstore_peers_key,
    )

    best_candidate = None
    best_score = -1
    for candidate in candidates:
      candidate_instance_id = candidate.get(DEEPLOY_PLUGIN_DATA.INSTANCE_ID)
      if not candidate_instance_id or candidate_instance_id in used_instance_ids:
        continue
      candidate_conf = self._extract_discovered_plugin_conf(
        candidate,
        instance_id_key=instance_id_key,
        chainstore_response_key=chainstore_response_key,
        chainstore_peers_key=chainstore_peers_key,
      )
      score = self._score_plugin_config_match(requested_conf, candidate_conf)
      if score > best_score:
        best_score = score
        best_candidate = candidate

    if best_candidate is None:
      for candidate in candidates:
        candidate_instance_id = candidate.get(DEEPLOY_PLUGIN_DATA.INSTANCE_ID)
        if candidate_instance_id and candidate_instance_id not in used_instance_ids:
          best_candidate = candidate
          break

    return best_candidate

  def _extract_plugin_request_conf(self, plugin_entry, instance_id_key, chainstore_response_key, chainstore_peers_key):
    """
    Produce a sanitized configuration dict from the update request plugin payload.
    """
    ignore_keys = {
      DEEPLOY_KEYS.PLUGIN_SIGNATURE,
      DEEPLOY_KEYS.PLUGIN_INSTANCE_ID,
      "signature",
      "instance_id",
      instance_id_key,
      chainstore_response_key,
      chainstore_peers_key,
    }

    result = {}
    for key, value in plugin_entry.items():
      if key in ignore_keys:
        continue
      result[key] = value

    return result

  def _extract_discovered_plugin_conf(self, discovered_plugin, instance_id_key, chainstore_response_key, chainstore_peers_key):
    """
    Produce a sanitized configuration dict from an already running plugin instance.
    """
    plugin_instance = discovered_plugin.get(DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE, {})
    instance_conf = {}
    if isinstance(plugin_instance, dict):
      instance_conf = plugin_instance.get("instance_conf", plugin_instance)
      if not isinstance(instance_conf, dict):
        instance_conf = {}

    ignore_keys = {
      instance_id_key,
      DEEPLOY_KEYS.PLUGIN_SIGNATURE,
      "signature",
      chainstore_response_key,
      chainstore_peers_key,
    }

    result = {}
    for key, value in instance_conf.items():
      if key in ignore_keys:
        continue
      result[key] = value

    return result

  # TODO: Remove this once instance_ids are sent and make sure instance_id is mandatory.
  # Update should be done strictly by instance_id.
  def _score_plugin_config_match(self, requested_conf, existing_conf):
    """
    Compute a similarity score between a request payload and an existing instance configuration.
    """
    if not requested_conf:
      return 0

    score = 0
    for key, value in requested_conf.items():
      if key not in existing_conf:
        continue
      existing_value = existing_conf[key]
      if isinstance(value, (dict, list)) and isinstance(existing_value, (dict, list)):
        try:
          if self.json_dumps(value, sort_keys=True) == self.json_dumps(existing_value, sort_keys=True):
            score += 3
        except TypeError:
          continue
      elif value == existing_value:
        score += 2
      elif str(value) == str(existing_value):
        score += 1

    return score
