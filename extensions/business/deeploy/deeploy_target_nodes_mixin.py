from naeural_core.main.net_mon import NetMonCt

from extensions.business.deeploy.deeploy_const import DEEPLOY_ERRORS, DEEPLOY_KEYS, DEEPLOY_RESOURCES, \
  DEFAULT_CONTAINER_RESOURCES,  CONTAINER_APP_RUNNER_SIGNATURE
from naeural_core import constants as ct

DEEPLOY_DEBUG = True

class _DeeployTargetNodesMixin:
  def __init__(self):
    super(_DeeployTargetNodesMixin, self).__init__()
    return


  def Pd(self, s, *args, **kwargs):
    """
    Print a message to the console.
    """
    if self.cfg_deeploy_verbose:
      s = "[DEPDBG] " + s
      self.P(s, *args, **kwargs)
    return


  def _parse_memory(self, mem):
    """
    Convert memory string to bytes.
    Args:
        mem (str | float | int): Memory string in format '512m', '1g', '1.3g, or bytes
    Returns:
        int: Memory in bytes
    """
    # If it's float, we suppose, that it's provided in GB.
    if not mem:
      return 0
    if type(mem) is float or type(mem) is int:
      return int(mem * 1024 * 1024 * 1024) # GB to bytes
    elif mem.endswith('m'):
      return int(float(mem[:-1]) * 1024 * 1024)  # MB to bytes
    elif mem.endswith('mb'):
      return int(float(mem[:-2]) * 1024 * 1024)  # MB to bytes
    elif mem.endswith('g'):
      return int(float(mem[:-1]) * 1024 * 1024 * 1024)  # GB to bytes
    elif mem.endswith('gb'):
      return int(float(mem[:-2]) * 1024 * 1024 * 1024)  # GB to bytes
    else:
      return int(float(mem))  # assume bytes

  def _check_and_maybe_convert_address(self, node_addr, raise_if_error=True):
    result = None
    if node_addr.startswith("0x"):
      is_eth = self.bc.is_valid_eth_address(node_addr)
      if is_eth:
        result = self.bc.eth_addr_to_internal_addr(node_addr)
      else:
        is_internal = self.bc.is_valid_internal_address(node_addr)
        if is_internal:
          result = node_addr
        # endif
      # endif
    # endif
    if result is None:
      msg = f"{DEEPLOY_ERRORS.NODES4}: Invalid node address: {node_addr}"
      if raise_if_error:
        raise ValueError(msg)
      else:
        self.P(msg, color='r')
    return result

  def __find_nodes_without_deeployed_apps(self, nodes, apps):
    suitable_nodes = {}
    for addr in nodes:

      ai_addr = self.bc.maybe_add_prefix(addr)
      current_node_pipelines = apps.get(ai_addr)

      # if we didn't manage to get node pipelines, skip it.
      if not current_node_pipelines:
        continue

      has_deeployed_pipelines = False
      for pipeline_name, pipeline_data in current_node_pipelines.items():
        is_deeployed = pipeline_data.get(NetMonCt.IS_DEEPLOYED)
        if is_deeployed:
          has_deeployed_pipelines = True
          break
      if has_deeployed_pipelines:
        continue
      suitable_nodes[addr] = 1

    return suitable_nodes

  def __get_plugin_instance_resources(self, node_addr, pipeline_name, plugin_signature, instance_id):
    """
    Get resources for a plugin instance on a node.
    Args:
        node_addr (str): Node address
        plugin_signature (str): Plugin signature
        instance_id (str): Plugin instance ID
    Returns:
        dict: Resources for the plugin instance
    """
    # Get the resources for the plugin instance
    network_known_nodes = self.netmon.network_known_nodes()
    current_node_pipelines = network_known_nodes.get(node_addr, {}).get(NetMonCt.PIPELINES, {})

    matching_pipeline = next((pipeline for pipeline in current_node_pipelines if pipeline.get(ct.NAME) == pipeline_name) ,None)

    selected_instance = next(
      (
        inst
        for plugin in matching_pipeline["PLUGINS"]  # outer Plugins list
        if plugin["SIGNATURE"] == plugin_signature
        for inst in plugin["INSTANCES"]  # inner Instances list
        if inst["INSTANCE_ID"] == instance_id
      ),
      None
    )

    container_resources = selected_instance.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
    return container_resources

  def __find_suitable_nodes_for_container_app(self, nodes_with_resources, container_requested_resources, apps):
    """
    Find suitable nodes for a container app deployment.
    Args:
        nodes_with_resources (dict): Dictionary with node addresses as keys and their resources as values
        apps (dict): Dictionary with node addresses as keys and their apps as values
    Returns:
        dict: Dictionary with node addresses (without 0xai_ part) as keys and their last deployment timestamp as values
    """
    suitable_nodes = {}

    required_cpu = container_requested_resources.get(DEEPLOY_RESOURCES.CPU, DEFAULT_CONTAINER_RESOURCES.CPU)
    required_mem = container_requested_resources.get(DEEPLOY_RESOURCES.MEMORY, DEFAULT_CONTAINER_RESOURCES.MEMORY)
    required_mem_bytes = self._parse_memory(required_mem)

    for addr, node_resources in nodes_with_resources.items():
      ai_addr = self.bc.maybe_add_prefix(addr)

      used_container_resources = []
      last_deeployment_ts = 0

      node_pipelines = apps.get(ai_addr, {})

      skip_node = False
      for pipeline_name, pipeline_data in node_pipelines.items():

        is_deeployed = pipeline_data.get(NetMonCt.IS_DEEPLOYED)
        if not is_deeployed or pipeline_name == 'admin_pipeline':
          # skip it if app was deeployed through SDK or if it's the admin pipeline
          continue

        pipeline_plugins = pipeline_data.get(NetMonCt.PLUGINS, [])
        has_different_signatures = not all(sign == CONTAINER_APP_RUNNER_SIGNATURE for sign in pipeline_plugins.keys()) #FIX CAR OR WORKER APP RUNNER

        if has_different_signatures:
          self.Pd(f"Node {addr} has pipeline '{pipeline_name}' with Native Apps signature. Skipping...")
          skip_node = True
          break

        for plugin_signature, plugin_instances in pipeline_plugins.items():
          # Sum up resources here and check them
          for plugin_instance in plugin_instances:
            instance_id = plugin_instance.get(NetMonCt.PLUGIN_INSTANCE)
            plugin_instance_resources = self.__get_plugin_instance_resources(node_addr=addr,
                                                                             pipeline_name=pipeline_name,
                                                                             plugin_signature=plugin_signature,
                                                                             instance_id=instance_id)

            used_container_resources.append(plugin_instance_resources)

          # Get the last deployment timestamp
          last_config = pipeline_data.get('last_config')
          if last_config:
            ts = self.datetime.fromisoformat(last_config).timestamp()
            if ts > last_deeployment_ts:
              last_deeployment_ts = ts

      if skip_node:
        continue
      self.Pd(f"Node {addr} has {self.json_dumps(used_container_resources)} used container resources.")
      # Sum up resources used by node.
      used_cpu = 0
      used_memory = 0
      for res in used_container_resources:
        cpu = int(res.get(DEEPLOY_RESOURCES.CPU, DEFAULT_CONTAINER_RESOURCES.CPU))
        memory = res.get(DEEPLOY_RESOURCES.MEMORY, DEFAULT_CONTAINER_RESOURCES.MEMORY)
        used_cpu += cpu
        used_memory += self._parse_memory(memory)

      # Add the required resources for the new container app.
      used_cpu += required_cpu
      used_memory += required_mem_bytes

      # Check if the node has enough resources
      has_failed = False
      if used_cpu > node_resources['cpu']:
        self.Pd(f"Node {addr} has not enough CPU cores. used_cpu ({used_cpu}) > node_cpu ({node_resources['cpu']})")
        has_failed = True

      if used_memory > node_resources['memory']:
        self.Pd(f"Node {addr} has not enough RAM. used_memory ({used_memory}) > node_memory ({node_resources['memory']})")
        has_failed = True

      if has_failed:
        self.Pd(f"Node {addr} has not enough available resources for the container app. Skipping...", color='y')
        continue

      suitable_nodes[addr] = last_deeployment_ts
    return suitable_nodes


  def __check_nodes_capabilities_and_extract_resources(self, nodes: list['str'], inputs):
    """
    Check if the nodes have required resources for the deeployment and if it supports the requested plugin.
      Checks if the node is capable of deploying the container app.
    Returns a dictionary with node addresses as keys and their total resources as values.
    """
    node_res_req = inputs.get(DEEPLOY_RESOURCES.NODE_RESOURCES_REQUEST, {})

    node_req_cpu = node_res_req.get(DEEPLOY_RESOURCES.CPU)
    node_req_memory = node_res_req.get(DEEPLOY_RESOURCES.MEMORY)
    node_req_memory_bytes = self._parse_memory(node_req_memory)
    job_tags = inputs.get(DEEPLOY_KEYS.JOB_TAGS, [])

    suitable_nodes_with_resources = {}
    for addr in nodes:
      # Check if the node supports the requested plugin
      if inputs.plugin_signature in [CONTAINER_APP_RUNNER_SIGNATURE]:
        is_did_supported = self.netmon.network_node_has_did(addr=addr)
        if not is_did_supported:
          self.Pd(f"Node {addr} does not support the requested plugin {inputs.plugin_signature}. Skipping...")
          continue

      if len(job_tags) > 0:
        # TODO: update the processing to work well with the new structure
        node_tags = self.netmon.get_network_node_tags(addr)
        self.P(f"Node {addr} tags: {self.json_dumps(node_tags)}")
        skip_node = False
        for tag in job_tags:
          self.P(f"Checking if node {addr} has the tag {tag}...")
          # Check if node has the required tag
          if tag not in node_tags or node_tags.get(tag):
            self.Pd(f"Node {addr} does not have the tag {tag}. Skipping...")
            skip_node = True
            break
        if skip_node:
          continue

      self.Pd(f"Node {addr} cont in function.")
      total_cpu = self.netmon.network_node_total_cpu_cores(addr)

      total_memory = self.netmon.network_node_total_mem(addr)
      total_memory_bytes = self._parse_memory(total_memory)

      current_node_total_resources = {
        'cpu': total_cpu,
        'memory': total_memory_bytes,
      }

      if node_res_req:

        if total_cpu < node_req_cpu:
          self.Pd(f"Node {addr} has not enough CPU cores in total. Skipping...")
          continue

        if total_memory_bytes < node_req_memory_bytes:
          self.Pd(f"Node {addr} has not enought RAM in total. Skipping...")
          continue

      suitable_nodes_with_resources[addr] = current_node_total_resources
    # endfor each node
    return suitable_nodes_with_resources


  def _find_nodes_for_deeployment(self, inputs):
    # Get required resources from the request
    required_resources = inputs.app_params.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
    target_nodes_count = inputs.get(DEEPLOY_KEYS.TARGET_NODES_COUNT, None)

    if not target_nodes_count:
      msg = f"{DEEPLOY_ERRORS.NODES3}: Nodes count was not provided!"
      raise ValueError(msg)

    # If target_nodes_count is set, we will select the top nodes based on their scores
    network_nodes = self.netmon.network_nodes_status()

    non_supervisor_nodes = []
    for addr, value in network_nodes.items():
      ai_addr = self.bc.maybe_add_prefix(addr)

      is_online = self.netmon.network_node_is_online(ai_addr)
      if value.get('is_supervisor') is True or not is_online:
      # FIXME: Disabled for now, as the most of the nodes are are marked as non-trusted.
      # if value.get('is_supervisor') is True or not value.get('trusted', False) or not is_online:
        continue
      non_supervisor_nodes.append(addr)

    self.Pd(f"Network nodes: {self.json_dumps(network_nodes)}")
    self.Pd(f"Non supervisor Network nodes: {self.json_dumps(non_supervisor_nodes)}")

    suitable_nodes_with_resources = self.__check_nodes_capabilities_and_extract_resources(
      nodes=non_supervisor_nodes, inputs=inputs)
    self.Pd(f"Suitable nodes with resources: {self.json_dumps(suitable_nodes_with_resources)}")
    apps = self._get_online_apps()
    nodes_that_fit = {}

    if inputs.plugin_signature == CONTAINER_APP_RUNNER_SIGNATURE: # if plugin in ['CONTAINER APP RUNNER' || WORKER APP RUNNER].
      nodes_that_fit = self.__find_suitable_nodes_for_container_app(nodes_with_resources=suitable_nodes_with_resources,
                                                                    container_requested_resources=required_resources,
                                                                    apps=apps)
    else:
      nodes_that_fit = self.__find_nodes_without_deeployed_apps(suitable_nodes_with_resources, apps)

    self.Pd(f"nodes_that_fit={self.json_dumps(nodes_that_fit)}")

    sorted_nodes = sorted(
      nodes_that_fit,
      key=lambda kv: (
        -network_nodes[kv]["SCORE"],
        nodes_that_fit[kv]
      ))

    self.Pd(f"Sorted Nodes: {self.json_dumps(sorted_nodes, indent=2)}.")

    if len(sorted_nodes) < inputs.target_nodes_count:
      msg = f"{DEEPLOY_ERRORS.NODES5}: Not enough online nodes available. Required: {inputs.target_nodes_count}, Available: {len(sorted_nodes)}"
      raise ValueError(msg)

    nodes_to_run = sorted_nodes[:inputs.target_nodes_count]
    self.Pd(f"Nodes to run: {nodes_to_run}")

    return nodes_to_run


  def _check_nodes_availability(self, inputs):
    """
    Check if the target nodes are online and have sufficient resources.
    
    TODO: (Vitalii)
      - implement the case where `target_nodes` is None or empty but `target_nodes_count` is set
        - get all online non supervisor nodes ✅
        - filter if they have the required resources (available memory, CPU, disk)
          - check the node if it has `node_res_req`
          - check the node if is has _available_ resources required by `CONTAINER_RESOURCES`
        - check if they have other pipelines running/deploy recently
        - get node scores (order desc by score)
        - select target_nodes_count nodes:
          - select top scored nodes that did not receive deployment recently
          
        - Outcome: 
          - only nodes that have available resources and are online will be returned
          - only top avail nodes will be used for deployment
          - nodes that did not receive deployment recently will be preferred
        
        Example - 2 node job with 6 GB mem:
          N1: 99 score, 1 pipeline recent, 9 GB avail, 2 cores avail, 100 GB disk avail
          N2: 95 score, 0 pipelines recent, 8 GB avail, 4 cores avail, 200 GB disk avail
          N3: 99 score, 2 pipelines recent, 90 GB avail, 1 core avail, 900 GB disk avail
          N4: 85 score, 0 pipelines recent, 6 GB avail, 2 cores avail, 300 GB disk avail
          N5: 99 score, 1 pipeline recent, 16 GB avail, 3 cores avail, 150 GB disk avail
          N6: 99 score, 0 pipelines recent, 5 GB avail, 1 core avail, 400 GB disk avail
          N7: failed comms
          N8: failed comms
          
          Returns:
          - N7, N8 filterted out
          - N6 filtered out (not enough memory)
          - SORT: N1, N5, N3, N2, N4
          - OUTPUT: N1, N5
          
    TODO: (Andrei)
      - Harden the node scores based on a longer history (currently gets to 99 after 2-3 hours of uptime)
        - Score use exponential moving average of the node pre-score for the last 24 hours
        - Use oracle network for whole series
        - Penalize nodes that have history less than 50 epochs (1 epoch = 24 hours)
    
    """
    nodes = []

    if not inputs.target_nodes:
      nodes_to_run = self._find_nodes_for_deeployment(inputs=inputs)
      return nodes_to_run

    for node in inputs.target_nodes:
      addr = self._check_and_maybe_convert_address(node)
      is_supervisor = self.netmon.network_node_is_supervisor(addr=addr)
      if is_supervisor:
        msg = f"{DEEPLOY_ERRORS.NODES6}: Node {addr} is a supervisor node and cannot be used for deeployment"
        raise ValueError(msg)
      is_online = self.netmon.network_node_is_online(addr)
      if is_online:
        node_resources = self.check_node_available_resources(addr, inputs)
        if not node_resources[DEEPLOY_RESOURCES.STATUS]:
          error_msg = f"{DEEPLOY_ERRORS.NODERES1}: Node {addr} has insufficient resources:\n"
          for detail in node_resources[DEEPLOY_RESOURCES.DETAILS]:
            error_msg += (
                  f"- {detail[DEEPLOY_RESOURCES.RESOURCE]}: available {detail[DEEPLOY_RESOURCES.AVAILABLE]:.2f}{detail[DEEPLOY_RESOURCES.UNIT]} < " +
                  f"required {detail[DEEPLOY_RESOURCES.REQUIRED]:.2f}{detail[DEEPLOY_RESOURCES.UNIT]}\n")
          raise ValueError(error_msg)
        # endif not node_resources
        nodes.append(addr)
      else:
        msg = f"{DEEPLOY_ERRORS.NODES1}: Node {addr} is not online"
        raise ValueError(msg)
      # endif is_online
    # endfor each target node check address and status
    return nodes


  def check_node_available_resources(self, addr, inputs):
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
    avail_mem_bytes = self._parse_memory(f"{avail_mem}g")
    avail_disk = self.netmon.network_node_available_disk(addr)  # in bytes

    # Get required resources from the request
    required_resources = inputs.app_params.get(DEEPLOY_RESOURCES.CONTAINER_RESOURCES, {})
    required_mem = required_resources.get(DEEPLOY_RESOURCES.MEMORY, DEFAULT_CONTAINER_RESOURCES.MEMORY)
    required_cpu = required_resources.get(DEEPLOY_RESOURCES.CPU, DEFAULT_CONTAINER_RESOURCES.CPU)

    required_mem_bytes = self._parse_memory(required_mem)

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
