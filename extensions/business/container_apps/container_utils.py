"""
container_utils.py
The utility mixin for container management used by ContainerAppRunnerPlugin

"""

import subprocess
import socket

# Path for container volumes
CONTAINER_VOLUMES_PATH = "/edge_node/_local_cache/_data/container_volumes"


class _ContainerUtilsMixin:

  ### START CONTAINER MIXIN METHODS ###
  
  def _get_cr_data(self):
    """
    Helper method to extract container registry data from configuration.
    
    Returns:
        tuple: (cr_server, cr_username, cr_password) extracted from cfg_cr_data
    """
    cr_data = getattr(self, 'cfg_cr_data', {})
    cr_server = cr_data.get('SERVER')
    cr_username = cr_data.get('USERNAME')
    cr_password = cr_data.get('PASSWORD')
    return cr_server, cr_username, cr_password

  def _login_to_registry(self):
    """
    Login to a private container registry using credentials from _get_cr_data.
    
    Returns:
        bool: True if login successful, False otherwise
    """
    cr_server, cr_username, cr_password = self._get_cr_data()
    self.P(f"Container registry data: SERVER={cr_server}, USERNAME={cr_username}, PASSWORD={'***' if cr_password else None}")
    # Skip login if no credentials provided
    if not cr_username or not cr_password or not cr_server:
      self.P("No registry credentials provided, skipping login", color='y')
      return True

    self.P(f"Logging into container registry: {cr_server}", color='b')

    try:
      result = self.docker_client.login(
        username=cr_username,
        password=cr_password,
        registry=cr_server
      )
      self.P(f"Successfully logged into registry {cr_server}", color='g')
      return True
    except Exception as e:
      self.P(f"Docker client login failed: {e}", color='y')

    return False

  def _get_default_env_vars(self):
    """
    Get the default environment variables for the container.

    WARNING: This is a critical method that should be thoroughly reviewed for attack vectors.

    Returns:
        dict: Default environment variables.
    """
    localhost_ip = self.log.get_localhost_ip()
    chainstore_peers = getattr(self, 'cfg_chainstore_peers', [])
    str_chainstore_peers = self.json_dumps(chainstore_peers)
    dct_env = {
      "CONTAINER_NAME": self.container_name,
      "EE_CONTAINER_NAME": self.container_name,
      "EE_HOST_IP": localhost_ip,
      "EE_HOST_ID": self.ee_id,
      "EE_HOST_ADDR": self.ee_addr,
      "EE_HOST_ETH_ADDR": self.bc.eth_address,
      "EE_CHAINSTORE_API_URL": f"http://{localhost_ip}:31234",
      "EE_R1FS_API_URL": f"http://{localhost_ip}:31235",
      "EE_CHAINSTORE_PEERS": str_chainstore_peers,
    }

    return dct_env

  def _maybe_send_plugin_start_confirmation(self):
    """
    Sets up confirmation data about plugin start in CHAINSTORE.
    TODO: Generalize this function and move it to the base class.
    """
    response_key = getattr(self, 'cfg_chainstore_response_key', None)
    if response_key is not None:
      N_CONFIRMATIONS = 3
      self.P(f"Responding to key {response_key} in {N_CONFIRMATIONS} confirmations")
      response_info = {
        'container_id': self.container_id,
        'start_time': self.time_to_str(self.container_start_time),
        'ports_mapping': self.extra_ports_mapping,
      }
      for confirmation in range(N_CONFIRMATIONS):
        self.P(f"Sending confirmation {confirmation + 1} to {response_key}: {self.json_dumps(response_info)}")
        response_info['confirmation'] = confirmation + 1
        to_save = self.deepcopy(response_info)
        self.chainstore_set(response_key, to_save)
        self.sleep(0.100) # wait 100 ms
    return


  def _setup_dynamic_env_var_host_ip(self):
    """ Definition for `host_ip` dynamic env var type. """
    return self.log.get_localhost_ip()

  def _setup_dynamic_env_var_some_other_calc_type(self):
    """ Example definition for `some_other_calc_type` dynamic env var type. """
    return "some_other_value"


  def _configure_dynamic_env(self):
    """
    Set up dynamic environment variables based on the configuration.

    This method iterates over the `cfg_dynamic_env` dictionary, which contains
    environment variable names as keys and a list of value parts as values. Each
    value part specifies its type (e.g., "static" or "host_ip") and its value.
    The method constructs the final value for each environment variable by
    concatenating its parts.
    """
    if len(self.cfg_dynamic_env):
      for variable_name, variable_value_list  in self.cfg_dynamic_env.items():
        variable_value = ''
        for variable_part in variable_value_list:
          part_type = variable_part['type']
          candidate_value = variable_part.get('value', 'UNK')
          if part_type != "static" :
            func_name = f"_setup_dynamic_env_var_{part_type}"
            found = False
            if hasattr(self, func_name):
              func = getattr(self, func_name)
              if callable(func):
                # Call the function and append its result to the variable value
                try:
                  candidate_value = func()
                  found = True
                except:
                  self.P(f"Error calling function {func_name} for dynamic env var {variable_name}", color='r')
              #endif callable
            #endif hasattr
            if not found:
              self.P(f"Dynamic env var {variable_name} has invalid type: {part_type}", color='r')
          # endif part_type
          variable_value += candidate_value
        # endfor each part
        self.dynamic_env[variable_name] = variable_value
        self.P(f"Dynamic env var {variable_name} = {variable_value}")
      #endfor each variable

  ## END CONTAINER MIXIN ###

  ### NEW CONTAINER MIXIN METHODS ###
  # Don't change the signature of this method as it overwrites the base class method.
  def _allocate_port(self, required_port=0, allow_dynamic=False, sleep_time=5):
    """
    Allocates an available port on the host system for container port mapping.

    This method finds an available port on the host system that can be used for container port mapping.
    If required_port is 0 (default), the OS will automatically select any available port.
    If required_port is specified, the method will attempt to bind to that specific port.

    The method uses a socket-based approach to port allocation:
    1. Creates a new TCP socket
    2. Sets SO_REUSEADDR option to allow immediate reuse of the port
    3. Binds to the specified port (or any available port if 0)
    4. Retrieves the actual port number that was bound
    5. Closes the socket to release it for actual use

    Args:
        required_port (int, optional): The specific port number to allocate.
            If 0 (default), the OS will select any available port.

    Returns:
        int: The allocated port number. This will be the same as required_port if specified
             and available, or a randomly assigned port if required_port is 0.

    Note:
        The socket is closed immediately after port allocation to allow the port to be used
        by the container. This is a common technique for port allocation in container runtimes.
    """
    port = None
    if required_port != 0:
      self.P(f"Trying to allocate requested port {required_port} ...")
      done = False
      while not done:
        try:
          sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
          sock.bind(("", required_port))
          port = sock.getsockname()[1]
          sock.close()
          done = True
        except Exception as e:
          port = None
          if allow_dynamic:
            self.P(f"Failed to allocate requested port {required_port}: {e}", color='r')
            done = True  # if allow_dynamic is True, we stop trying to bind to the required port
            required_port = 0  # reset to allow dynamic port allocation
          else:
            self.P(f"Port {required_port} is not available. Retrying in {sleep_time} seconds...", color='r')
            self.sleep(sleep_time)  # wait before retrying
        # endtry
      # endwhile done
    # endif required_port != 0

    if required_port == 0 and port is None:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.bind(("", 0))
      port = sock.getsockname()[1]
      sock.close()
    # endif
    return port

  def _setup_resource_limits_and_ports(self):
    """
    Sets up resource limits for the container based on the configuration.
    """
    DEFAULT_CPU_LIMIT = 1
    DEFAULT_GPU_LIMIT = 0
    DEFAULT_MEM_LIMIT = "512m"
    DEFAULT_PORTS = []

    container_resources = self.cfg_container_resources
    if isinstance(container_resources, dict) and len(container_resources) > 0:
      self._cpu_limit = container_resources.get("cpu", DEFAULT_CPU_LIMIT)
      self._gpu_limit = container_resources.get("gpu", DEFAULT_GPU_LIMIT)
      self._mem_limit = container_resources.get("memory", DEFAULT_MEM_LIMIT)

      ports = container_resources.get("ports", DEFAULT_PORTS)

      if len(ports) > 0:
        if isinstance(ports, list):
          # Handle list of container ports
          for container_port in ports:
            self.P(f"Additional container port {container_port} specified. Finding available host port ...")
            host_port = self._allocate_port()
            self.extra_ports_mapping[host_port] = container_port
            self.P(f"Allocated free host port {host_port} for container port {container_port}.")
        else:
          # Handle dict of port mappings
          # Check if main app port is mapped to a specific host port
          if self.cfg_port and isinstance(ports, dict) and self.cfg_port in ports.values():
            container_port = self.cfg_port
            requested_host_port = int(next((k for k, v in ports.items() if v == container_port), 0))

            self.P(f"Main app port {self.cfg_port} is not mapped to any host port in the ports dict. Allocating a new host port ...")

            self.port = self._allocate_port(requested_host_port, allow_dynamic=True)

            if self.port != requested_host_port:
              self.P(f"Requested host port {requested_host_port} is not available. Allocated port {self.port} instead.")

            self.extra_ports_mapping[self.port] = container_port

          for host_port, container_port in ports.items():
            try:
              host_port = int(host_port)
              if host_port in self.extra_ports_mapping:
                self.Pd(f"Host port {host_port} is already allocated for container port {self.extra_ports_mapping[host_port]}. Skipping allocation.")
                continue
              self._allocate_port(host_port)
              self.extra_ports_mapping[host_port] = container_port
            except Exception as e:
              self.P(f"Port {host_port} is not available.")
              self.P(e)
              raise RuntimeError(f"Port {host_port} is not available.")
          # endfor each port
        # endif ports list or dict
      # endif ports
    else:
      self._cpu_limit = DEFAULT_CPU_LIMIT
      self._gpu_limit = DEFAULT_GPU_LIMIT
      self._mem_limit = DEFAULT_MEM_LIMIT
    # endif resource limits

    if not self.port and self.cfg_port:
      self.port = self._allocate_port(allow_dynamic=True)  # Allocate a port for the container if needed
    return

  def _configure_volumes(self):
    """
    Processes the volumes specified in the configuration.
    """
    default_volume_rights = "rw"
    if hasattr(self, 'cfg_volumes') and self.cfg_volumes and len(self.cfg_volumes) > 0:
      for host_path, container_path in self.cfg_volumes.items():
        original_path = str(host_path)
        sanitized_name = self.sanitize_name(original_path)

        # Prefix the sanitized name with the instance ID
        prefixed_name = f"{self.cfg_instance_id}_{sanitized_name}"
        self.P(f"  Converted '{original_path}' → named volume '{prefixed_name}'")

        full_host_path = self.os_path.join(CONTAINER_VOLUMES_PATH, prefixed_name)
        self.volumes[full_host_path] = {"bind": container_path, "mode": default_volume_rights}

      # endfor each host path
    # endif volumes
    return


  ### END NEW CONTAINER MIXIN METHODS ###

  ### COMMON CONTAINER UTILITY METHODS ###
  def _setup_env_and_ports(self):
    # Environment variables
    # allow cfg_env to override default env vars
    self.env = self._get_default_env_vars()
    self.env.update(self.dynamic_env)
    if self.cfg_env:
      self.env.update(self.cfg_env)
    if self.dynamic_env:
      self.env.update(self.dynamic_env)
    # endif dynamic env

    # Ports mapping
    ports_mapping = self.extra_ports_mapping.copy() if self.extra_ports_mapping else {}
    if self.cfg_port and self.port:
      ports_mapping[self.port] = self.cfg_port
    # end if main port
    self.inverted_ports_mapping = {f"{v}/tcp": str(k) for k, v in ports_mapping.items()}

    return

  def _validate_container_config(self):
    """Validate container configuration before starting."""
    if not self.cfg_image:
      raise ValueError("IMAGE is required")

    if not isinstance(self.cfg_image, str):
      raise ValueError("IMAGE must be a string")

    # Validate container resources if provided
    if hasattr(self, 'cfg_container_resources') and self.cfg_container_resources:
      if not isinstance(self.cfg_container_resources, dict):
        raise ValueError("CONTAINER_RESOURCES must be a dictionary")

    # Validate environment variables if provided
    if hasattr(self, 'cfg_env') and self.cfg_env:
      if not isinstance(self.cfg_env, dict):
        raise ValueError("ENV must be a dictionary")

    return True

  def _get_container_health_status(self, container=None):
    """Get container health status using Docker client."""
    if container is None:
      container = getattr(self, 'container', None)

    if container is None:
      return "not_started"

    try:
      container.reload()
      return container.status
    except Exception as e:
      self.P(f"Error checking container health: {e}", color='r')
      return "error"


  def _validate_git_config(self):
    """Validate Git configuration for repository access."""
    if not hasattr(self, 'cfg_git_repo_owner') or not hasattr(self, 'cfg_git_repo_name'):
      return False

    if not self.cfg_git_repo_owner or not self.cfg_git_repo_name:
      self.P("Git repository owner or name not configured", color='y')
      return False

    # Check if we have credentials for private repos
    if hasattr(self, 'cfg_git_token') and not self.cfg_git_token:
      self.P("Warning: No Git token provided, repository must be public", color='y')

    return True

  def _validate_endpoint_config(self):
    """Validate endpoint configuration for health checks."""
    if not hasattr(self, 'cfg_endpoint_url') or not self.cfg_endpoint_url:
      return False

    # Basic URL validation
    if not isinstance(self.cfg_endpoint_url, str):
      self.P("Endpoint URL must be a string", color='r')
      return False

    if not self.cfg_endpoint_url.startswith('/'):
      self.P("Endpoint URL must start with '/'", color='r')
      return False

    if '..' in self.cfg_endpoint_url:
      self.P("Endpoint URL contains invalid path traversal", color='r')
      return False

    return True

  def _get_container_info(self):
    """Get comprehensive container information."""
    container = getattr(self, 'container', None)
    info = {
      'container_id': container.short_id if container else None,
      'container_name': getattr(self, 'container_name', None),
      'image': getattr(self, 'cfg_image', None),
      'status': self._get_container_health_status(container),
      'port': getattr(self, 'port', None),
      'start_time': getattr(self, 'container_start_time', None),
    }

    if hasattr(self, 'extra_ports_mapping') and self.extra_ports_mapping:
      info['extra_ports'] = self.extra_ports_mapping

    if hasattr(self, 'volumes') and self.volumes:
      info['volumes'] = self.volumes

    return info

  def _log_container_info(self):
    """Log comprehensive container information."""
    info = self._get_container_info()
    self.P("Container Information:", color='b')
    for key, value in info.items():
      if value is not None:
        self.P(f"  {key}: {value}", color='d')

  def _validate_port_allocation(self, port):
    """Validate that a port is properly allocated."""
    if not port:
      return False

    if not isinstance(port, int):
      return False

    if port < 1 or port > 65535:
      return False

    return True

  def _safe_get_container_stats(self):
    """Safely get container statistics without raising exceptions."""
    container = getattr(self, 'container', None)
    if not container:
      return None

    try:
      container.reload()
      return {
        'id': container.short_id,
        'status': container.status,
        'running': container.status == "running",
        'image': container.image.tags[0] if container.image.tags else str(container.image.id),
        'created': container.attrs.get('Created', 'Unknown'),
        'ports': container.attrs.get('NetworkSettings', {}).get('Ports', {})
      }
    except Exception as e:
      self.P(f"Error getting container stats: {e}", color='r')
      return None

  def _validate_docker_image_format(self, image_name):
    """Validate Docker image name format."""
    if not isinstance(image_name, str):
      return False
    
    # Basic validation - should contain at least one colon or slash
    if ':' not in image_name and '/' not in image_name:
      return False
    
    # Check for invalid characters
    invalid_chars = [' ', '\t', '\n', '\r']
    for char in invalid_chars:
      if char in image_name:
        return False
    
    return True

  ### END COMMON CONTAINER UTILITY METHODS ###