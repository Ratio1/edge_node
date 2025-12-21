"""
container_utils.py
The utility mixin for container management used by ContainerAppRunnerPlugin

"""

import os
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
      "R1EN_CONTAINER_NAME": self.container_name,
      "EE_HOST_IP": localhost_ip,
      "R1EN_HOST_IP": localhost_ip,
      "EE_HOST_ID": self.ee_id,
      "R1EN_HOST_ID": self.ee_id,
      "EE_HOST_ADDR": self.ee_addr,
      "R1EN_HOST_ADDR": self.ee_addr,
      "EE_HOST_ETH_ADDR": self.bc.eth_address,
      "R1EN_HOST_ETH_ADDR": self.bc.eth_address,
      "EE_EVM_NET": self.bc.get_evm_network(),
      "R1EN_EVM_NET": self.bc.get_evm_network(),
      "EE_CHAINSTORE_API_URL": f"http://{localhost_ip}:31234",
      "R1EN_CHAINSTORE_API_URL": f"http://{localhost_ip}:31234",
      "EE_R1FS_API_URL": f"http://{localhost_ip}:31235",
      "R1EN_R1FS_API_URL": f"http://{localhost_ip}:31235",
      "EE_CHAINSTORE_PEERS": str_chainstore_peers,
      "R1EN_CHAINSTORE_PEERS": str_chainstore_peers,
      
      # OBSERVATION: From now on only add new env vars with R1EN_ prefix
      #              to avoid missunderstandings with EE_ prefixed vars that
      #              are legacy from the Edge Node environment itself.
    }

    # Add semaphore keys if present
    semaphored_keys = getattr(self, 'cfg_semaphored_keys', None)
    if semaphored_keys:
      dct_env["R1EN_SEMAPHORED_KEYS"] = self.json_dumps(semaphored_keys)

    return dct_env

  def _get_chainstore_response_data(self):
    """
    Build container-specific response data for chainstore.

    This method overrides the base mixin implementation to provide
    container-specific information in the response.

    Returns:
        dict: Response data including container details, ports, and timing info.
    """
    # Start with base plugin data (from _ChainstoreResponseMixin)
    # Note: Since this mixin is used alongside _ChainstoreResponseMixin,
    # we should check if super() provides base data
    try:
      # Try to get base data if _ChainstoreResponseMixin is in the MRO
      data = super()._get_chainstore_response_data()
    except (AttributeError, TypeError):
      # Fallback if _ChainstoreResponseMixin is not in the inheritance chain
      data = {
        'plugin_signature': self.__class__.__name__,
        'instance_id': getattr(self, 'cfg_instance_id', None),
        'timestamp': self.time_to_str(self.time()) if hasattr(self, 'time_to_str') else None,
      }

    # Add container-specific information
    data.update({
      'container_id': getattr(self, 'container_id', None),
      'container_name': getattr(self, 'container_name', None),
      'start_time': self.time_to_str(self.container_start_time) if hasattr(self, 'container_start_time') else None,
      'ports_mapping': getattr(self, 'extra_ports_mapping', {}),
      'main_port': getattr(self, 'port', None),
      'image': getattr(self, 'cfg_image', None),
    })

    return data

  def _setup_dynamic_env_var_host_ip(self):
    """
    Get host IP address for dynamic environment variable.

    Returns
    -------
    str
        The localhost IP address
    """
    return self.log.get_localhost_ip()

  def _setup_dynamic_env_var_some_other_calc_type(self):
    """
    Example dynamic environment variable calculator.

    This is an example method showing how to implement custom dynamic
    environment variable types.

    Returns
    -------
    str
        Example static value
    """
    return "some_other_value"


  def _configure_dynamic_env(self):
    """
    Set up dynamic environment variables based on configuration.

    This method processes the cfg_dynamic_env dictionary, constructing
    environment variable values by concatenating parts that can be either
    static strings or dynamically computed values.

    Returns
    -------
    None

    Notes
    -----
    Dynamic parts are computed by calling methods named _setup_dynamic_env_var_{type}.
    For example, a part with type "host_ip" calls _setup_dynamic_env_var_host_ip().

    Examples
    --------
    cfg_dynamic_env format:
        {
          "MY_VAR": [
            {"type": "static", "value": "prefix_"},
            {"type": "host_ip"},
            {"type": "static", "value": "_suffix"}
          ]
        }
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
    Sets up resource limits and port mappings for the container based on configuration.

    Port Handling Logic:
      1. Process all ports from CONTAINER_RESOURCES["ports"] first
      2. If main PORT exists and not in ports mapping, allocate it
      3. All ports (including main PORT) go into extra_ports_mapping
      4. Validate no duplicate container ports

    Priority:
      - Explicit mappings in CONTAINER_RESOURCES["ports"] take precedence
      - Main PORT is allocated dynamically if not explicitly mapped
    """
    DEFAULT_CPU_LIMIT = 1
    DEFAULT_GPU_LIMIT = 0
    DEFAULT_MEM_LIMIT = "512m"
    DEFAULT_PORTS = []

    container_resources = self.cfg_container_resources
    if isinstance(container_resources, dict) and len(container_resources) > 0:
      self._cpu_limit = float(container_resources.get("cpu", DEFAULT_CPU_LIMIT))
      self._gpu_limit = container_resources.get("gpu", DEFAULT_GPU_LIMIT)
      self._mem_limit = container_resources.get("memory", DEFAULT_MEM_LIMIT)

      ports = container_resources.get("ports", DEFAULT_PORTS)

      # Track which container ports have been mapped to avoid duplicates
      mapped_container_ports = set()
      main_port_mapped = False

      if len(ports) > 0:
        if isinstance(ports, list):
          # Handle list of container ports - allocate dynamic host ports
          self.P("Processing container ports list...")
          for container_port in ports:
            if container_port in mapped_container_ports:
              self.P(f"Warning: Container port {container_port} already mapped, skipping duplicate", color='y')
              continue

            self.P(f"Container port {container_port} specified. Finding available host port...")
            host_port = self._allocate_port()
            self.extra_ports_mapping[host_port] = container_port
            mapped_container_ports.add(container_port)
            self.P(f"Allocated host port {host_port} -> container port {container_port}")

            # Check if this is the main port
            if self.cfg_port and container_port == self.cfg_port:
              self.port = host_port
              main_port_mapped = True
              self.P(f"Main PORT {self.cfg_port} mapped to host port {host_port}", color='g')

        elif isinstance(ports, dict):
          # Handle dict of explicit host_port -> container_port mappings
          self.P("Processing explicit port mappings...")

          # First, validate for duplicate container ports
          container_ports_in_dict = list(ports.values())
          if len(container_ports_in_dict) != len(set(container_ports_in_dict)):
            raise ValueError(
              f"Duplicate container ports found in CONTAINER_RESOURCES['ports']: {ports}. "
              "Each container port can only be mapped once."
            )

          # Process all explicit mappings
          for host_port, container_port in ports.items():
            try:
              host_port = int(host_port)
              container_port = int(container_port)

              # Check if this mapping was already processed
              if host_port in self.extra_ports_mapping:
                existing_container_port = self.extra_ports_mapping[host_port]
                if existing_container_port == container_port:
                  self.Pd(f"Port mapping {host_port}->{container_port} already exists, skipping")
                  continue
                else:
                  raise ValueError(
                    f"Host port {host_port} is already mapped to container port {existing_container_port}. "
                    f"Cannot map it to {container_port}"
                  )

              # Allocate the requested host port
              self.P(f"Allocating requested host port {host_port} for container port {container_port}...")
              allocated_port = self._allocate_port(host_port, allow_dynamic=False)

              if allocated_port != host_port:
                raise RuntimeError(
                  f"Failed to allocate requested host port {host_port}. "
                  f"Port may be in use by another process."
                )

              self.extra_ports_mapping[host_port] = container_port
              mapped_container_ports.add(container_port)
              self.P(f"Allocated host port {host_port} -> container port {container_port}", color='g')

              # Check if this is the main port
              if self.cfg_port and container_port == self.cfg_port:
                self.port = host_port
                main_port_mapped = True
                self.P(f"Main PORT {self.cfg_port} mapped to host port {host_port} (from explicit mapping)", color='g')

            except ValueError as e:
              raise ValueError(f"Invalid port mapping {host_port}:{container_port} - {e}")
            except Exception as e:
              self.P(f"Failed to allocate port {host_port}: {e}", color='r')
              raise RuntimeError(f"Port allocation failed for {host_port}:{container_port}")
        else:
          self.P(f"Invalid ports configuration type: {type(ports)}. Expected list or dict.", color='r')

      # Handle main PORT if it exists and wasn't mapped yet
      if self.cfg_port and not main_port_mapped:
        if self.cfg_port in mapped_container_ports:
          # Main PORT was mapped to a different host port in the loop above
          # Find which host port it was mapped to
          for h_port, c_port in self.extra_ports_mapping.items():
            if c_port == self.cfg_port:
              self.port = h_port
              self.P(f"Main PORT {self.cfg_port} already mapped to host port {h_port}", color='d')
              break
        else:
          # Allocate a dynamic host port for the main PORT
          self.P(f"Main PORT {self.cfg_port} not in explicit mappings. Allocating dynamic host port...")
          self.port = self._allocate_port(allow_dynamic=True)
          self.extra_ports_mapping[self.port] = self.cfg_port
          mapped_container_ports.add(self.cfg_port)
          self.P(f"Allocated host port {self.port} -> main PORT {self.cfg_port}", color='g')
        # endif main PORT
      # endif main_port_mapped
    else:
      # No container resources specified, use defaults
      self._cpu_limit = float(DEFAULT_CPU_LIMIT)
      self._gpu_limit = DEFAULT_GPU_LIMIT
      self._mem_limit = DEFAULT_MEM_LIMIT

      # Still handle main PORT if specified
      if self.cfg_port:
        self.P(f"No CONTAINER_RESOURCES specified. Allocating dynamic host port for main PORT {self.cfg_port}...")
        self.port = self._allocate_port(allow_dynamic=True)
        self.extra_ports_mapping[self.port] = self.cfg_port
        self.P(f"Allocated host port {self.port} -> main PORT {self.cfg_port}", color='g')
      # endif main PORT
    # endif container_resources
    return

  def _set_directory_permissions(self, path, mode=0o777):
    """
    Set directory permissions to allow non-root container access.

    Parameters
    ----------
    path : str
        Directory path to modify
    mode : int, optional
        Permission mode in octal notation (default: 0o777)

    Returns
    -------
    None

    Notes
    -----
    Failures are logged but do not raise exceptions. This is by design
    to allow containers to attempt access even if permission changes fail.
    """
    try:
      os.chmod(path, mode)
    except PermissionError:
      self.P(
        f"Permission denied when adjusting permissions for '{path}'. Container access may fail.",
        color='y'
      )
    except OSError as exc:
      self.P(
        f"Failed to adjust permissions for '{path}': {exc}",
        color='y'
      )

  def _configure_volumes(self):
    """
    Processes the volumes specified in the configuration.
    """
    default_volume_rights = "rw"
    if hasattr(self, 'cfg_volumes') and self.cfg_volumes and len(self.cfg_volumes) > 0:
      os.makedirs(CONTAINER_VOLUMES_PATH, exist_ok=True)
      self._set_directory_permissions(CONTAINER_VOLUMES_PATH)
      for host_path, container_path in self.cfg_volumes.items():
        original_path = str(host_path)
        sanitized_name = self.sanitize_name(original_path)

        # Prefix the sanitized name with the instance ID
        prefixed_name = f"{self.cfg_instance_id}_{sanitized_name}"
        self.P(f"  Converted '{original_path}' → named volume '{prefixed_name}'")

        host_volume_path = self.os_path.join(CONTAINER_VOLUMES_PATH, prefixed_name)
        try:
          os.makedirs(host_volume_path, exist_ok=True)
        except PermissionError as exc:
          raise RuntimeError(
            f"Insufficient permissions to create volume directory '{host_volume_path}': {exc}"
          ) from exc
        except OSError as exc:
          raise RuntimeError(
            f"Failed to prepare volume directory '{host_volume_path}': {exc}"
          ) from exc

        self._set_directory_permissions(host_volume_path)

        self.volumes[host_volume_path] = {"bind": container_path, "mode": default_volume_rights}

      # endfor each host path
    # endif volumes
    return

  def _configure_file_volumes(self):
    """
    Processes FILE_VOLUMES configuration to create files with specified content
    and mount them into the container.
    
    FILE_VOLUMES format:
      {
        "logical_name": {
          "content": "file content here...",
          "mounting_point": "/container/path/to/filename.ext"
        }
      }
    
    The method will:
      1. Extract filename from mounting_point
      2. Create a directory under CONTAINER_VOLUMES_PATH
      3. Write content to a file with the extracted filename
      4. Add volume mapping to self.volumes
    """
    default_volume_rights = "rw"
    
    if not hasattr(self, 'cfg_file_volumes') or not self.cfg_file_volumes:
      return
    
    if not isinstance(self.cfg_file_volumes, dict):
      self.P("FILE_VOLUMES must be a dictionary, skipping file volume configuration", color='r')
      return
    
    os.makedirs(CONTAINER_VOLUMES_PATH, exist_ok=True)
    self._set_directory_permissions(CONTAINER_VOLUMES_PATH)
    
    for logical_name, file_config in self.cfg_file_volumes.items():
      try:
        # Validate file_config structure
        if not isinstance(file_config, dict):
          self.P(f"FILE_VOLUMES['{logical_name}'] must be a dict with 'content' and 'mounting_point', skipping", color='r')
          continue
        
        content = file_config.get('content')
        mounting_point = file_config.get('mounting_point')
        
        if content is None:
          self.P(f"FILE_VOLUMES['{logical_name}'] missing 'content' field, skipping", color='r')
          continue
        
        if not mounting_point:
          self.P(f"FILE_VOLUMES['{logical_name}'] missing 'mounting_point' field, skipping", color='r')
          continue
        
        # Extract filename from mounting_point
        mounting_point = str(mounting_point)
        path_parts = mounting_point.rstrip('/').split('/')
        filename = path_parts[-1]
        
        if not filename:
          self.P(f"FILE_VOLUMES['{logical_name}'] could not extract filename from mounting_point '{mounting_point}', skipping", color='r')
          continue
        
        # Create sanitized directory for this file volume
        sanitized_name = self.sanitize_name(str(logical_name))
        prefixed_name = f"{self.cfg_instance_id}_{sanitized_name}"
        self.P(f"  Processing file volume '{logical_name}' → '{prefixed_name}/{filename}' → container '{mounting_point}'")
        
        # Create host directory
        host_volume_dir = self.os_path.join(CONTAINER_VOLUMES_PATH, prefixed_name)
        try:
          os.makedirs(host_volume_dir, exist_ok=True)
        except PermissionError as exc:
          raise RuntimeError(
            f"Insufficient permissions to create file volume directory '{host_volume_dir}': {exc}"
          ) from exc
        except OSError as exc:
          raise RuntimeError(
            f"Failed to prepare file volume directory '{host_volume_dir}': {exc}"
          ) from exc
        
        self._set_directory_permissions(host_volume_dir)
        
        # Write content to file
        host_file_path = self.os_path.join(host_volume_dir, filename)
        try:
          # Ensure content is a string
          content_str = str(content)
          with open(host_file_path, 'w', encoding='utf-8') as f:
            f.write(content_str)
          self.P(f"    Created file: {host_file_path} ({len(content_str)} chars)")
          
          # Set file permissions (readable by all, writable by owner)
          try:
            os.chmod(host_file_path, 0o644)
          except (PermissionError, OSError) as exc:
            self.P(f"    Warning: Could not set permissions for '{host_file_path}': {exc}", color='y')
          
        except PermissionError as exc:
          raise RuntimeError(
            f"Insufficient permissions to write file '{host_file_path}': {exc}"
          ) from exc
        except OSError as exc:
          raise RuntimeError(
            f"Failed to write file '{host_file_path}': {exc}"
          ) from exc
        
        # Add volume mapping (file-level mount)
        self.volumes[host_file_path] = {
          "bind": mounting_point,
          "mode": default_volume_rights
        }
        self.P(f"    Mapped: {host_file_path} → {mounting_point}", color='g')
        
      except Exception as exc:
        self.P(
          f"Error configuring file volume '{logical_name}': {exc}",
          color='r'
        )
        # Continue processing other file volumes
        continue
    
    # endfor each file volume
    return


  ### END NEW CONTAINER MIXIN METHODS ###

  ### COMMON CONTAINER UTILITY METHODS ###
  def _setup_env_and_ports(self):
    """
    Sets up environment variables and formats port mappings for Docker.

    This method should NOT allocate ports - only format already-allocated ports.
    All port allocations happen in _setup_resource_limits_and_ports.

    Environment variable precedence (later overrides earlier):
      1. Default env vars (system-provided)
      2. Dynamic env vars (computed at runtime)
      3. Semaphore env vars (from paired provider plugins)
      4. cfg_env (user-configured)
    """
    # Environment variables
    # allow cfg_env to override default env vars
    self.env = self._get_default_env_vars()
    self.env.update(self.dynamic_env)

    # Add environment variables from semaphored paired plugins
    if hasattr(self, 'semaphore_get_env'):
      semaphore_env = self.semaphore_get_env()
      if semaphore_env:
        log_lines = [
          "=" * 60,
          "SEMAPHORE ENV INJECTION",
          "=" * 60,
          f"  Adding {len(semaphore_env)} env vars from semaphored plugins:",
        ]
        for key, value in semaphore_env.items():
          log_lines.append(f"    {key} = {value}")
        log_lines.append("=" * 60)
        self.Pd("\n".join(log_lines))
        self.env.update(semaphore_env)
    # endif semaphore env

    if self.cfg_env:
      self.env.update(self.cfg_env)
    if self.dynamic_env:
      self.env.update(self.dynamic_env)
    # endif dynamic env

    # Format ports for Docker API
    # Docker expects: {"container_port/tcp": "host_port"}
    # extra_ports_mapping contains: {host_port: container_port}
    # All ports (including main PORT) are already in extra_ports_mapping
    self.inverted_ports_mapping = {
      f"{container_port}/tcp": str(host_port)
      for host_port, container_port in self.extra_ports_mapping.items()
    }

    # Log the final port mapping
    if self.inverted_ports_mapping:
      self.P("Final port mappings:", color='b')
      for container_port, host_port in self.inverted_ports_mapping.items():
        is_main = "(main)" if self.cfg_port and str(self.cfg_port) in container_port else ""
        self.P(f"  Container {container_port} -> Host {host_port} {is_main}", color='d')

    return

  def _validate_container_config(self):
    """
    Validate container configuration before starting container.

    Checks that required configuration fields are present and properly
    formatted, including IMAGE, CONTAINER_RESOURCES, and ENV.

    Returns
    -------
    bool
        Always returns True if validation passes

    Raises
    ------
    ValueError
        If IMAGE is missing, not a string, or if CONTAINER_RESOURCES
        or ENV have invalid types
    """
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
    """
    Get container health status using Docker client.

    Parameters
    ----------
    container : docker.models.containers.Container, optional
        Container object to check. If None, uses self.container

    Returns
    -------
    str
        Container status: 'running', 'stopped', 'not_started', or 'error'
    """
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


  def _validate_health_endpoint_config(self):
    """
    Validate health endpoint configuration.

    Performs security and format validation on the configured
    health endpoint path.

    Returns
    -------
    bool
        True if health endpoint configuration is valid, False otherwise

    Notes
    -----
    Validation checks include:
    - Path is a string
    - Path starts with '/'
    - Path does not contain path traversal sequences (..)
    """
    if not hasattr(self, 'cfg_health_endpoint_path') or not self.cfg_health_endpoint_path:
      return False

    path = self.cfg_health_endpoint_path

    # Basic path validation
    if not isinstance(path, str):
      self.P("Health endpoint path must be a string", color='r')
      return False

    if not path.startswith('/'):
      self.P("Health endpoint path must start with '/'", color='r')
      return False

    if '..' in path:
      self.P("Health endpoint path contains invalid path traversal", color='r')
      return False

    return True

  def _get_container_info(self):
    """
    Get comprehensive container information.

    Collects container metadata including ID, status, ports, and volumes
    into a single dictionary.

    Returns
    -------
    dict
        Container information with keys: container_id, container_name,
        image, status, port, start_time, and optionally extra_ports
        and volumes
    """
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
    """
    Log comprehensive container information to console.

    Formats and prints container metadata obtained from
    _get_container_info() in a readable format.

    Returns
    -------
    None
    """
    info = self._get_container_info()
    self.P("Container Information:", color='b')
    for key, value in info.items():
      if value is not None:
        self.P(f"  {key}: {value}", color='d')

  def _validate_port_allocation(self, port):
    """
    Validate that a port number is properly allocated.

    Parameters
    ----------
    port : int
        Port number to validate

    Returns
    -------
    bool
        True if port is valid (1-65535), False otherwise
    """
    if not port:
      return False

    if not isinstance(port, int):
      return False

    if port < 1 or port > 65535:
      return False

    return True

  def _safe_get_container_stats(self):
    """
    Safely get container statistics without raising exceptions.

    Returns
    -------
    dict or None
        Dictionary containing container stats (id, status, running, image,
        created, ports) or None if container doesn't exist or error occurs
    """
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
    """
    Validate Docker image name format.

    Parameters
    ----------
    image_name : str
        Docker image name to validate

    Returns
    -------
    bool
        True if image name format is valid, False otherwise

    Notes
    -----
    Validation checks:
    - Must be a string
    - Must contain at least one ':' (tag) or '/' (repository)
    - Must not contain whitespace characters
    """
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

  ### EXTRA TUNNELS METHODS ###

  def _normalize_extra_tunnel_config(self, container_port, config):
    """
    Normalize extra tunnel config to standard format.

    Currently supports simple string format: "token"
    Named "tunnel config" for future extensibility (e.g., dict with engine, enabled, etc.)

    Args:
      container_port: Container port (int)
      config: Token string (future: could be dict with {"token": str, "engine": str, "enabled": bool})

    Returns:
      str: Normalized token string (future: could return dict)

    Note:
      This method is designed to be extended in the future to support more complex
      tunnel configurations beyond simple token strings, such as:
      - Different tunnel engines (cloudflare, ngrok, custom)
      - Per-tunnel enabled/disabled flags
      - Custom tunnel parameters
      For now, it only handles string tokens for simplicity.
    """
    if isinstance(config, str):
      return config.strip()
    else:
      raise ValueError(
        f"EXTRA_TUNNELS[{container_port}] must be a string token, got {type(config)}"
      )

  def _allocate_extra_tunnel_ports(self, container_ports):
    """
    Allocate host ports for container ports defined only in EXTRA_TUNNELS.

    This handles the case where CONTAINER_RESOURCES["ports"] is empty but
    EXTRA_TUNNELS defines ports that need to be exposed.

    Parameters
    ----------
    container_ports : list of int
        List of container ports to allocate

    Returns
    -------
    None
    """
    self.P(f"Allocating host ports for {len(container_ports)} EXTRA_TUNNELS ports...", color='b')

    for container_port in container_ports:
      # Check if already allocated (shouldn't be, but safety check)
      if container_port in self.extra_ports_mapping.values():
        self.Pd(f"Port {container_port} already allocated, skipping")
        continue

      # Allocate dynamic host port
      host_port = self._allocate_port(allow_dynamic=True)
      self.extra_ports_mapping[host_port] = container_port

      self.P(f"  Allocated host port {host_port} -> container port {container_port}", color='g')

      # Special handling if this is the main PORT
      if self.cfg_port == container_port and not self.port:
        self.port = host_port
        self.P(f"  Main PORT {container_port} mapped to host port {host_port}", color='g')

    # Rebuild inverted_ports_mapping for Docker
    self.inverted_ports_mapping = {
      f"{container_port}/tcp": str(host_port)
      for host_port, container_port in self.extra_ports_mapping.items()
    }

    self.P(f"Port allocation complete. Total ports: {len(self.extra_ports_mapping)}", color='g')
    return

  def _validate_extra_tunnels_config(self):
    """
    Validate EXTRA_TUNNELS configuration.

    Key behaviors:
    1. If TUNNEL_ENGINE_ENABLED=False, EXTRA_TUNNELS are IGNORED
    2. Container ports can be defined only in EXTRA_TUNNELS (not in CONTAINER_RESOURCES)
    3. Ports from EXTRA_TUNNELS will be allocated dynamically if needed
    4. Dict keys can be strings or integers

    Returns:
      bool: True if valid
    """
    # Master switch check
    if not self.cfg_tunnel_engine_enabled:
      if self.cfg_extra_tunnels:
        self.P(
          f"TUNNEL_ENGINE_ENABLED=False: Ignoring {len(self.cfg_extra_tunnels)} EXTRA_TUNNELS",
          color='y'
        )
      return True

    if not self.cfg_extra_tunnels:
      self.Pd("No EXTRA_TUNNELS configured")
      return True

    if not isinstance(self.cfg_extra_tunnels, dict):
      raise ValueError("EXTRA_TUNNELS must be a dictionary {container_port: token}")

    # Track which ports need to be allocated
    ports_to_allocate = []

    for port_key, tunnel_config in self.cfg_extra_tunnels.items():
      # Convert port key to integer (handle both string and int keys)
      try:
        container_port = int(port_key)
      except (ValueError, TypeError):
        raise ValueError(f"EXTRA_TUNNELS key must be integer port, got: {port_key}")

      # Check if port is already allocated
      is_already_mapped = container_port in self.extra_ports_mapping.values()

      if not is_already_mapped:
        # Port not in CONTAINER_RESOURCES["ports"], will need to allocate
        self.Pd(
          f"EXTRA_TUNNELS port {container_port} not in CONTAINER_RESOURCES['ports'], "
          f"will allocate dynamically"
        )
        ports_to_allocate.append(container_port)

      # Normalize and validate tunnel config
      try:
        normalized = self._normalize_extra_tunnel_config(container_port, tunnel_config)
        if not normalized:
          raise ValueError(f"EXTRA_TUNNELS[{container_port}] token is empty")
        self.extra_tunnel_configs[container_port] = normalized
      except Exception as e:
        raise ValueError(f"EXTRA_TUNNELS[{container_port}] validation failed: {e}")

    # Allocate ports for EXTRA_TUNNELS not in CONTAINER_RESOURCES
    if ports_to_allocate:
      self._allocate_extra_tunnel_ports(ports_to_allocate)

    self.P(f"EXTRA_TUNNELS validated: {len(self.extra_tunnel_configs)} tunnel(s) configured", color='g')
    return True

  ### END EXTRA TUNNELS METHODS ###
