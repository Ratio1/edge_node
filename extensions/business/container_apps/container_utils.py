"""
container_utils.py
The utility mixin for container management used by ContainerAppRunnerPlugin

"""

import subprocess

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
  
  def _get_container_login_command(self):
    # Login to container registry if provided
    cr_server, cr_username, cr_password = self._get_cr_data()
    
    if cr_server and cr_username and cr_password:
      login_cmd = [
        self.cli_tool, "login",
        str(cr_server),
        "-u", str(cr_username),
        "-p", str(cr_password),
      ]
      return " ".join(login_cmd)

    return None


  def _get_container_pull_image_command(self):
    """
    Pull the container image (Docker/Podman).
    """
    full_ref = str(self.cfg_image)
    cmd = [self.cli_tool, "pull", full_ref]
    
    cr_server, _, _ = self._get_cr_data()
    
    if cr_server and not str(self.cfg_image).startswith(cr_server):
      # If image doesn't have the registry prefix, prepend it
      full_ref = f"{cr_server.rstrip('/')}/{self.cfg_image}"
      cmd = [self.cli_tool, "pull", full_ref]

    return " ".join(cmd)

  def _container_pull_image(self):
    """
    Pull the container image (Docker/Podman).
    """
    pulled = False
    full_ref = str(self.cfg_image)
    cmd_str = self._get_container_pull_image_command()
    cmd = cmd_str.split()
    try:
      result = subprocess.check_output(cmd)
      # now check if the image was pulled or if it was already present
      if "Image is up to date" in result.decode("utf-8", errors="ignore"):
        self.Pd(f"Image {full_ref} is already up to date.", score=30)
      else:
        self.Pd(f"Image {full_ref} pulled successfully.")
        pulled = True
    except Exception as exc:
      raise RuntimeError(f"Error pulling image: {exc}")
    # end if result
    self.Pd(f"Image {full_ref} pulled successfully: {result.decode('utf-8', errors='ignore')}", score=30)
    return pulled
  
  
  def _get_default_env_vars(self):
    """
    Get the default environment variables for the container.
    
    WARNING: This is a critical method that should be thoroughly reviewed for attack vectors.
    
    Returns:
        dict: Default environment variables.
    """
    localhost_ip = self.log.get_localhost_ip()
    dct_env = {
      "CONTAINER_NAME": self.container_name,
      "EE_HOST_IP": localhost_ip,
      "EE_HOST_ID": self.ee_id,
      "EE_HOST_ADDR": self.ee_addr,
      "EE_HOST_ETH_ADDR": self.bc.eth_address,
      "EE_CHAINSTORE_API_URL": f"http://{localhost_ip}:31234",
      "EE_R1FS_API_URL": f"http://{localhost_ip}:31235",
    }
    chainstore_peers = getattr(self, 'cfg_chainstore_peers', [])
    dct_env["EE_CHAINSTORE_PEERS"] = self.json_dumps(chainstore_peers)

    return dct_env


  def _get_container_run_command(self):
    """
    Launch the container in detached mode, returning its ID.
    """

    cmd = [
      self.cli_tool, "run", "--rm", "--name", str(self.container_name),
    ]

    # Resource limits
    if self._cpu_limit:
      cmd += ["--cpus", str(self._cpu_limit)]

    if self._mem_limit:
      cmd += ["--memory", str(self._mem_limit)]

    # Port mappings if we have any
    if hasattr(self, 'extra_ports_mapping') and self.extra_ports_mapping:
      for host_port, container_port  in self.extra_ports_mapping.items():
        if host_port == self.port:
          continue
        cmd += ["-p", f"{host_port}:{container_port}"]

    if self.port and self.cfg_port:
      cmd += ["-p", f"{self.port}:{self.cfg_port}"]

    # Env vars
    for key, val in self.cfg_env.items():
      cmd += ["-e", f"{key}={val}"]

    for key, val in self.dynamic_env.items():
      cmd += ["-e", f"{key}={val}"]

    # now add the default env vars
    for key, val in self._get_default_env_vars().items():
      cmd += ["-e", f"{key}={val}"]      

    # Volume mounts
    if len(self.volumes) > 0:
      for volume_label, container_path in self.volumes.items():
        # Create a named volume with the prefixed sanitized name
        volume_spec = f"{volume_label}:{container_path}"
        cmd += ["-v", volume_spec]
      #endfor
      self.P("Note: These named volumes will persist until manually removed with 'docker volume rm'")

    # Possibly prefix the registry to the image reference
    image_ref = str(self.cfg_image)
    cr_server, _, _ = self._get_cr_data()
    
    if cr_server and not image_ref.startswith(str(cr_server)):
      image_ref = f"{cr_server.rstrip('/')}/{image_ref}"
      
    cmd.append(image_ref)
    
    str_cmd = " ".join(cmd)

    return str_cmd


  def _container_exists(self, cid):
    """
    Check if container with ID cid is still running.
    """
    result = False
    if cid is not None:
      ps_cmd = [self.cli_tool, "ps", "-q", "-f", f"id={cid}"]
      try:
        ps_res = subprocess.run(ps_cmd, capture_output=True)
        if ps_res.returncode == 0:
          output = ps_res.stdout.decode("utf-8", errors="ignore").strip()
          result = len(output) > 0 and output in cid
      except Exception as e:
        self.P(f"Error checking container existence: {e}", color='r')
    return result


  def _container_is_running(self, cid):
    """
    Check if the container is still running similar to _container_exists.
    """
    cmd = [self.cli_tool, "inspect", "-f", "{{.State.Running}}", cid]
    try:
      res = subprocess.run(cmd, capture_output=True, check=True)
      is_running = res.stdout.decode("utf-8").strip() == "true"
    except Exception as e:
      self.P(f"Container status check: {e}", color='r')
      is_running = False    
    return is_running

  def _container_kill(self, cid):
    """
    Force kill a container by ID (if it exists).
    """
    if not self._container_exists(cid):
      self.P(f"Container {cid} does not exist. Cannot kill.")
      return
    # Use the CLI tool to kill the container
    kill_cmd = [self.cli_tool, "rm", "-f", cid]
    self.P(f"Stopping container {cid} ...")
    res = subprocess.run(kill_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
      err = res.stderr.decode("utf-8", errors="ignore")
      self.P(f"Error stopping container {cid}: {err}", color='r')
    else:
      self.P(f"Container {cid} stopped successfully.")
    return

  def _get_container_id(self):
    cmd = [self.cli_tool, "ps", "-q", "-f", f"name={self.container_name}"]
    try:
      res = subprocess.run(cmd, capture_output=True, check=True)
      container_id = res.stdout.decode("utf-8").strip()
      if container_id:
        self.container_id = container_id
        self.P(f"Container ID: {self.container_id}")
        return container_id
      else:
        self.Pd("No container found with the specified name.", color='r', score=29)
    except subprocess.CalledProcessError as e:
      self.P(f"Error getting container ID: {e}", color='r')
    return None

  def _container_maybe_reload(self, force_restart=False):
    """
    Check if the container is still running and perform the policy specified in the restart policy.
    """
    if self.container_id is None:
      self.Pd("Container ID is not set. Cannot check container status.")
      return

    if self._is_manually_stopped == True:
      self.Pd("Container is manually stopped. No action taken.")
      return

    is_running = self._container_is_running(self.container_id)

    if force_restart:
      self.P(f"Force restarting container {self.container_id} ...")
      self._restart_container()
      return

    if not is_running:
      self.P(f"Container {self.container_id} has stopped.")
      # Handle restart policy
      if self.cfg_restart_policy == "always":
        self.P(f"Restarting container {self.container_id} ...")
        self._restart_container()
      else:
        self.P(f"Container {self.container_id} has stopped. No action taken.")
    return

  def _restart_container(self):
    self._container_kill(self.container_id)
    self._reload_server()
    self.container_id = None
    self.container_start_time = self.time()  # Reset the start time after restart
    return

  def _maybe_set_container_id_and_show_app_info(self):
    if self.container_id is None:
      # this is the first time we are starting the container, so we need to get its ID
      container_id = self._get_container_id()
      if container_id:
        self.container_id = container_id
        self.P(f"Container ID set to: {self.container_id}")
        self.on_post_container_start()  # Call the lifecycle hoo        
        self._maybe_send_plugin_start_confirmation()
        self._show_container_app_info()
      #endif
    #endif
    return

  def _maybe_send_plugin_start_confirmation(self):
    """
    Sets up confirmation data about plugin start in CHAINSTORE.
    TODO: Generalize this function and move it to the base class.
    """
    response_key = getattr(self, 'cfg_chainstore_response_key', None)
    if response_key is not None:
      self.P(f"Responding to key {response_key}")
      response_info = {
        'container_id': self.container_id,
        'start_time': self.time_to_str(self.container_start_time),
        'ports_mapping': self.extra_ports_mapping,
      }
      self.P(f"Response to key {response_key}: {self.json_dumps(response_info)}")
      self.chainstore_set(response_key, response_info)
    return
  

  def _setup_dynamic_env_var_host_ip(self):
    """ Definition for `host_ip` dynamic env var type. """
    return self.log.get_localhost_ip()
  
  def _setup_dynamic_env_var_some_other_calc_type(self):
    """ Example definition for `some_other_calc_type` dynamic env var type. """
    return "some_other_value"


  def _setup_dynamic_env(self):
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

  def _show_container_app_info(self):
    """
    Displays the current resource limits for the container.
    This is a placeholder method and can be expanded as needed.
    """
    cr_server, cr_username, cr_password = self._get_cr_data()

    msg = "Container info:\n"
    msg += f"  Container ID:     {self.container_id}\n"
    msg += f"  Start Time:       {self.time_to_str(self.container_start_time)}\n"
    msg += f"  Resource CPU:     {self._cpu_limit} cores\n"
    msg += f"  Resource GPU:     {self._gpu_limit}\n"
    msg += f"  Resource Mem:     {self._mem_limit}\n"
    msg += f"  Target Image:     {self.cfg_image}\n"
    msg += f"  CR:               {cr_server}\n"
    msg += f"  CR User:          {cr_username}\n"
    msg += f"  CR Pass:          {'*' * len(cr_password) if cr_password else 'None'}\n"
    msg += f"  Env Vars:         {self.cfg_env}\n"
    msg += f"  Cont. Port:       {self.cfg_port}\n"
    msg += f"  Restart:          {self.cfg_restart_policy}\n"
    msg += f"  Image Pull:       {self.cfg_image_pull_policy}\n"
    if self.volumes and len(self.volumes) > 0:
      msg += "  Volumes:\n"
      for host_path, container_path in self.volumes.items():
        msg += f"    Host {host_path} → Container {container_path}\n"
    if self.extra_ports_mapping:
      msg += "  Extra Ports Mapping:\n"
      for host_port, container_port in self.extra_ports_mapping.items():
        msg += f"   Host {host_port} → Container {container_port}\n"
    msg += f"  Ngrok Host Port:  {self.port}\n"
    msg += f"  CLI Tool:         {self.cli_tool}\n"
    self.P(msg)
    return

  
  def _run_command_in_container(self, command):
    """
    Run a command inside the container.
    
    Args:
        command (str): The command to run inside the container.
    """
    if not self.container_id:
      self.P("Container ID is not set. Cannot run command.")
      return
    
    cmd = [self.cli_tool, "exec", "-i", self.container_id] + command.split()
    try:
      result = subprocess.run(cmd, capture_output=True, text=True, check=True)
      self.P(f"Command output: {result.stdout}")
    except subprocess.CalledProcessError as e:
      self.P(f"Error running command in container: {e.stderr}", color='r')
      
  ## END CONTAINER MIXIN ###
