"""
container_utils.py
The utility mixin for container management used by ContainerAppRunnerPlugin

"""

import subprocess

class _ContainerUtilsMixin:

  ### START CONTAINER MIXIN METHODS ###
  
  def _container_maybe_login(self):
    # Login to container registry if provided
    cr_data = getattr(self, 'cfg_cr_data', {})
    cr_server = cr_data.get('SERVER') or cr_data.get('server')
    cr_username = cr_data.get('USERNAME') or cr_data.get('username')
    cr_password = cr_data.get('PASSWORD') or cr_data.get('password')
    
    if cr_server and cr_username and cr_password:
      login_cmd = [
        self.cli_tool, "login",
        str(cr_server),
        "-u", str(cr_username),
        "-p", str(cr_password),
      ]
      try:
        self.P(f"Logging in to registry {cr_server} as {cr_username} ...")
        resp = subprocess.run(login_cmd, capture_output=True, check=True)
        self.P(f"Logged in to registry {cr_server} as {cr_username}.")
      except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode("utf-8", errors="ignore")
        raise RuntimeError(f"Registry login failed for {cr_server}: {err_msg}")
    else:
      self.P(f"CR Login missing: {cr_username} / {cr_password} @ {cr_server}")
    return    


  def _container_pull_image(self):
    """
    Pull the container image (Docker/Podman).
    """
    full_ref = str(self.cfg_image)
    cmd = [self.cli_tool, "pull", full_ref]
    
    cr_data = getattr(self, 'cfg_cr_data', {})
    cr_server = cr_data.get('SERVER') or cr_data.get('server')
    
    if cr_server and not str(self.cfg_image).startswith(cr_server):
      # If image doesn't have the registry prefix, prepend it
      full_ref = f"{cr_server.rstrip('/')}/{self.cfg_image}"
      cmd = [self.cli_tool, "pull", full_ref]
    self.P(f"Pulling image {full_ref} ...")
    try:
      result = subprocess.check_output(cmd)
    except Exception as exc:
      raise RuntimeError(f"Error pulling image: {exc}")
    #end if result
    self.P(f"Image {full_ref} pulled successfull: {result.decode('utf-8', errors='ignore')}")
    return
  

  def _container_run(self):
    """
    Launch the container in detached mode, returning its ID.
    """
    if self.cfg_image_pull_policy == "always":
      self._container_pull_image()

    cmd = [
      self.cli_tool, "run", "--rm", "-d", "--name", str(self.container_name),
    ]

    # Resource limits
    if self._cpu_limit:
      cmd += ["--cpus", str(self._cpu_limit)]
      
    if self._mem_limit:
      cmd += ["--memory", str(self._mem_limit)]

    # Port mappings if we have any
    if hasattr(self, 'extra_ports_mapping') and self.extra_ports_mapping:
      for host_port, container_port  in self.extra_ports_mapping.items():
        cmd += ["-p", f"{host_port}:{container_port}"]

    if self.port and self.cfg_port:
      cmd += ["-p", f"{self.port}:{self.cfg_port}"]

    # Env vars
    for key, val in self.cfg_env.items():
      cmd += ["-e", f"{key}={val}"]

    for key, val in self.dynamic_env.items():
      cmd += ["-e", f"{key}={val}"]
      
    cmd += ["-e", f"CONTAINER_NAME={self.container_name}"]
    
    # TODO: check if this is a potential security issue (host is a container itself but we need to make sure)
    cmd += ["-e", f"EE_HOST_ID={self._setup_dynamic_env_var_host_ip()}"] 
      

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
    cr_data = getattr(self, 'cfg_cr_data', {})
    cr_server = cr_data.get('SERVER') or cr_data.get('server')
    
    if cr_server and not image_ref.startswith(str(cr_server)):
      image_ref = f"{cr_server.rstrip('/')}/{image_ref}"
      
    cmd.append(image_ref)
    
    str_cmd = " ".join(cmd)

    self.P(f"Running container: {str_cmd}")
    res = subprocess.run(cmd, capture_output=True)
    if res.returncode != 0:
      err = res.stderr.decode("utf-8", errors="ignore")
      raise RuntimeError(f"Error starting container: {err}")
    
    self.container_proc = res
    self.container_id = res.stdout.decode("utf-8").strip()
    self.container_start_time = self.time()
    return self.container_id


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


  def _container_start_capture_logs(self):
    """
    Start capturing logs from the container in real-time using the CLI tool and a parallel process.
    """
    if self.container_id is None:
      raise RuntimeError("Container ID is not set. Cannot capture logs.")
    
    self._container_maybe_stop_log_reader()
    
    # Start a new log process
    log_cmd = [self.cli_tool, "logs", "-f", self.container_id]
    self.P(f"Capturing logs for container {self.container_id} ...")
    self.container_log_proc = subprocess.Popen(log_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # get the stdout of the `docker logs`` command
    # LogReader uses a separate thread to read the logs in chunks of size=50
    self.container_logreader = self.LogReader(self.container_log_proc.stdout, size=50)
    return
  
  
  def _container_maybe_stop_log_reader(self):    
    if self.container_log_proc is not None:
      self.P("Stopping LogReader...")
      self.container_logreader.stop()
      self.P("Stopping existing docker log process ...")
      self.container_log_proc.terminate()
      self.container_log_proc.wait()
      self.P("Existing docker log process stopped.")
      self.container_log_proc = None
    #endif log process & LogReader
    return  
  
  
  def _container_maybe_reload(self):
    """
    Check if the container is still running and perform the policy specified in the restart policy.
    """
    if self.container_id is None:
      self.P("Container ID is not set. Cannot check container status.")
      return

    if self._is_manually_stopped == True:
      self.P("Container is manually stopped. No action taken.")
      return

    is_running = self._container_is_running(self.container_id)

    if not is_running:
      self.P(f"Container {self.container_id} has stopped.")
      log_needs_restart = False
      # Handle restart policy
      if self.cfg_restart_policy == "always":
        self.P(f"Restarting container {self.container_id} ...")
        self._container_run()
        log_needs_restart = True
      else:
        self.P(f"Container {self.container_id} has stopped. No action taken.")
      
      if log_needs_restart:
        # Restart the log reader
        self.container_log_last_show_time = 0
        self.container_logs.clear()
        self._container_start_capture_logs()
    return
  
  
  def _container_retrieve_logs(self):
    if self.container_logreader is not None:
      logs = self.container_logreader.get_next_characters()
      if len(logs) > 0:
        # first check if the last line is complete (ends with \n)
        ends_with_newline = logs.endswith("\n")
        lines = logs.split("\n")
        lines[0] = self.container_log_last_line_start + lines[0] # add the last line start to the first line
        if not ends_with_newline:
          # if not, remove the last line from the list
          self.container_log_last_line_start = lines[-1]
          lines = lines[:-1]
        else:
          self.container_log_last_line_start = ""
        #endif
        #endif last line
        for log_line in lines:
          if len(log_line) > 0:
            timestamp = self.time() # get the current time
            self.container_logs.append((timestamp, log_line))
          # end if line valid
        # end for each line
      # end if logs
    #endif stdout log reader
    return


  def _container_retrieve_and_maybe_show_logs(self):
    """
    Check if the logs should be shown based on the configured interval.
    """
    self._container_retrieve_logs()
    current_time = self.time()
    if (current_time - self.container_log_last_show_time) > self.cfg_show_log_each:
      nr_lines = self.cfg_show_log_last_lines
      self.container_log_last_show_time = current_time
      msg = f"Container logs (last {nr_lines} lines):\n"
      lines = list(self.container_logs)[-nr_lines:]
      for timestamp, line in lines:
        str_timestamp = self.time_to_str(timestamp)
        msg += f"{str_timestamp}: {line}\n"
      # Show the logs
      self.P(msg)      
    #endif show log interval
    return
  
  
  def _container_get_log_from_to(self, start_time: float, end_time: float) -> list[str]:
    """
    Get logs from the container between start_time and end_time.
    """
    logs = []
    for timestamp, line in self.container_logs:
      if timestamp >= start_time and timestamp <= end_time:
        logs.append(line)
      #endif
    #end for each log line
    return logs

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
  ## END CONTAINER MIXIN ###