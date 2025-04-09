"""
container_utils.py
The utility mixin for container management used by ContainerAppRunnerPlugin

"""

import subprocess

class _ContainerUtilsMixin:

  ### START CONTAINER MIXIN METHODS ###
  
  def _container_maybe_login(self):
    # Login to container registry if provided
    if self.cfg_cr and self.cfg_cr_user and self.cfg_cr_password:
      login_cmd = [
        self.cli_tool, "login",
        str(self.cfg_cr),
        "-u", str(self.cfg_cr_user),
        "-p", str(self.cfg_cr_password),
      ]
      try:
        self.P(f"Logging in to registry {self.cfg_cr} as {self.cfg_cr_user} ...")
        resp = subprocess.run(login_cmd, capture_output=True, check=True)
        self.P(f"Logged in to registry {self.cfg_cr} as {self.cfg_cr_user}.")
      except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode("utf-8", errors="ignore")
        raise RuntimeError(f"Registry login failed for {self.cfg_cr}: {err_msg}")
    else:
      self.P(f"CR Login missing: {self.cfg_cr_user} / {self.cfg_cr_password} @ {self.cfg_cr}")
    return    


  def _container_pull_image(self):
    """
    Pull the container image (Docker/Podman).
    """
    cmd = [self.cli_tool, "pull", str(self.cfg_image)]
    if self.cfg_cr and not str(self.cfg_image).startswith(self.cfg_cr):
      # If image doesn't have the registry prefix, prepend it
      full_ref = f"{self.cfg_cr.rstrip('/')}/{self.cfg_image}"
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

    # Port mapping if we have a host port
    if self._host_port and self.cfg_port:
      cmd += ["-p", f"{self._host_port}:{self.cfg_port}"]

    # Env vars
    for key, val in self.cfg_env.items():
      cmd += ["-e", f"{key}={val}"]

    # Possibly prefix the registry to the image reference
    image_ref = str(self.cfg_image)
    if self.cfg_cr and not image_ref.startswith(str(self.cfg_cr)):
      image_ref = f"{self.cfg_cr.rstrip('/')}/{image_ref}"
      
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
    if cid is None:
      return False
    ps_cmd = [self.cli_tool, "ps", "-q", "-f", f"id={cid}"]
    ps_res = subprocess.run(ps_cmd, capture_output=True)
    if ps_res.returncode != 0:
      return False
    output = ps_res.stdout.decode("utf-8", errors="ignore").strip()
    return (output == cid)


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
      self.P("Stopping existing LogReader...")
      self.container_logreader.stop()
      self.P("Stopping existing log process ...")
      self.container_log_proc.terminate()
      self.container_log_proc.wait()
      self.P("Existing log process stopped.")
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

    # Check if the container is still running
    cmd = [self.cli_tool, "inspect", "-f", "{{.State.Running}}", self.container_id]
    try:
      res = subprocess.run(cmd, capture_output=True, check=True)
      is_running = res.stdout.decode("utf-8").strip() == "true"
    except subprocess.CalledProcessError as e:
      err_msg = e.stderr.decode("utf-8", errors="ignore")
      raise RuntimeError(f"Failed to check container status: {err_msg}")

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
        self.__last_log_show_time = 0
        self.container_logs.clear()
        self._container_start_capture_logs()
    return
  
  
  def _container_retrieve_logs(self):
    if self.container_logreader is not None:
      logs = self.container_logreader.get_next_characters()
      if len(logs) > 0:
        lines = logs.split("\n")
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
    if (current_time - self.__last_log_show_time) > self.cfg_show_log_each:
      nr_lines = self.cfg_show_log_last_lines
      self.__last_log_show_time = current_time
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
    
  
  ## END CONTAINER MIXIN ###