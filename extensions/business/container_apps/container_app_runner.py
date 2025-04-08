"""
container_app_runner.py
A Ratio1 plugin to run a single Docker/Podman container and (if needed) expose it via ngrok.

On-init:
  - CR login
  - Port allocation (optional)
  - Container run
  - ngrok tunnel (optional)
 
Loop:
  - check and maybe reload container
  - retrieve logs and maybe show them
  
On-close:
  - stop container
  - stop ngrok tunnel (if needed)
  - stop logs process
  - save logs to disk


"""

import shutil
import socket
import subprocess
import time

# 
from naeural_core.business.base import BasePluginExecutor as BasePlugin  # provides all the self.api_call methods
from naeural_core.business.mixins_libs.ngrok_mixin import _NgrokMixinPlugin # provides ngrok support

from .container_utils import _ContainerUtilsMixin # provides container management support currently empty it is embedded in the plugin

_CONFIG = {
  **BasePlugin.CONFIG,

  "PROCESS_DELAY": 10,  # seconds to wait between process calls
  "ALLOW_EMPTY_INPUTS": True,
  
  "NGROK_EDGE_LABEL": None,  # Optional ngrok edge label for the tunnel
  "NGROK_AUTH_TOKEN" : None,  # Optional ngrok auth token for the tunnel
  

  # Container-specific config options  
  "IMAGE": None,            # Required container image, e.g. "my_repo/my_app:latest"
  "CR": None,               # Optional container registry URL
  "CR_USER": None,          # Optional registry username
  "CR_PASSWORD": None,      # Optional registry password or token
  "ENV": {},                # dict of env vars for the container
  "PORT": None,             # internal container port if it's a web app (int)
  "CONTAINER_RESOURCES" : {
    "cpu": 1,         # e.g. "0.5" for half a CPU, or "1.0" for one CPU core
    "gpu": 0,
    "memory": "512m"  # e.g. "512m" for 512MB
  },
  "RESTART_POLICY": "always",  # "always" will restart the container if it stops
  "IMAGE_PULL_POLICY": "always",  # "always" will always pull the image
  
  
  #### Logging
  "SHOW_LOG_EACH" : 30,  # seconds to show logs
  "SHOW_LOG_LAST_LINES" : 20,  # last lines to show  
  "MAX_LOG_LINES" : 10_000,  # max lines to keep in memory
  
  # end of container-specific config options
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },  
}


class ContainerAppRunnerPlugin(
  _NgrokMixinPlugin, 
  BasePlugin,
  _ContainerUtilsMixin,
):
  """
  A Ratio1 plugin to run a single Docker/Podman container.

  This plugin:
    - Logs in to a container registry if CR_USER and CR_PASSWORD are provided.
    - Allocates a host port if PORT is provided and exposes it via ngrok using an edge label.
    - Runs the container with optional CPU and memory constraints.
    - Captures logs in real-time using the LogReader class.
    - Stores logs to disk upon plugin close using diskapi_save_pickle_to_output.
    - Supports a restart policy: "finish", "restart", or "pull-and-restart".
  """

  CONFIG = _CONFIG
  
  def __show_container_app_info(self):
    """
    Displays the current resource limits for the container.
    This is a placeholder method and can be expanded as needed.
    """
    msg = "Container info:\n"
    msg += f"  Container ID: {self.container_id}\n"
    msg += f"  Start Time:   {self.time_to_str(self.container_start_time)}\n"
    msg += f"  Resource CPU: {self._cpu_limit} cores\n"
    msg += f"  Resource GPU: {self._gpu_limit}\n"
    msg += f"  Resource Mem: {self._mem_limit}\n"
    msg += f"  Target Image: {self.cfg_image}\n"
    msg += f"  CR:           {self.cfg_cr}\n"
    msg += f"  CR User:      {self.cfg_cr_user}\n"
    msg += f"  CR Pass:      {'*' * len(self.cfg_cr_password) if self.cfg_cr_password else 'None'}\n"
    msg += f"  Env Vars:     {self.cfg_env}\n"
    msg += f"  Cont. Port:   {self.cfg_port}\n"
    msg += f"  Restart:      {self.cfg_restart_policy}\n"
    msg += f"  Image Pull:   {self.cfg_image_pull_policy}\n"
    msg += f"  Host Port:    {self._host_port}\n"
    msg += f"  CLI Tool:     {self.cli_tool}\n"
    self.P(msg)
    return
  
  
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
    result = subprocess.check_output(cmd)
    if result.returncode != 0:
      err = result.stderr.decode("utf-8", errors="ignore")
      raise RuntimeError(f"Error pulling image: {err}")
    #end if result
    self.P(f"Image {full_ref} pulled successfull: {result}")
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
    if self.cfg_cpu_limit:
      cmd += ["--cpus", str(self._cpu_limit)]
    if self.cfg_mem_limit:
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
    self.container_start_time = time.time()
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
    self.container_logreader = self.LogReader(self, self.container_log_proc.stdout, size=50)
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
    self.retrieve_logs()
    current_time = time.time()
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
  

  def on_init(self):
    """
    Lifecycle hook called once the plugin is initialized.
    Authenticates with the container registry (if config is provided).
    Determines whether Docker or Podman is available, sets up port (if needed),
    and prepares for container run.    
    """
    DEFAULT_CPU_LIMIT = 1
    DEFAULT_GPU_LIMIT = 0
    DEFAULT_MEM_LIMIT = "512m"
    
    
    self.container_id = None
    self.container_name = self.cfg_instance_id + "_" + self.uuid(4)
    self.container_proc = None
    
    self.__last_log_show_time = 0
    self.container_logs = self.deque(maxlen=self.cfg_max_log_lines)
    # self.__stderr_logreader = None # no need for now as we are monitoring `docker logs`
    self.container_log_proc = None    
    self.container_logreader = None
    
    
    resource_limits = self.cfg_container_resources
    if isinstance(resource_limits, dict) and len(resource_limits) > 0:
      self._cpu_limit = resource_limits.get("cpu", DEFAULT_CPU_LIMIT)
      self._gpu_limit = resource_limits.get("gpu", DEFAULT_GPU_LIMIT)
      self._mem_limit = resource_limits.get("memory", DEFAULT_MEM_LIMIT)
    else:
      self._cpu_limit = DEFAULT_CPU_LIMIT
      self._gpu_limit = DEFAULT_GPU_LIMIT
      self._mem_limit = DEFAULT_MEM_LIMIT
    #endif resource limits
    
    # Detect CLI tool (docker or podman)
    if shutil.which("docker"):
      self.cli_tool = "docker"
    elif shutil.which("podman"):
      self.cli_tool = "podman"
    else:
      raise RuntimeError("No container runtime (Docker/Podman) found on this system.")

    self._container_maybe_login()

    # If a container port is specified, we treat it as a web app
    # and request a host port for local binding
    self._host_port = None
    if self.cfg_port:
      self.P(f"Container port {self.cfg_port} specified. Finding available host port ...")
      # Allocate a host port for the container
      # We'll use a socket to find an available port
      # This is a common approach to find an available port
      # We'll bind to port 0, which tells the OS to pick an available port
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.bind(("", 0))
      self._host_port = sock.getsockname()[1]
      sock.close()
      self.P(f"Allocated free host port {self._host_port} for container port {self.cfg_port}.")    
      
      self.maybe_init_ngrok()
    #endif port

    # start the container app
    self._container_run()
    
    if self._host_port is not None:
      self.maybe_start_ngrok()
    
    self._container_start_capture_logs()
        
    # Show container app info
    self.__show_container_app_info()
    return


  def on_close(self):
    """
    Lifecycle hook called when plugin is stopping.
    Ensures container is shut down and logs are saved.
    Ensures the log process is killed.
    Stops ngrok tunnel if started.
    """
    
    # Stop the container if it's running
    if self.container_exists(self.container_id):
      self._container_kill(self.container_id)
      self._container_maybe_stop_log_reader()

    # Stop ngrok if needed
    self.maybe_stop_ngrok()
    
    # Save logs to disk
    # We'll store them in a single structure: a list of lines from dct_logs or so
    # We can do: logs, err_logs = self._get_delta_logs() or a custom approach
    try:
      # using parent class method to save logs
      self.diskapi_save_pickle_to_output(
        obj=self.container_logs, filename="container_logs.pkl"
      )
      self.P("Container logs saved to disk.")
    except Exception as exc:
      self.P(f"Failed to save logs: {exc}", color='r')
    return



  def process(self):
    """
    This is the main process loop for the plugin that gets called each PROCESS_DELAY seconds and
    it performs the following:
    
      1. self._container_maybe_reload() - check if the container is still running and perform the policy
          specified in the restart policy.
      2. self._container_retrieve_and_maybe_show_logs() - check if the logs should be show as well as complete the logs
    
    """
    self._container_maybe_reload()
    self._container_retrieve_and_maybe_show_logs()
    return