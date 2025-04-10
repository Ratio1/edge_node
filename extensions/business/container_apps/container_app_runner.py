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

__VER__ = "0.3.1"

_CONFIG = {
  **BasePlugin.CONFIG,

  "PROCESS_DELAY": 5,  # seconds to wait between process calls
  "ALLOW_EMPTY_INPUTS": True,
  
  "NGROK_EDGE_LABEL": None,  # Optional ngrok edge label for the tunnel
  "NGROK_AUTH_TOKEN" : None,  # Optional ngrok auth token for the tunnel
  "NGROK_USE_API": True,

  # TODO: this flag needs to be renamed both here and in the ngrok mixin
  "DEBUG_WEB_APP": False,  # If True, will run the web app in debug mode

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
  "SHOW_LOG_EACH" : 60,       # seconds to show logs
  "SHOW_LOG_LAST_LINES" : 5,  # last lines to show  
  "MAX_LOG_LINES" : 10_000,   # max lines to keep in memory
  
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
    - Supports a restart policy: "always" or ... not
    - Supports pull policy: "always" or ... not
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
    msg += f"  Host Port:    {self.port}\n"
    msg += f"  CLI Tool:     {self.cli_tool}\n"
    self.P(msg)
    return
  
  

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
    

    self._reset_ngrok() # call ngrok var init
    
    self.container_id = None
    self.container_name = self.cfg_instance_id + "_" + self.uuid(4)
    self.container_proc = None
    
    self.container_log_last_show_time = 0
    self.container_log_last_line_start = ""
    self.container_logs = self.deque(maxlen=self.cfg_max_log_lines)
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
    self.port = None
    if self.cfg_port:
      self.P(f"Container port {self.cfg_port} specified. Finding available host port ...")
      # Allocate a host port for the container
      # We'll use a socket to find an available port
      # This is a common approach to find an available port
      # We'll bind to port 0, which tells the OS to pick an available port
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.bind(("", 0))
      self.port = sock.getsockname()[1]
      sock.close()
      self.P(f"Allocated free host port {self.port} for container port {self.cfg_port}.")    
      
      self.maybe_init_ngrok()
    #endif port

    # start the container app
    self._container_run()
    
    if self.port is not None:
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
    self.P(f"Stopping container app '{self.container_id}' ...")
    # Stop the container if it's running
    if self._container_exists(self.container_id):
      self._container_kill(self.container_id)
      self._container_maybe_stop_log_reader()
      self.P("Container and log stopped.")
    else:
      self.P(f"Container '{self.container_id}' does not exist. Stop command canceled.")

    # Stop ngrok if needed
    self.P("Stopping ngrok tunnel ...")
    self.maybe_stop_ngrok()
    self.P("Ngrok tunnel stopped.")

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