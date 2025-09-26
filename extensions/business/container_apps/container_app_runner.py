"""
container_app_runner.py
A Ratio1 plugin to run a single Docker/Podman container and (if needed) expose it via tunnel engine.

On-init:
  - CR login
  - Port allocation (optional)
  - Container run
  - tunnel (optional)
 
Loop:
  - check and maybe reload container
  - retrieve logs and maybe show them
  
On-close:
  - stop container
  - stop tunnel (if needed)
  - stop logs process
  - save logs to disk


"""

import docker
import requests
import threading
import time
import socket

from naeural_core.business.base.web_app.base_tunnel_engine_plugin import BaseTunnelEnginePlugin as BasePlugin

from .container_utils import _ContainerUtilsMixin # provides container management support currently empty it is embedded in the plugin

__VER__ = "0.3.1"


_CONFIG = {
  **BasePlugin.CONFIG,

  "PROCESS_DELAY": 5,  # seconds to wait between process calls
  "ALLOW_EMPTY_INPUTS": True,

  "NGROK_EDGE_LABEL": None,  # Optional ngrok edge label for the tunnel
  "NGROK_AUTH_TOKEN" : None,  # Optional ngrok auth token for the tunnel
  "NGROK_USE_API": True,
  'NGROK_DOMAIN': None,
  'NGROK_URL_PING_INTERVAL': 10, # seconds to ping the ngrok URL and to send it in payload
  'NGROK_URL_PING_COUNT': 10, # nr or times we send payload with ngrok url

  # Generic tunnel engine Section
  "TUNNEL_ENGINE": "cloudflare",

  "TUNNEL_ENGINE_ENABLED": True,
  "TUNNEL_ENGINE_PING_INTERVAL": 30,  # seconds
  "TUNNEL_ENGINE_PARAMETERS": {
  },


  # TODO: this flag needs to be renamed both here and in the ngrok mixin
  "DEBUG_WEB_APP": False,  # If True, will run the web app in debug mode
  "CAR_VERBOSE": 1,

  # Container-specific config options
  "IMAGE": None,            # Required container image, e.g. "my_repo/my_app:latest"
  "CR_DATA": {              # dict of container registry data
    "SERVER": 'docker.io',  # Optional container registry URL
    "USERNAME": None,       # Optional registry username
    "PASSWORD": None,       # Optional registry password or token
  },
  "ENV": {},                # dict of env vars for the container
  "DYNAMIC_ENV": {},        # dict of dynamic env vars for the container
  "PORT": None,             # internal container port if it's a web app (int)
  "CONTAINER_RESOURCES" : {
    "cpu": 1,          # e.g. "0.5" for half a CPU, or "1.0" for one CPU core
    "gpu": 0,
    "memory": "512m",  # e.g. "512m" for 512MB,
    "ports": []        # dict of host_port: container_port mappings (e.g. {8080: 8081}) or list of container ports (e.g. [8080, 9000])
  },
  "RESTART_POLICY": "always",  # "always" will restart the container if it stops
  "IMAGE_PULL_POLICY": "always",  # "always" will always pull the image
  "AUTOUPDATE" : True, # If True, will check for image updates and pull them if available
  "AUTOUPDATE_INTERVAL": 100,

  "VOLUMES": {},                # dict mapping host paths to container paths, e.g. {"/host/path": "/container/path"}

  # Application endpoint polling
  "ENDPOINT_POLL_INTERVAL": 0,  # seconds between endpoint health checks
  "ENDPOINT_URL": None,  # endpoint to poll for health checks

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
  BasePlugin,
  _ContainerUtilsMixin,
):
  """
  A Ratio1 plugin to run a single Docker/Podman container.

  This plugin:
    - Logs in to a container registry if CR_USER and CR_PASSWORD are provided.
    - Allocates a host port if PORT is provided and exposes it via cloudflare using an access token.
    - Runs the container with optional CPU and memory constraints.
    - Captures logs in real-time using the LogReader class.
    - Stores logs to disk upon plugin close using diskapi_save_pickle_to_output.
    - Supports a restart policy: "always" or ... not
    - Supports pull policy: "always" or ... not
  """

  CONFIG = _CONFIG

  @property
  def port(self):
      return getattr(self, '_port', None)

  @port.setter
  def port(self, value):
      self._port = value

  def Pd(self, s, *args, score=-1, **kwargs):
    """
    Print a message to the console.
    """
    if self.cfg_car_verbose > score:
      s = "[DEPDBG] " + s
      self.P(s, *args, **kwargs)
    return


  def __reset_vars(self):
    self.container = None
    self.container_id = None
    self.container_name = self.cfg_instance_id + "_" + self.uuid(4)
    self.docker_client = docker.from_env()

    self.container_logs = self.deque(maxlen=self.cfg_max_log_lines)

    # Handle port allocation for main port and additional ports
    self.extra_ports_mapping = {}  # Dictionary to store host_port -> container_port mappings
    self.inverted_ports_mapping = {} # inverted mapping for docker-py container_port -> host_port

    self.volumes = {}
    self.env = {}
    self.dynamic_env = {}

    self._is_manually_stopped = False # Flag to indicate if the container was manually stopped

    # Initialize tunnel process
    self.tunnel_process = None

    # Log streaming
    self.log_thread = None
    self._stop_event = threading.Event()

    # Container start time tracking
    self.container_start_time = None

    # Periodic intervals
    self._last_endpoint_check = 0
    self._last_image_check = 0
    
    # Image update tracking
    self.current_image_hash = None

    return

  def on_init(self):
    """
    Lifecycle hook called once the plugin is initialized.
    Authenticates with the container registry (if config is provided).
    Determines whether Docker or Podman is available, sets up port (if needed),
    and prepares for container run.
    """

    self.__reset_vars()

    super(ContainerAppRunnerPlugin, self).on_init()

    self.container_start_time = self.time()

    # Login to container registry if credentials are provided
    if not self._login_to_registry():
      raise RuntimeError("Failed to login to container registry. Cannot proceed without authentication.")

    self.reset_tunnel_engine()

    self._configure_dynamic_env() # setup dynamic env vars for the container
    self._setup_resource_limits_and_ports() # setup container resource limits (CPU, GPU, memory, ports)
    self._configure_volumes() # setup container volumes

    self._setup_env_and_ports()

    return

  def on_command(self, data, **kwargs):
    """
    Called when a INSTANCE_COMMAND is received by the plugin instance.

    The command is sent via `cmdapi_send_instance_command` from a commanding node (Deeploy plugin)
    as in below simplified example:

    ```python
      pipeline = "some_app_pipeline"
      signature = "CONTAINER_APP_RUNNER"
      instance_id = "CONTAINER_APP_1e8dac"
      node_address = "0xai_1asdfG11sammamssdjjaggxffaffaheASSsa"

      instance_command = "RESTART"

      plugin.cmdapi_send_instance_command(
        pipeline=pipeline,
        signature=signature,
        instance_id=instance_id,
        instance_command=instance_command,
        node_address=node_address,
      )
    ```

    while the `on_command` method should look like this:

    ```python
      def on_command(self, data, **kwargs):
        if data == "RESTART":
          self.P("Restarting container...")
          ...
        elif data == "STOP":
          self.P("Stopping container (restart policy still applies)...")
          ...
        else:
          self.P(f"Unknown command: {data}")
        return
    ```

    """
    self.P(f"Received a command: {data}")
    self.P(f"Command kwargs: {kwargs}")

    if data == "RESTART":
      self.P("Restarting container...")
      self._is_manually_stopped = False
      self._stop_container_and_save_logs_to_disk()
      self._restart_container()
      return

    elif data == "STOP":
      self.P("Stopping container (restart policy still applies)...")
      self._stop_container_and_save_logs_to_disk()
      self._is_manually_stopped = True
      return
    else:
      self.P(f"Unknown plugin command: {data}")
    return

  def _on_config_changed(self):
    self.Pd("Received an updated config for ContainerAppRunner")
    self._stop_container_and_save_logs_to_disk()
    self._restart_container()

    return

  def on_post_container_start(self):
    """
    Lifecycle hook called after the container is started.
    Runs commands in the container if specified in the config.

      - after the container first start
      - after the container is restarted
    """
    self.P("Container started, running post-start commands...")
    return




  def start_tunnel_engine(self):
    """
    Start the tunnel engine using the base tunnel engine functionality.
    """
    if self.cfg_tunnel_engine_enabled:
      engine_name = "Cloudflare" if self.use_cloudflare() else "ngrok"
      self.P(f"Starting {engine_name} tunnel...", color='b')
      self.tunnel_process = self.run_tunnel_engine()
      if self.tunnel_process:
        self.P(f"{engine_name} tunnel started successfully", color='g')
      else:
        self.P(f"Failed to start {engine_name} tunnel", color='r')
    return

  def stop_tunnel_engine(self):
    """
    Stop the tunnel engine.
    """
    if self.tunnel_process:
      engine_name = "Cloudflare" if self.use_cloudflare() else "ngrok"
      self.P(f"Stopping {engine_name} tunnel...", color='b')
      self.stop_tunnel_command(self.tunnel_process)
      self.tunnel_process = None
      self.P(f"{engine_name} tunnel stopped", color='g')
    return

  def start_container(self):
    """Start the Docker container."""
    self.P(f"Launching container with image '{self.cfg_image}'...")

    self.P(f"Container data:")
    self.P(f"  Image: {self.cfg_image}")
    self.P(f"  Ports: {self.json_dumps(self.inverted_ports_mapping) if self.inverted_ports_mapping else 'None'}")
    self.P(f"  Env: {self.json_dumps(self.env) if self.env else 'None'}")
    self.P(f"  Volumes: {self.json_dumps(self.volumes) if self.volumes else 'None'}")
    self.P(f"  Resources: {self.json_dumps(self.cfg_container_resources) if self.cfg_container_resources else 'None'}")
    self.P(f"  Restart policy: {self.cfg_restart_policy}")
    self.P(f"  Pull policy: {self.cfg_image_pull_policy}")

    try:
      self.container = self.docker_client.containers.run(
        self.cfg_image,
        detach=True,
        ports=self.inverted_ports_mapping,
        environment=self.env,
        volumes=self.volumes,
        # restart_policy={"Name": self.cfg_restart_policy} if self.cfg_restart_policy != "no" else None,
        name=self.container_name,
      )
    except Exception as e:
      self.P(f"Could not start container: {e}", color='r')
      self.container = None
      return None

    self.container_id = self.container.short_id
    self.P(f"Container started (ID: {self.container.short_id})", color='g')

    self._maybe_send_plugin_start_confirmation()

    return self.container

  def stop_container(self):
    """Stop and remove the Docker container if it is running."""
    if not self.container:
      self.P("No container to stop", color='y')
      return

    try:
      # Stop the container (gracefully)
      self.P(f"Stopping container {self.container.short_id}...", color='b')
      self.container.stop(timeout=5)
      self.P(f"Container {self.container.short_id} stopped successfully", color='g')
    except Exception as e:
      self.P(f"Error stopping container: {e}", color='r')
    # end try

    try:
      self.P(f"Removing container {self.container.short_id}...", color='b')
      self.container.remove()
      self.P(f"Container {self.container.short_id} removed successfully", color='g')
    except Exception as e:
      self.P(f"Error removing container: {e}", color='r')
    finally:
      self.container = None
      self.container_id = None
    # end try
    return

  def _stream_logs(self, log_stream):
    """Consume a log iterator from container logs and print its output."""
    if not log_stream:
      self.P("No log stream provided", color='y')
      return

    try:
      for log_bytes in log_stream:
        if log_bytes is None:
          break
        try:
          log_str = log_bytes.decode("utf-8", errors="replace")
        except Exception as e:
          self.P(f"Warning: Could not decode log bytes: {e}", color='y')
          log_str = str(log_bytes)

        self.P(f"[CONTAINER] {log_str}", color='d', end='')
        self.container_logs.append(log_str)

        if self._stop_event.is_set():
          self.P("Log streaming stopped by stop event", color='y')
          break
    except Exception as e:
      self.P(f"Exception while streaming logs: {e}", color='r')
    # end try
    return

  def _check_health_endpoint(self, current_time=None):
    if not self.container or not self.cfg_endpoint_url or self.cfg_endpoint_poll_interval <= 0:
      return

    if current_time - self._last_endpoint_check >= self.cfg_endpoint_poll_interval:
      self._last_endpoint_check = current_time
      self._poll_endpoint()
    # end if time elapsed
    return

  def _poll_endpoint(self):
    """Poll the container's health endpoint and log the response."""
    if not self.port:
      self.P("No port allocated, cannot poll endpoint", color='r')
      return

    if not self.cfg_endpoint_url:
      self.P("No endpoint URL configured, skipping health check", color='y')
      return

    url = f"http://localhost:{self.port}{self.cfg_endpoint_url}"

    try:
      resp = requests.get(url, timeout=5)
      status = resp.status_code

      if status == 200:
        self.P(f"Health check: {url} -> {status} OK", color='g')
      else:
        self.P(f"Health check: {url} -> {status} Error", color='r')
    except requests.RequestException as e:
      self.P(f"Health check failed: {url} - {e}", color='r')
    except Exception as e:
      self.P(f"Unexpected error during health check: {e}", color='r')
    # end try
    return

  def _check_container_status(self):
    try:
      if self.container:
        # Refresh container status
        self.container.reload()
        if self.container.status != "running":
          self.P(f"Container stopped unexpectedly (exit code {self.container.attrs.get('State', {}).get('ExitCode')})", color='r')
          return False
        # end if container not running
      # end if self.container
      return True
    except Exception as e:
      self.P(f"Could not check container status: {e}", color='r')
      self.container = None
    # end try
    return False




  def _stop_container_and_save_logs_to_disk(self):
    """
    Stops the container and cloudflare tunnel.
    Then logs are saved to disk.
    """
    self.P(f"Stopping container app '{self.container_id}' ...")

    # Stop log streaming
    self._stop_event.set()
    if self.log_thread:
      self.log_thread.join(timeout=5)

    # Stop tunnel engine if needed
    self.stop_tunnel_engine()

    # Stop the container if it's running
    self.stop_container()

    # Save logs to disk
    try:
      # using parent class method to save logs
      self.diskapi_save_pickle_to_output(
        obj=list(self.container_logs), filename="container_logs.pkl"
      )
      self.P("Container logs saved to disk.")
    except Exception as exc:
      self.P(f"Failed to save logs: {exc}", color='r')
    return

  def on_close(self):
    """
    Lifecycle hook called when plugin is stopping.
    Ensures container is shut down and logs are saved.
    Ensures the log process is killed.
    Stops tunnel if started.
    """
    self._stop_container_and_save_logs_to_disk()

    super(ContainerAppRunnerPlugin, self).on_close()


  def _get_latest_image_hash(self):
    """
    Get the latest identifier for the configured Docker image tag.

    This method tries to resolve the remote content digest for ``self.cfg_image`` by
    asking the Docker daemon to perform a metadata-only pull (if the image is
    already up to date, no layers are re-downloaded). It returns the repo digest
    (e.g., ``sha256:...``) when available; if not available, it falls back to the
    local image ID.

    Returns
    -------
    str or None
      A digest like ``sha256:<hex>`` (preferred) or the local image ID. Returns
      ``None`` if neither can be obtained.

    Notes
    -----
    - Works for public and private registries as long as the Docker daemon has
      credentials configured.
    - This call contacts the registry; tune ``poll_interval`` appropriately.
    """
    if not self.cfg_image:
      self.P("No Docker image configured", color='r')
      return None

    # Ensure we're logged in to the registry before pulling
    if not self._login_to_registry():
      raise RuntimeError("Failed to login to container registry. Cannot proceed without authentication.")

    try:
      self.P(f"Image check: pulling '{self.cfg_image}' for metadata...", color='b')
      img = self.docker_client.images.pull(self.cfg_image)
      # docker-py may return Image or list[Image]
      if isinstance(img, list) and img:
        img = img[-1]
      # Ensure attributes loaded
      try:
        img.reload()
      except Exception as e:
        self.P(f"Warning: Could not reload image attributes: {e}", color='y')
      # end try

      attrs = getattr(img, "attrs", {}) or {}
      repo_digests = attrs.get("RepoDigests") or []
      if repo_digests:
        # 'repo@sha256:...'
        digest = repo_digests[0].split("@")[-1]
        return digest
      # Fallback to image id (sha256:...)
      return getattr(img, "id", None)
      
    except Exception as e:
      self.P(f"Image pull failed: {e}", color='r')
      # Fallback: check local image only
      try:
        self.P(f"Checking local image: {self.cfg_image}", color='b')
        img = self.docker_client.images.get(self.cfg_image)
        try:
          img.reload()
        except Exception as e:
          self.P(f"Warning: Could not reload local image attributes: {e}", color='y')
        # end try reload
        attrs = getattr(img, "attrs", {}) or {}
        repo_digests = attrs.get("RepoDigests") or []
        if repo_digests:
          digest = repo_digests[0].split("@")[-1]
          return digest
        return getattr(img, "id", None)
        
      except Exception as e2:
        self.P(f"Could not get local image: {e2}", color='r')
      # end try check for local image
    # end try
    return None

  def _check_image_updates(self, current_time=None):
    """Check for a new version of the Docker image and restart container if found."""
    if not self.cfg_autoupdate:
      return
      
    if current_time - self._last_image_check >= self.cfg_autoupdate_interval:
      self._last_image_check = current_time
      latest_image_hash = self._get_latest_image_hash()
      if latest_image_hash and self.current_image_hash and latest_image_hash != self.current_image_hash:
        self.P(f"New image version detected ({latest_image_hash} != {self.current_image_hash}). Restarting container...", color='y')
        # Update current_image_hash to the new one
        self.current_image_hash = latest_image_hash
        # Restart container from scratch
        self._restart_container()
      elif latest_image_hash:
        self.P(f"Current image hash: {self.current_image_hash} vs latest: {latest_image_hash}")
      # end if new image hash
    # end if time elapsed
    return

  def _restart_container(self):
    """Restart the container from scratch."""
    self.P("Restarting container from scratch...", color='b')
    self._stop_container_and_save_logs_to_disk()
    # Start a new container
    self._stop_event.clear()  # reset stop flag for new log thread
    self.container = self.start_container()
    self.start_tunnel_engine()
    self.container_start_time = self.time()

    # Start log streaming
    if self.container:
      self.log_thread = threading.Thread(
        target=self._stream_logs,
        args=(self.container.logs(stream=True, follow=True),),
        daemon=True,
      )
      self.log_thread.start()
    return

  def _handle_initial_launch(self):
    """Handle the initial container launch."""
    try:
      self.P("Initial container launch...", color='b')
      # Initialize current image hash for update tracking
      self.current_image_hash = self._get_latest_image_hash()
      self.container = self.start_container()
      self.container_start_time = self.time()

      # Start log streaming
      if self.container:
        self.log_thread = threading.Thread(
          target=self._stream_logs,
          args=(self.container.logs(stream=True, follow=True),),
          daemon=True,
        )
        self.log_thread.start()

      self.P("Container launched successfully", color='g')
      self.P(self.container)
      if self.current_image_hash:
        self.P(f"Current image hash: {self.current_image_hash}", color='d')
    except Exception as e:
      self.P(f"Could not start container: {e}", color='r')
    # end try
    return

  def _perform_periodic_monitoring(self):
    """Perform periodic monitoring tasks."""
    current_time = self.time()
    self._check_health_endpoint(current_time)
    self._check_image_updates(current_time)
    return

  def process(self):
    """
    This is the main process loop for the plugin that gets called each PROCESS_DELAY seconds and
    it performs the following:

      1. Initialize and start tunnel engine if needed
      2. Check if container is running and restart if needed
      3. Perform periodic monitoring (health checks, etc.)
      4. Tunnel engine ping and maintenance

    """
    if self._is_manually_stopped:
      self.Pd("Manually stopped app. Skipping launch...", color='y')
      return

    if not self.container:
      self._handle_initial_launch()

    self.maybe_init_tunnel_engine()

    self.maybe_start_tunnel_engine()

    # Start tunnel engine if not already running
    if self.cfg_tunnel_engine_enabled and not self.tunnel_process:
      self.start_tunnel_engine()

    if not self._check_container_status():
      return

    self._perform_periodic_monitoring()
    self.maybe_tunnel_engine_ping()

    return