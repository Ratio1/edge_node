"""
worker_app_runner.py
A Ratio1 plugin to run a single Docker container with automatic Git repository monitoring and updates.

This plugin:
  - Runs a Docker container with a specified image
  - Clones a Git repository into the container using separate username/token credentials
  - Executes build and run commands
  - Monitors for new commits and automatically restarts the container
  - Monitors for new Docker image versions and automatically restarts
  - Provides real-time log streaming
  - Handles graceful shutdown and cleanup
  - Cannot be deployed via Deeploy

On-init:
  - Initialize Docker client
  - Parse Git repository information
  - Set up monitoring state

Loop:
  - Poll application endpoint
  - Check for new Git commits
  - Check for new Docker image versions
  - Restart container if updates detected

On-close:
  - Stop and remove container
  - Clean up log threads
  - Save logs to disk
"""

import docker
import requests
import threading
import time
import json

from extensions.business.container_apps.container_utils import _ContainerUtilsMixin
from naeural_core.business.base.web_app.base_tunnel_engine_plugin import BaseTunnelEnginePlugin as BasePlugin


__VER__ = "1.0.0"

_CONFIG = {
  **BasePlugin.CONFIG,

  "PROCESS_DELAY": 5,
  "ALLOW_EMPTY_INPUTS": True,
  "TUNNEL_ENGINE_ENABLED": True,
  "TUNNEL_ENGINE": "cloudflare",
  "TUNNEL_ENGINE_PING_INTERVAL": 30,  # seconds
  "CLOUDFLARE_TOKEN": None,
  "TUNNEL_ENGINE_PARAMETERS": {},

  # Container configuration
  "IMAGE": "node:22",  # default Docker image to use
  "BUILD_AND_RUN_COMMANDS": ["npm install", "npm run build", "npm start"],  # commands to run in container

  # Container registry configuration
  "CR_DATA": {  # dict of container registry data
    "SERVER": 'docker.io',  # Optional container registry URL
    "USERNAME": None,  # Optional registry username
    "PASSWORD": None,  # Optional registry password or token
  },

  "VCS_DATA": {
    "PROVIDER": "github",  # currently only "github" is supported
    "USERNAME": None,  # GitHub username for cloning (if private repo)
    "TOKEN": None,  # GitHub personal access token for cloning (if private repo)
    "REPO_OWNER": None,  # GitHub repository owner (user or org)
    "REPO_NAME": None,  # GitHub repository name
    "BRANCH": "main",  # branch to monitor for updates
    "POLL_INTERVAL": 60,  # seconds between Git commit checks
  },

  # Environment variables for the container
  "ENV": {},
  "DYNAMIC_ENV": {},

  # Docker image monitoring
  "IMAGE_POLL_INTERVAL": 300,  # seconds between Docker image checks

  "POLL_COUNT": 0,

  "RESTART_POLICY": "always",  # "always" will restart the container if it stops
  "IMAGE_PULL_POLICY": "always",  # "always" will always pull the image

  # Application endpoint polling
  "ENDPOINT_POLL_INTERVAL": 30,  # seconds between endpoint health checks
  "ENDPOINT_URL": None,  # endpoint to poll for health checks, for example "/edgenode" or "/health"
  "PORT": None,  # internal container port if it's a web app (int)

  # Container resource limits
  "CONTAINER_RESOURCES": {
    "cpu": 1,  # e.g. "0.5" for half a CPU, or "1.0" for one CPU core
    "gpu": 0,
    "memory": "512m",  # e.g. "512m" for 512MB,
    # TODO: add disk usage and limit
    "ports": [] # dict of container_port: host_port mappings (e.g. {8080: 8081}) or list of container ports (e.g. [8080, 9000])
  },

  #### Logging
  "MAX_LOG_LINES": 10_000,  # max lines to keep in memory

  "CAR_VERBOSE": 10,  # max lines to keep in memory

  # Chainstore response configuration
  "CHAINSTORE_RESPONSE_KEY": None,  # Optional key to send confirmation data to chainstore

}


class WorkerAppRunnerPlugin(BasePlugin, _ContainerUtilsMixin):

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
      s = "[DEBUG] " + s
      self.P(s, *args, **kwargs)
    return


  def on_init(self):
    super(WorkerAppRunnerPlugin, self).on_init()

    self.__reset_vars()

    self.reset_tunnel_engine()

    self._set_default_branch()
    self._setup_resource_limits_and_ports() # setup container resource limits (CPU, GPU, memory, ports)
    self._configure_dynamic_env() # setup dynamic env vars for the container
    self._configure_repo_url()

    self.P(f"WorkerAppRunnerPlugin initialized (version {__VER__})", color='g')
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
      self.P("Restarting WAR...")
      self._is_manually_stopped = False
      self._stop_container_and_save_logs_to_disk()
      self._restart_from_scratch()
      return

    elif data == "STOP":
      self.P("Stopping container (restart policy still applies)...")
      self._stop_container_and_save_logs_to_disk()
      self._is_manually_stopped = True
      return
    else:
      self.P(f"Unknown plugin command: {data}")
    return

  def _on_config(self):
    self.Pd("Received an updated config for WorkerAppRunner")
    self._stop_container_and_save_logs_to_disk()
    self._restart_from_scratch()

    return

  def __reset_vars(self):
    """Reset internal state variables."""
    self.container = None

    self.current_commit = None  # Track the current commit SHA
    self.docker_client = docker.from_env()

    self.container_logs = self.deque(maxlen=self.cfg_max_log_lines)

    # Periodic intervals
    self._last_git_check = 0
    self._last_image_check = 0
    self._last_endpoint_check = 0

    # Initialize tunnel process
    self.tunnel_process = None

    # Determine default branch via GitHub API (so we know which branch to monitor)
    self.branch = None

    # Internal state
    self.container = None
    self.log_thread = None
    self._stop_event = threading.Event()
    self.extra_ports_mapping = {}
    self.volumes = {}
    self.dynamic_env = {}

    self._is_manually_stopped = False # Flag to indicate if the container was manually stopped

    # Container start time tracking
    self.container_start_time = None
    self.container_id = None

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


  def _configure_repo_url(self):
    # TODO: support other git providers
    vcs_data = self.cfg_vcs_data or {}
    self.repo_url = f"https://{vcs_data.get('USERNAME')}:{vcs_data.get('TOKEN')}@github.com/{vcs_data.get('REPO_OWNER')}/{vcs_data.get('REPO_NAME')}.git"
    return

  def _set_default_branch(self):
    """Determine the default branch of the repository via GitHub API."""
    vcs_data = self.cfg_vcs_data or {}
    repo_owner = vcs_data.get('REPO_OWNER')
    repo_name = vcs_data.get('REPO_NAME')
    
    if repo_owner and repo_name:
      try:
        resp = self._get_latest_commit(return_data=True)
        if resp is not None:
          _, data = resp
          self.P(f"Repository info:\n {json.dumps(data, indent=2)}", color='b')
          self.branch = data.get("default_branch", None)
          self.P(f"Default branch for {repo_owner}/{repo_name} is '{self.branch}'", color='y')
      except Exception as e:
        self.P(f"[WARN] Could not determine default branch: {e}")
    if not self.branch:
      self.branch = vcs_data.get('BRANCH', "main")  # Use VCS_DATA branch or fallback to 'main'
    return


  def start_container(self):
    """Start the Docker container without running build or app commands."""
    self.P(f"Launching container with image '{self.cfg_image}'...")
    # Run the base container in detached mode with a long-running sleep so it stays alive

    # todo: move these operations to a separate method, to prepare the container config
    # Ports mapping
    ports_mapping = self.extra_ports_mapping.copy() if self.extra_ports_mapping else {}
    if self.cfg_port and self.port:
      ports_mapping[self.port] = self.cfg_port

    inverted_ports_mapping = {f"{v}/tcp": k for k, v in ports_mapping.items()}

    # Volumes mapping (if any)

    # Environment variables
    env = self.cfg_env.copy() if self.cfg_env else {}
    if self.dynamic_env:
      env.update(self.dynamic_env)

    self.P(f"Container data:")
    self.P(f"  Image: {self.cfg_image}")
    self.P(f"  Ports: {self.json_dumps(inverted_ports_mapping) if inverted_ports_mapping else 'None'}")
    self.P(f"  Env: {self.json_dumps(env) if env else 'None'}")
    self.P(f"  Volumes: {self.json_dumps(self.volumes) if self.volumes else 'None'}")
    self.P(f"  Resources: {self.json_dumps(self.cfg_container_resources) if self.cfg_container_resources else 'None'}")
    self.P(f"  Restart policy: {self.cfg_restart_policy}")
    self.P(f"  Pull policy: {self.cfg_image_pull_policy}")
    self.P(f"  Build/Run commands: {self.cfg_build_and_run_commands if self.cfg_build_and_run_commands else 'None'}")

    self.container = self.docker_client.containers.run(
      self.cfg_image,
      command=["sh", "-c", "while true; do sleep 3600; done"],
      detach=True,
      ports=inverted_ports_mapping,
      environment=env,
    )
    self.container_id = self.container.short_id
    self.P(f"Container started (ID: {self.container.short_id})", color='g')
    return self.container


  def execute_build_and_run_cmds(self):
    """Clone the repository and execute build/run commands inside the running container."""
    if not self.container:
      raise RuntimeError("Container must be started before executing commands")

    shell_cmd = (
      f"git clone {self.repo_url} /app && cd /app && " +
      " && ".join(self.cfg_build_and_run_commands)
    )
    self.P(f"Running command in container: {shell_cmd}", color='b')
    # Execute the command and obtain a streaming iterator without blocking
    # although detach is set to False, we can still stream logs and the exec_run is not
    # blocking the calling thread
    exec_result = self.container.exec_run(["sh", "-c", shell_cmd], stream=True, detach=False)
    # Consume the iterator in a background thread so the main thread stays free
    self.log_thread = threading.Thread(
      target=self._stream_logs,
      args=(exec_result.output,),
      daemon=True,
    )
    self.log_thread.start()
    return

  def _get_container_memory(self):
    """Return current memory usage of the container in bytes."""
    if not self.container:
      return 0
    try:
      stats = self.container.stats(stream=False)
      return stats.get("memory_stats", {}).get("usage", 0)
    except Exception as e:
      self.P(f"[WARN] Could not fetch memory usage: {e}")
    # end try
    return 0


  def _launch_container_app(self):
    """Start container, then build and run the app, recording memory usage before and after."""
    container = self.start_container()
    
    # Set container start time
    self.container_start_time = self.time()
    
    # Memory usage before installing the app
    mem_before_mb = self._get_container_memory() / (1024 ** 2)

    # Execute build and run commands
    self.execute_build_and_run_cmds()

    # Allow some time for the app to start before measuring again
    time.sleep(1)
    mem_after_mb = self._get_container_memory() / (1024 ** 2)
    self.P(f"Container memory usage before build/run: {mem_before_mb:>5.0f} MB", color='d')
    self.P(f"Container memory usage after build/run:  {mem_after_mb:>5.0f} MB", color='d')

    # Send plugin start confirmation to chainstore if configured
    self._maybe_send_plugin_start_confirmation()

    return container

  def _restart_from_scratch(self):
    """Stop the current container and start a new one from scratch."""
    self.P("Restarting container from scratch...", color='b')
    self.stop_container()
    self._stop_event.set()  # signal log thread to stop if running
    if self.log_thread:
      self.log_thread.join(timeout=5)
    # Start a new container with the updated code
    self._stop_event.clear()  # reset stop flag for new log thread

    self.__reset_vars()
    self._set_default_branch()
    self._setup_resource_limits_and_ports() # setup container resource limits (CPU, GPU, memory, ports)
    self._configure_dynamic_env() # setup dynamic env vars for the container
    self._configure_repo_url()

    return self._launch_container_app()


  def _stream_logs(self, log_stream):
    """Consume a log iterator from exec_run and print its output."""
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
    if not self.container or not self.cfg_endpoint_url:
      return

    if not current_time:
      current_time = self.time()

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

  def _get_latest_commit(self, return_data=False):
    """Fetch the latest commit SHA of the repository's monitored branch via GitHub API."""
    vcs_data = self.cfg_vcs_data or {}
    repo_owner = vcs_data.get('REPO_OWNER')
    repo_name = vcs_data.get('REPO_NAME')
    token = vcs_data.get('TOKEN')
    
    if not repo_owner or not repo_name:
      self.P("Git repository owner or name not configured", color='y')
      return None

    if self.branch is None:
      api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    else:
      api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/branches/{self.branch}"
    headers = {"Authorization": f"token {token}"} if token else {}

    try:
      self.P(f"Commit check: {api_url}", color='b')
      resp = requests.get(api_url, headers=headers, timeout=10)
      
      if resp.status_code == 200:
        data = resp.json()
        latest_sha = data.get("commit", {}).get("sha", None)
        if return_data:
          return latest_sha, data
        return latest_sha
      elif resp.status_code == 404:
        self.P(f"Repository or branch not found: {api_url}", color='r')
      elif resp.status_code == 403:
        self.P("GitHub API rate limit exceeded or access denied", color='r')
      else:
        self.P(f"Failed to fetch latest commit (HTTP {resp.status_code}): {resp.text}", color='r')
      # end if response status
    except requests.RequestException as e:
      self.P(f"Network error while fetching latest commit: {e}", color='r')
    except Exception as e:
      self.P(f"Unexpected error while fetching latest commit: {e}", color='r')
    # end try
    return None

  def _check_git_updates(self, current_time=None):
    """Check for a new commit in the monitored branch and restart container if found."""
    if not current_time:
      current_time = self.time()

    vcs_data = self.cfg_vcs_data or {}
    poll_interval = vcs_data.get('POLL_INTERVAL', 60)
    
    if current_time - self._last_git_check >= poll_interval:
      self._last_git_check = current_time
      latest_commit = self._get_latest_commit()
      if latest_commit and self.current_commit and latest_commit != self.current_commit:
        self.P(f"New commit detected ({latest_commit[:7]} != {self.current_commit[:7]}). Restarting container...", color='y')
        # Update current_commit to the new one
        self.current_commit = latest_commit
        # Restart container from scratch
        self._restart_from_scratch()
      elif latest_commit:
        self.P(f"Latest commit on {self.branch}: {latest_commit} vs {self.current_commit}")
      # end if new commit
    # end if time elapsed
    return

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

    try:
      self.P(f"Image check: pulling '{self.cfg_image}' for metadata...", color='b')
      img = self.docker_client.images.pull(self.cfg_image)
      # docker-py may return Image or list[Image]
      if isinstance(img, list) and img:
        self.P("Multiple images returned, using the last one", color='y')
        self.P(self.json_dumps([i.id for i in img]), color='y')
        img = img[-1]
      # Ensure attributes loaded
      self.P(f"Image pulled: {getattr(img, 'id', 'unknown id')}", color='g')
      try:
        img.reload()
      except Exception as e:
        self.P(f"Warning: Could not reload image attributes: {e}", color='y')
      # end try

      self.P("Image loaded")


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
    if not current_time:
      current_time = self.time()
    if current_time - self._last_image_check >= self.cfg_image_poll_interval:
      self._last_image_check = current_time
      latest_image_hash = self._get_latest_image_hash()
      if latest_image_hash and self.current_image_hash and latest_image_hash != self.current_image_hash:
        self.P(f"New image version detected ({latest_image_hash} != {self.current_image_hash}). Restarting container...", color='y')
        # Update current_image_hash to the new one
        self.current_image_hash = latest_image_hash
        # Restart container from scratch
        self._restart_from_scratch()
      elif latest_image_hash:
        self.P(f"Current image hash: {self.current_image_hash} vs latest: {latest_image_hash}")
      # end if new image hash
    # end if time elapsed
    return

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
        obj=list(self.container_logs), filename="worker_app_runner_logs.pkl"
      )
      self.P("Container logs saved to disk.")
    except Exception as exc:
      self.P(f"Failed to save logs: {exc}", color='r')
    return


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


  def _handle_initial_launch(self):
    try:
      self.P("Initial container launch...", color='b')
      self.current_commit = self._get_latest_commit()
      self.current_image_hash = self._get_latest_image_hash()
      self.container = self._launch_container_app()
      self.P("Container launched successfully", color='g')
      self.P(self.container)
      if self.current_commit:
        self.P(f"Latest commit on {self.branch}: {self.current_commit}", color='d')

    except Exception as e:
      self.P(f"Could not start container: {e}", color='r')
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

  def _perform_periodic_monitoring(self):
    current_time = self.time()

    self._check_health_endpoint(current_time)

    self._check_git_updates(current_time)
    
    self._check_image_updates(current_time)

    return

  def on_close(self):
    """Cleanup on plugin close."""
    self.P("Shutting down WorkerAppRunnerPlugin...", color='b')
    self._stop_container_and_save_logs_to_disk()
    
    super(WorkerAppRunnerPlugin, self).on_close()

    self.Pd("WorkerAppRunnerPlugin has shut down", color='g')
    return

  def process(self):
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
