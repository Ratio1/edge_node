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

import os
import docker
import requests
import threading
import time
import json
from urllib.parse import urlparse

from naeural_core.business.base.web_app.base_tunnel_engine_plugin import BaseTunnelEnginePlugin as BasePlugin


__VER__ = "1.0.0"

_CONFIG = {
  **BasePlugin.CONFIG,

  "PROCESS_DELAY": 30,  # seconds to wait between process calls
  "ALLOW_EMPTY_INPUTS": True,

  # Container configuration
  "IMAGE": "node:18",  # default Docker image to use
  "REPO_URL": None,  # Git repository URL (without credentials)
  "BUILD_AND_RUN_COMMANDS": ["npm install", "npm run build", "npm start"],  # commands to run in container

  # Container registry configuration
  "CR_DATA": {  # dict of container registry data
    "SERVER": 'docker.io',  # Optional container registry URL
    "USERNAME": None,  # Optional registry username
    "PASSWORD": None,  # Optional registry password or token
  },

  # Environment variables for the container
  "ENV": {},

  # Container port mapping
  "PORT": 3000,  # internal container port

  # Git monitoring configuration
  "GIT_BRANCH": "main",  # branch to monitor for updates
  "GIT_POLL_INTERVAL": 60,  # seconds between Git commit checks

  # Docker image monitoring
  "IMAGE_POLL_INTERVAL": 300,  # seconds between Docker image checks

  "POLL_COUNT": 0,

  # Application endpoint polling
  "ENDPOINT_POLL_INTERVAL": 30,  # seconds between endpoint health checks
  "ENDPOINT_URL": "/edgenode",  # endpoint to poll for health checks

  # Container resource limits
  "CONTAINER_RESOURCES": {
    "cpu": 1,
    "gpu": 0,
    "memory": "512m",
  },

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES']
  },
}


class WorkerAppRunnerPlugin(BasePlugin):
  def on_init(self):
    super(WorkerAppRunnerPlugin, self).on_init()

    self.container = None

    self.done = False  # Flag to indicate when to stop the main loop
    self.current_commit = None  # Track the current commit SHA
    self.docker_client = docker.from_env()

    # Periodic intervals
    self._last_git_check = 0
    self._last_image_check = 0
    self._last_endpoint_check = 0

    # Determine default branch via GitHub API (so we know which branch to monitor)
    self.branch = None
    if self.cfg_repo_owner and self.cfg_repo_name:
      try:
        resp = self._get_latest_commit(return_data=True)
        if resp is not None:
          _, data = resp
          self.P(f"Repository info:\n {json.dumps(data, indent=2)}", color='b')
          self.branch = data.get("default_branch", None)
          self.P(f"Default branch for {self.cfg_repo_owner}/{self.cfg_repo_name} is '{self.branch}'", color='y')
      except Exception as e:
        self.P(f"[WARN] Could not determine default branch: {e}")
    if not self.branch:
      self.branch = "main"  # Fallback to 'main' if not determined

    # Internal state
    self.container = None
    self.log_thread = None
    self._stop_event = threading.Event()


    self.P(f"WorkerAppRunnerPlugin initialized (version {__VER__})", color='g')

    return




  def start_container(self):
    """Start the Docker container without running build or app commands."""
    self.P(f"Launching container with image '{self.cfg_image}'...")
    # Run the base container in detached mode with a long running sleep so it stays alive
    self.container = self.docker_client.containers.run(
      self.cfg_image,
      command=["sh", "-c", "while true; do sleep 3600; done"],
      detach=True,
      ports={"3000/tcp": 3000},
      environment=self.cfg_env,
    )
    self.P(f"Container started (ID: {self.container.short_id}).")
    return self.container


  def execute_build_and_run_cmds(self):
    """Clone the repository and execute build/run commands inside the running container."""
    if not self.container:
      raise RuntimeError("Container must be started before executing commands")

    shell_cmd = (
      f"git clone {self.cfg_repo_url} /app && cd /app && " +
      " && ".join(self.cfg_build_and_run_commands)
    )
    self.P("Running command in container: {}".format(shell_cmd))
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
      return 0


  def _launch_container_app(self):
    """Start container, then build and run the app, recording memory usage before and after."""
    container = self.start_container()
    # Memory usage before installing the app
    mem_before_mb = self._get_container_memory() / (1024 ** 2)

    # Execute build and run commands
    self.execute_build_and_run_cmds()

    # Allow some time for the app to start before measuring again
    time.sleep(1)
    mem_after_mb = self._get_container_memory() / (1024 ** 2)
    self.P(f"Container memory usage before build/run: {mem_before_mb:>5.0f} MB")
    self.P(f"Container memory usage after build/run:  {mem_after_mb:>5.0f} MB")

    return container

  def _restart_from_scratch(self):
    """Stop the current container and start a new one from scratch."""
    self.P("Restarting container from scratch...")
    self.stop_container()
    self._stop_event.set()  # signal log thread to stop if running
    if self.log_thread:
      self.log_thread.join(timeout=5)
    # Start a new container with the updated code
    self._stop_event.clear()  # reset stop flag for new log thread
    return self._launch_container_app()


  def _stream_logs(self, log_stream):
    """Consume a log iterator from exec_run and print its output."""
    if not log_stream:
      return
    try:
      for log_bytes in log_stream:
        if log_bytes is None:
          break
        try:
          log_str = log_bytes.decode("utf-8", errors="replace")
        except Exception:
          log_str = str(log_bytes)
        self.P(f"[CONTAINER] {log_str}", color='d', end='')
        if self._stop_event.is_set():
          break
    except Exception as e:
      self.P(f"[ERROR] Exception while streaming logs: {e}")
    return

  def _check_health_endpoint(self, current_time=None):
    if not self.container or not self.cfg_endpoint_url:
      return

    if current_time - self._last_endpoint_check >= self.cfg_endpoint_poll_interval:
      self._last_endpoint_check = current_time
      self._poll_endpoint()


  def _poll_endpoint(self):
    """Poll the container's health endpoint and log the response."""

    url = f"http://localhost:{self.cfg_port}{self.cfg_endpoint_url}"

    try:
      self.P(f"Polling health endpoint: {url}", color='b')
      resp = requests.get(url, timeout=5)
      status = resp.status_code

      if status == 200:
        self.P(f"Health check: {url} -> {status} OK", color='g')
      else:
        self.P(f"Health check: {url} -> {status} Error", color='r')

    except requests.RequestException as e:
      self.P(f"Health check failed: {url} - {e}", color='r')
    return

  def _get_latest_commit(self, return_data=False):
    """Fetch the latest commit SHA of the repository's monitored branch via GitHub API."""
    if not self.cfg_repo_owner or not self.cfg_repo_name:
      return None
    if self.branch is None:
      api_url = f"https://api.github.com/repos/{self.cfg_repo_owner}/{self.cfg_repo_name}"
    else:
      api_url = f"https://api.github.com/repos/{self.cfg_repo_owner}/{self.cfg_repo_name}/branches/{self.branch}"
    headers = {"Authorization": f"token {self.cfg_git_token}"} if self.cfg_git_token else {}
    try:
      self.P(f"Commit check: {api_url}", color='b')
      resp = requests.get(api_url, headers=headers, timeout=5)
      data = resp.json() if resp.status_code == 200 else {}
      if resp.status_code != 200:
        self.P(f"[ERROR] Failed to fetch latest commit: {resp.text}", color='r')
      latest_sha = data.get("commit", {}).get("sha", None)
      if return_data:
        return latest_sha, data
      return latest_sha
    except Exception as e:
      self.P(f"[WARN] Failed to fetch latest commit: {e}", color='r')
    return None

  def _check_git_updates(self, current_time=None):
    """Check for a new commit in the monitored branch and restart container if found."""
    if current_time - self._last_git_check < self.cfg_git_poll_interval:
      latest_commit = self._get_latest_commit()
      if latest_commit and self.current_commit and latest_commit != self.current_commit:
        self.P(f"New commit detected ({latest_commit[:7]} != {self.current_commit[:7]}). Restarting container...")
        # Update current_commit to the new one
        self.current_commit = latest_commit
        # Restart container from scratch
        self._restart_from_scratch()
      elif latest_commit:
        self.P(f"Latest commit on {self.branch}: {latest_commit} vs {self.current_commit}")
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
    try:
      self.P(f"Image check: pulling '{self.cfg_image}' for metadata...", color='b')
      img = self.docker_client.images.pull(self.cfg_image)
      # docker-py may return Image or list[Image]
      if isinstance(img, list) and img:
        img = img[-1]
      # Ensure attributes loaded
      try:
        img.reload()
      except Exception:
        pass
      attrs = getattr(img, "attrs", {}) or {}
      repo_digests = attrs.get("RepoDigests") or []
      if repo_digests:
        # 'repo@sha256:...'
        digest = repo_digests[0].split("@")[-1]
        return digest
      # Fallback to image id (sha256:...)
      return getattr(img, "id", None)
    except Exception as e:
      self.P(f"[WARN] Image pull failed: {e}", color='r')
      # Fallback: check local image only
      try:
        img = self.docker_client.images.get(self.cfg_image)
        try:
          img.reload()
        except Exception:
          pass
        attrs = getattr(img, "attrs", {}) or {}
        repo_digests = attrs.get("RepoDigests") or []
        if repo_digests:
          digest = repo_digests[0].split("@")[-1]
          return digest
        return getattr(img, "id", None)
      except Exception as e2:
        self.P(f"[WARN] Could not get local image: {e2}", color='r')
        return None

  def _check_image_updates(self, current_time=None):
    """Check for a new version of the Docker image and restart container if found."""
    if current_time - self._last_image_check >= self.cfg_image_poll_interval:
      self._last_image_check = current_time
      latest_image_hash = self._get_latest_image_hash()
      if latest_image_hash and self.current_image_hash and latest_image_hash != self.current_image_hash:
        self.P(f"New image version detected ({latest_image_hash} != {self.current_image_hash}). Restarting container...")
        # Update current_image_hash to the new one
        self.current_image_hash = latest_image_hash
        # Restart container from scratch
        self._restart_from_scratch()
      elif latest_image_hash:
        self.P(f"Current image hash: {self.current_image_hash} vs latest: {latest_image_hash}")
    return


  def stop_container(self):
    """Stop and remove the Docker container if it is running."""
    if self.container:
      try:
        # Stop the container (gracefully)
        self.container.stop(timeout=5)
      except Exception as e:
        self.P(f"[WARN] Error stopping container: {e}", color='r')
      try:
        self.container.remove()
      except Exception as e:
        self.P(f"[WARN] Error removing container: {e}", color='r')
      finally:
        self.container = None
    return

  def run(self):
    """Run the container and monitor it, restarting on new commits and handling graceful shutdown."""
    self.P("Starting container manager...")
    self.current_commit = self._get_latest_commit()
    self.current_image_hash = self._get_latest_image_hash()
    if self.current_commit:
      self.P(f"Latest commit on {self.branch}: {self.current_commit}")

    try:
      # Initial container launch
      self._launch_container_app()
      self.done = False
      while not self.done:
        # Sleep for the poll interval
        time.sleep(self.poll_interval)
        # Poll the application endpoint
        self._poll_endpoint()
        # Check for new commits in the repository
        latest_commit = self._get_latest_commit()
        trigger_restart = False
        if latest_commit and self.current_commit and latest_commit != self.current_commit:
          self.P(f"New commit detected ({latest_commit[:7]} != {self.current_commit[:7]}). Restarting container...")
          # Update current_commit to the new one
          self.current_commit = latest_commit
          trigger_restart = True

        if trigger_restart:
          # Stop and remove current container, and end its log thread
          self._restart_from_scratch()
          continue  # continue monitoring with new container

        elif latest_commit:
          self.P(f"Latest commit on {self.branch}: {latest_commit} vs {self.current_commit}")
        # If container has stopped on its own (unexpectedly), break out to end the loop
    except KeyboardInterrupt:
      # Handle Ctrl+C gracefully (SIGINT handled by signal handler too)
      self.P("\nKeyboardInterrupt received. Shutting down...")
      # (The signal handler will also invoke stop_container)
    finally:
      # Ensure container is cleaned up if still running
      self.stop_container()
      # Ensure log thread is stopped
      self._stop_event.set()
      if self.log_thread:
        self.log_thread.join(timeout=5)
      self.P("Container manager has exited.")
    return


  def _handle_initial_launch(self):
    try:
      self.P("Initial container launch...")
      self.current_commit = self._get_latest_commit()
      self.current_image_hash = self._get_latest_image_hash()
      self.container = self._launch_container_app()
      self.P("Container launched successfully.", color='g')
      self.P(self.container)
      if self.current_commit:
        self.P(f"Latest commit on {self.branch}: {self.current_commit}")

    except Exception as e:
      self.P(f"[ERR] Could not start container: {e}", color='r')

  def _check_container_status(self):
    try:
      if self.container:
        # Refresh container status
        self.container.reload()
        if self.container.status != "running":
          self.P("[ERROR] Container stopped unexpectedly (exit code {}).".format(
            self.container.attrs.get("State", {}).get("ExitCode")))
          return False
        # end if container not running
      # end if self.container
      return True
    except Exception as e:
      self.P(f"[ERROR] Could not check container status: {e}", color='r')
      self.container = None
      return False

  def _perform_periodic_monitoring(self):
    current_time = self.time()

    self._check_health_endpoint(current_time)

    self._check_git_updates(current_time)

    # self._check

  def on_close(self):
    """Cleanup on plugin close."""
    self.done = True
    self.stop_container()
    self._stop_event.set()
    if self.log_thread:
      self.log_thread.join(timeout=5)
    super(WorkerAppRunnerPlugin, self).on_close()

    return

  def process(self):
    if not self.container:
      self._handle_initial_launch()

    if not self._check_container_status():
      return

    self._perform_periodic_monitoring()

    return