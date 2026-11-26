"""
worker_app_runner.py
A Ratio1 plugin that extends ContainerAppRunnerPlugin with Git-aware restarts.

This plugin:
  - Runs build and run commands inside a container using ContainerAppRunner defaults
  - Clones a Git repository into the container before executing those commands
  - Monitors GitHub for new commits and restarts the container when changes land
  - Uses StopReason.EXTERNAL_UPDATE for Git-triggered restarts (planned restarts)
  - Streams logs and manages tunnel lifecycle through the base runner
"""

import shlex
import re
import subprocess

import requests
from urllib.parse import quote, urlsplit

from extensions.business.container_apps.container_app_runner import (
  ContainerAppRunnerPlugin,
  StopReason,
  RestartPolicy,
)


__VER__ = "1.1.0"

REPO_CLONE_PATH = "/app"


_CONFIG = {
  **ContainerAppRunnerPlugin.CONFIG,

  "CAR_VERBOSE": 10,
  "IMAGE": "node:22",
  "CONTAINER_ENTRYPOINT": "sh",
  "CONTAINER_START_COMMAND": ["-c", "while true; do sleep 3600; done"],
  "CONTAINER_USER": "root",
  "BUILD_AND_RUN_COMMANDS": ["npm install", "npm run build", "npm start"],
  "SETUP_REPO": True, # defines if we have to set up the repo (should add git clone commands or not)

  "VCS_DATA": {
    "PROVIDER": "github",
    "USERNAME": None,
    "TOKEN": None,
    "REPO_OWNER": None,  # optional legacy support
    "REPO_NAME": None,   # optional legacy support
    "REPO_URL": None,
    "BRANCH": "main",
    "POLL_INTERVAL": 60,
    "RATE_LIMIT_BACKOFF": 5 * 60,
  },

  # Disable image auto-update; Git monitoring drives restarts
  "AUTOUPDATE": False,

  # Chainstore response configuration (optional)
  "CHAINSTORE_RESPONSE_KEY": None,
}


class WorkerAppRunnerPlugin(ContainerAppRunnerPlugin):

  CONFIG = _CONFIG

  def Pd(self, s, *args, score=-1, **kwargs):
    """
    Print debug message if verbosity level allows.

    Parameters
    ----------
    s : str
        Message to print
    score : int, optional
        Verbosity threshold (default: -1). Message prints if cfg_car_verbose > score
    *args
        Additional positional arguments passed to P()
    **kwargs
        Additional keyword arguments passed to P()

    Returns
    -------
    None
    """
    if self.cfg_car_verbose > score:
      s = "[DEBUG] " + s
      self.P(s, *args, **kwargs)
    return

  def _after_reset(self):
    """
    Reset worker-specific state variables.

    Called after parent reset to initialize Git-related state variables
    for repository monitoring.

    Returns
    -------
    None
    """
    super()._after_reset()
    self.current_commit = None
    self._deployment_source_error = None
    self._deployment_git_captured = False
    self.branch = None
    self.repo_url = None
    self._last_git_check = 0
    self._git_backoff_until = 0
    self._repo_configured = False
    self._repo_owner = None
    self._repo_name = None
    return

  def _validate_subclass_config(self):
    """
    Validate WorkerAppRunner-specific configuration.

    Ensures BUILD_AND_RUN_COMMANDS and VCS_DATA are properly configured
    for Git-based container deployment.

    Returns
    -------
    None

    Raises
    ------
    ValueError
        If BUILD_AND_RUN_COMMANDS is empty, repository identification fails,
        or POLL_INTERVAL is invalid
    """
    super()._validate_subclass_config()

    if not self._build_commands:
      raise ValueError("BUILD_AND_RUN_COMMANDS must contain at least one command for WorkerAppRunner")

    vcs_data = getattr(self, 'cfg_vcs_data', {}) or {}
    owner, name = self._extract_repo_identifier(vcs_data)
    if not owner or not name:
      raise ValueError("VCS_DATA must provide a GitHub repository via REPO_URL or REPO_OWNER/REPO_NAME")

    self._repo_owner = owner
    self._repo_name = name

    poll_interval = vcs_data.get('POLL_INTERVAL', 60)
    try:
      poll_interval = int(poll_interval)
    except (TypeError, ValueError) as exc:
      raise ValueError("VCS_DATA.POLL_INTERVAL must be an integer") from exc

    if poll_interval < 0:
      raise ValueError("VCS_DATA.POLL_INTERVAL must be positive")

    return

  def _extra_on_init(self):
    """
    Perform worker-specific initialization.

    Ensures repository state is configured before container starts.
    If SEMAPHORED_KEYS is configured, defers repo state setup until
    semaphores are ready (called in _collect_exec_commands).

    Returns
    -------
    None
    """
    super()._extra_on_init()

    # If we have semaphored keys, defer repo state setup until container launch
    # (after semaphores are ready). _collect_exec_commands will call _ensure_repo_state().
    if self._semaphore_get_keys():
      self.Pd("Deferring _ensure_repo_state() until semaphores are ready")
      return

    self._ensure_repo_state(initial=True)
    return

  # --- Command orchestration -------------------------------------------------

  def _build_git_bootstrap_command(self):
    """
    Build shell command to install Git if missing in container.

    Creates a shell script that detects the container's package manager
    and installs Git using the appropriate command.

    Returns
    -------
    str
        Shell command that checks for git and installs it if needed

    Notes
    -----
    Supports package managers: apk, apt-get, apt, yum, dnf, microdnf,
    pacman, and zypper.
    """
    installers = [
      ("apk", "apk add --no-cache git openssh-client"),
      ("apt-get", "apt-get update && apt-get install -y git openssh-client"),
      ("apt", "apt update && apt install -y git openssh-client"),
      ("yum", "yum install -y git openssh-clients"),
      ("dnf", "dnf install -y git openssh-clients"),
      ("microdnf", "microdnf install -y git openssh-clients"),
      ("pacman", "pacman -Sy --noconfirm git openssh"),
      ("zypper", "zypper refresh && zypper install -y git openssh"),
    ]

    checks = []
    for idx, (binary, install_cmd) in enumerate(installers):
      clause = "elif" if idx else "if"
      checks.append(
        f"{clause} command -v {binary} >/dev/null 2>&1; then echo \"Installing git via {binary}\" && {install_cmd}"
      )
    checks.append("else echo \"git is required but no supported package manager was found.\" >&2; exit 1")

    inner_block = " ".join(f"{part};" for part in checks) + " fi;"
    return f"if ! command -v git >/dev/null 2>&1; then {inner_block} fi"

  def _deployment_pins_image(self):
    """
    A worker is never bound to the image it was started with.

    Its image (for example `node:22`) is only the base on which the repository is cloned and built;
    the application is the source code. A pinned worker restores its requested Git commit. The base
    image id exists only in the Docker store that pulled it. Replacing the node's own container can
    empty that store and make the old id unavailable. So the base image follows `IMAGE_PULL_POLICY` like that of an
    untracked worker, and its id is recorded for information only.

    Returns
    -------
    bool
      Always False.

    Examples
    --------
    >>> tracked_worker._deployment_pins_image()
    False
    >>> tracked_worker._get_full_image_ref()   # the configured base image, not a saved id
    'node:22'
    """
    # The base image is pulled again when it is missing; the pinned Git commit is what is restored.
    return False

  def _deployment_git_pin(self):
    if self._deployment_source_mode == "pinned":
      commit = self.cfg_vcs_data.get("COMMIT")
      if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Pinned workers require a complete Git commit")
      return commit
    return self._get_pinned_deployment_artifacts().get("git_commit")

  def _build_git_clone_command(self, repo_path):
    repo_url = shlex.quote(self.repo_url)
    repo_path = shlex.quote(repo_path)
    commit = self._deployment_git_pin()
    if commit:
      # A moved branch must never change the source restored for this revision.
      return (f"git clone --no-checkout {repo_url} {repo_path} && "
              f"git -C {repo_path} fetch origin {shlex.quote(commit)} && "
              f"git -C {repo_path} checkout --detach {shlex.quote(commit)}")
    if self.branch:
      branch = shlex.quote(self.branch)
      # Fetch only the configured branch; this keeps startup clones smaller
      # and avoids accidentally running code from a different branch.
      return f"git clone --branch {branch} --single-branch {repo_url} {repo_path}"
    return f"git clone {repo_url} {repo_path}"

  def read_deployment_git_commit(self):
    """Inspect the live checkout with a bounded local Docker request.

    This one-shot repair challenge does not change the runner's readiness or
    cached artifacts. The Docker client deadline also bounds daemon failures.

    Parameters
    ----------
    None

    Returns
    -------
    str or None
      The full Git commit ID when the running container can attest to it.

    Examples
    --------
    >>> commit = runner.read_deployment_git_commit()
    """
    container_id = self.container.id
    if not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id):
      return None  # Only the actual Docker object held by this runner may be inspected.
    try:
      result = subprocess.run(
        ["docker", "exec", container_id, "timeout", "-k", "1", "5", "git", "-C", REPO_CLONE_PATH,
         "rev-parse", "--verify", "HEAD^{commit}"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=7, check=False,
      )  # The probe has fixed arguments and output, even when the Git process or daemon stalls.
      if getattr(self.container, "id", None) != container_id:
        return None  # A concurrent runner restart replaced the inspected Docker container.
      commit = result.stdout.decode("ascii").strip()
      return commit if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", commit) else None
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
      return None  # No executable observation can be made while Docker or the checkout is unavailable.

  def _capture_checkout(self):
    """
    Record the container's source before the worker confirms readiness.

    Until the check has passed (once after each restart from scratch, which resets it), each call
    reads the clone's HEAD inside the container (`git rev-parse HEAD`), checks it against the bound
    Git commit, and records it with the runtime artifacts. A clone that is not there yet keeps the
    worker waiting. A HEAD that differs from the bound commit is reported as "failed"
    (WORKLOAD_START_FAILED): that container never runs the bound source. Any other error of the check
    (the Docker exec, a HEAD that is not a commit id, the save of the artifacts) is logged in red and
    not reported: the next lap checks again, so a worker whose check passes later is reported ready
    and not left "failed".

    Parameters
    ----------
    None

    Returns
    -------
    bool
      Whether the source check passed.

    Notes
    -----
    A following worker with SETUP_REPO disabled may use prebuilt or mounted
    source. A nonzero Git command exit then passes the check without reporting a
    commit. A pinned worker still needs a matching Git checkout.

    Examples
    --------
    >>> worker._capture_checkout()   # the clone runs the bound commit
    True
    >>> worker._capture_checkout()   # the Docker exec raised: logged, tried again on the next lap
    False
    """
    if getattr(self, "_deployment_git_captured", False):
      return True
    try:
      result = self.container.exec_run(
        ["timeout", "5", "git", "-C", REPO_CLONE_PATH, "rev-parse", "HEAD"],
        stdout=True, stderr=True,
      )
      if result.exit_code != 0:
        if self._deployment_source_mode == "following" and not self.cfg_setup_repo:
          # Pre-baked or mounted source may lack .git. There is no commit to report.
          self._deployment_git_captured = True
          return True
        # The clone/build command may still be running when a permissive generic
        # health mode first reports readiness. Keep waiting for the source proof.
        self._app_ready = False
        return False
      commit = result.output.decode("ascii").strip() if result.exit_code == 0 else ""
      if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError("The running source revision is unavailable")
      artifacts = self._get_pinned_deployment_artifacts()
      requested = self._deployment_git_pin()
      if requested and requested != commit:
        # A confirmed wrong revision cannot become ready on a subsequent check.
        self.report_deployment_status("failed", error_code="WORKLOAD_START_FAILED")
        raise RuntimeError("The running source does not match its immutable binding")
      artifacts.update(self.get_deployment_runtime_artifacts())
      artifacts["git_commit"] = commit
      self._save_deployment_artifacts(artifacts)
      self.current_commit = commit  # Subsequent checks compare with the actual checkout.
      self._deployment_git_captured = True
      return True
    except Exception as exc:
      self._app_ready = False
      self.set_plugin_ready(False)
      # Only the proven mismatch above is reported as failed; any other error is not, and the next lap checks again,
      # as for a clone not there yet. Before, every error was, and that failure stayed although the worker later ran.
      self.P("Could not confirm the running source revision: {}. Checked again on the next lap.".format(exc), color='r')
      return False

  def _stream_deployment_exec(self, execution_id, output, stop_event):
    # The clone is a separate Docker exec. No user build command can race observation of its HEAD.
    succeeded = super()._stream_deployment_exec(execution_id, output, stop_event)
    if (succeeded and self._deployment_source_mode in ("following", "pinned")
        and not self._deployment_git_captured and not stop_event.is_set()):
      if self._capture_checkout():
        self._commands_started = False  # Let the plugin thread issue the build on its next tick.
      else:
        self._report_exec_failure()

  def _confirm_app_readiness(self):
    if not self._capture_checkout():
      return False
    return super()._confirm_app_readiness()

  def _is_app_ready(self):
    if self._deployment_source_mode in ("following", "pinned") and (
        not getattr(self, "_build_dispatched", False) or getattr(self, "_commands_failed", False)):
      # A completed clone, or a failed build, cannot satisfy even a delay-only health check.
      return False
    return super()._is_app_ready()

  def start_container(self):
    # Starts after a volume sync/reset also need a fresh Git observation.
    self._deployment_git_captured = False
    self._build_dispatched = False
    return super().start_container()

  def _check_stopped_source(self):
    if not self._repo_configured:
      self._ensure_repo_state()
      return False
    if self._check_git_updates(self.time()):
      self._restart_container(StopReason.EXTERNAL_UPDATE)
      return True
    # A failed build retains its checkout even if its container exits or the restart budget is unlimited.
    return getattr(self, "_commands_failed", False) or super()._check_stopped_source()

  def _collect_exec_commands(self):
    """
    Collect commands to execute inside container.

    Builds command sequence that:
    1. Installs git if needed
    2. Clones repository
    3. Executes build/run commands

    Returns
    -------
    list of str
        Shell commands to execute, or empty list if repo not configured
    """
    base_commands = super()._collect_exec_commands()
    if not base_commands:
      return []

    self._ensure_repo_state()

    if not self.repo_url:
      self.P("Repository URL is not configured; skipping build/run commands", color='r')
      return []

    repo_path = REPO_CLONE_PATH
    source_mode = self._deployment_source_mode
    build = [f"cd {repo_path} && {cmd}" for cmd in base_commands]
    if source_mode in ("following", "pinned") and self._deployment_git_captured:
      self._build_dispatched = True
      return build
    commands = [self._build_git_bootstrap_command()]
    # With an externally prepared checkout, the bootstrap still enables HEAD validation.
    if self.cfg_setup_repo:
      commands.append(f"rm -rf {repo_path}")
      commands.append(self._build_git_clone_command(repo_path))
    if source_mode not in ("following", "pinned"):
      commands.extend(build)  # Catalogue and legacy workers retain their existing single exec.
    return commands

  # --- Monitoring ------------------------------------------------------------

  def _perform_additional_checks(self, current_time):
    """
    Check for git updates and trigger restart if needed.

    Parameters
    ----------
    current_time : float
        Current timestamp for interval checking

    Returns
    -------
    StopReason or None
        StopReason.EXTERNAL_UPDATE if new commit detected, None otherwise
    """
    sync_reason = super()._perform_additional_checks(current_time)
    if sync_reason:
      return sync_reason
    if getattr(self, "_reset_processed_this_tick", False):
      return None
    return self._check_git_updates(current_time)

  def _check_git_updates(self, current_time=None):
    """
    Check for new commits in the repository.

    Returns
    -------
    StopReason or None
      StopReason.EXTERNAL_UPDATE if a new commit was detected and restart is required,
      None otherwise.
    """
    mode = self._deployment_source_mode
    if mode == "pinned" or (mode in ("service", None) and self._deployment_tracks_runtime()):
      return None
    if mode == "following" and not self.cfg_setup_repo:
      # Restarting on a branch change cannot update a checkout managed outside the runner.
      return None
    if not current_time:
      current_time = self.time()

    poll_interval = self._git_poll_interval
    if current_time - self._last_git_check < poll_interval:
      return None

    self._last_git_check = current_time
    previous_commit = self.current_commit
    if mode == "following" and not self.branch:
      self._set_default_branch()  # The repository metadata may have been unavailable during startup.
    latest_commit = self._get_latest_commit() if self.branch else None

    if mode == "following":
      # Failure to read the branch is independent of workload health. Check it again next interval.
      self._deployment_source_error = None if latest_commit else "SOURCE_UNREACHABLE"
    if not latest_commit:
      return None

    if (previous_commit and latest_commit != previous_commit) or (
        not previous_commit and getattr(self, "_commands_failed", False)):
      # When both the first lookup and the clone failed, the first readable commit permits a retry.
      self.P(
        f"New branch head {latest_commit[:7]}. Restart required.",
        color='y',
      )
      return StopReason.EXTERNAL_UPDATE  # Git update triggers external update restart
    else:
      self.P(f"Commit check ({self.branch}): {latest_commit}", color='d')
    return None

  # --- Git helpers -----------------------------------------------------------

  @property
  def _git_poll_interval(self):
    """
    Get Git polling interval from configuration.

    Returns
    -------
    int
        Polling interval in seconds (minimum 15, default 60)
    """
    vcs_data = getattr(self, 'cfg_vcs_data', {}) or {}
    try:
      interval = int(vcs_data.get('POLL_INTERVAL', 60))
    except (TypeError, ValueError):
      interval = 60
    return max(interval, 15)

  def _ensure_repo_state(self, initial=False):
    """
    Ensure repository state is configured.

    Configures branch, repository URL, and fetches latest commit.

    Parameters
    ----------
    initial : bool, optional
        If True, forces reconfiguration even if already configured (default: False)

    Returns
    -------
    None
    """
    if self._repo_configured and not initial:
      return

    self._configure_repo_url()
    artifacts = self._get_pinned_deployment_artifacts()
    if self._deployment_git_pin():
      self._repo_configured = True
      return
    following = self._deployment_source_mode == "following"
    if following and not self.cfg_setup_repo:
      # The existing /app tree is authoritative when Git setup is disabled.
      self.branch = self.cfg_vcs_data.get("BRANCH") or self.branch
      self._repo_configured = True
      return
    if not following and getattr(self, "cfg_deeploy_runtime_artifacts", None) is not None:
      raise ValueError("Restoring a worker requires its exact previous Git commit")
    self._set_default_branch()

    latest_commit = self._get_latest_commit() if self.branch else None
    self._last_git_check = self.time()

    if latest_commit:
      self.P(f"Latest commit on {self.branch}: {latest_commit}", color='d')
    else:
      self.P("Unable to determine latest commit during initialization", color='y')

    if following:
      self.current_commit = latest_commit  # Baseline for a failed clone until its actual checkout is available.
      self._deployment_source_error = None if latest_commit else "SOURCE_UNREACHABLE"
    elif self._deployment_tracks_runtime():
      if not isinstance(latest_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", latest_commit):
        raise ValueError("The deployment Git commit could not be resolved")
      artifacts["git_commit"] = latest_commit
      self._save_deployment_artifacts(artifacts)

    self._repo_configured = True
    return

  def _configure_repo_url(self):
    """
    Configure repository URL with authentication if provided.

    Builds GitHub repository URL with optional username/token credentials.

    Returns
    -------
    None

    Notes
    -----
    Sets self.repo_url with one of these formats:
    - Public: https://github.com/owner/repo.git
    - Token only: https://token@github.com/owner/repo.git
    - User+token: https://user:token@github.com/owner/repo.git
    """
    vcs_data = getattr(self, 'cfg_vcs_data', {}) or {}
    username = vcs_data.get('USERNAME')
    token = vcs_data.get('TOKEN')

    owner = getattr(self, "_repo_owner", None)
    repo = getattr(self, "_repo_name", None)
    if not owner or not repo:
      owner, repo = self._extract_repo_identifier(vcs_data)

    if not owner or not repo:
      self.repo_url = None
      return

    base_url = f"https://github.com/{owner}/{repo}.git"

    if username and token:
      self.repo_url = f"https://{username}:{token}@github.com/{owner}/{repo}.git"
    elif token and not username:
      self.repo_url = f"https://{token}@github.com/{owner}/{repo}.git"
    elif username and not token:
      self.repo_url = f"https://{username}@github.com/{owner}/{repo}.git"
    else:
      self.repo_url = base_url
    return

  def _set_default_branch(self):
    """
    Determine and set the default repository branch.

    Attempts to fetch the default branch from GitHub API if not
    configured, falling back to 'main' if detection fails.

    Returns
    -------
    None

    Notes
    -----
    Branch selection priority:
    1. cfg_vcs_data['BRANCH'] if specified
    2. GitHub API default_branch if accessible
    3. 'main' as final fallback
    """
    vcs_data = getattr(self, 'cfg_vcs_data', {}) or {}
    repo_branch = vcs_data.get('BRANCH')
    repo_owner = getattr(self, "_repo_owner", None) or vcs_data.get('REPO_OWNER')
    repo_name = getattr(self, "_repo_name", None) or vcs_data.get('REPO_NAME')

    self.branch = repo_branch or self.branch

    if repo_owner and repo_name and not self.branch:
      try:
        _, data = self._get_latest_commit(return_data=True)
        if data is not None:
          default_branch = data.get('default_branch')  # On a repository response, 'name' names the repo.
          if default_branch:
            self.branch = default_branch
            self.P(f"Default branch for {repo_owner}/{repo_name} is '{self.branch}'", color='y')
      except Exception as exc:
        self.P(f"[WARN] Could not determine default branch: {exc}")

    if not self.branch and self._deployment_source_mode != "following":
      self.branch = repo_branch or "main"
    # Following workers leave an unknown branch unset: Git clones the remote default, even when it is not main.
    return

  def _get_latest_commit(self, return_data=False):
    vcs_data = getattr(self, 'cfg_vcs_data', {}) or {}
    repo_owner = getattr(self, "_repo_owner", None) or vcs_data.get('REPO_OWNER')
    repo_name = getattr(self, "_repo_name", None) or vcs_data.get('REPO_NAME')
    token = vcs_data.get('TOKEN')

    if not repo_owner or not repo_name:
      self.P("Git repository owner or name not configured", color='y')
      return (None, None) if return_data else None

    if self.branch is None:
      api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    else:
      api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/branches/{quote(self.branch, safe='')}"

    headers = {"Authorization": f"token {token}"} if token else {}

    if self.time() < self._git_backoff_until:
      return (None, None) if return_data else None

    try:
      self.Pd(f"Commit check URL: {api_url}", score=5, color='b')
      resp = requests.get(api_url, headers=headers, timeout=10)

      if resp.status_code == 200:
        data = resp.json()
        latest_sha = data.get("commit", {}).get("sha", None)
        if self._deployment_source_mode == "following" and (
            not isinstance(latest_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", latest_sha)):
          latest_sha = None  # An incomplete GitHub response gives no evidence that the branch moved.
        if latest_sha and self._deployment_source_mode != "following":
          self.current_commit = latest_sha
        if return_data:
          return latest_sha, data
        return latest_sha
      if resp.status_code == 404:
        self.P(f"Repository or branch not found: {api_url}", color='r')
      elif resp.status_code == 403:
        vcs_backoff = (getattr(self, 'cfg_vcs_data', {}) or {}).get('RATE_LIMIT_BACKOFF', 300)
        self._git_backoff_until = self.time() + vcs_backoff
        self.P(f"GitHub API rate limit exceeded or access denied. Backing off for {vcs_backoff}s.", color='r')
      else:
        self.P(f"Failed to fetch latest commit (HTTP {resp.status_code}): {resp.text}", color='r')
    except requests.RequestException as exc:
      self.P(f"Network error while fetching latest commit: {exc}", color='r')
    except Exception as exc:
      self.P(f"Unexpected error while fetching latest commit: {exc}", color='r')

    return (None, None) if return_data else None

  # --- Helpers ---------------------------------------------------------------

  def _extract_repo_identifier(self, vcs_data):
    """
    Extract repository owner and name from VCS configuration.

    Parses REPO_OWNER/REPO_NAME or extracts from REPO_URL.

    Parameters
    ----------
    vcs_data : dict
        VCS configuration dictionary

    Returns
    -------
    tuple of (str, str)
        Repository owner and name, or (None, None) if extraction fails

    Examples
    --------
    >>> _extract_repo_identifier({'REPO_OWNER': 'user', 'REPO_NAME': 'repo'})
    ('user', 'repo')
    >>> _extract_repo_identifier({'REPO_URL': 'https://github.com/user/repo.git'})
    ('user', 'repo')
    """
    repo_url = vcs_data.get('REPO_URL')
    owner = vcs_data.get('REPO_OWNER')
    name = vcs_data.get('REPO_NAME')

    if owner and name:
      return owner, name

    if not repo_url:
      return owner, name

    try:
      parsed = urlsplit(repo_url)
      path = parsed.path or ""
      path = path.strip('/')
      if path.endswith('.git'):
        path = path[:-4]
      segments = [segment for segment in path.split('/') if segment]
      if len(segments) >= 2:
        owner = segments[0]
        name = segments[1]
    except Exception as exc:
      self.Pd(f"Failed to parse REPO_URL '{repo_url}': {exc}", score=5, color='y')

    return owner, name
