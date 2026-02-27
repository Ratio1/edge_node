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

import requests
from urllib.parse import urlsplit

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
  "CONTAINER_START_COMMAND": ["sh", "-c", "while true; do sleep 3600; done"],
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
    commands = [
      self._build_git_bootstrap_command()
    ]
    if self.cfg_setup_repo:
      commands.append(f"rm -rf {repo_path}")
      commands.append(f"git clone {self.repo_url} {repo_path}")
    # endif
    # last_commit = commit
    commands.extend([f"cd {repo_path} && {cmd}" for cmd in base_commands])
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
    if not current_time:
      current_time = self.time()

    poll_interval = self._git_poll_interval
    if current_time - self._last_git_check < poll_interval:
      return None

    self._last_git_check = current_time
    previous_commit = self.current_commit
    latest_commit = self._get_latest_commit()

    if not latest_commit:
      return None

    if previous_commit and latest_commit != previous_commit:
      self.P(
        f"New commit detected ({latest_commit[:7]} != {previous_commit[:7]}). Restart required.",
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

    self._set_default_branch()
    self._configure_repo_url()

    latest_commit = self._get_latest_commit()
    self._last_git_check = self.time()

    if latest_commit:
      self.P(f"Latest commit on {self.branch}: {latest_commit}", color='d')
    else:
      self.P("Unable to determine latest commit during initialization", color='y')

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

    owner = self._repo_owner
    repo = self._repo_name

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
    repo_owner = self._repo_owner or vcs_data.get('REPO_OWNER')
    repo_name = self._repo_name or vcs_data.get('REPO_NAME')

    self.branch = repo_branch or self.branch

    if repo_owner and repo_name and repo_branch is None:
      try:
        _, data = self._get_latest_commit(return_data=True)
        if data is not None:
          default_branch = data.get('default_branch') or data.get('name')
          if default_branch:
            self.branch = default_branch
            self.P(f"Default branch for {repo_owner}/{repo_name} is '{self.branch}'", color='y')
      except Exception as exc:
        self.P(f"[WARN] Could not determine default branch: {exc}")

    if not self.branch:
      self.branch = repo_branch or "main"
    return

  def _get_latest_commit(self, return_data=False):
    vcs_data = getattr(self, 'cfg_vcs_data', {}) or {}
    repo_owner = self._repo_owner or vcs_data.get('REPO_OWNER')
    repo_name = self._repo_name or vcs_data.get('REPO_NAME')
    token = vcs_data.get('TOKEN')

    if not repo_owner or not repo_name:
      self.P("Git repository owner or name not configured", color='y')
      return (None, None) if return_data else None

    if self.branch is None:
      api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    else:
      api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/branches/{self.branch}"

    headers = {"Authorization": f"token {token}"} if token else {}

    if self.time() < self._git_backoff_until:
      return (None, None) if return_data else None

    try:
      self.Pd(f"Commit check URL: {api_url}", score=5, color='b')
      resp = requests.get(api_url, headers=headers, timeout=10)

      if resp.status_code == 200:
        data = resp.json()
        latest_sha = data.get("commit", {}).get("sha", None)
        if latest_sha:
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
