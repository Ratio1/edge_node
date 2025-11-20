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
  },

  # Disable image auto-update; Git monitoring drives restarts
  "AUTOUPDATE": False,

  # Application endpoint polling defaults
  "ENDPOINT_POLL_INTERVAL": 30,
  "ENDPOINT_URL": None,

  # Chainstore response configuration (optional)
  "CHAINSTORE_RESPONSE_KEY": None,
}


class WorkerAppRunnerPlugin(ContainerAppRunnerPlugin):

  CONFIG = _CONFIG

  def Pd(self, s, *args, score=-1, **kwargs):
    if self.cfg_car_verbose > score:
      s = "[DEBUG] " + s
      self.P(s, *args, **kwargs)
    return

  def _after_reset(self):
    super()._after_reset()
    self.current_commit = None
    self.branch = None
    self.repo_url = None
    self._last_git_check = 0
    self._repo_configured = False
    self._repo_owner = None
    self._repo_name = None
    return

  def _validate_subclass_config(self):
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
    super()._extra_on_init()
    self._ensure_repo_state(initial=True)
    return

  # --- Command orchestration -------------------------------------------------

  def _build_git_bootstrap_command(self):
    """Return a shell snippet that installs git if it is missing in the container."""
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
    """Check for git updates and return StopReason if restart is required."""
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
    latest_commit = self._get_latest_commit()

    if not latest_commit:
      return None

    if self.current_commit and latest_commit != self.current_commit:
      self.P(
        f"New commit detected ({latest_commit[:7]} != {self.current_commit[:7]}). Restart required.",
        color='y',
      )
      self.current_commit = latest_commit
      return StopReason.EXTERNAL_UPDATE  # Git update triggers external update restart
    else:
      if not self.current_commit:
        self.current_commit = latest_commit
      self.P(f"Commit check ({self.branch}): {latest_commit}", color='d')
    return None

  # --- Git helpers -----------------------------------------------------------

  @property
  def _git_poll_interval(self):
    vcs_data = getattr(self, 'cfg_vcs_data', {}) or {}
    try:
      interval = int(vcs_data.get('POLL_INTERVAL', 60))
    except (TypeError, ValueError):
      interval = 60
    return max(interval, 15)

  def _ensure_repo_state(self, initial=False):
    if self._repo_configured and not initial:
      return

    self._set_default_branch()
    self._configure_repo_url()

    latest_commit = self._get_latest_commit()
    if latest_commit:
      self.current_commit = latest_commit
      self.P(f"Latest commit on {self.branch}: {latest_commit}", color='d')
    else:
      self.P("Unable to determine latest commit during initialization", color='y')

    self._repo_configured = True
    return

  def _configure_repo_url(self):
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

    try:
      self.Pd(f"Commit check URL: {api_url}", score=5, color='b')
      resp = requests.get(api_url, headers=headers, timeout=10)

      if resp.status_code == 200:
        data = resp.json()
        latest_sha = data.get("commit", {}).get("sha", None)
        if return_data:
          return latest_sha, data
        return latest_sha
      if resp.status_code == 404:
        self.P(f"Repository or branch not found: {api_url}", color='r')
      elif resp.status_code == 403:
        self.P("GitHub API rate limit exceeded or access denied", color='r')
      else:
        self.P(f"Failed to fetch latest commit (HTTP {resp.status_code}): {resp.text}", color='r')
    except requests.RequestException as exc:
      self.P(f"Network error while fetching latest commit: {exc}", color='r')
    except Exception as exc:
      self.P(f"Unexpected error while fetching latest commit: {exc}", color='r')

    return (None, None) if return_data else None

  # --- Helpers ---------------------------------------------------------------

  def _extract_repo_identifier(self, vcs_data):
    """Derive repository owner and name from VCS configuration."""
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
