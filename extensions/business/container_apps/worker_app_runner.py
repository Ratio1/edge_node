"""
DRAFT worker_app_runner.py


TODO:
- add git clone command after each container is started
- OBS: cannot use the parent already existing git helper functions as they deploy in the Edge Node host not in the container.
  - use `remote_commit = self.git_get_last_commit_hash(repo_url=url, user=username, token=token)` to check if the repo is at the latest version
    - save latest commit hash in plugin state
    - if last version restart the container and re-run the clone & build-and-run commands

- (fix running the build and run commands)

"""

from .container_app_runner import ContainerAppRunnerPlugin as BasePlugin

__VER__ = "0.0.1"

_CONFIG = {
  **BasePlugin.CONFIG,

  "IMAGE": "node:lts-alpine",   # default image to run
  
  "GIT_URL" : None,         # clone mandatory url of the git repository
  
  "BUILD_AND_RUN_COMMANDS" : [], 
  
  "CR_DATA": {              # dict of container registry data
    "SERVER": 'docker.io',  # Optional container registry URL
    "USERNAME": None,       # Optional registry username
    "PASSWORD": None,       # Optional registry password or token
  },

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },  
}

class WorkerAppRunnerPlugin(
  BasePlugin
):
  """
  A Ratio1 plugin to run a single Docker/Podman container.

  This plugin:
    - Does the same job, as ContainerAppRunner, except:
      - Mapping the volumes is done directly, you can map any path to your container path
      - Runs only on oracles.
      - Can't be deployed via Deeploy
  """

  CONFIG = _CONFIG


  def on_init(self):
    super(WorkerAppRunnerPlugin, self).on_init()

    return
  
  def __run_commands_in_container(self):
    for container_command in self.cfg_build_and_run_commands:
      if container_command:
        self.log.info(f"Running command in container: {container_command}")
        self._run_command_in_container(container_command) # this is from container utils.
      else:
        self.log.warning("Empty command found in build and run commands, skipping.")
    return
  
  
  def on_post_container_start(self):
    """
    Lifecycle hook called after the container has started.
    Runs any build and run commands specified in the configuration.
    """
    super(WorkerAppRunnerPlugin, self).on_post_container_start()
    
    self.__run_commands_in_container()
    
    return

  def on_close(self):
    """
    Lifecycle hook called when plugin is stopping.
    Ensures container is shut down and logs are saved.
    Ensures the log process is killed.
    Stops tunnel if started.
    """
    super(WorkerAppRunnerPlugin, self).on_close()

  def process(self):
    super(WorkerAppRunnerPlugin, self).process()
    return