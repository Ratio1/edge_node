"""
admin_container_app_runner.py
A Ratio1 plugin that runs only on Oracles, to run a single Docker/Podman container
and (if needed) expose it via tunnel engine.
"""

from .container_app_runner import ContainerAppRunnerPlugin as BasePlugin

__VER__ = "1.0.0"

_CONFIG = {
  **BasePlugin.CONFIG,

  "RUNS_ONLY_ON_SUPERVISOR_NODE" : True,

  "MOUNT_EDGE_NODE_DATA_VOLUME": False,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },  
}

EDGE_NODE_DATA_PATH = "/edge_node/_local_cache/_data"
EDGE_NODE_DATA_MOUNT_POINT = "/edge_node_data"

class AdminContainerAppRunnerPlugin(
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
    super(AdminContainerAppRunnerPlugin, self).on_init()
    if not self.volumes:
      self.volumes = {}

    if self.cfg_mount_edge_node_data_volume == True:
      self.volumes[EDGE_NODE_DATA_PATH] = EDGE_NODE_DATA_MOUNT_POINT
    return


  def _configure_volumes(self):
    """
    Processes the volumes specified in the configuration.
    """
    if hasattr(self, 'cfg_volumes') and self.cfg_volumes and len(self.cfg_volumes) > 0:
      for host_path, container_path in self.cfg_volumes.items():
        original_path = str(host_path)
        self.volumes[original_path] = container_path

      # endfor each host path
    # endif volumes
    return

  def on_close(self):
    """
    Lifecycle hook called when plugin is stopping.
    Ensures container is shut down and logs are saved.
    Ensures the log process is killed.
    Stops tunnel if started.
    """
    super(AdminContainerAppRunnerPlugin, self).on_close()

  def process(self):
    super(AdminContainerAppRunnerPlugin, self).process()
    return