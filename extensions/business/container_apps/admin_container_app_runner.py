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
    """
    Initialize the admin container app runner plugin.

    Calls parent initialization and ensures volumes dict is initialized.

    Returns
    -------
    None
    """
    super(AdminContainerAppRunnerPlugin, self).on_init()
    if not self.volumes:
      self.volumes = {}

    return


  def _configure_volumes(self):
    """
    Process volume configuration for admin container.

    Configures volume mappings for the container, including optional edge node
    data volume and user-specified volumes. Unlike the base class, this method
    allows direct host path mapping without sandboxing.

    Returns
    -------
    None

    Notes
    -----
    - If MOUNT_EDGE_NODE_DATA_VOLUME is True, mounts /edge_node/_local_cache/_data
    - All volumes are mounted with 'rw' (read-write) permissions
    - Host paths are used directly without sanitization (admin-only feature)
    """
    default_volume_rights = "rw"

    if self.cfg_mount_edge_node_data_volume == True:
      self.volumes[EDGE_NODE_DATA_PATH] = {"bind": EDGE_NODE_DATA_MOUNT_POINT, "mode": default_volume_rights}
    if hasattr(self, 'cfg_volumes') and self.cfg_volumes and len(self.cfg_volumes) > 0:
      for host_path, container_path in self.cfg_volumes.items():
        original_path = str(host_path)
        self.volumes[original_path] = {"bind": container_path, "mode": default_volume_rights}
      # endfor each host path
    # endif volumes
    return

  def on_close(self):
    """
    Lifecycle hook called when plugin is stopping.

    Ensures proper cleanup of container resources including:
    - Container shutdown
    - Log saving to disk
    - Log process termination
    - Tunnel termination if active

    Returns
    -------
    None
    """
    super(AdminContainerAppRunnerPlugin, self).on_close()

  def process(self):
    """
    Main process loop for the admin container app runner.

    Delegates to parent class process method for container management,
    health checks, and tunnel maintenance.

    Returns
    -------
    None
    """
    super(AdminContainerAppRunnerPlugin, self).process()
    return