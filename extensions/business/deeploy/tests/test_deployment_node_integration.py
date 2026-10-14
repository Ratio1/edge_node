"""Exercise the real Edge coordinator against three Core lifecycle journals.

Workloads and transport are simulated; admission, stop fencing, observation,
publication, persistence and coordinator recovery execute production methods.
"""
import copy
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from naeural_core.business.deployment_lifecycle import DeploymentLifecycle
from extensions.business.deeploy.tests.test_deployment_operations import Coordinator, NODE_OPERATIONS_HKEY


class DeploymentNodeIntegrationTests(unittest.TestCase):
  def test_two_ready_one_init_failure_stops_every_node_and_fences_late_start(self):
    with tempfile.TemporaryDirectory() as directory:
      coordinator = Coordinator()
      operation = coordinator.operation()
      nodes = {node: DeploymentLifecycle(os.path.join(directory, node + '.json'), node)
               for node in ('A', 'B', 'C')}
      plugins = {}
      start_configs = {}

      def deliver(config, node_address):
        lifecycle = nodes[node_address]
        self.assertTrue(lifecycle.admit(config, 'oracle', True))
        if config['DEEPLOY_OPERATION']['action'] == 'start':
          start_configs[node_address] = copy.deepcopy(config)
          plugin = SimpleNamespace(is_plugin_ready=lambda: True,
                                   thread=SimpleNamespace(is_alive=lambda: True),
                                   _deployment_cleanup_complete=False)
          plugins[node_address] = plugin
          lifecycle.attach(config, 'RUNNER', 'worker', plugin)
          if node_address == 'C':
            lifecycle.fail(config, 'RUNNER', 'worker', 'PLUGIN_INIT_FAILED')
        else:
          plugin = plugins[node_address]
          plugin.thread.is_alive = lambda: False
          plugin._deployment_cleanup_complete = True

      coordinator.cmdapi_start_pipeline = deliver
      coordinator._save_operation(operation)
      with patch('naeural_core.business.deployment_lifecycle.time.time', side_effect=lambda: coordinator.now):
        for _ in range(8):
          coordinator._advance_deployment_operation(operation)
          for lifecycle in nodes.values():
            def setter(key, record, **kwargs):
              coordinator.storage[NODE_OPERATIONS_HKEY, key] = copy.deepcopy(record)
              return True
            lifecycle.publish(setter, lambda record, **kwargs: record.update(
              EE_SIGN='valid', EE_SENDER=record['node_addr']))
          coordinator.now += 2
      self.assertEqual((operation['phase'], operation['outcome'], operation['recovery']),
                       ('completed', 'failed', 'completed'))
      coordinator._commit_operation_revision.assert_not_called()
      for node, lifecycle in nodes.items():
        self.assertTrue(all(record['status'] == 'stopped' for record in lifecycle.records.values()))
        # Reload the fsynced journal: a delayed original start stays fenced after restart.
        restarted = DeploymentLifecycle(os.path.join(directory, node + '.json'), node)
        self.assertFalse(restarted.admit(start_configs[node], 'oracle', True))


if __name__ == '__main__':
  unittest.main()
