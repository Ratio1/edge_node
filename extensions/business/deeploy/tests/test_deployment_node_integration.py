"""Exercise the real Edge coordinator against three Core lifecycle journals.

Workloads and transport are simulated; admission, stop fencing, observation,
publication, persistence and coordinator recovery execute production methods.
"""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from naeural_core.business.deployment_lifecycle import DeploymentLifecycle
from ratio1.bc import DefaultBlockEngine
from ratio1.const.base import BCct
from extensions.business.deeploy.tests.test_deployment_operations import Coordinator, NODE_OPERATIONS_HKEY


class DeploymentNodeIntegrationTests(unittest.TestCase):
  def test_legacy_create_recovers_after_restart_with_signed_worker_stop(self):
    with tempfile.TemporaryDirectory() as directory:
      # Use the real SDK signature on the Core report and a disposable test key.
      log = SimpleNamespace(P=lambda *args, **kwargs: None, get_data_folder=lambda: directory,
                            get_target_folder=lambda *args: directory, get_base_folder=lambda: directory)
      with patch.dict(os.environ):  # The SDK exports its PEM path during initialization.
        signer = DefaultBlockEngine(directory, log, config={BCct.K_PEM_FILE: "worker.pem"}, eth_enabled=False)
      worker = signer.address
      planned = worker.removeprefix(BCct.ADDR_PREFIX)  # Plans made by the previous auto selector.
      coordinator = Coordinator()
      operation = coordinator.operation()
      operation["nodes"] = [planned]
      operation["instances"] = {planned: operation["instances"]["A"]}
      coordinator.plan["configs"] = {planned: coordinator.plan["configs"]["A"]}
      coordinator._save_operation(operation)
      journal = DeploymentLifecycle(os.path.join(directory, "worker.json"), worker)

      # Drive the real journal through start, readiness and coordinator-issued cleanup.
      coordinator._advance_deployment_operation(operation)
      _, start = coordinator.commands[-1]
      self.assertTrue(journal.admit(start, "oracle", True))
      app = SimpleNamespace(is_plugin_ready=lambda: True, thread=SimpleNamespace(is_alive=lambda: True),
                            _deployment_cleanup_complete=False)
      journal.attach(start, "RUNNER", "worker", app)

      def replicate(key, record, **kwargs):
        return coordinator.chainstore_hset(NODE_OPERATIONS_HKEY, key, record)

      with patch("naeural_core.business.deployment_lifecycle.time.time", side_effect=coordinator.time):
        journal.publish(replicate, signer.sign)
        coordinator.now = operation["deadline"] + 1
        coordinator._fail_deployment_rollout(operation, "READINESS_DEADLINE_EXCEEDED", "Readiness timeout.")
        coordinator._advance_deployment_operation(operation)
        _, stop = coordinator.commands[-1]
        self.assertTrue(journal.admit(stop, "oracle", True))
        app.thread.is_alive = lambda: False
        app._deployment_cleanup_complete = True
        journal.publish(replicate, signer.sign)
      operation["recovery"] = "blocked"
      coordinator._save_operation(operation)
      # Recreate the oracle's process state from the persisted records and original plan.
      checkpoint = Path(directory) / "oracle.json"
      checkpoint.write_text(json.dumps({"entries": list(coordinator.storage.items()), "plan": coordinator.plan}))
      saved = json.loads(checkpoint.read_text())
      restarted = Coordinator()
      restarted.now = coordinator.now + 60
      restarted.plan = saved["plan"]
      restarted.storage = {tuple(key): value for key, value in saved["entries"]}
      verify_fixture = restarted.bc.verify
      restarted.bc.verify = lambda record, **kw: (
        verify_fixture(record, **kw) if record["EE_SENDER"] == "oracle" else signer.verify(record, **kw)
      )

      # Later reports from a different revision or with an invalid signature cannot replace the stop.
      receipts = list(restarted.chainstore_hgetall(NODE_OPERATIONS_HKEY).values())
      self.assertEqual({report["status"] for report in receipts}, {"ready", "stopped"})
      stopped = next(report for report in receipts if report["status"] == "stopped")
      wrong_revision = dict(stopped, revision=2, status="ready", sequence=stopped["sequence"] + 1)
      signer.sign(wrong_revision)
      self.assertTrue(signer.verify(wrong_revision).valid)
      restarted.chainstore_hset(NODE_OPERATIONS_HKEY, "wrong-revision", wrong_revision)
      restarted.chainstore_hset(NODE_OPERATIONS_HKEY, "invalid-signature",
                                dict(stopped, status="ready", sequence=stopped["sequence"] + 2))

      # A captured ready report cannot override the newest verified stop.
      restarted._reconcile_coordinator_operations()
      finished = restarted._operation_records()[operation["operation_id"]]
      self.assertEqual((finished["phase"], finished["outcome"], finished["recovery"]),
                       ("completed", "failed", "completed"))
      self.assertEqual(restarted.commands, [], "Already confirmed cleanup needs no additional dispatch")
      self.assertEqual([call["action"] for call in restarted.custody.calls], ["revoke"])
      restarted._commit_operation_revision.assert_not_called()

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
