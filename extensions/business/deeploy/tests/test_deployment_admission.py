"""Exercise real durable admission separately from request-planning fixtures."""
import copy
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.deployment_operations import (
  _DeploymentOperationsMixin, OPERATIONS_HKEY, SECRET_REVISIONS_HKEY,
)
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin
from extensions.business.deeploy.tests.support import LifecycleCustodyDouble


def config(node, revision=1, secret_revision="previous:deploy"):
  return {
    "NAME": "app", "TYPE": "Void", "OWNER": "owner",
    "DEEPLOY_SPECS": {"job_id": 7, "revision": revision,
                       "secret_revision": secret_revision,
                       "current_target_nodes": ["A", "B"]},
    "PLUGINS": [{"SIGNATURE": "APP", "INSTANCES": [{
      "INSTANCE_ID": "instance-" + node, "NODE_LABEL": node,
      "CHAINSTORE_RESPONSE_KEY": "retired-response-key",
      "ENV": {"SECRET": "__R1_DAUTH_SECRET__"},
    }]}],
  }


class Admission(_DeploymentOperationsMixin, _DeeployMixin):
  def __init__(self):
    self.bc = SimpleNamespace(
      address="oracle",
      get_dauth_oracles=lambda: (["oracle", "replica"], []),
      verify=lambda record, **kwargs: SimpleNamespace(valid=record.get("EE_SIGN") == "valid"),
      sign=lambda record, **kwargs: record.update(EE_SIGN="valid", EE_SENDER="oracle"),
    )
    self.evm_network = "test"
    self.cfg_deployment_readiness_timeout = 60
    self._deployment_operations_event = threading.Event()
    self._deployment_plans = {}
    self._deployment_plan_cache_lock = threading.Lock()
    self._deployment_preparations = {}
    self.storage = {}
    self.deepcopy = copy.deepcopy
    self.previous_configs = None
    self.custody = LifecycleCustodyDouble(self)
    self.bc.reconcile_dauth_job_secrets = self.custody
    self.writes = []
    self.plans = {}
    self.fail_namespace = None
    self.fail_blob = False
    self.r1fs = SimpleNamespace(add_json=self.add_plan, get_json=lambda cid, **kwargs: copy.deepcopy(self.plans[cid]))
    self._get_response = lambda value: value
    self.commands = []

  def time(self):
    return 100

  def _operation_peers(self):
    return ["oracle", "replica"]

  def chainstore_hset(self, namespace, key, value, **kwargs):
    self.writes.append((namespace, key))
    self.storage[namespace, key] = copy.deepcopy(value)
    return namespace != self.fail_namespace

  def chainstore_hget(self, namespace, key):
    if namespace in (SECRET_REVISIONS_HKEY, 'DAUTH_JOB_SECRETS'):
      raise AssertionError('Coordinator must use the dAuth RPC for protected storage.')
    return copy.deepcopy(self.storage.get((namespace, key)))

  def chainstore_hgetall(self, namespace):
    return {key: copy.deepcopy(value) for (ns, key), value in self.storage.items() if ns == namespace}

  def add_plan(self, plan, **kwargs):
    if self.fail_blob:
      return None
    self.plans["plan-cid"] = copy.deepcopy(plan)
    return "plan-cid"

  def cmdapi_start_pipeline(self, **kwargs):
    self.commands.append(kwargs)

  def _get_pipeline_from_cstore(self, job_id):
    pointer = self.storage.get(('DEEPLOY_DEPLOYED_JOBS', str(job_id)))
    return pointer.get('pipeline_cid') if isinstance(pointer, dict) else pointer

  def _previous_deployment_configs(self, pipeline):
    # Scenario fixtures supply the public plan separately from flat custody data.
    if pipeline.get('DEEPLOY_SPECS', {}).get('secret_revision'):
      if self.previous_configs is None:
        raise ValueError('The exact previous node configurations are unavailable.')
      return copy.deepcopy(self.previous_configs)
    return super()._previous_deployment_configs(pipeline)

  def seed_previous(self, configs, bundle):
    self.previous_configs = configs
    reference = next(iter(configs.values()))['DEEPLOY_SPECS']['secret_revision']
    self.storage[SECRET_REVISIONS_HKEY, '7|' + reference] = copy.deepcopy(bundle)
    self.custody.previous_bundle = copy.deepcopy(bundle)

  def admit(self, request=None, prior=None, prior_bundle=None):
    request = request or {"request_id": "stable-request", "job_id": 7}
    if prior_bundle is not None:
      self.custody.previous_bundle = copy.deepcopy(prior_bundle)
    return self._admit_prepared_deployment(
      request=request, auth_result={DEEPLOY_KEYS.ESCROW_OWNER: "owner"},
      app_id="app", configs={node: config(node) for node in ["A", "B"]},
      prior_pipeline=prior, is_create=prior is None,
    )


class DeploymentAdmissionTests(unittest.TestCase):
  def test_live_admission_does_not_block_other_jobs_or_race_recovery(self):
    plugin = Admission()
    staging = threading.Event()
    release = threading.Event()
    store = plugin.custody
    def pause_staging(payload):
      staging.set()
      if not release.wait(5):
        raise RuntimeError("Test did not release admission")
      return store(payload)
    plugin.bc.reconcile_dauth_job_secrets = pause_staging
    plugin._advance_deployment_operation = Mock()
    with ThreadPoolExecutor(max_workers=1) as executor:
      admission = executor.submit(plugin.admit)
      try:
        self.assertTrue(staging.wait(5))
        live = next(iter(plugin._operation_records().values()))
        other = copy.deepcopy(live)
        other.update(operation_id=live["operation_id"] + "-other", job_id=8,
                     phase="accepted", sequence=0)
        plugin._save_operation(other)
        plugin.time = lambda: live["preparation_deadline"] + 1
        plugin._reconcile_coordinator_operations()
        advanced = plugin._advance_deployment_operation.call_args_list
        self.assertEqual([call.args[0]["job_id"] for call in advanced], [8])

        # Admission finishes AFTER the worker captures `preparing`. It must
        # still skip that stale snapshot, then reload `accepted` next pass.
        read_records = plugin._operation_records
        def finish_while_reading():
          snapshots = read_records()
          release.set()
          admission.result(timeout=5)
          return snapshots
        plugin._operation_records = finish_while_reading
        plugin._advance_deployment_operation.reset_mock()
        plugin._reconcile_coordinator_operations()
        self.assertEqual([call.args[0]["job_id"] for call in
                          plugin._advance_deployment_operation.call_args_list], [8])
        plugin._operation_records = read_records
        plugin._advance_deployment_operation.reset_mock()
        plugin._reconcile_coordinator_operations()
        phases = {call.args[0]["job_id"]: call.args[0]["phase"] for call in
                  plugin._advance_deployment_operation.call_args_list}
        self.assertEqual(phases, {7: "accepted", 8: "accepted"})
        self.assertEqual(plugin._deployment_preparations, {})
      finally:
        release.set()

  def test_failed_admission_hands_preparing_operation_to_recovery(self):
    plugin = Admission()
    plugin.bc.reconcile_dauth_job_secrets = Mock(side_effect=RuntimeError("storage unavailable"))
    with self.assertRaisesRegex(RuntimeError, "storage unavailable"):
      plugin.admit()
    plugin._advance_deployment_operation = Mock()
    plugin._reconcile_coordinator_operations()
    plugin._advance_deployment_operation.assert_called_once()
    self.assertEqual(plugin._advance_deployment_operation.call_args.args[0]["phase"], "preparing")
    self.assertEqual(plugin._deployment_preparations, {})

  def test_failed_initial_publication_does_not_leak_local_ownership(self):
    plugin = Admission()
    plugin._save_operation = Mock(side_effect=RuntimeError("storage unavailable"))
    with self.assertRaisesRegex(RuntimeError, "storage unavailable"):
      plugin.admit()
    plugin._advance_deployment_operation = Mock()
    plugin._reconcile_coordinator_operations()
    plugin._advance_deployment_operation.assert_not_called()
    self.assertEqual(plugin._deployment_preparations, {})

  def test_acceptance_persists_plan_and_secret_revision_without_dispatch(self):
    plugin = Admission()
    result = plugin.admit()
    self.assertEqual((result["status_code"], result["status"]), (202, "accepted"))
    operation = plugin._operation_records()[result["operation_id"]]
    self.assertEqual(operation["coordinator"], "oracle")
    self.assertIsNone(operation["outcome"])
    self.assertTrue(plugin._deployment_operations_event.is_set())
    self.assertEqual(plugin.commands, [])
    self.assertEqual(plugin.writes[0][0], OPERATIONS_HKEY)
    self.assertEqual(plugin.storage[plugin.writes[0]]["phase"], "preparing")
    self.assertEqual(plugin.writes[1][0], SECRET_REVISIONS_HKEY)
    self.assertTrue(all(namespace == OPERATIONS_HKEY for namespace, _ in plugin.writes[2:]))
    self.assertNotIn("protected-value", str(result))
    self.assertNotIn("protected-value", str(operation))
    self.assertNotIn("protected-value", str(plugin.plans))
    for node, pipeline in plugin.plans["plan-cid"]["configs"].items():
      self.assertEqual(pipeline["DEEPLOY_SPECS"]["revision"], 1)
      self.assertNotIn("CHAINSTORE_RESPONSE_KEY", pipeline["PLUGINS"][0]["INSTANCES"][0])
      revision = pipeline["DEEPLOY_SPECS"]["secret_revision"]
      stored = plugin.storage[SECRET_REVISIONS_HKEY, "7|" + revision]
      self.assertEqual(stored["job_secrets"]["secret"], "protected-value")
      self.assertEqual(stored["pipelines"][node], pipeline)

  def test_retry_reuses_operation_and_rejects_changed_intent(self):
    plugin = Admission()
    request = {"request_id": "stable-request", "job_id": 7, "nonce": "old"}
    result = plugin.admit(request)
    retry = plugin._find_request_operation({**request, "nonce": "new"}, "owner", "create")
    self.assertEqual(retry["operation_id"], result["operation_id"])
    with self.assertRaisesRegex(ValueError, "different deployment input"):
      plugin._find_request_operation({**request, "plugins": []}, "owner", "create")
    with self.assertRaisesRegex(ValueError, "already active"):
      plugin._find_request_operation({**request, "request_id": "new-request"}, "owner", "create")

  def test_admission_failure_never_dispatches_or_wakes_execution(self):
    for failure in (SECRET_REVISIONS_HKEY, OPERATIONS_HKEY, "r1fs"):
      with self.subTest(failure=failure):
        plugin = Admission()
        plugin.fail_namespace = failure
        plugin.fail_blob = failure == "r1fs"
        with self.assertRaises(RuntimeError):
          plugin.admit()
        self.assertFalse(plugin._deployment_operations_event.is_set())
        self.assertEqual(plugin.commands, [])

  def test_update_retains_exact_previous_node_configs_and_secret_binding(self):
    plugin = Admission()
    previous = {node: config(node, revision=4) for node in ["A", "B"]}
    plugin.seed_previous(previous, {
      "pipelines": copy.deepcopy(previous), "job_secrets": {"secret": "old-secret"},
    })
    result = plugin.admit(
      {"request_id": "update", "job_id": 7, "expected_revision": 4},
      prior=previous["A"], prior_bundle={"job_secrets": {"secret": "old-secret"}},
    )
    self.assertEqual(result["revision"], 5)
    operation = plugin._operation_records()[result["operation_id"]]
    self.assertEqual(operation["previous_operation_id"], "previous")
    self.assertEqual(operation["previous_secret_revision"], "previous:deploy")
    restored = plugin.plans["plan-cid"]["previous_configs"]
    for node, pipeline in restored.items():
      self.assertEqual(pipeline["PLUGINS"], previous[node]["PLUGINS"])
      self.assertEqual(pipeline["DEEPLOY_SPECS"]["revision"], 4)
      restore_revision = pipeline["DEEPLOY_SPECS"]["secret_revision"]
      self.assertTrue(restore_revision.endswith(":restore"))
      self.assertEqual(plugin.storage[SECRET_REVISIONS_HKEY, "7|" + restore_revision]["job_secrets"]["secret"], "old-secret")
    self.assertEqual(plugin.storage[SECRET_REVISIONS_HKEY, "7|previous:deploy"]["pipelines"], previous)
    self.assertEqual(plugin.commands, [])

  def test_update_preconditions_fail_before_secret_or_plan_writes(self):
    for revision in (None, True, 0, 2):
      with self.subTest(revision=revision):
        plugin = Admission()
        with self.assertRaisesRegex(ValueError, "revision changed"):
          plugin.admit({"request_id": "update", "job_id": 7, "expected_revision": revision},
                       prior=config("A"), prior_bundle={})
        self.assertEqual(plugin.writes, [])
        self.assertEqual(plugin.plans, {})
    plugin = Admission()
    with self.assertRaisesRegex(ValueError, "exact previous node configurations"):
      plugin.admit({"request_id": "update", "job_id": 7, "expected_revision": 1},
                   prior=config("A"), prior_bundle={})
    self.assertEqual(plugin.writes, [])

  def test_polling_on_another_oracle_is_authorized_and_redacted(self):
    owner = Admission()
    result = owner.admit()
    reader = Admission()
    reader.bc.address = "replica"
    reader.storage = copy.deepcopy(owner.storage)
    reader.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("wallet", request)
    reader.deeploy_get_auth_result = lambda inputs: {DEEPLOY_KEYS.ESCROW_OWNER: "owner"}
    status = reader._deployment_status({"operation_id": result["operation_id"]})
    self.assertEqual(status["operation_id"], result["operation_id"])
    self.assertEqual(status["coordinator"], "oracle")
    self.assertEqual(status["ready_nodes"], 0)
    self.assertEqual(status["target_nodes"], 2)
    self.assertNotIn("protected-value", str(status))
    self.assertNotIn("plan_cid", status)
    reader.deeploy_get_auth_result = lambda inputs: {DEEPLOY_KEYS.ESCROW_OWNER: "stranger"}
    denied = reader._deployment_status({"operation_id": result["operation_id"]})
    self.assertNotIn("operation_id", denied)
    self.assertEqual(reader.commands, [])

  def test_update_rejects_incomplete_or_mismatched_previous_placement_before_writes(self):
    mutations = {
      "missing-node": lambda configs: configs.pop("B"),
      "extra-node": lambda configs: configs.update(C=config("C", revision=4)),
      "wrong-app": lambda configs: configs["B"].update(NAME="different-app"),
      "wrong-job": lambda configs: configs["B"]["DEEPLOY_SPECS"].update(job_id=8),
      "wrong-revision": lambda configs: configs["B"]["DEEPLOY_SPECS"].update(revision=3),
      "no-required-instance": lambda configs: configs["B"].update(PLUGINS=[]),
    }
    for label, mutate in mutations.items():
      with self.subTest(label=label):
        plugin = Admission()
        previous = {node: config(node, revision=4) for node in ("A", "B")}
        canonical = copy.deepcopy(previous["A"])
        mutate(previous)
        plugin.seed_previous(previous, {
          "pipelines": previous, "job_secrets": {"secret": "original-secret"},
        })
        original_storage = copy.deepcopy(plugin.storage)
        with self.assertRaisesRegex(ValueError, "exact complete placement"):
          plugin.admit(
            {"request_id": "update", "job_id": 7, "expected_revision": 4},
            prior=canonical, prior_bundle={"job_secrets": {"secret": "original-secret"}},
          )
        self.assertEqual(plugin.writes, [])
        self.assertEqual(plugin.plans, {})
        self.assertEqual(plugin.storage, original_storage)
        self.assertEqual(plugin.commands, [])

  def test_latest_job_poll_prefers_generation_over_clock_and_snapshot_sequence(self):
    plugin = Admission()
    first = plugin.admit({"request_id": "first", "job_id": 7})
    old = plugin._operation_records()[first["operation_id"]]
    old.update(created_at=1000, sequence=100)
    plugin._save_operation(old)
    plugin.storage["DEEPLOY_DEPLOYED_JOBS", "7"] = {"revision": 1, "deleted": True}
    plugin.time = lambda: 50
    second = plugin.admit({"request_id": "second", "job_id": 7})
    plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("wallet", request)
    plugin.deeploy_get_auth_result = lambda inputs: {DEEPLOY_KEYS.ESCROW_OWNER: "owner"}
    latest = plugin._deployment_status({"job_id": 7})
    self.assertEqual(latest["operation_id"], second["operation_id"])
    self.assertEqual(latest["target_revision"], 2)
    # Explicit historical selectors still resolve their requested operation.
    historical = plugin._deployment_status({"operation_id": first["operation_id"]})
    self.assertEqual(historical["operation_id"], first["operation_id"])
