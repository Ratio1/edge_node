"""Observed failed attempts still consume deployment generations across clocks."""
import copy
import unittest

from extensions.business.deeploy.deployment_operations import OPERATIONS_HKEY, SECRET_REVISIONS_HKEY
from extensions.business.deeploy.tests.test_deployment_admission import Admission, config
from extensions.business.deeploy.tests.test_deployment_mutations import Mutations


class DeploymentRevisionOrderTests(unittest.TestCase):
  def latest(self, plugin):
    plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("wallet", request)
    plugin.deeploy_get_auth_result = lambda inputs: {"escrow_owner": "owner"}
    return plugin._deployment_status({"job_id": 7})

  def test_failed_create_retry_is_newer_despite_earlier_clock(self):
    plugin = Admission()
    plugin.time = lambda: 1000
    first = plugin.admit()
    operation = plugin._operation_records()[first["operation_id"]]
    operation.update(outcome="failed", recovery="completed")
    plugin._save_operation(operation, "completed")
    request = {"request_id": "new-intent", "job_id": 7}
    self.assertIsNone(plugin._find_request_operation(request, "owner", "create"))
    plugin.time = lambda: 50
    second = plugin.admit(request)
    self.assertEqual((first["revision"], second["revision"]), (1, 2))
    self.assertEqual(self.latest(plugin)["operation_id"], second["operation_id"])
    self.assertEqual(self.latest(plugin)["phase"], "accepted")

  def test_failed_preparation_retry_advances_create_and_update_generation(self):
    for kind in ("create", "update"):
      with self.subTest(kind=kind):
        plugin = Admission()
        plugin.time = lambda: 1000
        prior = None
        prior_bundle = None
        request = {"request_id": "failed-preparation", "job_id": 7}
        if kind == "update":
          configs = {node: config(node, revision=4) for node in ("A", "B")}
          prior = configs["A"]
          prior_bundle = {"job_secrets": {"secret": "original"}}
          plugin.storage[SECRET_REVISIONS_HKEY, "7|previous:deploy"] = {
            **prior_bundle, "pipelines": configs,
          }
          request["expected_revision"] = 4
        # The operation persists locally but replica confirmation fails before
        # any protected copy is written. Expiry takes the real cleanup path.
        plugin.fail_namespace = OPERATIONS_HKEY
        with self.assertRaises(RuntimeError):
          plugin.admit(request, prior=prior, prior_bundle=prior_bundle)
        plugin.fail_namespace = None
        plugin.time = lambda: 1121
        failed = next(iter(plugin._operation_records().values()))
        plugin.r1fs.get_json = lambda cid, **kwargs: copy.deepcopy(plugin.plans[cid])
        plugin._advance_deployment_operation(failed)
        self.assertEqual((failed["phase"], failed["outcome"]), ("completed", "failed"))
        self.assertEqual(plugin.commands, [])
        request = {**request, "request_id": "deliberate-retry"}
        self.assertIsNone(plugin._find_request_operation(request, "owner", kind))
        plugin.time = lambda: 50
        result = plugin.admit(request, prior=prior, prior_bundle=prior_bundle)
        self.assertEqual(result["revision"], failed["target_revision"] + 1)
        self.assertEqual(self.latest(plugin)["operation_id"], result["operation_id"])

  def test_delete_advances_past_observed_failed_attempt_and_canonical_generation(self):
    plugin = Mutations()
    # A completed preparation failure may be newer than the canonical pointer.
    observed = Admission()
    observed.time = lambda: 1000
    observed.storage["DEEPLOY_DEPLOYED_JOBS", "7"] = {"revision": 9}
    accepted = observed.admit()
    failed = observed._operation_records()[accepted["operation_id"]]
    failed.update(outcome="failed", recovery="completed")
    observed._save_operation(failed, "completed")
    plugin.storage.update({key: copy.deepcopy(value) for key, value in observed.storage.items()
                           if key[0] == OPERATIONS_HKEY})
    plugin.storage["DEEPLOY_DEPLOYED_JOBS", "7"] = {"revision": 9, "pipeline_cid": "canonical-cid"}
    plugin.now = 50
    result = plugin.delete()
    self.assertEqual(result["revision"], 11)
    self.assertEqual(self.latest(plugin)["operation_id"], result["operation_id"])

  def test_unverified_or_other_job_operations_do_not_advance_generation(self):
    plugin = Admission()
    accepted = plugin.admit()
    original = plugin._operation_records()[accepted["operation_id"]]
    foreign = dict(original, operation_id=original["operation_id"] + "-foreign", job_id=8, target_revision=100)
    unsigned = dict(original, operation_id=original["operation_id"] + "-unsigned", target_revision=200, EE_SIGN="invalid")
    plugin.storage[OPERATIONS_HKEY, "foreign"] = foreign
    plugin.storage[OPERATIONS_HKEY, "unsigned"] = unsigned
    self.assertEqual(plugin._next_deployment_revision(7), 2)


if __name__ == '__main__':
  unittest.main()
