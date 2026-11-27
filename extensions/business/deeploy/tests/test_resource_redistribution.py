"""Regression checks for saved-revision resource and identity accounting."""
import copy
import unittest

from extensions.business.deeploy.container_allocations import redistribution_requirements
from extensions.business.deeploy.tests.support import make_deeploy_plugin


def config(rows, native=False):
  return {"DEEPLOY_SPECS": {"job_app_type": "native" if native else "stack",
                           "node_res_req": {"cpu": 3, "memory": "10g"}},
          "PLUGINS": [{"SIGNATURE": "CONTAINER_APP_RUNNER", "INSTANCES": [
            {"INSTANCE_ID": iid, "CONTAINER_RESOURCES": {"cpu": cpu, "memory": ram, "storage": storage}}
            for iid, cpu, ram, storage in rows]}]}


class RedistributionTests(unittest.TestCase):
  def test_splits_below_tier_without_spending_headroom(self):
    old = config([("kept", ".8", "1.5g", "3g")])
    new = config([("kept", ".3", "512m", "3g"), ("extra", ".5", "1g", "0g")])
    for native in (False, True):
      for item in (old, new):
        item["DEEPLOY_SPECS"]["job_app_type"] = "native" if native else "stack"
      self.assertEqual(set(redistribution_requirements({"A": old}, {"A": new}, {})), {"A"})
      for field, value in (("cpu", ".5001"), ("memory", "1.01g"), ("storage", "0.01m")):
        different = copy.deepcopy(new)
        different["PLUGINS"][0]["INSTANCES"][1]["CONTAINER_RESOURCES"][field] = value
        with self.subTest(field=field), self.assertRaisesRegex(ValueError, "saved"):
          redistribution_requirements({"A": old}, {"A": different}, {})

  def test_reorder_and_legacy_noop_preserve_resources(self):
    old = config([("one", 4, "512m", "0g"), ("two", 3, "10g", "2g")], native=True)
    reordered = copy.deepcopy(old)
    reordered["PLUGINS"][0]["INSTANCES"].reverse()
    self.assertFalse(redistribution_requirements({"A": old}, {"A": reordered}, {"cpu":3,"memory":"10g"}))

  def test_resource_edit_requires_original_placement_and_tier(self):
    old = config([("one", 1, "1g", "2g")])
    new = config([("one", ".5", "512m", "1g"), ("two", ".5", "512m", "1g")])
    with self.assertRaisesRegex(ValueError, "placement"):
      redistribution_requirements({"A": old}, {"B": new}, {})
    new["DEEPLOY_SPECS"]["node_res_req"]["cpu"] = 4
    with self.assertRaisesRegex(ValueError, "tier"):
      redistribution_requirements({"A": old}, {"A": new}, {})

  def test_masked_credentials_follow_the_surviving_identity(self):
    plugin = make_deeploy_plugin()
    old = config([("removed", 1, "1g", "0g"), ("retained", 1, "1g", "0g")])
    values = {"PLUGINS": [{"INSTANCES": [{"ENV": {"VALUE": "first"}}, {"ENV": {"VALUE": "second"}}]}]}
    from extensions.business.deeploy.deeploy_mixin import DEEPLOY_DAUTH_SECRET_PLACEHOLDER as masked
    for instance in old["PLUGINS"][0]["INSTANCES"]:
      instance["ENV"] = {"VALUE": masked}
    new = copy.deepcopy(old)
    new["PLUGINS"][0]["INSTANCES"].pop(0)
    complete = plugin._build_complete_dauth_job_secret_bundle(7, new, {}, {"job_secrets": values}, old, match_prior_instance=True)
    self.assertEqual(complete["job_secrets"]["PLUGINS"][0]["INSTANCES"][0]["ENV"]["VALUE"], "second")
    new["PLUGINS"][0]["INSTANCES"][0]["INSTANCE_ID"] = "new"
    with self.assertRaisesRegex(ValueError, "Unresolved"):
      plugin._build_complete_dauth_job_secret_bundle(7, new, {}, {"job_secrets": values}, old, match_prior_instance=True)

  def test_missing_saved_native_caps_use_docker_defaults(self):
    old = config([("one", 1, "512m", "0g")], native=True)
    old["PLUGINS"][0]["INSTANCES"][0].pop("CONTAINER_RESOURCES")
    new = config([("one", ".5", "256m", "0g"), ("two", ".5", "256m", "0g")], native=True)
    self.assertEqual(redistribution_requirements({"A": old}, {"A": new}, {})["A"], ["1.0", "536870912", "0"])

  def test_native_running_omissions_are_lossless_only_for_the_same_old_row(self):
    from extensions.business.deeploy.container_allocations import prepare_native_omissions, restore_native_omissions
    from extensions.business.deeploy.tests.support import make_plugin_entry
    row = make_plugin_entry("CONTAINER_APP_RUNNER", instance_id="one", CONTAINER_RESOURCES={"ports": {"web":80}})
    omissions = prepare_native_omissions([row])
    self.assertEqual(row["CONTAINER_RESOURCES"]["memory"], "512m")
    old = config([("one", 1, "512m", "0g")], native=True)
    old["PLUGINS"][0]["INSTANCES"][0]["CONTAINER_RESOURCES"] = {"ports": {"web": 80}}
    new = copy.deepcopy(old)
    new["PLUGINS"][0]["INSTANCES"][0]["CONTAINER_RESOURCES"] = row["CONTAINER_RESOURCES"]
    restore_native_omissions({"A": new}, omissions)
    self.assertEqual(old, new)
    self.assertFalse(redistribution_requirements({"A": old}, {"A": new}, {}))
    old["PLUGINS"][0]["INSTANCES"][0]["CONTAINER_RESOURCES"]["cpu"] = 2
    with self.assertRaisesRegex(ValueError, "remain absent"):
      redistribution_requirements({"A": old}, {"A": new}, {})

  def test_dynamic_secret_cannot_cross_a_changed_expression_after_identity_remap(self):
    from extensions.business.deeploy.deeploy_mixin import DEEPLOY_DAUTH_SECRET_PLACEHOLDER as masked
    plugin = make_deeploy_plugin()
    old = config([("removed", 1, "1g", "0g"), ("kept", 1, "1g", "0g")])
    field = {"K": [{"type":"static", "value":masked}, {"type":"shmem", "path":["a","x"]}]}
    old["PLUGINS"][0]["INSTANCES"][1]["DYNAMIC_ENV"] = field
    new = copy.deepcopy(old)
    new["PLUGINS"][0]["INSTANCES"].pop(0)
    new["PLUGINS"][0]["INSTANCES"][0]["DYNAMIC_ENV"]["K"][1]["path"] = ["b","x"]
    values = {"PLUGINS":[{"INSTANCES":[{}, {"DYNAMIC_ENV":{"K":[{"value":"previous"}]}}]}]}
    with self.assertRaisesRegex(ValueError, "Unresolved"):
      plugin._build_complete_dauth_job_secret_bundle(7, new, {}, {"job_secrets": values}, old, match_prior_instance=True)

  def test_missing_legacy_worker_tier_is_reconstructed_from_paid_allocation(self):
    old = config([("one", 1, "1g", "0g")], native=True)
    old["DEEPLOY_SPECS"].pop("node_res_req")
    new = config([("one", ".5", "512m", "0g"), ("two", ".5", "512m", "0g")], native=True)
    self.assertTrue(redistribution_requirements({"A": old}, {"A": new}, {"cpu": 3, "memory": "14g"}))
    noop = copy.deepcopy(old)
    noop["DEEPLOY_SPECS"]["node_res_req"] = {"cpu": 30, "memory": "10g"}
    with self.assertRaisesRegex(ValueError, "tier"):
      redistribution_requirements({"A": old}, {"A": noop}, {"cpu": 3, "memory": "14g"})
    new["DEEPLOY_SPECS"]["node_res_req"]["cpu"] = 30
    with self.assertRaisesRegex(ValueError, "tier"):
      redistribution_requirements({"A": old}, {"A": new}, {"cpu": 3, "memory": "14g"})
