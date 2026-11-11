"""Offline integration proofs for full-placement scale and confirmed deletion."""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from extensions.business.deeploy.deployment_mutations import _DeploymentMutationsMixin
from extensions.business.deeploy.deployment_operations import (
  NODE_OPERATIONS_HKEY, OPERATIONS_HKEY, SECRET_REVISIONS_HKEY, _DeploymentOperationsMixin,
)
from extensions.business.deeploy.deeploy_job_mixin import DEEPLOY_JOBS_CSTORE_HKEY, DAUTH_JOB_SECRETS_CSTORE_HKEY
from extensions.business.deeploy.tests.test_deployment_admission import Admission, config


class Mutations(_DeploymentMutationsMixin, Admission):
  # Node configs come from R1FS as in production: the plan named by the stored pointer.
  _previous_deployment_configs = _DeploymentOperationsMixin._previous_deployment_configs

  def __init__(self):
    super().__init__()
    self.now = 100
    self.bc.get_job_details = lambda job_id: {"escrowOwner": "owner"}
    self.current = {node: config(node, revision=4) for node in ("A", "B")}
    for node, pipeline in self.current.items():
      pipeline["PLUGINS"][0]["INSTANCES"][0].update(
        VOLUMES={"data": "/preserved-" + node}, ENV={"SECRET": "__R1_DAUTH_SECRET__", "NODE_VALUE": node},
      )
    # The stored job is one node's config; the plan holds every node's own config.
    self.pipeline = copy.deepcopy(self.current["A"])
    self.plans["current-plan"] = dict(configs=self.current, previous_configs={})
    self.reports = self.current
    self.netmon = SimpleNamespace(network_known_pipelines=lambda: {
      node: [copy.deepcopy(config)] for node, config in self.reports.items()})
    self.storage[SECRET_REVISIONS_HKEY, "7|previous:deploy"] = dict(
      job_id="7", revision="previous:deploy", pipelines=copy.deepcopy(self.current), job_secrets={"secret": "protected"},
    )
    self.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = dict(
      revision=4, pipeline_cid="canonical-cid", plan_cid="current-plan", deleted=False)
    self._delete_pipeline_cid_from_r1fs = Mock(return_value=True)
    self.r1fs.get_json = lambda cid, **kwargs: copy.deepcopy(self.plans[cid])
    self._deployment_operations_stop = __import__("threading").Event()
    self.captured_scale = None

  def time(self):
    return self.now

  def get_job_pipeline_from_cstore(self, *args, **kwargs):
    return copy.deepcopy(self.pipeline)

  def _get_pipeline_from_cstore(self, job_id):
    pointer = self.storage[DEEPLOY_JOBS_CSTORE_HKEY, str(job_id)]
    return pointer.get("pipeline_cid") if isinstance(pointer, dict) else pointer

  def _load_dauth_job_secret_bundle(self, job_id):
    raise AssertionError('A mutation coordinator cannot load protected job bundles.')

  def _get_pipeline_params_from_deeploy_specs(self, specs):
    return {}

  def prepare_create_update_pipelines(self, base, new_nodes, update_nodes, running_apps_for_job, generated_instance_identity_aliases):
    self.asserted_update_nodes = update_nodes
    base["deeploy_specs"].update(current_target_nodes=["A", "B"] + new_nodes)
    instance = base["plugins"][0]["INSTANCES"][0]
    instance["ENV"]["CRDB_CA_CERT"] = "new-ca"
    instance["PER_NODE_CONFIG"] = {"byNode": {node: {"ENV": {"CERT": "cert-" + node}} for node in ["A", "B"] + new_nodes}}
    return {node: copy.deepcopy(base) for node in new_nodes}, {}, {}

  def _build_scale_up_create_pipeline_configs(self, created, owner):
    result = {}
    for node, base in created.items():
      result[node] = copy.deepcopy(self.pipeline)
      result[node]["PLUGINS"] = copy.deepcopy(base["plugins"])
      result[node]["PLUGINS"][0]["INSTANCES"][0]["INSTANCE_ID"] = "new-" + node
    return result

  def _admit_prepared_deployment(self, **kwargs):
    self.captured_scale = copy.deepcopy(kwargs)
    return {"status_code": 202}

  def stop_report(self, operation, node, status="stopped"):
    report = dict(operation_id=operation["operation_id"], attempt="retire", revision=4,
                  coordinator="oracle", node_addr=node, app_id="app", status=status,
                  sequence=1, updated_at=self.now, instances=[], EE_SIGN="valid", EE_SENDER=node)
    self.storage[NODE_OPERATIONS_HKEY, node] = report

  def delete(self, **overrides):
    return self._admit_delete_operation(
      dict(request_id="delete-request", job_id=7, expected_revision=4, **overrides),
      {"escrow_owner": "owner"},
    )


class DeploymentMutationTests(unittest.TestCase):
  def test_delete_accepts_existing_pipeline_without_revision_metadata(self):
    plugin = Mutations()
    for pipeline in [plugin.pipeline, *plugin.current.values()]:
      pipeline["DEEPLOY_SPECS"].pop("revision")
      pipeline["DEEPLOY_SPECS"].pop("secret_revision")
    # Stored before plans existed: every node runs the stored copy.
    plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = "canonical-cid"
    plugin.reports = {node: copy.deepcopy(plugin.pipeline) for node in ("A", "B")}
    result = plugin._admit_delete_operation(
      dict(request_id="legacy-delete", job_id=7, expected_revision=0),
      {"escrow_owner": "owner"},
    )
    self.assertEqual(result["status_code"], 202)
    operation = plugin._operation_records()[result["operation_id"]]
    self.assertEqual(operation["previous_revision"], 0)
    self.assertEqual(operation["target_revision"], 1)
    self.assertIsNone(operation["previous_secret_revision"])
    self.assertEqual(operation["previous_nodes"], ["A", "B"])
    self.assertEqual(plugin.commands, [])

  def test_scale_up_keeps_exact_existing_placement_and_updates_all_certificate_generations(self):
    plugin = Mutations()
    result = plugin._admit_scale_up_operation(
      {"request_id": "scale-request", "job_id": 7, "expected_revision": 4},
      {"escrow_owner": "owner"}, ["C"],
    )
    self.assertEqual(result["status_code"], 202)
    admitted = plugin.captured_scale
    self.assertEqual(admitted["mutation"], "scale_up")
    self.assertEqual(list(admitted["configs"]), ["A", "B", "C"])
    for node in ("A", "B"):
      instance = admitted["configs"][node]["PLUGINS"][0]["INSTANCES"][0]
      self.assertEqual(instance["INSTANCE_ID"], "instance-" + node)
      self.assertEqual(instance["VOLUMES"], {"data": "/preserved-" + node})
      self.assertEqual(instance["ENV"]["NODE_VALUE"], node)
      self.assertEqual(instance["ENV"]["CRDB_CA_CERT"], "new-ca")
      self.assertIn("C", instance["PER_NODE_CONFIG"]["byNode"])
      self.assertEqual(admitted["configs"][node]["DEEPLOY_SPECS"]["current_target_nodes"], ["A", "B", "C"])
    self.assertEqual(admitted["prior_pipeline"], plugin.pipeline)
    self.assertEqual(plugin.current["B"]["PLUGINS"][0]["INSTANCES"][0]["ENV"], {"SECRET": "__R1_DAUTH_SECRET__", "NODE_VALUE": "B"})
    self.assertEqual(plugin.commands, [])

  def test_real_managed_scale_preparation_shares_one_new_ca_across_all_nodes(self):
    from extensions.business.deeploy.tests.support import make_deeploy_plugin
    plugin = Mutations()
    plugin.current["C"] = copy.deepcopy(plugin.current["A"])
    plugin.current["C"]["PLUGINS"][0]["INSTANCES"][0]["INSTANCE_ID"] = "instance-C"
    for node, pipeline in plugin.current.items():
      pipeline["DEEPLOY_SPECS"]["current_target_nodes"] = ["A", "B", "C"]
      pipeline["PLUGINS"][0]["SIGNATURE"] = "CONTAINER_APP_RUNNER"
      instance = pipeline["PLUGINS"][0]["INSTANCES"][0]
      instance.update(IMAGE="ghcr.io/ratio1/r1db:stable", ENV={
        "CRDB_DATABASE": "appdb", "CRDB_USER": "app_user", "CRDB_PASSWORD": "password",
        "CRDB_HOSTNAMES": "roach1,roach2,roach3,roach4", "NODE_VALUE": node,
        "CRDB_CA_CRT": "old-ca", "CRDB_NODE_KEY": "old-private-key",
      })
    plugin.pipeline = copy.deepcopy(plugin.current["A"])
    plugin.storage[SECRET_REVISIONS_HKEY, "7|previous:deploy"]["pipelines"] = copy.deepcopy(plugin.current)
    real = make_deeploy_plugin()
    real.time = plugin.time
    plugin.prepare_create_update_pipelines = real.prepare_create_update_pipelines
    plugin._build_scale_up_create_pipeline_configs = real._build_scale_up_create_pipeline_configs
    plugin._admit_scale_up_operation({"request_id": "scale", "job_id": 7, "expected_revision": 4},
                                    {"escrow_owner": "owner"}, ["D"])
    configs = plugin.captured_scale["configs"]
    certificates = []
    for index, (node, pipeline) in enumerate(configs.items()):
      materialized = real._materialize_plugins_for_node(pipeline["PLUGINS"], node, index)
      env = materialized[0]["INSTANCES"][0]["ENV"]
      self.assertIn("BEGIN CERTIFICATE", env["CRDB_CA_CRT"])
      certificates.append(env["CRDB_CA_CRT"])
      if node in plugin.current:
        self.assertEqual(materialized[0]["INSTANCES"][0]["VOLUMES"], plugin.current[node]["PLUGINS"][0]["INSTANCES"][0]["VOLUMES"])
        self.assertEqual(env["NODE_VALUE"], node)
    self.assertEqual(len(set(certificates)), 1)
    self.assertNotIn("old-private-key", str(configs))
    self.assertNotIn("old-ca", str(configs))

  def test_owner_transfer_rolls_full_placement_with_new_owner_on_recovery(self):
    plugin = Mutations()
    result = plugin._admit_owner_transfer_operation(7, "owner", "new-owner", "verified-transaction|3")
    self.assertEqual(result["status_code"], 202)
    admitted = plugin.captured_scale
    self.assertEqual(admitted["mutation"], "owner_transfer")
    self.assertEqual(admitted["restore_owner"], "new-owner")
    self.assertEqual(admitted["prior_pipeline"]["OWNER"], "owner")
    self.assertEqual(set(admitted["configs"]), {"A", "B"})
    for node, config in admitted["configs"].items():
      expected = copy.deepcopy(plugin.current[node]["PLUGINS"])
      expected[0]["INSTANCES"][0].pop("CHAINSTORE_RESPONSE_KEY")  # each node owns its response key
      self.assertEqual(config["OWNER"], "new-owner")
      self.assertEqual(config["PLUGINS"], expected)
    first_request_id = admitted["request"]["request_id"]
    plugin._admit_owner_transfer_operation(7, "owner", "new-owner", "later-transaction|4")
    self.assertNotEqual(first_request_id, plugin.captured_scale["request"]["request_id"])

  def test_owner_transfer_rejects_an_unrelated_current_owner_or_unverified_event(self):
    plugin = Mutations()
    with self.assertRaises(ValueError):
      plugin._admit_owner_transfer_operation(7, "different-owner", "new-owner", "verified|3")
    with self.assertRaises(ValueError):
      plugin._admit_owner_transfer_operation(7, "owner", "new-owner", None)
    self.assertIsNone(plugin.captured_scale)

  def test_node_relink_renames_the_old_node_everywhere_and_keeps_its_settings(self):
    plugin = Mutations()
    plugin.current["A"]["PLUGINS"][0]["INSTANCES"][0].update(CHAINSTORE_PEERS=["A", "B"])
    result = plugin._admit_node_relink_operation(7, "A", "N")
    self.assertEqual(result["status_code"], 202)
    admitted = plugin.captured_scale
    self.assertEqual((admitted["mutation"], admitted["node_aliases"]), ("node_relink", {"A": "N"}))
    # Admission renames the stored copy and its previous configs with the same aliases.
    self.assertEqual(admitted["prior_pipeline"]["DEEPLOY_SPECS"]["current_target_nodes"], ["A", "B"])
    self.assertEqual(set(admitted["configs"]), {"N", "B"})
    moved = admitted["configs"]["N"]["PLUGINS"][0]["INSTANCES"][0]
    self.assertEqual((moved["INSTANCE_ID"], moved["ENV"]["NODE_VALUE"]), ("instance-A", "N"))
    self.assertEqual(moved["CHAINSTORE_PEERS"], ["N", "B"])
    self.assertEqual(moved["VOLUMES"], {"data": "/preserved-A"})

  def test_node_relink_requires_the_old_node_and_not_the_new_one_in_placement(self):
    plugin = Mutations()
    for old_node, new_node in (("C", "N"), ("A", "B")):
      with self.assertRaises(ValueError):
        plugin._admit_node_relink_operation(7, old_node, new_node)
    self.assertIsNone(plugin.captured_scale)

  def test_node_relink_to_new_hardware_needs_no_report_from_either_node(self):
    plugin = Mutations()
    plugin.reports = {}  # the old node is gone and the new one runs nothing yet
    self.assertEqual(plugin._admit_node_relink_operation(7, "A", "N")["status_code"], 202)
    moved = plugin.captured_scale["configs"]["N"]["PLUGINS"][0]["INSTANCES"][0]
    self.assertEqual((moved["INSTANCE_ID"], moved["VOLUMES"]), ("instance-A", {"data": "/preserved-A"}))

  def test_update_keeps_each_scaled_node_instance_and_ignores_reports(self):
    plugin = Mutations()
    forged = copy.deepcopy(plugin.current["B"])
    forged["PLUGINS"][0]["INSTANCES"][0]["IMAGE"] = "forged-image"
    plugin.reports = {"A": plugin.current["A"], "B": forged}
    plugin._admit_owner_transfer_operation(7, "owner", "new-owner", "tx|1")
    configs = plugin.captured_scale["configs"]
    for node in ("A", "B"):
      instance = configs[node]["PLUGINS"][0]["INSTANCES"][0]
      self.assertEqual((instance["INSTANCE_ID"], instance["VOLUMES"]), ("instance-" + node, {"data": "/preserved-" + node}))
    self.assertNotIn("forged-image", str(configs))

  def test_job_stored_before_plans_uses_its_stored_copy_unless_nodes_run_it_differently(self):
    plugin = Mutations()
    plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = "canonical-cid"  # no plan named
    with self.assertRaisesRegex(ValueError, "differently from its stored copy"):
      plugin._admit_owner_transfer_operation(7, "owner", "new-owner", "tx|1")  # B runs instance-B
    plugin.reports = {node: copy.deepcopy(plugin.pipeline) for node in ("A", "B")}
    plugin.reports["B"]["DEEPLOY_SPECS"]["current_target_nodes"] = ["B", "A"]
    with self.assertRaisesRegex(ValueError, "differently from its stored copy"):
      plugin._admit_owner_transfer_operation(7, "owner", "new-owner", "tx|1")  # lost list order
    self.assertIsNone(plugin.captured_scale)
    plugin.reports = {node: copy.deepcopy(plugin.pipeline) for node in ("A", "B")}
    plugin._admit_owner_transfer_operation(7, "owner", "new-owner", "tx|1")
    for config in plugin.captured_scale["configs"].values():
      self.assertEqual(config["PLUGINS"][0]["INSTANCES"][0]["INSTANCE_ID"], "instance-A")

  def test_node_relink_retries_as_a_new_request_an_hour_after_a_failed_attempt(self):
    plugin = Mutations()
    plugin._admit_node_relink_operation(7, "A", "N")
    first = plugin.captured_scale["request"]
    failed = dict(operation_id="0" * 16 + "-x", sequence=1, request_id=first["request_id"],
                  request_hash="h", kind="update", mutation="node_relink", job_id=7, app_id="app",
                  owner="owner", network="test", coordinator="oracle", target_revision=first["attempt"],
                  phase="completed", outcome="failed", updated_at=plugin.now, EE_SIGN="valid", EE_SENDER="oracle")
    plugin._operation_records = lambda: {failed["operation_id"]: failed}
    plugin.captured_scale = None
    plugin.now += 3599
    self.assertIsNone(plugin._admit_node_relink_operation(7, "A", "N"))
    self.assertIsNone(plugin.captured_scale)
    plugin.now += 1
    plugin._admit_node_relink_operation(7, "A", "N")
    retry = plugin.captured_scale["request"]
    self.assertEqual(retry["attempt"], first["attempt"] + 1)
    self.assertNotEqual(retry["request_id"], first["request_id"])

  def test_node_relinks_run_on_one_oracle_per_job_in_hash_order(self):
    plugin = Mutations()
    plugin.plugins_shmem = {"CHAIN_DIST_NODE_RELINKS": {7: ("A", "N")}}
    plugin._operation_peers = lambda: ["oracle", "other", "offline"]
    plugin.netmon = SimpleNamespace(network_node_is_online=lambda peer: peer != "offline")
    plugin._admit_node_relink_operation = Mock()
    plugin.P = Mock()
    rank = sorted(["oracle", "other"], key=lambda peer: __import__("hashlib").sha256(
      "7|{}".format(peer).encode()).hexdigest()).index("oracle")
    calls = []
    for _ in range(4):
      plugin._maybe_admit_node_relinks()
      calls.append(plugin._admit_node_relink_operation.call_count)
      plugin.now += 300
    # A ranked oracle waits 900 s per rank, then retries every 300 s until the job moves.
    self.assertEqual(calls, [sum(1 for look in range(i + 1) if look * 300 >= 900 * rank) for i in range(4)])
    plugin._admit_node_relink_operation.assert_called_with(7, "A", "N")
    online_checks = plugin.netmon.network_node_is_online
    plugin.netmon.network_node_is_online = Mock(side_effect=AssertionError("checked between looks"))
    plugin.now -= 1
    plugin._maybe_admit_node_relinks()
    plugin.netmon.network_node_is_online = online_checks
    plugin.plugins_shmem["CHAIN_DIST_NODE_RELINKS"] = {}
    plugin._maybe_admit_node_relinks()
    self.assertEqual(plugin._node_relinks_seen, {})

  def test_delete_generation_advances_after_previous_content_was_restored(self):
    plugin = Mutations()
    plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = dict(revision=9, pipeline_cid="canonical-cid", plan_cid="current-plan", deleted=False)
    plugin._get_pipeline_from_cstore = lambda job_id: "canonical-cid"
    result = plugin.delete()
    operation = plugin._operation_records()[result["operation_id"]]
    self.assertEqual(operation["previous_revision"], 4)
    self.assertEqual(operation["target_revision"], 10)
    for node in ("A", "B"):
      plugin.stop_report(operation, node)
    plugin._advance_delete_operation(operation)
    pointer = plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"]
    self.assertEqual(pointer["revision"], 10)
    self.assertEqual(pointer["EE_SENDER"], "oracle")
    self.assertIsNone(pointer["pipeline_cid"])
    self.assertEqual(plugin.storage[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"]["deployment_revision"], 10)

  def test_scale_up_rejects_stale_revision_or_existing_target(self):
    for revision, nodes in ((3, ["C"]), (4, ["B"]), (4, [])):
      plugin = Mutations()
      with self.assertRaises(ValueError):
        plugin._admit_scale_up_operation({"request_id": "scale", "job_id": 7, "expected_revision": revision},
                                        {"escrow_owner": "owner"}, nodes)
      self.assertIsNone(plugin.captured_scale)
      self.assertEqual(plugin.writes, [])

  def test_delete_rechecks_current_escrow_owner_before_stopping_anything(self):
    plugin = Mutations()
    plugin.bc.get_job_details = lambda job_id: {"escrowOwner": "new-owner"}
    with self.assertRaisesRegex(ValueError, "current escrow owner"):
      plugin.delete()
    self.assertEqual(plugin.commands, [])
    self.assertEqual(plugin.writes, [])

  def test_scale_rejects_unmappable_node_plugin_order_before_writing(self):
    plugin = Mutations()
    plugin.plans["current-plan"]["configs"]["B"]["PLUGINS"][0]["SIGNATURE"] = "DIFFERENT_PLUGIN"
    with self.assertRaisesRegex(ValueError, "cannot be mapped safely"):
      plugin._admit_scale_up_operation({"request_id": "scale", "job_id": 7, "expected_revision": 4},
                                      {"escrow_owner": "owner"}, ["C"])
    self.assertEqual(plugin.writes, [])

  def test_delete_is_durable_async_and_rejects_partial_targets(self):
    plugin = Mutations()
    with self.assertRaisesRegex(ValueError, "entire job"):
      plugin.delete(target_nodes=["A"])
    self.assertEqual(plugin.writes, [])
    result = plugin.delete()
    self.assertEqual(result["status_code"], 202)
    operation = plugin._operation_records()[result["operation_id"]]
    self.assertEqual(operation["kind"], "delete")
    self.assertEqual(operation["previous_nodes"], ["A", "B"])
    self.assertEqual(operation["previous_operation_id"], "previous")
    self.assertEqual(plugin.commands, [])
    self.assertEqual(plugin.delete()["operation_id"], operation["operation_id"])

  def test_delete_keeps_secrets_until_all_nodes_confirm_stop(self):
    plugin = Mutations()
    operation_id = plugin.delete()["operation_id"]
    operation = plugin._operation_records()[operation_id]
    plugin.stop_report(operation, "A")
    plugin.now = 200
    plugin._advance_delete_operation(operation)
    self.assertEqual(operation["recovery"], "blocked")
    self.assertEqual(plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"]["pipeline_cid"], "canonical-cid")
    self.assertEqual(plugin.storage[SECRET_REVISIONS_HKEY, "7|previous:deploy"]["job_secrets"], {"secret": "protected"})
    self.assertEqual(plugin.commands[-1]["node_address"], "B")
    self.assertEqual(plugin.commands[-1]["config"]["DEEPLOY_OPERATION"]["action"], "retire")
    plugin.stop_report(operation, "B")
    plugin._advance_delete_operation(operation)
    self.assertEqual(operation["phase"], "completed")
    self.assertNotIn("settlement", operation)
    self.assertTrue(plugin.storage[SECRET_REVISIONS_HKEY, "7|previous:deploy|revoked"])
    self.assertTrue(plugin.storage[SECRET_REVISIONS_HKEY, "7|previous:deploy"]["revoked"])
    self.assertEqual(plugin.storage[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"]["job_secrets"], {})
    self.assertTrue(plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"]["deleted"])
    plugin._delete_pipeline_cid_from_r1fs.assert_called_with("canonical-cid")

  def test_stuck_delete_writes_no_snapshot_per_pass_and_completes_when_the_node_stops(self):
    plugin = Mutations()
    operation_id = plugin.delete()["operation_id"]
    plugin.stop_report(plugin._operation_records()[operation_id], "A")
    sequences = []
    for _ in range(150):  # 300 s of 2 s worker passes; B never answers, the 60 s deadline passes
      plugin.now += 2
      operation = plugin._operation_records()[operation_id]
      plugin._advance_delete_operation(operation)
      sequences.append(operation["sequence"])
    # One snapshot at admission and one for the blocked transition; command retries write none.
    self.assertEqual(set(sequences), {1, 2})
    self.assertEqual(sequences[-100:], [2] * 100)
    # Repair re-sends repeat a confirmed snapshot; they never produce a new one.
    self.assertEqual(len({key for namespace, key in plugin.writes if namespace == OPERATIONS_HKEY}), 2)
    self.assertLessEqual(sum(namespace == OPERATIONS_HKEY for namespace, _ in plugin.writes), 2 + 300 // 30 + 1)
    self.assertEqual((operation["recovery"], operation["error"]["code"]), ("blocked", "STOP_UNCONFIRMED"))
    retires = [command for command in plugin.commands if command["node_address"] == "B"]
    self.assertGreaterEqual(len(retires), 29)
    plugin.stop_report(operation, "B")
    plugin.now += 2
    plugin._advance_delete_operation(plugin._operation_records()[operation_id])
    self.assertEqual(plugin._operation_records()[operation_id]["phase"], "completed")

  def test_delete_retries_metadata_cleanup_after_a_partial_write(self):
    plugin = Mutations()
    operation_id = plugin.delete()["operation_id"]
    operation = plugin._operation_records()[operation_id]
    for node in ("A", "B"):
      plugin.stop_report(operation, node)
    plugin.fail_namespace = DEEPLOY_JOBS_CSTORE_HKEY
    with self.assertRaisesRegex(RuntimeError, "metadata cleanup"):
      plugin._advance_delete_operation(operation)
    plugin.fail_namespace = None
    plugin._advance_delete_operation(operation)
    self.assertEqual(operation["phase"], "completed")

  def test_delete_does_not_erase_a_newer_canonical_revision(self):
    plugin = Mutations()
    operation_id = plugin.delete()["operation_id"]
    operation = plugin._operation_records()[operation_id]
    for node in ("A", "B"):
      plugin.stop_report(operation, node)
    plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = "newer-cid"
    with self.assertRaisesRegex(RuntimeError, "no longer matches"):
      plugin._advance_delete_operation(operation)
    self.assertNotIn((SECRET_REVISIONS_HKEY, "7|previous:deploy|revoked"), plugin.storage)


if __name__ == "__main__":
  unittest.main()
