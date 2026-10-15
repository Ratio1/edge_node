"""Existing persisted pipelines survive restart without weakening revision auth."""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ratio1.bc.base import BaseBlockEngine
from ratio1.const.base import dAuth
from naeural_core.main.orchestrator import Orchestrator
from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY, DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY, DEEPLOY_JOBS_CSTORE_HKEY,
)
from extensions.business.dauth.test_dauth_registry_gating import (
  REQUEST_TIME, REQUEST_NONCE, _make_dauth_harness,
)


def existing_job():
  plugin = _make_dauth_harness()
  plugin.chainstore_hsync = Mock(return_value={"merged_fields": 0})
  plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = "old-cid"
  plugin._r1fs_data["old-cid"] = {
    "NAME": "existing", "TYPE": "Void", "OWNER": "owner",
    "DEEPLOY_SPECS": {"job_id": 7, "date_updated": 1, "current_target_nodes": ["node-runner"]},
    "PLUGINS": [{"SIGNATURE": "TEST_PLUGIN", "INSTANCES": [{"INSTANCE_ID": "instance",
                 "ENV": {"TOKEN": dAuth.DAUTH_SECRET_PLACEHOLDER}}]}],
  }
  plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"] = {
    "job_id": "7", "pipeline_cid": "old-cid",
    "job_secrets": {"PLUGINS": [{"INSTANCES": [{"ENV": {"TOKEN": "existing-secret"}}]}]},
  }
  return plugin


def request(**overrides):
  return {"EE_SENDER": "node-runner", "EE_ETH_SENDER": "0xRUNNER", "job_id": "7",
          "nonce": REQUEST_NONCE, **overrides}


class ExistingPipelineSecretTests(unittest.TestCase):
  def test_existing_runner_gets_only_cid_bound_current_bundle(self):
    plugin = existing_job()
    result = plugin.process_dauth_get_secret_request(request())
    self.assertNotIn("revision", result)
    self.assertEqual(result["nonce"], REQUEST_NONCE)
    bundle = json.loads(plugin.bc.encrypt_calls[-1][0])
    self.assertEqual(bundle["pipeline_cid"], "old-cid")
    self.assertEqual(bundle["job_secrets"]["PLUGINS"][0]["INSTANCES"][0]["ENV"]["TOKEN"], "existing-secret")
    self.assertEqual([call.kwargs["hkey"] for call in plugin.chainstore_hsync.call_args_list],
                     [DEEPLOY_JOBS_CSTORE_HKEY, DAUTH_JOB_SECRETS_CSTORE_HKEY])

  def test_pre_cid_bundle_uses_existing_structural_binding(self):
    plugin = existing_job()
    plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"].pop("pipeline_cid")
    plugin.process_dauth_get_secret_request(request())
    self.assertEqual(plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"]["pipeline_cid"], "old-cid")

  def test_revision_metadata_and_deletion_never_allow_unversioned_lookup(self):
    for marker in ({"revision": 1, "pipeline_cid": "old-cid"},
                   {"revision": 2, "deleted": True, "pipeline_cid": None},
                   {"revision": 3, "pipeline_cid": "reused-cid"}):
      with self.subTest(marker=marker):
        plugin = existing_job()
        plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = marker
        with self.assertRaises(ValueError):
          plugin.process_dauth_get_secret_request(request())
        self.assertEqual(plugin.bc.encrypt_calls, [])

  def test_versioned_pipeline_or_bundle_cannot_use_old_raw_pointer(self):
    for field, value in (("secret_revision", "op:restore"), ("revision", 1)):
      plugin = existing_job()
      plugin._r1fs_data["old-cid"]["DEEPLOY_SPECS"][field] = value
      with self.assertRaises(ValueError):
        plugin.process_dauth_get_secret_request(request())
      self.assertEqual(plugin.bc.encrypt_calls, [])
    for marker in ({"revision": "op:deploy"}, {"deployment_revision": 1},
                   {"operation_id": "op"}, {"deleted": True}, {"revoked": True}):
      with self.subTest(marker=marker):
        plugin = existing_job()
        bundle = plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"]
        bundle.pop("pipeline_cid")  # Binding must not strip version metadata.
        bundle.update(marker)
        with self.assertRaises(ValueError):
          plugin.process_dauth_get_secret_request(request())
        self.assertEqual(plugin.bc.encrypt_calls, [])

  def test_unrelated_node_and_invalid_signature_or_nonce_are_rejected(self):
    for overrides in ({"EE_SENDER": "node-other", "EE_ETH_SENDER": "0xOTHER"},
                      {"nonce": hex(int((REQUEST_TIME - 121) * 1000))}):
      plugin = existing_job()
      with self.assertRaises(ValueError):
        plugin.process_dauth_get_secret_request(request(**overrides))
      self.assertEqual(plugin.bc.encrypt_calls, [])
    plugin = existing_job()
    plugin.bc.valid_signature = False
    with self.assertRaises(ValueError):
      plugin.process_dauth_get_secret_request(request())
    plugin.chainstore_hsync.assert_not_called()

  def test_secret_generation_mismatch_and_pointer_change_fail_closed(self):
    plugin = existing_job()
    plugin._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"]["pipeline_cid"] = "new-cid"
    with self.assertRaisesRegex(ValueError, "generation mismatch"):
      plugin.process_dauth_get_secret_request(request())
    self.assertEqual(plugin.bc.encrypt_calls, [])
    plugin = existing_job()
    load = plugin._load_current_dauth_secret_bundle
    def change_generation(*args, **kwargs):
      bundle = load(*args, **kwargs)
      plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = {"revision": 1, "pipeline_cid": "old-cid"}
      return bundle
    plugin._load_current_dauth_secret_bundle = change_generation
    with self.assertRaisesRegex(RuntimeError, "generation changed"):
      plugin.process_dauth_get_secret_request(request())
    self.assertEqual(plugin.bc.encrypt_calls, [])

  def test_replica_repair_disables_stale_unversioned_lookup(self):
    plugin = existing_job()
    def sync(**kwargs):
      plugin._chainstore[DEEPLOY_JOBS_CSTORE_HKEY, "7"] = {"revision": 2, "deleted": True}
      return {"merged_fields": 1}
    plugin.chainstore_hsync = sync
    with self.assertRaises(ValueError):
      plugin.process_dauth_get_secret_request(request())
    self.assertEqual(plugin.bc.encrypt_calls, [])

  def test_unavailable_repair_is_retryable_without_serving_cached_secrets(self):
    plugin = existing_job()
    plugin.chainstore_hsync.return_value = None
    with self.assertRaises(RuntimeError):
      plugin.process_dauth_get_secret_request(request())
    self.assertEqual(plugin.bc.encrypt_calls, [])

  def test_first_update_preserves_existing_secrets_in_exact_restore_revision(self):
    from extensions.business.deeploy.tests.test_deployment_admission import Admission
    from extensions.business.deeploy.tests.support import make_deeploy_plugin
    server = existing_job()
    previous = deepcopy(server._r1fs_data["old-cid"])
    bundle = deepcopy(server._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"])
    coordinator = Admission()
    coordinator.netmon = SimpleNamespace(network_known_pipelines=lambda: {"node-runner": [previous]})
    coordinator._redact_pipeline_configs_and_build_secret_bundle = (
      make_deeploy_plugin()._redact_pipeline_configs_and_build_secret_bundle
    )
    accepted = coordinator._admit_prepared_deployment(
      request={"request_id": "first-update", "job_id": 7, "expected_revision": 0},
      auth_result={"escrow_owner": "owner"}, app_id="existing",
      configs={"node-runner": deepcopy(previous)}, bundle=bundle,
      prior_pipeline=previous, prior_bundle=bundle, is_create=False,
    )
    restore = coordinator.plans["plan-cid"]["previous_configs"]["node-runner"]
    revision = restore["DEEPLOY_SPECS"]["secret_revision"]
    self.assertEqual(revision, accepted["operation_id"] + ":restore")
    self.assertEqual(restore["DEEPLOY_SPECS"]["revision"], 0)
    key = (DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY, "7|" + revision)
    server._chainstore[key] = deepcopy(coordinator.storage[key])
    result = server.process_dauth_get_secret_request(request(revision=revision))
    self.assertEqual(result["revision"], revision)
    restored_bundle = json.loads(server.bc.encrypt_calls[-1][0])
    self.assertEqual(restored_bundle["job_secrets"], bundle["job_secrets"])
    self.assertEqual(server._chainstore[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"], bundle)
    self.assertNotIn("secret_revision", previous["DEEPLOY_SPECS"])

  def test_persisted_pipeline_resolves_through_sdk_and_dauth_after_each_restart(self):
    server = existing_job()
    canonical = deepcopy(server._r1fs_data["old-cid"])
    requests = []
    def post(url, json, timeout):
      requests.append(deepcopy(json["body"]))
      result = server.process_dauth_get_secret_request(json["body"])
      return SimpleNamespace(status_code=200, json=lambda: {"result": result})
    with tempfile.TemporaryDirectory() as directory:
      saved = Path(directory) / "pipeline.json"
      saved.write_text(json.dumps(canonical))
      for _ in range(2):
        engine = SimpleNamespace(
          evm_network="mainnet", get_network_data=lambda network: {dAuth.EvmNetData.DAUTH_URL_KEY: "https://offline/get_auth_data"},
          sign=lambda body: body.update(EE_SENDER="node-runner", EE_ETH_SENDER="0xRUNNER"),
          verify=lambda *args, **kwargs: SimpleNamespace(valid=True, sender="oracle"),
          node_address_to_eth_address=lambda address: "0xORACLE", web3_is_dauth_oracle=lambda *args, **kwargs: True,
          decrypt=lambda **kwargs: server.bc.encrypt_calls[-1][0],
        )
        engine.get_dauth_job_secret_bundle = BaseBlockEngine.get_dauth_job_secret_bundle.__get__(engine)
        node = Orchestrator.__new__(Orchestrator)
        node._blockchain_manager = engine
        node._current_dct_config_streams = {"existing": json.loads(saved.read_text())}
        messages = []
        node.P = lambda message, **kwargs: messages.append(message)
        node._ensure_runtime_secret_resolution_state()
        self.assertEqual(node._runtime_secret_cache, {})
        with patch("ratio1.bc.base.requests.post", side_effect=post), patch("ratio1.bc.base.time", return_value=REQUEST_TIME):
          self.assertEqual(node._resolve_runtime_streams_once(now=10), 1, messages)
        runtime = node._get_runtime_streams_snapshot()["existing"]
        self.assertEqual(runtime["PLUGINS"][0]["INSTANCES"][0]["ENV"]["TOKEN"], "existing-secret")
        self.assertEqual(node._current_dct_config_streams["existing"], canonical)
        self.assertEqual(json.loads(saved.read_text()), canonical)
    self.assertEqual(len(requests), 2)
    self.assertTrue(all("revision" not in body for body in requests))


if __name__ == "__main__":
  unittest.main()
