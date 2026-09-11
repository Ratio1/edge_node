"""Bound model launch and secret overlays cannot change the saved provider destination."""
from copy import deepcopy
import unittest
from unittest.mock import MagicMock, call, patch

from extensions.business.cybersec.red_mesh.model_testing.launch import launch_model_test, preflight_model_test_provider
from extensions.business.cybersec.red_mesh.model_testing.secrets import attach_model_test_provider_secret, resolve_model_test_runtime_config
from extensions.business.cybersec.red_mesh.model_testing.worker import ModelTestWorker
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.execution import ResolvedExecutionContext

from .test_execution_binding_models import binding_payload
from .test_model_testing import _owner, _provider, _valid_launch_kwargs, PUBLIC_TEST_IP


LAUNCH = "extensions.business.cybersec.red_mesh.model_testing.launch."
SECRETS = "extensions.business.cybersec.red_mesh.model_testing.secrets."
WORKER = "extensions.business.cybersec.red_mesh.model_testing.worker."


class TestTenantExecutionModel(unittest.TestCase):
  def setUp(self):
    target = {"kind": "model", "adapter": "openai_compatible", "model": "unit-model",
              "endpointUrl": f"https://{PUBLIC_TEST_IP}/v1/chat/completions"}
    facts = {key: value for key, value in binding_payload().items()
             if key not in ("schema_version", "original_launcher", "participant_order")}
    self.context = ResolvedExecutionContext({**facts, "asset_target": target,
      "asset_target_digest": canonical_digest(target), "selected_candidates": ["node-a", "node-b"]})
    self.binding = self.context.build_binding("launcher-node", ["node-b"]).to_dict()
    self.owner = _owner(cfg_model_testing={"ENABLED": True},
      cfg_chainstore_peers=["node-a", "node-b", "foreign-node"],
      get_model_test_resource_scores=lambda peers: {"node-a": 1, "node-b": 2, "foreign-node": 100},
      _require_worker_execution=MagicMock())
    self.config = {"job_id": "job-123", "job_type": "model_test", "scan_type": "model_test",
      "execution_binding": self.binding, "tested_model": _provider(),
      "model_provider_secret_ref": "secret-cid"}
    self.execution_identity = ("job-123", 1, "node-b", 1)

  def test_conflicting_provider_denies_before_dns_client_or_secret_effects(self):
    for provider in ({**_provider(), "base_url": "https://foreign.example/v1"},
                     {**_provider(), "model": "other-model"},
                     {**_provider(), "method": "moderation"},
                     {**_provider(), "adapter": "mock"}):
      with self.subTest(provider=provider), \
           patch(LAUNCH + "_validate_provider", side_effect=AssertionError("No DNS validation")), \
           patch(LAUNCH + "OpenAICompatibleProviderClient", side_effect=AssertionError("No provider")), \
           patch(LAUNCH + "attach_model_test_provider_secret", side_effect=AssertionError("No secret write")):
        launched = launch_model_test(self.owner, **{**_valid_launch_kwargs(), "tested_model": provider},
          execution_context=self.context)
        self.assertEqual(launched.get("error_class"), "execution_target_mismatch")
        preflight = preflight_model_test_provider(self.owner, created_by_id="actor", tested_model=provider,
          tested_model_secret_payload={"api_key": "test-only"}, execution_context=self.context)
        self.assertFalse(preflight["ok"])
        self.assertEqual(preflight.get("error_class"), "execution_target_mismatch")
    self.owner.r1fs.add_json.assert_not_called()
    self.owner.chainstore_hset.assert_not_called()

  def test_launch_derives_saved_provider_and_binds_only_actual_selected_worker_before_secret_save(self):
    captured = []
    with patch(SECRETS + "R1fsSecretStore") as secret_store, \
         patch(LAUNCH + "_artifact_repo") as artifacts, \
         patch(LAUNCH + "_write_job_record", side_effect=lambda owner, job_id, row: deepcopy(row)), \
         patch(LAUNCH + "_write_initial_progress"), \
         patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")):
      secret_store.return_value.save_model_test_provider_credentials.return_value = "secret-cid"
      secret_store.return_value.last_key_metadata = {}
      artifacts.return_value.put_job_config.side_effect = lambda config, **kw: captured.append(deepcopy(config)) or "config-cid"
      result = launch_model_test(self.owner, **{**_valid_launch_kwargs(),
        "tested_model": {"provider_label": "Saved provider"}, "selected_peers": ["foreign-node"]},
        execution_context=self.context)
      self.assertNotIn("error", result, result)
      payload = secret_store.return_value.save_model_test_provider_credentials.call_args.args[1]
    self.assertEqual(payload["tested_model"]["base_url"], self.context.to_dict()["asset_target"]["endpointUrl"])
    self.assertEqual(result["worker"], "node-b")
    self.assertEqual(result["job_specs"]["execution_binding"], self.binding)
    self.assertEqual(captured[0]["execution_binding"], self.binding)
    self.assertEqual(result["job_config"]["execution_binding"], self.binding)
    self.assertEqual(result["model_test_node_selection"]["candidate_peer_ids"], ["node-a", "node-b"])
    self.assertNotIn("other_jobs", result)

  def test_preflight_checks_effective_runtime_provider_before_client_creation(self):
    with patch(LAUNCH + "_runtime_provider", return_value={**_provider(), "base_url": "https://foreign.example/v1"}), \
         patch(LAUNCH + "OpenAICompatibleProviderClient") as client:
      result = preflight_model_test_provider(self.owner, created_by_id="actor", tested_model=_provider(),
        tested_model_secret_payload={"api_key": "test-only"}, execution_context=self.context)
    self.assertFalse(result["ok"])
    self.assertEqual(result.get("error_class"), "execution_target_mismatch")
    client.assert_not_called()

  def test_secret_attach_checks_effective_provider_before_save(self):
    for config, tested in ((self.config, {**_provider(), "base_url": "https://foreign.example/v1"}),
                            ({**self.config, "execution_binding": None}, _provider())):
      with self.subTest(config=config, tested=tested), patch(SECRETS + "R1fsSecretStore") as store:
        with self.assertRaises(ValueError):
          attach_model_test_provider_secret(self.owner, job_id="job-123", sanitized_config=config,
            tested_model=tested, tested_model_secret_payload={"api_key": "test-only"},
            evaluator_model=None, evaluator_model_secret_payload=None)
        store.return_value.save_model_test_provider_credentials.assert_not_called()

  def test_secret_overlay_is_checked_before_runtime_configuration_is_returned(self):
    for overlay in ({"base_url": "https://foreign.example/v1"}, {"model": "other"},
                    {"adapter": "mock"}, {"method": "moderation"}):
      with self.subTest(overlay=overlay), patch(SECRETS + "R1fsSecretStore") as store:
        store.return_value.load_model_test_provider_credentials.return_value = {
          "tested_model": {**_provider(), "api_key": "test-only", **overlay}}
        with self.assertRaises(ValueError):
          resolve_model_test_runtime_config(self.owner, self.config)
    with patch(SECRETS + "R1fsSecretStore") as store:
      store.return_value.load_model_test_provider_credentials.return_value = {
        "tested_model": {**_provider(), "api_key": "test-only"}}
      resolved = resolve_model_test_runtime_config(self.owner, self.config)
    self.assertEqual(resolved["execution_binding"], self.binding)
    self.assertEqual(resolved["tested_model"]["api_key"], "test-only")

  def test_worker_checks_final_configuration_before_runner_or_provider_construction(self):
    worker = ModelTestWorker(self.owner, job_id="job-123", initiator="launcher-node", job_config=self.config,
                             execution_identity=self.execution_identity)
    retargeted = {**self.config, "tested_model": {**_provider(), "model": "foreign-model"}}
    with patch(WORKER + "resolve_model_test_runtime_config", return_value=retargeted), \
         patch(WORKER + "ModelTestRunner") as runner:
      worker.execute_job()
    runner.assert_not_called()
    self.assertTrue(worker.state["done"])
    self.assertEqual(worker.state["model_test_summary"]["overall_status"], "failed")

  def test_worker_requires_fresh_authority_before_secret_reads(self):
    for guard in (None, MagicMock(side_effect=ValueError("Execution unavailable"))):
      self.owner._require_worker_execution = guard
      worker = ModelTestWorker(self.owner, job_id="job-123", initiator="launcher-node", job_config=self.config,
                               execution_identity=self.execution_identity)
      with self.subTest(guard=guard), patch(WORKER + "resolve_model_test_runtime_config") as secret, \
           patch(WORKER + "ModelTestRunner") as runner:
        worker.execute_job()
      secret.assert_not_called()
      runner.assert_not_called()
      self.assertEqual(worker.state["model_test_summary"]["overall_status"], "failed")

  def test_valid_bound_worker_uses_runtime_provider_after_fresh_guard(self):
    worker = ModelTestWorker(self.owner, job_id="job-123", initiator="launcher-node", job_config=self.config,
                             execution_identity=self.execution_identity)
    with patch(WORKER + "resolve_model_test_runtime_config", return_value=deepcopy(self.config)) as secret, \
         patch(WORKER + "ModelTestRunner") as runner:
      runner.return_value.run.return_value = {"model_test_summary": {"overall_status": "completed"}}
      worker.execute_job()
    self.assertEqual(self.owner._require_worker_execution.call_args_list, [
      call("job-123", self.config, execution_identity=self.execution_identity),
      call("job-123", self.config, execution_identity=self.execution_identity),
    ])
    secret.assert_called_once()
    runner.assert_called_once()
    self.assertEqual(worker.state["model_test_summary"]["overall_status"], "completed")

  def test_worker_cannot_lose_or_replace_the_saved_binding_after_secret_resolution(self):
    for resolved in ({key: value for key, value in self.config.items() if key != "execution_binding"},
                     {**self.config, "execution_binding": {**self.binding, "actor_id": "replacement"}}):
      worker = ModelTestWorker(self.owner, job_id="job-123", initiator="launcher-node", job_config=self.config,
                               execution_identity=self.execution_identity)
      with self.subTest(resolved=resolved), patch(WORKER + "resolve_model_test_runtime_config", return_value=resolved), \
           patch(WORKER + "ModelTestRunner") as runner:
        worker.execute_job()
      runner.assert_not_called()
      self.assertEqual(worker.state["model_test_summary"]["overall_status"], "failed")
