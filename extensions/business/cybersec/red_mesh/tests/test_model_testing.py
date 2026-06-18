import socket
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.model_testing import (
  get_capability_status,
  launch_model_test,
  select_model_test_execution_node,
  validate_model_provider_credentials,
  validate_provider_url,
)
from extensions.business.cybersec.red_mesh.models import (
  CStoreJobFinalized,
  CStoreJobRunning,
  CStoreWorker,
)
from extensions.business.cybersec.red_mesh.repositories import ArtifactRepository
from extensions.business.cybersec.red_mesh.tests.conftest import mock_plugin_modules


PUBLIC_TEST_IP = "93.184.216.34"


def _owner(**kwargs):
  defaults = {
    "CONFIG": {},
    "config_data": {},
    "cfg_chainstore_peers": ["node-a"],
    "cfg_instance_id": "instance",
    "ee_addr": "launcher-node",
    "ee_id": "Launcher",
    "uuid": MagicMock(return_value="job-123"),
    "time": MagicMock(return_value=123.0),
    "r1fs": MagicMock(),
    "chainstore_hset": MagicMock(),
    "chainstore_hgetall": MagicMock(return_value={}),
  }
  defaults.update(kwargs)
  return SimpleNamespace(**defaults)


def _provider(base_url=f"https://{PUBLIC_TEST_IP}/v1", credential_ref=""):
  result = {
    "adapter": "openai_compatible",
    "provider_label": "Unit Provider",
    "base_url": base_url,
    "model": "unit-model",
  }
  if credential_ref:
    result["credential_ref"] = credential_ref
  return result


def _valid_launch_kwargs(secret="sentinel-model-api-key"):
  return {
    "task_name": "CBRN smoke",
    "task_description": "Run reviewed CBRN safety pack",
    "created_by_name": "tester",
    "created_by_id": "user-123",
    "authorized": True,
    "test_set_id": "cbrn_safety_v1",
    "tested_model": _provider(),
    "tested_model_secret_payload": {"api_key": secret},
    "use_default_evaluator_model": False,
    "evaluator_model": _provider(),
    "evaluator_model_secret_payload": {"api_key": secret},
  }


class TestModelTestingCapability(unittest.TestCase):

  def test_capability_status_default_disabled_and_sanitized(self):
    owner = _owner(cfg_model_testing={
      "ENABLED": False,
      "RAW_EVIDENCE_SECRET_REF": "raw-secret-name",
      "DEFAULT_EVALUATOR_MODEL": {
        "provider_label": "Evaluator",
        "api_key": "super-secret",
      },
    })

    status = get_capability_status(owner)

    model_testing = status["model_testing"]
    self.assertFalse(model_testing["enabled"])
    self.assertEqual(model_testing["disabled_reason"], "disabled_by_policy")
    self.assertEqual(model_testing["restricted_raw_permission"], "job:view_raw_model_evidence")
    self.assertEqual(model_testing["restricted_raw_purge_permission"], "job:purge_raw_model_evidence")
    self.assertEqual(model_testing["default_evaluator_model_label"], "Evaluator")
    self.assertNotIn("super-secret", str(status))
    self.assertNotIn("raw-secret-name", str(status))

  def test_launch_model_test_disabled_fails_before_persistence(self):
    owner = _owner()

    result = launch_model_test(owner, **_valid_launch_kwargs())

    self.assertEqual(result["error"], "model_testing_disabled")
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()


class TestModelTestingProviderSecurity(unittest.TestCase):

  def test_provider_url_rejects_forbidden_url_shapes(self):
    bad_urls = [
      "http://provider.example/v1",
      "https://user:pw@provider.example/v1",
      "https://provider.example/v1?api_key=secret",
      "https://provider.example/v1#secret",
      "https://127.0.0.1/v1",
      "https://10.0.0.1/v1",
      "https://169.254.169.254/latest",
      "https://[::1]/v1",
    ]

    for base_url in bad_urls:
      with self.subTest(base_url=base_url):
        _, err = validate_provider_url(base_url)
        self.assertIsNotNone(err)
        self.assertIn(err["error_class"], {"invalid_url", "forbidden_destination"})

  def test_provider_url_rejects_mixed_dns_answers(self):
    def resolver(hostname, port, type=socket.SOCK_STREAM):
      return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_TEST_IP, 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
      ]

    _, err = validate_provider_url("https://provider.example/v1", resolver=resolver)

    self.assertIsNotNone(err)
    self.assertEqual(err["error_class"], "forbidden_destination")

  def test_duplicate_credential_sources_fail_closed(self):
    _, err = validate_model_provider_credentials(
      {
        "credential_ref": "model_provider/operator/user-123/provider-a",
      },
      {"api_key": "secret"},
      role="tested_model",
      created_by_id="user-123",
    )

    self.assertEqual(err["error_class"], "duplicate_credential_source")

  def test_inline_credential_fields_in_provider_config_fail_closed(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})

    for role, provider_key in (
      ("tested_model", "tested_model"),
      ("evaluator_model", "evaluator_model"),
    ):
      with self.subTest(role=role):
        kwargs = _valid_launch_kwargs()
        kwargs[provider_key] = {
          **kwargs[provider_key],
          "api_key": "inline-secret",
        }
        result = launch_model_test(owner, **kwargs)
        self.assertEqual(result["error"], "validation_error")
        self.assertEqual(result["error_class"], "invalid_provider_config")
        self.assertNotIn("inline-secret", str(result))
        owner.r1fs.add_json.assert_not_called()
        owner.chainstore_hset.assert_not_called()

  def test_inline_auth_headers_in_provider_config_fail_closed(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})
    kwargs = _valid_launch_kwargs()
    kwargs["tested_model"] = {
      **kwargs["tested_model"],
      "headers": {"Authorization": "Bearer inline-secret"},
    }

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertEqual(result["error_class"], "invalid_provider_config")
    self.assertNotIn("inline-secret", str(result))
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_invalid_credential_refs_use_same_sanitized_error(self):
    refs = [
      "not-a-model-provider-ref",
      "model_provider/operator/other/provider-a",
      "model_provider/operator/user-123/nested/provider",
      "model_provider/deploy/default_evaluator/provider-a",
      "model_provider/unknown/provider-a",
    ]

    for ref in refs:
      with self.subTest(ref=ref):
        _, err = validate_model_provider_credentials(
          {"credential_ref": ref},
          {},
          role="tested_model",
          created_by_id="user-123",
        )
        self.assertEqual(err["error_class"], "credential_unavailable")
        self.assertNotIn(ref, str(err))

  def test_enabled_launch_persists_one_worker_entry_and_does_not_echo_secret(self):
    owner = _owner(
      cfg_model_testing={"ENABLED": True},
      cfg_chainstore_peers=["node-a", "node-b"],
    )
    secret = "sentinel-model-api-key"
    kwargs = _valid_launch_kwargs(secret=secret)
    kwargs["selected_peers"] = ["node-b"]
    kwargs["limits"] = {
      "tested_max_tokens": 128,
      "api_key": secret,
      "unknown_secret_field": secret,
    }

    result = launch_model_test(owner, **kwargs)

    self.assertNotIn("error", result)
    self.assertEqual(result["job_type"], "model_test")
    self.assertEqual(result["worker"], "node-b")
    self.assertNotIn(secret, str(result))
    self.assertTrue(result["job_config"]["tested_model"]["credential_ref_present"] is False)
    self.assertEqual(result["job_config"]["limits"]["tested_max_tokens"], 128)
    self.assertNotIn("api_key", result["job_config"]["limits"])
    self.assertNotIn("unknown_secret_field", result["job_config"]["limits"])
    self.assertEqual(result["model_test_node_selection"]["selection_mode"], "manual")
    self.assertEqual(result["model_test_node_selection"]["selected_execution_node"], "node-b")

    owner.r1fs.add_json.assert_called_once()
    stored_config = owner.r1fs.add_json.call_args.args[0]
    self.assertEqual(stored_config["job_type"], "model_test")
    self.assertEqual(stored_config["scan_type"], "model_test")
    self.assertEqual(stored_config["job_id"], "job-123")
    self.assertEqual(stored_config["model_test_node_selection"]["selected_execution_node"], "node-b")
    self.assertNotIn(secret, str(stored_config))

    owner.chainstore_hset.assert_called_once()
    stored_job = owner.chainstore_hset.call_args.kwargs["value"]
    self.assertEqual(stored_job["job_type"], "model_test")
    self.assertEqual(stored_job["scan_type"], "model_test")
    self.assertEqual(set(stored_job["workers"]), {"node-b"})
    self.assertEqual(stored_job["workers"]["node-b"]["worker_type"], "model_test")
    self.assertEqual(stored_job["workers"]["node-b"]["model_test_worker_status"], "queued")
    self.assertNotIn("node-a", stored_job["workers"])

  def test_enabled_launch_rejects_invalid_selected_peer_before_persistence(self):
    owner = _owner(
      cfg_model_testing={"ENABLED": True},
      cfg_chainstore_peers=["node-a"],
    )
    kwargs = _valid_launch_kwargs()
    kwargs["selected_peers"] = ["node-x"]

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("Invalid peer addresses", result["message"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_enabled_launch_returns_storage_error_before_cstore_write(self):
    r1fs = MagicMock()
    r1fs.add_json.return_value = ""
    owner = _owner(cfg_model_testing={"ENABLED": True}, r1fs=r1fs)

    result = launch_model_test(owner, **_valid_launch_kwargs())

    self.assertEqual(result["error"], "storage_error")
    owner.chainstore_hset.assert_not_called()

  def test_enabled_launch_rejects_limits_above_v1_caps(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})
    kwargs = _valid_launch_kwargs()
    kwargs["limits"] = {"tested_max_tokens": 257}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("limits.tested_max_tokens", result["message"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_enabled_launch_rejects_temperature_above_fixed_v1_cap(self):
    owner = _owner(cfg_model_testing={
      "ENABLED": True,
      "LIMITS": {"TEMPERATURE": 1},
    })
    kwargs = _valid_launch_kwargs()
    kwargs["limits"] = {"temperature": 0.1}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("limits.temperature", result["message"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_enabled_launch_rejects_non_finite_temperature(self):
    owner = _owner(cfg_model_testing={"ENABLED": True})
    kwargs = _valid_launch_kwargs()
    kwargs["limits"] = {"temperature": "nan"}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("limits.temperature", result["message"])
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()

  def test_raw_evidence_opt_in_rejected_while_policy_disabled(self):
    owner = _owner(cfg_model_testing={"ENABLED": True, "RAW_EVIDENCE_ENABLED": False})
    kwargs = _valid_launch_kwargs()
    kwargs["raw_evidence"] = {"enabled": True, "reason": "debug"}

    result = launch_model_test(owner, **kwargs)

    self.assertEqual(result["error"], "validation_error")
    self.assertEqual(result["error_class"], "raw_evidence_disabled")
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()


class TestModelTestingRawEvidenceGuards(unittest.TestCase):

  def test_get_report_denies_raw_model_test_evidence_artifact(self):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.r1fs.get_json.return_value = {
      "kind": "redmesh_model_test_raw_evidence",
      "job_id": "job-1",
      "cases": [],
    }

    result = PentesterApi01Plugin.get_report(plugin, "raw-cid")

    self.assertEqual(result["error"], "forbidden")
    self.assertNotIn("cases", str(result))


class TestModelTestNodeSelection(unittest.TestCase):

  def test_manual_one_peer_selects_that_execution_node(self):
    owner = _owner(cfg_chainstore_peers=["node-a", "node-b"])

    selection, err = select_model_test_execution_node(
      owner,
      selected_peers=[" node-b "],
      resource_scores_getter=lambda _owner, _candidates: {"node-a": 100},
    )

    self.assertIsNone(err)
    self.assertEqual(selection["selection_mode"], "manual")
    self.assertEqual(selection["selection_reason"], "manual_single_peer")
    self.assertEqual(selection["selected_execution_node"], "node-b")
    self.assertEqual(selection["candidate_peer_ids"], ["node-b"])
    self.assertFalse(selection["telemetry_used"])
    self.assertFalse(selection["random_fallback"])

  def test_auto_all_chooses_highest_resource_chainstore_peer(self):
    owner = _owner(cfg_chainstore_peers=["node-a", "node-b", "node-c"])

    selection, err = select_model_test_execution_node(
      owner,
      selected_peers=[],
      resource_scores_getter=lambda _owner, _candidates: {
        "node-a": 10,
        "node-b": 50,
        "node-c": 20,
      },
    )

    self.assertIsNone(err)
    self.assertEqual(selection["selection_mode"], "auto_all")
    self.assertEqual(selection["selection_reason"], "highest_resource_score")
    self.assertEqual(selection["selected_execution_node"], "node-b")
    self.assertEqual(selection["candidate_count"], 3)
    self.assertEqual(selection["telemetry_available_count"], 3)
    self.assertTrue(selection["telemetry_used"])
    self.assertFalse(selection["random_fallback"])

  def test_auto_subset_uses_selected_candidate_pool(self):
    owner = _owner(cfg_chainstore_peers=["node-a", "node-b", "node-c"])

    selection, err = select_model_test_execution_node(
      owner,
      selected_peers=["node-a", "node-c", "node-a"],
      resource_scores_getter=lambda _owner, _candidates: {
        "node-b": 100,
        "node-c": 25,
        "node-a": 20,
      },
    )

    self.assertIsNone(err)
    self.assertEqual(selection["selection_mode"], "auto_subset")
    self.assertEqual(selection["requested_peer_ids"], ["node-a", "node-c"])
    self.assertEqual(selection["candidate_peer_ids"], ["node-a", "node-c"])
    self.assertEqual(selection["selected_execution_node"], "node-c")

  def test_resource_ties_use_stable_lexical_peer_id_order(self):
    owner = _owner(cfg_chainstore_peers=["node-b", "node-a"])

    selection, err = select_model_test_execution_node(
      owner,
      selected_peers=[],
      resource_scores_getter=lambda _owner, _candidates: {
        "node-b": 10,
        "node-a": 10,
      },
    )

    self.assertIsNone(err)
    self.assertEqual(selection["selected_execution_node"], "node-a")

  def test_random_fallback_when_resource_telemetry_unavailable(self):
    owner = _owner(cfg_chainstore_peers=["node-a", "node-b", "node-c"])

    selection, err = select_model_test_execution_node(
      owner,
      selected_peers=[],
      resource_scores_getter=lambda _owner, _candidates: {},
      random_source=lambda candidates: candidates[-1],
    )

    self.assertIsNone(err)
    self.assertEqual(selection["selection_mode"], "auto_all")
    self.assertEqual(selection["selection_reason"], "random_no_usable_telemetry")
    self.assertEqual(selection["selected_execution_node"], "node-c")
    self.assertFalse(selection["telemetry_used"])
    self.assertEqual(selection["telemetry_available_count"], 0)
    self.assertTrue(selection["random_fallback"])

  def test_invalid_selected_peer_rejected_before_selection(self):
    owner = _owner(cfg_chainstore_peers=["node-a"])

    selection, err = select_model_test_execution_node(owner, selected_peers=["node-x"])

    self.assertIsNone(selection)
    self.assertEqual(err["error"], "validation_error")
    self.assertIn("Invalid peer addresses", err["message"])

  def test_falsey_non_list_selected_peers_rejected(self):
    owner = _owner(cfg_chainstore_peers=["node-a"])

    selection, err = select_model_test_execution_node(owner, selected_peers="")

    self.assertIsNone(selection)
    self.assertEqual(err["error"], "validation_error")
    self.assertIn("selected_peers must be a list", err["message"])


class TestModelTestingPersistenceContracts(unittest.TestCase):

  def test_artifact_repository_preserves_model_test_config_without_scan_defaults(self):
    owner = _owner()
    owner.r1fs.add_json.return_value = "cid-config"
    config = {
      "schema_version": "model_test_job_config_v1",
      "job_type": "model_test",
      "task_name": "CBRN smoke",
      "task_description": "Run reviewed CBRN safety pack",
      "created_by_name": "tester",
      "created_by_id": "user-123",
      "test_set_id": "cbrn_safety_v1",
      "tested_model": {"provider_label": "Tested"},
      "evaluator_model": {"provider_label": "Evaluator"},
      "limits": {"max_cases": 12},
      "raw_evidence": {"requested": False},
      "selected_peers": ["node-a"],
      "model_test_node_selection": {
        "selected_execution_node": "node-a",
        "selection_mode": "manual",
      },
    }

    cid = ArtifactRepository(owner).put_job_config(config)

    self.assertEqual(cid, "cid-config")
    stored = owner.r1fs.add_json.call_args.args[0]
    self.assertEqual(stored["job_type"], "model_test")
    self.assertEqual(stored["scan_type"], "model_test")
    self.assertEqual(stored["model_test_node_selection"]["selected_execution_node"], "node-a")
    self.assertNotIn("target", stored)
    self.assertNotIn("start_port", stored)
    self.assertNotIn("end_port", stored)

  def test_cstore_models_preserve_model_test_fields(self):
    worker = CStoreWorker(
      start_port=0,
      end_port=0,
      worker_type="model_test",
      model_test_worker_status="queued",
    )
    running = CStoreJobRunning(
      job_id="job-1",
      job_status="RUNNING",
      job_pass=1,
      run_mode="SINGLEPASS",
      launcher="launcher-node",
      launcher_alias="Launcher",
      target="Tested",
      scan_type="model_test",
      target_url="",
      task_name="CBRN smoke",
      start_port=0,
      end_port=0,
      date_created=123.0,
      job_config_cid="cid-config",
      workers={"node-a": worker.to_dict()},
      timeline=[],
      pass_reports=[],
      job_type="model_test",
      model_test_summary={"overall_status": "queued"},
      model_test_node_selection={"selected_execution_node": "node-a"},
    )

    payload = running.to_dict()
    round_tripped = CStoreJobRunning.from_dict(payload).to_dict()

    self.assertEqual(round_tripped["job_type"], "model_test")
    self.assertEqual(round_tripped["model_test_summary"]["overall_status"], "queued")
    self.assertEqual(round_tripped["model_test_node_selection"]["selected_execution_node"], "node-a")
    self.assertEqual(round_tripped["workers"]["node-a"]["worker_type"], "model_test")
    self.assertEqual(round_tripped["workers"]["node-a"]["model_test_worker_status"], "queued")

  def test_finalized_cstore_model_preserves_model_test_fields(self):
    finalized = CStoreJobFinalized(
      job_id="job-1",
      job_status="FINALIZED",
      target="Tested",
      scan_type="model_test",
      target_url="",
      task_name="CBRN smoke",
      risk_score=0,
      run_mode="SINGLEPASS",
      duration=10,
      pass_count=0,
      launcher="launcher-node",
      launcher_alias="Launcher",
      worker_count=1,
      start_port=0,
      end_port=0,
      date_created=123.0,
      date_completed=133.0,
      job_cid="cid-archive",
      job_config_cid="cid-config",
      job_type="model_test",
      model_test_summary={"overall_status": "complete"},
      model_test_node_selection={"selected_execution_node": "node-a"},
    )

    payload = CStoreJobFinalized.from_dict(finalized.to_dict()).to_dict()

    self.assertEqual(payload["job_type"], "model_test")
    self.assertEqual(payload["model_test_summary"]["overall_status"], "complete")
    self.assertEqual(payload["model_test_node_selection"]["selected_execution_node"], "node-a")

  def test_scan_poller_ignores_model_test_jobs(self):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.time.return_value = 10
    plugin._PentesterApi01Plugin__last_checked_jobs = 0
    plugin.cfg_check_jobs_each = 1
    plugin.cfg_instance_id = "instance"
    plugin.ee_addr = "node-a"
    plugin.scan_jobs = {}
    plugin.completed_jobs_reports = {}
    plugin.chainstore_hgetall.return_value = {
      "job-1": {
        "job_id": "job-1",
        "job_type": "model_test",
        "scan_type": "model_test",
        "target": "Unit Provider / unit-model",
        "workers": {
          "node-a": {
            "worker_type": "model_test",
            "start_port": 0,
            "end_port": 0,
            "finished": False,
          },
        },
      },
    }
    plugin._normalize_job_record.side_effect = lambda key, specs, migrate=False: (key, specs)

    PentesterApi01Plugin._maybe_launch_jobs(plugin)

    self.assertEqual(plugin.scan_jobs, {})
    plugin._get_worker_entry.assert_not_called()
