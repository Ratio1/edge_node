import json
import sys
import struct
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.constants import JOB_ARCHIVE_VERSION, MAX_CONTINUOUS_PASSES
from extensions.business.cybersec.red_mesh.graybox.scenario_runtime import (
  build_graybox_worker_assignments,
  runtime_scenario_ids,
)
from extensions.business.cybersec.red_mesh.models import CStoreJobRunning

from .conftest import DummyOwner, MANUAL_RUN, PentestLocalWorker, color_print, mock_plugin_modules


class TestPhase1ConfigCID(unittest.TestCase):
  """Phase 1: Job Config CID — extract static config from CStore to R1FS."""

  def test_config_cid_roundtrip(self):
    """JobConfig.from_dict(config.to_dict()) preserves all fields."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    original = JobConfig(
      target="example.com",
      start_port=1,
      end_port=1024,
      exceptions=[22, 80],
      distribution_strategy="SLICE",
      port_order="SHUFFLE",
      nr_local_workers=4,
      enabled_features=["http_headers", "sql_injection"],
      excluded_features=["brute_force"],
      run_mode="SINGLEPASS",
      scan_min_delay=0.1,
      scan_max_delay=0.5,
      ics_safe_mode=True,
      redact_credentials=False,
      scanner_identity="test-scanner",
      scanner_user_agent="RedMesh/1.0",
      task_name="Test Scan",
      task_description="A test scan",
      monitor_interval=300,
      selected_peers=["peer1", "peer2"],
      created_by_name="tester",
      created_by_id="user-123",
      authorized=True,
    )
    d = original.to_dict()
    restored = JobConfig.from_dict(d)
    self.assertEqual(original, restored)

  def test_config_to_dict_has_required_fields(self):
    """to_dict() includes target, start_port, end_port, run_mode."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    config = JobConfig(
      target="10.0.0.1",
      start_port=1,
      end_port=65535,
      exceptions=[],
      distribution_strategy="SLICE",
      port_order="SEQUENTIAL",
      nr_local_workers=2,
      enabled_features=[],
      excluded_features=[],
      run_mode="CONTINUOUS_MONITORING",
    )
    d = config.to_dict()
    self.assertEqual(d["target"], "10.0.0.1")
    self.assertEqual(d["start_port"], 1)
    self.assertEqual(d["end_port"], 65535)
    self.assertEqual(d["run_mode"], "CONTINUOUS_MONITORING")

  def test_config_strip_none(self):
    """_strip_none removes None values from serialized config."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    config = JobConfig(
      target="example.com",
      start_port=1,
      end_port=100,
      exceptions=[],
      distribution_strategy="SLICE",
      port_order="SEQUENTIAL",
      nr_local_workers=2,
      enabled_features=[],
      excluded_features=[],
      run_mode="SINGLEPASS",
      selected_peers=None,
    )
    d = config.to_dict()
    self.assertNotIn("selected_peers", d)

  @classmethod
  def _mock_plugin_modules(cls):
    mock_plugin_modules()

  @classmethod
  def _build_mock_plugin(cls, job_id="test-job", time_val=1000000.0, r1fs_cid="QmFakeConfigCID"):
    """Build a mock plugin instance for launch_test testing."""
    plugin = MagicMock()
    plugin.ee_addr = "node-1"
    plugin.ee_id = "node-alias-1"
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_redmesh_secret_store_key = "unit-test-redmesh-secret-key"
    plugin.cfg_port_order = "SEQUENTIAL"
    plugin.cfg_excluded_features = []
    plugin.cfg_distribution_strategy = "SLICE"
    plugin.cfg_run_mode = "SINGLEPASS"
    plugin.cfg_monitor_interval = 60
    plugin.cfg_scanner_identity = ""
    plugin.cfg_scanner_user_agent = ""
    plugin.cfg_nr_local_workers = 2
    plugin.cfg_scan_target_allowlist = []
    plugin.cfg_network_concurrency_warning_threshold = 16
    plugin.cfg_graybox_budgets = {
      "AUTH_ATTEMPTS": 10,
      "ROUTE_DISCOVERY": 100,
      "STATEFUL_ACTIONS": 1,
    }
    plugin.cfg_llm_agent = {"ENABLED": False}
    plugin.cfg_ics_safe_mode = False
    plugin.cfg_scan_min_rnd_delay = 0
    plugin.cfg_scan_max_rnd_delay = 0
    plugin.uuid.return_value = job_id
    plugin.time.return_value = time_val
    plugin.json_dumps.return_value = "{}"
    plugin.r1fs = MagicMock()
    plugin.r1fs.add_json.return_value = r1fs_cid
    plugin.chainstore_hset = MagicMock()
    plugin.chainstore_hgetall.return_value = {}
    plugin.chainstore_peers = ["node-1"]
    plugin.cfg_chainstore_peers = ["node-1"]
    plugin._redact_job_config = staticmethod(lambda d: d)
    plugin._validate_feature_catalog = MagicMock()
    return plugin

  @classmethod
  def _bind_launch_helpers(cls, plugin):
    """Bind real launch helper methods onto a MagicMock plugin host."""
    cls._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin._coerce_scan_type = lambda scan_type=None: PentesterApi01Plugin._coerce_scan_type(plugin, scan_type)
    plugin._validation_error = lambda message: PentesterApi01Plugin._validation_error(plugin, message)
    plugin._parse_exceptions = lambda exceptions: PentesterApi01Plugin._parse_exceptions(plugin, exceptions)
    plugin._get_supported_features = lambda scan_type=None, categs=False: PentesterApi01Plugin._get_supported_features(
      plugin, scan_type=scan_type, categs=categs
    )
    plugin._get_all_features = lambda categs=False, scan_type=None: PentesterApi01Plugin._get_all_features(
      plugin, categs=categs, scan_type=scan_type
    )
    plugin._get_feature_catalog = lambda scan_type=None: PentesterApi01Plugin._get_feature_catalog(plugin, scan_type)
    plugin._resolve_enabled_features = lambda excluded, scan_type="network": (
      PentesterApi01Plugin._resolve_enabled_features(plugin, excluded, scan_type=scan_type)
    )
    plugin._resolve_active_peers = lambda selected: PentesterApi01Plugin._resolve_active_peers(plugin, selected)
    plugin._normalize_common_launch_options = lambda **kwargs: PentesterApi01Plugin._normalize_common_launch_options(
      plugin, **kwargs
    )
    plugin._build_network_workers = lambda active_peers, start_port, end_port, distribution_strategy: (
      PentesterApi01Plugin._build_network_workers(plugin, active_peers, start_port, end_port, distribution_strategy)
    )
    plugin._build_webapp_workers = lambda active_peers, target_port: (
      PentesterApi01Plugin._build_webapp_workers(plugin, active_peers, target_port)
    )
    plugin._announce_launch = lambda **kwargs: PentesterApi01Plugin._announce_launch(plugin, **kwargs)
    plugin.launch_network_scan = lambda **kwargs: PentesterApi01Plugin.launch_network_scan(plugin, **kwargs)
    plugin.launch_webapp_scan = lambda **kwargs: PentesterApi01Plugin.launch_webapp_scan(plugin, **kwargs)
    return plugin

  @classmethod
  def _extract_job_specs(cls, plugin, job_id):
    """Extract the job_specs dict from chainstore_hset calls."""
    for call in plugin.chainstore_hset.call_args_list:
      kwargs = call[1] if call[1] else {}
      if kwargs.get("key") == job_id:
        return kwargs["value"]
    return None

  @classmethod
  def _latest_job_config(cls, plugin):
    """Return the last R1FS JSON payload that looks like a JobConfig."""
    for call in reversed(plugin.r1fs.add_json.call_args_list):
      payload = call[0][0]
      if isinstance(payload, dict) and "target" in payload and "start_port" in payload:
        return payload
    return None

  def _launch(self, plugin, **kwargs):
    """Call launch_test with mocked base modules."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    self._bind_launch_helpers(plugin)
    defaults = dict(target="example.com", start_port=1, end_port=1024, exceptions="", authorized=True)
    defaults.update(kwargs)
    return PentesterApi01Plugin.launch_test(plugin, **defaults)

  def _launch_network(self, plugin, **kwargs):
    """Call launch_network_scan with mocked base modules."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    self._bind_launch_helpers(plugin)
    defaults = dict(target="example.com", start_port=1, end_port=1024, exceptions="", authorized=True)
    defaults.update(kwargs)
    return PentesterApi01Plugin.launch_network_scan(plugin, **defaults)

  def _launch_webapp(self, plugin, **kwargs):
    """Call launch_webapp_scan with mocked base modules."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    self._bind_launch_helpers(plugin)
    defaults = dict(
      target_url="https://example.com/app",
      official_username="admin",
      official_password="secret",
      authorized=True,
    )
    defaults.update(kwargs)
    return PentesterApi01Plugin.launch_webapp_scan(plugin, **defaults)

  def test_launch_builds_job_config_and_stores_cid(self):
    """launch_test() builds JobConfig, saves to R1FS, stores job_config_cid in CStore."""
    plugin = self._build_mock_plugin(job_id="test-job-1", r1fs_cid="QmFakeConfigCID123")
    self._launch(plugin)

    # Verify r1fs.add_json was called with a JobConfig dict
    self.assertTrue(plugin.r1fs.add_json.called)
    config_dict = plugin.r1fs.add_json.call_args_list[0][0][0]
    self.assertEqual(config_dict["target"], "example.com")
    self.assertEqual(config_dict["start_port"], 1)
    self.assertEqual(config_dict["end_port"], 1024)
    self.assertIn("run_mode", config_dict)

    # Verify CStore has job_config_cid
    job_specs = self._extract_job_specs(plugin, "test-job-1")
    self.assertIsNotNone(job_specs, "Expected chainstore_hset call for job_specs")
    self.assertEqual(job_specs["job_config_cid"], "QmFakeConfigCID123")

  def test_cstore_has_no_static_config(self):
    """After launch, CStore object has no exceptions, distribution_strategy, etc."""
    plugin = self._build_mock_plugin(job_id="test-job-2")
    self._launch(plugin)

    job_specs = self._extract_job_specs(plugin, "test-job-2")
    self.assertIsNotNone(job_specs)

    # These static config fields must NOT be in CStore
    removed_fields = [
      "exceptions", "distribution_strategy", "enabled_features",
      "excluded_features", "scan_min_delay", "scan_max_delay",
      "ics_safe_mode", "redact_credentials", "scanner_identity",
      "scanner_user_agent", "nr_local_workers", "task_description",
      "monitor_interval", "selected_peers", "created_by_name",
      "created_by_id", "authorized", "port_order",
    ]
    for field in removed_fields:
      self.assertNotIn(field, job_specs, f"CStore should not contain '{field}'")

  def test_cstore_has_listing_fields(self):
    """CStore has target, task_name, start_port, end_port, date_created."""
    plugin = self._build_mock_plugin(job_id="test-job-3", time_val=1700000000.0)
    self._launch(plugin, start_port=80, end_port=443, task_name="Web Scan")

    job_specs = self._extract_job_specs(plugin, "test-job-3")
    self.assertIsNotNone(job_specs)

    self.assertEqual(job_specs["target"], "example.com")
    self.assertEqual(job_specs["task_name"], "Web Scan")
    self.assertEqual(job_specs["start_port"], 80)
    self.assertEqual(job_specs["end_port"], 443)
    self.assertEqual(job_specs["date_created"], 1700000000.0)
    self.assertEqual(job_specs["risk_score"], 0)

  def test_pass_reports_initialized_empty(self):
    """CStore has pass_reports: [] (no pass_history)."""
    plugin = self._build_mock_plugin(job_id="test-job-4")
    self._launch(plugin, start_port=1, end_port=100)

    job_specs = self._extract_job_specs(plugin, "test-job-4")
    self.assertIsNotNone(job_specs)

    self.assertIn("pass_reports", job_specs)
    self.assertEqual(job_specs["pass_reports"], [])
    self.assertNotIn("pass_history", job_specs)

  def test_launch_fails_if_r1fs_unavailable(self):
    """If R1FS fails to store config, launch aborts with error."""
    plugin = self._build_mock_plugin(job_id="test-job-5", r1fs_cid=None)
    result = self._launch(plugin, start_port=1, end_port=100)

    self.assertIn("error", result)
    # CStore should NOT have been written with the job
    job_specs = self._extract_job_specs(plugin, "test-job-5")
    self.assertIsNone(job_specs)

  def test_launch_webapp_scan_uses_mirrored_worker_assignments(self):
    """Webapp launches assign the same resolved target port to every selected peer."""
    plugin = self._build_mock_plugin(job_id="test-job-webapp")
    plugin.chainstore_peers = ["node-1", "node-2"]
    plugin.cfg_chainstore_peers = ["node-1", "node-2"]

    result = self._launch_webapp(plugin, selected_peers=["node-1", "node-2"])
    self.assertNotIn("error", result)

    job_specs = self._extract_job_specs(plugin, "test-job-webapp")
    workers = job_specs["workers"]
    self.assertEqual(workers["node-1"]["start_port"], 443)
    self.assertEqual(workers["node-1"]["end_port"], 443)
    self.assertEqual(workers["node-2"]["start_port"], 443)
    self.assertEqual(workers["node-2"]["end_port"], 443)
    self.assertEqual(
      workers["node-1"]["assigned_scenario_ids"],
      list(runtime_scenario_ids()),
    )
    self.assertEqual(
      workers["node-2"]["assigned_scenario_ids"],
      list(runtime_scenario_ids()),
    )
    self.assertEqual(workers["node-1"]["budget_scope"], "per_worker")
    self.assertTrue(workers["node-1"]["assignment_hash"])

  def test_launch_webapp_scan_can_slice_api_scenarios_between_workers(self):
    plugin = self._build_mock_plugin(job_id="test-job-webapp-slice")
    plugin.chainstore_peers = ["node-1", "node-2", "node-3"]
    plugin.cfg_chainstore_peers = ["node-1", "node-2", "node-3"]

    result = self._launch_webapp(
      plugin,
      selected_peers=["node-1", "node-2", "node-3"],
      graybox_assignment_strategy="SLICE",
      request_budget=30,
    )
    self.assertNotIn("error", result)

    job_specs = self._extract_job_specs(plugin, "test-job-webapp-slice")
    workers = job_specs["workers"]
    assigned_sets = [
      set(workers[node]["assigned_scenario_ids"])
      for node in ("node-1", "node-2", "node-3")
    ]
    self.assertEqual(set().union(*assigned_sets), set(runtime_scenario_ids()))
    self.assertFalse(assigned_sets[0] & assigned_sets[1])
    self.assertFalse(assigned_sets[0] & assigned_sets[2])
    self.assertFalse(assigned_sets[1] & assigned_sets[2])
    self.assertEqual(
      sum(workers[node]["assigned_request_budget"] for node in workers),
      30,
    )
    self.assertEqual({workers[node]["budget_scope"] for node in workers}, {"per_scan"})

  def test_launch_webapp_scan_rejects_mirror_stateful_multi_worker(self):
    plugin = self._build_mock_plugin(job_id="test-job-webapp-stateful")
    plugin.chainstore_peers = ["node-1", "node-2"]
    plugin.cfg_chainstore_peers = ["node-1", "node-2"]

    result = self._launch_webapp(
      plugin,
      selected_peers=["node-1", "node-2"],
      allow_stateful_probes=True,
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("MIRROR with stateful", result["message"])

  def test_launch_webapp_scan_neutralizes_network_only_fields(self):
    """Webapp config does not persist bogus network defaults like exceptions='64297'."""
    plugin = self._build_mock_plugin(job_id="test-job-webcfg")
    self._launch_webapp(plugin)

    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(config_dict["scan_type"], "webapp")
    self.assertEqual(config_dict["exceptions"], [])
    self.assertEqual(config_dict["distribution_strategy"], "MIRROR")
    self.assertEqual(config_dict["nr_local_workers"], 1)
    self.assertEqual(config_dict["target_url"], "https://example.com/app")

  def test_launch_webapp_scan_persists_secret_ref_not_inline_passwords(self):
    """Webapp launch stores a separate secret blob and persists only secret_ref in JobConfig."""
    plugin = self._build_mock_plugin(job_id="test-job-websecret")
    plugin.r1fs.add_json.side_effect = ["QmSecretCID", "QmConfigCID"]

    result = self._launch_webapp(
      plugin,
      official_username="admin",
      official_password="secret",
      regular_username="user",
      regular_password="pass",
      weak_candidates=["admin:admin"],
    )

    self.assertNotIn("error", result)
    self.assertEqual(len(plugin.r1fs.add_json.call_args_list), 2)

    secret_doc = plugin.r1fs.add_json.call_args_list[0][0][0]
    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    secret_kwargs = plugin.r1fs.add_json.call_args_list[0][1]

    self.assertEqual(secret_doc["kind"], "redmesh_graybox_credentials")
    self.assertEqual(secret_doc["storage_mode"], "encrypted_r1fs_json_v1")
    self.assertEqual(secret_doc["payload"]["official_password"], "secret")
    self.assertEqual(secret_doc["payload"]["regular_password"], "pass")
    self.assertEqual(secret_doc["payload"]["weak_candidates"], ["admin:admin"])
    self.assertEqual(secret_kwargs["secret"], "unit-test-redmesh-secret-key")

    self.assertEqual(config_dict["secret_ref"], "QmSecretCID")
    self.assertEqual(config_dict["official_username"], "")
    self.assertEqual(config_dict["official_password"], "")
    self.assertEqual(config_dict["regular_username"], "")
    self.assertEqual(config_dict["regular_password"], "")
    self.assertNotIn("weak_candidates", config_dict)
    self.assertTrue(config_dict["has_regular_credentials"])
    self.assertTrue(config_dict["has_weak_candidates"])

    job_specs = self._extract_job_specs(plugin, "test-job-websecret")
    self.assertEqual(job_specs["job_config_cid"], "QmConfigCID")

  def test_launch_webapp_scan_persists_bearer_token_only_in_secret_payload(self):
    """API-native bearer auth uses the same R1FS secret lane as form passwords."""
    plugin = self._build_mock_plugin(job_id="test-job-bearer-secret")
    plugin.r1fs.add_json.side_effect = ["QmSecretCID", "QmConfigCID"]

    result = self._launch_webapp(
      plugin,
      official_username="",
      official_password="",
      bearer_token="BEARER-TOKEN-MUST-NOT-PERSIST",
      target_config={
        "api_security": {
          "auth": {
            "auth_type": "bearer",
            "authenticated_probe_path": "/api/me/",
          },
        },
      },
    )

    self.assertNotIn("error", result)
    secret_doc = plugin.r1fs.add_json.call_args_list[0][0][0]
    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]

    self.assertEqual(
      secret_doc["payload"]["bearer_token"],
      "BEARER-TOKEN-MUST-NOT-PERSIST",
    )
    self.assertEqual(config_dict["secret_ref"], "QmSecretCID")
    self.assertTrue(config_dict["has_bearer_token"])
    self.assertEqual(config_dict["bearer_token"], "")
    self.assertNotIn(
      "BEARER-TOKEN-MUST-NOT-PERSIST",
      json.dumps(config_dict),
    )

  def test_launch_webapp_scan_rejects_nested_target_config_secret(self):
    """Nested request bodies cannot carry raw secrets into persisted JobConfig."""
    plugin = self._build_mock_plugin(job_id="test-job-target-secret")

    result = self._launch_webapp(
      plugin,
      target_config={
        "api_security": {
          "token_endpoints": {
            "token_request_body": {
              "client_id": "redmesh",
              "client_secret": "plain-secret",
            },
          },
        },
      },
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("target_config", result["message"])
    self.assertEqual(plugin.r1fs.add_json.call_count, 0)

  def test_launch_webapp_scan_rejects_unknown_target_config_key(self):
    """Unknown nested target_config keys fail closed instead of disappearing."""
    plugin = self._build_mock_plugin(job_id="test-job-target-unknown")

    result = self._launch_webapp(
      plugin,
      target_config={
        "api_security": {
          "object_endpoints": [
            {"path": "/api/records/{id}/", "typo": True},
          ],
        },
      },
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("unknown field", result["message"])
    self.assertEqual(plugin.r1fs.add_json.call_count, 0)

  def test_launch_webapp_scan_persists_target_config_secret_ref_value_only_in_secret_payload(self):
    """Typed target_config secret refs resolve through the R1FS secret payload."""
    plugin = self._build_mock_plugin(job_id="test-job-target-secret-ref")
    plugin.r1fs.add_json.side_effect = ["QmSecretCID", "QmConfigCID"]

    result = self._launch_webapp(
      plugin,
      target_config={
        "api_security": {
          "token_endpoints": {
            "token_request_body": {
              "client_id": "redmesh",
              "client_secret": {"secret_ref": "oauth_client_secret"},
            },
          },
        },
      },
      target_config_secrets={"oauth_client_secret": "OAUTH-CLIENT-SECRET"},
    )

    self.assertNotIn("error", result)
    secret_doc = plugin.r1fs.add_json.call_args_list[0][0][0]
    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(
      secret_doc["payload"]["target_config_secrets"],
      {"oauth_client_secret": "OAUTH-CLIENT-SECRET"},
    )
    self.assertNotIn("OAUTH-CLIENT-SECRET", json.dumps(config_dict))
    self.assertEqual(
      config_dict["target_config"]["api_security"]["token_endpoints"][
        "token_request_body"
      ]["client_secret"],
      {"secret_ref": "oauth_client_secret"},
    )

  def test_launch_webapp_scan_rejects_missing_target_config_secret_ref_value(self):
    plugin = self._build_mock_plugin(job_id="test-job-target-secret-ref-missing")

    result = self._launch_webapp(
      plugin,
      target_config={
        "api_security": {
          "token_endpoints": {
            "token_request_body": {
              "client_secret": {"secret_ref": "oauth_client_secret"},
            },
          },
        },
      },
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("missing", result["message"])
    self.assertEqual(plugin.r1fs.add_json.call_count, 0)

  def test_launch_webapp_scan_rejects_unknown_target_config_secret_value(self):
    plugin = self._build_mock_plugin(job_id="test-job-target-secret-ref-extra")

    result = self._launch_webapp(
      plugin,
      target_config={"api_security": {"token_endpoints": {}}},
      target_config_secrets={"unused": "secret"},
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("unknown secret_ref", result["message"])
    self.assertEqual(plugin.r1fs.add_json.call_count, 0)

  def test_launch_webapp_scan_rejects_secret_ref_outside_approved_body(self):
    plugin = self._build_mock_plugin(job_id="test-job-target-secret-ref-bad-place")

    result = self._launch_webapp(
      plugin,
      target_config={
        "api_security": {
          "auth": {
            "api_key_header_name": {"secret_ref": "header_name"},
          },
        },
      },
      target_config_secrets={"header_name": "X-Secret"},
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("outside an approved request body", result["message"])
    self.assertEqual(plugin.r1fs.add_json.call_count, 0)

  def test_launch_webapp_scan_rejects_secret_persistence_without_store_key(self):
    """Webapp launch fails closed when no strong secret-store key is configured."""
    plugin = self._build_mock_plugin(job_id="test-job-websecret-nokey")
    plugin.cfg_redmesh_secret_store_key = ""
    plugin.cfg_comms_host_key = ""
    plugin.cfg_attestation = {"ENABLED": True, "PRIVATE_KEY": "", "MIN_SECONDS_BETWEEN_SUBMITS": 86400, "RETRIES": 2}

    with patch.dict("os.environ", {}, clear=True):
      result = self._launch_webapp(
        plugin,
        official_username="admin",
        official_password="secret",
      )

    self.assertEqual(result["error"], "Failed to store job config in R1FS")
    self.assertEqual(len(plugin.r1fs.add_json.call_args_list), 0)

  def test_launch_webapp_scan_rejects_implicit_secret_store_fallback_key(self):
    """Communication/attestation keys are not reused unless unsafe dev fallback is explicit."""
    plugin = self._build_mock_plugin(job_id="test-job-websecret-fallback-key")
    plugin.cfg_redmesh_secret_store_key = ""
    plugin.cfg_comms_host_key = "unsafe-comms-host-key"
    plugin.cfg_allow_unsafe_secret_store_fallback = False
    plugin.cfg_attestation = {
      "ENABLED": True,
      "PRIVATE_KEY": "unsafe-attestation-key",
      "MIN_SECONDS_BETWEEN_SUBMITS": 86400,
      "RETRIES": 2,
    }

    with patch.dict("os.environ", {}, clear=True):
      result = self._launch_webapp(
        plugin,
        official_username="admin",
        official_password="secret",
      )

    self.assertEqual(result["error"], "Failed to store job config in R1FS")
    self.assertEqual(len(plugin.r1fs.add_json.call_args_list), 0)

  def test_launch_webapp_scan_records_unsafe_secret_store_fallback_metadata(self):
    """Explicit unsafe fallback is visible in persisted non-secret metadata."""
    plugin = self._build_mock_plugin(job_id="test-job-websecret-dev-fallback")
    plugin.cfg_redmesh_secret_store_key = ""
    plugin.cfg_comms_host_key = "unsafe-comms-host-key"
    plugin.cfg_allow_unsafe_secret_store_fallback = True
    plugin.r1fs.add_json.side_effect = ["QmSecretCID", "QmConfigCID"]

    with patch.dict("os.environ", {}, clear=True):
      result = self._launch_webapp(
        plugin,
        official_username="admin",
        official_password="secret",
      )

    self.assertNotIn("error", result)
    secret_doc = plugin.r1fs.add_json.call_args_list[0][0][0]
    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertTrue(secret_doc["unsafe_key_fallback"])
    self.assertEqual(secret_doc["key_id"], "unsafe-dev:cfg_comms_host_key")
    self.assertTrue(config_dict["secret_store_unsafe_fallback"])
    self.assertEqual(config_dict["secret_store_key_id"], "unsafe-dev:cfg_comms_host_key")

  def test_launch_webapp_scan_rejects_missing_target_url(self):
    """Webapp endpoint returns structured validation error for missing URL."""
    plugin = self._build_mock_plugin(job_id="test-job-weberr")
    result = self._launch_webapp(plugin, target_url="")
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("target_url", result["message"])

  def test_launch_webapp_scan_rejects_invalid_url_scheme(self):
    """Webapp endpoint rejects malformed or non-http(s) targets."""
    plugin = self._build_mock_plugin(job_id="test-job-webbadurl")
    result = self._launch_webapp(plugin, target_url="ftp://example.com/app")
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("http/https", result["message"])

  def test_launch_network_scan_requires_authorization_with_structured_error(self):
    """Network endpoint returns validation_error when authorization is missing."""
    plugin = self._build_mock_plugin(job_id="test-job-noauth")
    result = self._launch_network(plugin, authorized=False)
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("authorization", result["message"].lower())

  def test_launch_network_scan_rejects_target_confirmation_mismatch(self):
    """Target confirmation must echo the resolved target host."""
    plugin = self._build_mock_plugin(job_id="test-job-confirm")
    result = self._launch_network(plugin, target="example.com", target_confirmation="other.example.com", authorized=True)
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("target_confirmation", result["message"])

  def test_launch_webapp_scan_enforces_target_allowlist(self):
    """Webapp targets outside the allowlist are rejected before launch."""
    plugin = self._build_mock_plugin(job_id="test-job-allowlist")
    result = self._launch_webapp(
      plugin,
      target_url="https://example.com/app",
      target_allowlist=["internal.example.org"],
    )
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("allowlist", result["message"])

  def test_launch_webapp_scan_rejects_out_of_scope_api_paths(self):
    """Path-scoped authorization applies to configured API probe paths."""
    plugin = self._build_mock_plugin(job_id="test-job-path-scope")

    result = self._launch_webapp(
      plugin,
      target_allowlist=["example.com", "/api/public/"],
      target_config={
        "login_path": "/api/public/login/",
        "logout_path": "/api/public/logout/",
        "api_security": {
          "function_endpoints": [
            {"path": "/admin/export-users/"},
          ],
        },
      },
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("outside authorized scope", result["message"])
    self.assertEqual(plugin.r1fs.add_json.call_count, 0)

  def test_launch_webapp_scan_accepts_in_scope_templated_api_paths(self):
    """Templated API paths are normalized and allowed inside the scope prefix."""
    plugin = self._build_mock_plugin(job_id="test-job-path-scope-ok")

    result = self._launch_webapp(
      plugin,
      target_allowlist=["example.com", "/api/public/"],
      target_config={
        "login_path": "/api/public/login/",
        "logout_path": "/api/public/logout/",
        "api_security": {
          "object_endpoints": [
            {"path": "/api/public/users/{id}/"},
          ],
        },
      },
    )

    self.assertNotIn("error", result)

  def test_launch_webapp_scan_persists_authorization_context(self):
    """Authorization metadata is stored in immutable job config and audit context."""
    plugin = self._build_mock_plugin(job_id="test-job-authctx")
    plugin._log_audit_event = MagicMock()

    self._launch_webapp(
      plugin,
      target_confirmation="example.com",
      scope_id="scope-123",
      authorization_ref="TICKET-42",
      engagement_metadata={"ticket": "TICKET-42", "owner": "alice"},
      target_allowlist=["example.com", "/api/"],
      target_config={
        "login_path": "/api/login/",
        "logout_path": "/api/logout/",
        "discovery": {"scope_prefix": "/api/"},
      },
    )

    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(config_dict["target_confirmation"], "example.com")
    self.assertEqual(config_dict["scope_id"], "scope-123")
    self.assertEqual(config_dict["authorization_ref"], "TICKET-42")
    self.assertEqual(config_dict["engagement_metadata"]["owner"], "alice")
    self.assertEqual(config_dict["target_allowlist"], ["example.com", "/api/"])
    audit_payload = plugin._log_audit_event.call_args[0][1]
    self.assertEqual(audit_payload["scope_id"], "scope-123")
    self.assertEqual(audit_payload["authorization_ref"], "TICKET-42")

  def test_launch_webapp_scan_preserves_api_security_payload(self):
    """OWASP API Top 10 target_config.api_security passes through to JobConfig."""
    plugin = self._build_mock_plugin(job_id="test-job-api-security")

    api_security_payload = {
      "object_endpoints": [
        {"path": "/api/records/{id}/", "test_ids": [1, 2],
         "owner_field": "owner", "tenant_field": "tenant_id"},
      ],
      "function_endpoints": [
        {"path": "/api/admin/users/{uid}/promote/",
         "method": "POST", "privilege": "admin",
         "revert_path": "/api/admin/users/{uid}/demote/"},
      ],
      "token_endpoints": {
        "token_path": "/api/token/",
        "protected_path": "/api/me/",
        "logout_path": "/api/auth/logout/",
      },
      "inventory_paths": {
        "current_version": "/api/v2/",
        "canonical_probe_path": "/api/v2/records/1/",
        "deprecated_paths": ["/api/v1/legacy/"],
      },
    }

    self._launch_webapp(
      plugin,
      target_config={
        "discovery": {"scope_prefix": "/api/"},
        "api_security": api_security_payload,
      },
    )

    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    api_security = config_dict["target_config"]["api_security"]
    # Object endpoints preserved
    self.assertEqual(len(api_security["object_endpoints"]), 1)
    self.assertEqual(
      api_security["object_endpoints"][0]["tenant_field"], "tenant_id"
    )
    # Function endpoints + revert path preserved
    self.assertEqual(
      api_security["function_endpoints"][0]["revert_path"],
      "/api/admin/users/{uid}/demote/",
    )
    # Token endpoints preserved
    self.assertEqual(
      api_security["token_endpoints"]["logout_path"], "/api/auth/logout/"
    )
    # Inventory paths preserved
    self.assertEqual(
      api_security["inventory_paths"]["canonical_probe_path"],
      "/api/v2/records/1/",
    )
    self.assertEqual(
      api_security["inventory_paths"]["deprecated_paths"],
      ["/api/v1/legacy/"],
    )

  def test_launch_webapp_scan_applies_safety_policy_caps(self):
    """Graybox launch policy caps weak-auth and discovery budgets and records warnings."""
    plugin = self._build_mock_plugin(job_id="test-job-policy")
    plugin.cfg_graybox_budgets = {
      "AUTH_ATTEMPTS": 3,
      "ROUTE_DISCOVERY": 20,
      "STATEFUL_ACTIONS": 0,
    }

    self._launch_webapp(
      plugin,
      max_weak_attempts=9,
      allow_stateful_probes=True,
      verify_tls=False,
      target_config={"discovery": {"scope_prefix": "/api/", "max_pages": 50}},
    )

    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(config_dict["max_weak_attempts"], 3)
    self.assertEqual(config_dict["target_config"]["discovery"]["max_pages"], 20)
    self.assertFalse(config_dict["allow_stateful_probes"])
    warnings = config_dict["safety_policy"]["warnings"]
    self.assertTrue(any("capped" in warning for warning in warnings))
    self.assertTrue(any("TLS verification is disabled" in warning for warning in warnings))

  def test_launch_webapp_scan_rejects_invalid_numeric_safety_values(self):
    plugin = self._build_mock_plugin(job_id="test-job-bad-request-budget")
    result = self._launch_webapp(plugin, request_budget="abc")
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("request_budget", result["message"])

    plugin = self._build_mock_plugin(job_id="test-job-bad-weak-attempts")
    result = self._launch_webapp(plugin, max_weak_attempts=0)
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("max_weak_attempts", result["message"])

  def test_launch_webapp_scan_rejects_invalid_target_config_numeric_values(self):
    plugin = self._build_mock_plugin(job_id="test-job-bad-max-requests")
    result = self._launch_webapp(
      plugin,
      target_config={"api_security": {"max_total_requests": "abc"}},
    )
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("api_security.max_total_requests", result["message"])

    plugin = self._build_mock_plugin(job_id="test-job-bad-discovery")
    result = self._launch_webapp(
      plugin,
      target_config={"discovery": {"scope_prefix": "/api/", "max_pages": -1}},
    )
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("discovery.max_pages", result["message"])

    plugin = self._build_mock_plugin(job_id="test-job-bad-payload-size")
    result = self._launch_webapp(
      plugin,
      target_config={
        "api_security": {
          "resource_endpoints": [
            {
              "path": "/api/records/",
              "allow_oversized_payload_probe": True,
              "oversized_payload_bytes": 262_145,
            },
          ],
        },
      },
    )
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("oversized_payload_bytes", result["message"])

  def test_launch_webapp_scan_normalizes_numeric_strings(self):
    plugin = self._build_mock_plugin(job_id="test-job-numeric-strings")
    self._launch_webapp(
      plugin,
      request_budget="42",
      max_weak_attempts="5",
      target_config={
        "discovery": {"scope_prefix": "/api/", "max_pages": "12", "max_depth": "2"},
        "api_security": {
          "object_endpoints": [
            {"path": "/api/records/{id}/", "test_ids": ["1", "2"]},
          ],
        },
      },
    )

    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(config_dict["max_weak_attempts"], 5)
    self.assertEqual(config_dict["target_config"]["discovery"]["max_pages"], 12)
    self.assertEqual(config_dict["target_config"]["discovery"]["max_depth"], 2)
    self.assertEqual(
      config_dict["target_config"]["api_security"]["max_total_requests"],
      42,
    )
    self.assertEqual(
      config_dict["target_config"]["api_security"]["object_endpoints"][0]["test_ids"],
      [1, 2],
    )

  def test_launch_test_rejects_invalid_scan_type(self):
    """Compatibility endpoint rejects unknown scan types with a structured error."""
    plugin = self._build_mock_plugin(job_id="test-job-badtype")
    result = self._launch(plugin, scan_type="invalid-scan-type")
    self.assertEqual(result["error"], "validation_error")
    self.assertIn("Invalid scan_type", result["message"])

  def test_launch_test_routes_to_scan_type_specific_endpoint(self):
    """Compatibility launch_test routes to network/webapp launch methods."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.launch_network_scan = MagicMock(return_value={"route": "network"})
    plugin.launch_webapp_scan = MagicMock(return_value={"route": "webapp"})

    network = PentesterApi01Plugin.launch_test(plugin, target="example.com", authorized=True, scan_type="network")
    webapp = PentesterApi01Plugin.launch_test(
      plugin,
      target="example.com",
      target_url="https://example.com/app",
      official_username="admin",
      official_password="secret",
      bearer_token="TOKEN-123",
      api_key="KEY-123",
      bearer_refresh_token="REFRESH-123",
      request_budget=42,
      authorized=True,
      scan_type="webapp",
    )

    self.assertEqual(network["route"], "network")
    self.assertEqual(webapp["route"], "webapp")
    plugin.launch_network_scan.assert_called_once()
    plugin.launch_webapp_scan.assert_called_once()
    webapp_kwargs = plugin.launch_webapp_scan.call_args.kwargs
    self.assertEqual(webapp_kwargs["bearer_token"], "TOKEN-123")
    self.assertEqual(webapp_kwargs["api_key"], "KEY-123")
    self.assertEqual(webapp_kwargs["bearer_refresh_token"], "REFRESH-123")
    self.assertEqual(webapp_kwargs["request_budget"], 42)

  def test_launch_test_persists_typed_ptes_context(self):
    """Compatibility launch_test preserves typed engagement/RoE/auth fields."""
    plugin = self._build_mock_plugin(job_id="test-job-ptes-context")

    result = self._launch(
      plugin,
      engagement={
        "client_name": "ACME",
        "data_classification": "PII",
        "asset_exposure": "external",
      },
      roe={
        "strength_of_test": "light",
        "dos_allowed": False,
        "post_exploit_rules": "va_only",
      },
      authorization={
        "document_cid": "QmAuthCID",
        "authorized_signer_name": "Alice",
      },
    )

    self.assertNotIn("error", result)
    config_dict = self._latest_job_config(plugin)
    self.assertEqual(config_dict["engagement"]["client_name"], "ACME")
    self.assertEqual(config_dict["engagement"]["data_classification"], "PII")
    self.assertEqual(config_dict["roe"]["strength_of_test"], "light")
    self.assertEqual(config_dict["authorization"]["document_cid"], "QmAuthCID")
    self.assertEqual(config_dict["authorization"]["authorized_signer_name"], "Alice")

  def test_launch_rejects_invalid_typed_ptes_context(self):
    """Typed PTES payloads are validated before JobConfig persistence."""
    plugin = self._build_mock_plugin(job_id="test-job-ptes-invalid")

    result = self._launch(
      plugin,
      engagement={"client_name": "ACME", "data_classification": "SECRET"},
    )

    self.assertEqual(result["error"], "validation_error")
    self.assertIn("engagement is invalid", result["message"])
    self.assertFalse(plugin.r1fs.add_json.called)

  def test_launch_webapp_scan_persists_graybox_enabled_features_only(self):
    """Webapp launches resolve enabled features from the graybox capability set only."""
    plugin = self._build_mock_plugin(job_id="test-job-webfeatures")
    self._launch_webapp(plugin, excluded_features=["_graybox_injection"])

    config_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(config_dict["excluded_features"], ["_graybox_injection"])
    self.assertIn("_graybox_access_control", config_dict["enabled_features"])
    self.assertIn("_graybox_weak_auth", config_dict["enabled_features"])
    self.assertNotIn("_graybox_injection", config_dict["enabled_features"])
    self.assertFalse(any(method.startswith("_service_info_") for method in config_dict["enabled_features"]))
    self.assertFalse(any(method.startswith("_web_test_") for method in config_dict["enabled_features"]))


class TestPhase4FeatureCatalog(unittest.TestCase):
  """Phase 4: feature catalog and scan-type capability modeling."""

  @classmethod
  def _mock_plugin_modules(cls):
    mock_plugin_modules()

  def _build_plugin(self):
    plugin = MagicMock()
    plugin.json_dumps = staticmethod(json.dumps)
    plugin.P = MagicMock()
    return TestPhase1ConfigCID._bind_launch_helpers(plugin)

  def test_get_all_features_filters_by_scan_type(self):
    """Capability discovery is scan-type-aware."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = self._build_plugin()
    network = PentesterApi01Plugin._get_all_features(plugin, scan_type="network")
    webapp = PentesterApi01Plugin._get_all_features(plugin, scan_type="webapp")
    merged = PentesterApi01Plugin._get_all_features(plugin)

    self.assertIn("_service_info_http", network)
    self.assertIn("_post_scan_correlate", network)
    self.assertNotIn("_graybox_access_control", network)
    self.assertIn("_graybox_access_control", webapp)
    self.assertNotIn("_service_info_http", webapp)
    self.assertIn("_graybox_access_control", merged)
    self.assertIn("_service_info_http", merged)

  def test_get_feature_catalog_filters_graybox_category(self):
    """Catalog filtering returns only graybox entries for webapp scans."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = self._build_plugin()
    response = PentesterApi01Plugin.get_feature_catalog(plugin, scan_type="webapp")

    self.assertEqual([item["category"] for item in response["catalog"]], ["graybox"])
    self.assertIn("_graybox_access_control", response["all_methods"])
    self.assertNotIn("_service_info_http", response["all_methods"])

  def test_validate_feature_catalog_rejects_missing_worker_methods(self):
    """Startup validation fails loudly when catalog methods are not executable."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = self._build_plugin()
    bad_catalog = [
      {
        "id": "graybox",
        "label": "Graybox",
        "description": "Broken",
        "category": "graybox",
        "methods": ["_graybox_missing_method"],
      }
    ]

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.FEATURE_CATALOG",
      bad_catalog,
    ):
      with self.assertRaises(RuntimeError):
        PentesterApi01Plugin._validate_feature_catalog(plugin)

  def test_network_features_come_from_explicit_registry(self):
    """Network feature discovery stays tied to the explicit registry order."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker
    from extensions.business.cybersec.red_mesh.constants import NETWORK_FEATURE_METHODS, NETWORK_FEATURE_REGISTRY

    self.assertEqual(PentestLocalWorker.get_supported_features(), list(NETWORK_FEATURE_METHODS))
    self.assertEqual(PentestLocalWorker.get_supported_features(categs=True), {
      category: list(methods)
      for category, methods in NETWORK_FEATURE_REGISTRY.items()
    })



class TestPhase2PassFinalization(unittest.TestCase):
  """Phase 2: Single Aggregation + Consolidated Pass Reports."""

  @classmethod
  def _mock_plugin_modules(cls):
    """Install mock modules so pentester_api_01 can be imported without naeural_core."""
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_finalize_plugin(self, job_id="test-job", job_pass=1, run_mode="SINGLEPASS",
                              llm_enabled=False, r1fs_returns=None):
    """Build a mock plugin pre-configured for _maybe_finalize_pass testing."""
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_llm_agent = {
      "ENABLED": llm_enabled,
      "TIMEOUT": 30,
      "AUTO_ANALYSIS_TYPE": "security_assessment",
    }
    plugin.cfg_llm_agent_api_host = "localhost"
    plugin.cfg_llm_agent_api_port = 8080
    plugin.cfg_monitor_interval = 60
    plugin.cfg_monitor_jitter = 0
    plugin.cfg_attestation = {"ENABLED": True, "PRIVATE_KEY": "", "MIN_SECONDS_BETWEEN_SUBMITS": 300, "RETRIES": 2}
    plugin.time.return_value = 1000100.0
    plugin.json_dumps.return_value = "{}"

    # R1FS mock
    plugin.r1fs = MagicMock()
    cid_counter = {"n": 0}
    def fake_add_json(data, show_logs=True):
      cid_counter["n"] += 1
      if r1fs_returns is not None:
        return r1fs_returns.get(cid_counter["n"], f"QmCID{cid_counter['n']}")
      return f"QmCID{cid_counter['n']}"
    plugin.r1fs.add_json.side_effect = fake_add_json

    # Job config in R1FS
    plugin.r1fs.get_json.return_value = {
      "target": "example.com", "start_port": 1, "end_port": 1024,
      "run_mode": run_mode, "enabled_features": [], "monitor_interval": 60,
    }

    # Build job_specs with two finished workers
    job_specs = {
      "job_id": job_id,
      "job_status": "RUNNING",
      "job_pass": job_pass,
      "run_mode": run_mode,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 0,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": True, "report_cid": "QmReportA"},
        "worker-B": {"start_port": 513, "end_port": 1024, "finished": True, "report_cid": "QmReportB"},
      },
      "timeline": [{"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher-alias", "actor_type": "system", "meta": {}}],
      "pass_reports": [],
    }

    plugin.chainstore_hgetall.return_value = {job_id: job_specs}
    plugin.chainstore_hset = MagicMock()

    Plugin = self._get_plugin_class()
    plugin._count_nested_findings = lambda section: Plugin._count_nested_findings(section)
    plugin._count_all_findings = lambda report: Plugin._count_all_findings(plugin, report)

    return plugin, job_specs

  def _sample_node_report(
    self,
    start_port=1,
    end_port=512,
    open_ports=None,
    findings=None,
    graybox_findings=None,
    web_findings=None,
    correlation_findings=None,
  ):
    """Build a sample node report dict."""
    report = {
      "start_port": start_port,
      "end_port": end_port,
      "open_ports": open_ports or [80, 443],
      "ports_scanned": end_port - start_port + 1,
      "nr_open_ports": len(open_ports or [80, 443]),
      "service_info": {},
      "web_tests_info": {},
      "completed_tests": ["port_scan"],
      "port_protocols": {"80": "http", "443": "https"},
      "port_banners": {},
      "correlation_findings": correlation_findings or [],
      "graybox_results": {},
    }
    if findings:
      # Add findings under service_info for port 80
      report["service_info"] = {
        "80": {
          "_service_info_http": {
            "findings": findings,
          }
        }
      }
    if web_findings:
      report["web_tests_info"] = {
        "80": {
          "_web_test_xss": {
            "findings": web_findings,
          }
        }
      }
    if graybox_findings:
      report["graybox_results"] = {
        "443": {
          "_graybox_test": {
            "findings": graybox_findings,
          }
        }
      }
    return report

  def test_single_aggregation(self):
    """_collect_node_reports called exactly once per pass finalization."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    # Mock _collect_node_reports and _get_aggregated_report
    report_a = self._sample_node_report(1, 512, [80])
    report_b = self._sample_node_report(513, 1024, [443])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a, "worker-B": report_b})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80, 443], "service_info": {}, "web_tests_info": {},
      "completed_tests": ["port_scan"], "ports_scanned": 1024,
      "nr_open_ports": 2, "port_protocols": {"80": "http", "443": "https"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "monitor_interval": 60})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 25, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # _collect_node_reports called exactly once
    plugin._collect_node_reports.assert_called_once()

  def test_pass_report_cid_in_r1fs(self):
    """PassReport stored in R1FS with correct fields."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {"findings_score": 5}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # r1fs.add_json called twice: once for aggregated data, once for PassReport
    self.assertEqual(plugin.r1fs.add_json.call_count, 2)

    # Second call is the PassReport
    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(pass_report_dict["pass_nr"], 1)
    self.assertIn("aggregated_report_cid", pass_report_dict)
    self.assertIn("worker_reports", pass_report_dict)
    self.assertEqual(pass_report_dict["risk_score"], 10)
    self.assertIn("risk_breakdown", pass_report_dict)
    self.assertIn("date_started", pass_report_dict)
    self.assertIn("date_completed", pass_report_dict)

  def test_pass_report_worker_meta_counts_graybox_findings(self):
    """WorkerReportMeta.nr_findings includes graybox findings."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    report_a = self._sample_node_report(
      1,
      512,
      [443],
      findings=[{"title": "svc"}],
      web_findings=[{"title": "web"}],
      graybox_findings=[
        {"scenario_id": "S1", "status": "vulnerable"},
        {"scenario_id": "S2", "status": "not_vulnerable"},
      ],
      correlation_findings=[{"title": "corr"}],
    )
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [443], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"443": "https"}, "graybox_results": report_a["graybox_results"],
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "scan_type": "webapp"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {"findings_score": 5}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(pass_report_dict["worker_reports"]["worker-A"]["nr_findings"], 5)

  def test_aggregated_report_separate_cid(self):
    """aggregated_report_cid is a separate R1FS write from the PassReport."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: "QmAggCID", 2: "QmPassCID"})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # First R1FS write = aggregated data, second = PassReport
    agg_dict = plugin.r1fs.add_json.call_args_list[0][0][0]
    pass_dict = plugin.r1fs.add_json.call_args_list[1][0][0]

    # The PassReport references the aggregated CID
    self.assertEqual(pass_dict["aggregated_report_cid"], "QmAggCID")

    # Aggregated data should have open_ports (from AggregatedScanData)
    self.assertIn("open_ports", agg_dict)

  def test_continuous_pass_returns_job_status_to_running(self):
    """Continuous monitoring jobs re-enter RUNNING after pass finalization."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(run_mode="CONTINUOUS_MONITORING")

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "monitor_interval": 60})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    self.assertEqual(job_specs["job_status"], "RUNNING")
    self.assertIsNotNone(job_specs.get("next_pass_at"))

  def test_continuous_pass_cap_stops_and_archives_job(self):
    """Continuous jobs stop and archive instead of scheduling pass 101."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(
      run_mode="CONTINUOUS_MONITORING",
      job_pass=MAX_CONTINUOUS_PASSES,
    )

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "monitor_interval": 60})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()
    plugin._build_job_archive = MagicMock()
    plugin._clear_live_progress = MagicMock()
    plugin._log_audit_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    self.assertEqual(job_specs["job_status"], "STOPPED")
    self.assertIsNone(job_specs.get("next_pass_at"))
    plugin._build_job_archive.assert_called_once_with(job_specs["job_id"], job_specs)
    plugin._clear_live_progress.assert_called_once()
    plugin._log_audit_event.assert_called_once_with("continuous_pass_cap_reached", {
      "job_id": job_specs["job_id"],
      "pass_nr": MAX_CONTINUOUS_PASSES,
      "max_continuous_passes": MAX_CONTINUOUS_PASSES,
    })
    event_types = [c.args[1] for c in plugin._emit_timeline_event.call_args_list]
    self.assertIn("pass_cap_reached", event_types)
    self.assertIn("stopped", event_types)

  def test_continuous_pass_cap_handles_recovered_over_cap_state(self):
    """Recovered continuous jobs already over cap are stopped cleanly."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(
      run_mode="CONTINUOUS_MONITORING",
      job_pass=MAX_CONTINUOUS_PASSES + 2,
    )

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "monitor_interval": 60})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()
    plugin._build_job_archive = MagicMock()
    plugin._clear_live_progress = MagicMock()
    plugin._log_audit_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    self.assertEqual(job_specs["job_status"], "STOPPED")
    plugin._build_job_archive.assert_called_once_with(job_specs["job_id"], job_specs)
    plugin._log_audit_event.assert_called_once()

  def test_finding_id_deterministic(self):
    """Same input produces same finding_id; different title produces different id."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_service_info_http": {
            "findings": [
              {"title": "SQL Injection", "severity": "HIGH", "cwe_id": "CWE-89", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    risk1, findings1 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    risk2, findings2 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)

    self.assertEqual(findings1[0]["finding_id"], findings2[0]["finding_id"])

    # Different title → different finding_id
    aggregated2 = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_service_info_http": {
            "findings": [
              {"title": "XSS Vulnerability", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }
    _, findings3 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated2)
    self.assertNotEqual(findings1[0]["finding_id"], findings3[0]["finding_id"])

  def test_finding_id_cwe_collision(self):
    """Same CWE, different title, same port+probe → different finding_ids."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_web_test_xss": {
            "findings": [
              {"title": "Reflected XSS in search", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "certain"},
              {"title": "Stored XSS in comment", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "certain"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 2)
    self.assertNotEqual(findings[0]["finding_id"], findings[1]["finding_id"])

  def test_finding_enrichment_fields(self):
    """Each finding has finding_id, port, protocol, probe, category."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [443], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"443": "https"},
      "service_info": {
        "443": {
          "_service_info_ssl": {
            "findings": [
              {"title": "Weak TLS", "severity": "MEDIUM", "cwe_id": "CWE-326", "confidence": "certain"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 1)
    f = findings[0]
    self.assertIn("finding_id", f)
    self.assertEqual(len(f["finding_id"]), 16)  # 16-char hex
    self.assertEqual(f["port"], 443)
    self.assertEqual(f["protocol"], "https")
    self.assertEqual(f["probe"], "_service_info_ssl")
    self.assertEqual(f["category"], "service")

  def test_port_protocols_none(self):
    """port_protocols is None → protocol defaults to 'unknown' (no crash)."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [22], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": None,
      "service_info": {
        "22": {
          "_service_info_ssh": {
            "findings": [
              {"title": "Weak SSH key", "severity": "LOW", "cwe_id": "CWE-320", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["protocol"], "unknown")

  def test_llm_success_no_llm_failed(self):
    """LLM succeeds → llm_failed absent from serialized PassReport."""
    from extensions.business.cybersec.red_mesh.models import PassReport

    pr = PassReport(
      pass_nr=1, date_started=1000.0, date_completed=1100.0, duration=100.0,
      aggregated_report_cid="QmAgg",
      worker_reports={},
      risk_score=50,
      llm_analysis="# Analysis\nAll good.",
      quick_summary="No critical issues found.",
      llm_failed=None,  # success
    )
    d = pr.to_dict()
    self.assertNotIn("llm_failed", d)
    self.assertEqual(d["llm_analysis"], "# Analysis\nAll good.")

  def test_llm_failure_flag_and_timeline(self):
    """Structured LLM validation failure → llm_failed: True, timeline event added."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(llm_enabled=True)

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    def _structured_failure(*_args, **_kwargs):
      plugin._last_structured_llm_failed = True
      return {"background_draft": "[AI generation failed validation]", "error": True}

    plugin._run_structured_report_sections = MagicMock(side_effect=_structured_failure)
    plugin._run_aggregated_llm_analysis = MagicMock(side_effect=AssertionError("legacy raw LLM path must not run"))
    plugin._run_quick_summary_analysis = MagicMock(side_effect=AssertionError("legacy quick summary path must not run"))

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # Check PassReport has llm_failed=True
    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertTrue(pass_report_dict.get("llm_failed"))
    self.assertTrue(pass_report_dict["llm_report_sections"]["error"])
    plugin._run_structured_report_sections.assert_called_once()

    # Check timeline event was emitted for llm_failed
    llm_failed_calls = [
      c for c in plugin._emit_timeline_event.call_args_list
      if c[0][1] == "llm_failed"
    ]
    self.assertEqual(len(llm_failed_calls), 1)
    # _emit_timeline_event(job_specs, "llm_failed", label, meta={"pass_nr": ...})
    call_kwargs = llm_failed_calls[0][1]  # keyword args
    meta = call_kwargs.get("meta", {})
    self.assertIn("pass_nr", meta)

  def test_finalization_uses_structured_llm_only(self):
    """PTES finalization must not call legacy raw aggregate/quick-summary LLM paths."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(llm_enabled=True)

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()
    def _structured_success(*_args, **_kwargs):
      plugin._last_structured_llm_failed = False
      return {
        "executive_headline": "Structured headline",
        "background_draft": "Structured summary",
        "overall_posture": "Structured posture",
        "recommendation_summary": ["Patch exposed services"],
        "conclusion": "Structured conclusion",
      }

    plugin._run_structured_report_sections = MagicMock(side_effect=_structured_success)
    plugin._run_aggregated_llm_analysis = MagicMock(side_effect=AssertionError("legacy raw LLM path must not run"))
    plugin._run_quick_summary_analysis = MagicMock(side_effect=AssertionError("legacy quick summary path must not run"))

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    plugin._run_quick_summary_analysis.assert_not_called()
    plugin._run_aggregated_llm_analysis.assert_not_called()
    plugin._run_structured_report_sections.assert_called_once()
    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(pass_report_dict["quick_summary"], "Structured headline")
    self.assertIn("## Overall Posture", pass_report_dict["llm_analysis"])
    self.assertIn("Structured posture", pass_report_dict["llm_analysis"])

  def test_pass_reports_survive_typed_job_record_rewrites(self):
    """Pass reports must stay attached after typed repository rewrites the job dict."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()
    job_specs["scan_type"] = "network"
    job_specs["target_url"] = ""
    plugin.chainstore_hget.return_value = job_specs

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "scan_type": "network"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()
    plugin._build_job_archive = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    self.assertEqual(len(job_specs["pass_reports"]), 1)
    self.assertEqual(job_specs["pass_reports"][0]["pass_nr"], 1)
    archived_job_specs = plugin._build_job_archive.call_args[0][1]
    self.assertEqual(len(archived_job_specs["pass_reports"]), 1)

  def test_aggregated_report_write_failure(self):
    """R1FS fails for aggregated → pass finalization skipped, no partial state."""
    PentesterApi01Plugin = self._get_plugin_class()
    # First R1FS write (aggregated) returns None = failure
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: None, 2: "QmPassCID"})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore should NOT have pass_reports appended
    self.assertEqual(len(job_specs["pass_reports"]), 0)
    # CStore hset was called for intermediate status updates (COLLECTING, ANALYZING, FINALIZING)
    # but NOT for finalization — verify job_status is NOT FINALIZED in the last write
    for call_args in plugin.chainstore_hset.call_args_list:
      value = call_args.kwargs.get("value") or call_args[1].get("value") if len(call_args) > 1 else None
      if isinstance(value, dict):
        self.assertNotEqual(value.get("job_status"), "FINALIZED")

  def test_pass_report_write_failure(self):
    """R1FS fails for pass report → CStore pass_reports not appended."""
    PentesterApi01Plugin = self._get_plugin_class()
    # First R1FS write (aggregated) succeeds, second (pass report) fails
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: "QmAggCID", 2: None})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore should NOT have pass_reports appended
    self.assertEqual(len(job_specs["pass_reports"]), 0)
    # CStore hset was called for status updates but NOT for finalization
    for call_args in plugin.chainstore_hset.call_args_list:
      value = call_args.kwargs.get("value") or call_args[1].get("value") if len(call_args) > 1 else None
      if isinstance(value, dict):
        self.assertNotEqual(value.get("job_status"), "FINALIZED")

  def test_cstore_risk_score_updated(self):
    """After pass, risk_score on CStore matches pass result."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 42, "breakdown": {"findings_score": 30}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore risk_score updated
    self.assertEqual(job_specs["risk_score"], 42)

    # PassReportRef in pass_reports has same risk_score
    self.assertEqual(len(job_specs["pass_reports"]), 1)
    ref = job_specs["pass_reports"][0]
    self.assertEqual(ref["risk_score"], 42)
    self.assertIn("report_cid", ref)
    self.assertEqual(ref["pass_nr"], 1)



class TestPhase4UiAggregate(unittest.TestCase):
  """Phase 4: UI Aggregate Computation."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _make_plugin(self):
    plugin = MagicMock()
    Plugin = self._get_plugin_class()
    plugin._count_services = lambda si: Plugin._count_services(plugin, si)
    plugin._dedupe_items = lambda items: Plugin._dedupe_items(items)
    plugin._extract_graybox_ui_stats = lambda aggregated, latest_pass=None: Plugin._extract_graybox_ui_stats(
      plugin, aggregated, latest_pass
    )
    plugin._compute_ui_aggregate = lambda passes, agg, job_config=None: Plugin._compute_ui_aggregate(
      plugin, passes, agg, job_config=job_config
    )
    plugin.SEVERITY_ORDER = Plugin.SEVERITY_ORDER
    plugin.CONFIDENCE_ORDER = Plugin.CONFIDENCE_ORDER
    return plugin, Plugin

  def _make_finding(self, severity="HIGH", confidence="firm", finding_id="abc123", title="Test"):
    return {"finding_id": finding_id, "severity": severity, "confidence": confidence, "title": title}

  def _make_pass(self, pass_nr=1, findings=None, risk_score=0, worker_reports=None):
    return {
      "pass_nr": pass_nr,
      "risk_score": risk_score,
      "risk_breakdown": {"findings_score": 10},
      "quick_summary": "Summary text",
      "findings": findings,
      "worker_reports": worker_reports or {
        "w1": {"start_port": 1, "end_port": 512, "open_ports": [80]},
      },
    }

  def _make_aggregated(self, open_ports=None, service_info=None):
    return {
      "open_ports": open_ports or [80, 443],
      "service_info": service_info or {
        "80": {"_service_info_http": {"findings": []}},
        "443": {"_service_info_https": {"findings": []}},
      },
    }

  def _make_webapp_aggregated(self):
    return {
      "open_ports": [443],
      "service_info": {
        "443": {
          "_graybox_discovery": {
            "routes": ["/login", "/login", "/admin"],
            "forms": [
              {"action": "/login", "method": "POST"},
              {"action": "/login", "method": "POST"},
              {"action": "/admin", "method": "POST"},
            ],
            "findings": [],
          },
        },
      },
      "graybox_results": {
        "443": {
          "_graybox_authz": {
            "findings": [
              {"scenario_id": "S-1", "status": "vulnerable", "severity": "HIGH"},
              {"scenario_id": "S-2", "status": "not_vulnerable", "severity": "INFO"},
              {"scenario_id": "S-3", "status": "inconclusive", "severity": "INFO"},
            ],
          },
        },
      },
    }

  def test_findings_count_uppercase_keys(self):
    """findings_count keys are UPPERCASE."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="CRITICAL", finding_id="f1"),
      self._make_finding(severity="HIGH", finding_id="f2"),
      self._make_finding(severity="HIGH", finding_id="f3"),
      self._make_finding(severity="MEDIUM", finding_id="f4"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    fc = result.to_dict()["findings_count"]
    self.assertEqual(fc["CRITICAL"], 1)
    self.assertEqual(fc["HIGH"], 2)
    self.assertEqual(fc["MEDIUM"], 1)
    for key in fc:
      self.assertEqual(key, key.upper())

  def test_top_findings_max_10(self):
    """More than 10 CRITICAL+HIGH -> capped at 10."""
    plugin, _ = self._make_plugin()
    findings = [self._make_finding(severity="CRITICAL", finding_id=f"f{i}") for i in range(15)]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    self.assertEqual(len(result.to_dict()["top_findings"]), 10)

  def test_top_findings_sorted(self):
    """CRITICAL before HIGH, within same severity sorted by confidence."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="HIGH", confidence="certain", finding_id="f1", title="H-certain"),
      self._make_finding(severity="CRITICAL", confidence="tentative", finding_id="f2", title="C-tentative"),
      self._make_finding(severity="HIGH", confidence="tentative", finding_id="f3", title="H-tentative"),
      self._make_finding(severity="CRITICAL", confidence="certain", finding_id="f4", title="C-certain"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    top = result.to_dict()["top_findings"]
    self.assertEqual(top[0]["title"], "C-certain")
    self.assertEqual(top[1]["title"], "C-tentative")
    self.assertEqual(top[2]["title"], "H-certain")
    self.assertEqual(top[3]["title"], "H-tentative")

  def test_top_findings_excludes_medium(self):
    """MEDIUM/LOW/INFO findings never in top_findings."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="MEDIUM", finding_id="f1"),
      self._make_finding(severity="LOW", finding_id="f2"),
      self._make_finding(severity="INFO", finding_id="f3"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertNotIn("top_findings", d)  # stripped by _strip_none (None)

  def test_finding_timeline_single_pass(self):
    """1 pass -> finding_timeline is None (stripped)."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertNotIn("finding_timeline", d)  # None → stripped

  def test_finding_timeline_multi_pass(self):
    """3 passes with overlapping findings -> correct first_seen, last_seen, pass_count."""
    plugin, _ = self._make_plugin()
    f_persistent = self._make_finding(finding_id="persist1")
    f_transient = self._make_finding(finding_id="transient1")
    f_new = self._make_finding(finding_id="new1")
    passes = [
      self._make_pass(pass_nr=1, findings=[f_persistent, f_transient]),
      self._make_pass(pass_nr=2, findings=[f_persistent]),
      self._make_pass(pass_nr=3, findings=[f_persistent, f_new]),
    ]
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate(passes, agg)
    ft = result.to_dict()["finding_timeline"]
    self.assertEqual(ft["persist1"]["first_seen"], 1)
    self.assertEqual(ft["persist1"]["last_seen"], 3)
    self.assertEqual(ft["persist1"]["pass_count"], 3)
    self.assertEqual(ft["transient1"]["first_seen"], 1)
    self.assertEqual(ft["transient1"]["last_seen"], 1)
    self.assertEqual(ft["transient1"]["pass_count"], 1)
    self.assertEqual(ft["new1"]["first_seen"], 3)
    self.assertEqual(ft["new1"]["last_seen"], 3)
    self.assertEqual(ft["new1"]["pass_count"], 1)

  def test_zero_findings(self):
    """findings_count is {}, top_findings is [], total_findings is 0."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertEqual(d["total_findings"], 0)
    # findings_count and top_findings are None (stripped) when empty
    self.assertNotIn("findings_count", d)
    self.assertNotIn("top_findings", d)

  def test_open_ports_sorted_unique(self):
    """total_open_ports is deduped and sorted."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated(open_ports=[443, 80, 443, 22, 80])
    result = plugin._compute_ui_aggregate([p], agg)
    self.assertEqual(result.to_dict()["total_open_ports"], [22, 80, 443])

  def test_count_services(self):
    """_count_services counts ports with at least one detected service."""
    plugin, _ = self._make_plugin()
    service_info = {
      "80": {"_service_info_http": {}, "_web_test_xss": {}},
      "443": {"_service_info_https": {}, "_service_info_http": {}},
    }
    self.assertEqual(plugin._count_services(service_info), 2)
    self.assertEqual(plugin._count_services({}), 0)
    self.assertEqual(plugin._count_services(None), 0)

  def test_webapp_graybox_fields_populated(self):
    """Webapp aggregates include scan_type, discovery counts, and scenario stats."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(
      findings=[self._make_finding(severity="HIGH", finding_id="gb1")],
      worker_reports={"w1": {"start_port": 443, "end_port": 443, "open_ports": [443]}},
    )
    p["scan_metrics"] = {
      "scenarios_total": 3,
      "scenarios_vulnerable": 1,
    }
    agg = self._make_webapp_aggregated()

    result = plugin._compute_ui_aggregate([p], agg, job_config={"scan_type": "webapp"}).to_dict()
    self.assertEqual(result["scan_type"], "webapp")
    self.assertEqual(result["total_routes_discovered"], 2)
    self.assertEqual(result["total_forms_discovered"], 2)
    self.assertEqual(result["total_scenarios"], 3)
    self.assertEqual(result["total_scenarios_vulnerable"], 1)



class TestPhase3Archive(unittest.TestCase):
  """Phase 3: Job Close & Archive."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_archive_plugin(self, job_id="test-job", pass_count=1, run_mode="SINGLEPASS",
                              job_status="FINALIZED", r1fs_write_fail=False, r1fs_verify_fail=False):
    """Build a mock plugin pre-configured for _build_job_archive testing."""
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.time.return_value = 1000200.0
    plugin.json_dumps.return_value = "{}"

    # R1FS mock
    plugin.r1fs = MagicMock()

    # Build pass report dicts and refs
    pass_reports_data = []
    pass_report_refs = []
    for i in range(1, pass_count + 1):
      pr = {
        "pass_nr": i,
        "date_started": 1000000.0 + (i - 1) * 100,
        "date_completed": 1000000.0 + i * 100,
        "duration": 100.0,
        "aggregated_report_cid": f"QmAgg{i}",
        "worker_reports": {
          "worker-A": {"report_cid": f"QmWorker{i}A", "start_port": 1, "end_port": 512, "ports_scanned": 512, "open_ports": [80], "nr_findings": 2},
        },
        "risk_score": 25 + i,
        "risk_breakdown": {"findings_score": 10},
        "findings": [
          {"finding_id": f"f{i}a", "severity": "HIGH", "confidence": "firm", "title": f"Finding {i}A"},
          {"finding_id": f"f{i}b", "severity": "MEDIUM", "confidence": "firm", "title": f"Finding {i}B"},
        ],
        "scan_metrics": {
          "scenarios_total": 2,
          "scenarios_vulnerable": 1,
        },
        "quick_summary": f"Summary for pass {i}",
      }
      pass_reports_data.append(pr)
      pass_report_refs.append({"pass_nr": i, "report_cid": f"QmPassReport{i}", "risk_score": 25 + i})

    # Job config
    job_config = {
      "target": "example.com", "start_port": 1, "end_port": 1024,
      "run_mode": run_mode, "enabled_features": [], "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "redact_credentials": True,
      "official_username": "admin",
      "official_password": "super-secret",
      "regular_username": "user",
      "regular_password": "user-pass",
      "weak_candidates": ["admin:admin", "user:user"],
    }

    # Latest aggregated data
    latest_aggregated = {
      "open_ports": [80, 443],
      "service_info": {
        "80": {"_service_info_http": {}},
        "443": {
          "_graybox_discovery": {
            "routes": ["/login", "/admin", "/login"],
            "forms": [
              {"action": "/login", "method": "POST"},
              {"action": "/admin", "method": "POST"},
              {"action": "/admin", "method": "POST"},
            ],
          },
        },
      },
      "web_tests_info": {},
      "graybox_results": {
        "443": {
          "_graybox_test": {
            "findings": [
              {"scenario_id": "S1", "status": "vulnerable"},
              {"scenario_id": "S2", "status": "not_vulnerable"},
            ],
          },
        },
      },
      "completed_tests": ["port_scan"],
      "ports_scanned": 1024,
    }

    # R1FS get_json: return the right data for each CID
    cid_map = {"QmConfigCID": job_config}
    for i, pr in enumerate(pass_reports_data):
      cid_map[f"QmPassReport{i+1}"] = pr
      cid_map[f"QmAgg{i+1}"] = latest_aggregated

    if r1fs_write_fail:
      plugin.r1fs.add_json.return_value = None
    else:
      archive_cid = "QmArchiveCID"
      plugin.r1fs.add_json.return_value = archive_cid
      if r1fs_verify_fail:
        # add_json succeeds but get_json for the archive CID returns None
        orig_map = dict(cid_map)
        def verify_fail_get(cid):
          if cid == archive_cid:
            return None
          return orig_map.get(cid)
        plugin.r1fs.get_json.side_effect = verify_fail_get
      else:
        # Verification succeeds — archive CID also returns data
        cid_map[archive_cid] = {"job_id": job_id}  # minimal archive for verification
        plugin.r1fs.get_json.side_effect = lambda cid: cid_map.get(cid)

    if not r1fs_write_fail and not r1fs_verify_fail:
      plugin.r1fs.get_json.side_effect = lambda cid: cid_map.get(cid)

    # Job specs (running state)
    job_specs = {
      "job_id": job_id,
      "job_status": job_status,
      "job_pass": pass_count,
      "run_mode": run_mode,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 25 + pass_count,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": True, "report_cid": "QmReportA"},
      },
      "timeline": [
        {"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher-alias", "actor_type": "system", "meta": {}},
      ],
      "pass_reports": pass_report_refs,
    }

    plugin.chainstore_hset = MagicMock()

    # Bind real methods for archive building
    Plugin = self._get_plugin_class()
    plugin._compute_ui_aggregate = lambda passes, agg, job_config=None: Plugin._compute_ui_aggregate(
      plugin, passes, agg, job_config=job_config
    )
    plugin._count_services = lambda si: Plugin._count_services(plugin, si)
    plugin._dedupe_items = lambda items: Plugin._dedupe_items(items)
    plugin._extract_graybox_ui_stats = lambda aggregated, latest_pass=None: Plugin._extract_graybox_ui_stats(
      plugin, aggregated, latest_pass
    )
    plugin.SEVERITY_ORDER = Plugin.SEVERITY_ORDER
    plugin.CONFIDENCE_ORDER = Plugin.CONFIDENCE_ORDER
    plugin._redact_job_config = lambda d: Plugin._redact_job_config(d)

    return plugin, job_specs, pass_reports_data, job_config

  def test_archive_written_to_r1fs(self):
    """Archive stored in R1FS with job_id, job_config, passes, ui_aggregate."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, job_config = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # r1fs.add_json called with archive dict
    self.assertTrue(plugin.r1fs.add_json.called)
    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(archive_dict["archive_version"], JOB_ARCHIVE_VERSION)
    self.assertEqual(archive_dict["job_id"], "test-job")
    self.assertEqual(archive_dict["job_config"]["target"], "example.com")
    self.assertEqual(len(archive_dict["passes"]), 1)
    self.assertIn("ui_aggregate", archive_dict)
    self.assertIn("total_open_ports", archive_dict["ui_aggregate"])

  def test_archive_ui_aggregate_includes_graybox_summary(self):
    """Archive UI aggregate preserves graybox scan metadata and scenario counts."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    ui = archive_dict["ui_aggregate"]
    self.assertEqual(ui["scan_type"], "webapp")
    self.assertEqual(ui["total_routes_discovered"], 2)
    self.assertEqual(ui["total_forms_discovered"], 2)
    self.assertEqual(ui["total_scenarios"], 2)
    self.assertEqual(ui["total_scenarios_vulnerable"], 1)

  def test_archive_redacts_job_config_credentials(self):
    """Archived job_config masks credentials when redact_credentials is enabled."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(archive_dict["job_config"]["official_password"], "***")
    self.assertEqual(archive_dict["job_config"]["regular_password"], "***")
    self.assertEqual(archive_dict["job_config"]["weak_candidates"], ["***", "***"])
    self.assertEqual(archive_dict["job_config"]["official_username"], "admin")

  def test_archive_redaction_removes_secret_ref(self):
    """Archived job_config does not expose secret_ref references."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()
    plugin.r1fs.get_json.side_effect = [
      {
        "target": "example.com",
        "start_port": 443,
        "end_port": 443,
        "run_mode": "SINGLEPASS",
        "scan_type": "webapp",
        "target_url": "https://example.com/app",
        "redact_credentials": True,
        "secret_ref": "QmSecretCID",
        "official_username": "",
      },
      {
        "pass_nr": 1,
        "date_started": 1,
        "date_completed": 2,
        "duration": 1,
        "aggregated_report_cid": "QmAgg",
        "worker_reports": {},
        "risk_score": 0,
      },
      {"open_ports": [], "service_info": {}, "web_tests_info": {}},
      {"job_id": "test-job"},
    ]

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertNotIn("secret_ref", archive_dict["job_config"])

  def test_archive_duration_computed(self):
    """duration == date_completed - date_created, not 0."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    # date_created=1000000, time()=1000200 → duration=200
    self.assertEqual(archive_dict["duration"], 200.0)
    self.assertGreater(archive_dict["duration"], 0)

  def test_stub_has_job_cid_and_config_cid(self):
    """After prune, CStore stub has job_cid and job_config_cid."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # Extract the stub written to CStore
    hset_call = plugin.chainstore_hset.call_args
    stub = hset_call[1]["value"]
    self.assertEqual(stub["job_cid"], "QmArchiveCID")
    self.assertEqual(stub["job_config_cid"], "QmConfigCID")
    self.assertEqual(stub["scan_type"], "webapp")
    self.assertEqual(stub["target_url"], "https://example.com/app")

  def test_archive_clears_live_progress_before_prune(self):
    """Archive commit clears :live rows before the CStore stub is written."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()
    events = []

    def clear_live(job_id, worker_addresses):
      events.append(("clear_live", job_id, tuple(worker_addresses)))

    def record_hset(*args, **kwargs):
      if kwargs.get("hkey") == "test-instance" and kwargs.get("key") == "test-job":
        events.append(("archive_prune", kwargs["value"].get("job_cid")))

    plugin._clear_live_progress = MagicMock(side_effect=clear_live)
    plugin.chainstore_hset.side_effect = record_hset

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    self.assertGreaterEqual(len(events), 2)
    self.assertEqual(events[0], ("clear_live", "test-job", ("worker-A",)))
    self.assertEqual(events[1], ("archive_prune", "QmArchiveCID"))

  def test_stub_fields_match_model(self):
    """Stub has exactly CStoreJobFinalized fields."""
    from extensions.business.cybersec.red_mesh.models import CStoreJobFinalized
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    stub = plugin.chainstore_hset.call_args[1]["value"]
    # Verify it can be loaded into CStoreJobFinalized
    finalized = CStoreJobFinalized.from_dict(stub)
    self.assertEqual(finalized.job_id, "test-job")
    self.assertEqual(finalized.job_status, "FINALIZED")
    self.assertEqual(finalized.target, "example.com")
    self.assertEqual(finalized.scan_type, "webapp")
    self.assertEqual(finalized.target_url, "https://example.com/app")
    self.assertEqual(finalized.pass_count, 1)
    self.assertEqual(finalized.worker_count, 1)
    self.assertEqual(finalized.start_port, 1)
    self.assertEqual(finalized.end_port, 1024)
    self.assertGreater(finalized.duration, 0)

  def test_pass_report_cids_cleaned_up(self):
    """After archive, individual pass CIDs deleted from R1FS."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # Check delete_file was called for pass report CID
    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertIn("QmPassReport1", delete_calls)

  def test_node_report_cids_preserved(self):
    """Worker report CIDs NOT deleted."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertNotIn("QmWorker1A", delete_calls)

  def test_aggregated_report_cids_preserved(self):
    """aggregated_report_cid per pass NOT deleted."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertNotIn("QmAgg1", delete_calls)

  def test_archive_write_failure_no_prune(self):
    """R1FS write fails -> CStore untouched, full running state retained."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(r1fs_write_fail=True)

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # CStore should NOT have been pruned
    plugin.chainstore_hset.assert_not_called()
    # pass_reports still present in job_specs
    self.assertEqual(len(job_specs["pass_reports"]), 1)

  def test_archive_verify_failure_no_prune(self):
    """CID not retrievable -> CStore untouched."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(r1fs_verify_fail=True)

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    plugin.chainstore_hset.assert_not_called()

  def test_archive_verify_retries_before_prune(self):
    """Archive verification retries transient read-after-write failures before pruning CStore."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()
    plugin.cfg_archive_verify_retries = 3
    verify_attempts = {"count": 0}
    orig_get = plugin.r1fs.get_json.side_effect

    def flaky_get(cid):
      if cid == "QmArchiveCID":
        verify_attempts["count"] += 1
        if verify_attempts["count"] < 3:
          return None
        return {"job_id": "test-job"}
      return orig_get(cid)

    plugin.r1fs.get_json.side_effect = flaky_get

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    self.assertEqual(verify_attempts["count"], 3)
    plugin.chainstore_hset.assert_called_once()

  def test_stuck_recovery(self):
    """FINALIZED without job_cid -> _build_job_archive retried via _maybe_finalize_pass."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(job_status="FINALIZED")
    # Simulate stuck state: FINALIZED but no job_cid
    job_specs["job_status"] = "FINALIZED"
    # No job_cid in specs

    plugin.chainstore_hgetall.return_value = {"test-job": job_specs}
    plugin._normalize_job_record = MagicMock(return_value=("test-job", job_specs))
    plugin._build_job_archive = MagicMock()

    Plugin._maybe_finalize_pass(plugin)

    plugin._build_job_archive.assert_called_once_with("test-job", job_specs)

  def test_idempotent_rebuild(self):
    """Calling _build_job_archive twice doesn't corrupt state."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)
    first_stub = plugin.chainstore_hset.call_args[1]["value"]

    # Reset and call again (simulating a retry where data is still available)
    plugin.chainstore_hset.reset_mock()
    plugin.r1fs.add_json.reset_mock()
    new_archive_cid = "QmArchiveCID2"
    plugin.r1fs.add_json.return_value = new_archive_cid

    # Update get_json to also return data for the new archive CID
    orig_side_effect = plugin.r1fs.get_json.side_effect
    def extended_get(cid):
      if cid == new_archive_cid:
        return {"job_id": "test-job"}
      return orig_side_effect(cid)
    plugin.r1fs.get_json.side_effect = extended_get

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    second_stub = plugin.chainstore_hset.call_args[1]["value"]
    # Both produce valid stubs
    self.assertEqual(first_stub["job_id"], second_stub["job_id"])
    self.assertEqual(first_stub["pass_count"], second_stub["pass_count"])

  def test_multipass_archive(self):
    """Archive with 3 passes contains all pass data."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(pass_count=3, run_mode="CONTINUOUS_MONITORING", job_status="STOPPED")

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(len(archive_dict["passes"]), 3)
    self.assertEqual(archive_dict["passes"][0]["pass_nr"], 1)
    self.assertEqual(archive_dict["passes"][2]["pass_nr"], 3)
    stub = plugin.chainstore_hset.call_args[1]["value"]
    self.assertEqual(stub["pass_count"], 3)
    self.assertEqual(stub["job_status"], "STOPPED")



class TestPhase5Endpoints(unittest.TestCase):
  """Phase 5: API Endpoints."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_finalized_stub(self, job_id="test-job"):
    """Build a CStoreJobFinalized-shaped dict."""
    return {
      "job_id": job_id,
      "job_status": "FINALIZED",
      "target": "example.com",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "task_name": "Test",
      "risk_score": 42,
      "run_mode": "SINGLEPASS",
      "duration": 200.0,
      "pass_count": 1,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "worker_count": 2,
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "date_completed": 1000200.0,
      "job_cid": "QmArchiveCID",
      "job_config_cid": "QmConfigCID",
    }

  def _build_running_job(self, job_id="run-job", pass_count=8):
    """Build a running job dict with N pass_reports."""
    pass_reports = [
      {"pass_nr": i, "report_cid": f"QmPass{i}", "risk_score": 10 + i}
      for i in range(1, pass_count + 1)
    ]
    return {
      "job_id": job_id,
      "job_status": "RUNNING",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "job_pass": pass_count,
      "run_mode": "CONTINUOUS_MONITORING",
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Continuous Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 18,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": False},
        "worker-B": {"start_port": 513, "end_port": 1024, "finished": False},
      },
      "timeline": [
        {"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher", "actor_type": "system", "meta": {}},
        {"type": "started", "label": "Started", "date": 1000001.0, "actor": "launcher", "actor_type": "system", "meta": {}},
      ],
      "pass_reports": pass_reports,
    }

  def _build_plugin(self, jobs_dict):
    """Build a mock plugin with given jobs in CStore."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_redmesh_secret_store_key = "unit-test-redmesh-secret-key"
    plugin.r1fs = MagicMock()

    plugin.chainstore_hgetall.return_value = dict(jobs_dict)
    plugin.chainstore_hget.side_effect = lambda hkey, key: jobs_dict.get(key)
    plugin._normalize_job_record = MagicMock(
      side_effect=lambda k, v: (k, v) if isinstance(v, dict) and v.get("job_id") else (None, None)
    )

    # Bind real methods so endpoint logic executes properly
    plugin._get_all_network_jobs = lambda: Plugin._get_all_network_jobs(plugin)
    plugin._get_job_from_cstore = lambda job_id: Plugin._get_job_from_cstore(plugin, job_id)
    return plugin

  def test_get_job_archive_finalized(self):
    """get_job_archive for finalized job returns archive with matching job_id."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    archive_data = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "fin-job",
      "passes": [{"findings": [{"finding_id": "f-1", "title": "Issue"}]}],
      "ui_aggregate": {},
      "job_config": {},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }
    plugin.r1fs.get_json.return_value = archive_data
    plugin.chainstore_hgetall.side_effect = [
      {"fin-job": stub},
      {"fin-job:f-1": {"job_id": "fin-job", "finding_id": "f-1", "status": "accepted_risk", "note": "documented"}},
    ]

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["job_id"], "fin-job")
    self.assertEqual(result["archive"]["job_id"], "fin-job")
    self.assertEqual(result["archive"]["archive_version"], JOB_ARCHIVE_VERSION)
    self.assertEqual(result["archive"]["passes"][0]["findings"][0]["triage"]["status"], "accepted_risk")

  def test_get_job_archive_running(self):
    """get_job_archive for running job returns not_available error."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=2)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.get_job_archive(plugin, job_id="run-job")
    self.assertEqual(result["error"], "not_available")

  def test_manual_structured_analysis_backfills_legacy_fields(self):
    """Manual structured analysis updates the pass report for get_analysis compatibility."""
    Plugin = self._get_plugin_class()
    job_specs = self._build_running_job("job-llm", pass_count=1)
    for worker in job_specs["workers"].values():
      worker["finished"] = True
      worker["report_cid"] = "QmWorkerReport"

    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_llm_agent = {
      "ENABLED": True,
      "TIMEOUT": 30,
      "AUTO_ANALYSIS_TYPE": "security_assessment",
    }
    plugin.cfg_llm_agent_api_port = 8080
    plugin.r1fs = MagicMock()
    plugin.r1fs.get_json.return_value = {
      "pass_nr": 1,
      "aggregated_report_cid": "QmAgg1",
      "worker_reports": {"worker-A": {}},
    }
    plugin.r1fs.add_json.return_value = "QmUpdatedPass"
    plugin.chainstore_hget.side_effect = lambda hkey, key: job_specs if key == "job-llm" else None
    plugin.chainstore_hset = MagicMock()
    plugin.P = MagicMock()
    plugin._log_audit_event = MagicMock()
    plugin._emit_timeline_event = MagicMock()
    plugin._get_job_from_cstore = MagicMock(return_value=job_specs)
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": {"open_ports": [443]}})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [443],
      "service_info": {},
      "web_tests_info": {},
    })
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))

    def _structured_success(*_args, **_kwargs):
      plugin._last_structured_llm_failed = False
      return {
        "executive_headline": "Manual structured headline",
        "overall_posture": "Manual structured posture",
        "recommendation_summary": ["Review internet exposure"],
        "conclusion": "Manual structured conclusion",
      }

    plugin._run_structured_report_sections = MagicMock(side_effect=_structured_success)

    result = Plugin.analyze_job(plugin, job_id="job-llm")

    updated_pass = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(result["analysis_type"], "structured_report_sections")
    self.assertEqual(job_specs["pass_reports"][-1]["report_cid"], "QmUpdatedPass")
    self.assertEqual(updated_pass["quick_summary"], "Manual structured headline")
    self.assertIn("Manual structured posture", updated_pass["llm_analysis"])
    self.assertIn("Review internet exposure", updated_pass["llm_analysis"])

  def test_get_job_archive_integrity_mismatch(self):
    """Corrupted job_cid pointing to wrong archive is rejected."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    # Archive has a different job_id
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "other-job",
      "passes": [],
      "ui_aggregate": {},
      "job_config": {},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["error"], "integrity_mismatch")

  def test_get_job_archive_unsupported_version(self):
    """Unsupported archive versions are rejected explicitly."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION + 1,
      "job_id": "fin-job",
      "passes": [],
      "ui_aggregate": {},
      "job_config": {},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["error"], "unsupported_archive_version")

  def test_normalize_job_record_initializes_job_revision(self):
    """Legacy records get a normalized integer job_revision."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})
    plugin._write_job_record = MagicMock(side_effect=lambda job_id, specs, context="": specs)
    plugin._delete_job_record = MagicMock()

    normalized_key, normalized = Plugin._normalize_job_record(plugin, "job-1", {"job_id": "job-1", "workers": {}})

    self.assertEqual(normalized_key, "job-1")
    self.assertEqual(normalized["job_revision"], 0)

  def test_write_job_record_bumps_revision(self):
    """Centralized job writes bump the revision counter."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})
    plugin.chainstore_hget.side_effect = None
    plugin.chainstore_hget.return_value = {"job_id": "job-1", "job_revision": 2}
    plugin.chainstore_hset = MagicMock()
    plugin._log_audit_event = MagicMock()
    plugin.P = MagicMock()

    updated = Plugin._write_job_record(plugin, "job-1", {"job_id": "job-1", "job_revision": 2}, context="test")

    self.assertEqual(updated["job_revision"], 3)
    running = CStoreJobRunning.from_dict({
      "job_id": "job-1",
      "job_status": "RUNNING",
      "job_pass": 1,
      "run_mode": "SINGLEPASS",
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 10,
      "date_created": 1.0,
      "job_config_cid": "QmConfig",
      "workers": {},
      "timeline": [],
      "pass_reports": [],
      "job_revision": updated["job_revision"],
    })
    self.assertEqual(running.job_revision, 3)
    plugin._log_audit_event.assert_not_called()

  def test_job_write_guarantees_report_detection_only_mode(self):
    """RedMesh exposes detection-only semantics when chainstore lacks CAS."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})

    self.assertFalse(Plugin._supports_guarded_job_writes(plugin))
    self.assertEqual(Plugin._get_job_write_guarantees(plugin), {
      "mode": "detection_only",
      "guarded_writes": False,
      "stale_write_detection": True,
      "job_revision": True,
    })

  def test_write_job_record_logs_stale_write(self):
    """Revision mismatches are logged as stale-write detections."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})
    plugin.chainstore_hget.side_effect = None
    plugin.chainstore_hget.return_value = {"job_id": "job-1", "job_revision": 5}
    plugin.chainstore_hset = MagicMock()
    plugin._log_audit_event = MagicMock()
    plugin.P = MagicMock()

    updated = Plugin._write_job_record(plugin, "job-1", {"job_id": "job-1", "job_revision": 3}, context="close_job")

    self.assertEqual(updated["job_revision"], 6)
    plugin._log_audit_event.assert_called_once_with("stale_write_detected", {
      "job_id": "job-1",
      "expected_revision": 3,
      "current_revision": 5,
      "context": "close_job",
      "write_mode": "detection_only",
    })

  def test_get_job_config_resolves_secret_ref_for_runtime(self):
    """Runtime config loading resolves secret_ref into inline credentials."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})
    plugin.r1fs.get_json.side_effect = [
      {
        "scan_type": "webapp",
        "target_url": "https://example.com/app",
        "secret_ref": "QmSecretCID",
        "official_username": "",
        "official_password": "",
        "regular_username": "",
        "regular_password": "",
      },
      {
        "kind": "redmesh_graybox_credentials",
        "job_id": "test-job",
        "storage_mode": "encrypted_r1fs_json_v1",
        "payload": {
          "official_username": "admin",
          "official_password": "secret",
          "regular_username": "user",
          "regular_password": "pass",
          "weak_candidates": ["admin:admin"],
        },
      },
    ]

    config = Plugin._get_job_config(
      plugin, {"job_id": "test-job", "job_config_cid": "QmConfigCID"},
      resolve_secrets=True,
    )

    self.assertEqual(config["official_username"], "admin")
    self.assertEqual(config["official_password"], "secret")
    self.assertEqual(config["regular_password"], "pass")
    self.assertEqual(config["weak_candidates"], ["admin:admin"])
    self.assertNotIn("secret_ref", config)
    self.assertEqual(
      plugin.r1fs.get_json.call_args_list[1],
      unittest.mock.call("QmSecretCID", secret="unit-test-redmesh-secret-key"),
    )

  def test_get_job_config_fails_closed_for_secret_ref_without_key(self):
    """Secret refs are not resolved via plaintext fallback when no key exists."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})
    plugin.cfg_redmesh_secret_store_key = ""
    plugin.cfg_comms_host_key = ""
    plugin.cfg_attestation = {"ENABLED": True, "PRIVATE_KEY": "", "MIN_SECONDS_BETWEEN_SUBMITS": 86400, "RETRIES": 2}
    plugin.r1fs.get_json.side_effect = [
      {
        "scan_type": "webapp",
        "target_url": "https://example.com/app",
        "secret_ref": "QmSecretCID",
      },
      {
        "kind": "redmesh_graybox_credentials",
        "payload": {
          "official_username": "admin",
          "official_password": "secret",
        },
      },
    ]

    with self.assertRaises(ValueError):
      Plugin._get_job_config(
        plugin, {"job_id": "test-job", "job_config_cid": "QmConfigCID"},
        resolve_secrets=True,
      )
    self.assertEqual(len(plugin.r1fs.get_json.call_args_list), 1)

  def test_mark_worker_terminal_error_sets_common_fields(self):
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})
    job_specs = {
      "job_id": "job-terminal",
      "workers": {"worker-a": {"start_port": 443, "end_port": 443}},
    }

    with patch.object(Plugin, "_write_job_record", return_value=job_specs) as write:
      Plugin._mark_worker_terminal_error(
        plugin,
        job_specs,
        "worker-a",
        "secret_resolution_failed",
        "Failed to resolve graybox secret_ref",
        context="test_terminal",
      )

    worker = job_specs["workers"]["worker-a"]
    self.assertTrue(worker["finished"])
    self.assertEqual(worker["terminal_reason"], "secret_resolution_failed")
    self.assertIn("secret_ref", worker["error"])
    write.assert_called_once()

  def test_maybe_launch_jobs_secret_resolution_failure_marks_terminal(self):
    Plugin = self._get_plugin_class()
    assignments, error = build_graybox_worker_assignments(["launcher-node"])
    self.assertIsNone(error)
    worker_entry = {
      "start_port": 443,
      "end_port": 443,
      "finished": False,
      "result": None,
      **assignments["launcher-node"],
    }
    job_specs = {
      "job_id": "job-secret-fail",
      "job_status": "RUNNING",
      "job_pass": 1,
      "target": "example.com",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "launcher": "launcher-node",
      "launcher_alias": "launcher",
      "workers": {"launcher-node": worker_entry},
      "run_mode": "SINGLEPASS",
      "job_config_cid": "QmConfigCID",
    }
    plugin = self._build_plugin({"job-secret-fail": job_specs})
    plugin._PentesterApi01Plugin__last_checked_jobs = 0
    plugin.cfg_check_jobs_each = 0
    plugin.time.return_value = 100
    plugin.scan_jobs = {}
    plugin.completed_jobs_reports = {}
    plugin.lst_completed_jobs = []
    plugin._foreign_jobs_logged = set()
    plugin._normalize_job_record = lambda key, spec, migrate=False: (key, spec)
    plugin._get_worker_entry = lambda job_id, spec: Plugin._get_worker_entry(plugin, job_id, spec)
    plugin._get_active_execution_identity = lambda job_id: None
    plugin._build_execution_identity = lambda job_id, pass_nr, worker_addr, revision: (
      job_id, pass_nr, worker_addr, revision,
    )
    plugin._get_job_config = MagicMock(
      side_effect=ValueError("Failed to resolve graybox secret_ref")
    )

    with patch.object(Plugin, "_write_job_record", return_value=job_specs) as write:
      Plugin._maybe_launch_jobs(plugin)

    self.assertTrue(worker_entry["finished"])
    self.assertEqual(worker_entry["terminal_reason"], "secret_resolution_failed")
    self.assertIn("secret_ref", worker_entry["error"])
    write.assert_called_once()

  def test_get_job_data_running_last_5(self):
    """Running job with 8 passes returns last 5 refs only."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=8)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.get_job_data(plugin, job_id="run-job")
    self.assertTrue(result["found"])
    refs = result["job"]["pass_reports"]
    self.assertEqual(len(refs), 5)
    # Should be the last 5 (pass_nr 4-8)
    self.assertEqual(refs[0]["pass_nr"], 4)
    self.assertEqual(refs[-1]["pass_nr"], 8)

  def test_get_job_data_finalized_returns_stub(self):
    """Finalized job returns stub as-is with job_cid."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    result = Plugin.get_job_data(plugin, job_id="fin-job")
    self.assertTrue(result["found"])
    self.assertEqual(result["job"]["job_cid"], "QmArchiveCID")
    self.assertEqual(result["job"]["pass_count"], 1)

  def test_list_jobs_finalized_as_is(self):
    """Finalized stubs returned unmodified with all CStoreJobFinalized fields."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("fin-job", result)
    job = result["fin-job"]
    self.assertEqual(job["job_cid"], "QmArchiveCID")
    self.assertEqual(job["pass_count"], 1)
    self.assertEqual(job["worker_count"], 2)
    self.assertEqual(job["risk_score"], 42)
    self.assertEqual(job["duration"], 200.0)
    self.assertEqual(job["scan_type"], "webapp")
    self.assertEqual(job["target_url"], "https://example.com/app")

  def test_list_jobs_running_stripped(self):
    """Running jobs have counts but no timeline, workers, or pass_reports."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=3)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("run-job", result)
    job = result["run-job"]
    # Should have counts
    self.assertEqual(job["pass_count"], 3)
    self.assertEqual(job["worker_count"], 2)
    self.assertEqual(job["scan_type"], "webapp")
    self.assertEqual(job["target_url"], "https://example.com/app")
    # Should NOT have heavy fields
    self.assertNotIn("timeline", job)
    self.assertNotIn("workers", job)
    self.assertNotIn("pass_reports", job)

  def test_get_job_progress_returns_job_status(self):
    """get_job_progress surfaces job_status from CStore job specs."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=2)
    plugin = self._build_plugin({"run-job": running})
    plugin.chainstore_hgetall.return_value = {
      "run-job:worker-A": {
        "job_id": "run-job",
        "worker_addr": "worker-A",
        "pass_nr": running["job_pass"],
        "assignment_revision_seen": 1,
        "progress": 50,
        "phase": "service_probes",
        "ports_scanned": 50,
        "ports_total": 100,
        "open_ports_found": [],
        "completed_tests": [],
        "updated_at": 100.0,
        "started_at": 90.0,
        "first_seen_live_at": 90.0,
        "last_seen_at": 100.0,
      },
    }
    plugin.time.return_value = 100.0

    result = Plugin.get_job_progress(plugin, job_id="run-job")
    self.assertEqual(result["status"], "RUNNING")
    self.assertIn("worker-A", result["workers"])
    self.assertEqual(result["workers"]["worker-A"]["worker_state"], "active")

  def test_get_job_status_does_not_report_completed_when_distributed_job_is_incomplete(self):
    """Local completion must not hide an unfinished assigned peer."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})
    plugin.lst_completed_jobs = ["job-1"]
    plugin.completed_jobs_reports = {
      "job-1": {
        "local-1": {"target": "example.com", "ports_scanned": 10},
      },
    }
    plugin.scan_jobs = {}
    plugin._get_job_status = lambda job_id: Plugin._get_job_status(plugin, job_id)
    plugin.time.return_value = 100.0
    plugin.chainstore_hget.return_value = {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "job_pass": 1,
      "target": "example.com",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 10, "finished": True, "assignment_revision": 1},
        "worker-B": {"start_port": 11, "end_port": 20, "finished": False, "assignment_revision": 1},
      },
    }
    plugin.chainstore_hgetall.side_effect = lambda hkey: (
      {
        "job-1:worker-A": {
          "job_id": "job-1",
          "worker_addr": "worker-A",
          "pass_nr": 1,
          "assignment_revision_seen": 1,
          "progress": 100.0,
          "phase": "done",
          "ports_scanned": 10,
          "ports_total": 10,
          "open_ports_found": [],
          "completed_tests": [],
          "updated_at": 100.0,
          "started_at": 90.0,
          "first_seen_live_at": 90.0,
          "last_seen_at": 100.0,
          "finished": True,
        },
      } if hkey == "test-instance:live" else {"job-1": plugin.chainstore_hget.return_value}
    )

    result = Plugin.get_job_status(plugin, job_id="job-1")

    self.assertEqual(result["status"], "network_tracked")
    self.assertEqual(result["workers"]["worker-B"]["worker_state"], "unseen")

  def test_get_job_data_includes_reconciled_workers(self):
    """get_job_data includes reconciled worker state for active jobs."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=2)
    plugin = self._build_plugin({"run-job": running})
    plugin.time.return_value = 100.0
    plugin.chainstore_hgetall.side_effect = lambda hkey: (
      {
        "run-job:worker-A": {
          "job_id": "run-job",
          "worker_addr": "worker-A",
          "pass_nr": running["job_pass"],
          "assignment_revision_seen": 1,
          "progress": 50,
          "phase": "service_probes",
          "ports_scanned": 50,
          "ports_total": 100,
          "open_ports_found": [],
          "completed_tests": [],
          "updated_at": 100.0,
          "started_at": 90.0,
          "first_seen_live_at": 90.0,
          "last_seen_at": 100.0,
        },
      } if hkey == "test-instance:live" else {"run-job": running}
    )

    result = Plugin.get_job_data(plugin, job_id="run-job")

    self.assertIn("workers_reconciled", result["job"])
    self.assertEqual(result["job"]["workers_reconciled"]["worker-A"]["worker_state"], "active")

  def test_get_job_archive_not_found(self):
    """get_job_archive for non-existent job returns not_found."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})

    result = Plugin.get_job_archive(plugin, job_id="missing-job")
    self.assertEqual(result["error"], "not_found")

  def test_get_job_archive_r1fs_failure(self):
    """get_job_archive when R1FS fails returns fetch_failed."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = None

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["error"], "fetch_failed")

  def test_get_analysis_finalized_reads_archive(self):
    """Finalized jobs resolve stored LLM analysis from archive passes after CStore pruning."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "fin-job",
      "passes": [
        {
          "pass_nr": 1,
          "date_completed": 10.0,
          "report_cid": "QmPass1",
          "llm_analysis": "Archive-backed analysis",
          "quick_summary": "Archive-backed summary",
          "worker_reports": {"node-A": {}, "node-B": {}},
        },
      ],
      "ui_aggregate": {},
      "job_config": {"target": "10.0.0.1"},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_analysis(plugin, job_id="fin-job")

    self.assertEqual(result["job_id"], "fin-job")
    self.assertEqual(result["analysis"], "Archive-backed analysis")
    self.assertEqual(result["quick_summary"], "Archive-backed summary")
    self.assertEqual(result["num_workers"], 2)
    self.assertEqual(result["total_passes"], 1)

  def test_get_analysis_finalized_derives_legacy_fields_from_structured_sections(self):
    """Structured-only archives still satisfy the legacy get_analysis contract."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "fin-job",
      "passes": [
        {
          "pass_nr": 1,
          "date_completed": 10.0,
          "aggregated_report_cid": "QmAgg1",
          "llm_report_sections": {
            "executive_headline": "Structured archive headline",
            "overall_posture": "Structured archive posture",
            "recommendation_summary": ["Reduce exposed services"],
            "conclusion": "Structured archive conclusion",
          },
          "worker_reports": {"node-A": {}},
        },
      ],
      "ui_aggregate": {},
      "job_config": {"target": "10.0.0.1"},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_analysis(plugin, job_id="fin-job")

    self.assertEqual(result["quick_summary"], "Structured archive headline")
    self.assertIn("Structured archive posture", result["analysis"])
    self.assertIn("Reduce exposed services", result["analysis"])

  def test_get_analysis_finalized_reports_llm_failed_from_archive(self):
    """Finalized archive reads surface llm_failed instead of pretending pass history is missing."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "fin-job",
      "passes": [
        {
          "pass_nr": 1,
          "date_completed": 10.0,
          "report_cid": "QmPass1",
          "llm_failed": True,
          "quick_summary": None,
          "worker_reports": {"node-A": {}},
        },
      ],
      "ui_aggregate": {},
      "job_config": {"target": "10.0.0.1"},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_analysis(plugin, job_id="fin-job")

    self.assertEqual(result["error"], "No LLM analysis available for this pass")
    self.assertTrue(result["llm_failed"])
    self.assertEqual(result["pass_nr"], 1)

  def test_get_analysis_finalized_archive_integrity_error_bubbles_up(self):
    """Archive integrity failures should be returned instead of falling back to pruned CStore state."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "other-job",
      "passes": [],
      "ui_aggregate": {},
      "job_config": {},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_analysis(plugin, job_id="fin-job")

    self.assertEqual(result["error"], "integrity_mismatch")
    self.assertEqual(result["job_id"], "fin-job")

  def test_get_job_archive_summary_only(self):
    """Summary mode returns bounded pass-history summaries instead of full pass payloads."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "fin-job",
      "passes": [
        {
          "pass_nr": 1,
          "date_started": 1.0,
          "date_completed": 2.0,
          "duration": 1.0,
          "risk_score": 10,
          "quick_summary": "pass 1",
          "aggregated_report_cid": "QmAgg1",
          "worker_reports": {"node-A": {}},
          "findings": [{"finding_id": "f-1"}],
        },
        {
          "pass_nr": 2,
          "date_started": 2.0,
          "date_completed": 3.0,
          "duration": 1.0,
          "risk_score": 12,
          "quick_summary": "pass 2",
          "aggregated_report_cid": "QmAgg2",
          "worker_reports": {"node-A": {}, "node-B": {}},
          "findings": [{"finding_id": "f-2"}, {"finding_id": "f-3"}],
        },
      ],
      "ui_aggregate": {},
      "job_config": {},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_job_archive(plugin, job_id="fin-job", summary_only=True, pass_limit=1)

    self.assertEqual(result["archive"]["archive_query"]["returned_passes"], 1)
    self.assertTrue(result["archive"]["archive_query"]["summary_only"])
    self.assertEqual(result["archive"]["passes"][0]["findings_count"], 1)
    self.assertNotIn("findings", result["archive"]["passes"][0])

  def test_get_job_archive_paginated_passes(self):
    """Archive queries can page pass history without dropping the rest of the archive contract."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "fin-job",
      "passes": [{"pass_nr": 1}, {"pass_nr": 2}, {"pass_nr": 3}],
      "ui_aggregate": {},
      "job_config": {},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }

    result = Plugin.get_job_archive(plugin, job_id="fin-job", pass_offset=1, pass_limit=1)

    self.assertEqual([p["pass_nr"] for p in result["archive"]["passes"]], [2])
    self.assertTrue(result["archive"]["archive_query"]["truncated"])

  def test_update_finding_triage_persists_mutable_state(self):
    """Analyst triage updates stay outside archive storage and append audit history."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = {
      "archive_version": JOB_ARCHIVE_VERSION,
      "job_id": "fin-job",
      "passes": [{"findings": [{"finding_id": "f-1", "title": "Issue"}]}],
      "ui_aggregate": {},
      "job_config": {},
      "timeline": [],
      "duration": 0,
      "date_created": 0,
      "date_completed": 0,
    }
    plugin.time.return_value = 123.0
    plugin._log_audit_event = MagicMock()
    triage_store = {}
    triage_audit_store = {}

    def _chainstore_hget(hkey, key):
      if hkey.endswith(":triage"):
        return triage_store.get(key)
      if hkey.endswith(":triage:audit"):
        return triage_audit_store.get(key)
      return {"fin-job": stub}.get(key)

    def _chainstore_hgetall(hkey):
      if hkey.endswith(":triage"):
        return dict(triage_store)
      if hkey.endswith(":triage:audit"):
        return dict(triage_audit_store)
      return {"fin-job": stub}

    def _chainstore_hset(hkey, key, value):
      if hkey.endswith(":triage"):
        triage_store[key] = value
      elif hkey.endswith(":triage:audit"):
        triage_audit_store[key] = value

    plugin.chainstore_hget.side_effect = _chainstore_hget
    plugin.chainstore_hgetall.side_effect = _chainstore_hgetall
    plugin.chainstore_hset.side_effect = _chainstore_hset

    result = Plugin.update_finding_triage(
      plugin,
      job_id="fin-job",
      finding_id="f-1",
      status="accepted_risk",
      note="Approved by analyst",
      actor="alice",
      review_at=456.0,
    )

    self.assertEqual(result["triage"]["status"], "accepted_risk")
    self.assertEqual(result["audit"][-1]["actor"], "alice")
    self.assertEqual(triage_store["fin-job:f-1"]["review_at"], 456.0)
    plugin._log_audit_event.assert_called_once()

  def test_get_job_triage_not_found(self):
    """Triage query returns found=False when no mutable state exists yet."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.chainstore_hgetall.side_effect = [
      {"fin-job": stub},
      {},
    ]
    plugin.chainstore_hget.side_effect = [
      [],
    ]

    result = Plugin.get_job_triage(plugin, job_id="fin-job", finding_id="missing")

    self.assertFalse(result["found"])
    self.assertEqual(result["audit"], [])


class TestPhase2AuditCounting(unittest.TestCase):
  """Phase 2: audit counts include graybox findings."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_close_job_audit_counts_graybox_findings(self):
    """_close_job audit nr_findings includes graybox results."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "node-A"
    plugin.cfg_instance_id = "test-instance"
    plugin.global_shmem = {}
    plugin.log.get_localhost_ip.return_value = "127.0.0.1"
    plugin.P = MagicMock()
    plugin.json_dumps.return_value = "{}"
    plugin.r1fs.add_json.return_value = "QmWorkerReport"
    plugin._get_job_config = MagicMock(return_value={"redact_credentials": False})
    plugin._redact_report = MagicMock(side_effect=lambda r: r)
    plugin._normalize_job_record = MagicMock(side_effect=lambda job_id, raw: (job_id, raw))
    plugin._log_audit_event = MagicMock()
    plugin._count_nested_findings = lambda section: Plugin._count_nested_findings(section)
    plugin._count_all_findings = lambda report: Plugin._count_all_findings(plugin, report)

    report = {
      "start_port": 443,
      "end_port": 443,
      "ports_scanned": 1,
      "open_ports": [443],
      "service_info": {
        "443": {"_service_info_https": {"findings": [{"title": "svc"}]}},
      },
      "web_tests_info": {
        "443": {"_web_test_xss": {"findings": [{"title": "web"}]}},
      },
      "correlation_findings": [{"title": "corr"}],
      "graybox_results": {
        "443": {"_graybox_test": {"findings": [{"scenario_id": "S1"}, {"scenario_id": "S2"}]}},
      },
    }

    worker = MagicMock()
    worker.get_status.return_value = report
    plugin.scan_jobs = {"job-1": {"local-1": worker}}
    plugin._get_aggregated_report = MagicMock(return_value=report)

    job_specs = {
      "job_id": "job-1",
      "target": "example.com",
      "workers": {"node-A": {"start_port": 443, "end_port": 443}},
      "job_config_cid": "QmConfig",
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.chainstore_hset = MagicMock()

    Plugin._close_job(plugin, "job-1")

    plugin._log_audit_event.assert_called_once()
    event_type, details = plugin._log_audit_event.call_args[0]
    self.assertEqual(event_type, "scan_completed")
    self.assertEqual(details["nr_findings"], 5)
