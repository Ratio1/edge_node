"""Bound effective destinations are checked before DNS, secrets or worker construction."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.execution import ResolvedExecutionContext


def context(target):
  return ResolvedExecutionContext({
    "namespace": "deployment", "tenant_id": "tn_00000000-0000-4000-8000-000000000001",
    "asset_id": "as_00000000-0000-4000-8000-000000000002", "asset_target": target,
    "asset_target_digest": canonical_digest(target), "actor_id": "creator",
    "actor_generation": "generation-1", "node_failure_policy": "stop",
    "selected_candidates": ["node-1", "node-2"],
  })


def test_saved_network_target_is_derived_and_actual_override_denied_without_dns():
  from extensions.business.cybersec.red_mesh.tenancy.effective_targets import resolve_launch_target, validate_effective_config
  admission = context({"kind": "network", "address": "192.0.2.1"})
  with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")):
    assert resolve_launch_target(admission, "network", "") == "192.0.2.1"
    with pytest.raises(ValueError, match="Execution target mismatch"):
      resolve_launch_target(admission, "network", "foreign.example")
    config = {"scan_type": "network", "target": "192.0.2.1",
              "execution_binding": admission.build_binding("launcher", ["node-1"]).to_dict()}
    validate_effective_config(config, target="192.0.2.1")
    with pytest.raises(ValueError, match="Execution target mismatch"):
      validate_effective_config(config, target="192.0.2.2")
    for invalid in (None, "", False):
      with pytest.raises(ValueError, match="Execution target mismatch"):
        validate_effective_config(config, target=invalid)


def test_real_endpoint_fresh_admission_conflict_denies_before_target_effects():
  from .test_tenant_execution import TestTenantExecution
  from .test_api import TestPhase1ConfigCID
  from extensions.business.cybersec.red_mesh.tenancy.identity import resolve_actor, TenantMembership
  fixture = TestTenantExecution()
  fixture.setUp()
  try:
    asset = fixture.ready()
    owner = TestPhase1ConfigCID._build_mock_plugin()
    TestPhase1ConfigCID._bind_launch_helpers(owner)
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    owner._execution_service = lambda: fixture.service
    owner._resolve_launch_actor = lambda actor: resolve_actor(actor, fixture.service.accounts)
    # The launch helpers stub admission for the configuration suites; this one is about admission.
    owner._admit_execution = lambda *args: PentesterApi01Plugin._admit_execution(owner, *args)
    kwargs = dict(actor=fixture.actor, tenant_id=fixture.tenant, asset_id=asset["assetId"],
                  selected_peers=["node-a"], authorized=True, start_port=1, end_port=4)
    with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
         patch.object(fixture.service.accounts, "get_account", wraps=fixture.service.accounts.get_account) as reads:
      denied = PentesterApi01Plugin.launch_network_scan(owner, expected_target_digest="0" * 64, **kwargs)
      assert denied["status_code"] == 409
      assert reads.call_count == 1
      owner.r1fs.add_json.assert_not_called()
      owner.chainstore_hset.assert_not_called()
    allowed = PentesterApi01Plugin.launch_network_scan(owner, expected_target_digest=asset["targetDigest"], **kwargs)
    assert allowed["job_config"]["target"] == fixture.target["address"]
    assert allowed["job_specs"]["execution_binding"]["participant_order"] == ["node-a"]
  finally:
    fixture.doCleanups()


def test_bound_network_launch_publishes_same_binding_and_never_lists_global_jobs():
  from .test_api import TestPhase1ConfigCID
  from extensions.business.cybersec.red_mesh.services.launch_api import launch_network_scan
  owner = TestPhase1ConfigCID._build_mock_plugin()
  TestPhase1ConfigCID._bind_launch_helpers(owner)
  owner._normalize_job_record.side_effect = AssertionError("No global jobs")
  admission = context({"kind": "network", "address": "192.0.2.1"})
  result = launch_network_scan(owner, execution_context=admission, authorized=True,
                              start_port=1, end_port=4, exceptions="")
  assert "error" not in result, result
  binding = result["job_specs"]["execution_binding"]
  assert binding == result["job_config"]["execution_binding"]
  assert binding["participant_order"] == ["node-1", "node-2"]
  assert "other_jobs" not in result
  owner.chainstore_hgetall.assert_not_called()


def test_bound_network_denials_precede_config_and_secret_writes():
  from .test_api import TestPhase1ConfigCID
  from extensions.business.cybersec.red_mesh.services.launch_api import launch_network_scan
  admission = context({"kind": "network", "address": "192.0.2.1"})
  for kwargs in ({"target": "192.0.2.2", "end_port": 4}, {"end_port": 1}):
    owner = TestPhase1ConfigCID._build_mock_plugin()
    TestPhase1ConfigCID._bind_launch_helpers(owner)
    result = launch_network_scan(owner, execution_context=admission, authorized=True,
                                start_port=1, exceptions="", **kwargs)
    assert result.get("error"), result
    owner.r1fs.add_json.assert_not_called()
    owner.chainstore_hset.assert_not_called()


def test_endpoint_admission_refuses_an_incomplete_selector_after_one_account_read():
  """RM-084 P6: the unbound launch is gone. A launch naming no tenant, asset or digest is malformed,
  and it is refused before any tenant admission runs -- still after exactly one account read."""
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView, TenantMembership
  service = MagicMock()
  actor = {"account_id": "creator"}
  for selectors in ((None, None, None), ("tn_x", None, None), ("tn_x", "as_x", " ")):
    account = AccountView("creator", True, tenant_memberships=(TenantMembership("super_tenant_admin", None),))
    owner = SimpleNamespace(_resolve_launch_actor=MagicMock(return_value=(account, None)),
      _execution_service=lambda: service, cfg_instance_id="deployment")
    result_account, admission, error = PentesterApi01Plugin._admit_execution(owner, actor, *selectors)
    assert error == {"error": "invalid_request", "status_code": 400}
    assert result_account is None and admission is None
    owner._resolve_launch_actor.assert_called_once_with(actor)
  service._resolve_execution_admission_for_account.assert_not_called()


def test_bound_manual_analysis_is_denied_before_report_reads_or_executor_admission():
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  owner = MagicMock(cfg_llm_agent_api_port=8080, cfg_request_timeout=120)
  # RM-026 I1b B6: the preparation step consumes the admitted snapshot and never reads the store
  # itself. The legacy snapshot set excludes bound records, so this stands for the tenant-bound
  # snapshot RM-078 will supply -- launch authority must still not be borrowable here.
  bound = {"job_id": "bound-job", "execution_binding":
    context({"kind": "network", "address": "192.0.2.1"}).build_binding("launcher", ["node-1"]).to_dict()}
  with patch("extensions.business.cybersec.red_mesh.pentester_api_01.get_llm_agent_config",
             return_value={"ENABLED": True}):
    prepared, error = PentesterApi01Plugin._prepare_manual_analysis(owner, "bound-job",
                                                                    checked_job=bound)
  assert prepared is None and error["status_code"] == 503
  owner._get_job_from_cstore.assert_not_called()
  owner._collect_bounded_manual_analysis_reports.assert_not_called()
  owner._get_manual_analysis_executor.assert_not_called()
  owner._get_job_config.assert_not_called()


def test_worker_fresh_boundary_denies_unknown_authority_and_binding_swap():
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
  admission = context({"kind": "network", "address": "192.0.2.1"})
  binding = admission.build_binding("launcher", ["node-1"]).to_dict()
  config = {"execution_binding": binding, "target": "192.0.2.1", "scan_type": "network"}
  record = {"job_id": "job", "job_pass": 1, "execution_binding": binding, "job_status": "RUNNING",
            "workers": {"node-1": {"assignment_revision": 1}}}
  repo, service = MagicMock(), MagicMock()
  repo.get_job.return_value = record
  owner = SimpleNamespace(_get_job_state_repository=lambda: repo, _execution_service=lambda: service,
    ee_addr="node-1", cfg_instance_id="instance")
  owner._execution_operation_allowed = lambda *args, **kwargs: PentesterApi01Plugin._execution_operation_allowed(owner, *args, **kwargs)
  identity = ("job", 1, "node-1", 1)
  PentesterApi01Plugin._require_worker_execution(owner, "job", config, execution_identity=identity)
  service.reauthorize_execution.assert_called_once()
  for mutation in ("unavailable_authority", "binding_swap", "unassigned"):
    service.reauthorize_execution.side_effect = None
    record["execution_binding"] = binding
    record["workers"] = {"node-1": {"assignment_revision": 1}}
    if mutation == "unavailable_authority":
      service.reauthorize_execution.side_effect = TenantStoreError("Unavailable")
    elif mutation == "binding_swap":
      record["execution_binding"] = {**binding, "node_failure_policy": "continue"}
    else:
      record["workers"] = {}
    with pytest.raises(ValueError, match="Execution unavailable"):
      PentesterApi01Plugin._require_worker_execution(owner, "job", config, execution_identity=identity)


@pytest.mark.parametrize("mutation", ["pass", "assignment", "worker", "missing_context", "missing_pass", "missing_revision", "boolean_pass"])
def test_stale_worker_context_denies_before_secret_read_and_local_start(mutation):
  from copy import deepcopy
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  from extensions.business.cybersec.red_mesh.services.launch import launch_local_jobs
  binding = context({"kind": "network", "address": "192.0.2.1"}).build_binding("launcher", ["node-1"]).to_dict()
  config = {"execution_binding": binding, "target": "192.0.2.1", "scan_type": "network"}
  discovered = {"job_id": "job", "job_pass": 2, "job_config_cid": "config-cid", "job_status": "RUNNING",
    "execution_binding": binding, "workers": {"node-1": {"assignment_revision": 3, "start_port": 10, "end_port": 20}}}
  current = deepcopy(discovered)
  identity = ("job", 2, "node-1", 3)
  if mutation == "pass":
    current["job_pass"] = 3
  elif mutation == "assignment":
    current["workers"]["node-1"].update(assignment_revision=4, start_port=30, end_port=40)
  elif mutation == "worker":
    identity = ("job", 2, "node-2", 3)
  elif mutation == "missing_context":
    identity = None
  elif mutation == "missing_pass":
    current.pop("job_pass")
  elif mutation == "missing_revision":
    current["workers"]["node-1"].pop("assignment_revision")
  else:
    current["job_pass"] = True
  repo, artifacts, service = MagicMock(), MagicMock(), MagicMock()
  repo.get_job.return_value = current
  artifacts.get_job_config_model.return_value.to_dict.return_value = config
  owner = SimpleNamespace(_get_job_state_repository=lambda: repo, _execution_service=lambda: service,
    _artifact_repository=artifacts, ee_addr="node-1", cfg_instance_id="instance")
  owner._execution_operation_allowed = lambda *args, **kwargs: PentesterApi01Plugin._execution_operation_allowed(owner, *args, **kwargs)
  owner._require_worker_execution = lambda *args, **kwargs: PentesterApi01Plugin._require_worker_execution(owner, *args, **kwargs)
  with patch.object(PentesterApi01Plugin, "_get_artifact_repository", return_value=artifacts), \
       patch("extensions.business.cybersec.red_mesh.pentester_api_01.resolve_job_config_secrets") as secrets:
    with pytest.raises(ValueError, match="Execution unavailable"):
      PentesterApi01Plugin._get_job_config(owner, discovered, resolve_secrets=True, execution_identity=identity)
  secrets.assert_not_called()
  with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy") as strategy:
    with pytest.raises(ValueError, match="Execution unavailable"):
      launch_local_jobs(owner, job_id="job", target="192.0.2.1", launcher="launcher", start_port=10,
        end_port=20, job_config=config, execution_identity=identity)
  strategy.assert_not_called()
  assert "execution_identity" not in config


def test_malformed_model_config_binding_is_skipped_without_poisoning_discovery_loop():
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  binding = context({"kind": "model", "adapter": "openai_compatible", "model": "fixture",
    "endpointUrl": "https://192.0.2.1/v1/chat/completions"}).build_binding("launcher", ["node-1"]).to_dict()
  record = {"job_id": "job", "job_type": "model_test", "job_status": "RUNNING", "execution_binding": binding}
  owner = MagicMock()
  owner.chainstore_hgetall.return_value = {"job": record}
  owner._normalize_job_record.return_value = ("job", record)
  owner.model_test_jobs = {}
  owner._get_worker_entry.return_value = {"finished": False}
  owner._execution_operation_allowed.return_value = True
  owner._get_artifact_repository.return_value.get_job_config.return_value = {"execution_binding": None}
  with patch("extensions.business.cybersec.red_mesh.pentester_api_01.ModelTestWorker") as worker:
    PentesterApi01Plugin._maybe_launch_model_test_jobs(owner)
  worker.assert_not_called()
  owner._publish_model_test_progress.assert_not_called()


def test_bound_model_worker_cannot_load_another_jobs_credentials_with_same_binding():
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  from extensions.business.cybersec.red_mesh.model_testing.worker import ModelTestWorker
  binding = context({"kind": "model", "adapter": "openai_compatible", "model": "fixture",
    "endpointUrl": "https://192.0.2.1/v1/chat/completions"}).build_binding("launcher", ["node-1"]).to_dict()
  config = {"job_id": "other-job", "scan_type": "model_test", "execution_binding": binding,
            "model_provider_secret_ref": "other-secret", "test_sets": [{"id": "cbrn_safety_v1"}]}
  record = {"job_id": "requested-job", "job_type": "model_test", "execution_binding": binding,
            "job_status": "RUNNING", "workers": {"node-1": {}}}
  repo, service = MagicMock(), MagicMock()
  repo.get_job.return_value = record
  owner = SimpleNamespace(_get_job_state_repository=lambda: repo, _execution_service=lambda: service,
    ee_addr="node-1", cfg_instance_id="instance")
  owner._execution_operation_allowed = lambda *args, **kwargs: PentesterApi01Plugin._execution_operation_allowed(owner, *args, **kwargs)
  owner._require_worker_execution = lambda *args, **kwargs: PentesterApi01Plugin._require_worker_execution(owner, *args, **kwargs)
  for mutation in ("config_id", "stored_id"):
    config["job_id"] = "other-job" if mutation == "config_id" else "requested-job"
    record["job_id"] = "requested-job" if mutation == "config_id" else "other-job"
    worker = ModelTestWorker(owner, job_id="requested-job", initiator="launcher", job_config=config)
    with patch("extensions.business.cybersec.red_mesh.model_testing.worker.resolve_model_test_runtime_config") as secrets, \
         patch("extensions.business.cybersec.red_mesh.model_testing.worker.ModelTestRunner") as runner:
      worker.execute_job()
    secrets.assert_not_called()
    runner.assert_not_called()


def _worker_identity_fixture(kind):
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  target = {"kind": "network", "address": "192.0.2.1"} if kind == "network" else (
    {"kind": "webapp", "url": "https://target.example/api", "allowedPathPrefix": "/api"} if kind == "webapp" else
    {"kind": "model", "adapter": "openai_compatible", "model": "fixture",
     "endpointUrl": "https://192.0.2.1/v1/chat/completions"})
  binding = context(target).build_binding("launcher", ["node-1"]).to_dict()
  scan_type = "model_test" if kind == "model" else kind
  config = {"job_id": "job", "execution_binding": binding, "target": "192.0.2.1", "scan_type": scan_type}
  if kind == "webapp":
    config["target_url"] = target["url"]
  record = {"job_id": "job", "job_pass": 2, "job_config_cid": "config-cid", "job_status": "RUNNING",
    "job_type": scan_type, "scan_type": scan_type, "target": config["target"], "launcher": "launcher",
    "execution_binding": binding, "workers": {"node-1": {"assignment_revision": 3, "start_port": 10, "end_port": 20}}}
  repo, artifacts, service = MagicMock(), MagicMock(), MagicMock()
  repo.get_job.return_value = record
  artifacts.get_job_config.return_value = config
  artifacts.get_job_config_model.return_value.to_dict.return_value = config
  owner = TestPhase1ConfigCID._build_mock_plugin()
  owner._get_job_state_repository = lambda: repo
  owner._get_artifact_repository = lambda: artifacts
  owner._execution_service = lambda: service
  owner._execution_operation_allowed = lambda *args, **kwargs: PentesterApi01Plugin._execution_operation_allowed(owner, *args, **kwargs)
  owner._require_worker_execution = lambda *args, **kwargs: PentesterApi01Plugin._require_worker_execution(owner, *args, **kwargs)
  return PentesterApi01Plugin, owner, config, record, artifacts


@pytest.mark.parametrize("kind", ["network", "model"])
@pytest.mark.parametrize("stale", [False, True])
def test_discovery_carries_captured_identity_and_does_not_start_stale_work(kind, stale):
  from copy import deepcopy
  plugin, owner, config, current, artifacts = _worker_identity_fixture(kind)
  discovered = deepcopy(current)
  owner.chainstore_hgetall.return_value = {"job": discovered}
  owner._normalize_job_record.side_effect = lambda key, specs, **kwargs: (key, specs)
  owner._get_worker_entry.side_effect = lambda job, specs: specs["workers"].get(owner.ee_addr)
  owner._PentesterApi01Plugin__last_checked_jobs = 0
  owner.cfg_check_jobs_each = 0
  owner.scan_jobs, owner.model_test_jobs, owner.completed_jobs_reports = {}, {}, {}
  owner._get_job_config = lambda *args, **kwargs: plugin._get_job_config(owner, *args, **kwargs)
  if stale:
    current["job_pass"] += 1
    current["workers"]["node-1"].update(assignment_revision=4, start_port=30, end_port=40)
  with patch.object(plugin, "_get_artifact_repository", return_value=artifacts), \
       patch.object(plugin, "_mark_worker_terminal_error") as terminal, \
       patch("extensions.business.cybersec.red_mesh.pentester_api_01.resolve_job_config_secrets", return_value=config) as secrets, \
       patch("extensions.business.cybersec.red_mesh.pentester_api_01.launch_local_jobs", return_value={"worker": MagicMock()}) as launch, \
       patch("extensions.business.cybersec.red_mesh.pentester_api_01.ModelTestWorker") as model_worker:
    if kind == "network":
      plugin._maybe_launch_jobs(owner)
    else:
      plugin._maybe_launch_model_test_jobs(owner)
    if stale:
      secrets.assert_not_called()
      launch.assert_not_called()
      model_worker.assert_not_called()
      terminal.assert_not_called()
    else:
      call = launch.call_args if kind == "network" else model_worker.call_args
      assert call.kwargs["execution_identity"] == ("job", 2, "node-1", 3)
      if kind == "network":
        assert call.kwargs["start_port"] == 10 and call.kwargs["end_port"] == 20
      else:
        model_worker.return_value.start.assert_called_once()
  assert "execution_identity" not in config


def test_network_start_checks_actual_range_from_same_fresh_read():
  from extensions.business.cybersec.red_mesh.services.launch import launch_local_jobs
  _plugin, owner, config, record, _artifacts = _worker_identity_fixture("network")
  identity = ("job", 2, "node-1", 3)
  for supplied in ({"start_port": 1, "end_port": 20}, {"start_port": 10, "end_port": 21},
                   {"start_port": 10, "end_port": 20, "target_ports": [443]}):
    with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy") as strategy:
      with pytest.raises(ValueError, match="Execution unavailable"):
        launch_local_jobs(owner, job_id="job", target="192.0.2.1", launcher="launcher",
          job_config=config, execution_identity=identity, **supplied)
    strategy.assert_not_called()
  owner._execution_service().reauthorize_execution.reset_mock()
  with patch("extensions.business.cybersec.red_mesh.services.launch._launch_network_jobs", return_value={"worker": object()}) as start:
    result = launch_local_jobs(owner, job_id="job", target="192.0.2.1", launcher="launcher",
      start_port=10, end_port=20, job_config=config, execution_identity=identity)
  assert result and start.call_args.kwargs["execution_identity"] == identity
  owner._execution_service().reauthorize_execution.assert_called_once()


@pytest.mark.parametrize("kind", ["model", "webapp"])
def test_async_worker_rechecks_captured_identity_before_secret_or_http_effects(kind):
  from extensions.business.cybersec.red_mesh.model_testing.worker import ModelTestWorker
  from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxLocalWorker
  _plugin, owner, config, current, _artifacts = _worker_identity_fixture(kind)
  identity = ("job", 2, "node-1", 3)
  current["workers"]["node-1"]["assignment_revision"] = 4
  if kind == "model":
    worker = ModelTestWorker(owner, job_id="job", initiator="launcher", job_config=config, execution_identity=identity)
    with patch("extensions.business.cybersec.red_mesh.model_testing.worker.resolve_model_test_runtime_config") as secrets, \
         patch("extensions.business.cybersec.red_mesh.model_testing.worker.ModelTestRunner") as runner:
      worker.execute_job()
    secrets.assert_not_called()
    runner.assert_not_called()
  else:
    worker = GrayboxLocalWorker.__new__(GrayboxLocalWorker)
    worker.owner, worker.job_id, worker._execution_identity = owner, "job", identity
    worker.job_config = SimpleNamespace(execution_binding=config["execution_binding"], to_dict=lambda: config)
    worker.metrics, worker.state = MagicMock(), {}
    worker._phase_open, worker._phase = False, ""
    worker._sanitize_error, worker._record_fatal = str, MagicMock()
    worker._run_preflight_phase, worker._safe_cleanup = MagicMock(), MagicMock()
    worker.execute_job()
    worker._run_preflight_phase.assert_not_called()
    worker._safe_cleanup.assert_not_called()
    worker._record_fatal.assert_called_once()
  assert worker.state["done"] is True


def test_model_identity_change_during_secret_read_denies_provider_start():
  from extensions.business.cybersec.red_mesh.model_testing.worker import ModelTestWorker
  _plugin, owner, config, current, _artifacts = _worker_identity_fixture("model")
  config["tested_model"] = {"adapter": "openai_compatible", "model": "fixture",
                            "base_url": "https://192.0.2.1/v1", "method": "chat"}
  identity = ("job", 2, "node-1", 3)
  def resolve(_owner, original):
    current["job_pass"] += 1
    return original
  worker = ModelTestWorker(owner, job_id="job", initiator="launcher", job_config=config, execution_identity=identity)
  with patch("extensions.business.cybersec.red_mesh.model_testing.worker.resolve_model_test_runtime_config", side_effect=resolve) as secrets, \
       patch("extensions.business.cybersec.red_mesh.model_testing.worker.ModelTestRunner") as runner:
    worker.execute_job()
  secrets.assert_called_once()
  runner.assert_not_called()
  assert worker.state["model_test_summary"]["overall_status"] == "failed"


def test_bound_legacy_wrapper_and_revised_network_batch_cannot_start_workers():
  from extensions.business.cybersec.red_mesh.services.launch import launch_local_jobs
  from extensions.business.cybersec.red_mesh.constants import ScanType
  plugin, owner, config, current, _artifacts = _worker_identity_fixture("network")
  with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy") as strategy:
    with pytest.raises(ValueError, match="Execution unavailable"):
      plugin._launch_job(owner, job_id="job", target="192.0.2.1", network_worker_address="launcher",
        start_port=10, end_port=20)
  strategy.assert_not_called()
  guard = owner._require_worker_execution
  checks = []
  def revise_before_batch(*args, **kwargs):
    if checks:
      current["workers"]["node-1"]["assignment_revision"] += 1
    checks.append(True)
    return guard(*args, **kwargs)
  owner._require_worker_execution = revise_before_batch
  worker_class = MagicMock()
  with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy",
             return_value=SimpleNamespace(scan_type=ScanType.NETWORK, worker_cls=worker_class)):
    with pytest.raises(ValueError, match="Execution unavailable"):
      launch_local_jobs(owner, job_id="job", target="192.0.2.1", launcher="launcher", start_port=10,
        end_port=20, job_config=config, execution_identity=("job", 2, "node-1", 3))
  worker_class.assert_not_called()


def test_unbound_network_job_never_starts_a_worker():
  """RM-084 P6: an unbound job has no tenant to reauthorize against, so no worker starts for it."""
  from extensions.business.cybersec.red_mesh.services.launch import launch_local_jobs
  _plugin, owner, config, current, _artifacts = _worker_identity_fixture("network")
  config.pop("execution_binding")
  current.pop("execution_binding")
  deferred = []
  class DeferredThread:
    def __init__(self, *, target, daemon):
      deferred.append(self)
    def start(self):
      pass
  with patch("extensions.business.cybersec.red_mesh.worker.base.threading.Thread", DeferredThread), \
       pytest.raises(ValueError, match="Execution unavailable"):
    launch_local_jobs(owner, job_id="job", target="192.0.2.1", launcher="launcher",
      start_port=10, end_port=20, nr_local_workers_override=1, job_config=config, execution_identity=None)
  assert deferred == []
  owner.chainstore_hset.assert_not_called()


@pytest.mark.parametrize("mutation", ["pass", "assignment", "missing_guard", "actual_target", "source_config_removed", "matching"])
def test_real_network_worker_rechecks_deferred_thread_before_any_socket(mutation):
  from extensions.business.cybersec.red_mesh.services.launch import launch_local_jobs
  from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker
  _plugin, owner, config, current, _artifacts = _worker_identity_fixture("network")
  identity = ("job", 2, "node-1", 3)
  deferred = []
  class DeferredThread:
    def __init__(self, *, target, daemon):
      self.target = target
      deferred.append(self)
    def start(self):
      pass
  with patch("extensions.business.cybersec.red_mesh.worker.base.threading.Thread", DeferredThread):
    local = launch_local_jobs(owner, job_id="job", target="192.0.2.1", launcher="launcher",
      start_port=10, end_port=20, nr_local_workers_override=1, job_config=config, execution_identity=identity)
  worker = next(iter(local.values()))
  assert isinstance(worker, PentestLocalWorker) and len(deferred) == 1
  if mutation == "pass":
    current["job_pass"] = 3
  elif mutation == "assignment":
    current["workers"]["node-1"]["assignment_revision"] = 4
  elif mutation == "missing_guard":
    owner._require_worker_execution = None
  elif mutation == "actual_target":
    worker.target = "192.0.2.2"
  elif mutation == "source_config_removed":
    config.pop("execution_binding")
    current["job_pass"] = 3
  owner.chainstore_hset.reset_mock()
  owner.r1fs.add_json.reset_mock()
  with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket",
             side_effect=AssertionError("Recording socket boundary; no network")) as sockets, \
       patch.object(worker.metrics, "start_scan", wraps=worker.metrics.start_scan) as metrics:
    deferred[0].target()
  if mutation == "matching":
    sockets.assert_called_once()
    metrics.assert_called_once()
  else:
    sockets.assert_not_called()
    metrics.assert_not_called()
    assert worker.state["completed_tests"] == []
    assert worker.state["ports_scanned"] == []
    assert worker.state["execution_denied"] is True
    assert worker.state["done"] is True and worker.state["canceled"] is True
  owner.chainstore_hset.assert_not_called()
  owner.r1fs.add_json.assert_not_called()
  owner.r1fs.get_json.assert_not_called()
  owner._publish_live_progress.assert_not_called()
