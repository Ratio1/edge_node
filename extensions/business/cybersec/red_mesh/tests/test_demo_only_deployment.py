"""RM-140: a demo-only deployment refuses every real launch and never starts an announced job."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from .test_tenant_execution_effects import _worker_identity_fixture


PLUGIN_MODULE = "extensions.business.cybersec.red_mesh.pentester_api_01"
REFUSAL = {"error": "demo_only_deployment", "status_code": 409, "success": False}


def _plugin_class():
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
  return PentesterApi01Plugin


@pytest.mark.parametrize("value, expected", [
  (None, False), (False, False), (True, True), (0, False), (1, True),
  ("false", False), ("off", False), ("", False), ("true", True), ("yes", True),
])
def test_get_demo_only_reads_the_deployment_value(value, expected):
  from extensions.business.cybersec.red_mesh.services.config import get_demo_only
  assert get_demo_only(SimpleNamespace(cfg_redmesh_demo_only=value)) is expected


def test_get_demo_only_is_off_when_unset_or_not_a_deployment_value():
  from extensions.business.cybersec.red_mesh.services.config import get_demo_only
  assert get_demo_only(SimpleNamespace()) is False
  assert get_demo_only(MagicMock()) is False
  assert get_demo_only(SimpleNamespace(cfg_redmesh_demo_only={"ENABLED": True})) is False


def _admission_owner(flag):
  from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView, TenantMembership
  account = AccountView("creator", True, tenant_memberships=(TenantMembership("super_tenant_admin", None),))
  service = MagicMock()
  owner = SimpleNamespace(_resolve_launch_actor=MagicMock(return_value=(account, None)),
    _execution_service=lambda: service, cfg_instance_id="deployment", cfg_redmesh_demo_only=flag)
  return owner, service


@pytest.mark.parametrize("flag, refused", [(True, True), ("true", True), (False, False), ("false", False), (None, False)])
def test_admission_refuses_on_a_demo_only_deployment_before_any_tenant_read(flag, refused):
  plugin = _plugin_class()
  owner, service = _admission_owner(flag)
  account, admission, error = plugin._admit_execution(owner, {"account_id": "creator"}, "tn_x", "en_x", "ea_1")
  if refused:
    assert error == REFUSAL
    assert account is None and admission is None
    service._resolve_execution_admission_for_account.assert_not_called()
  else:
    assert error is None
    service._resolve_execution_admission_for_account.assert_called_once()


def test_admission_still_reports_an_unknown_actor_first():
  plugin = _plugin_class()
  owner, service = _admission_owner(True)
  denial = {"error": "actor_unknown", "status_code": 403, "success": False}
  owner._resolve_launch_actor.return_value = (None, denial)
  assert plugin._admit_execution(owner, {"account_id": "x"}, "tn_x", "en_x", "ea_1")[2] == denial


@pytest.mark.parametrize("endpoint, kwargs", [
  ("launch_network_scan", {"target": "192.0.2.10", "start_port": 1, "end_port": 4, "authorized": True}),
  ("launch_webapp_scan", {"target_url": "https://example.com/app", "authorized": True}),
  ("launch_test", {"target": "192.0.2.10", "start_port": 1, "end_port": 4, "authorized": True}),
  ("launch_model_test", {"token": "t"}),
  ("preflight_model_test_provider", {"token": "t"}),
])
def test_every_launch_and_the_provider_preflight_are_refused_with_no_job_record(endpoint, kwargs):
  from .test_api import TestPhase1ConfigCID
  plugin = _plugin_class()
  owner = TestPhase1ConfigCID._build_mock_plugin()
  TestPhase1ConfigCID._bind_launch_helpers(owner)
  owner.cfg_redmesh_demo_only = True
  service = MagicMock()
  owner._execution_service = lambda: service
  # The launch helpers stub admission for the configuration suites; this one is about admission.
  owner._admit_execution = lambda *args, **kw: plugin._admit_execution(owner, *args, **kw)
  with patch(f"{PLUGIN_MODULE}.validate_backend_token", return_value=None), \
       patch(f"{PLUGIN_MODULE}.preflight_model_test_provider") as provider:
    result = getattr(plugin, endpoint)(owner, actor={"account_id": "tester"}, tenant_id="tn_x",
                                       engagement_id="en_x", engagement_asset_id="ea_1", **kwargs)
  assert result == REFUSAL
  service._resolve_execution_admission_for_account.assert_not_called()
  provider.assert_not_called()
  owner.r1fs.add_json.assert_not_called()
  owner.chainstore_hset.assert_not_called()


def test_feature_catalog_reports_the_lock():
  from .test_api import TestPhase1ConfigCID
  plugin = _plugin_class()
  owner = TestPhase1ConfigCID._bind_launch_helpers(MagicMock())
  assert plugin.get_feature_catalog(owner)["demo_only"] is False
  owner.cfg_redmesh_demo_only = True
  assert plugin.get_feature_catalog(owner)["demo_only"] is True


def _announced(kind):
  from copy import deepcopy
  plugin, owner, config, current, artifacts = _worker_identity_fixture(kind)
  owner.chainstore_hgetall.return_value = {"job": deepcopy(current)}
  owner._normalize_job_record.side_effect = lambda key, specs, **kwargs: (key, specs)
  owner._get_worker_entry.side_effect = lambda job, specs: specs["workers"].get(owner.ee_addr)
  owner._PentesterApi01Plugin__last_checked_jobs = 0
  owner.cfg_check_jobs_each = 0
  owner.scan_jobs, owner.model_test_jobs, owner.completed_jobs_reports = {}, {}, {}
  owner._get_job_config = lambda *args, **kwargs: plugin._get_job_config(owner, *args, **kwargs)
  owner.cfg_redmesh_demo_only = True
  owner._demo_only_jobs_logged = set()
  return plugin, owner, config, artifacts


@pytest.mark.parametrize("kind", ["network", "model"])
def test_an_announced_job_is_never_started_and_the_refusal_is_logged_once(kind):
  plugin, owner, config, artifacts = _announced(kind)
  with patch.object(plugin, "_get_artifact_repository", return_value=artifacts), \
       patch.object(plugin, "_mark_worker_terminal_error") as terminal, \
       patch(f"{PLUGIN_MODULE}.resolve_job_config_secrets", return_value=config) as secrets, \
       patch(f"{PLUGIN_MODULE}.launch_local_jobs") as launch, \
       patch(f"{PLUGIN_MODULE}.ModelTestWorker") as model_worker:
    for _ in range(2):
      owner._PentesterApi01Plugin__last_checked_jobs = 0
      if kind == "network":
        plugin._maybe_launch_jobs(owner)
      else:
        plugin._maybe_launch_model_test_jobs(owner)
  launch.assert_not_called()
  model_worker.assert_not_called()
  secrets.assert_not_called()
  terminal.assert_not_called()
  artifacts.get_job_config.assert_not_called()
  artifacts.get_job_config_model.assert_not_called()
  assert owner.scan_jobs == {} and owner.model_test_jobs == {}
  printed = [str(call.args[0]) for call in owner.P.call_args_list if call.args]
  assert not any("Starting job" in line for line in printed)
  assert sum("Demo-only deployment" in line for line in printed) == 1


@pytest.mark.parametrize("kind", ["network", "model"])
def test_the_same_job_starts_when_the_deployment_is_not_demo_only(kind):
  plugin, owner, config, artifacts = _announced(kind)
  owner.cfg_redmesh_demo_only = False
  with patch.object(plugin, "_get_artifact_repository", return_value=artifacts), \
       patch.object(plugin, "_mark_worker_terminal_error"), \
       patch(f"{PLUGIN_MODULE}.resolve_job_config_secrets", return_value=config), \
       patch(f"{PLUGIN_MODULE}.launch_local_jobs", return_value={"worker": MagicMock()}) as launch, \
       patch(f"{PLUGIN_MODULE}.ModelTestWorker") as model_worker:
    if kind == "network":
      plugin._maybe_launch_jobs(owner)
    else:
      plugin._maybe_launch_model_test_jobs(owner)
  if kind == "network":
    launch.assert_called_once()
  else:
    model_worker.return_value.start.assert_called_once()
