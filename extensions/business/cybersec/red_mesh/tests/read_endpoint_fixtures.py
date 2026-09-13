"""Real read admission and projection fixtures; only external storage/framework are synthetic."""
from collections import deque
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.models.reports import AggregatedScanData
from . import test_api as api_fixtures
from .test_execution_binding_models import binding_payload
from .test_tenant_read_access import ReadStore
from .test_tenant_administration import FakeAdministrationStore


def install_legacy_read_store(case, owner, Plugin, *, jobs=None):
  """Migrate an existing effect fixture while keeping requester/control reads real and separate."""
  environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
  environment.start()
  case.addCleanup(environment.stop)
  store = FakeAdministrationStore()
  store.account("reader", role="admin")
  owner.cfg_tenancy_namespace = "deployment"
  owner.cfg_tenant_execution_enabled = False
  owner.cfg_tenant_execution_stage = "compatibility"
  tenant_store = CstoreTenantAdministrationStore(store, owner.cfg_tenancy_namespace)
  tenant_store.put("execution_rollout", owner.cfg_instance_id,
                   record={"stage": "compatibility", "enabled": False})
  control_hkey, _ = tenant_store._location("execution_rollout", (owner.cfg_instance_id,))
  original_get = getattr(owner, "chainstore_hget", lambda **kwargs: None)
  original_list = getattr(owner, "chainstore_hgetall", lambda **kwargs: {})
  def get(*, hkey, key):
    if hkey in ("auth", control_hkey):
      return store.chainstore_hget(hkey=hkey, key=key)
    if jobs is not None and hkey == owner.cfg_instance_id:
      return jobs.get(key)
    return original_get(hkey=hkey, key=key)
  def listing(*, hkey):
    if hkey in ("auth", control_hkey):
      return store.chainstore_hgetall(hkey=hkey)
    if jobs is not None and hkey == owner.cfg_instance_id:
      return jobs
    return original_list(hkey=hkey)
  owner.chainstore_hget, owner.chainstore_hgetall = get, listing
  owner._normalize_job_record = lambda key, record, **kwargs: Plugin._normalize_job_record(owner, key, record, **kwargs)
  return {"account_id": "reader"}


@contextmanager
def read_endpoint_fixture(*, bound=True, archived=True):
  with patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"}):
    Plugin = api_fixtures.TestPhase3Archive()._get_plugin_class()
    store = ReadStore()
    tenant_store = CstoreTenantAdministrationStore(store, "deployment")
    administration = TenantAdministrationService(CstoreAuthAccountReader(store), tenant_store)
    request_id = str(uuid4())
    prepared = administration.prepare_tenant({"account_id": "creator"}, request_id,
      "Read fixture", "read-fixture", "initial")
    assert prepared["success"], prepared
    tenant_id = prepared["data"]["tenantId"]
    store.grant("initial", tenant_id)
    activated = administration.activate_tenant({"account_id": "creator"}, request_id)
    assert activated["success"], activated
    store.account("reader", role="admin", memberships=[{"role": "tenant_admin", "tenant_id": tenant_id}]
                  if bound else None)
    tenant_store.put("execution_rollout", store.cfg_instance_id,
                     record={"stage": "compatibility", "enabled": False})
    binding = {**binding_payload(), "tenant_id": tenant_id}
    job = {"job_id": "job-1", "target": "192.0.2.10", "scan_type": "network",
           "job_status": "FINALIZED" if archived else "RUNNING", "launcher": "node-a",
           "workers": {}, "pass_reports": [] if archived else [{"pass_nr": 1, "report_cid": "pass"}]}
    config = {"target": job["target"]}
    if bound:
      job["execution_binding"] = binding
      config["execution_binding"] = deepcopy(binding)
    pass_report = {"pass_nr": 1, "llm_analysis": "Associated analysis", "quick_summary": "Summary",
                   "aggregated_report_cid": "aggregate", "worker_reports": {"node-a": {"report_cid": "worker"}},
                   "findings": [{"finding_id": "finding-1", "title": "Fixture finding"}]}
    artifacts = {"pass": pass_report, "aggregate": AggregatedScanData(
      open_ports=[443], service_info={}, web_tests_info={}, completed_tests=[]).to_dict(),
                 "worker": {"job_id": "job-1", "worker_addr": "node-a", "open_ports": [443]},
                 "archive": {"job_id": "job-1", "job_config": config, "passes": [deepcopy(pass_report)]}}
    if archived:
      job["job_cid"] = "archive"
    store.jobs["job-1" if bound else "legacy-alias"] = job
    artifact_reads = []
    def get_json(cid, **kwargs):
      artifact_reads.append((cid, kwargs))
      value = artifacts.get(cid)
      if isinstance(value, Exception):
        raise value
      return value
    owner = SimpleNamespace(cfg_instance_id=store.cfg_instance_id, cfg_tenancy_namespace="deployment",
      cfg_tenant_execution_enabled=False, cfg_tenant_execution_stage="compatibility", cfg_chainstore_peers=[],
      chainstore_hget=store.chainstore_hget, chainstore_hgetall=store.chainstore_hgetall,
      chainstore_hset=store.chainstore_hset, r1fs=SimpleNamespace(get_json=get_json),
      scan_jobs={"job-1": {}}, model_test_jobs={}, time=lambda: 100.0,
      _audit_log=deque([{"job_id": "foreign", "event": "private"}, {"job_id": "job-1", "event": "visible"}]))
    owner._normalize_job_record = lambda key, record, **kwargs: Plugin._normalize_job_record(owner, key, record, **kwargs)
    store.reads.clear()
    yield SimpleNamespace(Plugin=Plugin, owner=owner, store=store, actor={"account_id": "reader"},
      tenant_id=tenant_id if bound else None, job=job, artifacts=artifacts, artifact_reads=artifact_reads,
      administration=administration, tenant_store=tenant_store)
