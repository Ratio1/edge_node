"""Real read admission and projection fixtures; only external storage/framework are synthetic."""
from collections import deque
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.models.reports import AggregatedScanData
from . import test_api as api_fixtures
from .test_execution_binding_models import binding_payload
from .test_tenant_read_access import ReadStore
from .test_tenant_administration import FakeAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.policy import PLATFORM_ROLES

_SAME_TENANT = object()


def install_tenant_read_store(case, owner, Plugin, *, jobs=None, role="super_tenant_admin"):
  """A reader that admits through a real tenant (RM-084 P2; the only kind since P6).

  Every supplied job record is bound to that tenant, since the tenant reader returns only records
  it owns -- with the binding its own launch would have written: its assigned workers as the
  participants, and a model asset for a model test. An archive read for a bound job carries the same
  binding in its `job_config`, as the finalizer writes it; the artifact reader refuses one that does
  not. Returns `(actor, tenant_id)` for the call under test.
  """
  environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
  environment.start()
  case.addCleanup(environment.stop)
  store = FakeAdministrationStore()
  owner.cfg_tenancy_namespace = "deployment"
  owner.cfg_chainstore_peers = []
  tenant_store = CstoreTenantAdministrationStore(store, owner.cfg_tenancy_namespace)
  administration = TenantAdministrationService(CstoreAuthAccountReader(store), tenant_store)
  request_id = str(uuid4())
  prepared = administration.prepare_tenant({"account_id": "creator"}, request_id,
    "Read fixture", "read-fixture", "initial")
  assert prepared["success"], prepared
  tenant_id = prepared["data"]["tenantId"]
  store.grant("initial", tenant_id)
  activated = administration.activate_tenant({"account_id": "creator"}, request_id)
  assert activated["success"], activated
  store.account("reader", memberships=[
    {"role": role, "tenant_id": None if role in PLATFORM_ROLES else tenant_id}])
  bound = {key: {**record, "execution_binding": _binding_for(record, tenant_id)}
           for key, record in (jobs or {}).items()}
  original_get = getattr(owner, "chainstore_hget", lambda **kwargs: None)
  original_list = getattr(owner, "chainstore_hgetall", lambda **kwargs: {})
  # Identity lives under the auth hkey and tenancy under a JSON-encoded one; every other hash
  # (the plugin's own records) keeps whatever the caller's fixture already installed.
  def ours(hkey):
    return hkey == "auth" or hkey.startswith('["redmesh"')

  def get(*, hkey, key):
    if hkey == owner.cfg_instance_id:
      return deepcopy(bound.get(key))
    if ours(hkey):
      return store.chainstore_hget(hkey=hkey, key=key)
    return original_get(hkey=hkey, key=key)

  def listing(*, hkey):
    if hkey == owner.cfg_instance_id:
      return deepcopy(bound)
    if ours(hkey):
      return store.chainstore_hgetall(hkey=hkey)
    return original_list(hkey=hkey)

  owner.chainstore_hget, owner.chainstore_hgetall = get, listing
  read_json = getattr(getattr(owner, "r1fs", None), "get_json", None)
  if read_json is not None:
    def get_json(cid, *args, **kwargs):
      payload = read_json(cid, *args, **kwargs)
      job = bound.get(payload.get("job_id")) if isinstance(payload, dict) else None
      if job is not None and isinstance(payload.get("job_config"), dict):
        payload = {**payload, "job_config": {**payload["job_config"],
                                             "execution_binding": deepcopy(job["execution_binding"])}}
      return payload
    # Still a mock, so a suite can assert on how the artifact was read (never pinned, say).
    owner.r1fs.get_json = MagicMock(side_effect=get_json)
  owner._normalize_job_record = lambda key, record, **kwargs: Plugin._normalize_job_record(owner, key, record, **kwargs)
  return {"account_id": "reader"}, tenant_id


def _binding_for(record, tenant_id):
  binding = {**binding_payload(), "tenant_id": tenant_id}
  workers = record.get("workers") if isinstance(record, dict) else None
  if isinstance(workers, dict) and workers:
    binding["participant_order"] = list(workers)
  if isinstance(record, dict) and (record.get("job_type") == "model_test" or record.get("scan_type") == "model_test"):
    target = {"kind": "model", "adapter": "openai_compatible", "model": "fixture",
              "endpointUrl": "https://192.0.2.1/v1/chat/completions"}
    binding.update(asset_target=target, asset_target_digest=canonical_digest(target),
                   participant_order=binding["participant_order"][:1])
  return binding


@contextmanager
def read_endpoint_fixture(*, bound=True, archived=True, role="tenant_admin"):
  """`role` is the bound reader's single membership; a platform role carries `tenant_id: None`."""
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
    store.account("reader", memberships=[{"role": role,
                                "tenant_id": None if role in PLATFORM_ROLES else tenant_id}]
                  if bound else None)
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
      cfg_chainstore_peers=[],
      chainstore_hget=store.chainstore_hget, chainstore_hgetall=store.chainstore_hgetall,
      chainstore_hset=store.chainstore_hset, r1fs=SimpleNamespace(get_json=get_json),
      scan_jobs={"job-1": {}}, model_test_jobs={}, time=lambda: 100.0,
      _audit_log=deque([{"job_id": "foreign", "event": "private"}, {"job_id": "job-1", "event": "visible"}]))
    owner._normalize_job_record = lambda key, record, **kwargs: Plugin._normalize_job_record(owner, key, record, **kwargs)
    store.reads.clear()
    yield SimpleNamespace(Plugin=Plugin, owner=owner, store=store, actor={"account_id": "reader"},
      tenant_id=tenant_id if bound else None, job=job, artifacts=artifacts, artifact_reads=artifact_reads,
      administration=administration, tenant_store=tenant_store)


def as_role(fixture, role, *, tenant_id=_SAME_TENANT):
  """Replace the fixture reader's memberships with one row (RM-084: the only authority there is).

  A platform role carries `tenant_id: None`; a tenant-local role defaults to the fixture's tenant.
  Returns the tenant the call should name, so a test reads as one line.
  """
  local = tenant_id is _SAME_TENANT
  row = {"role": role, "tenant_id": None if role in PLATFORM_ROLES
         else fixture.tenant_id if local else tenant_id}
  fixture.store.data[("auth", "reader")]["memberships"] = [row]
  return fixture.tenant_id if local or role in PLATFORM_ROLES else tenant_id


def allow_pentester(fixture, enabled=True):
  """Flip the fixture tenant's Allow Pentester switch.

  RM-084 P3 binds `analysis:run` and `authorization:upload` to it, so a suite exercising either has
  to say which side of the switch it is on rather than inherit the default (off).
  """
  tenant = fixture.tenant_store.get("tenant", fixture.tenant_id)
  fixture.tenant_store.put("tenant", fixture.tenant_id,
                           record={**tenant, "allow_pentester": bool(enabled)})
  return fixture.tenant_id
