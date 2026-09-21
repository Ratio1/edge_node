"""Current-reader authorization for internal job snapshots, not an endpoint or cached lease."""
from copy import deepcopy

from .administration import AdministrationDenied
from .execution import binding_from_record
from .identity import resolve_actor
from .ports import TenantStoreError


# RM-078. A fixed set, not "anything the matrix contains": a future matrix entry must not reach
# tenant reads without its own decision. `reports:view` and `audit:view` are the original two; the
# three effect operations are the ones the owner specified, and each endpoint still opts in within
# its own slice (B6, B8, B9) rather than by appearing here.
_TENANT_OPERATIONS = frozenset({
  "reports:view", "audit:view", "analysis:run", "engagement:delete", "jobs:purge",
  "reports:export",  # stop_monitoring (RM-026 MVP)
  "evidence:read"})  # get_raw_model_test_evidence (RM-084 P2)


class TenantReadAccess:
  def __init__(self, administration, jobs):
    self.administration = administration
    self.jobs = jobs

  def _authorize(self, actor, tenant_id, operation):
    account, denial = resolve_actor(actor, self.administration.accounts)
    if denial:
      raise AdministrationDenied(denial["status_code"], denial["error"])
    if operation not in _TENANT_OPERATIONS:
      raise AdministrationDenied(403, "forbidden")
    self.administration.authorize_tenant_for_account(account, tenant_id, operation)

  def _owns_record(self, record, tenant_id):
    if not isinstance(record, dict):
      return False
    raw_binding = record.get("execution_binding")
    return (isinstance(raw_binding, dict)
            and raw_binding.get("namespace") == self.administration.store.namespace
            and raw_binding.get("tenant_id") == tenant_id)

  def _snapshot(self, record, tenant_id, job_id):
    # Classify ownership before parsing: corrupt foreign/unattributed rows are not ours.
    if not self._owns_record(record, tenant_id):
      return None
    try:
      snapshot = deepcopy(record)
      if not self._owns_record(snapshot, tenant_id):
        return None
      binding_from_record(snapshot)
      if not isinstance(job_id, str) or not job_id.strip() or snapshot.get("job_id") != job_id:
        raise ValueError("Invalid job storage key")
      return snapshot
    except Exception:
      raise TenantStoreError("Tenant job storage is unavailable") from None

  def get_job(self, actor, tenant_id, job_id, *, operation="reports:view"):
    """Return a detached raw job only after fresh identity and tenant publication checks."""
    self._authorize(actor, tenant_id, operation)
    try:
      record = self.jobs.get_job(job_id)
    except Exception:
      raise TenantStoreError("Tenant job storage is unavailable") from None
    snapshot = self._snapshot(record, tenant_id, job_id)
    if snapshot is None:
      raise AdministrationDenied(404, "not_found")
    return snapshot

  def list_jobs(self, actor, tenant_id, *, operation="reports:view"):
    """Filter ownership before validation/projection; never publish a partial corrupt list."""
    self._authorize(actor, tenant_id, operation)
    try:
      records = self.jobs.list_jobs()
      if not isinstance(records, dict):
        raise TypeError("Invalid job enumeration")
      items = tuple(records.items())
    except Exception:
      raise TenantStoreError("Tenant job storage is unavailable") from None
    result = {}
    for job_id, record in items:
      snapshot = self._snapshot(record, tenant_id, job_id)
      if snapshot is not None:
        result[job_id] = snapshot
    return result
