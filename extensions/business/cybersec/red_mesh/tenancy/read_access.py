"""Current-reader authorization for internal job snapshots, not an endpoint or cached lease."""
from copy import deepcopy

from .administration import AdministrationDenied
from .execution import binding_from_record
from .identity import resolve_actor
from .ports import TenantStoreError


class TenantReadAccess:
  def __init__(self, administration, jobs):
    self.administration = administration
    self.jobs = jobs

  def _authorize(self, actor, tenant_id):
    account, denial = resolve_actor(actor, self.administration.accounts)
    if denial:
      raise AdministrationDenied(denial["status_code"], denial["error"])
    self.administration.authorize_tenant_for_account(account, tenant_id, "reports:view")

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

  def get_job(self, actor, tenant_id, job_id):
    """Return a detached raw job only after fresh identity and tenant publication checks."""
    self._authorize(actor, tenant_id)
    try:
      record = self.jobs.get_job(job_id)
    except Exception:
      raise TenantStoreError("Tenant job storage is unavailable") from None
    snapshot = self._snapshot(record, tenant_id, job_id)
    if snapshot is None:
      raise AdministrationDenied(404, "not_found")
    return snapshot

  def list_jobs(self, actor, tenant_id):
    """Filter ownership before validation/projection; never publish a partial corrupt list."""
    self._authorize(actor, tenant_id)
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
