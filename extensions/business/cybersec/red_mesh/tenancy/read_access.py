"""Current-reader authorization for internal job snapshots, not an endpoint or cached lease."""
from copy import deepcopy

from .administration import AdministrationDenied
from .execution import ExecutionRollout, binding_from_record
from .identity import TenantMembership, resolve_actor
from .ports import TenantStoreError


# RM-078. A fixed set, not "anything the matrix contains": a future matrix entry must not reach
# tenant reads without its own decision. `reports:view` and `audit:view` are the original two; the
# three effect operations are the ones the owner specified, and each endpoint still opts in within
# its own slice (B6, B8, B9) rather than by appearing here.
_TENANT_OPERATIONS = frozenset({
  "reports:view", "audit:view", "analysis:run", "engagement:delete", "jobs:purge",
  "reports:export"})  # stop_monitoring (RM-026 MVP)


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


class LegacyReadAccess:
  """Explicit compatibility reads; omission alone never establishes legacy authority.

  The trusted rollout callback must read current configured and stored controls on each call.
  Point lookup intentionally retains legacy whole-table/logical-ID semantics, without re-reading
  global state after the operation's detached snapshots have been checked.
  """

  def __init__(self, administration, jobs, normalize, read_rollout):
    self.administration = administration
    self.jobs = jobs
    self.normalize = normalize
    self.read_rollout = read_rollout

  def _authorize(self, actor, operation):
    account, denial = resolve_actor(actor, self.administration.accounts)
    if denial:
      raise AdministrationDenied(denial["status_code"], denial["error"])
    if account.tenant_memberships_present is not False or operation not in ("reports:view", "audit:view", "reports:export"):
      raise AdministrationDenied(403, "forbidden")
    if operation == "reports:export" and account.role != "admin" and account.app_role != "pentester":
      raise AdministrationDenied(403, "forbidden")
    if operation == "audit:view" and TenantMembership("super_tenant_admin", None) not in account.tenant_memberships:
      raise AdministrationDenied(403, "forbidden")
    try:
      rollout = self.read_rollout()
      if not isinstance(rollout, ExecutionRollout):
        raise ValueError("Invalid rollout reader result")
    except Exception:
      raise TenantStoreError("Legacy read controls are unavailable") from None
    if not rollout.allows_new(bound=False, membership_key_present=False, selectors_omitted=True):
      raise AdministrationDenied(403, "forbidden")

  @staticmethod
  def _reserve_bound_ids(reserved, key, record):
    for identifier in (key, record.get("job_id")):
      if isinstance(identifier, str) and identifier.strip():
        reserved.add(identifier)

  def _snapshots(self):
    try:
      records = self.jobs.list_jobs()
      if not isinstance(records, dict):
        raise ValueError("Invalid job enumeration")
      items = tuple(records.items())
      result = {}
      logical_ids = set()
      reserved = set()
      for key, raw in items:
        if not isinstance(raw, dict):
          continue
        if "execution_binding" in raw:
          self._reserve_bound_ids(reserved, key, raw)
          continue
        snapshot = deepcopy(raw)
        if "execution_binding" in snapshot:
          self._reserve_bound_ids(reserved, key, snapshot)
          continue
        if not isinstance(key, str) or not key.strip():
          raise ValueError("Invalid legacy storage key")
        normalized_key, normalized = self.normalize(key, snapshot, migrate=False)
        normalized = deepcopy(normalized)
        if (normalized_key != key or not isinstance(normalized, dict) or "execution_binding" in normalized
            or not isinstance(normalized.get("job_id"), str) or not normalized["job_id"].strip()
            or normalized["job_id"] in logical_ids):
          raise ValueError("Invalid or ambiguous legacy job identity")
        logical_ids.add(normalized["job_id"])
        result[key] = normalized
      if reserved.intersection(logical_ids) or reserved.intersection(result):
        raise ValueError("Ambiguous legacy and bound job identity")
      return result
    except Exception:
      raise TenantStoreError("Legacy job storage is unavailable") from None

  def get_job(self, actor, job_id, *, operation="reports:view"):
    self._authorize(actor, operation)
    snapshots = self._snapshots()
    for record in snapshots.values():
      if record["job_id"] == job_id:
        return record
    raise AdministrationDenied(404, "not_found")

  def list_jobs(self, actor, *, operation="reports:view"):
    self._authorize(actor, operation)
    return self._snapshots()
