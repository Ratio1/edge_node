import secrets

from ..models import (
  CStoreJobFinalized,
  CStoreJobRunning,
  FindingTriageAuditEntry,
  FindingTriageState,
  ReportReviewAuditEntry,
  ReportReviewState,
  RulebookReviewAuditEntry,
  RulebookReviewState,
  RulebookSubmissionRegistry,
  WorkerProgress,
)
from ..tenancy.execution import triage_scope


RUNNING_JOB_REQUIRED_FIELDS = {
  "job_id",
  "job_status",
  "run_mode",
  "launcher",
  "target",
  "start_port",
  "end_port",
  "date_created",
  "job_config_cid",
}


class JobStateRepository:
  """Repository for mutable RedMesh job state stored in CStore."""

  def __init__(self, owner):
    self.owner = owner

  @property
  def _jobs_hkey(self):
    return self.owner.cfg_instance_id

  @property
  def _live_hkey(self):
    return f"{self.owner.cfg_instance_id}:live"

  # RM-127: each node's self-published public IP, keyed by the node's address.
  @property
  def _node_info_hkey(self):
    return f"{self.owner.cfg_instance_id}:node_info"

  @property
  def _triage_hkey(self):
    return f"{self.owner.cfg_instance_id}:triage"

  @property
  def _triage_audit_hkey(self):
    return f"{self.owner.cfg_instance_id}:triage:audit"

  # Host-scoped triage (report-findings.md §Triage). The `t:` prefix keeps these disjoint from the
  # legacy `{cfg}:triage` and `{cfg}:triage:audit` hkeys and from the audit hkeys below.
  def host_triage_hkey(self, tenant_id):
    return f"{self.owner.cfg_instance_id}:triage:t:{self._scope_part(tenant_id)}"

  def host_triage_audit_hkey(self, tenant_id):
    return f"{self.owner.cfg_instance_id}:triage:audit:{self._scope_part(tenant_id)}"

  @staticmethod
  def _scope_part(value):
    if not isinstance(value, str) or not value.strip() or "\x1f" in value:
      raise ValueError("Invalid triage scope")
    return value

  @classmethod
  def host_triage_key(cls, host, finding_id):
    return f"{cls._scope_part(host)}\x1f{cls._scope_part(finding_id)}"

  @property
  def _model_test_raw_evidence_hkey(self):
    return f"{self.owner.cfg_instance_id}:model_test_raw_evidence"

  @property
  def _rulebook_review_hkey(self):
    return f"{self.owner.cfg_instance_id}:rulebook_review"

  @property
  def _rulebook_review_audit_hkey(self):
    return f"{self.owner.cfg_instance_id}:rulebook_review:audit"

  @property
  def _rulebook_review_submissions_hkey(self):
    return f"{self.owner.cfg_instance_id}:rulebook_review:submissions"

  # Report-level review (RM-086 item 4): its own hashes, keyed by job id, like
  # the rulebook review; never on the job record, never in the archive.
  @property
  def _report_review_hkey(self):
    return f"{self.owner.cfg_instance_id}:report_review"

  @property
  def _report_review_audit_hkey(self):
    return f"{self.owner.cfg_instance_id}:report_review:audit"

  def get_job(self, job_id):
    return self.owner.chainstore_hget(hkey=self._jobs_hkey, key=job_id)

  def _coerce_job_payload(self, value):
    if isinstance(value, CStoreJobRunning):
      return value.to_dict()
    if isinstance(value, CStoreJobFinalized):
      return value.to_dict()
    if not isinstance(value, dict):
      return value
    payload = dict(value)
    if payload.get("job_cid"):
      try:
        return CStoreJobFinalized.from_dict(payload).to_dict()
      except (KeyError, TypeError, ValueError):
        return payload
    if RUNNING_JOB_REQUIRED_FIELDS.issubset(payload):
      try:
        return CStoreJobRunning.from_dict(payload).to_dict()
      except (KeyError, TypeError, ValueError):
        return payload
    return payload

  def get_running_job(self, job_id):
    payload = self.get_job(job_id)
    if not isinstance(payload, dict) or payload.get("job_cid"):
      return None
    try:
      return CStoreJobRunning.from_dict(payload)
    except (KeyError, TypeError, ValueError):
      return None

  def get_finalized_job(self, job_id):
    payload = self.get_job(job_id)
    if not isinstance(payload, dict) or not payload.get("job_cid"):
      return None
    try:
      return CStoreJobFinalized.from_dict(payload)
    except (KeyError, TypeError, ValueError):
      return None

  def list_jobs(self):
    return self.owner.chainstore_hgetall(hkey=self._jobs_hkey)

  def put_job(self, job_id, value):
    payload = self._coerce_job_payload(value)
    self.owner.chainstore_hset(hkey=self._jobs_hkey, key=job_id, value=payload)
    return payload

  def put_running_job(self, job):
    if isinstance(job, CStoreJobRunning):
      payload = job.to_dict()
    else:
      payload = CStoreJobRunning.from_dict(job).to_dict()
    return self.put_job(payload["job_id"], payload)

  def put_finalized_job(self, job):
    if isinstance(job, CStoreJobFinalized):
      payload = job.to_dict()
    else:
      payload = CStoreJobFinalized.from_dict(job).to_dict()
    return self.put_job(payload["job_id"], payload)

  def delete_job(self, job_id):
    self.owner.chainstore_hset(hkey=self._jobs_hkey, key=job_id, value=None)
    return

  def list_live_progress(self):
    return self.owner.chainstore_hgetall(hkey=self._live_hkey)

  def get_live_progress(self, key):
    return self.owner.chainstore_hget(hkey=self._live_hkey, key=key)

  def get_live_progress_model(self, key):
    payload = self.get_live_progress(key)
    if not isinstance(payload, dict):
      return None
    return WorkerProgress.from_dict(payload)

  def put_live_progress(self, key, value):
    self.owner.chainstore_hset(hkey=self._live_hkey, key=key, value=value)
    return value

  def list_node_info(self):
    return self.owner.chainstore_hgetall(hkey=self._node_info_hkey)

  def put_node_info(self, node_address, value):
    # A short, single attempt: the publish runs inside `process()` and is retried by the caller.
    # `chainstore_hset` answers False for an unconfirmed write; the caller retries on it.
    return self.owner.chainstore_hset(hkey=self._node_info_hkey, key=node_address, value=value, timeout=2, max_retries=0)

  @staticmethod
  def _safe_int(value, default=0):
    try:
      return int(value)
    except (TypeError, ValueError):
      return default

  @staticmethod
  def _uses_ordered_progress(payload):
    if not isinstance(payload, dict):
      return False
    return (
      payload.get("job_type") == "model_test"
      or payload.get("scan_type") == "model_test"
      or payload.get("schema_version") == "model_test_progress_v1"
      or "progress_sequence" in payload
    )

  @staticmethod
  def _is_terminal_progress(payload):
    if not isinstance(payload, dict):
      return False
    phase = str(payload.get("phase") or "").lower()
    return bool(payload.get("finished")) or phase in {"done", "failed", "canceled"}

  def _should_accept_live_progress(self, key, payload):
    existing = self.get_live_progress(key)
    if not isinstance(existing, dict):
      return True, existing
    if not (
      self._uses_ordered_progress(existing)
      or self._uses_ordered_progress(payload)
    ):
      return True, existing

    existing_revision = self._safe_int(existing.get("assignment_revision_seen"), 1)
    incoming_revision = self._safe_int(payload.get("assignment_revision_seen"), 1)
    if incoming_revision < existing_revision:
      return False, existing
    if incoming_revision > existing_revision:
      return True, existing

    existing_sequence = self._safe_int(existing.get("progress_sequence"), 0)
    incoming_sequence = self._safe_int(payload.get("progress_sequence"), 0)
    if existing_sequence and not incoming_sequence:
      return False, existing
    if incoming_sequence and existing_sequence and incoming_sequence <= existing_sequence:
      return False, existing

    if self._is_terminal_progress(existing) and not self._is_terminal_progress(payload):
      return False, existing

    return True, existing

  def put_live_progress_model(self, progress):
    if isinstance(progress, WorkerProgress):
      payload = progress.to_dict()
    else:
      payload = WorkerProgress.from_dict(progress).to_dict()
    key = f"{payload['job_id']}:{payload['worker_addr']}"
    accepted, existing = self._should_accept_live_progress(key, payload)
    if not accepted:
      return existing
    return self.put_live_progress(key, payload)

  def delete_live_progress(self, key):
    self.owner.chainstore_hset(hkey=self._live_hkey, key=key, value=None)
    return

  def get_model_test_raw_evidence(self, job_id):
    return self.owner.chainstore_hget(
      hkey=self._model_test_raw_evidence_hkey,
      key=job_id,
    )

  def put_model_test_raw_evidence(self, job_id, value):
    self.owner.chainstore_hset(
      hkey=self._model_test_raw_evidence_hkey,
      key=job_id,
      value=value,
    )
    return value

  def delete_model_test_raw_evidence(self, job_id):
    self.owner.chainstore_hset(
      hkey=self._model_test_raw_evidence_hkey,
      key=job_id,
      value=None,
    )
    return

  # Legacy job-keyed triage (`{cfg}:triage`, `{cfg}:triage:audit`, field `{job_id}:{finding_id}`): no reader uses
  # it any more and nothing writes it. It stays only so a purge can delete what an older release left.
  @staticmethod
  def legacy_triage_key(job_id, finding_id):
    return f"{job_id}:{finding_id}"

  def legacy_list_job_triage(self, job_id):
    payload = self.owner.chainstore_hgetall(hkey=self._triage_hkey) or {}
    prefix = f"{job_id}:"
    return {
      key[len(prefix):]: value
      for key, value in payload.items()
      if isinstance(key, str) and key.startswith(prefix) and isinstance(value, dict)
    }

  def legacy_list_job_triage_audit(self, job_id):
    payload = self.owner.chainstore_hgetall(hkey=self._triage_audit_hkey) or {}
    prefix = f"{job_id}:"
    return {
      key[len(prefix):]: value
      for key, value in payload.items()
      if isinstance(key, str) and key.startswith(prefix) and isinstance(value, list)
    }

  def get_host_triage(self, tenant_id, host, finding_id):
    """The stored value as is (None when absent); a caller that trusts it validates its shape."""
    return self.owner.chainstore_hget(
      hkey=self.host_triage_hkey(tenant_id), key=self.host_triage_key(host, finding_id))

  def list_host_triage(self, tenant_id, host):
    """`finding_id -> record` of one tenant's host. Another tenant's hkey is never read."""
    payload = self.owner.chainstore_hgetall(hkey=self.host_triage_hkey(tenant_id)) or {}
    prefix = f"{self._scope_part(host)}\x1f"
    return {
      key[len(prefix):]: value
      for key, value in payload.items()
      if isinstance(key, str) and key.startswith(prefix) and isinstance(value, dict)
    }

  def list_triage_for_record(self, record):
    """The host triage map of the tenant and host a job record is bound to, never a caller's.

    `{}` for a record with no binding, a malformed one, or a target without triage (a model job).
    """
    binding = record.get("execution_binding") if isinstance(record, dict) else None
    scope = triage_scope(binding) if binding is not None else None
    return self.list_host_triage(*scope) if scope else {}

  def put_host_triage(self, triage):
    """Store a state that names its tenant and host; returns the stored payload."""
    payload = (triage if isinstance(triage, FindingTriageState) else FindingTriageState.from_dict(triage)).to_dict()
    self.owner.chainstore_hset(
      hkey=self.host_triage_hkey(payload.get("tenant_id")),
      key=self.host_triage_key(payload.get("host"), payload["finding_id"]),
      value=payload,
    )
    return payload

  # The audit is append-only: one field per entry, so nodes writing the same (tenant, host, finding) never
  # overwrite one another. `chainstore_hkeys` lists fields from local memory (tombstones included).
  HOST_AUDIT_KEEP = 50
  _HOST_AUDIT_HEAL = 5

  @classmethod
  def host_triage_audit_prefix(cls, host, finding_id):
    return f"{cls.host_triage_key(host, finding_id)}\x1f"

  def _host_audit_fields(self, tenant_id, host, finding_id):
    """The entry fields of one (host, finding), oldest first (the entry id sorts by time)."""
    prefix = self.host_triage_audit_prefix(host, finding_id)
    fields = self.owner.chainstore_hkeys(hkey=self.host_triage_audit_hkey(tenant_id)) or []
    return sorted(f for f in fields if isinstance(f, str) and f.startswith(prefix) and "\x1f" not in f[len(prefix):])

  def get_host_triage_audit(self, tenant_id, host, finding_id):
    """The newest `HOST_AUDIT_KEEP` entries of one (host, finding), oldest first."""
    hkey = self.host_triage_audit_hkey(tenant_id)
    entries = (self.owner.chainstore_hget(hkey=hkey, key=field)
               for field in self._host_audit_fields(tenant_id, host, finding_id)[-self.HOST_AUDIT_KEEP:])
    return [entry for entry in entries if isinstance(entry, dict)]

  def append_host_triage_audit(self, entry):
    """Write one entry under its own field, then prune what fell out of the newest `HOST_AUDIT_KEEP`.

    The prune is best effort: a concurrent writer may leave a few extra entries, never lose a recent one.
    Returns the stored entry.
    """
    payload = (entry if isinstance(entry, FindingTriageAuditEntry)
               else FindingTriageAuditEntry.from_dict(entry)).to_dict()
    tenant_id, host = payload.get("tenant_id"), payload.get("host")
    hkey = self.host_triage_audit_hkey(tenant_id)
    entry_id = f"{int(payload.get('timestamp', 0) * 1000):015d}-{secrets.token_hex(4)}"
    self.owner.chainstore_hset(
      hkey=hkey, key=f"{self.host_triage_audit_prefix(host, payload['finding_id'])}{entry_id}", value=payload)
    try:
      old = self._host_audit_fields(tenant_id, host, payload["finding_id"])[:-self.HOST_AUDIT_KEEP]
      for field in old[-self._HOST_AUDIT_HEAL:]:
        if self.owner.chainstore_hget(hkey=hkey, key=field) is not None:
          self.owner.chainstore_hset(hkey=hkey, key=field, value=None)
    except Exception:
      pass
    return payload

  def legacy_delete_job_triage(self, job_id):
    for finding_id in list(self.legacy_list_job_triage(job_id)):
      self.owner.chainstore_hset(
        hkey=self._triage_hkey,
        key=self.legacy_triage_key(job_id, finding_id),
        value=None,
      )
    for finding_id in list(self.legacy_list_job_triage_audit(job_id)):
      self.owner.chainstore_hset(
        hkey=self._triage_audit_hkey,
        key=self.legacy_triage_key(job_id, finding_id),
        value=None,
      )
    return

  @staticmethod
  def rulebook_key(job_id, profile_id):
    return f"{job_id}:{profile_id}"

  def get_rulebook_review(self, job_id, profile_id):
    return self.owner.chainstore_hget(
      hkey=self._rulebook_review_hkey,
      key=self.rulebook_key(job_id, profile_id),
    )

  def get_rulebook_review_model(self, job_id, profile_id):
    payload = self.get_rulebook_review(job_id, profile_id)
    if not isinstance(payload, dict):
      return None
    return RulebookReviewState.from_dict(payload)

  def put_rulebook_review(self, review):
    if isinstance(review, RulebookReviewState):
      payload = review.to_dict()
    else:
      payload = RulebookReviewState.from_dict(review).to_dict()
    self.owner.chainstore_hset(
      hkey=self._rulebook_review_hkey,
      key=self.rulebook_key(payload["job_id"], payload["profile_id"]),
      value=payload,
    )
    return payload

  def get_rulebook_review_audit(self, job_id, profile_id):
    payload = self.get_rulebook_review_audit_raw(job_id, profile_id)
    return payload if isinstance(payload, list) else []

  def get_rulebook_review_audit_raw(self, job_id, profile_id):
    """Preserve malformed versus absent records for checked read boundaries."""
    return self.owner.chainstore_hget(
      hkey=self._rulebook_review_audit_hkey,
      key=self.rulebook_key(job_id, profile_id),
    )

  def append_rulebook_review_audit(self, entry):
    if isinstance(entry, RulebookReviewAuditEntry):
      payload = entry.to_dict()
    else:
      payload = RulebookReviewAuditEntry.from_dict(entry).to_dict()
    key = self.rulebook_key(payload["job_id"], payload["profile_id"])
    audit_log = list(self.get_rulebook_review_audit(payload["job_id"], payload["profile_id"]))
    audit_log.append(payload)
    self.owner.chainstore_hset(hkey=self._rulebook_review_audit_hkey, key=key, value=audit_log)
    return audit_log

  def get_rulebook_submission_registry(self, job_id, profile_id):
    return self.owner.chainstore_hget(
      hkey=self._rulebook_review_submissions_hkey,
      key=self.rulebook_key(job_id, profile_id),
    )

  def get_rulebook_submission_registry_model(self, job_id, profile_id):
    payload = self.get_rulebook_submission_registry(job_id, profile_id)
    if not isinstance(payload, dict):
      return None
    return RulebookSubmissionRegistry.from_dict(payload)

  def put_rulebook_submission_registry(self, job_id, profile_id, registry):
    if isinstance(registry, RulebookSubmissionRegistry):
      payload = registry.to_dict()
    else:
      payload = RulebookSubmissionRegistry.from_dict(registry).to_dict()
    self.owner.chainstore_hset(
      hkey=self._rulebook_review_submissions_hkey,
      key=self.rulebook_key(job_id, profile_id),
      value=payload,
    )
    return payload

  def list_job_rulebook_submission_registries(self, job_id):
    payload = self.owner.chainstore_hgetall(hkey=self._rulebook_review_submissions_hkey) or {}
    prefix = f"{job_id}:"
    return {
      key[len(prefix):]: value
      for key, value in payload.items()
      if isinstance(key, str) and key.startswith(prefix) and isinstance(value, dict)
    }

  @staticmethod
  def report_review_key(job_id, pass_nr):
    return f"{job_id}:{int(pass_nr)}"

  def get_report_review(self, job_id, pass_nr):
    return self.owner.chainstore_hget(hkey=self._report_review_hkey,
                                      key=self.report_review_key(job_id, pass_nr))

  def get_report_review_model(self, job_id, pass_nr):
    payload = self.get_report_review(job_id, pass_nr)
    if not isinstance(payload, dict):
      return None
    return ReportReviewState.from_dict(payload)

  def list_job_report_review_models(self, job_id, latest_pass_nr):
    """Every pass's row for one job, by pass number, through keyed reads of passes 1..latest.

    Keyed rather than a hash enumeration, so a tenant-scoped read touches only
    this job's rows.
    """
    rows = {}
    for pass_nr in range(1, int(latest_pass_nr) + 1):
      model = self.get_report_review_model(job_id, pass_nr)
      if model is not None:
        rows[pass_nr] = model
    return rows

  def put_report_review(self, review):
    if isinstance(review, ReportReviewState):
      payload = review.to_dict()
    else:
      payload = ReportReviewState.from_dict(review).to_dict()
    self.owner.chainstore_hset(hkey=self._report_review_hkey,
                               key=self.report_review_key(payload["job_id"], payload["pass_nr"]),
                               value=payload)
    return payload

  def get_report_review_audit(self, job_id):
    payload = self.owner.chainstore_hget(hkey=self._report_review_audit_hkey, key=job_id)
    return payload if isinstance(payload, list) else []

  def append_report_review_audit(self, entry):
    if isinstance(entry, ReportReviewAuditEntry):
      payload = entry.to_dict()
    else:
      payload = ReportReviewAuditEntry.from_dict(entry).to_dict()
    audit_log = list(self.get_report_review_audit(payload["job_id"]))
    audit_log.append(payload)
    self.owner.chainstore_hset(hkey=self._report_review_audit_hkey, key=payload["job_id"], value=audit_log)
    return audit_log

  def delete_job_report_review(self, job_id):
    prefix = f"{job_id}:"
    payload = self.owner.chainstore_hgetall(hkey=self._report_review_hkey) or {}
    for key in list(payload if isinstance(payload, dict) else {}):
      if isinstance(key, str) and (key == job_id or key.startswith(prefix)):
        self.owner.chainstore_hset(hkey=self._report_review_hkey, key=key, value=None)
    self.owner.chainstore_hset(hkey=self._report_review_audit_hkey, key=job_id, value=None)
    return

  def delete_job_rulebook_reviews(self, job_id):
    prefix = f"{job_id}:"
    for hkey in (
      self._rulebook_review_hkey,
      self._rulebook_review_audit_hkey,
      self._rulebook_review_submissions_hkey,
    ):
      payload = self.owner.chainstore_hgetall(hkey=hkey) or {}
      if not isinstance(payload, dict):
        continue
      for key in list(payload):
        if isinstance(key, str) and key.startswith(prefix):
          self.owner.chainstore_hset(hkey=hkey, key=key, value=None)
    return
