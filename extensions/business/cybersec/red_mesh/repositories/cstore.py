from ..models import (
  CStoreJobFinalized,
  CStoreJobRunning,
  FindingTriageAuditEntry,
  FindingTriageState,
  WorkerProgress,
)


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

  @property
  def _triage_hkey(self):
    return f"{self.owner.cfg_instance_id}:triage"

  @property
  def _triage_audit_hkey(self):
    return f"{self.owner.cfg_instance_id}:triage:audit"

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

  def put_live_progress_model(self, progress):
    if isinstance(progress, WorkerProgress):
      payload = progress.to_dict()
    else:
      payload = WorkerProgress.from_dict(progress).to_dict()
    key = f"{payload['job_id']}:{payload['worker_addr']}"
    return self.put_live_progress(key, payload)

  def delete_live_progress(self, key):
    self.owner.chainstore_hset(hkey=self._live_hkey, key=key, value=None)
    return

  @staticmethod
  def triage_key(job_id, finding_id):
    return f"{job_id}:{finding_id}"

  def get_finding_triage(self, job_id, finding_id):
    return self.owner.chainstore_hget(
      hkey=self._triage_hkey,
      key=self.triage_key(job_id, finding_id),
    )

  def get_finding_triage_model(self, job_id, finding_id):
    payload = self.get_finding_triage(job_id, finding_id)
    if not isinstance(payload, dict):
      return None
    return FindingTriageState.from_dict(payload)

  def list_job_triage(self, job_id):
    payload = self.owner.chainstore_hgetall(hkey=self._triage_hkey) or {}
    prefix = f"{job_id}:"
    return {
      key[len(prefix):]: value
      for key, value in payload.items()
      if isinstance(key, str) and key.startswith(prefix) and isinstance(value, dict)
    }

  def list_job_triage_models(self, job_id):
    return {
      finding_id: FindingTriageState.from_dict(value)
      for finding_id, value in self.list_job_triage(job_id).items()
    }

  def put_finding_triage(self, triage):
    if isinstance(triage, FindingTriageState):
      payload = triage.to_dict()
    else:
      payload = FindingTriageState.from_dict(triage).to_dict()
    self.owner.chainstore_hset(
      hkey=self._triage_hkey,
      key=self.triage_key(payload["job_id"], payload["finding_id"]),
      value=payload,
    )
    return payload

  def get_finding_triage_audit(self, job_id, finding_id):
    payload = self.owner.chainstore_hget(
      hkey=self._triage_audit_hkey,
      key=self.triage_key(job_id, finding_id),
    )
    return payload if isinstance(payload, list) else []

  def list_job_triage_audit(self, job_id):
    payload = self.owner.chainstore_hgetall(hkey=self._triage_audit_hkey) or {}
    prefix = f"{job_id}:"
    return {
      key[len(prefix):]: value
      for key, value in payload.items()
      if isinstance(key, str) and key.startswith(prefix) and isinstance(value, list)
    }

  def append_finding_triage_audit(self, entry):
    if isinstance(entry, FindingTriageAuditEntry):
      payload = entry.to_dict()
    else:
      payload = FindingTriageAuditEntry.from_dict(entry).to_dict()
    key = self.triage_key(payload["job_id"], payload["finding_id"])
    audit_log = list(self.get_finding_triage_audit(payload["job_id"], payload["finding_id"]))
    audit_log.append(payload)
    self.owner.chainstore_hset(hkey=self._triage_audit_hkey, key=key, value=audit_log)
    return audit_log

  def delete_job_triage(self, job_id):
    for finding_id in list(self.list_job_triage(job_id)):
      self.owner.chainstore_hset(
        hkey=self._triage_hkey,
        key=self.triage_key(job_id, finding_id),
        value=None,
      )
    for finding_id in list(self.list_job_triage_audit(job_id)):
      self.owner.chainstore_hset(
        hkey=self._triage_audit_hkey,
        key=self.triage_key(job_id, finding_id),
        value=None,
      )
    return
