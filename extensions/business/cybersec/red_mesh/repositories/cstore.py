from ..models import CStoreJobFinalized, CStoreJobRunning, WorkerProgress


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

  def get_job(self, job_id):
    return self.owner.chainstore_hget(hkey=self._jobs_hkey, key=job_id)

  def get_running_job(self, job_id):
    payload = self.get_job(job_id)
    if not isinstance(payload, dict) or payload.get("job_cid"):
      return None
    return CStoreJobRunning.from_dict(payload)

  def get_finalized_job(self, job_id):
    payload = self.get_job(job_id)
    if not isinstance(payload, dict) or not payload.get("job_cid"):
      return None
    return CStoreJobFinalized.from_dict(payload)

  def list_jobs(self):
    return self.owner.chainstore_hgetall(hkey=self._jobs_hkey)

  def put_job(self, job_id, value):
    self.owner.chainstore_hset(hkey=self._jobs_hkey, key=job_id, value=value)
    return value

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
