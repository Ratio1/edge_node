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

  def list_jobs(self):
    return self.owner.chainstore_hgetall(hkey=self._jobs_hkey)

  def put_job(self, job_id, value):
    self.owner.chainstore_hset(hkey=self._jobs_hkey, key=job_id, value=value)
    return value

  def delete_job(self, job_id):
    self.owner.chainstore_hset(hkey=self._jobs_hkey, key=job_id, value=None)
    return

  def list_live_progress(self):
    return self.owner.chainstore_hgetall(hkey=self._live_hkey)

  def get_live_progress(self, key):
    return self.owner.chainstore_hget(hkey=self._live_hkey, key=key)

  def put_live_progress(self, key, value):
    self.owner.chainstore_hset(hkey=self._live_hkey, key=key, value=value)
    return value

  def delete_live_progress(self, key):
    self.owner.chainstore_hset(hkey=self._live_hkey, key=key, value=None)
    return
