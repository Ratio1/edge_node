class ArtifactRepository:
  """Repository for durable RedMesh artifacts stored in R1FS."""

  def __init__(self, owner):
    self.owner = owner

  def get_json(self, cid):
    if not cid:
      return None
    return self.owner.r1fs.get_json(cid)

  def put_json(self, payload, *, show_logs=False):
    return self.owner.r1fs.add_json(payload, show_logs=show_logs)

  def delete(self, cid, *, show_logs=False, raise_on_error=False):
    if not cid:
      return False
    return self.owner.r1fs.delete_file(cid, show_logs=show_logs, raise_on_error=raise_on_error)

  def get_job_config(self, job_specs):
    return self.get_json((job_specs or {}).get("job_config_cid"))

  def get_pass_report(self, report_cid):
    return self.get_json(report_cid)

  def get_archive(self, job_specs):
    return self.get_json((job_specs or {}).get("job_cid"))
