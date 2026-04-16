from ..models import JobArchive, JobConfig, PassReport


def _coerce_job_config_dict(payload):
  raw = dict(payload or {})
  raw.setdefault("target", raw.get("target_url", ""))
  raw.setdefault("start_port", 0)
  raw.setdefault("end_port", 0)
  return raw


class ArtifactRepository:
  """Repository for durable RedMesh artifacts stored in R1FS."""

  def __init__(self, owner):
    self.owner = owner

  def get_json(self, cid, *, secret=None):
    if not cid:
      return None
    if secret:
      return self.owner.r1fs.get_json(cid, secret=secret)
    return self.owner.r1fs.get_json(cid)

  def put_json(self, payload, *, show_logs=False, secret=None):
    if secret:
      return self.owner.r1fs.add_json(payload, show_logs=show_logs, secret=secret)
    return self.owner.r1fs.add_json(payload, show_logs=show_logs)

  def delete(self, cid, *, show_logs=False, raise_on_error=False):
    if not cid:
      return False
    return self.owner.r1fs.delete_file(cid, show_logs=show_logs, raise_on_error=raise_on_error)

  def get_job_config(self, job_specs):
    return self.get_json((job_specs or {}).get("job_config_cid"))

  def get_job_config_model(self, job_specs):
    payload = self.get_job_config(job_specs)
    if not isinstance(payload, dict):
      return None
    return JobConfig.from_dict(_coerce_job_config_dict(payload))

  def put_job_config(self, job_config, *, show_logs=False):
    if isinstance(job_config, JobConfig):
      payload = job_config.to_dict()
    else:
      payload = JobConfig.from_dict(_coerce_job_config_dict(job_config)).to_dict()
    return self.put_json(payload, show_logs=show_logs)

  def get_pass_report(self, report_cid):
    return self.get_json(report_cid)

  def get_pass_report_model(self, report_cid):
    payload = self.get_pass_report(report_cid)
    if not isinstance(payload, dict):
      return None
    return PassReport.from_dict(payload)

  def put_pass_report(self, pass_report, *, show_logs=False):
    if isinstance(pass_report, PassReport):
      payload = pass_report.to_dict()
    else:
      payload = PassReport.from_dict(pass_report).to_dict()
    return self.put_json(payload, show_logs=show_logs)

  def get_archive(self, job_specs):
    return self.get_json((job_specs or {}).get("job_cid"))

  def get_archive_model(self, job_specs):
    payload = self.get_archive(job_specs)
    if not isinstance(payload, dict):
      return None
    return JobArchive.from_dict(payload)

  def put_archive(self, archive, *, show_logs=False):
    if isinstance(archive, JobArchive):
      payload = archive.to_dict()
    else:
      payload = JobArchive.from_dict(archive).to_dict()
    return self.put_json(payload, show_logs=show_logs)
