"""
MISP export mixin for PentesterApi01Plugin.

Exposes four endpoints:
  - export_misp        — push scan results to a configured MISP server
  - export_misp_json   — download MISP-format JSON (no server needed)
  - get_misp_export_status  — check if a job has been exported
  - get_misp_export_config_status — check if MISP is enabled/configured (no secrets)
"""

from ..services import misp_export as _misp_export_service
from ..services.misp_config import get_misp_export_config
from ..services.misp_export import (
  _UNSET,
  export_misp_json,
  get_misp_export_status,
)


class _MispExportMixin:

  def _get_misp_export_config(self, tenant_id=None):
    """Return MISP config status (no secrets exposed)."""
    cfg = get_misp_export_config(self, tenant_id)
    return {
      "enabled": cfg["ENABLED"],
      "auto_export": cfg["AUTO_EXPORT"],
      "misp_configured": bool(cfg["MISP_URL"] and cfg["MISP_API_KEY"]),
      "min_severity": cfg["MIN_SEVERITY"],
    }

  def _build_misp_json(self, job_id, pass_nr=None, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
    """Build MISP JSON for download (no MISP server required)."""
    if checked_job is not _UNSET:
      from ..tenancy.administration import AdministrationDenied
      from ..tenancy.job_artifacts import checked_job_snapshot
      job = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
      if pass_nr is not None and (type(pass_nr) is not int or pass_nr < 1):
        raise AdministrationDenied(400, "invalid_request")
      cfg = get_misp_export_config(self)
      if not cfg["ENABLED"]:
        return {"status": "disabled"}
      # The tenant's MISP record decides the event's distribution and severity
      # floor, so a bound job without one has nothing to build from. Said as a
      # typed denial: it is a configuration state, and collapsing it into the
      # read guard's `unavailable` told the operator it was an outage (RM-090).
      _tenant_id, binding_error = _misp_export_service.tenant_export_binding(self, checked_job, "misp")
      if binding_error:
        raise AdministrationDenied(409, binding_error)
      return export_misp_json(self, job_id, pass_nr=pass_nr, checked_job=job, snapshot_mode=snapshot_mode)
    from ..tenancy.job_artifacts import validate_snapshot_mode
    validate_snapshot_mode(snapshot_mode, snapshot_supplied=False)
    cfg = get_misp_export_config(self)
    if not cfg["ENABLED"]:
      return {"status": "disabled"}
    try:
      return export_misp_json(self, job_id, pass_nr=pass_nr)
    except Exception as exc:
      self.P(f"[MISP] JSON export exception for job {job_id}: {exc}", color='r')
      return {"status": "error", "error": str(exc)}

  def _get_misp_export_status(self, job_id):
    """Check whether a job has been exported to MISP."""
    return get_misp_export_status(self, job_id)
