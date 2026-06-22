"""
MISP export mixin for PentesterApi01Plugin.

Exposes four endpoints:
  - export_misp        — push scan results to a configured MISP server
  - export_misp_json   — download MISP-format JSON (no server needed)
  - get_misp_export_status  — check if a job has been exported
  - get_misp_export_config_status — check if MISP is enabled/configured (no secrets)
"""

from ..services.misp_config import get_misp_export_config
from ..services.misp_export import (
  export_misp_json,
  get_misp_export_status,
  push_to_misp,
)


class _MispExportMixin:

  def _get_misp_export_config(self):
    """Return MISP config status (no secrets exposed)."""
    cfg = get_misp_export_config(self)
    return {
      "enabled": cfg["ENABLED"],
      "auto_export": cfg["AUTO_EXPORT"],
      "misp_configured": bool(cfg["MISP_URL"] and cfg["MISP_API_KEY"]),
      "min_severity": cfg["MIN_SEVERITY"],
    }

  def _export_to_misp(self, job_id, pass_nr=None):
    """Push job results to configured MISP instance."""
    cfg = get_misp_export_config(self)
    if not cfg["ENABLED"]:
      self.P("[MISP] MISP export is disabled. Skipping.", color='y')
      return {"status": "disabled"}
    if not cfg["MISP_URL"] or not cfg["MISP_API_KEY"]:
      self.P("[MISP] MISP URL or API key not configured. Skipping.", color='y')
      return {"status": "not_configured", "error": "MISP URL or API key not configured"}
    try:
      result = push_to_misp(self, job_id, pass_nr=pass_nr)
      if result.get("status") == "ok":
        self.P(
          f"[MISP] Export success for job {job_id}: "
          f"event {result.get('event_uuid')}, "
          f"{result.get('findings_exported')} findings, "
          f"{result.get('ports_exported')} ports",
          color='g'
        )
      else:
        self.P(f"[MISP] Export failed for job {job_id}: {result.get('error')}", color='y')
      return result
    except Exception as exc:
      self.P(f"[MISP] Export exception for job {job_id}: {exc}", color='r')
      return {"status": "error", "error": str(exc), "retryable": True}

  def _build_misp_json(self, job_id, pass_nr=None):
    """Build MISP JSON for download (no MISP server required)."""
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
