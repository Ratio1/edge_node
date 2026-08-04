from ...findings import Finding, Severity, probe_result, probe_error
from ...cve_db import check_cves
from ...constants import resolve_target_response_timeout


class _ServiceProbeBase:
  """
  Base mixin providing shared utilities for service probe sub-mixins.

  Subclasses inherit ``_emit_metadata`` for recording scan metadata and
  have direct access to the ``findings``, ``cve_db`` helpers via module-
  level imports.
  """

  def _target_timeout(self, standard_timeout):
    """Resolve target waits, defaulting lightweight probe fixtures to Standard."""
    return resolve_target_response_timeout(
      getattr(self, "timeout_profile", None), standard_timeout,
    )

  def _emit_metadata(self, category, key_or_item, value=None):
    """Safely append to scan_metadata sub-dicts without crashing if state is uninitialized."""
    meta = self.state.get("scan_metadata")
    if meta is None:
      return
    bucket = meta.get(category)
    if bucket is None:
      return
    if isinstance(bucket, dict):
      bucket[key_or_item] = value
    elif isinstance(bucket, list):
      bucket.append(key_or_item)
