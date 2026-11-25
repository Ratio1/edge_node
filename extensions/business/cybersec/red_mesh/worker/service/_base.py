import socket
import time

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

  @staticmethod
  def _deadline_in(seconds):
    return time.monotonic() + seconds

  def _recv_by(self, sock, size, deadline, read_timeout=3):
    """`sock.recv(size)` that gives up at `deadline` (time.monotonic) or when the job is stopped.

    One read waits at most the profile's timeout for `read_timeout`, and never past the deadline.
    """
    stop = getattr(self, "stop_event", None)
    remaining = deadline - time.monotonic()
    if remaining <= 0 or (stop is not None and stop.is_set()):
      raise socket.timeout("probe deadline")
    sock.settimeout(min(remaining, self._target_timeout(read_timeout)))
    return sock.recv(size)

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
