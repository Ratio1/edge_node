"""
Base class for graybox probe modules.

Provides shared utilities, error recovery, and capability declarations.
Probes receive fully initialized collaborators — they don't manage
sessions or credentials themselves.
"""

import requests

from ..findings import GrayboxFinding
from ..models import GrayboxProbeContext


class ProbeBase:
  """
  Shared utilities for graybox probe modules.

  Probes receive fully initialized collaborators — they don't manage
  sessions or credentials themselves.

  Capability declarations: subclasses set class-level attributes to
  declare their requirements. The worker introspects these after loading
  the class from the registry. No capability flags in the registry.
  """

  # Capability declarations — override in subclasses.
  requires_auth: bool = True
  requires_regular_session: bool = False
  is_stateful: bool = False

  def __init__(self, target_url, auth_manager, target_config, safety,
               discovered_routes=None, discovered_forms=None,
               regular_username="", allow_stateful=False):
    self.target_url = target_url.rstrip("/")
    self.auth = auth_manager
    self.target_config = target_config
    self.safety = safety
    self.discovered_routes = discovered_routes or []
    self.discovered_forms = discovered_forms or []
    self.regular_username = regular_username
    self._allow_stateful = allow_stateful
    self.findings: list[GrayboxFinding] = []

  @classmethod
  def from_context(cls, context: GrayboxProbeContext):
    """Build a probe from a typed worker-provided context."""
    return cls(**context.to_kwargs())

  def run_safe(self, probe_name, probe_fn):
    """
    Run a probe with error recovery.

    Does NOT call ensure_sessions — the worker is responsible for session
    lifecycle. Probes just use self.auth.official_session /
    self.auth.regular_session as-is.
    """
    try:
      probe_fn()
    except requests.exceptions.ConnectionError:
      self._record_error(probe_name, "target_unreachable")
    except requests.exceptions.Timeout:
      self._record_error(probe_name, "request_timeout")
    except Exception as exc:
      self._record_error(probe_name, self.safety.sanitize_error(str(exc)))

  def _record_error(self, probe_name, error_msg):
    """Store a non-fatal error as an INFO GrayboxFinding."""
    self.findings.append(GrayboxFinding(
      scenario_id=f"ERR-{probe_name}",
      title=f"Probe error: {probe_name}",
      status="inconclusive",
      severity="INFO",
      owasp="",
      evidence=[f"error={error_msg}"],
      error=error_msg,
    ))
