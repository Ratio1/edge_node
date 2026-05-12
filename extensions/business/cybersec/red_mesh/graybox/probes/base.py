"""
Base class for graybox probe modules.

Provides shared utilities, error recovery, and capability declarations.
Probes receive fully initialized collaborators — they don't manage
sessions or credentials themselves.
"""

import requests

from ..findings import GrayboxFinding
from ..models import GrayboxProbeContext, GrayboxProbeRunResult


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
               regular_username="", allow_stateful=False,
               request_budget=None):
    self.target_url = target_url.rstrip("/")
    self.auth = auth_manager
    self.target_config = target_config
    self.safety = safety
    self.discovered_routes = discovered_routes or []
    self.discovered_forms = discovered_forms or []
    self.regular_username = regular_username
    self._allow_stateful = allow_stateful
    # OWASP API Top 10 — Subphase 1.7. Optional shared RequestBudget.
    # When None, `self.budget()` always returns True (no enforcement).
    self.request_budget = request_budget
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

  def build_result(self, outcome: str = "completed", artifacts=None) -> GrayboxProbeRunResult:
    """Return a typed probe result without changing legacy run() contracts."""
    return GrayboxProbeRunResult(
      findings=list(self.findings),
      artifacts=list(artifacts or []),
      outcome=outcome,
    )

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

  # ── OWASP API Top 10 emit helpers (Subphase 1.6) ─────────────────────
  #
  # These wrap GrayboxFinding construction so probe authors don't repeat
  # the boilerplate and so finding emission has a single point at which
  # evidence redaction is enforced. The redaction itself is added in
  # Subphase 1.6 commit #2 (centralised scrubber).
  #
  # ATT&CK defaults: when ``attack`` is None, the helper resolves the
  # default mapping from the catalog via attack_for_scenario(scenario_id)
  # so probes don't have to remember per-scenario technique IDs.

  def _resolve_attack(self, scenario_id, attack):
    if attack is not None:
      return list(attack)
    try:
      from ..scenario_catalog import attack_for_scenario
    except ImportError:
      return []
    return attack_for_scenario(scenario_id)

  def _configured_secret_field_names(self):
    """Read the configured API-key header/query names from target_config.

    Returned as a tuple suitable for `scrub_graybox_secrets`. Falls back
    to () when ApiSecurityConfig.auth is absent.
    """
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return ()
    auth = getattr(api_security, "auth", None)
    if auth is None:
      return ()
    names = []
    if auth.api_key_header_name:
      names.append(auth.api_key_header_name)
    if auth.api_key_query_param:
      names.append(auth.api_key_query_param)
    if auth.bearer_token_header_name:
      names.append(auth.bearer_token_header_name)
    return tuple(names)

  def _scrub_for_emission(self, value):
    """Pre-emission scrub. Defense-in-depth alongside the storage-boundary
    scrubber in ``findings.to_flat_finding`` (Subphase 1.6 commit #2)."""
    from ..findings import scrub_graybox_secrets
    return scrub_graybox_secrets(
      value, secret_field_names=self._configured_secret_field_names(),
    )

  def emit_vulnerable(self, scenario_id, title, severity, owasp, cwe,
                       evidence, *, attack=None, evidence_artifacts=None,
                       replay_steps=None, remediation=None):
    """Append a vulnerable GrayboxFinding using the catalog's ATT&CK default."""
    self.findings.append(GrayboxFinding(
      scenario_id=scenario_id,
      title=self._scrub_for_emission(title),
      status="vulnerable",
      severity=severity,
      owasp=owasp,
      cwe=list(cwe or []),
      attack=self._resolve_attack(scenario_id, attack),
      evidence=self._scrub_for_emission(list(evidence or [])),
      evidence_artifacts=self._scrub_for_emission(list(evidence_artifacts or [])),
      replay_steps=self._scrub_for_emission(list(replay_steps or [])),
      remediation=self._scrub_for_emission(remediation or ""),
    ))

  def emit_clean(self, scenario_id, title, owasp, evidence):
    """Append a not_vulnerable / INFO GrayboxFinding (test ran OK, nothing found)."""
    self.findings.append(GrayboxFinding(
      scenario_id=scenario_id,
      title=self._scrub_for_emission(title),
      status="not_vulnerable",
      severity="INFO",
      owasp=owasp,
      evidence=self._scrub_for_emission(list(evidence or [])),
    ))

  def emit_inconclusive(self, scenario_id, title, owasp, reason):
    """Append an inconclusive / INFO GrayboxFinding.

    Use when a scenario could not be evaluated (missing config, stateful
    gating disabled, request budget exhausted, target returned an
    unexpected shape, etc.). ``reason`` is a short machine-readable
    string appended to the evidence as ``reason=<value>`` so reports can
    group inconclusives by cause.
    """
    self.findings.append(GrayboxFinding(
      scenario_id=scenario_id,
      title=self._scrub_for_emission(title),
      status="inconclusive",
      severity="INFO",
      owasp=owasp,
      evidence=[f"reason={self._scrub_for_emission(reason)}"],
    ))
