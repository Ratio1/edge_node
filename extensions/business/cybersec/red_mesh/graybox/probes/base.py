"""
Base class for graybox probe modules.

Provides shared utilities, error recovery, and capability declarations.
Probes receive fully initialized collaborators — they don't manage
sessions or credentials themselves.
"""

import requests

from ..findings import GrayboxFinding
from ..models import GrayboxProbeContext, GrayboxProbeRunResult
from ..rollback import MUTATION_ATTEMPTED_UNKNOWN, StatefulMutationPlan


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
               request_budget=None, allowed_scenario_ids=None,
               rollback_journal=None, job_id="", worker_id="",
               assignment_revision=0):
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
    self.allowed_scenario_ids = (
      None if allowed_scenario_ids is None else set(allowed_scenario_ids)
    )
    self.rollback_journal = rollback_journal
    self.job_id = job_id
    self.worker_id = worker_id
    self.assignment_revision = assignment_revision
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
    except requests.exceptions.ConnectionError as exc:
      self._record_error(probe_name, self._error_with_detail("target_unreachable", exc))
    except requests.exceptions.Timeout as exc:
      self._record_error(probe_name, self._error_with_detail("request_timeout", exc))
    except Exception as exc:
      self._record_error(probe_name, self._sanitize_error(str(exc)))

  def scenario_enabled(self, scenario_id: str) -> bool:
    """Return whether this worker is allowed to execute ``scenario_id``."""
    if self.allowed_scenario_ids is None:
      return True
    return scenario_id in self.allowed_scenario_ids

  def run_safe_scenario(self, scenario_id: str, probe_name: str, probe_fn):
    """Run a scenario only when the worker assignment permits it."""
    if not self.scenario_enabled(scenario_id):
      return
    self.run_safe(probe_name, probe_fn)

  def run_runtime_scenarios(self, probe_key: str):
    """Run assigned runtime-manifest scenarios for one probe family."""
    from ..scenario_runtime import runtime_scenarios_for_probe

    for scenario in runtime_scenarios_for_probe(probe_key):
      if not self.scenario_enabled(scenario.scenario_id):
        continue
      runner = getattr(self, scenario.runner)
      self.run_safe_scenario(
        scenario.scenario_id,
        scenario.runner.lstrip("_"),
        runner,
      )
    return self.findings

  def build_result(self, outcome: str = "completed", artifacts=None) -> GrayboxProbeRunResult:
    """Return a typed probe result without changing legacy run() contracts."""
    return GrayboxProbeRunResult(
      findings=list(self.findings),
      artifacts=list(artifacts or []),
      outcome=outcome,
    )

  # ── Stateful probe contract (Subphase 1.8) ──────────────────────────
  #
  # Every mutating check must implement: baseline → mutate → verify
  # → revert → cleanup-evidence. `StatefulProbeMixin.run_stateful`
  # orchestrates the four steps and the helper below builds the matching
  # finding. The lint test in test_stateful_contract.py asserts that no
  # stateful probe bypasses this path.
  STATEFUL_PROBE_LINT_MARKER = "uses_run_stateful"
  MUTATION_ATTEMPTED_UNKNOWN = MUTATION_ATTEMPTED_UNKNOWN

  def run_stateful(self, scenario_id, *, baseline_fn, mutate_fn,
                    verify_fn, revert_fn, finding_kwargs=None,
                    skip_reason_no_revert="no_revert_path_configured",
                    mutation_unverified_reason_fn=None,
                    no_mutation_reason_fn=None,
                    mutation_plan=None,
                    clean_when_verify_false=False):
    """Run a four-step stateful check.

    Steps:
      1. baseline_fn() -> baseline state (any pickle-safe value).
      2. mutate_fn(baseline) -> True if the mutation appeared to land.
      3. verify_fn(baseline) -> True if state actually changed
         (i.e. the vulnerability is confirmed).
      4. revert_fn(baseline) -> True if the revert succeeded.

    Emits one GrayboxFinding via emit_vulnerable / emit_clean with the
    `rollback_status` field populated on the finding. If the probe is
    not gated on `allow_stateful=True`, emits inconclusive
    (`stateful_probes_disabled`). If `revert_fn` is None, emits
    inconclusive (`no_revert_path_configured` by default).

    `finding_kwargs` supplies the title/severity/owasp/etc. for the
    vulnerable case. The clean case reuses ``title`` and ``owasp``.
    """
    finding_kwargs = dict(finding_kwargs or {})
    title = finding_kwargs.pop("title", scenario_id)
    owasp = finding_kwargs.pop("owasp", "")

    if not self.scenario_enabled(scenario_id):
      return False
    if not self._allow_stateful:
      self.emit_inconclusive(scenario_id, title, owasp,
                              "stateful_probes_disabled")
      return False
    if revert_fn is None:
      self.emit_inconclusive(scenario_id, title, owasp, skip_reason_no_revert)
      return False

    # 1. Baseline.
    try:
      baseline = baseline_fn()
    except Exception as exc:
      self.emit_inconclusive(
        scenario_id, title, owasp,
        f"baseline_failed:{self.safety.sanitize_error(str(exc))}",
      )
      return False

    # 2. Mutate. Journal before invoking mutate_fn so a timeout/crash
    # after the outbound request still leaves a cleanup record.
    journal_record_id = ""
    if self.rollback_journal is not None:
      plan = mutation_plan
      if plan is None:
        plan = StatefulMutationPlan(
          scenario_id=scenario_id,
          principal=getattr(self, "regular_username", "") or "",
        )
      journal_record_id = self.rollback_journal.record_pending(scenario_id, plan)
    mutated = False
    mutation_attempted_unknown = False
    try:
      mutate_result = mutate_fn(baseline)
      if mutate_result == MUTATION_ATTEMPTED_UNKNOWN:
        mutated = True
        mutation_attempted_unknown = True
      else:
        mutated = bool(mutate_result)
    except Exception as exc:
      self.emit_inconclusive(
        scenario_id, title, owasp,
        f"mutate_failed:{self.safety.sanitize_error(str(exc))}",
      )
      if journal_record_id:
        self.rollback_journal.update_status(
          journal_record_id, "mutation_failed",
        )
      return False

    # 3. Verify.
    confirmed = False
    verify_failed_reason = ""
    if mutated:
      try:
        confirmed = bool(verify_fn(baseline))
        if not confirmed:
          verify_failed_reason = (
            "mutation_attempted_unknown"
            if mutation_attempted_unknown else "mutation_unverified"
          )
      except Exception as exc:
        confirmed = False
        detail = self._sanitize_error(str(exc))
        verify_failed_reason = f"verify_failed:{detail}" if detail else "verify_failed"

    # 4. Revert (always attempt — even if not confirmed, the mutate may
    #    have left the target in an unintended state).
    rollback_status = "no_revert_needed" if not mutated else "revert_failed"
    if mutated:
      try:
        if revert_fn(baseline):
          rollback_status = "reverted"
      except Exception:
        rollback_status = "revert_failed"
    if journal_record_id:
      journal_status = {
        "no_revert_needed": "not_attempted",
        "reverted": "reverted",
        "revert_failed": "manual_cleanup_required",
      }.get(rollback_status, rollback_status)
      self.rollback_journal.update_status(
        journal_record_id,
        journal_status,
        rollback_status=rollback_status,
      )

    # 5. Emit. Confirmed = vulnerable. A mutation that cannot be verified
    # is inconclusive, not clean: the target may have changed, or request
    # budget/transport may have prevented confirmation.
    if confirmed:
      severity = finding_kwargs.pop("severity", "HIGH")
      # Severity bump on revert failure: HIGH→CRITICAL, MEDIUM→HIGH.
      if rollback_status == "revert_failed":
        severity = {"HIGH": "CRITICAL", "MEDIUM": "HIGH"}.get(severity, severity)
      cwe = finding_kwargs.pop("cwe", [])
      evidence = list(finding_kwargs.pop("evidence", []))
      remediation = finding_kwargs.pop("remediation", "")
      if rollback_status == "revert_failed":
        remediation = (
          (remediation + " ").strip()
          + " Manual cleanup required — see Replay Steps."
        )
      self.emit_vulnerable(
        scenario_id, title, severity, owasp, cwe, evidence,
        remediation=remediation,
        rollback_status=rollback_status,
        **finding_kwargs,
      )
      return True
    elif mutated:
      reason = verify_failed_reason or "mutation_unverified"
      if clean_when_verify_false and reason == "mutation_unverified":
        self.emit_clean(
          scenario_id, title, owasp,
          list(finding_kwargs.get("evidence", []) or []),
          rollback_status=rollback_status,
        )
        return False
      if callable(mutation_unverified_reason_fn):
        try:
          reason = mutation_unverified_reason_fn(baseline, rollback_status) or reason
        except Exception as exc:
          detail = self._sanitize_error(str(exc))
          reason = f"verify_reason_failed:{detail}" if detail else reason
      self.emit_inconclusive(
        scenario_id, title, owasp,
        reason,
        rollback_status=rollback_status,
      )
      return False
    else:
      reason = ""
      if callable(no_mutation_reason_fn):
        try:
          reason = no_mutation_reason_fn(baseline) or ""
        except Exception as exc:
          detail = self._sanitize_error(str(exc))
          reason = f"no_mutation_reason_failed:{detail}" if detail else ""
      if reason:
        self.emit_inconclusive(
          scenario_id, title, owasp, reason,
          rollback_status=rollback_status,
        )
        return False
      self.emit_clean(
        scenario_id, title, owasp,
        [],
        rollback_status=rollback_status,
      )
      return False

  def budget(self, n: int = 1) -> bool:
    """Consume ``n`` requests from the shared per-scan RequestBudget.

    Returns False (and records an exhaustion event on the budget object)
    when the budget can't cover the request. Probes that hit this should
    stop iteration and emit `inconclusive` with reason
    ``budget_exhausted``. Returns True when no budget is configured
    (legacy callers / tests without a budget).
    """
    if self.request_budget is None:
      return True
    return self.request_budget.consume(n)

  def cleanup_budget(self, n: int = 1) -> bool:
    """Return True for cleanup/revert requests.

    Cleanup requests are deliberately exempt from the normal probe
    request budget; budget exhaustion must not prevent rollback.
    """
    return True

  def request(self, session, method: str, url: str, **kwargs):
    """Probe-facing HTTP helper.

    Worker-created sessions are scoped by GrayboxHttpClient, so routing
    calls through the session keeps scope enforcement centralized while
    preserving the existing requests-like API.
    """
    return session.request(method, url, **kwargs)

  def stateful_request(self, session, method: str, url: str, **kwargs):
    """Issue a state-changing request through the scoped session wrapper."""
    return self.request(session, method, url, **kwargs)

  def _record_error(self, probe_name, error_msg):
    """Store a non-fatal error as an INFO GrayboxFinding."""
    error_msg = self._sanitize_error(error_msg)
    self.findings.append(GrayboxFinding(
      scenario_id=f"ERR-{probe_name}",
      title=f"Probe error: {probe_name}",
      status="inconclusive",
      severity="INFO",
      owasp="",
      evidence=[f"error={error_msg}"],
      error=error_msg,
    ))

  def _error_with_detail(self, code, exc):
    detail = self._sanitize_error(str(exc))
    if not detail:
      return code
    return f"{code}:{detail}"

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

    Returned as a tuple of strings suitable for `scrub_graybox_secrets`.
    Falls back to () when ApiSecurityConfig.auth is absent or the values
    are not strings (e.g. MagicMock fixtures in unit tests).
    """
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return ()
    auth = getattr(api_security, "auth", None)
    if auth is None:
      return ()
    names = []
    for attr in ("api_key_header_name", "api_key_query_param",
                  "bearer_token_header_name"):
      val = getattr(auth, attr, None)
      if isinstance(val, str) and val:
        names.append(val)
    return tuple(names)

  def _scrub_for_emission(self, value):
    """Pre-emission scrub. Defense-in-depth alongside the storage-boundary
    scrubber in ``findings.to_flat_finding`` (Subphase 1.6 commit #2)."""
    from ..findings import scrub_graybox_secrets
    return scrub_graybox_secrets(
      value, secret_field_names=self._configured_secret_field_names(),
    )

  def _sanitize_error(self, value):
    """Sanitize target-controlled exception text with configured secret names."""
    secret_field_names = self._configured_secret_field_names()
    try:
      sanitized = self.safety.sanitize_error(
        str(value), secret_field_names=secret_field_names,
      )
    except TypeError:
      sanitized = self.safety.sanitize_error(str(value))
    return self._scrub_for_emission(sanitized)

  def emit_vulnerable(self, scenario_id, title, severity, owasp, cwe,
                       evidence, *, attack=None, evidence_artifacts=None,
                       replay_steps=None, remediation=None,
                       rollback_status=""):
    """Append a vulnerable GrayboxFinding using the catalog's ATT&CK default.

    ``rollback_status`` is set by `run_stateful` for stateful probes;
    leave default for non-stateful findings.
    """
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
      rollback_status=rollback_status or "",
    ))

  def emit_clean(self, scenario_id, title, owasp, evidence,
                 *, rollback_status=""):
    """Append a not_vulnerable / INFO GrayboxFinding (test ran OK, nothing found)."""
    self.findings.append(GrayboxFinding(
      scenario_id=scenario_id,
      title=self._scrub_for_emission(title),
      status="not_vulnerable",
      severity="INFO",
      owasp=owasp,
      evidence=self._scrub_for_emission(list(evidence or [])),
      rollback_status=rollback_status or "",
    ))

  def emit_inconclusive(self, scenario_id, title, owasp, reason,
                        *, rollback_status=""):
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
      rollback_status=rollback_status or "",
    ))
