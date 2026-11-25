"""
Base class for graybox probe modules.

Provides shared utilities, error recovery, and capability declarations.
Probes receive fully initialized collaborators — they don't manage
sessions or credentials themselves.
"""

import requests

from ..findings import (
  GrayboxEvidenceArtifact,
  evidence_content_sha256,
  GrayboxFinding,
  location_from_evidence as _location_from_evidence,
)
from ..models import GrayboxProbeContext, GrayboxProbeRunResult
from ..rollback import MUTATION_ATTEMPTED_UNKNOWN, StatefulMutationPlan
from ..scenario_runtime import owns_legacy_families


_SNAPSHOT_MAX_CHARS = 2048
_SCRUB_WINDOW_CHARS = _SNAPSHOT_MAX_CHARS * 2


def _as_text(value) -> str:
  """Coerce a response attribute to text, tolerating types we did not expect."""
  if isinstance(value, str):
    return value
  if isinstance(value, bytes):
    return value.decode("utf-8", "replace")
  return ""


def _string_items(mapping) -> dict:
  """Header mapping as plain strings, dropping anything that will not coerce."""
  out = {}
  try:
    items = mapping.items()
  except Exception:
    return out
  try:
    for name, value in items:
      if isinstance(name, str) and isinstance(value, (str, bytes)):
        out[name] = _as_text(value)
  except Exception:
    return out
  return out


def _best_effort(builder, *args):
  """Run an evidence builder, returning None instead of raising.

  Evidence is supplementary; the finding is the product. A builder that raises
  propagates into `run_safe`, which converts the whole probe run into an error
  finding — so a response shape we did not anticipate would silently drop the
  vulnerability rather than merely fail to decorate it. Never let that trade
  happen.
  """
  try:
    return builder(*args)
  except Exception:
    return None


def _curl_reproduction(response, scrub):
  """Build a redacted, shell-safe `curl` line reproducing the triggering request.

  Derived from the captured request rather than hand-written by each probe, so
  it cannot drift from what was actually sent.

  Redaction matters more here than in a snapshot: this line is *designed* to be
  copied and run, so an Authorization header left in it hands a credential to
  whoever reads the report. Every component is `shlex.quote`d because the URL is
  target-controlled and must not be able to become a second shell command.

  Each component is scrubbed *before* it is quoted. Scrubbing the assembled line
  let a substitution reach inside the quoting a target had already been sealed
  into: a URL carrying both a quote character and a scrubber trigger came out
  with unbalanced quotes. That failed closed — bash rejected the line rather
  than running anything extra — but it left the reproduction unusable, and it
  only stayed harmless for as long as no scrubber pattern happened to produce a
  string that re-parses.
  """
  import shlex

  if response is None:
    return None
  request = getattr(response, "request", None)
  if request is None:
    return None
  method = (getattr(request, "method", "") or "GET").upper()
  url = getattr(request, "url", "") or getattr(response, "url", "") or ""
  if not url:
    return None

  def _safe(value):
    return shlex.quote(scrub(str(value)))

  parts = ["curl", "-i"]
  # GET is curl's default, so spelling it out is noise in something a reader
  # copies.
  if method != "GET":
    parts += ["-X", method]
  for name, value in _string_items(getattr(request, "headers", None)).items():
    parts += ["-H", _safe(f"{name}: {value}")]
  body = getattr(request, "body", None)
  if body:
    if isinstance(body, bytes):
      body = body.decode("utf-8", "replace")
    parts += ["--data-raw", _safe(body)]
  parts.append(_safe(url))
  return " ".join(parts)


def _artifact_from_response(response, scrub):
  """Build a redacted evidence artifact from the response that triggered a finding.

  `GrayboxEvidenceArtifact` was dead schema — zero constructions outside tests —
  so a finding carried no request/response evidence at all. Both snapshots go
  through the caller's scrubber before anything is retained: an artifact must
  not become a new route for archiving what the scrubber removes elsewhere.
  """
  from datetime import datetime, timezone

  if response is None:
    return None
  request = getattr(response, "request", None)
  method = getattr(request, "method", "") or ""
  url = getattr(request, "url", "") or getattr(response, "url", "") or ""
  request_headers = _string_items(getattr(request, "headers", None))
  request_body = getattr(request, "body", None)
  status = getattr(response, "status_code", "")
  response_headers = _string_items(getattr(response, "headers", None))
  body = _as_text(getattr(response, "text", ""))

  # Scrub over a window wider than what is kept, then truncate. Cutting first
  # split secrets that straddle the boundary, leaving a prefix the pattern no
  # longer matched — the retained half of an API key is still an API key. Any
  # secret with a character inside the retained region starts before it, so a
  # window of twice the limit contains the whole match; the extra is discarded
  # either way, which keeps the cost bounded on large bodies.
  request_snapshot = scrub("\n".join(
    [f"{method} {url}"]
    + [f"{name}: {value}" for name, value in request_headers.items()]
    + ([""] + [str(request_body)] if request_body else [])
  )[:_SCRUB_WINDOW_CHARS])[:_SNAPSHOT_MAX_CHARS]
  response_snapshot = scrub("\n".join(
    [f"HTTP {status}"]
    + [f"{name}: {value}" for name, value in response_headers.items()]
    + ["", body]
  )[:_SCRUB_WINDOW_CHARS])[:_SNAPSHOT_MAX_CHARS]

  latency_ms = 0
  elapsed = getattr(response, "elapsed", None)
  if elapsed is not None:
    try:
      latency_ms = int(round(float(elapsed.total_seconds()) * 1000))
    except (TypeError, ValueError, AttributeError):
      latency_ms = 0

  # Hashed after scrubbing, so the digest describes what is actually retained.
  digest = evidence_content_sha256(request_snapshot, response_snapshot)

  return GrayboxEvidenceArtifact(
    summary=f"{method} {url} -> HTTP {status}"[:_SNAPSHOT_MAX_CHARS],
    request_snapshot=request_snapshot,
    response_snapshot=response_snapshot,
    captured_at=datetime.now(timezone.utc).isoformat(),
    latency_ms=latency_ms,
    content_sha256=digest,
  )


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
               discovered_candidates=None,
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
    self.discovered_candidates = discovered_candidates or []
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
    """Run a legacy (non-manifest) family, on the legacy-owning worker only.

    Under SLICE the manifest divides the API scenarios but not these
    families, so every worker would repeat them; only slice index 0 runs them.
    """
    if not owns_legacy_families(getattr(self, "allowed_scenario_ids", None)):
      return
    self._run_guarded(probe_name, probe_fn)

  def _run_guarded(self, probe_name, probe_fn):
    """
    Run a probe with error recovery.

    Does NOT call ensure_sessions — the worker is responsible for session
    lifecycle. Probes just use self.auth.primary_session /
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

  def _api_auth_unverified(self) -> bool:
    """Return True when API auth was explicitly accepted without validation."""
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return False
    auth = getattr(api_security, "auth", None)
    if auth is None:
      return False
    auth_type = getattr(auth, "auth_type", "form") or "form"
    if auth_type not in ("bearer", "api_key"):
      return False
    probe_path = (getattr(auth, "authenticated_probe_path", "") or "").strip()
    return bool(getattr(auth, "allow_unverified_auth", False)) and not probe_path

  @staticmethod
  def _is_api_security_scenario(scenario_id: str) -> bool:
    return scenario_id.startswith("PT-OAPI") or scenario_id == "PT-API7-01"

  def _emit_auth_unverified(self, scenario_id: str):
    if any(
      f.scenario_id == scenario_id and "auth_unverified" in str(f.evidence)
      for f in self.findings
    ):
      return
    try:
      from ..scenario_catalog import graybox_scenario
      entry = graybox_scenario(scenario_id) or {}
    except ImportError:
      entry = {}
    self.emit_inconclusive(
      scenario_id,
      entry.get("title") or scenario_id,
      entry.get("owasp") or "",
      "auth_unverified",
    )

  def run_safe_scenario(self, scenario_id: str, probe_name: str, probe_fn):
    """Run a scenario only when the worker assignment permits it."""
    if not self.scenario_enabled(scenario_id):
      return
    if self._is_api_security_scenario(scenario_id) and self._api_auth_unverified():
      self._emit_auth_unverified(scenario_id)
      return
    self._run_guarded(probe_name, probe_fn)

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

    # 3. Verify. Only literal True confirms; the MUTATION_ATTEMPTED_UNKNOWN
    # sentinel (and any non-bool truthy value) must NEVER become a
    # vulnerable finding because Python truthiness collapsed uncertainty
    # into "confirmed" (PR406 B4).
    confirmed = False
    verify_failed_reason = ""
    if mutated:
      try:
        verify_result = verify_fn(baseline)
        if verify_result is True:
          confirmed = True
        else:
          confirmed = False
          if verify_result == MUTATION_ATTEMPTED_UNKNOWN or mutation_attempted_unknown:
            verify_failed_reason = "mutation_attempted_unknown"
            mutation_attempted_unknown = True
          else:
            verify_failed_reason = "mutation_unverified"
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

  # ── Reachability rule (RM-219) ──────────────────────────────────────
  #
  # A denied endpoint is not a clean endpoint. A response "reached the
  # handler" only when it is a 2xx that is not the login page (after
  # redirects), or a 3xx whose Location is not the login page. 401/403/404/405
  # and a redirect to login all mean "not reached"; a list of denial codes is
  # not enough because the target may deny with 404 or a login redirect.

  def _login_url_path(self) -> str:
    """Path of the configured login page, base-path aware, no trailing slash."""
    login_path = getattr(self.target_config, "login_path", "")
    if not isinstance(login_path, str) or not login_path:
      return ""
    from urllib.parse import urlparse
    return urlparse(self.target_url + "/" + login_path.lstrip("/")).path.rstrip("/")

  def _is_login_location(self, location, base_url="") -> bool:
    """True when ``location`` points at the configured login page.

    A relative ``location`` is resolved against ``base_url`` (the request
    URL), so ``login?next=`` and ``/app/login`` both match a login page that
    lives under a base path. Query and trailing slash are ignored.
    """
    location = _as_text(location)
    login = self._login_url_path()
    if not login or not location:
      return False
    from urllib.parse import urljoin, urlparse
    base_url = _as_text(base_url) or (self.target_url + "/")
    target = urlparse(urljoin(base_url, location)).path.rstrip("/")
    return target == login

  def _has_login_form(self, text) -> bool:
    """True when the body is a login form: password input plus username field.

    A page that only pre-fills a username next to a change-password form is
    not a login page, so a form with an action must post to the login path.
    A form posting to itself (no action, empty, "#" or query-only) needs a
    login shape: one password input, at most 3 visible fields.
    """
    import re
    text = _as_text(text)
    if not re.search(r'<input[^>]+type=["\']?password', text, re.IGNORECASE):
      return False
    username_field = getattr(self.target_config, "username_field", "")
    if isinstance(username_field, str) and username_field and re.search(
      r'<input[^>]+name=["\']?' + re.escape(username_field) + r'["\'\s>]',
      text, re.IGNORECASE,
    ) is None:
      return False
    actions = re.findall(
      r'<form[^>]*\baction=(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', text, re.IGNORECASE)
    actions = ["".join(groups) for groups in actions]
    if any(self._is_login_location(a) for a in actions):
      return True
    # No action, or an empty, "#" or query-only one, posts back to the page
    # itself: a login form rendered inline at the protected URL. An admin
    # "create user" page posts to itself too, so the inline form counts only
    # with exactly one password input and at most 3 visible fields.
    if actions and not any(
      not a.strip() or a.strip().startswith(("#", "?")) for a in actions
    ):
      return False
    passwords = re.findall(r'<input[^>]+type=["\']?password', text, re.IGNORECASE)
    visible = [
      tag for tag in re.findall(r'<input\b[^>]*>', text, re.IGNORECASE)
      if not re.search(r'type=["\']?(hidden|submit|button|image|reset)\b',
                       tag, re.IGNORECASE)
    ] + re.findall(r'<(?:select|textarea)\b', text, re.IGNORECASE)
    return len(passwords) == 1 and len(visible) <= 3

  def response_reached(self, resp, validation_ok=False, auth_required_marker="") -> bool:
    """Shared reachability check: did ``resp`` come from the endpoint's handler.

    ``validation_ok`` counts 400/415/422 as reached: the handler parsed the
    request and rejected the input, which is the secure result of a
    type-confusion probe and not a denial of the principal.
    ``auth_required_marker`` is the endpoint's configured auth-required body
    marker: a 2xx that carries it is a denial page, not the handler.
    """
    if resp is None:
      return False
    status = getattr(resp, "status_code", None)
    if not isinstance(status, int):
      return False
    if validation_ok and status in (400, 415, 422):
      return True
    request_url = _as_text(getattr(resp, "url", "")) or _as_text(
      getattr(getattr(resp, "request", None), "url", ""))
    headers = getattr(resp, "headers", None)
    if 300 <= status < 400:
      # Only seen when the caller sent allow_redirects=False. A redirect with
      # no Location is not a handled request.
      try:
        location = headers.get("Location", "") if headers is not None else ""
      except Exception:
        location = ""
      location = _as_text(location)
      if not location:
        return False
      return not self._is_login_location(location, request_url)
    if not 200 <= status < 300:
      return False
    if self._is_login_location(request_url):
      return False
    history = getattr(resp, "history", None)
    if isinstance(history, (list, tuple)):
      for hop in history:
        hop_headers = getattr(hop, "headers", None)
        try:
          hop_location = hop_headers.get("Location", "") if hop_headers is not None else ""
        except Exception:
          hop_location = ""
        hop_url = _as_text(getattr(hop, "url", ""))
        if self._is_login_location(hop_location, hop_url):
          return False
    text = getattr(resp, "text", "")
    if (isinstance(auth_required_marker, str) and auth_required_marker.strip()
        and auth_required_marker.strip().lower() in _as_text(text).lower()):
      return False
    return not self._has_login_form(text)

  def is_logout_path(self, path) -> bool:
    """True when ``path`` is the logout URL (trailing slash and query ignored)."""
    logout = getattr(self.target_config, "logout_path", "")
    path = _as_text(path)
    if not isinstance(logout, str) or not logout or not path:
      return False
    from urllib.parse import urlparse
    return (urlparse(path).path.rstrip("/")
            == urlparse(logout).path.rstrip("/"))

  def baseline_reached(self, session, url, **kwargs):
    """Plain GET baseline of ``url``: True/False for reached, None on a
    transport failure (the caller skips the endpoint)."""
    self.safety.throttle()
    try:
      resp = session.get(url, timeout=10, **kwargs)
    except Exception:
      return None
    return self.response_reached(resp)

  def _admin_baseline_reached(self, url) -> bool:
    """True when the admin session got a reached response on ``url``.

    Only meaningful with admin credentials: it tells a real denial of the
    regular user (admin gets 2xx on the same endpoint) from a mistyped path
    (admin gets 404 too). Always a plain GET, whatever verb the probe uses:
    the baseline must never mutate state under the admin principal.
    """
    if getattr(self.auth, "admin_context", "") != "provided":
      return False
    admin = getattr(self.auth, "official_session", None)
    if admin is None:
      return False
    cache = self.__dict__.setdefault("_admin_baseline_cache", {})
    if url not in cache:
      try:
        self.safety.throttle()
        resp = self.request(admin, "GET", url, timeout=10,
                            allow_redirects=False)
        cache[url] = self.response_reached(resp)
      except Exception:
        cache[url] = False
    return cache[url]

  def exempt_denial(self, resp, url) -> str:
    """Reason string when ``resp`` is a denial of the scan principal, else "".

    For scenarios where a denial is the secure result: 401/403, a login
    redirect, and a 404 only when an admin baseline reached the endpoint.
    """
    if resp is None:
      return ""
    status = getattr(resp, "status_code", None)
    if not isinstance(status, int):
      return ""
    if status in (401, 403):
      return f"status_{status}"
    if self.response_reached(resp):
      return ""
    if 200 <= status < 400:
      return "login_redirect"
    if status == 404 and self._admin_baseline_reached(url):
      return "status_404_admin_reached"
    return ""

  def bare_not_found(self, resp, url) -> bool:
    """True for a 404 that no admin baseline explains: skip, never clean."""
    return (
      getattr(resp, "status_code", None) == 404
      and not self._admin_baseline_reached(url)
    )

  def denial_reason(self) -> str:
    """Reason code for an endpoint that denied the scan principal."""
    if getattr(self.auth, "admin_context", "") == "absent":
      return "admin_context_absent"
    return "endpoint_denied"

  def emit_endpoint_denied(self, scenario_id):
    """Inconclusive finding for a scenario whose every endpoint was denied."""
    try:
      from ..scenario_catalog import graybox_scenario
      entry = graybox_scenario(scenario_id) or {}
    except ImportError:
      entry = {}
    self.emit_inconclusive(
      scenario_id,
      entry.get("title") or scenario_id,
      entry.get("owasp") or "",
      self.denial_reason(),
    )

  def principal_label(self) -> str:
    """Human name of the primary scan principal, for replay steps."""
    principal = getattr(self.auth, "primary_principal", "")
    if principal == "regular":
      return "the regular user"
    if principal == "official":
      return "the official user"
    return "the scan user"

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
    gateway_auth = getattr(api_security, "gateway_auth", None)
    names = []
    for descriptor in (auth, gateway_auth):
      if descriptor is None:
        continue
      for attr in ("api_key_header_name", "api_key_query_param",
                    "bearer_token_header_name"):
        val = getattr(descriptor, attr, None)
        if isinstance(val, str) and val and val not in names:
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

  def evidence_from(self, response):
    """Evidence artifacts for a finding built directly with `GrayboxFinding`.

    Same artifact `emit_vulnerable(response=...)` builds, without changing how
    the finding itself is constructed. Empty when there is no response.
    """
    built = _best_effort(_artifact_from_response, response, self._scrub_for_emission)
    return self._scrub_for_emission([built]) if built is not None else []

  def emit_vulnerable(self, scenario_id, title, severity, owasp, cwe,
                       evidence, *, attack=None, evidence_artifacts=None,
                       replay_steps=None, remediation=None,
                       rollback_status="", url=None, parameter=None,
                       method=None, response=None, cvss_vector=""):
    """Append a vulnerable GrayboxFinding using the catalog's ATT&CK default.

    ``cvss_vector`` is needed only where the label varies at run time: the
    catalog's vector is the scenario's, and a probe that reports it at another
    severity passes the vector of the weakness that severity stands for.

    ``rollback_status`` is set by `run_stateful` for stateful probes;
    leave default for non-stateful findings.

    ``url`` / ``parameter`` / ``method`` record *where* the finding manifests.
    They are optional so existing probes keep working, but a probe that omits
    them produces a finding with no machine-readable location — and two
    endpoints exhibiting the same scenario then collapse to one finding id.
    """
    scrubbed_evidence = self._scrub_for_emission(list(evidence or []))
    # Derived from the scrubbed evidence, never the raw list: a URL can carry a
    # token in its query string, and promoting it to a typed field must not
    # reintroduce what the scrubber just removed.
    derived_url, derived_parameter = _location_from_evidence(scrubbed_evidence)
    artifacts = list(evidence_artifacts or [])
    # Build one from the triggering response when the probe passes it, so the
    # finding carries real request/response evidence rather than only a
    # free-text summary. `evidence_artifacts` remains available for probes that
    # construct their own.
    built = _best_effort(_artifact_from_response, response, self._scrub_for_emission)
    if built is not None:
      artifacts.append(built)
    steps = list(replay_steps or [])
    # Appended after the probe's own steps: those describe the setup a reader
    # needs, and the curl is the final action that triggers the finding.
    curl = _best_effort(_curl_reproduction, response, self._scrub_for_emission)
    if curl:
      steps.append(curl)
    self.findings.append(GrayboxFinding(
      url=url or derived_url,
      parameter=parameter or derived_parameter,
      method=method,
      scenario_id=scenario_id,
      title=self._scrub_for_emission(title),
      status="vulnerable",
      severity=severity,
      owasp=owasp,
      cwe=list(cwe or []),
      attack=self._resolve_attack(scenario_id, attack),
      evidence=scrubbed_evidence,
      evidence_artifacts=self._scrub_for_emission(artifacts),
      replay_steps=self._scrub_for_emission(steps),
      remediation=self._scrub_for_emission(remediation or ""),
      rollback_status=rollback_status or "",
      cvss_vector=cvss_vector or "",
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
