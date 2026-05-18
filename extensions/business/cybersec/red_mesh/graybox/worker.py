"""
Graybox (authenticated webapp) scan worker.

Inherits from BaseLocalWorker (Phase 0) and orchestrates:
Preflight → Authentication → Route Discovery → Probes → Weak Auth → Cleanup.
"""

import importlib
from urllib.parse import urlparse

from ..worker.base import BaseLocalWorker
from ..constants import GRAYBOX_PROBE_REGISTRY
from .findings import (
  FindingRedactionContext,
  GrayboxEvidenceArtifact,
  GrayboxFinding,
)
from .auth import AuthManager
from .discovery import DiscoveryModule
from .http_client import GrayboxHttpClient
from .safety import SafetyControls
from .rollback import RollbackJournalRepository
from .scenario_runtime import GrayboxWorkerAssignment
from .models import (
  DiscoveryResult,
  GrayboxCredentialSet,
  GrayboxProbeContext,
  GrayboxProbeDefinition,
  GrayboxProbeRunResult,
  GrayboxTargetConfig,
)

# Weak auth uses a direct import (not the registry) because it is a
# distinct pipeline phase, not a generic probe.
from .probes.business_logic import BusinessLogicProbes


def _first_non_empty_str(values):
  """Aggregation helper: return the first truthy string in values.

  Used by get_worker_specific_result_fields() to merge top-level
  string fields (abort_reason, abort_phase) across multiple workers.
  Empty strings from non-aborted workers should not overwrite a real
  reason from an aborted peer.
  """
  for value in values or []:
    if isinstance(value, str) and value:
      return value
  return ""


class GrayboxAbort(Exception):
  """Signal that the graybox pipeline must stop immediately.

  Raised only from inside phase methods when a fatal safety or policy
  gate fails (unauthorized target, preflight rejection, unrecoverable
  auth failure). Caught exclusively by GrayboxLocalWorker.execute_job
  — do not catch elsewhere. The fatal finding is always recorded via
  _record_fatal before the exception is raised.
  """

  def __init__(self, reason: str, reason_class: str = "unknown"):
    self.reason = reason
    self.reason_class = reason_class
    super().__init__(reason)


class GrayboxLocalWorker(BaseLocalWorker):
  PHASE_PLAN = (
    ("preflight", "_run_preflight_phase"),
    ("authentication", "_run_authentication_phase"),
    ("discovery", "_run_discovery_phase"),
    ("graybox_probes", "_run_probe_phase"),
    ("weak_auth", "_run_weak_auth_phase"),
  )

  """
  Authenticated webapp probe worker.

  Inherits from BaseLocalWorker (Phase 0), which provides:
  - self.owner, self.job_id, self.initiator, self.target
  - self.local_worker_id (format "RM-{prefix}-{uuid[:4]}")
  - self.thread, self.stop_event (set by inherited start())
  - self.metrics (MetricsCollector instance)
  - self.initial_ports (declared, subclass populates)
  - self.state (declared as {}, subclass populates with full key set)
  - start(), stop(), _check_stopped(), P() — all inherited, not redefined

  Uses the two-layer finding architecture:
  - Probes create GrayboxFinding instances (layer 1)
  - Worker stores serialized findings in state["graybox_results"] (layer 2)
  - pentester_api_01.py normalizes them into flat finding dicts via
    _compute_risk_and_findings()
  """

  def __init__(self, owner, job_id, target_url, job_config,
               local_id="1", initiator=""):
    parsed = urlparse(target_url)

    super().__init__(
      owner=owner,
      job_id=job_id,
      initiator=initiator,
      local_id_prefix=local_id,
      target=parsed.hostname,
    )

    self.target_url = target_url.rstrip("/")
    self.job_config = job_config
    self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
    self._port_key = str(self._port)

    self.initial_ports = [self._port]

    self.target_config = GrayboxTargetConfig.from_dict(
      job_config.target_config or {}
    )
    self.assignment = GrayboxWorkerAssignment.from_job_config(job_config)

    # OWASP API Top 10 — Subphase 1.7. Per-scan request budget shared by
    # every probe instance. Default 1000; configurable via
    # `target_config.api_security.max_total_requests`.
    from .budget import RequestBudget
    if self.assignment.is_valid:
      budget_total = self.assignment.assigned_request_budget
    else:
      budget_total = getattr(
        self.target_config.api_security, "max_total_requests", 1000,
      )
    budget_total = max(1, int(budget_total))
    self.request_budget = RequestBudget(
      remaining=budget_total, total=budget_total,
    )
    self.http_client = GrayboxHttpClient(
      self.target_url,
      allowlist=getattr(job_config, "target_allowlist", None) or [],
      target_config=self.target_config,
    )

    # Modules (composition)
    self.safety = SafetyControls(
      request_delay=job_config.scan_min_delay or None,
      target_is_local=SafetyControls.is_local_target(target_url),
    )
    self.auth = AuthManager(
      target_url=self.target_url,
      target_config=self.target_config,
      verify_tls=job_config.verify_tls,
      http_client=self.http_client,
    )
    self.discovery = DiscoveryModule(
      target_url=self.target_url,
      auth_manager=self.auth,
      safety=self.safety,
      target_config=self.target_config,
    )

    self.state = {
      "job_id": job_id,
      "initiator": initiator,
      "target": parsed.hostname,
      "scan_type": "webapp",
      "target_url": self.target_url,
      "open_ports": [self._port],
      "ports_scanned": [self._port],
      "port_protocols": {self._port_key: parsed.scheme},
      "service_info": {},
      "web_tests_info": {},
      "correlation_findings": [],
      "graybox_results": {},
      "completed_tests": [],
      "done": False,
      "canceled": False,
      # Safety-gate abort state. Populated only when a preflight /
      # authorization / auth / session-refresh gate fails and raises
      # GrayboxAbort. Consumers (UI, archive, LLM analysis) use these
      # to distinguish a safety-aborted scan from a clean completion.
      "aborted": False,
      "abort_reason": "",
      "abort_phase": "",
      "graybox_assignment": (
        self.assignment.to_dict() if self.assignment.is_valid else {}
      ),
      "rollback_journal": [],
    }
    self.rollback_journal = RollbackJournalRepository(
      job_id=job_id,
      worker_id=self.local_worker_id,
      assignment_revision=self.assignment.assignment_revision
      if self.assignment.is_valid else 0,
      records=self.state["rollback_journal"],
    )
    # _phase_open is only touched on the worker thread — no cross-thread
    # reads. Guards the finally clause from double-closing a phase that
    # its owning method already closed explicitly.
    self._phase = ""
    self._phase_open = False
    self._credentials = GrayboxCredentialSet.from_job_config(job_config)

  @classmethod
  def get_feature_prefixes(cls):
    """Return feature prefixes for compatibility with capability discovery."""
    return ["_graybox_"]

  @classmethod
  def get_supported_features(cls, categs=False):
    """Return supported graybox features from the explicit probe registry."""
    features = [probe.key for probe in cls._iter_probe_definitions()] + ["_graybox_weak_auth"]
    if categs:
      return {"graybox": features}
    return features

  @staticmethod
  def _iter_probe_definitions():
    return [GrayboxProbeDefinition.from_entry(entry) for entry in GRAYBOX_PROBE_REGISTRY]

  # start(), stop(), _check_stopped(), P() are ALL inherited from
  # BaseLocalWorker. NOT redefined here.

  def get_status(self, for_aggregations=False):
    """Return worker state for aggregation by pentester_api_01.py."""
    status = dict(self.state)
    scenario_stats = self._compute_scenario_stats()
    metrics = self.metrics.build().to_dict()
    metrics.update({
      "scenarios_total": scenario_stats["total"],
      "scenarios_vulnerable": scenario_stats["vulnerable"],
      "scenarios_clean": scenario_stats["not_vulnerable"],
      "scenarios_inconclusive": scenario_stats["inconclusive"],
      "scenarios_error": scenario_stats["error"],
    })
    # OWASP API Top 10 — Subphase 1.7. Per-scan request budget snapshot
    # surfaces in scan_metrics so operators can see whether the scan was
    # budget-bound (and tune target_config.api_security.max_total_requests
    # accordingly).
    if self.request_budget is not None:
      snap = self.request_budget.snapshot()
      metrics["budget_total"] = snap["total"]
      metrics["budget_remaining"] = snap["remaining"]
      metrics["budget_exhausted_count"] = snap["exhausted_count"]
    status["scan_metrics"] = metrics
    status["scenario_stats"] = scenario_stats

    if not for_aggregations:
      status["local_worker_id"] = self.local_worker_id
      status["done"] = self.state["done"]
      status["canceled"] = self.state["canceled"]
      status["progress"] = self._phase or "initializing"

    # aborted / abort_reason / abort_phase are already present in
    # self.state and therefore in status via dict(self.state). They
    # remain available in both running and aggregation-facing
    # snapshots so finalization and live-progress can distinguish
    # safety aborts from clean completion.

    return status

  def execute_job(self):
    """Preflight → Auth → Discover → Probes → Weak Auth → Cleanup → Done.

    Fail-closed: a GrayboxAbort from any phase (raised via _abort when a
    safety/authorization gate fails) bypasses remaining phases. The
    aborted state is recorded so downstream consumers can distinguish
    "scan finished cleanly" from "scan was terminated at a safety gate."
    """
    discovery_result = DiscoveryResult()
    self.metrics.start_scan(1)
    try:
      self._run_preflight_phase()
      if self._check_stopped():
        return

      self._run_authentication_phase()
      if self._check_stopped():
        return

      discovery_result = self._run_discovery_phase()
      if self._check_stopped():
        return

      self._run_probe_phase(discovery_result)
      if self._check_stopped():
        return

      self._run_weak_auth_phase(discovery_result)

    except GrayboxAbort as exc:
      self.state["aborted"] = True
      self.state["abort_reason"] = exc.reason
      self.state["abort_phase"] = self._phase
      self.metrics.record_abort(
        phase=self._phase, reason_class=exc.reason_class,
      )
      # Auditable trail for compliance. Consistent [ABORT-ATTESTATION]
      # prefix so operators can grep /logs for every aborted scan.
      self.P(
        "[ABORT-ATTESTATION] job=%s worker=%s phase=%s reason_class=%s"
        % (self.job_id, self.local_worker_id,
           self._phase or "unknown", exc.reason_class),
        color='y',
      )
    except Exception as exc:
      self._record_fatal(self._sanitize_error(str(exc)))
    finally:
      self._safe_cleanup()
      if self._phase_open and self._phase:
        self.metrics.phase_end(self._phase)
        self._phase_open = False
      self.state["done"] = True

  def _safe_cleanup(self):
    """Run auth.cleanup without letting its errors mask an earlier abort."""
    try:
      self.auth.cleanup()
    except Exception as exc:
      self.P(
        "[GRAYBOX] auth.cleanup raised during shutdown: %s"
        % self._sanitize_error(str(exc)),
        color='y',
      )

  def _abort(self, reason: str, reason_class: str = "unknown"):
    """Record a fatal finding and raise GrayboxAbort.

    Parameters
    ----------
    reason : str
      Human-readable explanation. MUST be a worker-produced string
      (from code we control) — never raw target content (banners,
      response bodies), because abort_reason is surfaced via
      get_status() and may reach the LLM payload. Phase 2 of the
      remediation adds a defense-in-depth sanitizer at the LLM
      boundary, but the contract here is: don't rely on it.
    reason_class : str
      Short stable identifier for metrics grouping (e.g.
      "unauthorized_target", "preflight_error", "auth_failed").
    """
    self._record_fatal(reason)
    raise GrayboxAbort(reason, reason_class=reason_class)

  def _run_preflight_phase(self):
    self._set_phase("preflight")
    self.metrics.phase_start("preflight")
    self._phase_open = True
    try:
      if not self.assignment.is_valid:
        self._abort(
          "Invalid graybox worker assignment: "
          + self.assignment.validation_error,
          reason_class="assignment_invalid",
        )

      target_error = self.safety.validate_target(
        self.target_url, self.job_config.authorized,
      )
      if target_error:
        self._abort(target_error, reason_class="unauthorized_target")

      preflight_error = self.auth.preflight_check()
      if preflight_error:
        self._abort(preflight_error, reason_class="preflight_error")

      # Only warn about disabled TLS verification when the target is HTTPS —
      # for plaintext http:// targets the flag is a no-op and emitting a
      # PREFLIGHT-TLS finding is just noise.
      target_is_https = (self.target_url or "").lower().startswith("https://")
      if not self.job_config.verify_tls and target_is_https:
        self.P(
          f"WARNING: TLS verification disabled for {self.target_url}. "
          "Credentials may be intercepted by a MITM attacker.", color='y'
        )
        self._store_findings("_graybox_preflight", [GrayboxFinding(
          scenario_id="PREFLIGHT-TLS",
          title="TLS verification disabled",
          status="inconclusive",
          severity="LOW",
          owasp="A02:2021",
          cwe=["CWE-295"],
          evidence=[f"verify_tls=False", f"target={self.target_url}"],
          remediation="Enable TLS verification or use a trusted certificate.",
        )])
    finally:
      self.metrics.phase_end("preflight")
      self._phase_open = False

  def _run_authentication_phase(self):
    self._set_phase("authentication")
    self.metrics.phase_start("authentication")
    self._phase_open = True
    try:
      auth_ok = self.auth.authenticate(
        self._credentials.official, self._credentials.regular,
      )
      self._store_auth_results()
      self.state["completed_tests"].append("graybox_auth")
    finally:
      self.metrics.phase_end("authentication")
      self._phase_open = False

    if not auth_ok:
      self._abort(
        "Official authentication failed. Cannot proceed with graybox scan.",
        reason_class="auth_failed",
      )

  def _run_discovery_phase(self) -> DiscoveryResult:
    self._set_phase("discovery")
    self.metrics.phase_start("discovery")
    self._phase_open = True
    try:
      self._ensure_active_sessions("discovery")
      result = None
      discover_result = getattr(self.discovery, "discover_result", None)
      if callable(discover_result):
        maybe_result = discover_result(known_routes=self.job_config.app_routes)
        if isinstance(maybe_result, DiscoveryResult):
          result = maybe_result
      if result is None:
        routes, forms = self.discovery.discover(
          known_routes=self.job_config.app_routes,
        )
        result = DiscoveryResult(routes=routes, forms=forms)
      self._store_discovery_results(result.routes, result.forms)
      self.state["completed_tests"].append("graybox_discovery")
      return result
    finally:
      self.metrics.phase_end("discovery")
      self._phase_open = False

  def _build_probe_kwargs(self, discovery_result: DiscoveryResult) -> dict:
    allowed_scenario_ids = getattr(self.job_config, "assigned_scenario_ids", None)
    return GrayboxProbeContext(
      target_url=self.target_url,
      auth_manager=self.auth,
      target_config=self.target_config,
      safety=self.safety,
      discovered_routes=discovery_result.routes,
      discovered_forms=discovery_result.forms,
      regular_username=self._credentials.regular.username if self._credentials.regular else "",
      allow_stateful=self.job_config.allow_stateful_probes,
      request_budget=self.request_budget,
      allowed_scenario_ids=(
        None if allowed_scenario_ids is None else tuple(allowed_scenario_ids)
      ),
      rollback_journal=self.rollback_journal,
      job_id=self.job_id,
      worker_id=self.local_worker_id,
      assignment_revision=self.assignment.assignment_revision
      if self.assignment.is_valid else 0,
    )

  def _run_probe_phase(self, discovery_result: DiscoveryResult):
    self._set_phase("graybox_probes")
    self.metrics.phase_start("graybox_probes")
    self._phase_open = True
    try:
      self._ensure_active_sessions("graybox_probes")

      probe_context = self._build_probe_kwargs(discovery_result)
      excluded_features = set(self.job_config.excluded_features or [])
      graybox_excluded = "graybox" in excluded_features

      if not graybox_excluded:
        for probe_def in self._iter_probe_definitions():
          if self._check_stopped():
            break

          store_key = probe_def.key

          if store_key in excluded_features:
            self.metrics.record_probe(store_key, "skipped:disabled")
            continue

          self._run_registered_probe(probe_def, probe_context)
      else:
        for probe_def in self._iter_probe_definitions():
          self.metrics.record_probe(probe_def.key, "skipped:disabled")

      self.state["completed_tests"].append("graybox_probes")
    finally:
      self.metrics.phase_end("graybox_probes")
      self._phase_open = False

  def _run_weak_auth_phase(self, discovery_result: DiscoveryResult):
    # Single source of truth for the weak-auth gate — shared with
    # live-progress so the UI never reports "done" while weak-auth
    # still has work ahead.
    if GrayboxCredentialSet.weak_auth_enabled(self.job_config):
      self._set_phase("weak_auth")
      self.metrics.phase_start("weak_auth")
      self._phase_open = True
      try:
        self._ensure_active_sessions("weak_auth")
        probe_context = self._build_probe_kwargs(discovery_result)
        bl_probe = BusinessLogicProbes(
          **dict(probe_context.to_kwargs(), allow_stateful=False),
        )
        try:
          weak_findings = bl_probe.run_weak_auth(
            self._credentials.weak_candidates,
            self._credentials.max_weak_attempts,
          )
          self._store_findings("_graybox_weak_auth", weak_findings)
          self.metrics.record_probe("_graybox_weak_auth", "completed")
        except Exception as exc:
          self._record_probe_error("_graybox_weak_auth", exc)
          self.metrics.record_probe("_graybox_weak_auth", "failed")
        self.state["completed_tests"].append("graybox_weak_auth")
      finally:
        self.metrics.phase_end("weak_auth")
        self._phase_open = False
    elif self._credentials.weak_candidates and "_graybox_weak_auth" in (self.job_config.excluded_features or []):
      self.metrics.record_probe("_graybox_weak_auth", "skipped:disabled")

  def _run_registered_probe(self, entry, probe_context: GrayboxProbeContext):
    """Run one registered probe through a shared capability and error boundary."""
    probe_def = GrayboxProbeDefinition.from_entry(entry)
    store_key = probe_def.key
    probe_cls = self._import_probe(probe_def.cls_path)

    if probe_cls.is_stateful and not probe_context.allow_stateful:
      self.metrics.record_probe(store_key, "skipped:stateful_disabled")
      self._store_findings(store_key, [GrayboxFinding(
        scenario_id=f"SKIP-{store_key}",
        title="Probe skipped: stateful probes disabled",
        status="inconclusive", severity="INFO", owasp="",
        evidence=["stateful_probes_disabled=True"],
      )])
      return
    if probe_cls.requires_regular_session and not self.auth.regular_session:
      self.metrics.record_probe(store_key, "skipped:missing_regular_session")
      return
    if probe_cls.requires_auth and not self.auth.official_session:
      self.metrics.record_probe(store_key, "skipped:missing_auth")
      return

    require_regular = bool(probe_cls.requires_regular_session)
    # Per-probe session refresh: a transient auth-refresh failure must
    # not kill the entire scan. Mark the probe as failed:auth_refresh
    # and continue with subsequent probes. Phase-level session checks
    # (discovery/weak_auth) use _ensure_active_sessions which raises
    # on failure; this call explicitly does not.
    if not self.auth.ensure_sessions(
      self._credentials.official,
      self._credentials.regular if require_regular or self._credentials.regular else None,
    ):
      self.metrics.record_probe(store_key, "failed:auth_refresh")
      return

    try:
      from_context = getattr(probe_cls, "from_context", None)
      has_explicit_from_context = "from_context" in getattr(probe_cls, "__dict__", {})
      if has_explicit_from_context and callable(from_context):
        probe = from_context(probe_context)
      else:
        probe = probe_cls(**probe_context.to_kwargs())
      run_result = self._normalize_probe_run_result(probe.run())
      self._store_findings(store_key, run_result)
      self.metrics.record_probe(store_key, run_result.outcome)
    except Exception as exc:
      self._record_probe_error(store_key, exc)
      self.metrics.record_probe(store_key, "failed")

  def _ensure_active_sessions(self, scope, require_regular=False):
    """Fail closed if session refresh cannot restore required auth state.

    Raises GrayboxAbort on failure — the scan cannot continue without
    an authenticated session. Callers should NOT swallow the exception;
    it propagates to execute_job's single handler.
    """
    auth_ok = self.auth.ensure_sessions(
      self._credentials.official,
      self._credentials.regular if require_regular or self._credentials.regular else None,
    )
    if auth_ok:
      return True

    sanitized_scope = scope.replace("_", " ")
    self._abort(
      f"Authentication session refresh failed during {sanitized_scope}. "
      "Graybox scan cannot continue safely.",
      reason_class="session_refresh_failed",
    )

  @staticmethod
  def _normalize_probe_run_result(value) -> GrayboxProbeRunResult:
    return GrayboxProbeRunResult.from_value(value)

  def _store_findings(self, key, findings):
    """Store GrayboxFinding dicts in graybox_results under the port key."""
    run_result = self._normalize_probe_run_result(findings)
    port_results = self.state["graybox_results"].setdefault(self._port_key, {})
    with FindingRedactionContext(
      secret_field_names=self._configured_secret_field_names(),
    ):
      port_results[key] = {
        "findings": [f.to_dict() for f in run_result.findings],
        "artifacts": [
          GrayboxEvidenceArtifact.from_value(artifact).to_dict()
          for artifact in run_result.artifacts
        ],
        "outcome": run_result.outcome,
      }
    for finding in run_result.findings:
      self.metrics.record_finding(getattr(finding, "severity", "INFO"))

  def _configured_secret_field_names(self):
    api_security = getattr(self.target_config, "api_security", None)
    auth = getattr(api_security, "auth", None) if api_security is not None else None
    if auth is None:
      return ()
    names = []
    for attr in ("api_key_header_name", "api_key_query_param",
                  "bearer_token_header_name"):
      value = getattr(auth, attr, None)
      if isinstance(value, str) and value:
        names.append(value)
    return tuple(names)

  def _sanitize_error(self, value):
    try:
      return self.safety.sanitize_error(
        str(value), secret_field_names=self._configured_secret_field_names(),
      )
    except TypeError:
      return self.safety.sanitize_error(str(value))

  def _store_auth_results(self):
    port_info = self.state["service_info"].setdefault(self._port_key, {})
    port_info["_graybox_auth"] = {
      "official_success": self.auth.official_session is not None,
      "regular_success": self.auth.regular_session is not None,
      "auth_errors": list(self.auth._auth_errors),
      "findings": [],
    }

  def _store_discovery_results(self, routes, forms):
    port_info = self.state["service_info"].setdefault(self._port_key, {})
    port_info["_graybox_discovery"] = {
      "routes": routes,
      "forms": forms,
      "findings": [],
    }

  def _record_fatal(self, message):
    """Record unrecoverable error as a GrayboxFinding."""
    self._store_findings("_graybox_fatal", [GrayboxFinding(
      scenario_id="FATAL",
      title="Scan aborted",
      status="inconclusive",
      severity="INFO",
      owasp="",
      evidence=[f"error={message}"],
      error=message,
    )])

  def _record_probe_error(self, store_key, exc):
    """Record per-probe error without killing the scan."""
    sanitized = self._sanitize_error(str(exc))
    self._store_findings(store_key, [GrayboxFinding(
      scenario_id=f"ERR-{store_key}",
      title=f"Probe error: {store_key}",
      status="inconclusive",
      severity="INFO",
      owasp="",
      evidence=[f"error={sanitized}"],
      error=sanitized,
    )])

  @staticmethod
  def _import_probe(cls_path):
    """Dynamically import a probe class from the registry."""
    module_name, class_name = cls_path.rsplit(".", 1)
    full_module = f"..probes.{module_name}"
    mod = importlib.import_module(full_module, package=__name__)
    return getattr(mod, class_name)

  def _set_phase(self, phase):
    self._phase = phase

  def _compute_scenario_stats(self):
    """Compute scenario stats from graybox_results."""
    stats = {
      "total": 0, "vulnerable": 0, "not_vulnerable": 0,
      "inconclusive": 0, "error": 0,
    }
    for port_key, probes in self.state["graybox_results"].items():
      for probe_key, probe_data in probes.items():
        for finding in probe_data.get("findings", []):
          status = finding.get("status", "")
          if not status:
            continue
          stats["total"] += 1
          if status in stats:
            stats[status] += 1
          else:
            stats["error"] += 1
    return stats

  @staticmethod
  def get_worker_specific_result_fields():
    """Register graybox_results for aggregation."""
    return {
      "graybox_results": dict,
      "service_info": dict,
      "web_tests_info": dict,
      "open_ports": list,
      "completed_tests": list,
      "port_protocols": dict,
      "correlation_findings": list,
      "scan_metrics": dict,
      "ports_scanned": list,
      # Abort state aggregation (Phase 1):
      #   aborted:      OR across workers — any aborted → aggregate aborted
      #   abort_reason: first non-empty wins
      #   abort_phase:  first non-empty wins
      # These are top-level strings/bools, so _get_aggregated_report
      # dispatches them to the else-branch which calls the callable
      # with [existing, new]; the callables below encode the merge rule.
      "aborted": any,
      "abort_reason": _first_non_empty_str,
      "abort_phase": _first_non_empty_str,
    }
