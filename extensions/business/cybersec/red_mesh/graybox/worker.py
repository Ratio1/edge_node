"""
Graybox (authenticated webapp) scan worker.

Inherits from BaseLocalWorker (Phase 0) and orchestrates:
Preflight → Authentication → Route Discovery → Probes → Weak Auth → Cleanup.
"""

import importlib
from urllib.parse import urlparse

from ..worker.base import BaseLocalWorker
from ..constants import GRAYBOX_PROBE_REGISTRY
from .findings import GrayboxFinding
from .auth import AuthManager
from .discovery import DiscoveryModule
from .safety import SafetyControls
from .models import DiscoveryResult, GrayboxCredentialSet, GrayboxProbeContext, GrayboxTargetConfig

# Weak auth uses a direct import (not the registry) because it is a
# distinct pipeline phase, not a generic probe.
from .probes.business_logic import BusinessLogicProbes


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

    # Modules (composition)
    self.safety = SafetyControls(
      request_delay=job_config.scan_min_delay or None,
      target_is_local=SafetyControls.is_local_target(target_url),
    )
    self.auth = AuthManager(
      target_url=self.target_url,
      target_config=self.target_config,
      verify_tls=job_config.verify_tls,
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
    }
    self._phase = ""
    self._credentials = GrayboxCredentialSet.from_job_config(job_config)

  @classmethod
  def get_feature_prefixes(cls):
    """Return feature prefixes for compatibility with capability discovery."""
    return ["_graybox_"]

  @classmethod
  def get_supported_features(cls, categs=False):
    """Return supported graybox features from the explicit probe registry."""
    features = [entry["key"] for entry in GRAYBOX_PROBE_REGISTRY] + ["_graybox_weak_auth"]
    if categs:
      return {"graybox": features}
    return features

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
    status["scan_metrics"] = metrics
    status["scenario_stats"] = scenario_stats

    if not for_aggregations:
      status["local_worker_id"] = self.local_worker_id
      status["done"] = self.state["done"]
      status["canceled"] = self.state["canceled"]
      status["progress"] = self._phase or "initializing"

    return status

  def execute_job(self):
    """Preflight → Auth → Discover → Probes → Weak Auth → Cleanup → Done."""
    discovery_result = DiscoveryResult()
    self.metrics.start_scan(1)
    try:
      self._run_preflight_phase()
      if self._check_stopped():
        return

      auth_ok = self._run_authentication_phase()
      if not auth_ok:
        return

      if not self._check_stopped():
        discovery_result = self._run_discovery_phase()

      if not self._check_stopped():
        self._run_probe_phase(discovery_result)

      if not self._check_stopped():
        self._run_weak_auth_phase(discovery_result)

    except Exception as exc:
      self._record_fatal(self.safety.sanitize_error(str(exc)))
    finally:
      self.auth.cleanup()
      self.metrics.phase_end(self._phase)
      self.state["done"] = True

  def _run_preflight_phase(self):
    self._set_phase("preflight")
    self.metrics.phase_start("preflight")
    target_error = self.safety.validate_target(
      self.target_url, self.job_config.authorized,
    )
    if target_error:
      self._record_fatal(target_error)
      return

    preflight_error = self.auth.preflight_check()
    if preflight_error:
      self._record_fatal(preflight_error)
      return

    if not self.job_config.verify_tls:
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
    self.metrics.phase_end("preflight")

  def _run_authentication_phase(self) -> bool:
    self._set_phase("authentication")
    self.metrics.phase_start("authentication")
    auth_ok = self.auth.authenticate(self._credentials.official, self._credentials.regular)
    self._store_auth_results()
    self.state["completed_tests"].append("graybox_auth")
    self.metrics.phase_end("authentication")

    if not auth_ok:
      self._record_fatal("Official authentication failed. Cannot proceed with graybox scan.")
      return False
    return True

  def _run_discovery_phase(self) -> DiscoveryResult:
    self._set_phase("discovery")
    self.metrics.phase_start("discovery")
    self.auth.ensure_sessions(self._credentials.official, self._credentials.regular)
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
    self.metrics.phase_end("discovery")
    return result

  def _build_probe_kwargs(self, discovery_result: DiscoveryResult) -> dict:
    return GrayboxProbeContext(
      target_url=self.target_url,
      auth_manager=self.auth,
      target_config=self.target_config,
      safety=self.safety,
      discovered_routes=discovery_result.routes,
      discovered_forms=discovery_result.forms,
      regular_username=self._credentials.regular.username if self._credentials.regular else "",
      allow_stateful=self.job_config.allow_stateful_probes,
    )

  def _run_probe_phase(self, discovery_result: DiscoveryResult):
    self._set_phase("graybox_probes")
    self.metrics.phase_start("graybox_probes")
    self.auth.ensure_sessions(self._credentials.official, self._credentials.regular)

    probe_context = self._build_probe_kwargs(discovery_result)
    excluded_features = set(self.job_config.excluded_features or [])
    graybox_excluded = "graybox" in excluded_features

    if not graybox_excluded:
      for entry in GRAYBOX_PROBE_REGISTRY:
        if self._check_stopped():
          break

        store_key = entry["key"]

        if store_key in excluded_features:
          self.metrics.record_probe(store_key, "skipped:disabled")
          continue

        self._run_registered_probe(entry, probe_context)
    else:
      for entry in GRAYBOX_PROBE_REGISTRY:
        self.metrics.record_probe(entry["key"], "skipped:disabled")

    self.state["completed_tests"].append("graybox_probes")
    self.metrics.phase_end("graybox_probes")

  def _run_weak_auth_phase(self, discovery_result: DiscoveryResult):
    if (
      self._credentials.weak_candidates
      and "_graybox_weak_auth" not in (self.job_config.excluded_features or [])
    ):
      self._set_phase("weak_auth")
      self.metrics.phase_start("weak_auth")
      self.auth.ensure_sessions(self._credentials.official, self._credentials.regular)
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
      self.metrics.phase_end("weak_auth")
    elif self._credentials.weak_candidates and "_graybox_weak_auth" in (self.job_config.excluded_features or []):
      self.metrics.record_probe("_graybox_weak_auth", "skipped:disabled")

  def _run_registered_probe(self, entry: dict, probe_context: GrayboxProbeContext):
    """Run one registered probe through a shared capability and error boundary."""
    store_key = entry["key"]
    probe_cls = self._import_probe(entry["cls"])

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

    self.auth.ensure_sessions(self._credentials.official, self._credentials.regular)

    try:
      from_context = getattr(probe_cls, "from_context", None)
      has_explicit_from_context = "from_context" in getattr(probe_cls, "__dict__", {})
      if has_explicit_from_context and callable(from_context):
        probe = from_context(probe_context)
      else:
        probe = probe_cls(**probe_context.to_kwargs())
      findings = probe.run()
      self._store_findings(store_key, findings)
      self.metrics.record_probe(store_key, "completed")
    except Exception as exc:
      self._record_probe_error(store_key, exc)
      self.metrics.record_probe(store_key, "failed")

  def _store_findings(self, key, findings):
    """Store GrayboxFinding dicts in graybox_results under the port key."""
    port_results = self.state["graybox_results"].setdefault(self._port_key, {})
    port_results[key] = {
      "findings": [f.to_dict() for f in findings],
    }
    for finding in findings:
      self.metrics.record_finding(getattr(finding, "severity", "INFO"))

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
    sanitized = self.safety.sanitize_error(str(exc))
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
    }
