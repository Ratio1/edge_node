from copy import deepcopy
from urllib.parse import urlparse

from ..constants import (
  DISTRIBUTION_MIRROR,
  DISTRIBUTION_SLICE,
  JOB_STATUS_RUNNING,
  LOCAL_WORKERS_MAX,
  LOCAL_WORKERS_MIN,
  PORT_ORDER_SEQUENTIAL,
  PORT_ORDER_SHUFFLE,
  RUN_MODE_CONTINUOUS_MONITORING,
  RUN_MODE_SINGLEPASS,
  ScanType,
)
from ..models import (
  AuthorizationRef,
  CStoreJobRunning,
  EngagementContext,
  JobConfig,
  RulesOfEngagement,
)
from ..repositories import JobStateRepository
from .config import get_graybox_budgets_config
from .event_hooks import emit_attestation_status_event, emit_lifecycle_event
from .secrets import persist_job_config_with_secrets


def _job_repo(owner):
  getter = getattr(type(owner), "_get_job_state_repository", None)
  if callable(getter):
    return getter(owner)
  return JobStateRepository(owner)


def validation_error(message: str):
  """Return a consistent validation error payload."""
  return {"error": "validation_error", "message": message}


def _normalize_allowlist(entries):
  if not entries:
    return []
  if not isinstance(entries, (str, list, tuple, set)):
    return []
  if isinstance(entries, str):
    entries = [entries]
  normalized = []
  for entry in entries:
    value = str(entry).strip()
    if value:
      normalized.append(value.lower())
  return normalized


def _split_allowlist_entries(entries):
  hosts = []
  scopes = []
  for entry in _normalize_allowlist(entries):
    if entry.startswith("/"):
      scopes.append(entry)
      continue
    if "://" in entry:
      parsed = urlparse(entry)
      if parsed.hostname:
        hosts.append(parsed.hostname.lower())
      if parsed.path and parsed.path != "/":
        scopes.append(parsed.path.rstrip("/"))
      continue
    hosts.append(entry)
  return hosts, scopes


def _host_in_allowlist(hostname: str, entries) -> bool:
  hostname = (hostname or "").strip().lower()
  if not hostname:
    return False
  hosts, _ = _split_allowlist_entries(entries)
  if not hosts:
    return True
  return any(hostname == entry or hostname.endswith("." + entry) for entry in hosts)


def _scope_in_allowlist(scope_prefix: str, entries) -> bool:
  _, scopes = _split_allowlist_entries(entries)
  if not scopes:
    return True
  scope_prefix = (scope_prefix or "").strip()
  if not scope_prefix:
    return False
  return any(scope_prefix.startswith(entry) for entry in scopes)


def _extract_scope_prefix(target_config) -> str:
  if not isinstance(target_config, dict):
    return ""
  discovery = target_config.get("discovery") or {}
  if not isinstance(discovery, dict):
    return ""
  return str(discovery.get("scope_prefix", "") or "")


def _extract_discovery_max_pages(target_config) -> int:
  if not isinstance(target_config, dict):
    return 50
  discovery = target_config.get("discovery") or {}
  if not isinstance(discovery, dict):
    return 50
  try:
    return max(int(discovery.get("max_pages", 50) or 50), 1)
  except (TypeError, ValueError):
    return 50


def _validate_authorization_context(
  owner,
  *,
  target_host: str,
  scan_type: str,
  authorized: bool,
  target_confirmation: str,
  scope_id: str,
  authorization_ref: str,
  engagement_metadata,
  target_allowlist,
  target_config,
):
  if not authorized:
    return None, validation_error("Scan authorization required. Confirm you are authorized to scan this target.")
  if engagement_metadata is not None and not isinstance(engagement_metadata, dict):
    return None, validation_error("engagement_metadata must be a JSON object when provided")

  normalized_host = (target_host or "").strip().lower()
  normalized_confirmation = (target_confirmation or "").strip().lower()
  if normalized_confirmation and normalized_confirmation != normalized_host:
    return None, validation_error(
      f"target_confirmation must echo the resolved target host ({normalized_host})"
    )

  normalized_allowlist = _normalize_allowlist(
    target_allowlist or getattr(owner, "cfg_scan_target_allowlist", [])
  )
  if normalized_allowlist and not _host_in_allowlist(normalized_host, normalized_allowlist):
    return None, validation_error(
      f"Target {normalized_host} is outside the configured allowlist."
    )

  scope_prefix = _extract_scope_prefix(target_config)
  if scan_type == ScanType.WEBAPP.value and scope_prefix and normalized_allowlist:
    if not _scope_in_allowlist(scope_prefix, normalized_allowlist):
      return None, validation_error(
        f"Configured discovery scope {scope_prefix} is outside the configured allowlist."
      )

  return {
    "target_confirmation": normalized_confirmation or normalized_host,
    "scope_id": str(scope_id or "").strip(),
    "authorization_ref": str(authorization_ref or "").strip(),
    "engagement_metadata": deepcopy(engagement_metadata) if isinstance(engagement_metadata, dict) else None,
    "target_allowlist": normalized_allowlist or None,
  }, None


def _normalize_typed_payload(name: str, payload, model_cls):
  """Validate and normalize optional PTES typed launch payloads."""
  if payload is None:
    return None, None
  if not isinstance(payload, dict):
    return None, validation_error(f"{name} must be a JSON object when provided")
  if not payload:
    return None, None
  try:
    model = model_cls.from_dict(payload)
  except Exception as exc:
    return None, validation_error(f"{name} is malformed: {exc}")
  if model is None:
    return None, None
  validate = getattr(model, "validate", None)
  if callable(validate):
    errors = validate()
    if errors:
      return None, validation_error(f"{name} is invalid: {'; '.join(errors)}")
  is_empty = getattr(model, "is_empty", None)
  if callable(is_empty) and is_empty():
    return None, None
  return model.to_dict(), None


def _validate_typed_engagement_context(engagement, roe, authorization):
  normalized = {}
  for name, payload, model_cls in (
    ("engagement", engagement, EngagementContext),
    ("roe", roe, RulesOfEngagement),
    ("authorization", authorization, AuthorizationRef),
  ):
    value, err = _normalize_typed_payload(name, payload, model_cls)
    if err:
      return None, err
    normalized[name] = value
  return normalized, None


def _apply_launch_safety_policy(
  owner,
  *,
  scan_type: str,
  active_peers: list[str],
  nr_local_workers: int,
  scan_min_delay: float,
  max_weak_attempts: int,
  target_config,
  allow_stateful_probes: bool,
  verify_tls: bool,
):
  warnings = []
  policy = {"scan_type": scan_type}
  target_config_dict = deepcopy(target_config) if isinstance(target_config, dict) else target_config

  if scan_type == ScanType.NETWORK.value:
    concurrency_budget = max(len(active_peers or []), 1) * max(int(nr_local_workers or 1), 1)
    warning_threshold = max(int(getattr(owner, "cfg_network_concurrency_warning_threshold", 16) or 16), 1)
    policy.update({
      "concurrency_budget": concurrency_budget,
      "recommended_concurrency_budget": warning_threshold,
      "scan_min_delay": scan_min_delay,
    })
    if concurrency_budget > warning_threshold:
      warnings.append(
        f"Requested network concurrency {concurrency_budget} exceeds recommended threshold {warning_threshold}."
      )
    policy["warnings"] = warnings
    return max_weak_attempts, target_config_dict, allow_stateful_probes, policy

  graybox_budgets = get_graybox_budgets_config(owner)
  auth_budget = graybox_budgets["AUTH_ATTEMPTS"]
  discovery_budget = graybox_budgets["ROUTE_DISCOVERY"]
  stateful_budget = graybox_budgets["STATEFUL_ACTIONS"]

  requested_attempts = max(int(max_weak_attempts or 0), 0)
  effective_attempts = min(requested_attempts, auth_budget)
  if requested_attempts > effective_attempts:
    warnings.append(
      f"max_weak_attempts capped from {requested_attempts} to policy budget {effective_attempts}."
    )

  requested_pages = _extract_discovery_max_pages(target_config_dict)
  effective_pages = min(requested_pages, discovery_budget)
  if isinstance(target_config_dict, dict):
    discovery = dict(target_config_dict.get("discovery") or {})
    discovery["max_pages"] = effective_pages
    target_config_dict["discovery"] = discovery
  if requested_pages > effective_pages:
    warnings.append(
      f"discovery.max_pages capped from {requested_pages} to policy budget {effective_pages}."
    )

  effective_stateful = bool(allow_stateful_probes and stateful_budget > 0)
  if allow_stateful_probes and not effective_stateful:
    warnings.append("Stateful graybox probes were disabled by policy budget.")
  elif effective_stateful:
    warnings.append("Stateful graybox probes are enabled. Use only for explicitly approved workflows.")

  if not verify_tls:
    warnings.append("TLS verification is disabled for an authenticated scan.")

  policy.update({
    "auth_attempt_budget": auth_budget,
    "effective_auth_attempt_budget": effective_attempts,
    "route_discovery_budget": discovery_budget,
    "effective_route_discovery_budget": effective_pages,
    "stateful_action_budget": stateful_budget,
    "effective_stateful_action_budget": 1 if effective_stateful else 0,
    "warnings": warnings,
  })
  return effective_attempts, target_config_dict, effective_stateful, policy


def parse_exceptions(owner, exceptions):
  """Normalize port-exception input to a list of ints."""
  if not exceptions:
    return []
  if isinstance(exceptions, list):
    return [int(x) for x in exceptions if str(x).isdigit()]
  return [int(x) for x in owner.re.findall(r"\d+", str(exceptions)) if x.isdigit()]


def resolve_enabled_features(owner, excluded_features, scan_type=ScanType.NETWORK.value):
  """Validate excluded features and derive enabled features for audit/config."""
  excluded_features = excluded_features or owner.cfg_excluded_features or []
  all_features = owner._get_all_features(scan_type=scan_type)
  invalid = [f for f in excluded_features if f not in all_features]
  if invalid:
    owner.P(f"Warning: Unknown features in excluded_features (ignored): {owner.json_dumps(invalid)}")
  excluded_features = [f for f in excluded_features if f in all_features]
  enabled_features = [f for f in all_features if f not in excluded_features]
  owner.P(f"Excluded features: {owner.json_dumps(excluded_features)}")
  owner.P(f"Enabled features: {owner.json_dumps(enabled_features)}")
  return excluded_features, enabled_features


def resolve_active_peers(owner, selected_peers):
  """Validate selected peers against chainstore peers and return active peers."""
  chainstore_peers = owner.cfg_chainstore_peers
  if not chainstore_peers:
    return None, validation_error("No workers found in chainstore peers configuration.")

  if selected_peers and len(selected_peers) > 0:
    invalid_peers = [p for p in selected_peers if p not in chainstore_peers]
    if invalid_peers:
      return None, validation_error(
        f"Invalid peer addresses not found in chainstore_peers: {invalid_peers}. "
        f"Available peers: {chainstore_peers}"
      )
    return selected_peers, None
  return chainstore_peers, None


def normalize_common_launch_options(
  owner,
  distribution_strategy,
  port_order,
  run_mode,
  monitor_interval,
  scan_min_delay,
  scan_max_delay,
  nr_local_workers,
):
  """Apply defaults and bounds to common launch settings."""
  distribution_strategy = str(distribution_strategy).upper()
  if not distribution_strategy or distribution_strategy not in [DISTRIBUTION_MIRROR, DISTRIBUTION_SLICE]:
    distribution_strategy = owner.cfg_distribution_strategy

  port_order = str(port_order).upper()
  if not port_order or port_order not in [PORT_ORDER_SHUFFLE, PORT_ORDER_SEQUENTIAL]:
    port_order = owner.cfg_port_order

  run_mode = str(run_mode).upper()
  if not run_mode or run_mode not in [RUN_MODE_SINGLEPASS, RUN_MODE_CONTINUOUS_MONITORING]:
    run_mode = owner.cfg_run_mode
  if monitor_interval <= 0:
    monitor_interval = owner.cfg_monitor_interval

  if scan_min_delay <= 0:
    scan_min_delay = owner.cfg_scan_min_rnd_delay
  if scan_max_delay <= 0:
    scan_max_delay = owner.cfg_scan_max_rnd_delay
  if scan_min_delay > scan_max_delay:
    scan_min_delay, scan_max_delay = scan_max_delay, scan_min_delay

  nr_local_workers = int(nr_local_workers)
  if nr_local_workers <= 0:
    nr_local_workers = owner.cfg_nr_local_workers
  nr_local_workers = max(LOCAL_WORKERS_MIN, min(LOCAL_WORKERS_MAX, nr_local_workers))

  return {
    "distribution_strategy": distribution_strategy,
    "port_order": port_order,
    "run_mode": run_mode,
    "monitor_interval": monitor_interval,
    "scan_min_delay": scan_min_delay,
    "scan_max_delay": scan_max_delay,
    "nr_local_workers": nr_local_workers,
  }


def build_network_workers(owner, active_peers, start_port, end_port, distribution_strategy):
  """Build peer assignments for network scans."""
  num_workers = len(active_peers)
  if num_workers == 0:
    return None, validation_error("No workers available for job execution.")

  workers = {}
  if distribution_strategy == DISTRIBUTION_MIRROR:
    for address in active_peers:
      workers[address] = {
        "start_port": start_port,
        "end_port": end_port,
        "finished": False,
        "result": None,
      }
    return workers, None

  total_ports = end_port - start_port + 1
  base_ports_count = total_ports // num_workers
  rem_ports_count = total_ports % num_workers
  current_start = start_port
  for i, address in enumerate(active_peers):
    size = base_ports_count + 1 if i < rem_ports_count else base_ports_count
    current_end = current_start + size - 1
    workers[address] = {
      "start_port": current_start,
      "end_port": current_end,
      "finished": False,
      "result": None,
    }
    current_start = current_end + 1
  return workers, None


def build_webapp_workers(owner, active_peers, target_port):
  """Build peer assignments for webapp scans. Every peer gets the same target."""
  if not active_peers:
    return None, validation_error("No workers available for job execution.")
  workers = {}
  for address in active_peers:
    workers[address] = {
      "start_port": target_port,
      "end_port": target_port,
      "finished": False,
      "result": None,
    }
  return workers, None


def announce_launch(
  owner,
  *,
  target,
  start_port,
  end_port,
  exceptions,
  distribution_strategy,
  port_order,
  excluded_features,
  run_mode,
  monitor_interval,
  scan_min_delay,
  scan_max_delay,
  task_name,
  task_description,
  active_peers,
  workers,
  redact_credentials,
  ics_safe_mode,
  scanner_identity,
  scanner_user_agent,
  created_by_name,
  created_by_id,
  nr_local_workers,
  scan_type,
  target_url,
  official_username,
  official_password,
  regular_username,
  regular_password,
  weak_candidates,
  max_weak_attempts,
  app_routes,
  verify_tls,
  target_config,
  allow_stateful_probes,
  target_confirmation,
  scope_id,
  authorization_ref,
  engagement_metadata,
  target_allowlist,
  safety_policy,
  engagement=None,
  roe=None,
  authorization=None,
):
  """Persist immutable config, announce job in CStore, and return launch response."""
  excluded_features, enabled_features = resolve_enabled_features(
    owner,
    excluded_features,
    scan_type=scan_type,
  )

  if not scanner_identity:
    scanner_identity = owner.cfg_scanner_identity
  if not scanner_user_agent:
    scanner_user_agent = owner.cfg_scanner_user_agent

  job_id = owner.uuid(8)
  owner.P(f"Launching {job_id=} {target=} with {exceptions=}")
  owner.P(f"Announcing pentest to workers (instance_id {owner.cfg_instance_id})...")

  job_config = JobConfig(
    target=target,
    start_port=start_port,
    end_port=end_port,
    exceptions=exceptions,
    distribution_strategy=distribution_strategy,
    port_order=port_order,
    nr_local_workers=nr_local_workers,
    enabled_features=enabled_features,
    excluded_features=excluded_features,
    run_mode=run_mode,
    scan_min_delay=scan_min_delay,
    scan_max_delay=scan_max_delay,
    ics_safe_mode=ics_safe_mode,
    redact_credentials=redact_credentials,
    scanner_identity=scanner_identity,
    scanner_user_agent=scanner_user_agent,
    task_name=task_name,
    task_description=task_description,
    monitor_interval=monitor_interval,
    selected_peers=active_peers,
    created_by_name=created_by_name or "",
    created_by_id=created_by_id or "",
    authorized=True,
    target_confirmation=target_confirmation,
    scope_id=scope_id,
    authorization_ref=authorization_ref,
    engagement_metadata=engagement_metadata,
    target_allowlist=target_allowlist,
    safety_policy=safety_policy,
    scan_type=scan_type,
    target_url=target_url,
    official_username=official_username,
    official_password=official_password,
    regular_username=regular_username,
    regular_password=regular_password,
    weak_candidates=weak_candidates,
    max_weak_attempts=max_weak_attempts,
    app_routes=app_routes,
    verify_tls=verify_tls,
    target_config=target_config,
    allow_stateful_probes=allow_stateful_probes,
    engagement=engagement,
    roe=roe,
    authorization=authorization,
  )

  persisted_config, job_config_cid = persist_job_config_with_secrets(
    owner,
    job_id=job_id,
    config_dict=job_config.to_dict(),
  )
  if not job_config_cid:
    owner.P("Failed to store job config in R1FS — aborting launch", color='r')
    return {"error": "Failed to store job config in R1FS"}

  job_specs = CStoreJobRunning(
    job_id=job_id,
    job_status=JOB_STATUS_RUNNING,
    job_pass=1,
    run_mode=run_mode,
    launcher=owner.ee_addr,
    launcher_alias=owner.ee_id,
    target=target,
    scan_type=scan_type,
    target_url=target_url,
    task_name=task_name,
    start_port=start_port,
    end_port=end_port,
    date_created=owner.time(),
    job_config_cid=job_config_cid,
    workers=workers,
    timeline=[],
    pass_reports=[],
    next_pass_at=None,
    risk_score=0,
  ).to_dict()
  owner._emit_timeline_event(
    job_specs, "created",
    f"Job created by {created_by_name}",
    actor=created_by_name,
    actor_type="user"
  )
  owner._emit_timeline_event(job_specs, "started", "Scan started", actor=owner.ee_id, actor_type="node")
  emit_lifecycle_event(
    owner,
    job_specs,
    event_type="redmesh.job.started",
    event_action="started",
    event_outcome="success",
    pass_nr=1,
  )

  try:
    redmesh_job_start_attestation = owner._submit_redmesh_job_start_attestation(
      job_id=job_id,
      job_specs=job_specs,
      workers=workers,
    )
    if isinstance(redmesh_job_start_attestation, dict):
      job_specs["redmesh_job_start_attestation"] = redmesh_job_start_attestation
      owner._emit_timeline_event(
        job_specs, "blockchain_submit",
        "Job-start attestation submitted",
        actor_type="system",
        meta={**redmesh_job_start_attestation, "network": owner.REDMESH_ATTESTATION_NETWORK}
      )
      emit_attestation_status_event(
        owner,
        job_specs,
        state="submitted",
        network=owner.REDMESH_ATTESTATION_NETWORK,
        tx_hash=redmesh_job_start_attestation.get("tx_hash"),
        pass_nr=1,
      )
    elif redmesh_job_start_attestation is None:
      emit_attestation_status_event(
        owner,
        job_specs,
        state="skipped",
        network=owner.REDMESH_ATTESTATION_NETWORK,
        pass_nr=1,
      )
  except Exception as exc:
    import traceback
    owner.P(
      f"[ATTESTATION] Failed to submit job-start attestation for job {job_id}: {exc}\n"
      f"  Type: {type(exc).__name__}\n"
      f"  Args: {exc.args}\n"
      f"  Traceback:\n{traceback.format_exc()}",
      color='r'
    )
    emit_attestation_status_event(
      owner,
      job_specs,
      state="failed",
      network=owner.REDMESH_ATTESTATION_NETWORK,
      pass_nr=1,
    )

  write_job_record = getattr(type(owner), "_write_job_record", None)
  if callable(write_job_record):
    write_job_record(owner, job_id, job_specs, context="launch_test")
  else:
    _job_repo(owner).put_job(job_id, job_specs)

  owner._log_audit_event("scan_launched", {
    "job_id": job_id,
    "target": target,
    "start_port": start_port,
    "end_port": end_port,
    "launcher": owner.ee_addr,
    "enabled_features_count": len(enabled_features),
    "redact_credentials": redact_credentials,
    "ics_safe_mode": ics_safe_mode,
    "scope_id": scope_id,
    "authorization_ref": authorization_ref,
    "has_target_allowlist": bool(target_allowlist),
    "safety_warning_count": len((safety_policy or {}).get("warnings", [])),
  })

  all_network_jobs = _job_repo(owner).list_jobs()
  report = {}
  for other_key, other_spec in all_network_jobs.items():
    normalized_key, normalized_spec = owner._normalize_job_record(other_key, other_spec)
    if normalized_key and normalized_key != job_id:
      report[normalized_key] = normalized_spec

  owner.P(f"Current jobs:\n{owner.json_dumps(all_network_jobs, indent=2)}")
  return {
    "job_specs": job_specs,
    "worker": owner.ee_addr,
    "other_jobs": report,
    "job_config": persisted_config,
  }


def launch_network_scan(
  owner,
  *,
  target="",
  start_port=1,
  end_port=65535,
  exceptions="64297",
  distribution_strategy="",
  port_order="",
  excluded_features=None,
  run_mode="",
  monitor_interval=0,
  scan_min_delay=0.0,
  scan_max_delay=0.0,
  task_name="",
  task_description="",
  selected_peers=None,
  redact_credentials=True,
  ics_safe_mode=True,
  scanner_identity="",
  scanner_user_agent="",
  authorized=False,
  created_by_name="",
  created_by_id="",
  nr_local_workers=0,
  target_confirmation="",
  scope_id="",
  authorization_ref="",
  engagement_metadata=None,
  target_allowlist=None,
  engagement=None,
  roe=None,
  authorization=None,
):
  """Launch a network scan using network-specific validation and worker slicing."""
  if not target:
    return validation_error("target required for network scan")

  start_port = int(start_port)
  end_port = int(end_port)
  if start_port > end_port:
    return validation_error("start_port must be less than end_port")

  options = normalize_common_launch_options(
    owner,
    distribution_strategy=distribution_strategy,
    port_order=port_order,
    run_mode=run_mode,
    monitor_interval=monitor_interval,
    scan_min_delay=scan_min_delay,
    scan_max_delay=scan_max_delay,
    nr_local_workers=nr_local_workers,
  )
  active_peers, peer_error = resolve_active_peers(owner, selected_peers)
  if peer_error:
    return peer_error

  authorization_context, auth_error = _validate_authorization_context(
    owner,
    target_host=target,
    scan_type=ScanType.NETWORK.value,
    authorized=authorized,
    target_confirmation=target_confirmation,
    scope_id=scope_id,
    authorization_ref=authorization_ref,
    engagement_metadata=engagement_metadata,
    target_allowlist=target_allowlist,
    target_config=None,
  )
  if auth_error:
    return auth_error
  typed_context, typed_error = _validate_typed_engagement_context(
    engagement, roe, authorization
  )
  if typed_error:
    return typed_error

  max_weak_attempts, target_config, allow_stateful_probes, safety_policy = _apply_launch_safety_policy(
    owner,
    scan_type=ScanType.NETWORK.value,
    active_peers=active_peers,
    nr_local_workers=options["nr_local_workers"],
    scan_min_delay=options["scan_min_delay"],
    max_weak_attempts=5,
    target_config=None,
    allow_stateful_probes=False,
    verify_tls=True,
  )

  workers, worker_error = build_network_workers(
    owner,
    active_peers,
    start_port,
    end_port,
    options["distribution_strategy"],
  )
  if worker_error:
    return worker_error

  return announce_launch(
    owner,
    target=target,
    start_port=start_port,
    end_port=end_port,
    exceptions=parse_exceptions(owner, exceptions),
    distribution_strategy=options["distribution_strategy"],
    port_order=options["port_order"],
    excluded_features=excluded_features,
    run_mode=options["run_mode"],
    monitor_interval=options["monitor_interval"],
    scan_min_delay=options["scan_min_delay"],
    scan_max_delay=options["scan_max_delay"],
    task_name=task_name,
    task_description=task_description,
    active_peers=active_peers,
    workers=workers,
    redact_credentials=redact_credentials,
    ics_safe_mode=ics_safe_mode,
    scanner_identity=scanner_identity,
    scanner_user_agent=scanner_user_agent,
    created_by_name=created_by_name,
    created_by_id=created_by_id,
    nr_local_workers=options["nr_local_workers"],
    scan_type=ScanType.NETWORK.value,
    target_url="",
    official_username="",
    official_password="",
    regular_username="",
    regular_password="",
    weak_candidates=None,
    max_weak_attempts=5,
    app_routes=None,
    verify_tls=True,
    target_config=None,
    allow_stateful_probes=False,
    target_confirmation=authorization_context["target_confirmation"],
    scope_id=authorization_context["scope_id"],
    authorization_ref=authorization_context["authorization_ref"],
    engagement_metadata=authorization_context["engagement_metadata"],
    target_allowlist=authorization_context["target_allowlist"],
    safety_policy=safety_policy,
    engagement=typed_context["engagement"],
    roe=typed_context["roe"],
    authorization=typed_context["authorization"],
  )


def launch_webapp_scan(
  owner,
  *,
  target_url="",
  excluded_features=None,
  run_mode="",
  monitor_interval=0,
  scan_min_delay=0.0,
  scan_max_delay=0.0,
  task_name="",
  task_description="",
  selected_peers=None,
  redact_credentials=True,
  ics_safe_mode=True,
  scanner_identity="",
  scanner_user_agent="",
  authorized=False,
  created_by_name="",
  created_by_id="",
  official_username="",
  official_password="",
  regular_username="",
  regular_password="",
  weak_candidates=None,
  max_weak_attempts=5,
  app_routes=None,
  verify_tls=True,
  target_config=None,
  allow_stateful_probes=False,
  target_confirmation="",
  scope_id="",
  authorization_ref="",
  engagement_metadata=None,
  target_allowlist=None,
  engagement=None,
  roe=None,
  authorization=None,
):
  """Launch a graybox webapp scan using webapp-specific validation and mirrored worker assignment.

  ``target_config`` is a free-form dict deep-copied into the persisted
  ``JobConfig`` (`models/archive.py:80`) and parsed by the worker via
  ``GrayboxTargetConfig.from_dict`` (`graybox/worker.py:108`). All sections
  registered on ``GrayboxTargetConfig`` flow through unchanged, including
  the OWASP API Top 10 ``api_security`` section added in Subphase 1.1 of
  the API Top 10 plan. ``_apply_launch_safety_policy`` only normalises
  the ``discovery`` section; it does not strip unknown keys.
  """
  if not target_url:
    return validation_error("target_url required for webapp scan")
  if not official_username or not official_password:
    return validation_error("official credentials required for webapp scan")

  parsed = urlparse(target_url)
  if parsed.scheme not in ("http", "https") or not parsed.hostname:
    return validation_error("target_url must be a valid http/https URL")

  target = parsed.hostname
  target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

  authorization_context, auth_error = _validate_authorization_context(
    owner,
    target_host=target,
    scan_type=ScanType.WEBAPP.value,
    authorized=authorized,
    target_confirmation=target_confirmation,
    scope_id=scope_id,
    authorization_ref=authorization_ref,
    engagement_metadata=engagement_metadata,
    target_allowlist=target_allowlist,
    target_config=target_config,
  )
  if auth_error:
    return auth_error
  typed_context, typed_error = _validate_typed_engagement_context(
    engagement, roe, authorization
  )
  if typed_error:
    return typed_error

  options = normalize_common_launch_options(
    owner,
    distribution_strategy=DISTRIBUTION_MIRROR,
    port_order=PORT_ORDER_SEQUENTIAL,
    run_mode=run_mode,
    monitor_interval=monitor_interval,
    scan_min_delay=scan_min_delay,
    scan_max_delay=scan_max_delay,
    nr_local_workers=1,
  )
  active_peers, peer_error = resolve_active_peers(owner, selected_peers)
  if peer_error:
    return peer_error

  max_weak_attempts, target_config, allow_stateful_probes, safety_policy = _apply_launch_safety_policy(
    owner,
    scan_type=ScanType.WEBAPP.value,
    active_peers=active_peers,
    nr_local_workers=1,
    scan_min_delay=options["scan_min_delay"],
    max_weak_attempts=max_weak_attempts,
    target_config=target_config,
    allow_stateful_probes=allow_stateful_probes,
    verify_tls=verify_tls,
  )

  workers, worker_error = build_webapp_workers(owner, active_peers, target_port)
  if worker_error:
    return worker_error

  return announce_launch(
    owner,
    target=target,
    start_port=target_port,
    end_port=target_port,
    exceptions=[],
    distribution_strategy=DISTRIBUTION_MIRROR,
    port_order=PORT_ORDER_SEQUENTIAL,
    excluded_features=excluded_features,
    run_mode=options["run_mode"],
    monitor_interval=options["monitor_interval"],
    scan_min_delay=options["scan_min_delay"],
    scan_max_delay=options["scan_max_delay"],
    task_name=task_name,
    task_description=task_description,
    active_peers=active_peers,
    workers=workers,
    redact_credentials=redact_credentials,
    ics_safe_mode=ics_safe_mode,
    scanner_identity=scanner_identity,
    scanner_user_agent=scanner_user_agent,
    created_by_name=created_by_name,
    created_by_id=created_by_id,
    nr_local_workers=1,
    scan_type=ScanType.WEBAPP.value,
    target_url=target_url,
    official_username=official_username,
    official_password=official_password,
    regular_username=regular_username,
    regular_password=regular_password,
    weak_candidates=weak_candidates,
    max_weak_attempts=max_weak_attempts,
    app_routes=app_routes,
    verify_tls=verify_tls,
    target_config=target_config,
    allow_stateful_probes=allow_stateful_probes,
    target_confirmation=authorization_context["target_confirmation"],
    scope_id=authorization_context["scope_id"],
    authorization_ref=authorization_context["authorization_ref"],
    engagement_metadata=authorization_context["engagement_metadata"],
    target_allowlist=authorization_context["target_allowlist"],
    safety_policy=safety_policy,
    engagement=typed_context["engagement"],
    roe=typed_context["roe"],
    authorization=typed_context["authorization"],
  )


def launch_test(
  owner,
  *,
  target="",
  start_port=1,
  end_port=65535,
  exceptions="64297",
  distribution_strategy="",
  port_order="",
  excluded_features=None,
  run_mode="",
  monitor_interval=0,
  scan_min_delay=0.0,
  scan_max_delay=0.0,
  task_name="",
  task_description="",
  selected_peers=None,
  redact_credentials=True,
  ics_safe_mode=True,
  scanner_identity="",
  scanner_user_agent="",
  authorized=False,
  created_by_name="",
  created_by_id="",
  nr_local_workers=0,
  scan_type="network",
  target_url="",
  official_username="",
  official_password="",
  regular_username="",
  regular_password="",
  weak_candidates=None,
  max_weak_attempts=5,
  app_routes=None,
  verify_tls=True,
  target_config=None,
  allow_stateful_probes=False,
  target_confirmation="",
  scope_id="",
  authorization_ref="",
  engagement_metadata=None,
  target_allowlist=None,
  engagement=None,
  roe=None,
  authorization=None,
):
  """Compatibility shim that routes to scan-type-specific launch endpoints."""
  try:
    scan_type_enum = ScanType(scan_type)
  except ValueError:
    return validation_error(f"Invalid scan_type: {scan_type}. Valid: {[e.value for e in ScanType]}")

  if scan_type_enum == ScanType.WEBAPP:
    return owner.launch_webapp_scan(
      target_url=target_url,
      excluded_features=excluded_features,
      run_mode=run_mode,
      monitor_interval=monitor_interval,
      scan_min_delay=scan_min_delay,
      scan_max_delay=scan_max_delay,
      task_name=task_name,
      task_description=task_description,
      selected_peers=selected_peers,
      redact_credentials=redact_credentials,
      ics_safe_mode=ics_safe_mode,
      scanner_identity=scanner_identity,
      scanner_user_agent=scanner_user_agent,
      authorized=authorized,
      created_by_name=created_by_name,
      created_by_id=created_by_id,
      official_username=official_username,
      official_password=official_password,
      regular_username=regular_username,
      regular_password=regular_password,
      weak_candidates=weak_candidates,
      max_weak_attempts=max_weak_attempts,
      app_routes=app_routes,
      verify_tls=verify_tls,
      target_config=target_config,
      allow_stateful_probes=allow_stateful_probes,
      target_confirmation=target_confirmation,
      scope_id=scope_id,
      authorization_ref=authorization_ref,
      engagement_metadata=engagement_metadata,
      target_allowlist=target_allowlist,
      engagement=engagement,
      roe=roe,
      authorization=authorization,
    )

  return owner.launch_network_scan(
    target=target,
    start_port=start_port,
    end_port=end_port,
    exceptions=exceptions,
    distribution_strategy=distribution_strategy,
    port_order=port_order,
    excluded_features=excluded_features,
    run_mode=run_mode,
    monitor_interval=monitor_interval,
    scan_min_delay=scan_min_delay,
    scan_max_delay=scan_max_delay,
    task_name=task_name,
    task_description=task_description,
    selected_peers=selected_peers,
    redact_credentials=redact_credentials,
    ics_safe_mode=ics_safe_mode,
    scanner_identity=scanner_identity,
    scanner_user_agent=scanner_user_agent,
    authorized=authorized,
    created_by_name=created_by_name,
    created_by_id=created_by_id,
    nr_local_workers=nr_local_workers,
    target_confirmation=target_confirmation,
    scope_id=scope_id,
    authorization_ref=authorization_ref,
    engagement_metadata=engagement_metadata,
    target_allowlist=target_allowlist,
    engagement=engagement,
    roe=roe,
    authorization=authorization,
  )
