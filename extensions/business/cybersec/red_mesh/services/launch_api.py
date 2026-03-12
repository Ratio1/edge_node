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
from ..models import JobConfig
from .secrets import persist_job_config_with_secrets


def validation_error(message: str):
  """Return a consistent validation error payload."""
  return {"error": "validation_error", "message": message}


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
  )

  config_dict = job_config.to_dict()
  persisted_config, job_config_cid = persist_job_config_with_secrets(
    owner,
    job_id=job_id,
    config_dict=config_dict,
  )
  if not job_config_cid:
    owner.P("Failed to store job config in R1FS — aborting launch", color='r')
    return {"error": "Failed to store job config in R1FS"}

  job_specs = {
    "job_id": job_id,
    "target": target,
    "task_name": task_name,
    "scan_type": scan_type,
    "target_url": target_url,
    "start_port": start_port,
    "end_port": end_port,
    "risk_score": 0,
    "date_created": owner.time(),
    "launcher": owner.ee_addr,
    "launcher_alias": owner.ee_id,
    "timeline": [],
    "workers": workers,
    "job_status": JOB_STATUS_RUNNING,
    "run_mode": run_mode,
    "job_pass": 1,
    "next_pass_at": None,
    "pass_reports": [],
    "job_config_cid": job_config_cid,
  }
  owner._emit_timeline_event(
    job_specs, "created",
    f"Job created by {created_by_name}",
    actor=created_by_name,
    actor_type="user"
  )
  owner._emit_timeline_event(job_specs, "started", "Scan started", actor=owner.ee_id, actor_type="node")

  try:
    redmesh_job_start_attestation = owner._submit_redmesh_job_start_attestation(
      job_id=job_id,
      job_specs=job_specs,
      workers=workers,
    )
    if redmesh_job_start_attestation is not None:
      job_specs["redmesh_job_start_attestation"] = redmesh_job_start_attestation
      owner._emit_timeline_event(
        job_specs, "blockchain_submit",
        "Job-start attestation submitted",
        actor_type="system",
        meta={**redmesh_job_start_attestation, "network": owner.REDMESH_ATTESTATION_NETWORK}
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

  write_job_record = getattr(type(owner), "_write_job_record", None)
  if callable(write_job_record):
    write_job_record(owner, job_id, job_specs, context="launch_test")
  else:
    owner.chainstore_hset(hkey=owner.cfg_instance_id, key=job_id, value=job_specs)

  owner._log_audit_event("scan_launched", {
    "job_id": job_id,
    "target": target,
    "start_port": start_port,
    "end_port": end_port,
    "launcher": owner.ee_addr,
    "enabled_features_count": len(enabled_features),
    "redact_credentials": redact_credentials,
    "ics_safe_mode": ics_safe_mode,
  })

  all_network_jobs = owner.chainstore_hgetall(hkey=owner.cfg_instance_id)
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
):
  """Launch a network scan using network-specific validation and worker slicing."""
  if not authorized:
    return validation_error("Scan authorization required. Confirm you are authorized to scan this target.")
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
):
  """Launch a graybox webapp scan using webapp-specific validation and mirrored worker assignment."""
  if not authorized:
    return validation_error("Scan authorization required. Confirm you are authorized to scan this target.")
  if not target_url:
    return validation_error("target_url required for webapp scan")
  if not official_username or not official_password:
    return validation_error("official credentials required for webapp scan")

  parsed = urlparse(target_url)
  if parsed.scheme not in ("http", "https") or not parsed.hostname:
    return validation_error("target_url must be a valid http/https URL")

  target = parsed.hostname
  target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

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
  )
