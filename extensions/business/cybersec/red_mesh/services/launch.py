import random

from ..constants import (
  PORT_ORDER_SEQUENTIAL,
  PORT_ORDER_SHUFFLE,
  ScanType,
)
from ..models import JobConfig
from .scan_strategy import get_scan_strategy


def _launch_network_jobs(
  owner,
  strategy,
  *,
  job_id,
  target,
  launcher,
  start_port,
  end_port,
  job_config,
  nr_local_workers_override=None,
):
  exceptions = job_config.get("exceptions", [])
  if not isinstance(exceptions, list):
    exceptions = []
  port_order = job_config.get("port_order", owner.cfg_port_order)
  excluded_features = job_config.get("excluded_features", owner.cfg_excluded_features)
  enabled_features = job_config.get("enabled_features", [])
  scan_min_delay = job_config.get("scan_min_delay", owner.cfg_scan_min_rnd_delay)
  scan_max_delay = job_config.get("scan_max_delay", owner.cfg_scan_max_rnd_delay)
  ics_safe_mode = job_config.get("ics_safe_mode", owner.cfg_ics_safe_mode)
  scanner_identity = job_config.get("scanner_identity", owner.cfg_scanner_identity)
  scanner_user_agent = job_config.get("scanner_user_agent", owner.cfg_scanner_user_agent)
  workers_from_spec = job_config.get("nr_local_workers")
  if nr_local_workers_override is not None:
    workers_requested = nr_local_workers_override
  elif workers_from_spec is not None and int(workers_from_spec) > 0:
    workers_requested = int(workers_from_spec)
  else:
    workers_requested = owner.cfg_nr_local_workers

  owner.P("Using {} local workers for job {}".format(workers_requested, job_id))

  ports = list(range(start_port, end_port + 1))
  batches = []
  if port_order == PORT_ORDER_SEQUENTIAL:
    ports = sorted(ports)
  else:
    port_order = PORT_ORDER_SHUFFLE
    random.shuffle(ports)

  nr_ports = len(ports)
  if nr_ports == 0:
    raise ValueError("No ports available for local workers.")

  workers_requested = max(1, min(workers_requested, nr_ports))
  base_chunk, remainder = divmod(nr_ports, workers_requested)
  start_index = 0
  for index in range(workers_requested):
    chunk = base_chunk + (1 if index < remainder else 0)
    end_index = start_index + chunk
    batch = ports[start_index:end_index]
    if batch:
      batches.append(batch)
    start_index = end_index

  if not batches:
    raise ValueError("Unable to allocate port batches to workers.")

  local_jobs = {}
  for index, batch in enumerate(batches):
    try:
      owner.P("Launching {} requested by {} for target {} - {} ports. Port order {}".format(
        job_id, launcher, target, len(batch), port_order
      ))
      batch_job = strategy.worker_cls(
        owner=owner,
        local_id_prefix=str(index + 1),
        target=target,
        job_id=job_id,
        initiator=launcher,
        exceptions=exceptions,
        worker_target_ports=batch,
        excluded_features=excluded_features,
        enabled_features=enabled_features,
        scan_min_delay=scan_min_delay,
        scan_max_delay=scan_max_delay,
        ics_safe_mode=ics_safe_mode,
        scanner_identity=scanner_identity,
        scanner_user_agent=scanner_user_agent,
      )
      batch_job.start()
      local_jobs[batch_job.local_worker_id] = batch_job
    except Exception as exc:
      owner.P(
        "Failed to launch batch local job for ports [{}-{}]. Port order {}: {}".format(
          min(batch) if batch else "-",
          max(batch) if batch else "-",
          port_order,
          exc,
        ),
        color='r'
      )

  if not local_jobs:
    raise ValueError("No local workers could be launched for the requested port range.")
  return local_jobs


def _launch_webapp_job(
  owner,
  strategy,
  *,
  job_id,
  launcher,
  job_config,
):
  job_config_obj = JobConfig.from_dict(job_config)
  worker = strategy.worker_cls(
    owner=owner,
    job_id=job_id,
    target_url=job_config_obj.target_url,
    job_config=job_config_obj,
    local_id="1",
    initiator=launcher,
  )
  worker.start()
  return {worker.local_worker_id: worker}


def launch_local_jobs(
  owner,
  *,
  job_id,
  target,
  launcher,
  start_port,
  end_port,
  job_config,
  nr_local_workers_override=None,
):
  strategy = get_scan_strategy(job_config.get("scan_type", ScanType.NETWORK.value))
  if strategy.scan_type == ScanType.WEBAPP:
    return _launch_webapp_job(
      owner,
      strategy,
      job_id=job_id,
      launcher=launcher,
      job_config=job_config,
    )

  return _launch_network_jobs(
    owner,
    strategy,
    job_id=job_id,
    target=target,
    launcher=launcher,
    start_port=start_port,
    end_port=end_port,
    job_config=job_config,
    nr_local_workers_override=nr_local_workers_override,
  )
