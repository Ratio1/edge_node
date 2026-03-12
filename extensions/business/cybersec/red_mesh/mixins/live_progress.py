"""
Live progress mixin for RedMesh pentester API.

Handles real-time scan progress publishing to the CStore `:live` hset
and merging of scan metrics across worker threads.
"""

from ..models import WorkerProgress
from ..constants import PHASE_ORDER, GRAYBOX_PHASE_ORDER

DEFAULT_PROGRESS_PUBLISH_INTERVAL = 30.0


def _thread_phase(state):
  """Determine which phase a single thread is currently in.

  Supports both network and webapp (graybox) scan types. Network
  scans use the existing phase markers. Webapp scans use graybox_*
  markers and map to their own phase names.
  """
  tests = set(state.get("completed_tests", []))
  scan_type = state.get("scan_type")

  if scan_type == "webapp":
    # Graybox phase progression:
    # preflight -> authentication -> discovery -> graybox_probes -> weak_auth -> done
    if "graybox_weak_auth" in tests or "graybox_probes" in tests:
      return "done"
    if "graybox_discovery" in tests:
      return "graybox_probes"
    if "graybox_auth" in tests:
      return "discovery"
    return "preflight"

  # Network phase progression (unchanged):
  if "correlation_completed" in tests:
    return "done"
  if "web_tests_completed" in tests:
    return "correlation"
  if "service_info_completed" in tests:
    return "web_tests"
  if "fingerprint_completed" in tests:
    return "service_probes"
  return "port_scan"


class _LiveProgressMixin:
  """Live progress tracking methods for PentesterApi01Plugin."""

  def _get_progress_publish_interval(self):
    """Return a safe numeric live-progress publish interval in seconds."""
    interval = getattr(self, "_progress_publish_interval", None)
    if interval is None:
      interval = getattr(self, "cfg_progress_publish_interval", None)
    if interval is None:
      config = getattr(self, "CONFIG", None)
      if isinstance(config, dict):
        interval = config.get("PROGRESS_PUBLISH_INTERVAL")
    try:
      interval = float(interval)
    except (TypeError, ValueError):
      interval = DEFAULT_PROGRESS_PUBLISH_INTERVAL
    if interval <= 0:
      interval = DEFAULT_PROGRESS_PUBLISH_INTERVAL
    return interval

  @staticmethod
  def _merge_worker_metrics(metrics_list):
    """Merge scan_metrics dicts from multiple local worker threads."""
    if not metrics_list:
      return None
    merged = {}
    # Sum connection outcomes
    outcomes = {}
    for m in metrics_list:
      for k, v in (m.get("connection_outcomes") or {}).items():
        outcomes[k] = outcomes.get(k, 0) + v
    if outcomes:
      merged["connection_outcomes"] = outcomes
    # Sum coverage
    cov_scanned = sum(m.get("coverage", {}).get("ports_scanned", 0) for m in metrics_list if m.get("coverage"))
    cov_range = sum(m.get("coverage", {}).get("ports_in_range", 0) for m in metrics_list if m.get("coverage"))
    cov_skipped = sum(m.get("coverage", {}).get("ports_skipped", 0) for m in metrics_list if m.get("coverage"))
    cov_open = sum(m.get("coverage", {}).get("open_ports_count", 0) for m in metrics_list if m.get("coverage"))
    if cov_range:
      merged["coverage"] = {
        "ports_in_range": cov_range, "ports_scanned": cov_scanned,
        "ports_skipped": cov_skipped,
        "coverage_pct": round(cov_scanned / cov_range * 100, 1),
        "open_ports_count": cov_open,
      }
    # Sum finding distribution
    findings = {}
    for m in metrics_list:
      for k, v in (m.get("finding_distribution") or {}).items():
        findings[k] = findings.get(k, 0) + v
    if findings:
      merged["finding_distribution"] = findings
    # Sum service distribution
    services = {}
    for m in metrics_list:
      for k, v in (m.get("service_distribution") or {}).items():
        services[k] = services.get(k, 0) + v
    if services:
      merged["service_distribution"] = services
    # Sum probe counts
    for field in ("probes_attempted", "probes_completed", "probes_skipped", "probes_failed"):
      merged[field] = sum(m.get(field, 0) for m in metrics_list)
    # Sum graybox scenario counters
    for field in (
      "scenarios_total",
      "scenarios_vulnerable",
      "scenarios_clean",
      "scenarios_inconclusive",
      "scenarios_error",
    ):
      merged[field] = sum(m.get(field, 0) for m in metrics_list)
    # Merge probe breakdown (union of all probes)
    probe_bd = {}
    for m in metrics_list:
      for k, v in (m.get("probe_breakdown") or {}).items():
        # Keep worst status: failed > skipped > completed
        existing = probe_bd.get(k)
        if existing is None or v == "failed" or (v.startswith("skipped") and existing == "completed"):
          probe_bd[k] = v
    if probe_bd:
      merged["probe_breakdown"] = probe_bd
    # Total duration: max across threads/nodes (they run in parallel)
    merged["total_duration"] = max(m.get("total_duration", 0) for m in metrics_list)
    # Phase durations: max per phase (threads/nodes run in parallel, so wall-clock
    # time for each phase is the max across all of them)
    all_phases = {}
    for m in metrics_list:
      for phase, dur in (m.get("phase_durations") or {}).items():
        all_phases[phase] = max(all_phases.get(phase, 0), dur)
    if all_phases:
      merged["phase_durations"] = all_phases
    longest = max(metrics_list, key=lambda m: m.get("total_duration", 0))
    # Merge stats distributions (response_times, port_scan_delays)
    # Use weighted mean, global min/max, approximate p95/p99 from max of per-thread values
    for stats_field in ("response_times", "port_scan_delays"):
      stats_list = [m[stats_field] for m in metrics_list if m.get(stats_field)]
      if stats_list:
        total_count = sum(s.get("count", 0) for s in stats_list)
        if total_count > 0:
          merged[stats_field] = {
            "min": min(s["min"] for s in stats_list),
            "max": max(s["max"] for s in stats_list),
            "mean": round(sum(s["mean"] * s.get("count", 1) for s in stats_list) / total_count, 4),
            "median": round(sum(s["median"] * s.get("count", 1) for s in stats_list) / total_count, 4),
            "stddev": round(max(s.get("stddev", 0) for s in stats_list), 4),
            "p95": round(max(s.get("p95", 0) for s in stats_list), 4),
            "p99": round(max(s.get("p99", 0) for s in stats_list), 4),
            "count": total_count,
          }
    # Success rate over time: take from the longest-running thread
    if longest.get("success_rate_over_time"):
      merged["success_rate_over_time"] = longest["success_rate_over_time"]
    # Detection flags (any thread detecting = True)
    merged["rate_limiting_detected"] = any(m.get("rate_limiting_detected") for m in metrics_list)
    merged["blocking_detected"] = any(m.get("blocking_detected") for m in metrics_list)
    # Open port details: union, deduplicate by port
    all_details = []
    seen_ports = set()
    for m in metrics_list:
      for d in (m.get("open_port_details") or []):
        if d["port"] not in seen_ports:
          seen_ports.add(d["port"])
          all_details.append(d)
    if all_details:
      merged["open_port_details"] = sorted(all_details, key=lambda x: x["port"])
    # Banner confirmation: sum counts
    bc_confirmed = sum(m.get("banner_confirmation", {}).get("confirmed", 0) for m in metrics_list)
    bc_guessed = sum(m.get("banner_confirmation", {}).get("guessed", 0) for m in metrics_list)
    if bc_confirmed + bc_guessed > 0:
      merged["banner_confirmation"] = {"confirmed": bc_confirmed, "guessed": bc_guessed}
    return merged

  def _publish_live_progress(self):
    """
    Publish live progress for all active local scan jobs.

    Builds per-thread progress data and writes a single WorkerProgress entry
    per job to the `:live` CStore hset. Called periodically from process().

    Progress is stage-based (stage_idx / 5 * 100) with port-scan sub-progress.
    Phase is the earliest (least advanced) phase across all threads.
    Per-thread data (phase, ports) is included when multiple threads are active.
    """
    now = self.time()
    publish_interval = _LiveProgressMixin._get_progress_publish_interval(self)
    if now - self._last_progress_publish < publish_interval:
      return
    self._last_progress_publish = now

    live_hkey = f"{self.cfg_instance_id}:live"
    ee_addr = self.ee_addr

    for job_id, local_workers in self.scan_jobs.items():
      if not local_workers:
        continue

      # Determine phase order based on scan type (inspect first worker)
      first_worker = next(iter(local_workers.values()))
      if first_worker.state.get("scan_type") == "webapp":
        phase_order = GRAYBOX_PHASE_ORDER
      else:
        phase_order = PHASE_ORDER
      nr_phases = len(phase_order)

      # Build per-thread data
      total_scanned = 0
      total_ports = 0
      all_open = set()
      all_tests = set()
      thread_entries = {}
      thread_phases = []
      worker_metrics = []

      for tid, worker in local_workers.items():
        state = worker.state
        nr_ports = len(worker.initial_ports)
        t_scanned = len(state.get("ports_scanned", []))
        t_open = sorted(state.get("open_ports", []))
        t_phase = _thread_phase(state)

        total_scanned += t_scanned
        total_ports += nr_ports
        all_open.update(t_open)
        all_tests.update(state.get("completed_tests", []))
        worker_metrics.append(worker.metrics.build().to_dict())
        thread_phases.append(t_phase)

        thread_entries[tid] = {
          "phase": t_phase,
          "ports_scanned": t_scanned,
          "ports_total": nr_ports,
          "open_ports_found": t_open,
        }

      # Overall phase: earliest (least advanced) across threads
      phase_indices = [phase_order.index(p) if p in phase_order else nr_phases for p in thread_phases]
      min_phase_idx = min(phase_indices) if phase_indices else 0
      phase = phase_order[min_phase_idx] if min_phase_idx < nr_phases else "done"

      # Stage-based progress: completed_stages / total * 100
      # During port_scan, add sub-progress based on ports scanned
      stage_progress = (min_phase_idx / nr_phases) * 100
      if phase == "port_scan" and total_ports > 0:
        stage_progress += (total_scanned / total_ports) * (100 / nr_phases)
      progress_pct = round(min(stage_progress, 100), 1)

      # Look up pass number from CStore
      job_specs = self.chainstore_hget(hkey=self.cfg_instance_id, key=job_id)
      pass_nr = 1
      if isinstance(job_specs, dict):
        pass_nr = job_specs.get("job_pass", 1)

      # Merge metrics from all local threads
      merged_metrics = worker_metrics[0] if len(worker_metrics) == 1 else self._merge_worker_metrics(worker_metrics)

      progress = WorkerProgress(
        job_id=job_id,
        worker_addr=ee_addr,
        pass_nr=pass_nr,
        progress=progress_pct,
        phase=phase,
        ports_scanned=total_scanned,
        ports_total=total_ports,
        open_ports_found=sorted(all_open),
        completed_tests=sorted(all_tests),
        updated_at=now,
        live_metrics=merged_metrics,
        threads=thread_entries if len(thread_entries) > 1 else None,
      )
      self.chainstore_hset(
        hkey=live_hkey,
        key=f"{job_id}:{ee_addr}",
        value=progress.to_dict(),
      )
      self.P(
        "[LIVE->CSTORE] Published worker progress "
        f"job_id={job_id} worker={ee_addr} pass={pass_nr} "
        f"phase={phase} progress={progress_pct}% "
        f"ports={total_scanned}/{total_ports} open={len(all_open)} "
        f"key={job_id}:{ee_addr}"
      )

  def _clear_live_progress(self, job_id, worker_addresses):
    """
    Remove live progress keys for a completed job.

    Parameters
    ----------
    job_id : str
      Job identifier.
    worker_addresses : list[str]
      Worker addresses whose progress keys should be removed.
    """
    live_hkey = f"{self.cfg_instance_id}:live"
    for addr in worker_addresses:
      self.chainstore_hset(
        hkey=live_hkey,
        key=f"{job_id}:{addr}",
        value=None,  # delete
      )
