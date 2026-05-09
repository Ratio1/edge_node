import random

from ..constants import (
  JOB_STATUS_ANALYZING,
  JOB_STATUS_COLLECTING,
  JOB_STATUS_FINALIZED,
  JOB_STATUS_FINALIZING,
  JOB_STATUS_RUNNING,
  JOB_STATUS_SCHEDULED_FOR_STOP,
  JOB_STATUS_STOPPED,
  MAX_CONTINUOUS_PASSES,
  RUN_MODE_CONTINUOUS_MONITORING,
  RUN_MODE_SINGLEPASS,
)
from ..models import AggregatedScanData, PassReport, PassReportRef, WorkerReportMeta
from ..repositories import ArtifactRepository, JobStateRepository
from .config import get_attestation_config
from .config import get_llm_agent_config
from .event_hooks import (
  emit_attestation_status_event,
  emit_finding_event,
  emit_lifecycle_event,
)
from .scan_strategy import coerce_scan_type, get_scan_strategy
from .state_machine import is_intermediate_job_status, is_terminal_job_status, set_job_status


def _job_repo(owner):
  getter = getattr(type(owner), "_get_job_state_repository", None)
  if callable(getter):
    return getter(owner)
  return JobStateRepository(owner)


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


def _write_job_record(owner, job_key, job_specs, context):
  write_job_record = getattr(type(owner), "_write_job_record", None)
  if callable(write_job_record):
    return write_job_record(owner, job_key, job_specs, context=context)
  return job_specs


def maybe_finalize_pass(owner):
  """
  Launcher finalizes completed passes and orchestrates continuous monitoring.
  """
  all_jobs = _job_repo(owner).list_jobs()
  artifacts = _artifact_repo(owner)

  for job_key, job_specs in all_jobs.items():
    normalized_key, job_specs = owner._normalize_job_record(job_key, job_specs)
    if normalized_key is None:
      continue

    is_launcher = job_specs.get("launcher") == owner.ee_addr
    if not is_launcher:
      continue

    workers = job_specs.get("workers", {})
    if not workers:
      continue

    run_mode = job_specs.get("run_mode", RUN_MODE_SINGLEPASS)
    job_status = job_specs.get("job_status", JOB_STATUS_RUNNING)
    all_finished = all(w.get("finished") for w in workers.values())
    next_pass_at = job_specs.get("next_pass_at")
    job_pass = job_specs.get("job_pass", 1)
    job_id = job_specs.get("job_id")
    if is_terminal_job_status(job_status):
      if not job_specs.get("job_cid") and job_specs.get("pass_reports"):
        owner.P(f"[STUCK RECOVERY] {job_id} is {job_status} but has no job_cid — retrying archive build", color='y')
        owner._build_job_archive(job_id, job_specs)
      continue
    if is_intermediate_job_status(job_status):
      continue

    if all_finished and next_pass_at is None:
      pass_date_started = owner._get_timeline_date(job_specs, "pass_started") or owner._get_timeline_date(job_specs, "created")
      pass_date_completed = owner.time()
      now_ts = pass_date_completed

      set_job_status(job_specs, JOB_STATUS_COLLECTING)
      job_specs = _write_job_record(owner, job_key, job_specs, context="finalize_collecting")

      node_reports = owner._collect_node_reports(workers)
      # Audit #4: resolve the worker class from scan_type so
      # graybox-specific aggregation fields (graybox_results,
      # completed_tests, aborted/abort_reason/abort_phase) merge
      # across multiple graybox workers instead of being dropped
      # by the default network-worker rules.
      scan_type_raw = job_specs.get("scan_type")
      try:
        strategy = get_scan_strategy(coerce_scan_type(scan_type_raw))
        worker_cls = strategy.worker_cls
      except Exception:
        worker_cls = None
      aggregated = (
        owner._get_aggregated_report(node_reports, worker_cls=worker_cls)
        if node_reports else {}
      )
      if node_reports:
        owner.P(
          f"[FINALIZE] {job_id} pass {job_pass} aggregating as "
          f"{scan_type_raw or 'network'} via "
          f"{worker_cls.__name__ if worker_cls else 'default'} "
          f"({len(node_reports)} worker reports)"
        )

      risk_score = 0
      flat_findings = []
      risk_result = None
      if aggregated:
        risk_result, flat_findings = owner._compute_risk_and_findings(aggregated)
        risk_score = risk_result["score"]
        job_specs["risk_score"] = risk_score
        owner.P(f"Risk score for job {job_id} pass {job_pass}: {risk_score}/100")

      job_config = owner._get_job_config(job_specs)
      llm_cfg = get_llm_agent_config(owner)
      llm_text = None
      summary_text = None
      llm_report_sections = None
      structured_llm_failed = None
      if llm_cfg["ENABLED"] and aggregated:
        set_job_status(job_specs, JOB_STATUS_ANALYZING)
        job_specs = _write_job_record(owner, job_key, job_specs, context="finalize_analyzing")
        # PTES report narrative uses only the structured LLM path.
        # Legacy aggregate/quick-summary calls accepted raw scan-shaped
        # payloads and are intentionally bypassed for report finalization.
        try:
          llm_report_sections = owner._run_structured_report_sections(
            job_id=job_id,
            findings=flat_findings,
            aggregated_report=aggregated,
            engagement=job_config.get("engagement") if isinstance(job_config, dict) else None,
          )
          structured_llm_failed = getattr(owner, "_last_structured_llm_failed", None)
        except Exception as exc:
          owner.P(
            f"Structured LLM call raised for job {job_id}: {exc}",
            color='y',
          )
          llm_report_sections = None
          structured_llm_failed = True

      llm_failed = True if (llm_cfg["ENABLED"] and structured_llm_failed) else None
      if llm_failed:
        owner._emit_timeline_event(
          job_specs, "llm_failed",
          f"LLM analysis unavailable for pass {job_pass}",
          meta={"pass_nr": job_pass}
        )

      worker_metas = {}
      for addr, report in node_reports.items():
        nr_findings = owner._count_all_findings(report)
        worker_metas[addr] = WorkerReportMeta(
          report_cid=workers[addr].get("report_cid", ""),
          start_port=report.get("start_port", 0),
          end_port=report.get("end_port", 0),
          ports_scanned=report.get("ports_scanned", 0),
          open_ports=report.get("open_ports", []),
          nr_findings=nr_findings,
          node_ip=report.get("node_ip", ""),
        ).to_dict()

      aggregated_report_cid = None
      if aggregated:
        aggregated_data = AggregatedScanData.from_dict(aggregated).to_dict()
        aggregated_report_cid = artifacts.put_json(aggregated_data, show_logs=False)
        if not aggregated_report_cid:
          owner.P(f"Failed to store aggregated report for pass {job_pass} in R1FS", color='r')
          continue

      redmesh_test_attestation = None
      should_submit_attestation = True
      if run_mode == RUN_MODE_CONTINUOUS_MONITORING:
        last_attestation_at = job_specs.get("last_attestation_at")
        min_interval = get_attestation_config(owner)["MIN_SECONDS_BETWEEN_SUBMITS"]
        if last_attestation_at is not None and now_ts - last_attestation_at < min_interval:
          elapsed = round(now_ts - last_attestation_at)
          owner.P(
            f"[ATTESTATION] Skipping test attestation for job {job_id}: "
            f"last submitted {elapsed}s ago, min interval is {min_interval}s",
            color='y'
          )
          should_submit_attestation = False

      if should_submit_attestation:
        try:
          attestation_node_ips = [
            r.get("node_ip") for r in node_reports.values()
            if r.get("node_ip")
          ]
          redmesh_test_attestation = owner._submit_redmesh_test_attestation(
            job_id=job_id,
            job_specs=job_specs,
            workers=workers,
            vulnerability_score=risk_score,
            node_ips=attestation_node_ips,
            report_cid=aggregated_report_cid,
          )
          if isinstance(redmesh_test_attestation, dict):
            job_specs["last_attestation_at"] = now_ts
            emit_attestation_status_event(
              owner,
              job_specs,
              state="submitted",
              network=owner.REDMESH_ATTESTATION_NETWORK,
              tx_hash=redmesh_test_attestation.get("tx_hash"),
              pass_nr=job_pass,
            )
          elif redmesh_test_attestation is None:
            emit_attestation_status_event(
              owner,
              job_specs,
              state="skipped",
              network=owner.REDMESH_ATTESTATION_NETWORK,
              pass_nr=job_pass,
            )
        except Exception as exc:
          import traceback
          owner.P(
            f"[ATTESTATION] Failed to submit test attestation for job {job_id}: {exc}\n"
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
            pass_nr=job_pass,
          )
      else:
        emit_attestation_status_event(
          owner,
          job_specs,
          state="skipped",
          network=owner.REDMESH_ATTESTATION_NETWORK,
          pass_nr=job_pass,
        )

      worker_scan_metrics = {}
      for addr, report in node_reports.items():
        if report.get("scan_metrics"):
          entry = {"scan_metrics": report["scan_metrics"]}
          if report.get("thread_scan_metrics"):
            entry["threads"] = report["thread_scan_metrics"]
          worker_scan_metrics[addr] = entry
      node_metrics = [e["scan_metrics"] for e in worker_scan_metrics.values()]
      pass_metrics = None
      if node_metrics:
        pass_metrics = node_metrics[0] if len(node_metrics) == 1 else owner._merge_worker_metrics(node_metrics)

      pass_report = PassReport(
        pass_nr=job_pass,
        date_started=pass_date_started,
        date_completed=pass_date_completed,
        duration=round(pass_date_completed - pass_date_started, 2) if pass_date_started else 0,
        aggregated_report_cid=aggregated_report_cid or "",
        worker_reports=worker_metas,
        risk_score=risk_score,
        risk_breakdown=risk_result["breakdown"] if risk_result else None,
        llm_analysis=llm_text,
        quick_summary=summary_text,
        llm_failed=llm_failed,
        llm_report_sections=llm_report_sections,
        findings=flat_findings if flat_findings else None,
        scan_metrics=pass_metrics,
        worker_scan_metrics=worker_scan_metrics if worker_scan_metrics else None,
        redmesh_test_attestation=redmesh_test_attestation,
      )

      pass_report_cid = artifacts.put_pass_report(pass_report, show_logs=False)
      if not pass_report_cid:
        owner.P(f"Failed to store pass report for pass {job_pass} in R1FS", color='r')
        continue

      job_specs.setdefault("pass_reports", []).append(
        PassReportRef(job_pass, pass_report_cid, risk_score).to_dict()
      )
      emit_lifecycle_event(
        owner,
        job_specs,
        event_type="redmesh.job.pass_completed",
        event_action="pass_completed",
        event_outcome="success",
        pass_nr=job_pass,
      )
      for finding in flat_findings or []:
        emit_finding_event(
          owner,
          job_specs,
          finding=finding,
          event_action="created",
          pass_nr=job_pass,
        )

      set_job_status(job_specs, JOB_STATUS_FINALIZING)
      job_specs = _write_job_record(owner, job_key, job_specs, context="finalize_finalizing")

      if run_mode == RUN_MODE_SINGLEPASS:
        set_job_status(job_specs, JOB_STATUS_FINALIZED)
        owner._emit_timeline_event(job_specs, "scan_completed", "Scan completed")
        if redmesh_test_attestation is not None:
          owner._emit_timeline_event(
            job_specs, "blockchain_submit",
            "Job-finished attestation submitted",
            actor_type="system",
            meta={**redmesh_test_attestation, "network": owner.REDMESH_ATTESTATION_NETWORK}
          )
        owner.P(f"[SINGLEPASS] Job {job_id} complete. Status set to FINALIZED.")
        owner._emit_timeline_event(job_specs, "finalized", "Job finalized")
        owner._build_job_archive(job_key, job_specs)
        owner._clear_live_progress(job_id, list(workers.keys()))
        continue

      if job_status == JOB_STATUS_SCHEDULED_FOR_STOP:
        set_job_status(job_specs, JOB_STATUS_STOPPED)
        owner._emit_timeline_event(job_specs, "scan_completed", f"Scan completed (pass {job_pass})")
        emit_lifecycle_event(
          owner,
          job_specs,
          event_type="redmesh.job.stopped",
          event_action="stopped",
          event_outcome="success",
          pass_nr=job_pass,
        )
        if redmesh_test_attestation is not None:
          owner._emit_timeline_event(
            job_specs, "blockchain_submit",
            f"Test attestation submitted (pass {job_pass})",
            actor_type="system",
            meta={**redmesh_test_attestation, "network": owner.REDMESH_ATTESTATION_NETWORK}
          )
        owner.P(f"[CONTINUOUS] Pass {job_pass} complete for job {job_id}. Status set to STOPPED (soft stop was scheduled)")
        owner._emit_timeline_event(job_specs, "stopped", "Job stopped")
        owner._build_job_archive(job_key, job_specs)
        owner._clear_live_progress(job_id, list(workers.keys()))
        continue

      if job_pass >= MAX_CONTINUOUS_PASSES:
        set_job_status(job_specs, JOB_STATUS_STOPPED)
        owner._emit_timeline_event(job_specs, "scan_completed", f"Scan completed (pass {job_pass})")
        emit_lifecycle_event(
          owner,
          job_specs,
          event_type="redmesh.job.stopped",
          event_action="stopped",
          event_outcome="success",
          pass_nr=job_pass,
        )
        owner._emit_timeline_event(
          job_specs,
          "pass_cap_reached",
          f"Maximum continuous passes reached ({MAX_CONTINUOUS_PASSES})",
          meta={"pass_nr": job_pass, "max_continuous_passes": MAX_CONTINUOUS_PASSES},
        )
        owner._log_audit_event("continuous_pass_cap_reached", {
          "job_id": job_id,
          "pass_nr": job_pass,
          "max_continuous_passes": MAX_CONTINUOUS_PASSES,
        })
        if redmesh_test_attestation is not None:
          owner._emit_timeline_event(
            job_specs, "blockchain_submit",
            f"Test attestation submitted (pass {job_pass})",
            actor_type="system",
            meta={**redmesh_test_attestation, "network": owner.REDMESH_ATTESTATION_NETWORK}
          )
        owner.P(
          f"[CONTINUOUS] Pass {job_pass} complete for job {job_id}. "
          f"Status set to STOPPED (max {MAX_CONTINUOUS_PASSES} passes reached)"
        )
        owner._emit_timeline_event(job_specs, "stopped", "Job stopped")
        owner._build_job_archive(job_key, job_specs)
        owner._clear_live_progress(job_id, list(workers.keys()))
        continue

      if redmesh_test_attestation is not None:
        owner._emit_timeline_event(
          job_specs, "blockchain_submit",
          f"Test attestation submitted (pass {job_pass})",
          actor_type="system",
          meta={**redmesh_test_attestation, "network": owner.REDMESH_ATTESTATION_NETWORK}
        )
      set_job_status(job_specs, JOB_STATUS_RUNNING)
      interval = job_config.get("monitor_interval", owner.cfg_monitor_interval)
      jitter = random.uniform(0, owner.cfg_monitor_jitter)
      job_specs["next_pass_at"] = owner.time() + interval + jitter
      owner._emit_timeline_event(job_specs, "pass_completed", f"Pass {job_pass} completed")

      owner.P(f"[CONTINUOUS] Pass {job_pass} complete for job {job_id}. Next pass in {interval}s (+{jitter:.1f}s jitter)")
      _write_job_record(owner, job_key, job_specs, context="continuous_next_pass")
      owner._clear_live_progress(job_id, list(workers.keys()))

      owner.completed_jobs_reports.pop(job_id, None)
      if job_id in owner.lst_completed_jobs:
        owner.lst_completed_jobs.remove(job_id)

    elif run_mode == RUN_MODE_CONTINUOUS_MONITORING and all_finished and next_pass_at and owner.time() >= next_pass_at:
      job_specs["job_pass"] = job_pass + 1
      job_specs["next_pass_at"] = None
      owner._emit_timeline_event(job_specs, "pass_started", f"Pass {job_pass + 1} started")

      for addr in workers:
        workers[addr]["finished"] = False
        workers[addr]["result"] = None
        workers[addr]["report_cid"] = None

      _write_job_record(owner, job_key, job_specs, context="continuous_restart")
      owner.P(f"[CONTINUOUS] Starting pass {job_pass + 1} for job {job_id}")
