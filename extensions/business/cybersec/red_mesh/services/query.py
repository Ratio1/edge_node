from copy import deepcopy
from collections import deque

from ..models import JobArchive, render_legacy_llm_fields
from ..model_test_sanitization import (
  MODEL_TEST_JOB_TYPE,
  sanitize_model_test_error_class,
  sanitize_model_test_results,
  sanitize_model_test_summary,
  sanitize_raw_evidence_metadata,
)
from ..repositories import ArtifactRepository, JobStateRepository
from ..tenancy.job_artifacts import (
  MAX_ARTIFACT_REFERENCES, TenantJobArtifacts, checked_job_snapshot, validate_snapshot_mode,
)
from ..tenancy.ports import TenantStoreError
from ..tenancy.administration import AdministrationDenied
from .reconciliation import reconcile_job_workers
from .triage import get_job_archive_with_triage

_UNSET = object()


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


def _summarize_archive_passes(passes: list[dict]) -> list[dict]:
  summaries = []
  for pass_data in passes or []:
    if not isinstance(pass_data, dict):
      continue
    findings = pass_data.get("findings") or []
    summaries.append({
      "pass_nr": pass_data.get("pass_nr"),
      "date_started": pass_data.get("date_started"),
      "date_completed": pass_data.get("date_completed"),
      "duration": pass_data.get("duration"),
      "risk_score": pass_data.get("risk_score", 0),
      "quick_summary": pass_data.get("quick_summary"),
      "llm_failed": pass_data.get("llm_failed", False),
      "aggregated_report_cid": pass_data.get("aggregated_report_cid", ""),
      "worker_count": len(pass_data.get("worker_reports") or {}),
      "findings_count": len(findings),
    })
  return summaries


def _paginate_archive_passes(archive: dict, *, summary_only: bool, pass_offset: int, pass_limit: int):
  all_passes = list(archive.get("passes", []) or [])
  total_passes = len(all_passes)
  pass_offset = max(int(pass_offset or 0), 0)
  pass_limit = max(int(pass_limit or 0), 0)
  selected = all_passes[pass_offset:]
  if pass_limit > 0:
    selected = selected[:pass_limit]
  archive = dict(archive)
  archive["passes"] = _summarize_archive_passes(selected) if summary_only else selected
  archive["archive_query"] = {
    "summary_only": bool(summary_only),
    "pass_offset": pass_offset,
    "pass_limit": pass_limit,
    "total_passes": total_passes,
    "returned_passes": len(selected),
    "truncated": pass_offset > 0 or (pass_limit > 0 and pass_offset + len(selected) < total_passes),
  }
  return archive


def _model_test_live_metrics(summary: dict) -> dict:
  if not isinstance(summary, dict):
    return {}
  metrics = {}
  aliases = {
    "cases_total": "total_cases",
    "total_cases": "total_cases",
    "cases_completed": "completed_cases",
    "completed_cases": "completed_cases",
    "evaluated_cases": "evaluated_cases",
    "execution_failed_cases": "execution_failed_cases",
    "evaluation_failed_cases": "evaluation_failed_cases",
  }
  for src, dst in aliases.items():
    value = summary.get(src)
    if isinstance(value, (int, float)):
      metrics[dst] = value
  return metrics


def _is_model_test_specs(job_specs: dict) -> bool:
  return isinstance(job_specs, dict) and (
    job_specs.get("job_type") == MODEL_TEST_JOB_TYPE
    or job_specs.get("scan_type") == MODEL_TEST_JOB_TYPE
  )


def _sanitize_model_test_worker_payload(payload: dict, fallback_summary: dict) -> dict:
  sanitized = dict(payload or {})
  had_raw_error = bool(sanitized.get("error") or sanitized.get("error_message"))
  summary = sanitize_model_test_summary(sanitized.get("model_test_summary") or fallback_summary)
  sanitized["model_test_summary"] = summary
  if "model_test_results" in sanitized:
    sanitized["model_test_results"] = sanitize_model_test_results(sanitized.get("model_test_results"))
  if "model_test_raw_evidence" in sanitized or "model_test_raw_evidence_metadata" in sanitized:
    sanitized["model_test_raw_evidence"] = sanitize_raw_evidence_metadata(
      sanitized.get("model_test_raw_evidence") or sanitized.get("model_test_raw_evidence_metadata")
    )
    sanitized.pop("model_test_raw_evidence_metadata", None)
  error_class = sanitize_model_test_error_class(
    sanitized.get("error_class")
    or summary.get("error_class")
  )
  if error_class:
    sanitized["error_class"] = error_class
  elif had_raw_error:
    sanitized["error_class"] = "unknown_error"
  else:
    sanitized.pop("error_class", None)
  sanitized.pop("error", None)
  sanitized.pop("error_message", None)
  sanitized["scan_type"] = MODEL_TEST_JOB_TYPE
  sanitized["job_type"] = MODEL_TEST_JOB_TYPE
  return sanitized


def _sanitize_model_test_job_specs(job_specs: dict) -> dict:
  if not _is_model_test_specs(job_specs):
    return job_specs
  sanitized = dict(job_specs)
  had_raw_error = bool(sanitized.get("error") or sanitized.get("error_message"))
  summary = sanitize_model_test_summary(sanitized.get("model_test_summary"))
  sanitized["model_test_summary"] = summary
  if "model_test_results" in sanitized:
    sanitized["model_test_results"] = sanitize_model_test_results(sanitized.get("model_test_results"))
  if "model_test_raw_evidence" in sanitized or "model_test_raw_evidence_metadata" in sanitized:
    sanitized["model_test_raw_evidence"] = sanitize_raw_evidence_metadata(
      sanitized.get("model_test_raw_evidence") or sanitized.get("model_test_raw_evidence_metadata")
    )
    sanitized.pop("model_test_raw_evidence_metadata", None)
  error_class = sanitize_model_test_error_class(
    sanitized.get("error_class")
    or summary.get("error_class")
  )
  if error_class:
    sanitized["error_class"] = error_class
  elif had_raw_error:
    sanitized["error_class"] = "unknown_error"
  else:
    sanitized.pop("error_class", None)
  sanitized.pop("error", None)
  sanitized.pop("error_message", None)
  for workers_key in ("workers", "workers_reconciled"):
    workers = sanitized.get(workers_key)
    if isinstance(workers, dict):
      sanitized[workers_key] = {
        worker_addr: _sanitize_model_test_worker_payload(worker_entry, summary)
        if isinstance(worker_entry, dict) and (
          worker_entry.get("worker_type") == MODEL_TEST_JOB_TYPE
          or worker_entry.get("model_test_worker_status")
          or worker_entry.get("scan_type") == MODEL_TEST_JOB_TYPE
          or worker_entry.get("job_type") == MODEL_TEST_JOB_TYPE
        )
        else worker_entry
        for worker_addr, worker_entry in workers.items()
      }
  return sanitized


def _augment_model_test_progress(job_specs: dict, workers: dict) -> dict:
  summary = sanitize_model_test_summary(job_specs.get("model_test_summary") or {})
  for worker_addr, payload in list((workers or {}).items()):
    if not isinstance(payload, dict):
      continue
    enriched = _sanitize_model_test_worker_payload(payload, summary)
    enriched.setdefault("job_id", job_specs.get("job_id"))
    enriched.setdefault("worker_addr", worker_addr)
    enriched.setdefault("job_type", MODEL_TEST_JOB_TYPE)
    enriched.setdefault("scan_type", MODEL_TEST_JOB_TYPE)
    enriched.setdefault("pass_nr", job_specs.get("job_pass", 1))
    enriched.setdefault("progress", 0)
    enriched.setdefault("phase", "model_test_node_selected")
    enriched.setdefault("phase_index", 2)
    enriched.setdefault("total_phases", 5)
    enriched.setdefault("ports_scanned", 0)
    enriched.setdefault("ports_total", 0)
    enriched.setdefault("open_ports_found", [])
    enriched.setdefault("completed_tests", [])
    enriched["model_test_summary"] = sanitize_model_test_summary(
      enriched.get("model_test_summary") or summary
    )
    enriched.setdefault("live_metrics", _model_test_live_metrics(enriched["model_test_summary"]))
    workers[worker_addr] = enriched
  return workers


def _checked_live_progress(owner, job, snapshot_mode):
  """Point-read only assigned workers and validate the exact detached payload identity."""
  try:
    workers = job.get("workers", {})
    if not isinstance(workers, dict) or len(workers) > MAX_ARTIFACT_REFERENCES:
      raise ValueError("Invalid assigned workers")
    participants = set(job["execution_binding"]["participant_order"]) if snapshot_mode == "tenant_bound" else None
    result = {}
    for address, assignment in workers.items():
      if (not isinstance(address, str) or not address.strip() or not isinstance(assignment, dict)
          or participants is not None and address not in participants):
        raise ValueError("Invalid worker assignment")
      key = f"{job['job_id']}:{address}"
      payload = deepcopy(_job_repo(owner).get_live_progress(key))
      if payload is None:
        continue
      if (not isinstance(payload, dict) or payload.get("job_id") != job["job_id"]
          or payload.get("worker_addr") != address):
        raise ValueError("Invalid live progress identity")
      result[key] = payload
    return result
  except Exception:
    raise TenantStoreError("Tenant progress is unavailable") from None


def get_job_data(owner, job_id: str, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Retrieve job data from CStore.

  Finalized/stopped jobs return the lightweight stub as-is. Running jobs keep
  only the most recent pass report references to avoid large response payloads.
  """
  scoped = checked_job is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=scoped)
  job_specs = (checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
               if scoped else owner._get_job_from_cstore(job_id))
  if not job_specs:
    return {
      "job_id": job_id,
      "found": False,
      "message": "Job not found in network store.",
    }

  job_specs = _sanitize_model_test_job_specs(job_specs)

  if job_specs.get("job_cid"):
    return {
      "job_id": job_id,
      "found": True,
      "job": job_specs,
    }

  pass_reports = job_specs.get("pass_reports", [])
  if scoped and not isinstance(pass_reports, list):
    raise TenantStoreError("Tenant job is unavailable")
  if isinstance(pass_reports, list) and len(pass_reports) > 5:
    job_specs["pass_reports"] = pass_reports[-5:]

  live_payloads = _checked_live_progress(owner, job_specs, snapshot_mode) if scoped else None
  if isinstance(job_specs.get("workers"), dict):
    now = None
    time_fn = getattr(owner, "time", None)
    if callable(time_fn):
      try:
        now = float(time_fn())
      except (TypeError, ValueError):
        now = None
    job_specs["workers_reconciled"] = reconcile_job_workers(
      owner,
      job_specs,
      live_payloads=live_payloads if scoped else _job_repo(owner).list_live_progress() or {},
      now=now,
    )

  return {
    "job_id": job_id,
    "found": True,
    "job": job_specs,
  }


def get_job_archive(owner, job_id: str, summary_only: bool = False, pass_offset: int = 0, pass_limit: int = 0,
                    *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Retrieve the full archived job payload from R1FS for finalized jobs.
  """
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked_job is not _UNSET)
  result = (get_job_archive_with_triage(owner, job_id) if checked_job is _UNSET
            else get_job_archive_with_triage(owner, job_id, checked_job=checked_job, snapshot_mode=snapshot_mode))
  if "archive" not in result:
    if checked_job is not _UNSET:
      return {**result, "success": False, "error": "not_found", "status_code": 404}
    return result
  if result["archive"].get("job_type") == "model_test":
    return result
  if summary_only or int(pass_offset or 0) > 0 or int(pass_limit or 0) > 0:
    result = dict(result)
    result["archive"] = _paginate_archive_passes(
      result["archive"],
      summary_only=summary_only,
      pass_offset=pass_offset,
      pass_limit=pass_limit,
    )
  return result


def get_job_analysis(owner, job_id: str = "", cid: str = "", pass_nr: int = None,
                     *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Retrieve stored LLM analysis for a job or pass report CID.

  Finalized jobs are resolved from the archived job payload so analysis remains
  available after CStore pruning. Running jobs continue to resolve via live
  pass report references in CStore.
  """
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked_job is not _UNSET)
  if checked_job is not _UNSET:
    job = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
    context = TenantJobArtifacts(job, _artifact_repo(owner).get_json,
      snapshot_mode=snapshot_mode).analysis_pass(pass_nr=pass_nr, cid=cid)
    report = context["pass"]
    analysis = report.get("llm_analysis")
    summary = report.get("quick_summary")
    if not analysis:
      analysis, derived_summary = render_legacy_llm_fields(report.get("llm_report_sections"))
      summary = summary or derived_summary
    result = {"job_id": job_id, "pass_nr": report["pass_nr"]}
    if snapshot_mode == "tenant_bound":
      result["execution_binding"] = job["execution_binding"]
    if not analysis:
      result.update(success=False, error="not_found", status_code=404, llm_failed=report.get("llm_failed", False),
                    job_status=job.get("job_status"))
      return result
    result.update(completed_at=report.get("date_completed"), report_cid=context["report_cid"],
                  target=job.get("target"), num_workers=len(report.get("worker_reports", {}) or {}),
                  total_passes=context["total_passes"], analysis=analysis, quick_summary=summary)
    return result
  if cid:
    try:
      analysis = owner.r1fs.get_json(cid)
      if analysis is None:
        return {"error": "Analysis not found", "cid": cid}
      return {"cid": cid, "analysis": analysis}
    except Exception as e:
      return {"error": str(e), "cid": cid}

  if not job_id:
    return {"error": "Either job_id or cid must be provided"}

  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {"error": "Job not found", "job_id": job_id}

  job_status = job_specs.get("job_status")

  if job_specs.get("job_cid"):
    archive_result = get_job_archive_with_triage(owner, job_id)
    if "archive" not in archive_result:
      return {
        "error": archive_result.get("error", "archive_unavailable"),
        "message": archive_result.get("message"),
        "job_id": job_id,
        "job_status": job_status,
      }

    archive = archive_result["archive"]
    passes = archive.get("passes", []) or []
    if not passes:
      return {"error": "No pass reports available for this job", "job_id": job_id, "job_status": job_status}

    if pass_nr is not None:
      target_pass = next((entry for entry in passes if entry.get("pass_nr") == pass_nr), None)
      if not target_pass:
        return {
          "error": f"Pass {pass_nr} not found in history",
          "job_id": job_id,
          "available_passes": [entry.get("pass_nr") for entry in passes],
          "job_status": job_status,
        }
    else:
      target_pass = passes[-1]

    llm_analysis = target_pass.get("llm_analysis")
    quick_summary = target_pass.get("quick_summary")
    if not llm_analysis:
      llm_analysis, derived_summary = render_legacy_llm_fields(target_pass.get("llm_report_sections"))
      quick_summary = quick_summary or derived_summary
    if not llm_analysis:
      return {
        "error": "No LLM analysis available for this pass",
        "job_id": job_id,
        "pass_nr": target_pass.get("pass_nr"),
        "llm_failed": target_pass.get("llm_failed", False),
        "job_status": job_status,
      }

    job_config = archive.get("job_config", {}) or {}
    target_value = job_config.get("target") or job_specs.get("target")
    # Archived passes store aggregated_report_cid (written by
    # finalization.py) — not report_cid. The running-branch response
    # below returns a PassReport CID via the pass's report_cid field.
    # Both are opaque to current consumers (Navigator doesn't call
    # /get_analysis; MISP uses aggregated_report_cid directly). Key
    # name "report_cid" kept stable for API continuity.
    aggregated_cid = target_pass.get("aggregated_report_cid")
    if not aggregated_cid:
      # Archive-integrity anomaly: the pass has no aggregated CID,
      # which should only happen if the aggregation step failed or
      # the archive was written by an older, buggy path. Log with a
      # grep-able [ARCHIVE-INTEGRITY] prefix so operators notice.
      owner.P(
        "[ARCHIVE-INTEGRITY] job=%s pass=%s missing aggregated_report_cid"
        % (job_id, target_pass.get("pass_nr")),
        color='y',
      )
    return {
      "job_id": job_id,
      "pass_nr": target_pass.get("pass_nr"),
      "completed_at": target_pass.get("date_completed"),
      "report_cid": aggregated_cid,
      "target": target_value,
      "num_workers": len(target_pass.get("worker_reports", {}) or {}),
      "total_passes": len(passes),
      "analysis": llm_analysis,
      "quick_summary": quick_summary,
    }

  pass_reports = job_specs.get("pass_reports", [])
  if not pass_reports:
    if job_status == "RUNNING":
      return {"error": "Job still running, no passes completed yet", "job_id": job_id, "job_status": job_status}
    return {"error": "No pass reports available for this job", "job_id": job_id, "job_status": job_status}

  if pass_nr is not None:
    target_pass = next((entry for entry in pass_reports if entry.get("pass_nr") == pass_nr), None)
    if not target_pass:
      return {
        "error": f"Pass {pass_nr} not found in history",
        "job_id": job_id,
        "available_passes": [entry.get("pass_nr") for entry in pass_reports],
      }
  else:
    target_pass = pass_reports[-1]

  report_cid = target_pass.get("report_cid")
  if not report_cid:
    return {
      "error": "No pass report CID available for this pass",
      "job_id": job_id,
      "pass_nr": target_pass.get("pass_nr"),
      "job_status": job_status,
    }

  try:
    pass_data = owner.r1fs.get_json(report_cid)
    if pass_data is None:
      return {"error": "Pass report not found in R1FS", "cid": report_cid, "job_id": job_id}

    llm_analysis = pass_data.get("llm_analysis")
    quick_summary = pass_data.get("quick_summary")
    if not llm_analysis:
      llm_analysis, derived_summary = render_legacy_llm_fields(pass_data.get("llm_report_sections"))
      quick_summary = quick_summary or derived_summary
    if not llm_analysis:
      return {
        "error": "No LLM analysis available for this pass",
        "job_id": job_id,
        "pass_nr": target_pass.get("pass_nr"),
        "llm_failed": pass_data.get("llm_failed", False),
        "job_status": job_status,
      }

    return {
      "job_id": job_id,
      "pass_nr": target_pass.get("pass_nr"),
      "completed_at": pass_data.get("date_completed"),
      "report_cid": report_cid,
      "target": job_specs.get("target"),
      "num_workers": len(job_specs.get("workers", {})),
      "total_passes": len(pass_reports),
      "analysis": llm_analysis,
      "quick_summary": quick_summary,
    }
  except Exception as e:
    return {"error": str(e), "cid": report_cid, "job_id": job_id}


def get_job_progress(owner, job_id: str, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Return real-time progress for all workers in the given job.
  """
  scoped = checked_job is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=scoped)
  if scoped:
    job_specs = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
    all_progress = _checked_live_progress(owner, job_specs, snapshot_mode)
  else:
    all_progress = _job_repo(owner).list_live_progress() or {}
    job_specs = _job_repo(owner).get_job(job_id)
  status = None
  scan_type = None
  result = {}
  if isinstance(job_specs, dict):
    is_model_test = _is_model_test_specs(job_specs)
    status = job_specs.get("job_status")
    scan_type = job_specs.get("scan_type")
    result = reconcile_job_workers(owner, job_specs, live_payloads=all_progress)
    if is_model_test:
      job_specs = _sanitize_model_test_job_specs(job_specs)
      result = _augment_model_test_progress(job_specs, result)
  else:
    prefix = f"{job_id}:"
    for key, value in all_progress.items():
      if key.startswith(prefix) and value is not None:
        worker_addr = key[len(prefix):]
        result[worker_addr] = value
  response = {"job_id": job_id, "status": status, "scan_type": scan_type, "workers": result}
  if scoped and snapshot_mode == "tenant_bound":
    response["execution_binding"] = job_specs["execution_binding"]
  if isinstance(job_specs, dict) and _is_model_test_specs(job_specs):
    response.update({
      "job_type": MODEL_TEST_JOB_TYPE,
      "task_kind": MODEL_TEST_JOB_TYPE,
      "model_test_summary": sanitize_model_test_summary(job_specs.get("model_test_summary")),
      "model_test_node_selection": job_specs.get("model_test_node_selection"),
    })
    if "model_test_raw_evidence" in job_specs:
      response["model_test_raw_evidence"] = sanitize_raw_evidence_metadata(
        job_specs.get("model_test_raw_evidence")
      )
  return response


def _checked_jobs_snapshot(checked_jobs, snapshot_mode):
  try:
    if not isinstance(checked_jobs, dict):
      raise ValueError("Invalid checked job enumeration")
    items = tuple(checked_jobs.items())
    result = {}
    for key, value in items:
      if not isinstance(key, str) or not key.strip():
        raise ValueError("Invalid job key")
      job = checked_job_snapshot(value, key if snapshot_mode == "tenant_bound" else None,
                                 snapshot_mode=snapshot_mode)
      for field, kind in (("workers", dict), ("pass_reports", list)):
        if field in job and not isinstance(job[field], kind):
          raise ValueError("Invalid job projection")
      result[key] = job
    return result
  except Exception:
    raise TenantStoreError("Tenant jobs are unavailable") from None


def list_network_jobs(owner, *, checked_jobs=_UNSET, snapshot_mode="tenant_bound"):
  """
  Return a normalized network-job listing from CStore.
  """
  scoped = checked_jobs is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=scoped)
  if scoped:
    raw_network_jobs = _checked_jobs_snapshot(checked_jobs, snapshot_mode)
  else:
    raw_network_jobs = _job_repo(owner).list_jobs()
  normalized_jobs = {}
  for job_key, job_spec in raw_network_jobs.items():
    if scoped and snapshot_mode == "legacy_unbound":
      # The trusted reader already normalized the captured row without migrating its alias key.
      normalized_key, normalized_spec = job_key, job_spec
    else:
      normalized_key, normalized_spec = owner._normalize_job_record(job_key, job_spec)
    if scoped and snapshot_mode == "tenant_bound":
      if normalized_key != job_key:
        raise TenantStoreError("Tenant jobs are unavailable")
      normalized_spec = checked_job_snapshot(normalized_spec, job_key)
    if normalized_key and normalized_spec:
      if normalized_spec.get("job_cid"):
        normalized_jobs[normalized_key] = _sanitize_model_test_job_specs(normalized_spec)
        continue

      normalized_jobs[normalized_key] = {
        "job_id": normalized_spec.get("job_id"),
        "job_status": normalized_spec.get("job_status"),
        "job_type": normalized_spec.get("job_type"),
        "target": normalized_spec.get("target"),
        "scan_type": normalized_spec.get("scan_type", "network"),
        "target_url": normalized_spec.get("target_url", ""),
        "task_name": normalized_spec.get("task_name"),
        "risk_score": normalized_spec.get("risk_score", 0),
        "run_mode": normalized_spec.get("run_mode"),
        "start_port": normalized_spec.get("start_port"),
        "end_port": normalized_spec.get("end_port"),
        "date_created": normalized_spec.get("date_created"),
        "launcher": normalized_spec.get("launcher"),
        "launcher_alias": normalized_spec.get("launcher_alias"),
        "worker_count": len(normalized_spec.get("workers", {}) or {}),
        "pass_count": len(normalized_spec.get("pass_reports", []) or []),
        "job_pass": normalized_spec.get("job_pass", 1),
        "model_test_summary": sanitize_model_test_summary(normalized_spec.get("model_test_summary"))
        if _is_model_test_specs(normalized_spec)
        else normalized_spec.get("model_test_summary"),
        "model_test_node_selection": normalized_spec.get("model_test_node_selection"),
      }
      if scoped and snapshot_mode == "tenant_bound":
        normalized_jobs[normalized_key]["execution_binding"] = normalized_spec["execution_binding"]
  return normalized_jobs


def get_job_status(owner, job_id: str, *, checked_job, snapshot_mode="tenant_bound"):
  """Scoped status uses only the checked stored job, never local completion recovery."""
  data = get_job_data(owner, job_id, checked_job=checked_job, snapshot_mode=snapshot_mode)
  job = data["job"]
  result = {"job_id": job_id, "target": job.get("target"), "status": "network_tracked", "job": job,
            "workers": job.get("workers_reconciled")}
  if snapshot_mode == "tenant_bound":
    result["execution_binding"] = job["execution_binding"]
  return result


def get_job_report(owner, job_id: str, cid: str, *, checked_job, snapshot_mode="tenant_bound"):
  """Read one ordinary associated report without pinning it or its typed ancestors."""
  job = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
  if not isinstance(cid, str) or not cid.strip():
    raise AdministrationDenied(400, "invalid_request")
  artifacts = TenantJobArtifacts(job, lambda reference: owner.r1fs.get_json(reference, pin=False),
                                 snapshot_mode=snapshot_mode)
  result = {"job_id": job_id, "cid": cid, "report": artifacts.report(cid)}
  if snapshot_mode == "tenant_bound":
    result["execution_binding"] = job["execution_binding"]
  return result


def get_job_audit(owner, limit: int = 100, *, checked_jobs, snapshot_mode="tenant_bound"):
  """The caller supplies audit-authorized jobs; filter copied events before totals and limits."""
  validate_snapshot_mode(snapshot_mode)
  jobs = _checked_jobs_snapshot(checked_jobs, snapshot_mode)
  permitted = {job["job_id"] for job in jobs.values()}
  if type(limit) is not int:
    raise AdministrationDenied(400, "invalid_request")
  try:
    if not isinstance(owner._audit_log, (list, tuple, deque)):
      raise ValueError("Invalid audit collection")
    entries = tuple(owner._audit_log)
    result = []
    for entry in entries:
      copied = deepcopy(entry)
      if (isinstance(copied, dict) and isinstance(copied.get("job_id"), str)
          and copied["job_id"] in permitted):
        result.append(copied)
    return {"audit_log": result[-limit:] if limit > 0 else result, "total": len(result)}
  except Exception:
    raise TenantStoreError("Tenant audit is unavailable") from None


def list_local_jobs(owner, *, checked_jobs=_UNSET, snapshot_mode="tenant_bound"):
  """
  Return jobs currently running on the local node.
  """
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked_jobs is not _UNSET)
  if checked_jobs is not _UNSET:
    jobs = _checked_jobs_snapshot(checked_jobs, snapshot_mode)
    local_ids = set(getattr(owner, "scan_jobs", {})) | set(getattr(owner, "model_test_jobs", {}))
    return {key: get_job_status(owner, job["job_id"], checked_job=job, snapshot_mode=snapshot_mode)
            for key, job in jobs.items() if job["job_id"] in local_ids}
  local_jobs = {
    job_id: owner._get_job_status(job_id)
    for job_id in getattr(owner, "scan_jobs", {})
  }
  for job_id, worker in getattr(owner, "model_test_jobs", {}).items():
    job_specs = _job_repo(owner).get_job(job_id)
    if isinstance(job_specs, dict) and not _is_model_test_specs(job_specs):
      continue
    job_specs = job_specs if isinstance(job_specs, dict) else {}
    worker_state = getattr(worker, "state", None)
    live_summary = worker_state.get("model_test_summary") if isinstance(worker_state, dict) else None
    job_status = job_specs.get("job_status") or "RUNNING"
    local_jobs[job_id] = {
      "job_id": job_id,
      "status": job_status,
      "job_status": job_status,
      "job_type": MODEL_TEST_JOB_TYPE,
      "task_kind": MODEL_TEST_JOB_TYPE,
      "scan_type": MODEL_TEST_JOB_TYPE,
      "model_test_summary": sanitize_model_test_summary(
        live_summary or job_specs.get("model_test_summary")
      ),
      "model_test_node_selection": job_specs.get("model_test_node_selection"),
    }
  return local_jobs
