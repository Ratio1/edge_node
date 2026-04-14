from ..models import JobArchive
from ..repositories import ArtifactRepository, JobStateRepository
from .reconciliation import reconcile_job_workers
from .triage import get_job_archive_with_triage


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


def get_job_data(owner, job_id: str):
  """
  Retrieve job data from CStore.

  Finalized/stopped jobs return the lightweight stub as-is. Running jobs keep
  only the most recent pass report references to avoid large response payloads.
  """
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {
      "job_id": job_id,
      "found": False,
      "message": "Job not found in network store.",
    }

  if job_specs.get("job_cid"):
    return {
      "job_id": job_id,
      "found": True,
      "job": job_specs,
    }

  pass_reports = job_specs.get("pass_reports", [])
  if isinstance(pass_reports, list) and len(pass_reports) > 5:
    job_specs["pass_reports"] = pass_reports[-5:]

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
      live_payloads=_job_repo(owner).list_live_progress() or {},
      now=now,
    )

  return {
    "job_id": job_id,
    "found": True,
    "job": job_specs,
  }


def get_job_archive(owner, job_id: str, summary_only: bool = False, pass_offset: int = 0, pass_limit: int = 0):
  """
  Retrieve the full archived job payload from R1FS for finalized jobs.
  """
  result = get_job_archive_with_triage(owner, job_id)
  if "archive" not in result:
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


def get_job_analysis(owner, job_id: str = "", cid: str = "", pass_nr: int = None):
  """
  Retrieve stored LLM analysis for a job or pass report CID.

  Finalized jobs are resolved from the archived job payload so analysis remains
  available after CStore pruning. Running jobs continue to resolve via live
  pass report references in CStore.
  """
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
    return {
      "job_id": job_id,
      "pass_nr": target_pass.get("pass_nr"),
      "completed_at": target_pass.get("date_completed"),
      "report_cid": target_pass.get("report_cid"),
      "target": target_value,
      "num_workers": len(target_pass.get("worker_reports", {}) or {}),
      "total_passes": len(passes),
      "analysis": llm_analysis,
      "quick_summary": target_pass.get("quick_summary"),
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
      "quick_summary": pass_data.get("quick_summary"),
    }
  except Exception as e:
    return {"error": str(e), "cid": report_cid, "job_id": job_id}


def get_job_progress(owner, job_id: str):
  """
  Return real-time progress for all workers in the given job.
  """
  all_progress = _job_repo(owner).list_live_progress() or {}

  job_specs = _job_repo(owner).get_job(job_id)
  status = None
  scan_type = None
  result = {}
  if isinstance(job_specs, dict):
    status = job_specs.get("job_status")
    scan_type = job_specs.get("scan_type")
    result = reconcile_job_workers(owner, job_specs, live_payloads=all_progress)
  else:
    prefix = f"{job_id}:"
    for key, value in all_progress.items():
      if key.startswith(prefix) and value is not None:
        worker_addr = key[len(prefix):]
        result[worker_addr] = value
  return {"job_id": job_id, "status": status, "scan_type": scan_type, "workers": result}


def list_network_jobs(owner):
  """
  Return a normalized network-job listing from CStore.
  """
  raw_network_jobs = _job_repo(owner).list_jobs()
  normalized_jobs = {}
  for job_key, job_spec in raw_network_jobs.items():
    normalized_key, normalized_spec = owner._normalize_job_record(job_key, job_spec)
    if normalized_key and normalized_spec:
      if normalized_spec.get("job_cid"):
        normalized_jobs[normalized_key] = normalized_spec
        continue

      normalized_jobs[normalized_key] = {
        "job_id": normalized_spec.get("job_id"),
        "job_status": normalized_spec.get("job_status"),
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
      }
  return normalized_jobs


def list_local_jobs(owner):
  """
  Return jobs currently running on the local node.
  """
  return {
    job_id: owner._get_job_status(job_id)
    for job_id, local_workers in owner.scan_jobs.items()
  }
