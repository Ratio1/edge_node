import random
import re
from copy import deepcopy
from functools import partial

from ..constants import (
  JOB_STATUS_ANALYZING,
  JOB_STATUS_COLLECTING,
  JOB_STATUS_FINALIZED,
  JOB_STATUS_FINALIZING,
  JOB_STATUS_FAILED,
  JOB_STATUS_RUNNING,
  JOB_STATUS_SCHEDULED_FOR_STOP,
  JOB_STATUS_STOPPED,
  MAX_CONTINUOUS_PASSES,
  RUN_MODE_CONTINUOUS_MONITORING,
  RUN_MODE_SINGLEPASS,
)
from ..credential_redaction import redact_credential_text
from ..mixins.report import get_host_aggregated_report
from ..models import (
  AggregatedScanData,
  PassReport,
  PassReportRef,
  WorkerReportMeta,
  render_legacy_llm_fields,
)
from ..repositories import ArtifactRepository, JobStateRepository
from ..tenancy.execution import binding_from_record
from ..tenancy.identity import IdentityStoreError
from ..tenancy.ports import TenantStoreError
from .config import get_attestation_config
from .control import stop_monitoring
from .engagement_ledger import port_ranges
from .engagement_ledger_store import EngagementLedgerRecorder
from .config import get_llm_agent_config
from .event_hooks import (
  emit_attestation_status_event as _emit_attestation_status_event,
  emit_finding_event as _emit_finding_event,
  emit_lifecycle_event as _emit_lifecycle_event,
)
from .misp_auto_push import enqueue_misp_auto_push, poll_misp_auto_push
from .rulebook_assessment import ensure_rulebook_assessment
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


def _owner_method(owner, name):
  method = getattr(type(owner), name, None)
  if callable(method):
    return method.__get__(owner, type(owner))
  method = owner.__dict__.get(name)
  return method if callable(method) else None


def _execution_denial_reason(owner, job_specs, *, operation="current", config=None):
  """Why launcher-side execution is refused, as a short code, or None when it is allowed (RM-221).

  Local report finalization is separate; this checks current bound ownership for effects.
  """
  reason_for = _owner_method(owner, "_execution_denial_reason")
  checker = _owner_method(owner, "_execution_operation_allowed")
  if reason_for is None and checker is None:
    return "forbidden"
  try:
    # RM-108 phase 5: admission never yields a job with no execution_binding, so this reauthorizes
    # against the current stored record unconditionally rather than only for a bound snapshot.
    current = _job_repo(owner).get_job(job_specs["job_id"])
    if not isinstance(current, dict) or _execution_identity(current) != _execution_identity(job_specs):
      return "identity_mismatch"
    if current.get("launcher") != owner.ee_addr:
      return "not_launcher"
    if is_terminal_job_status(current.get("job_status")):
      return "job_terminal"
    if reason_for is None:  # an owner that only answers yes or no
      return None if checker(current, operation=operation, config=config) is True else "forbidden"
    # One reauthorization call: the boolean is derived from the reason, never asked twice.
    reason = reason_for(current, operation=operation, config=config)
    return reason if reason is None or (isinstance(reason, str) and reason) else "forbidden"
  except (IdentityStoreError, TenantStoreError):
    return "store_unavailable"
  except Exception as exc:
    owner.P(f"[EXECUTION] denial check raised {type(exc).__name__}", color='y')
    return "internal_error"


def _execution_operation_allowed(owner, job_specs, *, operation="current", config=None):
  return _execution_denial_reason(owner, job_specs, operation=operation, config=config) is None


def _record_execution_denied(owner, job_specs, *, operation, reason, pass_nr):
  """One `execution_denied` timeline entry and log line per pass and operation (launcher gates only)."""
  for event in job_specs.get("timeline") or []:
    meta = event.get("meta") if isinstance(event, dict) else None
    if (isinstance(meta, dict) and event.get("type") == "execution_denied"
        and meta.get("operation") == operation and meta.get("pass_nr") == pass_nr):
      return
  owner.P(f"[EXECUTION] {job_specs.get('job_id')} pass {pass_nr}: {operation} refused ({reason})", color='y')
  owner._emit_timeline_event(
    job_specs, "execution_denied", f"Execution refused for {operation}: {reason}",
    actor_type="system", meta={"operation": operation, "reason": reason, "pass_nr": pass_nr},
  )


_ANALYSIS_DENIED_MESSAGE = "Automatic analysis execution unavailable"


class _AnalysisDenied(RuntimeError):
  pass


def _llm_failure_reason(owner):
  """Why the last structured narrative failed, from the issues the provider path recorded."""
  validation = getattr(owner, "_last_structured_llm_validation", None)
  errors = validation.get("errors") if isinstance(validation, dict) else None
  if not errors:
    return "provider_error"  # the call itself raised before any validation ran
  for error in errors:
    if error.get("code") == "llm_call_failed":
      # The authority check runs inside the provider call (before_provider_call); its raise lands here.
      return ("execution_authority_denied"
              if _ANALYSIS_DENIED_MESSAGE in str(error.get("message")) else "provider_error")
  if any(error.get("code") == "empty_response" for error in errors):
    return "provider_error"
  return "validation_failed"


def _check_execution(owner, job_specs, *, operation, pass_nr, config=None):
  """The denial reason, or None when allowed; a denial is recorded on the job timeline."""
  reason = _execution_denial_reason(owner, job_specs, config=config)
  if reason is not None:
    _record_execution_denied(owner, job_specs, operation=operation, reason=reason, pass_nr=pass_nr)
  return reason


def attestation_unsubmitted_reason(owner):
  """Why a submit that returned nothing (not raised) submitted nothing: its own early returns."""
  try:
    if not get_attestation_config(owner)["ENABLED"]:
      return "attestation_disabled"
    if owner._attestation_get_tenant_private_key() is None:
      return "no_tenant_key"
  except Exception:
    pass
  return "submit_failed"


def _execution_identity(job_specs):
  for field, default, minimum in (("job_pass", 1, 1), ("job_revision", 0, 0)):
    value = job_specs.get(field, default)
    if type(value) is not int or value < minimum:
      raise ValueError("Invalid execution revision")
  return (
    job_specs.get("job_id"), job_specs.get("launcher"), job_specs.get("job_pass", 1),
    job_specs.get("job_revision", 0), binding_from_record(job_specs),
  )


def _check_automatic_analysis_authority(owner, job_specs):
  if not _execution_operation_allowed(owner, job_specs):
    raise RuntimeError(_ANALYSIS_DENIED_MESSAGE)


def emit_attestation_status_event(owner, job_specs, **kwargs):
  if _execution_operation_allowed(owner, job_specs):
    return _emit_attestation_status_event(owner, job_specs, **kwargs)


def emit_finding_event(owner, job_specs, **kwargs):
  if _execution_operation_allowed(owner, job_specs):
    return _emit_finding_event(owner, job_specs, **kwargs)


def emit_lifecycle_event(owner, job_specs, **kwargs):
  if _execution_operation_allowed(owner, job_specs):
    return _emit_lifecycle_event(owner, job_specs, **kwargs)


# RM-095: how often a running continuous pass re-reads its engagement. Before a new pass the
# engagement is always read.
ENGAGEMENT_RECHECK_SECONDS = 60


def _stop_if_engagement_ended(owner, job_specs, *, due):
  """Hard-stop a continuous job whose engagement has ended; True when it was stopped.

  RM-095 (owner, 2026-09-28): the engagement ends at `valid_until` or on a revoke, and the job
  stops then, mid-pass included, the way an operator's HARD stop does. Passes finalized before
  the stop keep their reports. RM-108 phase 5: admission never yields a job with no engagement, so
  this check always applies to an admitted job; `_engagement_end_reason` still returns None rather
  than raising if a record is somehow missing one.
  """
  check = getattr(owner, "_engagement_end_reason", None)
  if not callable(check):
    return False
  job_id = job_specs.get("job_id")
  # Per job: when it was last checked, so a running pass is polled at most once a minute.
  checks = getattr(owner, "_engagement_checks", None)
  if not isinstance(checks, dict):
    checks = {}
    owner._engagement_checks = checks
  entry = checks.setdefault(job_id, {"at": float("-inf")})
  now = owner.time()
  if not due and now - entry["at"] < ENGAGEMENT_RECHECK_SECONDS:
    return False
  entry["at"] = now
  # Fail-safe: one job whose config or engagement cannot be read must not break the loop for the
  # others, and never reads as an ended engagement.
  try:
    # RM-107: a schema-2 binding names its engagement, so the check needs no config read (an R1FS
    # outage then never lets a pass start after the engagement ended).
    binding = job_specs.get("execution_binding")
    engagement_id = binding.get("engagement_id") if isinstance(binding, dict) else None
    if not engagement_id:
      return False
    reason = check(job_specs)
  except Exception as exc:
    owner.P(f"[CONTINUOUS] Engagement check for job {job_id} unavailable: {exc}", color='y')
    return False
  if reason is None:
    return False
  owner._emit_timeline_event(
    job_specs, "engagement_ended", f"Engagement ended ({reason}): job stopped",
    actor_type="system", meta={"engagement_id": engagement_id, "reason": reason},
  )
  result = stop_monitoring(owner, job_id, "HARD", checked_job=job_specs)
  if not isinstance(result, dict) or result.get("error"):
    return False
  checks.pop(job_id, None)
  (getattr(owner, "_pass_holds", None) or {}).pop(job_id, None)
  owner._log_audit_event("continuous_stopped_engagement_ended", {
    "job_id": job_id, "engagement_id": engagement_id, "reason": reason, "pass_nr": job_specs.get("job_pass", 1),
  })
  owner.P(f"[CONTINUOUS] Job {job_id} stopped: its engagement ended ({reason})", color='y')
  return True


def _all_workers_finished_with_reports(workers):
  if not isinstance(workers, dict) or not workers:
    return False
  for worker in workers.values():
    if not isinstance(worker, dict):
      return False
    if not worker.get("finished") or not worker.get("report_cid"):
      return False
  return True


def _current_pass_ref(job_specs):
  """The stored `PassReportRef` dict of the current pass, or None."""
  job_pass = job_specs.get("job_pass", 1)
  return next((ref for ref in job_specs.get("pass_reports") or []
               if isinstance(ref, dict) and ref.get("pass_nr") == job_pass), None)


def _is_stale_intermediate_recovery_candidate(job_specs, workers, job_status, next_pass_at):
  if not is_intermediate_job_status(job_status):
    return False
  if job_specs.get("job_cid"):
    return False
  # A current pass that already has its report is not re-run (it would store a second report);
  # an earlier pass's report does not block the current pass (I-268).
  if _current_pass_ref(job_specs) is not None:
    return False
  if next_pass_at is not None:
    return False
  return _all_workers_finished_with_reports(workers)


def _record_stale_intermediate_recovery(owner, job_specs, previous_status, worker_count):
  job_id = job_specs.get("job_id")
  pass_nr = job_specs.get("job_pass", 1)
  launcher = job_specs.get("launcher")
  owner.P(
    "[STUCK RECOVERY] launcher retrying stale intermediate job "
    f"job_id={job_id} launcher={launcher} previous_status={previous_status} "
    f"pass={pass_nr} workers={worker_count}",
    color='y',
  )
  log_audit_event = getattr(owner, "_log_audit_event", None)
  if callable(log_audit_event):
    log_audit_event("stale_intermediate_finalization_recovery", {
      "job_id": job_id,
      "launcher": launcher,
      "previous_status": previous_status,
      "pass_nr": pass_nr,
      "worker_count": worker_count,
    })


def _stop_scheduled(job_specs, job_status):
  """A soft stop is due: the status says so, or its timeline entry is pending. The entry survives the
  COLLECTING and FINALIZING writes that replace the status, and a job is stopped once it acts on it."""
  return job_status == JOB_STATUS_SCHEDULED_FOR_STOP or any(
    isinstance(event, dict) and event.get("type") == "scheduled_for_stop"
    for event in job_specs.get("timeline") or [])


def _resume_finalizing_tail(owner, job_key, job_specs, workers, ref):
  """I-268: finish a pass whose launcher exited after the FINALIZING write (pass report stored, no
  archive). The steps after that write run from the stored artifacts: the pass is not scored, stored,
  attested or announced again. Retried at most once a minute; audited once per job."""
  job_id = job_specs.get("job_id")
  job_pass = job_specs.get("job_pass", 1)
  retries = getattr(owner, "_finalizing_recovery", None)
  if not isinstance(retries, dict):
    retries = owner._finalizing_recovery = {}
  last = retries.get(job_id)
  if last is not None and owner.time() - last < ENGAGEMENT_RECHECK_SECONDS:
    return
  retries[job_id] = owner.time()
  if last is None:
    owner.P(f"[STUCK RECOVERY] {job_id} is FINALIZING with pass {job_pass} stored — resuming finalization",
            color='y')
    log_audit_event = getattr(owner, "_log_audit_event", None)
    if callable(log_audit_event):
      log_audit_event("stale_finalizing_recovery", {
        "job_id": job_id, "launcher": job_specs.get("launcher"),
        "run_mode": job_specs.get("run_mode", RUN_MODE_SINGLEPASS), "pass_nr": job_pass})
  artifacts = _artifact_repo(owner)
  stored = artifacts.get_pass_report(ref.get("report_cid"))
  aggregated_cid = stored.get("aggregated_report_cid") if isinstance(stored, dict) else None
  aggregated = artifacts.get_json(aggregated_cid) if aggregated_cid else None
  node_reports = owner._collect_node_reports(workers) if isinstance(aggregated, dict) else None
  if not isinstance(aggregated, dict) or not isinstance(node_reports, dict) or set(node_reports) != set(workers):
    # Not finished on a guess: an unreadable report (one worker's is enough) could hide an aborted
    # pass or a ledger range. Retried next minute.
    owner.P(f"[STUCK RECOVERY] {job_id} pass {job_pass} artifacts unreadable — retrying later", color='y')
    return
  job_config = owner._get_job_config(job_specs, resolve_secrets=False) or {}
  abort_state = _pass_abort_state(aggregated, node_reports)
  date_completed = stored.get("date_completed") or owner.time()
  job_specs = _ensure_rulebook_assessment_after_pass(owner, job_specs, job_id=job_id, pass_nr=job_pass)
  if not ref.get("pass_changes_cid"):
    job_specs = _record_engagement_ledger_after_pass(
      owner, job_key, job_specs, artifacts, job_id=job_id, pass_nr=job_pass,
      pass_report_cid=ref.get("report_cid"), node_reports=node_reports, workers=workers,
      date_completed=date_completed, flat_findings=stored.get("findings") or [], aggregated=aggregated,
      pass_metrics=stored.get("scan_metrics"), abort_state=abort_state, job_config=job_config,
    )
  _finish_pass(
    owner, job_key, job_specs, workers=workers, job_config=job_config, abort_state=abort_state,
    redmesh_test_attestation=stored.get("redmesh_test_attestation"),
    pass_date_started=stored.get("date_started"), pass_date_completed=date_completed,
    pass_window_egress_ips=[meta.get("node_ip") for meta in (stored.get("worker_reports") or {}).values()
                            if isinstance(meta, dict) and meta.get("node_ip")],
    pass_window_report_refs={"pass_report_cid": ref.get("report_cid"), "aggregated_report_cid": aggregated_cid},
    stop_scheduled=_stop_scheduled(job_specs, job_specs.get("job_status")),
  )
  if is_terminal_job_status(job_specs.get("job_status")):
    current = _job_repo(owner).get_job(job_key)
    if (isinstance(current, dict) and current.get("job_status") == JOB_STATUS_FINALIZING
        and not current.get("job_cid")):
      # The archive did not land. Keep the end state, so the terminal archive retry takes over and the
      # stop and cap events of this tail are not sent again on the next attempt.
      _write_job_record(owner, job_key, job_specs, context="finalizing_recovery_terminal")


def _automatic_analysis_report_identity(workers):
  return tuple(sorted(
    (str(address), str(worker.get("report_cid") or ""))
    for address, worker in (workers or {}).items()
    if isinstance(worker, dict)
  ))


def _automatic_analysis_state_matches(job_specs, state):
  if not isinstance(job_specs, dict) or not isinstance(state, dict):
    return False
  if state.get("execution_identity") is not None:
    try:
      if _execution_identity(job_specs) != state["execution_identity"]:
        return False
    except (ValueError, TypeError):
      return False
  return (
    job_specs.get("job_id") == state.get("job_id")
    and job_specs.get("job_pass", 1) == state.get("pass_nr")
    and _automatic_analysis_report_identity(job_specs.get("workers"))
      == state.get("report_identity")
  )


def _poll_automatic_analysis(owner, all_jobs):
  """Yield while automatic model work runs, then return its single result."""
  state = owner.__dict__.get("_automatic_analysis_state")
  if not isinstance(state, dict):
    return None, False

  current_job = None
  for job_key, job_specs in all_jobs.items():
    normalized_key, normalized = owner._normalize_job_record(job_key, job_specs)
    if normalized_key is None:
      continue
    if isinstance(normalized, dict) and normalized.get("job_id") == state.get("job_id"):
      current_job = normalized
      break

  future = state.get("future")
  invalidated = (
    not _automatic_analysis_state_matches(current_job, state)
    or is_terminal_job_status((current_job or {}).get("job_status"))
    or (state.get("execution_identity") is not None
        and not _execution_operation_allowed(owner, current_job))
  )
  if invalidated:
    state["discard_result"] = True
    if future is not None:
      future.cancel()

  if future is None:
    owner._automatic_analysis_state = None
    return None, False
  if not future.done():
    return None, True
  if state.get("discard_result"):
    try:
      future.result()
    except Exception:
      pass
    owner._automatic_analysis_state = None
    return None, False

  try:
    sections = future.result()
  except Exception as exc:
    owner.P(
      f"Structured LLM call raised for job {state.get('job_id')}: {exc}",
      color='y',
    )
    sections = None
    failed, reason = True, "provider_error"
  else:
    failed = bool(getattr(owner, "_last_structured_llm_failed", None))
    reason = _llm_failure_reason(owner) if failed else None
  owner._automatic_analysis_state = None
  return {
    "state": state,
    "sections": sections,
    "failed": failed,
    "reason": reason,
  }, False


def _attestation_required(job_specs, job_config) -> bool:
  if isinstance(job_specs, dict) and "blockchain_attestation_enabled" in job_specs:
    return bool(job_specs.get("blockchain_attestation_enabled"))
  if isinstance(job_config, dict):
    return bool(job_config.get("blockchain_attestation_enabled", False))
  return False


def _enqueue_misp_auto_push(owner, job_specs, pass_nr):
  # RM-221 (owner): no automatic push while the end attestation is failed; a manual push stays possible.
  if job_specs.get("attestation_status") != "failed":
    enqueue_misp_auto_push(owner, job_specs, pass_nr)


def _mark_job_failed(owner, job_key, job_specs, *, job_id, pass_nr, failure_class, message, meta=None):
  job_specs["failure_class"] = failure_class
  job_specs["failure_message"] = message
  set_job_status(job_specs, JOB_STATUS_FAILED)
  owner._emit_timeline_event(
    job_specs,
    failure_class,
    message,
    actor_type="system",
    meta={"pass_nr": pass_nr, "failure_class": failure_class, **(meta or {})},
  )
  emit_lifecycle_event(
    owner,
    job_specs,
    event_type="redmesh.job.failed",
    event_action="failed",
    event_outcome="failure",
    pass_nr=pass_nr,
  )
  _write_job_record(owner, job_key, job_specs, context=failure_class)
  owner._build_job_archive(job_key, job_specs)
  owner._clear_live_progress(job_id, list((job_specs.get("workers") or {}).keys()))


def _pass_abort_state(aggregated, node_reports):
  """
  The graybox abort state of a pass, or None when no worker aborted.

  `empty` is True when the abort left nothing tested: no worker attempted a
  probe. The graybox worker records `aborted` on its report when a safety
  gate (preflight, authorization, authentication, session refresh) raises
  GrayboxAbort; before this the launcher never read it, so a scan that
  failed to log in finalized as a completed job with a risk score computed
  from its own "Scan aborted" finding. The rule keys on the abort plus the
  probe count, not on the reason class, so a future degraded mode that runs
  anonymous scenarios after a failed login (RM-060) still counts as a scan.
  """
  if not isinstance(aggregated, dict) or not aggregated.get("aborted"):
    return None
  probes_attempted = 0
  for report in (node_reports or {}).values():
    metrics = report.get("scan_metrics") if isinstance(report, dict) else None
    if isinstance(metrics, dict):
      probes_attempted += int(metrics.get("probes_attempted") or 0)
  return {
    "aborted": True,
    "abort_reason": str(aggregated.get("abort_reason") or ""),
    "abort_phase": str(aggregated.get("abort_phase") or ""),
    "abort_reason_class": str(aggregated.get("abort_reason_class") or "unknown"),
    "empty": probes_attempted == 0,
  }


_ABORT_REASON_MAX_CHARS = 240
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _abort_reason_text(reason):
  """
  The abort reason as it may be printed on the job record, the timeline, the
  archive, the PDF and the console.

  The worker composes it from strings it controls, but two callers embed an
  exception text or the operator's target URL, and in the mesh it arrives
  from another node's report. Same treatment as the LLM boundary gives the
  same field (`_sanitize_untrusted_text`): credential redaction, control
  bytes stripped, a hard cap.
  """
  text = redact_credential_text(str(reason or ""))
  text = " ".join(_CONTROL_CHARS_RE.sub(" ", text).split())
  return text[:_ABORT_REASON_MAX_CHARS] or "no reason recorded"


def _ensure_rulebook_assessment_after_pass(owner, job_specs, *, job_id, pass_nr):
  try:
    result = ensure_rulebook_assessment(owner, job_id, pass_nr=pass_nr)
  except Exception as exc:
    owner.P(f"[NIS2] Rulebook assessment ensure failed for job {job_id} pass {pass_nr}: {exc}", color='y')
    return job_specs

  if not isinstance(result, dict) or result.get("status") != "ok":
    error = result.get("error") if isinstance(result, dict) else "unknown_error"
    owner.P(f"[NIS2] Rulebook assessment not generated for job {job_id} pass {pass_nr}: {error}", color='y')
    return job_specs

  owner.P(
    f"[NIS2] Rulebook assessment ready for job {job_id} pass {pass_nr}: "
    f"{result.get('artifact_cid') or 'cached'}"
  )
  refreshed = owner._get_job_from_cstore(job_id)
  return refreshed if isinstance(refreshed, dict) else job_specs


def _record_skipped_ledger_pass(owner, job_specs, *, job_id, pass_nr, date_completed):
  """RM-121: a pass left without a stored pass report still gets a `skipped` ledger entry, so the
  job's later passes are folded. Non-fatal."""
  try:
    recorder = EngagementLedgerRecorder.for_job(owner, job_specs)
    if recorder is not None:
      recorder.record_skipped(job_id=job_id, pass_nr=pass_nr, date_completed=date_completed)
  except Exception as exc:
    owner.P(f"[LEDGER] Skipped entry for job {job_id} pass {pass_nr} not written ({type(exc).__name__})",
            color='y')


def _completed_port_ranges(node_reports, workers):
  """The port runs of the workers whose report the pass collected: the worker's own port list when it
  has one (comparison mode slices are not contiguous), else its `[start_port, end_port]`."""
  ranges = []
  for address, report in (node_reports or {}).items():
    if not isinstance(report, dict):
      continue
    entry = (workers or {}).get(address) or {}
    ports = report.get("target_ports") or entry.get("target_ports")
    if ports:
      ranges.extend(port_ranges(ports))
    else:
      ranges.append([int(report.get("start_port") or 0), int(report.get("end_port") or 0)])
  return ranges


def _record_engagement_ledger_after_pass(owner, job_key, job_specs, artifacts, *, job_id, pass_nr,
                                         pass_report_cid, node_reports, workers, **facts):
  """RM-121: the engagement finding ledger's post-pass hook (launcher only, every pass, non-fatal).

  Stores the pass-changes artifact, puts its CID on the pass's `PassReportRef`, then writes the
  asset's pass entry and folds (`continuous-monitoring.md` §2.1). A failure is logged and leaves a
  `skipped` entry when the pass has none yet; the pass and the job go on.
  """
  recorder = None
  try:
    recorder = EngagementLedgerRecorder.for_job(owner, job_specs)
    if recorder is None:
      return job_specs
    completed_ranges = _completed_port_ranges(node_reports, workers)
    changes_cid = recorder.store_pass_changes(
      artifacts, job_id=job_id, pass_nr=pass_nr, pass_report_cid=pass_report_cid,
      completed_ranges=completed_ranges, **facts)
    refs = job_specs.get("pass_reports") or []
    for index, ref in enumerate(refs):
      if ref.get("pass_nr") == pass_nr and ref.get("report_cid") == pass_report_cid:
        refs[index] = PassReportRef.from_dict({**ref, "pass_changes_cid": changes_cid}).to_dict()
    written = _write_job_record(owner, job_key, job_specs, context="finalize_engagement_ledger")
    if written is not None:  # None: the write was not confirmed; the job record keeps the pass as it was
      job_specs = written
    recorder.record_pass(
      artifacts, job_id=job_id, pass_nr=pass_nr, date_completed=facts["date_completed"],
      pass_report_cid=pass_report_cid, pass_changes_cid=changes_cid)
  except Exception as exc:
    owner.P(f"[LEDGER] Engagement ledger not updated for job {job_id} pass {pass_nr} ({type(exc).__name__})",
            color='y')
    try:
      if recorder is not None:
        recorder.record_skipped(job_id=job_id, pass_nr=pass_nr, date_completed=facts.get("date_completed"))
    except Exception as skipped_exc:
      owner.P(f"[LEDGER] Skipped entry for job {job_id} pass {pass_nr} not written ({type(skipped_exc).__name__})",
              color='y')
  return job_specs


def _finish_pass(owner, job_key, job_specs, *, workers, job_config, abort_state, redmesh_test_attestation,
                 pass_date_started, pass_date_completed, pass_window_egress_ips, pass_window_report_refs,
                 stop_scheduled):
  """The steps after a pass's FINALIZING write and its ledger hook: the run-mode end state (FINALIZED,
  STOPPED, FAILED scan_aborted, or RUNNING with the next pass due), its events and the archive. Shared by
  the uninterrupted pass and the resume of a pass whose launcher exited after that write (I-268)."""
  job_id = job_specs.get("job_id")
  job_pass = job_specs.get("job_pass", 1)
  run_mode = job_specs.get("run_mode", RUN_MODE_SINGLEPASS)
  empty_abort = bool(abort_state and abort_state["empty"])
  if empty_abort and job_pass <= 1:
    phase = abort_state["abort_phase"] or "unknown"
    _mark_job_failed(
      owner, job_key, job_specs, job_id=job_id, pass_nr=job_pass,
      failure_class="scan_aborted",
      message=f"Scan aborted during {phase}: {_abort_reason_text(abort_state['abort_reason'])}",
      meta={"abort_phase": phase, "abort_reason_class": abort_state["abort_reason_class"]},
    )
    return
  if empty_abort:
    # A monitor whose target was unreachable for one pass is not a failed
    # job; the pass says so and the schedule continues.
    owner._emit_timeline_event(
      job_specs,
      "pass_aborted",
      f"Pass {job_pass} aborted during {abort_state['abort_phase'] or 'unknown'}: "
      f"{_abort_reason_text(abort_state['abort_reason'])}",
      actor_type="system",
      meta={
        "pass_nr": job_pass,
        "abort_phase": abort_state["abort_phase"],
        "abort_reason_class": abort_state["abort_reason_class"],
      },
    )

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
    _enqueue_misp_auto_push(owner, job_specs, job_pass)
    owner._clear_live_progress(job_id, list(workers.keys()))
    return

  if stop_scheduled:
    set_job_status(job_specs, JOB_STATUS_STOPPED)
    owner._emit_timeline_event(job_specs, "scan_completed", f"Scan completed (pass {job_pass})")
    emit_lifecycle_event(
      owner,
      job_specs,
      event_type="redmesh.job.stopped",
      event_action="stopped",
      event_outcome="success",
      pass_nr=job_pass,
      started_at=pass_date_started,
      actual_end_at=pass_date_completed,
      expected_egress_ips=pass_window_egress_ips,
      report_refs=pass_window_report_refs,
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
    _enqueue_misp_auto_push(owner, job_specs, job_pass)
    owner._clear_live_progress(job_id, list(workers.keys()))
    return

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
      started_at=pass_date_started,
      actual_end_at=pass_date_completed,
      expected_egress_ips=pass_window_egress_ips,
      report_refs=pass_window_report_refs,
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
    _enqueue_misp_auto_push(owner, job_specs, job_pass)
    owner._clear_live_progress(job_id, list(workers.keys()))
    return

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
  enqueue_misp_auto_push(owner, job_specs, job_pass)
  owner._clear_live_progress(job_id, list(workers.keys()))

  owner.completed_jobs_reports.pop(job_id, None)
  if job_id in owner.lst_completed_jobs:
    owner.lst_completed_jobs.remove(job_id)


def maybe_finalize_pass(owner):
  """
  Launcher finalizes completed passes and orchestrates continuous monitoring.
  """
  # RM-139: merge finished automatic MISP pushes first, before the job list is read and whatever
  # the analysis slot says, so no loop write below can start from a record without the merge.
  poll_misp_auto_push(owner)
  all_jobs = _job_repo(owner).list_jobs()
  artifacts = _artifact_repo(owner)
  automatic_completion, should_yield = _poll_automatic_analysis(
    owner,
    all_jobs,
  )
  if should_yield:
    return

  for job_key, job_specs in all_jobs.items():
    normalized_key, job_specs = owner._normalize_job_record(job_key, job_specs)
    if normalized_key is None:
      continue
    if job_specs.get("job_type") == "model_test":
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
    resumed_automatic_analysis = (
      isinstance(automatic_completion, dict)
      and _automatic_analysis_state_matches(
        job_specs,
        automatic_completion.get("state"),
      )
    )
    if resumed_automatic_analysis:
      if job_status != JOB_STATUS_SCHEDULED_FOR_STOP:
        job_status = automatic_completion["state"]["job_status"]
    elif isinstance(automatic_completion, dict):
      continue
    if is_terminal_job_status(job_status):
      if not job_specs.get("job_cid") and job_specs.get("pass_reports"):
        owner.P(f"[STUCK RECOVERY] {job_id} is {job_status} but has no job_cid — retrying archive build", color='y')
        owner._build_job_archive(job_id, job_specs)
      continue
    if is_intermediate_job_status(job_status) and not resumed_automatic_analysis:
      ref = _current_pass_ref(job_specs)
      if (job_status == JOB_STATUS_FINALIZING and ref is not None and not job_specs.get("job_cid")
          and next_pass_at is None and _all_workers_finished_with_reports(workers)):
        _resume_finalizing_tail(owner, job_key, job_specs, workers, ref)
        continue
      if not _is_stale_intermediate_recovery_candidate(job_specs, workers, job_status, next_pass_at):
        continue
      _record_stale_intermediate_recovery(owner, job_specs, job_status, len(workers))
      set_job_status(job_specs, JOB_STATUS_COLLECTING)
      job_status = job_specs.get("job_status", JOB_STATUS_COLLECTING)

    new_pass_due = bool(all_finished and next_pass_at and owner.time() >= next_pass_at)
    if (run_mode == RUN_MODE_CONTINUOUS_MONITORING and not (all_finished and next_pass_at is None)
        # RM-248: a held pass is checked on the running-pass cadence, not on every tick.
        and _stop_if_engagement_ended(owner, job_specs, due=new_pass_due and job_id not in (
          getattr(owner, "_pass_holds", None) or {}))):
      continue

    if all_finished and next_pass_at is None:
      pass_date_started = owner._get_timeline_date(job_specs, "pass_started") or owner._get_timeline_date(job_specs, "created")
      pass_date_completed = (
        automatic_completion["state"]["pass_date_completed"]
        if resumed_automatic_analysis else owner.time()
      )
      now_ts = pass_date_completed

      set_job_status(job_specs, JOB_STATUS_COLLECTING)
      job_specs = _write_job_record(owner, job_key, job_specs, context="finalize_collecting")

      # Retain completed/partial reports even when new execution is denied.
      # Provider work and external emissions each require their own fresh check.
      node_reports = owner._collect_node_reports(workers)
      worker_finding_summaries = {
        addr: owner._summarize_worker_findings(report)
        for addr, report in node_reports.items()
      }
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
        get_host_aggregated_report(owner, node_reports, worker_cls=worker_cls)
        if node_reports else {}
      )
      if node_reports:
        owner.P(
          f"[FINALIZE] {job_id} pass {job_pass} aggregating as "
          f"{scan_type_raw or 'network'} via "
          f"{worker_cls.__name__ if worker_cls else 'default'} "
          f"({len(node_reports)} worker reports)"
        )
        if not aggregated:
          _record_skipped_ledger_pass(
            owner, job_specs, job_id=job_id, pass_nr=job_pass, date_completed=pass_date_completed)
          _mark_job_failed(
            owner, job_key, job_specs, job_id=job_id, pass_nr=job_pass,
            failure_class="report_aggregation_failed",
            message="Worker reports could not be merged into a pass report",
          )
          continue

      risk_score = 0
      flat_findings = []
      host_triage = {}
      risk_result = None
      abort_state = _pass_abort_state(aggregated, node_reports)
      empty_abort = bool(abort_state and abort_state["empty"])
      if aggregated:
        # The host triage map (report-findings.md §Triage): a closed finding leaves this pass's score and a
        # confirmed possible one is scored certain. A failed read scores as if nothing were triaged.
        try:
          host_triage = _job_repo(owner).list_triage_for_record(job_specs)
        except Exception as exc:
          owner.P(f"[FINALIZE] {job_id} host triage unavailable: {type(exc).__name__}", color='y')
          host_triage = {}
        risk_result, flat_findings = owner._compute_risk_and_findings(aggregated, host_triage)
        risk_score = risk_result["score"]
        if empty_abort:
          # Nothing was tested, so there is nothing to score. The flat findings
          # are kept: the "Scan aborted" record is the evidence of why.
          risk_score = 0
          risk_result = None
          owner.P(
            f"[ABORT] {job_id} pass {job_pass} aborted during "
            f"{abort_state['abort_phase'] or 'unknown'} with no probe attempted; "
            "no risk score and no analysis",
            color='y',
          )
        # A monitor's headline score stays at its last scored pass; only the
        # pass record says this one tested nothing.
        if not (empty_abort and job_pass > 1):
          job_specs["risk_score"] = risk_score
        owner.P(f"Risk score for job {job_id} pass {job_pass}: {risk_score}/100")

      job_config = owner._get_job_config(job_specs, resolve_secrets=False)
      llm_cfg = get_llm_agent_config(owner)
      llm_text = None
      summary_text = None
      llm_report_sections = None
      structured_llm_failed = None
      llm_failure_reason = None
      analysis_denial = _execution_denial_reason(owner, job_specs, config=job_config)
      if empty_abort:
        pass  # no analysis of a scan that tested nothing
      elif llm_cfg["ENABLED"] and aggregated and analysis_denial is not None:
        structured_llm_failed = True
        llm_failure_reason = "execution_authority_denied"
        _record_execution_denied(
          owner, job_specs, operation="llm_analysis", reason=analysis_denial, pass_nr=job_pass)
      elif llm_cfg["ENABLED"] and aggregated:
        if resumed_automatic_analysis:
          llm_report_sections = automatic_completion["sections"]
          structured_llm_failed = automatic_completion["failed"]
          llm_failure_reason = automatic_completion.get("reason") or "provider_error"
        else:
          set_job_status(job_specs, JOB_STATUS_ANALYZING)
          job_specs = _write_job_record(owner, job_key, job_specs, context="finalize_analyzing")
          try:
            if _check_execution(
              owner, job_specs, operation="llm_analysis", pass_nr=job_pass, config=job_config,
            ) is not None:
              raise _AnalysisDenied(_ANALYSIS_DENIED_MESSAGE)
            executor = owner._get_manual_analysis_executor()
            # RM-108 phase 5: _execution_operation_allowed above already required a binding.
            provider_options = {
              "before_provider_call": partial(
                _check_automatic_analysis_authority, owner, deepcopy(job_specs),
              ),
            }
            # HTTP work yields with PostponedRequest. Automatic work has no
            # request to postpone, so process() yields by checking this future
            # on later turns.
            future = executor.submit(
              owner._run_structured_report_sections,
              job_id=job_id,
              findings=flat_findings,
              triage=host_triage,  # the live host map: closes and confirms findings for the analysis only
              aggregated_report=aggregated,
              engagement=(
                job_config.get("engagement")
                if isinstance(job_config, dict) else None
              ),
              **provider_options,
            )
            owner._automatic_analysis_state = {
              "job_id": job_id,
              "pass_nr": job_pass,
              "report_identity": _automatic_analysis_report_identity(workers),
              "job_status": job_status,
              "pass_date_completed": pass_date_completed,
              "future": future,
              "discard_result": False,
              "execution_identity": _execution_identity(job_specs),
            }
            return
          except Exception as exc:
            owner._automatic_analysis_state = None
            owner.P(
              f"Structured LLM call raised for job {job_id}: {exc}",
              color='y',
            )
            structured_llm_failed = True
            llm_failure_reason = (
              "execution_authority_denied" if isinstance(exc, _AnalysisDenied) else "provider_error")

        if llm_report_sections and not structured_llm_failed:
          llm_text, summary_text = render_legacy_llm_fields(llm_report_sections)

      llm_failed = True if (llm_cfg["ENABLED"] and structured_llm_failed) else None
      if llm_failed:
        owner._emit_timeline_event(
          job_specs, "llm_failed",
          f"LLM analysis unavailable for pass {job_pass}",
          meta={"pass_nr": job_pass, "reason": llm_failure_reason or "provider_error"}
        )

      worker_metas = {}
      for addr, report in node_reports.items():
        nr_findings, finding_counts, finding_signatures = worker_finding_summaries[addr]
        worker_metas[addr] = WorkerReportMeta(
          report_cid=workers[addr].get("report_cid", ""),
          start_port=report.get("start_port", 0),
          end_port=report.get("end_port", 0),
          ports_scanned=report.get("ports_scanned", 0),
          open_ports=report.get("open_ports", []),
          nr_findings=nr_findings,
          node_ip=report.get("node_ip", ""),
          country=(report.get("country_code") or "").upper(),
          finding_counts=finding_counts,
          finding_signatures=finding_signatures,
          response_evidence=report.get("response_evidence"),
        ).to_dict()

      aggregated_report_cid = None
      if aggregated:
        aggregated_data = AggregatedScanData.from_dict(aggregated).to_dict()
        aggregated_report_cid = artifacts.put_json(aggregated_data, show_logs=False)
        if not aggregated_report_cid:
          owner.P(f"Failed to store aggregated report for pass {job_pass} in R1FS", color='r')
          _record_skipped_ledger_pass(
            owner, job_specs, job_id=job_id, pass_nr=job_pass, date_completed=pass_date_completed)
          continue

      redmesh_test_attestation = None
      required_attestation = _attestation_required(job_specs, job_config)
      stop_scheduled = _stop_scheduled(job_specs, job_status)
      terminal_after_pass = (
        run_mode == RUN_MODE_SINGLEPASS
        or stop_scheduled
        or job_pass >= MAX_CONTINUOUS_PASSES
      )
      # A scan that tested nothing gets no on-chain "0 vulnerabilities" record;
      # the job fails below instead.
      should_submit_attestation = bool(required_attestation and terminal_after_pass and not empty_abort)
      if not should_submit_attestation:
        pass
      elif run_mode == RUN_MODE_CONTINUOUS_MONITORING and not terminal_after_pass:
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

      attestation_failure_reason = None
      if should_submit_attestation:
        attestation_failure_reason = _check_execution(
          owner, job_specs, operation="attestation", pass_nr=job_pass)
      if should_submit_attestation and attestation_failure_reason is None:
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
          attestation_failure_reason = "submit_failed"
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
      if required_attestation and terminal_after_pass and not empty_abort and not (
        isinstance(redmesh_test_attestation, dict) and redmesh_test_attestation.get("tx_hash")
      ):
        emit_attestation_status_event(
          owner,
          job_specs,
          state="failed",
          network=owner.REDMESH_ATTESTATION_NETWORK,
          pass_nr=job_pass,
        )
        # RM-221: the scan finished, so the job keeps its normal terminal status and its results;
        # only the attestation is marked failed (retry_job_attestation can submit it later).
        attestation_failure_reason = attestation_failure_reason or attestation_unsubmitted_reason(owner)
        job_specs["attestation_status"] = "failed"
        job_specs["attestation_failure_reason"] = attestation_failure_reason
        owner._emit_timeline_event(
          job_specs, "attestation_failed", "End attestation was not submitted",
          actor_type="system", meta={"pass_nr": job_pass, "reason": attestation_failure_reason},
        )
      elif required_attestation and terminal_after_pass and not empty_abort:
        job_specs["attestation_status"] = "submitted"

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

      if llm_report_sections is not None and _check_execution(
        owner, job_specs, operation="llm_analysis", pass_nr=job_pass, config=job_config,
      ) is not None:
        llm_report_sections = llm_text = summary_text = None
        llm_failed = True
        llm_failure_reason = "execution_authority_denied"

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
        llm_failure_reason=llm_failure_reason if llm_failed else None,
        llm_report_sections=llm_report_sections,
        findings=flat_findings if flat_findings else None,
        scan_metrics=pass_metrics,
        worker_scan_metrics=worker_scan_metrics if worker_scan_metrics else None,
        redmesh_test_attestation=redmesh_test_attestation,
        **({k: abort_state[k] for k in ("aborted", "abort_reason", "abort_phase", "abort_reason_class")}
           if abort_state else {}),
      )

      pass_report_cid = artifacts.put_pass_report(pass_report, show_logs=False)
      if not pass_report_cid:
        owner.P(f"Failed to store pass report for pass {job_pass} in R1FS", color='r')
        _record_skipped_ledger_pass(
          owner, job_specs, job_id=job_id, pass_nr=job_pass, date_completed=pass_date_completed)
        continue

      job_specs.setdefault("pass_reports", []).append(
        PassReportRef(job_pass, pass_report_cid, risk_score).to_dict()
      )
      pass_window_report_refs = {"pass_report_cid": pass_report_cid}
      if aggregated_report_cid:
        pass_window_report_refs["aggregated_report_cid"] = aggregated_report_cid
      pass_window_egress_ips = [
        meta.get("node_ip") for meta in worker_metas.values()
        if meta.get("node_ip")
      ]
      emit_lifecycle_event(
        owner,
        job_specs,
        event_type="redmesh.job.pass_completed",
        event_action="pass_completed",
        event_outcome="success",
        pass_nr=job_pass,
        started_at=pass_date_started,
        actual_end_at=pass_date_completed,
        expected_egress_ips=pass_window_egress_ips,
        report_refs=pass_window_report_refs,
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
      job_specs = _ensure_rulebook_assessment_after_pass(owner, job_specs, job_id=job_id, pass_nr=job_pass)
      job_specs = _record_engagement_ledger_after_pass(
        owner, job_key, job_specs, artifacts, job_id=job_id, pass_nr=job_pass,
        pass_report_cid=pass_report_cid, node_reports=node_reports, workers=workers,
        date_completed=pass_date_completed,
        flat_findings=flat_findings, aggregated=aggregated, pass_metrics=pass_metrics,
        abort_state=abort_state, job_config=job_config,
      )

      _finish_pass(
        owner, job_key, job_specs, workers=workers, job_config=job_config, abort_state=abort_state,
        redmesh_test_attestation=redmesh_test_attestation, pass_date_started=pass_date_started,
        pass_date_completed=pass_date_completed, pass_window_egress_ips=pass_window_egress_ips,
        pass_window_report_refs=pass_window_report_refs, stop_scheduled=stop_scheduled,
      )

    elif run_mode == RUN_MODE_CONTINUOUS_MONITORING and all_finished and next_pass_at and owner.time() >= next_pass_at:
      job_config = owner._get_job_config(job_specs, resolve_secrets=False)
      # RM-248: a pass held for a suspension is re-checked at most once a minute, like a running pass.
      holds = getattr(owner, "_pass_holds", None)
      if not isinstance(holds, dict):
        holds = owner._pass_holds = {}
      if owner.time() - holds.get(job_id, float("-inf")) < ENGAGEMENT_RECHECK_SECONDS:
        continue
      denial = _execution_denial_reason(owner, job_specs, operation="new_pass", config=job_config)
      holds.pop(job_id, None)
      if denial is not None:
        # RM-248: a suspended engagement holds the next pass (the job is neither stopped nor failed);
        # the first held tick leaves one timeline entry, and the pass starts after the resume.
        if denial == "engagement_suspended":
          holds[job_id] = owner.time()
          held = len(job_specs.get("timeline") or [])
          _record_execution_denied(owner, job_specs, operation="new_pass", reason=denial, pass_nr=job_pass)
          if len(job_specs["timeline"]) > held:
            _write_job_record(owner, job_key, job_specs, context="continuous_hold")
        continue
      job_specs["job_pass"] = job_pass + 1
      job_specs["next_pass_at"] = None
      owner._emit_timeline_event(job_specs, "pass_started", f"Pass {job_pass + 1} started")

      for addr in workers:
        workers[addr]["finished"] = False
        workers[addr]["result"] = None
        workers[addr]["report_cid"] = None

      _write_job_record(owner, job_key, job_specs, context="continuous_restart")
      owner.P(f"[CONTINUOUS] Starting pass {job_pass + 1} for job {job_id}")
