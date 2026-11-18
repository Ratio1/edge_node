import time
from copy import deepcopy
from contextlib import ExitStack

from ..cve_view import apply_triage, drop_closed, effective_status
from ..model_testing.artifacts import ModelTestArchive
from ..model_testing.constants import is_model_test_job
from ..models import FindingTriageAuditEntry, FindingTriageState, JobArchive, VALID_TRIAGE_STATUSES
from ..repositories import ArtifactRepository, JobStateRepository
from ..repositories.cstore import TriageStoreError
from ..tenancy.administration import AdministrationDenied
from ..tenancy.job_artifacts import (
  MAX_ARTIFACT_REFERENCES, TenantJobArtifacts, checked_job_snapshot, validate_snapshot_mode,
)
from ..tenancy.execution import triage_scope
from ..tenancy.ports import TenantStoreError
from ..tenancy.tenant_assets import NOTES_MAX
from .event_hooks import emit_finding_event

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


def _write_job_record(owner, job_id, job_specs, context):
  writer = getattr(type(owner), "_write_job_record", None)
  if callable(writer):
    return writer(owner, job_id, job_specs, context=context)
  launcher = job_specs.get("launcher") if isinstance(job_specs, dict) else None
  if launcher and launcher != getattr(owner, "ee_addr", None):
    return None
  return _job_repo(owner).put_job(job_id, job_specs)


def _archive_contains_finding(archive: dict, finding_id: str) -> bool:
  return _find_archive_finding(archive, finding_id) is not None


def _find_archive_finding(archive: dict, finding_id: str):
  for pass_report in archive.get("passes", []) or []:
    for finding in pass_report.get("findings", []) or []:
      if isinstance(finding, dict) and finding.get("finding_id") == finding_id:
        return finding
  return None


def _stamp(finding, triage):
  # Embeds the record; a confirmed possible finding reads certain. The stored archive and its score are not rewritten.
  finding.update(apply_triage([finding], {finding.get("finding_id"): triage})[0])


def _merge_triage_into_archive_dict(archive: dict, triage_map: dict) -> dict:
  merged = deepcopy(archive)
  for pass_report in merged.get("passes", []) or []:
    for finding in pass_report.get("findings", []) or []:
      if not isinstance(finding, dict):
        continue
      triage = triage_map.get(finding.get("finding_id"))
      if triage:
        _stamp(finding, triage)
  ui = merged.get("ui_aggregate")
  if isinstance(ui, dict):
    # A finding closed after the build leaves the stored top findings; the stored score is not recomputed.
    if isinstance(ui.get("top_findings"), list):
      ui["top_findings"] = drop_closed(ui["top_findings"], triage_map)
    for finding in ui.get("top_findings", []) or []:
      if not isinstance(finding, dict):
        continue
      triage = triage_map.get(finding.get("finding_id"))
      if triage:
        _stamp(finding, triage)
  return merged


def _checked_triage_map(owner, job, archive, finding_id=""):
  """Read state only for archive-owned findings; reports:view does not grant audit:view.

  The map is the job's tenant and host, both from the job's own execution binding. A record that does
  not name that tenant and host, or this finding, is a broken store, never a foreign row to skip.
  """
  try:
    passes = archive.get("passes", [])
    if not isinstance(passes, list) or len(passes) > MAX_ARTIFACT_REFERENCES:
      raise ValueError("Invalid archived passes")
    finding_ids = set()
    count = 0
    for report in passes:
      findings = report.get("findings", [])
      if not isinstance(findings, list):
        raise ValueError("Invalid archived findings")
      count += len(findings)
      if count > MAX_ARTIFACT_REFERENCES:
        raise ValueError("Finding read budget exceeded")
      for finding in findings:
        identifier = finding.get("finding_id")
        if not isinstance(identifier, str) or not identifier.strip():
          raise ValueError("Invalid finding identity")
        finding_ids.add(identifier)
    if finding_id and finding_id not in finding_ids:
      raise AdministrationDenied(404, "not_found")
    scope = triage_scope(job["execution_binding"])
    if scope is None:
      return {}
    tenant_id, host = scope
    repo = _job_repo(owner)
    result = {}
    # Point reads of the archive's own findings, not an enumeration of the tenant's hkey.
    for identifier in ([finding_id] if finding_id else sorted(finding_ids)):
      state = deepcopy(repo.get_host_triage(tenant_id, host, identifier))
      if state is None:
        continue
      if not isinstance(state, dict) or not _names_key(state, tenant_id, host, identifier):
        raise ValueError("Invalid finding state identity")
      result[identifier] = FindingTriageState.from_dict(state).to_dict()
    return result
  except AdministrationDenied:
    raise
  except Exception:
    raise TenantStoreError("Tenant finding state is unavailable") from None


def _with_effective_status(owner, triage_map):
  """Each record with `effective_status` beside the stored `status`: an `accepted_risk` past its `review_at`
  reads `reopened`, so a reader does not re-implement the expiry. A read-time copy, never stored."""
  clock = getattr(owner, "time", None)
  now = clock() if callable(clock) else time.time()
  return {finding_id: {**record, "effective_status": effective_status(record, now)}
          for finding_id, record in triage_map.items()}


def get_job_triage(owner, job_id: str, finding_id: str = "", *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked_job is not _UNSET)
  if checked_job is not _UNSET:
    job = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
    archive = TenantJobArtifacts(job, _artifact_repo(owner).get_json, snapshot_mode=snapshot_mode).archive()
    if archive is None:
      raise AdministrationDenied(404, "not_found")
    if is_model_test_job(job):
      if finding_id:
        raise AdministrationDenied(404, "not_found")
      triage_map = {}
    else:
      triage_map = _with_effective_status(owner, _checked_triage_map(owner, job, archive, finding_id))
    result = {"job_id": job_id}
    if snapshot_mode == "tenant_bound":
      result["execution_binding"] = job["execution_binding"]
    if finding_id:
      state = triage_map.get(finding_id)
      result.update(finding_id=finding_id, found=state is not None, triage=state)
    else:
      result["triage"] = triage_map
    return result
  record = owner._get_job_from_cstore(job_id)
  triage_map = _with_effective_status(owner, _job_repo(owner).list_triage_for_record(record))
  if finding_id:
    state = triage_map.get(finding_id)
    scope = triage_scope(record.get("execution_binding")) if isinstance(record, dict) and record.get("execution_binding") else None
    audit = _job_repo(owner).get_host_triage_audit(*scope, finding_id) if scope else []
    if state is None:
      return {"job_id": job_id, "finding_id": finding_id, "found": False, "triage": None, "audit": audit}
    return {"job_id": job_id, "finding_id": finding_id, "found": True, "triage": state, "audit": audit}
  return {"job_id": job_id, "triage": triage_map}


MAX_TRIAGE_FINDINGS = 500
_LOCK_ATTEMPTS = 3
_CLOSING_STATUSES = frozenset({"false_positive", "remediated", "accepted_risk"})


def _host_job_ids(owner, job, scope):
  """Every job of the same deployment, tenant and host as `job`, itself included (from the bindings)."""
  namespace = job["execution_binding"]["namespace"]
  ids = {job["job_id"]}
  for key, record in (_job_repo(owner).list_jobs() or {}).items():
    binding = record.get("execution_binding") if isinstance(record, dict) else None
    if (isinstance(key, str) and isinstance(binding, dict) and binding.get("namespace") == namespace
        and triage_scope(binding) == scope):
      ids.add(key)
  return ids


def _error(code, message, **extra):
  return {"error": code, "message": message, **extra}


def update_finding_triage(owner, job_id: str, finding_ids, status: str, note: str = "", actor: str = "",
                          review_at: float = 0, confirm: bool = False, *, checked_job=_UNSET, ledger=None):
  """Set the triage of one or many findings of a job, stored by (tenant, host, finding), not by job.

  Tenant and host come from the job's own execution binding; `actor` is the server-resolved account, never
  a body field. A pending rulebook submission on any job of the same tenant and host blocks the write: the
  locks of every such job are taken in sorted `(job_id, profile_id)` order, the order purge uses, so no two
  takers can wait on each other. The locks are per process. Across nodes only the pending registry read below
  applies, and a read is not a lock: a submission that a sibling job's launcher on another node starts after
  that read can still see this write land. Known limit, accepted for v1 (owner, 2026-11-18); CStore has no
  cross-node lock. A set of findings (a dismissed rollup) is written one record each, because CStore has no
  cross-record transaction: the result lists each member and a retry skips the ones already written.

  A write the store did not confirm (CStore can store a field locally and then time out waiting for its peers)
  reports `write_failed`. The launcher remembers it in memory, and the next request for that finding writes the
  state and audit entry again, and emits the event, before it reports or replaces the record. A change whose writes
  were confirmed but whose event failed is kept too; the next request emits only the event. After a launcher
  restart only a missing audit entry marks a change unfinished: an audit entry stored locally but never
  confirmed then reads as finished, and its finding event is not emitted. Known limit, accepted for v1
  (owner, 2026-11-18).
  """
  from .rulebook_assessment import _submission_lock, list_rulebook_profiles

  ids = [finding_ids] if isinstance(finding_ids, str) else finding_ids
  if (not isinstance(ids, (list, tuple)) or not ids or len(ids) > MAX_TRIAGE_FINDINGS
      or any(not isinstance(item, str) or not item.strip() or "\x1f" in item for item in ids)):
    return _error("validation_error", "finding_ids must be 1 to %d finding ids." % MAX_TRIAGE_FINDINGS)
  if not isinstance(note, str) or len(note) > NOTES_MAX:
    return _error("validation_error", "note must be text of at most %d characters." % NOTES_MAX)
  if status not in VALID_TRIAGE_STATUSES:
    return _error("validation_error",
                  f"Unsupported triage status: {status}. Allowed: {sorted(VALID_TRIAGE_STATUSES)}")
  if status == "accepted_risk":
    if type(review_at) not in (int, float) or review_at <= owner.time():
      return _error("validation_error", "accepted_risk requires review_at, a future time (epoch seconds).")
  else:
    review_at = 0
  if confirm and status != "open":
    return _error("validation_error", "A confirmation is recorded with status open.")
  ids = list(dict.fromkeys(ids))
  job = owner._get_job_from_cstore(job_id) if checked_job is _UNSET else checked_job
  if not isinstance(job, dict) or not job:
    return _error("not_found", f"Job {job_id} not found.")
  binding = job.get("execution_binding")
  scope = triage_scope(binding) if binding is not None else None
  profiles = sorted(profile["profile_id"] for profile in list_rulebook_profiles())
  repo = _job_repo(owner)
  for _attempt in range(_LOCK_ATTEMPTS):
    hosted = sorted(_host_job_ids(owner, job, scope)) if scope else [job_id]
    with ExitStack() as stack:
      for target in sorted((member, profile) for member in hosted for profile in profiles):
        stack.enter_context(_submission_lock(owner, *target))
      if scope and not set(_host_job_ids(owner, job, scope)) <= set(hosted):
        continue  # a sibling appeared before the locks were held: release everything and take the larger set
      for member in hosted:
        for profile in profiles:
          registry = repo.get_rulebook_submission_registry(member, profile)
          if isinstance(registry, dict) and registry.get("pending"):
            return _error("submission_in_progress",
                          "Finding triage cannot change while a formal review submission is pending.",
                          job_id=job_id, finding_ids=ids)
      return _update_finding_triage_locked(owner, job_id, job, scope, ids, status, note, actor, review_at,
                                           confirm, checked_job is not _UNSET, ledger)
  return _error("triage_contention", "Jobs of this host are changing; retry.", job_id=job_id, retryable=True)


def _names_key(state, tenant_id, host, finding_id):
  """True when a stored record names the (tenant, host, finding) it is stored under."""
  return (state.get("finding_id") == finding_id and state.get("tenant_id") == tenant_id
          and state.get("host") == host)


def _unfinished_writes(owner):
  """`(tenant, host, finding) -> {"state", "state_confirmed"}`: the triage changes this launcher started whose writes
  the store did not all confirm. In memory: a restart forgets it, and then only a missing audit entry marks a change
  unfinished."""
  unfinished = getattr(owner, "_triage_unfinished_writes", None)
  if not isinstance(unfinished, dict):
    unfinished = owner._triage_unfinished_writes = {}
  return unfinished


def _stored_state(stored):
  """`stored` as a FindingTriageState, or None for a malformed record (left as is, like one without an entry id)."""
  try:
    return FindingTriageState.from_dict(stored)
  except (KeyError, TypeError, ValueError):
    return None


def _commit_triage(owner, repo, key, state, ledger, announce, write_state=True, write_audit=True, audit_payload=None):
  """Write `state` and its audit entry under `state.audit_entry_id`, each write confirmed, then `announce` it.

  The unfinished map holds the change, with the phase it reached, until the announce returns: the next request for
  the finding repeats only what is left (`write_state`/`write_audit` False skip a confirmed write; same fields and
  payloads) before it reports. Each confirmed write is recorded on the ledger. The audit entry records the change
  as made (job, actor, time).
  """
  from ..tenancy.effects import EffectState

  if ledger is not None:
    ledger.checkpoint()
  unfinished = _unfinished_writes(owner)
  state_payload = state.to_dict()
  if write_state:
    unfinished[key] = {"state": state_payload, "state_confirmed": False, "audit_confirmed": False}
    state_payload = repo.put_host_triage(state)
    if ledger is not None:
      ledger.record(EffectState.PERSISTED)
  if write_audit:
    unfinished[key] = {"state": state_payload, "state_confirmed": True, "audit_confirmed": False}
    audit_payload = repo.append_host_triage_audit(FindingTriageAuditEntry(
      job_id=state_payload["job_id"], finding_id=state_payload["finding_id"], status=state_payload["status"],
      note=state_payload.get("note", ""), actor=state_payload.get("actor", ""), timestamp=state_payload["updated_at"],
      tenant_id=state_payload["tenant_id"], host=state_payload["host"]), entry_id=state_payload["audit_entry_id"])
    if ledger is not None:
      ledger.record(EffectState.PERSISTED)
  unfinished[key] = {"state": state_payload, "state_confirmed": True, "audit_confirmed": True, "audit": audit_payload}
  announce(state_payload)
  unfinished.pop(key, None)
  return state_payload, audit_payload


def _announce_triage(owner, record, archived, state_payload):
  """The node audit log line and the finding event of a written change; the event goes to this request's job."""
  if hasattr(owner, "_log_audit_event"):
    owner._log_audit_event("finding_triage_updated", {
      "job_id": state_payload["job_id"], "finding_id": state_payload["finding_id"], "status": state_payload["status"],
      "actor": state_payload.get("actor", "")})
  finding_event = dict(archived)
  finding_event["triage_state"] = state_payload["status"]
  emit_finding_event(owner, record, finding=finding_event, event_action="triaged")


def _update_finding_triage_locked(owner, job_id, job, scope, ids, status, note, actor, review_at, confirm,
                                  checked, ledger):
  now = owner.time()
  if is_model_test_job(job):
    return _error("model_test_not_supported", "Model-test jobs have no finding triage.", job_id=job_id)
  if scope is None:
    return _error("not_available", f"Job {job_id} has no target to triage findings against.")
  if not job.get("job_cid"):
    return _error("not_available", f"Job {job_id} is still running (triage requires archived findings).")
  launcher = job.get("launcher")
  if launcher and launcher != getattr(owner, "ee_addr", None):
    return _error("job_launcher_mismatch", "Finding triage must be handled by the job launcher.",
                  status_code=409, job_id=job_id)
  if checked:
    archive = TenantJobArtifacts(job, _artifact_repo(owner).get_json, snapshot_mode="tenant_bound").archive()
  else:
    archive = _artifact_repo(owner).get_archive(job)
  if not isinstance(archive, dict):
    return _error("fetch_failed", f"Failed to fetch archive for job {job_id}.")

  tenant_id, host = scope
  repo = _job_repo(owner)
  # The event and the SOC status go on the stored record, not on a detached admission snapshot.
  record = (owner._get_job_from_cstore(job_id) if checked else job) or job
  results = []
  announced = False
  for finding_id in ids:
    archived = _find_archive_finding(archive, finding_id)
    if archived is None:
      results.append({"finding_id": finding_id, "outcome": "not_found"})
      continue
    if confirm and archived.get("confidence") != "tentative":
      results.append({"finding_id": finding_id, "outcome": "not_tentative"})
      continue
    stored = repo.get_host_triage(tenant_id, host, finding_id)
    if isinstance(stored, dict) and not _names_key(stored, tenant_id, host, finding_id):
      # A broken store, as on the read side: never replayed (its body would choose the write's tenant and host),
      # never replaced. Fails closed for this member.
      results.append({"finding_id": finding_id, "outcome": "store_inconsistent"})
      continue
    key = (tenant_id, host, finding_id)
    unfinished = _unfinished_writes(owner)
    pending = unfinished.get(key)
    stored_id = stored.get("audit_entry_id") if isinstance(stored, dict) else None
    # An unfinished change is finished first, under its own entry id, so its audit entry is written once, before this
    # request is reported or replaces the record:
    # - this launcher wrote its state and the store confirmed it, but not its audit entry: the entry is written again,
    #   whatever the record holds now (a sibling job's launcher may have replaced it since);
    # - this launcher wrote its state but the store did not confirm it, and the record still holds it: both again;
    # - otherwise the record's audit entry is missing (after a restart, or written by another node): both again.
    # A state write that stored nothing, or that a newer change replaced before it was confirmed, was reported
    # `write_failed` and is dropped. A record without the id (an older node wrote it) is left as is. Known limit: a
    # node that sees the state before the audit field replicates finishes it too; the entry is the same field and
    # payload, but the finding event is emitted again.
    # A change whose writes were both confirmed but whose event was not emitted (the announce raised) is announced.
    finish, phase = None, {}
    if pending and pending["state_confirmed"]:
      finish = FindingTriageState.from_dict(pending["state"])
      phase = {"write_state": False, "write_audit": not pending["audit_confirmed"], "audit_payload": pending.get("audit")}
    elif pending and pending["state"].get("audit_entry_id") == stored_id:
      finish = _stored_state(stored)
    else:
      unfinished.pop(key, None)
      if stored_id and not repo.has_host_triage_audit_entry(tenant_id, host, finding_id, stored_id):
        finish = _stored_state(stored)
    # A write keeps an earlier confirmation unless it is a new one or the finding is dismissed as a false positive.
    kept = isinstance(stored, dict) and stored.get("confirmed") is True and status != "false_positive"
    confirmed = True if confirm or kept else None
    confirmed_by = stored.get("confirmed_by") if kept else ((actor or "") if confirm else None)
    same = (isinstance(stored, dict) and stored.get("status") == status and stored.get("note", "") == (note or "")
            and stored.get("review_at") == (review_at or None)
            and bool(stored.get("confirmed")) == bool(confirmed)
            and (not confirmed or stored.get("confirmed_by") == confirmed_by))
    if same and finish is None:
      results.append({"finding_id": finding_id, "outcome": "unchanged", "triage": deepcopy(stored)})
      continue
    state_payload = deepcopy(stored)
    announce = lambda payload, archived=archived: _announce_triage(owner, record, archived, payload)
    try:
      if finish is not None:
        _, audit_payload = _commit_triage(owner, repo, key, finish, ledger, announce, **phase)
        announced = True
      if not same:
        state_payload, audit_payload = _commit_triage(owner, repo, key, FindingTriageState(
          job_id=job_id, finding_id=finding_id, status=status, note=note or "", actor=actor or "", updated_at=now,
          review_at=review_at or None, tenant_id=tenant_id, host=host,
          confirmed=confirmed, confirmed_by=confirmed_by,
          audit_entry_id=repo.new_host_triage_audit_entry_id(now)), ledger, announce)
        announced = True
    except TriageStoreError:
      # The store did not confirm a write: report it, never a success; a retry finishes the member.
      results.append({"finding_id": finding_id, "outcome": "write_failed", "retryable": True})
      continue
    results.append({"finding_id": finding_id, "outcome": "updated", "triage": state_payload,
                    "audit": audit_payload})
  # An emitted event changes the record's SOC status, also when a later write of the same member failed.
  if announced and isinstance(record.get("soc_event_status"), dict):
    _write_job_record(owner, job_id, record, context="finding_triage_soc_event")
  return {
    "job_id": job_id,
    "requested_status": status,
    "results": results,
    # a rollup counts as dismissed only when every member is written (now or on an earlier call)
    "complete": all(item["outcome"] in ("updated", "unchanged") for item in results),
  }


def get_job_archive_with_triage(owner, job_id: str, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked_job is not _UNSET)
  if checked_job is not _UNSET:
    job = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
    payload = TenantJobArtifacts(job, _artifact_repo(owner).get_json, snapshot_mode=snapshot_mode).archive()
    result = {"job_id": job_id}
    if snapshot_mode == "tenant_bound":
      result["execution_binding"] = job["execution_binding"]
    if payload is None:
      return {**result, "error": "not_available"}
    try:
      model = ModelTestArchive if is_model_test_job(job) else JobArchive
      archive = model.from_dict(payload).to_dict()
      triage_map = {} if is_model_test_job(job) else _with_effective_status(
        owner, _checked_triage_map(owner, job, payload))
      return {**result, "archive": _merge_triage_into_archive_dict(archive, triage_map), "triage": triage_map}
    except Exception:
      raise TenantStoreError("Tenant archive is unavailable") from None
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {"error": "not_found", "message": f"Job {job_id} not found."}

  job_cid = job_specs.get("job_cid")
  if not job_cid:
    return {"error": "not_available", "message": f"Job {job_id} is still running (no archive yet)."}

  if is_model_test_job(job_specs):
    try:
      payload = _artifact_repo(owner).get_archive(job_specs)
      if not isinstance(payload, dict):
        return {"error": "fetch_failed", "message": f"Failed to fetch archive from R1FS (CID: {job_cid})."}
      archive = ModelTestArchive.from_dict(payload).to_dict()
    except (KeyError, TypeError, ValueError) as exc:
      return {
        "error": "unsupported_archive_version",
        "message": str(exc),
        "job_id": job_id,
        "job_cid": job_cid,
      }

    if archive.get("job_id") != job_id:
      owner.P(
        f"[INTEGRITY] Archive CID {job_cid} has job_id={archive.get('job_id')}, expected {job_id}",
        color='r'
      )
      return {"error": "integrity_mismatch", "message": "Archive job_id does not match requested job_id."}

    return {"job_id": job_id, "archive": archive, "triage": {}}

  try:
    archive = _artifact_repo(owner).get_archive_model(job_specs)
    if archive is None:
      return {"error": "fetch_failed", "message": f"Failed to fetch archive from R1FS (CID: {job_cid})."}
    archive = archive.to_dict()
  except ValueError as exc:
    return {
      "error": "unsupported_archive_version",
      "message": str(exc),
      "job_id": job_id,
      "job_cid": job_cid,
    }

  if archive.get("job_id") != job_id:
    owner.P(
      f"[INTEGRITY] Archive CID {job_cid} has job_id={archive.get('job_id')}, expected {job_id}",
      color='r'
    )
    return {"error": "integrity_mismatch", "message": "Archive job_id does not match requested job_id."}

  archived_ids = {finding.get("finding_id") for pass_report in archive.get("passes", []) or []
                  for finding in pass_report.get("findings", []) or [] if isinstance(finding, dict)}
  triage_map = _with_effective_status(owner, {
    key: value for key, value in _job_repo(owner).list_triage_for_record(job_specs).items() if key in archived_ids})
  merged_archive = _merge_triage_into_archive_dict(archive, triage_map)
  return {"job_id": job_id, "archive": merged_archive, "triage": triage_map}
