from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone

from ..models import render_legacy_llm_fields
from .config import get_api_operations_config, get_llm_agent_config
from .scan_strategy import coerce_scan_type, get_scan_strategy


OPERATION_SCHEMA_VERSION = "redmesh_api_operation_v1"
OPERATION_TYPE_ANALYZE_JOB = "analyze_job"

STATE_QUEUED = "queued"
STATE_RUNNING = "running"
STATE_SUCCEEDED = "succeeded"
STATE_FAILED = "failed"
STATE_CANCEL_REQUESTED = "cancel_requested"
STATE_CANCELED = "canceled"
STATE_EXPIRED = "expired"

ACTIVE_OPERATION_STATES = {
  STATE_QUEUED,
  STATE_RUNNING,
  STATE_CANCEL_REQUESTED,
}
TERMINAL_OPERATION_STATES = {
  STATE_SUCCEEDED,
  STATE_FAILED,
  STATE_CANCELED,
  STATE_EXPIRED,
}

PUBLIC_FAILURE_KEYS = {
  "failure_class",
  "retryable",
  "phase",
  "short_message",
  "attempt_count",
}
RESULT_HANDLE_PREFIX = "opres_"

ALLOWED_ANALYSIS_TYPES = {
  "structured_report_sections",
}
ALLOWED_FOCUS_AREAS = {
  "api",
  "authentication",
  "authorization",
  "databases",
  "network",
  "services",
  "tls",
  "web",
}
_CID_RE = re.compile(r"(?i)\b(?:Qm[1-9A-HJ-NP-Za-km-z]{20,}|bafy[a-z2-7]{20,}|r1fs:[^\s,;]+)\b")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s,;]+")
_SENSITIVE_RE = re.compile(r"(?i)(api[_-]?key|authorization|bearer|password|secret|token|credential|prompt)")
_TOKEN_VALUE_RE = re.compile(
  r"(?i)\b(?:sk|pk|rk|xox[baprs]|gh[pousr]|eyJ)[A-Za-z0-9._=-]{8,}\b"
)


class ApiOperationError(Exception):
  def __init__(self, code: str, message: str = "", *, retryable: bool = False):
    super().__init__(message or code)
    self.code = code
    self.message = message or code
    self.retryable = bool(retryable)


def _utc_timestamp():
  return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _utc_timestamp_after(seconds: int):
  delta = timedelta(seconds=max(_safe_int(seconds, 0), 0))
  return (datetime.now(timezone.utc) + delta).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_int(value, default=0):
  try:
    return int(value)
  except (TypeError, ValueError):
    return default


def _sha256(value: str) -> str:
  return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hmac_sha256(secret: str, value: str) -> str:
  return hmac.new(
    str(secret or "").encode("utf-8"),
    str(value or "").encode("utf-8"),
    hashlib.sha256,
  ).hexdigest()


def _constant_time_in(value: str, candidates: list[str]) -> bool:
  found = False
  for candidate in candidates:
    found = hmac.compare_digest(value, str(candidate or "")) or found
  return found


def _error(code: str, message: str = "", *, retryable: bool = False, **extra):
  payload = {
    "error": code,
    "message": message or code,
    "retryable": bool(retryable),
  }
  payload.update(extra)
  return payload


def _not_found():
  return _error("operation_not_found", "Operation not found")


def _operation_store_lock(owner):
  lock = getattr(owner, "_api_operation_store_lock", None)
  if lock is None:
    lock = threading.RLock()
    setattr(owner, "_api_operation_store_lock", lock)
  return lock


def _job_operation_lock(owner, job_id: str):
  locks = getattr(owner, "_api_operation_job_locks", None)
  if not isinstance(locks, dict):
    locks = {}
    setattr(owner, "_api_operation_job_locks", locks)
  key = str(job_id or "")
  lock = locks.get(key)
  if lock is None:
    lock = threading.RLock()
    locks[key] = lock
  return lock


def _safe_log(owner, message: str, color=None):
  logger = getattr(owner, "P", None)
  if callable(logger):
    if color is None:
      logger(message)
    else:
      logger(message, color=color)


def _resolve_operation_hmac_secret(config: dict) -> str:
  inline = str(config.get("HMAC_SECRET") or "").strip()
  if inline:
    return inline
  env_name = str(config.get("HMAC_SECRET_ENV") or "").strip()
  if env_name:
    return str(os.environ.get(env_name, "") or "").strip()
  return ""


def _valid_token_hashes(config: dict) -> list[str]:
  hashes = [str(item or "").strip().lower() for item in config.get("TOKEN_HASHES") or [] if item]
  env_name = str(config.get("TOKEN_ENV") or "").strip()
  if env_name:
    env_token = str(os.environ.get(env_name, "") or "").strip()
    if env_token:
      hashes.append(_sha256(env_token))
  return hashes


def derive_operation_auth_context(owner, token: str) -> dict:
  config = get_api_operations_config(owner)
  if not config.get("ENABLED"):
    raise ApiOperationError("operation_auth_disabled", "API operations are disabled")

  token = str(token or "").strip()
  if not token:
    raise ApiOperationError("operation_auth_required", "Bearer token is required")

  token_hash = _sha256(token)
  valid_hashes = _valid_token_hashes(config)
  if not valid_hashes:
    raise ApiOperationError("operation_auth_not_configured", "API operation auth is not configured")
  if not _constant_time_in(token_hash, valid_hashes):
    raise ApiOperationError("operation_auth_denied", "Bearer token is not authorized")

  secret = _resolve_operation_hmac_secret(config)
  if not secret:
    raise ApiOperationError("operation_auth_not_configured", "API operation HMAC secret is not configured")

  scope_id = str(getattr(owner, "cfg_instance_id", "") or "redmesh").strip() or "redmesh"
  actor_digest = _hmac_sha256(secret, f"token:{token}")[:32]
  actor_id = f"token:{actor_digest}"
  return {
    "tenant_id": scope_id,
    "scope_id": scope_id,
    "scope_hash": _hmac_sha256(secret, f"scope:{scope_id}"),
    "actor_id": actor_id,
    "actor_hash": _hmac_sha256(secret, f"actor:{actor_id}"),
    "auth_source": "redmesh_api_operations",
    "hmac_secret": secret,
    "config": config,
  }


class ApiOperationRepository:
  """Repository for RedMesh API operation rows stored in CStore."""

  def __init__(self, owner):
    self.owner = owner

  @property
  def operations_hkey(self):
    return f"{getattr(self.owner, 'cfg_instance_id', 'redmesh')}:api_operations"

  @property
  def idempotency_hkey(self):
    return f"{getattr(self.owner, 'cfg_instance_id', 'redmesh')}:api_operations:idempotency"

  def get_operation(self, operation_id: str):
    return self.owner.chainstore_hget(hkey=self.operations_hkey, key=operation_id)

  def list_operations(self):
    payload = self.owner.chainstore_hgetall(hkey=self.operations_hkey)
    return payload if isinstance(payload, dict) else {}

  def put_operation(self, operation: dict, *, expected_revision=None, context: str = "", allow_stale=False) -> dict:
    operation_id = str((operation or {}).get("operation_id") or "")
    current = self.get_operation(operation_id)
    current_revision = _safe_int((current or {}).get("revision"), 0) if isinstance(current, dict) else 0
    incoming_revision = _safe_int((operation or {}).get("revision"), 0)
    if expected_revision is None:
      expected_revision = incoming_revision

    if isinstance(current, dict) and current_revision != expected_revision:
      audit = getattr(self.owner, "_log_audit_event", None)
      if callable(audit):
        audit("api_operation_stale_write_detected", {
          "operation_id": operation_id,
          "expected_revision": expected_revision,
          "current_revision": current_revision,
          "context": context or "",
          "write_mode": "detection_only",
        })
      if not allow_stale:
        return current

    payload = dict(operation or {})
    payload["revision"] = current_revision + 1
    payload["updated_at"] = _utc_timestamp()
    self.owner.chainstore_hset(hkey=self.operations_hkey, key=operation_id, value=payload)
    return payload

  def get_idempotency(self, key: str):
    return self.owner.chainstore_hget(hkey=self.idempotency_hkey, key=key)

  def put_idempotency(self, key: str, value: dict):
    self.owner.chainstore_hset(hkey=self.idempotency_hkey, key=key, value=dict(value or {}))
    return value


def _normalize_focus_areas(value, config: dict) -> list[str]:
  if value is None:
    raw_values = []
  elif isinstance(value, (list, tuple, set)):
    raw_values = list(value)
  else:
    raw_values = [value]

  max_items = _safe_int(config.get("MAX_FOCUS_AREAS"), 8)
  max_len = _safe_int(config.get("MAX_FOCUS_AREA_LENGTH"), 80)
  normalized = []
  seen = set()
  for item in raw_values:
    text = str(item or "").strip()
    if not text:
      continue
    text = text[:max_len]
    key = text.lower().replace("-", "_").replace(" ", "_")
    if key not in ALLOWED_FOCUS_AREAS:
      raise ApiOperationError("invalid_focus_area", "focus_areas contains an unsupported value")
    if key in seen:
      continue
    seen.add(key)
    normalized.append(key)
    if len(normalized) >= max_items:
      break
  return sorted(normalized, key=lambda item: item.lower())


def _normalize_analysis_type(value: str) -> str:
  normalized = str(value or "structured_report_sections").strip().lower()
  if not normalized:
    normalized = "structured_report_sections"
  if normalized not in ALLOWED_ANALYSIS_TYPES:
    raise ApiOperationError("invalid_analysis_type", "analysis_type is not supported for async analyze operations")
  return normalized


def _redact_public_text(value: str, limit=160) -> str:
  text = str(value or "")
  text = _CID_RE.sub("[redacted-cid]", text)
  text = _URL_RE.sub("[redacted-url]", text)
  text = _TOKEN_VALUE_RE.sub("[redacted-token]", text)
  if _SENSITIVE_RE.search(text):
    text = _SENSITIVE_RE.sub("[redacted]", text)
  if len(text) > limit:
    text = text[:limit].rstrip() + "..."
  return text


def _sanitize_public_value(value, *, depth=0):
  if depth > 3:
    return None
  if isinstance(value, str):
    return _redact_public_text(value)
  if isinstance(value, bool) or value is None:
    return value
  if isinstance(value, (int, float)):
    return value
  if isinstance(value, list):
    return [
      item for item in (
        _sanitize_public_value(item, depth=depth + 1)
        for item in value[:16]
      )
      if item is not None
    ]
  if isinstance(value, dict):
    public = {}
    for key, item in value.items():
      key_text = str(key or "")
      if _SENSITIVE_RE.search(key_text) or key_text.endswith("_cid") or key_text in {"cid", "url", "details"}:
        continue
      sanitized = _sanitize_public_value(item, depth=depth + 1)
      if sanitized is not None:
        public[key_text[:64]] = sanitized
    return public
  return _redact_public_text(value)


def _canonical_fingerprint(secret: str, payload: dict) -> str:
  canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
  return _hmac_sha256(secret, canonical)


def _idempotency_hash(context: dict, idempotency_key: str) -> str:
  return _hmac_sha256(context["hmac_secret"], f"idempotency:{idempotency_key}")


def _idempotency_index_key(context: dict, operation_type: str, idempotency_key_hash: str) -> str:
  return ":".join([
    context["scope_hash"],
    context["actor_hash"],
    operation_type,
    idempotency_key_hash,
  ])


def _operation_visible_to_context(operation: dict, context: dict) -> bool:
  return (
    isinstance(operation, dict)
    and operation.get("actor_hash") == context.get("actor_hash")
    and operation.get("scope_hash") == context.get("scope_hash")
  )


def _parse_utc_timestamp(value: str):
  try:
    return datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
  except ValueError:
    return None


def _operation_expired(operation: dict) -> bool:
  expires_at = _parse_utc_timestamp((operation or {}).get("expires_at"))
  if expires_at is None:
    return False
  return datetime.now(timezone.utc) >= expires_at


def _lease_expired(operation: dict) -> bool:
  lease = (operation or {}).get("lease")
  if not isinstance(lease, dict):
    return False
  expires_at = _parse_utc_timestamp(lease.get("expires_at"))
  if expires_at is None:
    return False
  return datetime.now(timezone.utc) >= expires_at


def _expire_operation_if_needed(repo: ApiOperationRepository, operation: dict) -> dict:
  if not isinstance(operation, dict) or not _operation_expired(operation):
    return operation
  if operation.get("state") in TERMINAL_OPERATION_STATES:
    return operation
  updated = dict(operation)
  updated["state"] = STATE_EXPIRED
  updated["phase"] = "expired"
  updated["finished_at"] = updated.get("finished_at") or _utc_timestamp()
  return repo.put_operation(
    updated,
    expected_revision=operation.get("revision"),
    context="expire_api_operation",
  )


def _recover_stale_operation_if_needed(repo: ApiOperationRepository, operation: dict) -> dict:
  operation = _expire_operation_if_needed(repo, operation)
  if not isinstance(operation, dict):
    return operation
  if operation.get("operation_type") != OPERATION_TYPE_ANALYZE_JOB:
    return operation
  if not _operation_owned_by_node(repo.owner, operation):
    return operation
  if not _operation_job_visible(repo.owner, operation):
    return operation
  if operation.get("state") in TERMINAL_OPERATION_STATES:
    return operation
  if operation.get("state") not in {STATE_RUNNING, STATE_CANCEL_REQUESTED}:
    return operation
  if not _lease_expired(operation):
    return operation

  updated = dict(operation)
  now = _utc_timestamp()
  if operation.get("state") == STATE_CANCEL_REQUESTED:
    cancel = dict(updated.get("cancel") or {})
    cancel["requested"] = True
    cancel["observed_at"] = now
    cancel["side_effects"] = "unknown_after_restart"
    updated.update({
      "state": STATE_CANCELED,
      "phase": "canceled",
      "finished_at": now,
      "lease": {},
      "cancel": cancel,
    })
  elif _safe_int(operation.get("attempt"), 0) < _safe_int(operation.get("max_attempts"), 1):
    updated.update({
      "state": STATE_QUEUED,
      "phase": "recovered",
      "lease": {},
      "retryable": True,
      "recovered_at": now,
    })
  else:
    updated.update({
      "state": STATE_FAILED,
      "phase": "lease_expired",
      "finished_at": now,
      "lease": {},
      "retryable": False,
      "failure": _failure_payload(
        "operation_failed",
        "lease_expired",
        "Operation worker lease expired",
        retryable=False,
        attempt_count=operation.get("attempt"),
      ),
    })

  return repo.put_operation(
    updated,
    expected_revision=operation.get("revision"),
    context="recover_stale_api_operation",
  )


def _operation_job_visible(owner, operation: dict) -> bool:
  job_id = str((operation or {}).get("related_job_id") or "").strip()
  if not job_id:
    return False
  return isinstance(_get_job(owner, job_id), dict)


def _operation_owned_by_node(owner, operation: dict) -> bool:
  owner_node = str((operation or {}).get("owner_node") or "").strip()
  local_node = str(getattr(owner, "ee_addr", "") or "").strip()
  return not owner_node or not local_node or owner_node == local_node


def _operation_cancel_requested(operation: dict) -> bool:
  cancel = (operation or {}).get("cancel")
  return (
    (operation or {}).get("state") == STATE_CANCEL_REQUESTED
    or isinstance(cancel, dict) and bool(cancel.get("requested"))
  )


def _failure_payload(failure_class: str, phase: str, message: str, *, retryable=False, attempt_count=0):
  public_class = failure_class if failure_class in {
    "job_changed",
    "job_has_no_report_data",
    "job_not_found",
    "llm_disabled",
    "llm_config_error",
    "result_persist_failed",
    "structured_llm_failed",
    "unsupported_operation_type",
    "worker_start_failed",
  } else "operation_failed"
  public_message = message if isinstance(message, str) and len(message) <= 240 else public_class
  if public_class == "operation_failed":
    public_message = "Operation failed"
  return {
    "failure_class": str(public_class or "operation_failed"),
    "phase": str(phase or "failed"),
    "short_message": _redact_public_text(public_message or public_class or "Operation failed"),
    "retryable": bool(retryable),
    "attempt_count": _safe_int(attempt_count, 0),
  }


def _worker_thread_alive(owner) -> bool:
  worker = getattr(owner, "_api_operation_worker_thread", None)
  return bool(worker and worker.is_alive())


def _operation_lease_valid(operation: dict, lease_token: str) -> bool:
  lease = (operation or {}).get("lease")
  return isinstance(lease, dict) and hmac.compare_digest(
    str(lease.get("token") or ""),
    str(lease_token or ""),
  )


def _result_handle(owner, operation_id: str, job_id: str, pass_nr) -> str:
  secret = _resolve_operation_hmac_secret(get_api_operations_config(owner))
  if not secret:
    return f"{RESULT_HANDLE_PREFIX}{uuid.uuid4().hex}"
  digest = _hmac_sha256(secret, f"{operation_id}:{job_id}:{pass_nr}")[:32]
  return f"{RESULT_HANDLE_PREFIX}{digest}"


def _write_job_record(owner, job_id: str, job_specs: dict, *, expected_revision=None, context=""):
  writer = getattr(type(owner), "_write_job_record", None)
  if callable(writer):
    return writer(owner, job_id, job_specs, expected_revision=expected_revision, context=context)
  writer = getattr(owner, "_write_job_record", None)
  if callable(writer):
    return writer(job_id, job_specs, expected_revision=expected_revision, context=context)
  owner.chainstore_hset(hkey=getattr(owner, "cfg_instance_id", "redmesh"), key=job_id, value=job_specs)
  return job_specs


def _job_revision(job_specs: dict) -> int:
  return _safe_int((job_specs or {}).get("job_revision"), 0)


def _latest_pass_matches(job_specs: dict, *, expected_revision: int, report_cid: str, pass_nr) -> bool:
  if not isinstance(job_specs, dict):
    return False
  if _job_revision(job_specs) != _safe_int(expected_revision, 0):
    return False
  pass_reports = job_specs.get("pass_reports") or []
  if not pass_reports:
    return False
  latest_ref = pass_reports[-1]
  if latest_ref.get("report_cid") != report_cid:
    return False
  if pass_nr is not None and latest_ref.get("pass_nr") != pass_nr:
    return False
  return True


def _operation_target_matches_job(operation: dict, job_specs: dict) -> bool:
  pass_reports = (job_specs or {}).get("pass_reports") or []
  latest_ref = pass_reports[-1] if pass_reports else {}
  target_revision = _safe_int((operation or {}).get("target_job_revision_at_create"), 0)
  return _latest_pass_matches(
    job_specs,
    expected_revision=target_revision,
    report_cid=(operation or {}).get("target_report_cid_at_create"),
    pass_nr=(operation or {}).get("target_pass_nr_at_create"),
  ) and bool(latest_ref)


def _fail_job_changed(owner, operation_id: str, lease_token: str, *, artifact_written=False):
  failure = _failure_payload(
    "job_changed",
    "job_changed",
    "Job pass report changed before the operation could update it",
    retryable=False,
  )
  if artifact_written:
    failure["side_effects"] = "result_artifact_written"
  return _finish_worker_operation(
    owner,
    operation_id,
    lease_token,
    state=STATE_FAILED,
    phase="job_changed",
    failure=failure,
    retryable=False,
  )


def _emit_operation_timeline(owner, job_specs: dict, event_type: str, message: str, *, pass_nr=None):
  emitter = getattr(owner, "_emit_timeline_event", None)
  if not callable(emitter):
    return
  meta = {}
  if pass_nr is not None:
    meta["pass_nr"] = pass_nr
  emitter(job_specs, event_type, message, actor_type="user", meta=meta)


def _load_worker_operation(repo: ApiOperationRepository, operation_id: str, lease_token: str):
  operation = repo.get_operation(operation_id)
  operation = _expire_operation_if_needed(repo, operation)
  if not isinstance(operation, dict):
    return None
  if operation.get("state") in TERMINAL_OPERATION_STATES:
    return None
  if not _operation_lease_valid(operation, lease_token):
    return None
  return operation


def _update_worker_operation(owner, operation_id: str, lease_token: str, updates: dict, *, context: str):
  with _operation_store_lock(owner):
    repo = ApiOperationRepository(owner)
    operation = _load_worker_operation(repo, operation_id, lease_token)
    if not isinstance(operation, dict) or operation.get("state") in TERMINAL_OPERATION_STATES:
      return operation

    updated = dict(operation)
    updated.update(dict(updates or {}))
    lease = dict(updated.get("lease") or {})
    lease["heartbeat_at"] = _utc_timestamp()
    lease["expires_at"] = _utc_timestamp_after(context_config(owner).get("LEASE_SECONDS"))
    updated["lease"] = lease
    return repo.put_operation(
      updated,
      expected_revision=operation.get("revision"),
      context=context,
    )


def context_config(owner) -> dict:
  return get_api_operations_config(owner)


def _finish_worker_operation(
    owner,
    operation_id: str,
    lease_token: str,
    *,
    state: str,
    phase: str,
    failure=None,
    result_public=None,
    retryable=False,
    cancel_side_effects=None,
):
  with _operation_store_lock(owner):
    repo = ApiOperationRepository(owner)
    operation = _load_worker_operation(repo, operation_id, lease_token)
    if not isinstance(operation, dict):
      return None
    if operation.get("state") in TERMINAL_OPERATION_STATES:
      return operation

    updated = dict(operation)
    updated["state"] = state
    updated["phase"] = phase
    updated["finished_at"] = _utc_timestamp()
    updated["retryable"] = bool(retryable)
    if failure:
      updated["failure"] = failure
    if result_public:
      updated["result_public"] = result_public
    if cancel_side_effects is not None:
      cancel = dict(updated.get("cancel") or {})
      cancel["requested"] = True
      cancel["observed_at"] = updated["finished_at"]
      cancel["side_effects"] = cancel_side_effects
      updated["cancel"] = cancel
    return repo.put_operation(
      updated,
      expected_revision=operation.get("revision"),
      context=f"finish_{phase}",
    )


def _fail_worker_operation(owner, operation_id: str, lease_token: str, phase: str, exc, *, retryable=False):
  failure = _failure_payload(
    exc.__class__.__name__ if not isinstance(exc, ApiOperationError) else exc.code,
    phase,
    getattr(exc, "message", str(exc)),
    retryable=retryable or bool(getattr(exc, "retryable", False)),
    attempt_count=0,
  )
  return _finish_worker_operation(
    owner,
    operation_id,
    lease_token,
    state=STATE_FAILED,
    phase=phase,
    failure=failure,
    retryable=failure["retryable"],
  )


def _cancel_worker_operation(owner, operation_id: str, lease_token: str, *, side_effects: str):
  return _finish_worker_operation(
    owner,
    operation_id,
    lease_token,
    state=STATE_CANCELED,
    phase="canceled",
    cancel_side_effects=side_effects,
  )


def _public_failure(failure):
  if not isinstance(failure, dict):
    return None
  return {
    key: _sanitize_public_value(failure[key])
    for key in PUBLIC_FAILURE_KEYS
    if key in failure
  }


def _public_result(result):
  if not isinstance(result, dict):
    return None
  public = {}
  if result.get("kind"):
    public["kind"] = result.get("kind")
  if result.get("handle"):
    public["handle"] = result.get("handle")
  if result.get("pass_nr") is not None:
    public["pass_nr"] = result.get("pass_nr")
  summary = result.get("summary")
  if isinstance(summary, dict):
    public["summary"] = _sanitize_public_value(summary)
  return public or None


def public_operation_view(operation: dict) -> dict:
  if not isinstance(operation, dict):
    return {}
  view = {
    "operation_id": operation.get("operation_id"),
    "operation_type": operation.get("operation_type"),
    "state": operation.get("state"),
    "phase": operation.get("phase"),
    "related_job_id": operation.get("related_job_id"),
    "created_at": operation.get("created_at"),
    "updated_at": operation.get("updated_at"),
    "started_at": operation.get("started_at"),
    "finished_at": operation.get("finished_at"),
    "expires_at": operation.get("expires_at"),
    "retryable": bool(operation.get("retryable", False)),
    "attempt": operation.get("attempt"),
    "max_attempts": operation.get("max_attempts"),
  }
  poll_after_ms = operation.get("poll_after_ms")
  if poll_after_ms is not None:
    view["poll_after_ms"] = poll_after_ms
  failure = _public_failure(operation.get("failure"))
  if failure:
    view["failure"] = failure
  result = _public_result(operation.get("result_public"))
  if result:
    view["result"] = result
  cancel = operation.get("cancel")
  if isinstance(cancel, dict):
    view["cancel"] = {
      key: cancel.get(key)
      for key in ("requested", "requested_at", "observed_at", "side_effects")
      if key in cancel
    }
  return {key: value for key, value in view.items() if value is not None}


def _active_operations(repo: ApiOperationRepository):
  return [
    operation for operation in (repo.list_operations() or {}).values()
    if (
      isinstance(operation, dict)
      and operation.get("state") in ACTIVE_OPERATION_STATES
      and not _operation_expired(operation)
      and not _lease_expired(operation)
    )
  ]


def _check_backpressure(repo: ApiOperationRepository, context: dict, job_id: str):
  config = context["config"]
  active = _active_operations(repo)
  if len(active) >= _safe_int(config.get("MAX_QUEUE_GLOBAL"), 32):
    raise ApiOperationError("operation_backpressure", "API operation queue is full", retryable=True)

  actor_count = sum(1 for operation in active if operation.get("actor_hash") == context["actor_hash"])
  if actor_count >= _safe_int(config.get("MAX_QUEUE_PER_ACTOR"), 8):
    raise ApiOperationError("operation_backpressure", "API operation actor quota is full", retryable=True)

  job_count = sum(
    1 for operation in active
    if operation.get("operation_type") == OPERATION_TYPE_ANALYZE_JOB
    and operation.get("related_job_id") == job_id
  )
  if job_count >= _safe_int(config.get("MAX_QUEUE_PER_JOB"), 1):
    raise ApiOperationError("operation_backpressure", "API operation job quota is full", retryable=True)


def _get_job(owner, job_id: str):
  getter = getattr(owner, "_get_job_from_cstore", None)
  if callable(getter):
    return getter(job_id)
  return owner.chainstore_hget(hkey=getattr(owner, "cfg_instance_id", "redmesh"), key=job_id)


def _has_report_data(job_specs: dict) -> bool:
  pass_reports = job_specs.get("pass_reports")
  if isinstance(pass_reports, list) and pass_reports:
    return True
  workers = job_specs.get("workers") or {}
  if not isinstance(workers, dict):
    return False
  for worker in workers.values():
    if not isinstance(worker, dict):
      continue
    if worker.get("report_cid") or worker.get("result"):
      return True
  return False


def _validate_analyze_job_admission(owner, job_id: str) -> dict:
  llm_cfg = get_llm_agent_config(owner)
  if not llm_cfg.get("ENABLED"):
    raise ApiOperationError("llm_disabled", "LLM Agent API is not enabled")
  if not getattr(owner, "cfg_llm_agent_api_port", None):
    raise ApiOperationError("llm_config_error", "LLM Agent API port not configured")

  job_specs = _get_job(owner, job_id)
  if not isinstance(job_specs, dict):
    raise ApiOperationError("job_not_found", "Job not found")

  workers = job_specs.get("workers") or {}
  if not isinstance(workers, dict) or not workers:
    raise ApiOperationError("job_has_no_workers", "No workers found for this job")
  if not all(isinstance(worker, dict) and worker.get("finished") for worker in workers.values()):
    raise ApiOperationError("job_not_complete", "Job not yet complete")
  if not _has_report_data(job_specs):
    raise ApiOperationError("job_has_no_report_data", "No report data available for this job")
  return job_specs


def _aggregate_node_reports(owner, job_specs: dict, node_reports: dict) -> dict:
  worker_cls = None
  try:
    strategy = get_scan_strategy(coerce_scan_type((job_specs or {}).get("scan_type")))
    worker_cls = getattr(strategy, "worker_cls", None)
  except Exception:
    worker_cls = None

  if worker_cls is not None:
    try:
      return owner._get_aggregated_report(node_reports, worker_cls=worker_cls)
    except TypeError:
      pass
  return owner._get_aggregated_report(node_reports)


def create_analyze_job_operation(
    owner,
    token: str,
    job_id: str,
    analysis_type: str = "",
    focus_areas=None,
    idempotency_key: str = "",
):
  try:
    context = derive_operation_auth_context(owner, token)
    config = context["config"]
    job_id = str(job_id or "").strip()
    if not job_id:
      raise ApiOperationError("invalid_job_id", "job_id is required")

    idempotency_key = str(idempotency_key or "").strip()
    max_key_len = _safe_int(config.get("MAX_IDEMPOTENCY_KEY_LENGTH"), 128)
    if idempotency_key and len(idempotency_key) > max_key_len:
      raise ApiOperationError("invalid_idempotency_key", "Idempotency key is too long")

    normalized_focus = _normalize_focus_areas(focus_areas, config)
    normalized_analysis = _normalize_analysis_type(analysis_type)
    job_specs = _validate_analyze_job_admission(owner, job_id)
    request_public = {
      "analysis_type": normalized_analysis,
      "focus_areas": normalized_focus,
    }
    request_fingerprint = _canonical_fingerprint(context["hmac_secret"], {
      "operation_type": OPERATION_TYPE_ANALYZE_JOB,
      "job_id": job_id,
      "analysis_type": normalized_analysis,
      "focus_areas": normalized_focus,
      "scope_hash": context["scope_hash"],
      "actor_hash": context["actor_hash"],
    })

    with _operation_store_lock(owner):
      repo = ApiOperationRepository(owner)
      idempotency_key_hash = ""
      index_key = ""
      if idempotency_key:
        idempotency_key_hash = _idempotency_hash(context, idempotency_key)
        index_key = _idempotency_index_key(context, OPERATION_TYPE_ANALYZE_JOB, idempotency_key_hash)
        existing = repo.get_idempotency(index_key)
        if isinstance(existing, dict):
          if existing.get("request_fingerprint") != request_fingerprint:
            return _error("idempotency_conflict", "Idempotency key was used with a different request")
          operation = repo.get_operation(existing.get("operation_id", ""))
          operation = _expire_operation_if_needed(repo, operation)
          if _operation_visible_to_context(operation, context):
            return {
              "status": "accepted",
              "idempotent_replay": True,
              "operation": public_operation_view(operation),
            }

      _check_backpressure(repo, context, job_id)

      pass_reports = job_specs.get("pass_reports") or []
      latest_ref = pass_reports[-1] if pass_reports else {}
      now = _utc_timestamp()
      operation_id = f"op_{uuid.uuid4().hex}"
      operation = {
        "schema_version": OPERATION_SCHEMA_VERSION,
        "operation_id": operation_id,
        "operation_type": OPERATION_TYPE_ANALYZE_JOB,
        "owner_node": str(getattr(owner, "ee_addr", "") or ""),
        "state": STATE_QUEUED,
        "phase": "queued",
        "actor": {
          "actor_id": context["actor_id"],
          "auth_source": context["auth_source"],
        },
        "scope": {
          "tenant_id": context["tenant_id"],
          "scope_id": context["scope_id"],
        },
        "actor_hash": context["actor_hash"],
        "scope_hash": context["scope_hash"],
        "related_job_id": job_id,
        "target_job_revision_at_create": _safe_int(job_specs.get("job_revision"), 0),
        "target_pass_nr_at_create": latest_ref.get("pass_nr"),
        "target_report_cid_at_create": latest_ref.get("report_cid"),
        "request_public": request_public,
        "request_fingerprint": request_fingerprint,
        "idempotency_key_hash": idempotency_key_hash,
        "attempt": 0,
        "max_attempts": max(_safe_int(getattr(owner, "cfg_llm_api_retries", 1), 1), 1),
        "revision": 0,
        "lease": {},
        "retryable": False,
        "result_public": None,
        "cancel": {},
        "created_at": now,
        "updated_at": now,
        "expires_at": _utc_timestamp_after(config.get("OPERATION_TTL_SECONDS")),
        "poll_after_ms": _safe_int(config.get("POLL_AFTER_MS"), 1000),
      }
      operation = repo.put_operation(operation, expected_revision=0, context="create_analyze_job_operation")
      if index_key:
        repo.put_idempotency(index_key, {
          "operation_id": operation_id,
          "request_fingerprint": request_fingerprint,
          "created_at": now,
          "expires_at": operation.get("expires_at"),
        })

    return {
      "status": "accepted",
      "operation": public_operation_view(operation),
    }
  except ApiOperationError as exc:
    extra = {}
    if exc.code == "operation_backpressure":
      extra["retry_after_ms"] = _safe_int(get_api_operations_config(owner).get("POLL_AFTER_MS"), 1000)
    return _error(exc.code, exc.message, retryable=exc.retryable, **extra)


def _claim_next_api_operation_locked(owner):
  repo = ApiOperationRepository(owner)
  lease_seconds = context_config(owner).get("LEASE_SECONDS")
  now = _utc_timestamp()

  operations = sorted(
    (repo.list_operations() or {}).values(),
    key=lambda item: str((item or {}).get("created_at") or ""),
  )
  for operation in operations:
    operation = _recover_stale_operation_if_needed(repo, operation)
    if not isinstance(operation, dict):
      continue
    if operation.get("state") != STATE_QUEUED:
      continue
    if operation.get("operation_type") != OPERATION_TYPE_ANALYZE_JOB:
      continue
    if not _operation_owned_by_node(owner, operation):
      continue
    if not _operation_job_visible(owner, operation):
      continue

    lease_token = uuid.uuid4().hex
    claimed = dict(operation)
    attempt = _safe_int(claimed.get("attempt"), 0) + 1
    claimed.update({
      "state": STATE_RUNNING,
      "phase": "claimed",
      "started_at": claimed.get("started_at") or now,
      "attempt": attempt,
      "lease": {
        "owner_node": str(getattr(owner, "ee_addr", "") or ""),
        "token": lease_token,
        "acquired_at": now,
        "heartbeat_at": now,
        "expires_at": _utc_timestamp_after(lease_seconds),
      },
    })
    updated = repo.put_operation(
      claimed,
      expected_revision=operation.get("revision"),
      context="claim_api_operation",
    )
    if _operation_lease_valid(updated, lease_token) and updated.get("state") == STATE_RUNNING:
      return updated["operation_id"], lease_token
  return None


def maybe_start_api_operation_worker(owner) -> bool:
  """Start one bounded background API operation worker if queued work exists."""
  config = get_api_operations_config(owner)
  if not config.get("ENABLED"):
    return False

  with _operation_store_lock(owner):
    if _worker_thread_alive(owner):
      return False
    claimed = _claim_next_api_operation_locked(owner)
    if not claimed:
      return False
    operation_id, lease_token = claimed
    thread = threading.Thread(
      target=execute_api_operation_worker,
      args=(owner, operation_id, lease_token),
      name=f"redmesh-api-operation-{operation_id[:12]}",
      daemon=True,
    )
    setattr(owner, "_api_operation_worker_thread", thread)

  try:
    thread.start()
  except Exception as exc:
    _safe_log(owner, f"Failed to start API operation worker for {operation_id}: {exc}", color="y")
    _fail_worker_operation(owner, operation_id, lease_token, "worker_start_failed", exc, retryable=True)
    return False
  return True


def _execute_analyze_job_operation(owner, operation: dict, lease_token: str):
  operation_id = operation["operation_id"]
  job_id = str(operation.get("related_job_id") or "")

  _update_worker_operation(
    owner,
    operation_id,
    lease_token,
    {"phase": "collecting_reports"},
    context="api_operation_collecting_reports",
  )

  job_specs = _validate_analyze_job_admission(owner, job_id)
  if not _operation_target_matches_job(operation, job_specs):
    _fail_job_changed(owner, operation_id, lease_token)
    return

  workers = job_specs.get("workers") or {}
  node_reports = owner._collect_node_reports(workers)
  aggregated_report = _aggregate_node_reports(owner, job_specs, node_reports) if node_reports else {}
  if not aggregated_report:
    raise ApiOperationError("job_has_no_report_data", "No report data available for this job")

  job_config = owner._get_job_config(job_specs)
  _risk_result, flat_findings = owner._compute_risk_and_findings(aggregated_report)

  _update_worker_operation(
    owner,
    operation_id,
    lease_token,
    {"phase": "llm_pending"},
    context="api_operation_llm_pending",
  )

  llm_report_sections = owner._run_structured_report_sections(
    job_id=job_id,
    findings=flat_findings,
    aggregated_report=aggregated_report,
    engagement=job_config.get("engagement") if isinstance(job_config, dict) else None,
  )
  structured_failed = bool(getattr(owner, "_last_structured_llm_failed", False))
  if llm_report_sections is None:
    raise ApiOperationError(
      "structured_llm_failed",
      "Structured LLM report generation failed",
      retryable=True,
    )

  with _operation_store_lock(owner):
    repo = ApiOperationRepository(owner)
    current = _load_worker_operation(repo, operation_id, lease_token)
    if not isinstance(current, dict):
      return
    if _operation_cancel_requested(current):
      _cancel_worker_operation(owner, operation_id, lease_token, side_effects="none")
      return

  _update_worker_operation(
    owner,
    operation_id,
    lease_token,
    {"phase": "persisting_result"},
    context="api_operation_persisting_result",
  )

  target_report_cid = operation.get("target_report_cid_at_create")
  target_pass_nr = operation.get("target_pass_nr_at_create")
  with _job_operation_lock(owner, job_id):
    latest_job_specs = _get_job(owner, job_id)
    if not isinstance(latest_job_specs, dict):
      raise ApiOperationError("job_not_found", "Job not found")
    latest_job_specs = copy.deepcopy(latest_job_specs)
    expected_job_revision = _safe_int(operation.get("target_job_revision_at_create"), 0)

    pass_reports = latest_job_specs.get("pass_reports") or []
    if not pass_reports:
      raise ApiOperationError("job_has_no_report_data", "No pass report data available for this job")
    latest_ref = pass_reports[-1]
    current_report_cid = latest_ref.get("report_cid")
    current_pass_nr = latest_ref.get("pass_nr", latest_job_specs.get("job_pass", 1))
    if target_report_cid and current_report_cid != target_report_cid:
      _fail_job_changed(owner, operation_id, lease_token)
      return
    if target_pass_nr is not None and current_pass_nr != target_pass_nr:
      _fail_job_changed(owner, operation_id, lease_token)
      return

    pass_data = owner.r1fs.get_json(current_report_cid)
    if not isinstance(pass_data, dict):
      raise ApiOperationError("job_has_no_report_data", "Pass report data is not available")

    fresh_job_specs = _get_job(owner, job_id)
    if not _latest_pass_matches(
        fresh_job_specs,
        expected_revision=expected_job_revision,
        report_cid=current_report_cid,
        pass_nr=current_pass_nr,
    ):
      _fail_job_changed(owner, operation_id, lease_token)
      return

    pass_data = dict(pass_data)
    pass_data["llm_report_sections"] = llm_report_sections
    pass_data["llm_operation_id"] = operation_id
    if structured_failed:
      pass_data["llm_failed"] = True
    else:
      pass_data.pop("llm_failed", None)
      llm_text, summary_text = render_legacy_llm_fields(llm_report_sections)
      if llm_text:
        pass_data["llm_analysis"] = llm_text
      if summary_text:
        pass_data["quick_summary"] = summary_text

    with _operation_store_lock(owner):
      repo = ApiOperationRepository(owner)
      current = _load_worker_operation(repo, operation_id, lease_token)
      if not isinstance(current, dict):
        return
      if _operation_cancel_requested(current):
        _cancel_worker_operation(owner, operation_id, lease_token, side_effects="none")
        return

    updated_cid = owner.r1fs.add_json(pass_data, show_logs=False)
    if not updated_cid:
      raise ApiOperationError("result_persist_failed", "Failed to persist updated pass report", retryable=True)

    fresh_job_specs = _get_job(owner, job_id)
    if not _latest_pass_matches(
        fresh_job_specs,
        expected_revision=expected_job_revision,
        report_cid=current_report_cid,
        pass_nr=current_pass_nr,
    ):
      _fail_job_changed(owner, operation_id, lease_token, artifact_written=True)
      return

    with _operation_store_lock(owner):
      repo = ApiOperationRepository(owner)
      current = _load_worker_operation(repo, operation_id, lease_token)
      if not isinstance(current, dict):
        return
      if _operation_cancel_requested(current):
        _cancel_worker_operation(owner, operation_id, lease_token, side_effects="result_artifact_written")
        return

    latest_job_specs = copy.deepcopy(fresh_job_specs)
    pass_reports = latest_job_specs.get("pass_reports") or []
    latest_ref = pass_reports[-1]
    latest_ref["report_cid"] = updated_cid
    _emit_operation_timeline(
      owner,
      latest_job_specs,
      "llm_analysis",
      "Manual structured LLM report sections completed",
      pass_nr=current_pass_nr,
    )
    _write_job_record(
      owner,
      job_id,
      latest_job_specs,
      expected_revision=_safe_int(latest_job_specs.get("job_revision"), 0),
      context="manual_llm_operation_update",
    )

  handle = _result_handle(owner, operation_id, job_id, current_pass_nr)
  result_public = {
    "kind": "redmesh_analyze_job_operation_result",
    "handle": handle,
    "pass_nr": current_pass_nr,
    "summary": {
      "llm_report_sections_available": True,
      "llm_failed": structured_failed,
      "job_updated": True,
    },
  }
  _finish_worker_operation(
    owner,
    operation_id,
    lease_token,
    state=STATE_SUCCEEDED,
    phase="succeeded",
    result_public=result_public,
  )


def execute_api_operation_worker(owner, operation_id: str, lease_token: str):
  try:
    repo = ApiOperationRepository(owner)
    with _operation_store_lock(owner):
      operation = _load_worker_operation(repo, operation_id, lease_token)
    if not isinstance(operation, dict) or operation.get("state") in TERMINAL_OPERATION_STATES:
      return
    if operation.get("operation_type") != OPERATION_TYPE_ANALYZE_JOB:
      raise ApiOperationError("unsupported_operation_type", "Operation type is not supported")
    _execute_analyze_job_operation(owner, operation, lease_token)
  except Exception as exc:
    _safe_log(owner, f"API operation {operation_id} failed: {exc}", color="y")
    _fail_worker_operation(owner, operation_id, lease_token, "failed", exc, retryable=getattr(exc, "retryable", False))
  finally:
    with _operation_store_lock(owner):
      worker = getattr(owner, "_api_operation_worker_thread", None)
      if worker is threading.current_thread():
        setattr(owner, "_api_operation_worker_thread", None)


def get_api_operation_status(owner, token: str, operation_id: str):
  try:
    context = derive_operation_auth_context(owner, token)
  except ApiOperationError as exc:
    return _error(exc.code, exc.message, retryable=exc.retryable)

  with _operation_store_lock(owner):
    repo = ApiOperationRepository(owner)
    operation = repo.get_operation(str(operation_id or "").strip())
    operation = _expire_operation_if_needed(repo, operation)
    if not _operation_visible_to_context(operation, context):
      return _not_found()
    if not _operation_job_visible(owner, operation):
      return _not_found()
    return {"operation": public_operation_view(operation)}


def cancel_api_operation(owner, token: str, operation_id: str, reason: str = ""):
  try:
    context = derive_operation_auth_context(owner, token)
  except ApiOperationError as exc:
    return _error(exc.code, exc.message, retryable=exc.retryable)

  with _operation_store_lock(owner):
    repo = ApiOperationRepository(owner)
    operation = repo.get_operation(str(operation_id or "").strip())
    operation = _expire_operation_if_needed(repo, operation)
    if not _operation_visible_to_context(operation, context):
      return _not_found()
    if not _operation_job_visible(owner, operation):
      return _not_found()

    state = operation.get("state")
    if state in TERMINAL_OPERATION_STATES:
      return {"operation": public_operation_view(operation)}

    cancel = dict(operation.get("cancel") or {})
    cancel.update({
      "requested": True,
      "requested_at": cancel.get("requested_at") or _utc_timestamp(),
      "reason": _redact_public_text(str(reason or ""), limit=160),
      "side_effects": cancel.get("side_effects") or "none",
    })
    operation["cancel"] = cancel
    if state == STATE_QUEUED:
      operation["state"] = STATE_CANCELED
      operation["phase"] = "canceled"
      operation["finished_at"] = _utc_timestamp()
      cancel["observed_at"] = operation["finished_at"]
    else:
      operation["state"] = STATE_CANCEL_REQUESTED
      operation["phase"] = "cancel_requested"
    updated = repo.put_operation(operation, expected_revision=operation.get("revision"), context="cancel_api_operation")
    return {"operation": public_operation_view(updated)}


def get_api_operation_result(owner, token: str, result_handle: str):
  try:
    context = derive_operation_auth_context(owner, token)
  except ApiOperationError as exc:
    return _error(exc.code, exc.message, retryable=exc.retryable)

  handle = str(result_handle or "").strip()
  if _CID_RE.search(handle):
    return _error("invalid_result_handle", "Operation result handles are opaque; raw CIDs are not accepted")
  if not handle.startswith(RESULT_HANDLE_PREFIX):
    return _not_found()

  with _operation_store_lock(owner):
    repo = ApiOperationRepository(owner)
    for operation in (repo.list_operations() or {}).values():
      operation = _expire_operation_if_needed(repo, operation)
      if not _operation_visible_to_context(operation, context):
        continue
      if not _operation_job_visible(owner, operation):
        continue
      if operation.get("state") != STATE_SUCCEEDED:
        continue
      result = _public_result(operation.get("result_public"))
      if isinstance(result, dict) and result.get("handle") == handle:
        return {
          "operation_id": operation.get("operation_id"),
          "result": result,
        }
  return _not_found()
