"""Fail-closed Model Testing launch gate."""

import uuid
from math import isfinite

from ..constants import JOB_STATUS_RUNNING, RUN_MODE_SINGLEPASS
from ..models import CStoreJobRunning
from ..repositories import ArtifactRepository, JobStateRepository
from ..services.config import get_model_testing_config
from .artifacts import MODEL_TEST_JOB_CONFIG_SCHEMA
from .constants import MODEL_TEST_JOB_TYPE
from .node_selection import select_model_test_execution_node
from .security import (
  validate_provider_config_shape,
  validate_model_provider_credentials,
  validate_provider_url,
)


TEST_SET_ID = "cbrn_safety_v1"

def _validation_error(message: str, *, error_class=None):
  result = {"error": "validation_error", "message": message}
  if error_class:
    result["error_class"] = error_class
  return result


def _bounded_text(value, field_path, *, minimum=1, maximum=120):
  text = str(value or "").strip()
  if len(text) < minimum:
    return None, _validation_error(f"{field_path} is required")
  if len(text) > maximum:
    return None, _validation_error(f"{field_path} is too long")
  return text, None


def _bounded_int(value, field_path, *, default, minimum=1, maximum=None):
  if value is None:
    value = default
  if isinstance(value, bool):
    return None, _validation_error(f"{field_path} must be an integer")
  if isinstance(value, str):
    value = value.strip()
  if isinstance(value, float) and not value.is_integer():
    return None, _validation_error(f"{field_path} must be an integer")
  try:
    parsed = int(value)
  except (TypeError, ValueError):
    return None, _validation_error(f"{field_path} must be an integer")
  if parsed < minimum:
    return None, _validation_error(f"{field_path} must be greater than or equal to {minimum}")
  if maximum is not None and parsed > maximum:
    return None, _validation_error(f"{field_path} must be less than or equal to {maximum}")
  return parsed, None


def _bounded_float(value, field_path, *, default, minimum=0.0, maximum=None):
  if value is None:
    value = default
  if isinstance(value, bool):
    return None, _validation_error(f"{field_path} must be numeric")
  try:
    parsed = float(value)
  except (TypeError, ValueError):
    return None, _validation_error(f"{field_path} must be numeric")
  if not isfinite(parsed):
    return None, _validation_error(f"{field_path} must be finite")
  if parsed < minimum:
    return None, _validation_error(f"{field_path} must be greater than or equal to {minimum}")
  if maximum is not None and parsed > maximum:
    return None, _validation_error(f"{field_path} must be less than or equal to {maximum}")
  return parsed, None


def _normalize_limits(limits, cfg):
  if limits is None:
    limits = {}
  if not isinstance(limits, dict):
    return None, _validation_error("limits must be a JSON object")
  caps = cfg["LIMITS"]
  normalized = {}
  int_fields = (
    ("max_cases", "MAX_CASES", 1),
    ("tested_max_tokens", "TESTED_MAX_TOKENS", 1),
    ("evaluator_max_tokens", "EVALUATOR_MAX_TOKENS", 1),
    ("per_call_timeout_seconds", "PER_CALL_TIMEOUT_SECONDS", 1),
    ("total_timeout_seconds", "TOTAL_TIMEOUT_SECONDS", 1),
    ("max_retries", "MAX_RETRIES", 0),
  )
  for public_key, cap_key, minimum in int_fields:
    parsed, err = _bounded_int(
      limits.get(public_key),
      f"limits.{public_key}",
      default=caps[cap_key],
      minimum=minimum,
      maximum=caps[cap_key],
    )
    if err:
      return None, err
    normalized[public_key] = parsed
  parsed_temperature, err = _bounded_float(
    limits.get("temperature"),
    "limits.temperature",
    default=caps["TEMPERATURE"],
    minimum=0.0,
    maximum=caps["TEMPERATURE"],
  )
  if err:
    return None, err
  normalized["temperature"] = parsed_temperature
  return normalized, None


def _validate_provider(role, provider, secret_payload, *, created_by_id, use_default_evaluator_model=False):
  if not isinstance(provider, dict):
    return None, _validation_error(f"{role} must be a JSON object")
  err = validate_provider_config_shape(provider, role=role)
  if err:
    return None, err
  adapter = str(provider.get("adapter") or "").strip()
  if adapter not in {"openai_compatible", "mock"}:
    return None, _validation_error(f"{role}.adapter must be openai_compatible")
  if adapter == "mock":
    return None, _validation_error(f"{role}.adapter mock is test-only")
  provider_label, err = _bounded_text(provider.get("provider_label"), f"{role}.provider_label")
  if err:
    return None, err
  model, err = _bounded_text(provider.get("model"), f"{role}.model", maximum=200)
  if err:
    return None, err
  url_info, err = validate_provider_url(provider.get("base_url"))
  if err:
    return None, err
  credential_info, err = validate_model_provider_credentials(
    provider,
    secret_payload,
    role=role,
    created_by_id=created_by_id,
    use_default_evaluator_model=use_default_evaluator_model,
  )
  if err:
    return None, err
  return {
    "adapter": adapter,
    "provider_label": provider_label,
    "safe_hostname": url_info["safe_hostname"],
    "model": model,
    "credential_ref_present": credential_info["credential_ref_present"],
  }, None


def _raw_evidence_requested(raw_evidence):
  return isinstance(raw_evidence, dict) and bool(raw_evidence.get("enabled"))


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


def _job_repo(owner):
  getter = getattr(type(owner), "_get_job_state_repository", None)
  if callable(getter):
    return getter(owner)
  return JobStateRepository(owner)


def _write_job_record(owner, job_id, job_specs):
  writer = getattr(type(owner), "_write_job_record", None)
  if callable(writer):
    return writer(owner, job_id, job_specs, context="launch_model_test")
  return _job_repo(owner).put_job(job_id, job_specs)


def _new_job_id(owner):
  maker = getattr(owner, "uuid", None)
  if callable(maker):
    return maker(8)
  return str(uuid.uuid4())[:8]


def _now(owner):
  clock = getattr(owner, "time", None)
  if callable(clock):
    return clock()
  return 0


def _emit_timeline(owner, job_specs, event_type, label, *, actor="", actor_type="system"):
  emitter = getattr(owner, "_emit_timeline_event", None)
  if callable(emitter):
    emitter(job_specs, event_type, label, actor=actor, actor_type=actor_type)
    return
  job_specs.setdefault("timeline", []).append({
    "type": event_type,
    "label": label,
    "actor": actor,
    "actor_type": actor_type,
    "date": _now(owner),
  })


def _target_label(model_config):
  label = str((model_config or {}).get("provider_label") or "").strip()
  model = str((model_config or {}).get("model") or "").strip()
  if label and model:
    return f"{label} / {model}"
  return label or model or "Model Test"


def launch_model_test(
  owner,
  *,
  task_name="",
  task_description="",
  selected_peers=None,
  created_by_name="",
  created_by_id="",
  authorized=False,
  test_set_id=TEST_SET_ID,
  tested_model=None,
  tested_model_secret_payload=None,
  use_default_evaluator_model=False,
  evaluator_model=None,
  evaluator_model_secret_payload=None,
  limits=None,
  raw_evidence=None,
):
  """Validate Model Testing launch input and fail closed until execution lands."""
  cfg = get_model_testing_config(owner)
  if not cfg["ENABLED"]:
    return {
      "error": "model_testing_disabled",
      "message": "Model Testing is disabled by policy.",
      "disabled_reason": "disabled_by_policy",
    }
  if authorized is not True:
    return _validation_error("authorized must be true")
  task_name, err = _bounded_text(task_name, "task_name")
  if err:
    return err
  task_description, err = _bounded_text(task_description, "task_description", maximum=2000)
  if err:
    return err
  created_by_name, err = _bounded_text(created_by_name, "created_by_name")
  if err:
    return err
  created_by_id, err = _bounded_text(created_by_id, "created_by_id")
  if err:
    return err
  if test_set_id != TEST_SET_ID:
    return _validation_error("test_set_id must be cbrn_safety_v1")
  if _raw_evidence_requested(raw_evidence) and not cfg["RAW_EVIDENCE_ENABLED"]:
    return _validation_error(
      "raw_evidence is disabled by policy",
      error_class="raw_evidence_disabled",
    )
  normalized_limits, err = _normalize_limits(limits, cfg)
  if err:
    return err

  tested_model_config, err = _validate_provider(
    "tested_model",
    tested_model,
    tested_model_secret_payload,
    created_by_id=created_by_id,
  )
  if err:
    return err

  evaluator_model_config = None
  if use_default_evaluator_model:
    if not cfg.get("DEFAULT_EVALUATOR_MODEL"):
      return _validation_error("default evaluator model is unavailable")
  else:
    evaluator_model_config, err = _validate_provider(
      "evaluator_model",
      evaluator_model,
      evaluator_model_secret_payload,
      created_by_id=created_by_id,
    )
  if err:
    return err

  node_selection, err = select_model_test_execution_node(owner, selected_peers)
  if err:
    return err

  job_id = _new_job_id(owner)
  sanitized_config = {
    "schema_version": MODEL_TEST_JOB_CONFIG_SCHEMA,
    "job_type": MODEL_TEST_JOB_TYPE,
    "scan_type": MODEL_TEST_JOB_TYPE,
    "job_id": job_id,
    "task_name": task_name,
    "task_description": task_description,
    "created_by_name": created_by_name,
    "created_by_id": created_by_id,
    "test_set_id": test_set_id,
    "tested_model": tested_model_config,
    "evaluator_model": evaluator_model_config or {"source": "default_config"},
    "limits": normalized_limits,
    "raw_evidence": {
      "requested": _raw_evidence_requested(raw_evidence),
    },
    "selected_peers": node_selection["requested_peer_ids"],
    "model_test_node_selection": node_selection,
  }

  job_config_cid = _artifact_repo(owner).put_job_config(sanitized_config, show_logs=False)
  if not job_config_cid:
    return {
      "error": "storage_error",
      "message": "Failed to store model test job config in R1FS",
    }

  created_at = _now(owner)
  execution_node = node_selection["selected_execution_node"]
  workers = {
    execution_node: {
      "worker_type": MODEL_TEST_JOB_TYPE,
      "model_test_worker_status": "queued",
      "start_port": 0,
      "end_port": 0,
      "finished": False,
      "canceled": False,
      "result": None,
      "assignment_revision": 1,
      "assigned_at": created_at,
    }
  }
  job_specs = CStoreJobRunning(
    job_id=job_id,
    job_status=JOB_STATUS_RUNNING,
    job_pass=1,
    run_mode=RUN_MODE_SINGLEPASS,
    launcher=getattr(owner, "ee_addr", ""),
    launcher_alias=getattr(owner, "ee_id", ""),
    target=_target_label(tested_model_config),
    scan_type=MODEL_TEST_JOB_TYPE,
    target_url="",
    task_name=task_name,
    start_port=0,
    end_port=0,
    date_created=created_at,
    job_config_cid=job_config_cid,
    workers=workers,
    timeline=[],
    pass_reports=[],
    next_pass_at=None,
    risk_score=0,
    job_type=MODEL_TEST_JOB_TYPE,
    model_test_summary={"overall_status": "queued"},
    model_test_node_selection=node_selection,
  ).to_dict()
  _emit_timeline(
    owner,
    job_specs,
    "created",
    f"Model Test Job created by {created_by_name}",
    actor=created_by_name,
    actor_type="user",
  )
  _emit_timeline(
    owner,
    job_specs,
    "model_test_node_selected",
    "Model Test Execution Node selected",
    actor=getattr(owner, "ee_id", ""),
    actor_type="node",
  )
  persisted_specs = _write_job_record(owner, job_id, job_specs)
  return {
    "job_specs": persisted_specs,
    "worker": execution_node,
    "job_type": MODEL_TEST_JOB_TYPE,
    "job_config": sanitized_config,
    "model_test_node_selection": node_selection,
  }
