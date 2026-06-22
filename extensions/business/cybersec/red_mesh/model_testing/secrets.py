"""Runtime-only provider credential handling for Model Testing."""

from __future__ import annotations

from copy import deepcopy

from ..services.secrets import R1fsSecretStore


MODEL_TEST_PROVIDER_SECRET_REF = "model_provider_secret_ref"
_ARCHIVE_STRIP_KEYS = {
  MODEL_TEST_PROVIDER_SECRET_REF,
  "model_provider_secret_store_key_id",
  "model_provider_secret_store_key_version",
  "model_provider_secret_store_key_source",
  "model_provider_secret_store_unsafe_fallback",
}


def _api_key_from_payload(secret_payload):
  if not isinstance(secret_payload, dict):
    return ""
  return str(secret_payload.get("api_key") or "").strip()


def _runtime_provider(provider, secret_payload):
  provider = dict(provider or {})
  runtime = {
    "adapter": provider.get("adapter") or "openai_compatible",
    "provider_label": provider.get("provider_label") or "",
    "base_url": provider.get("base_url") or "",
    "model": provider.get("model") or "",
  }
  api_key = _api_key_from_payload(secret_payload)
  if api_key:
    runtime["api_key"] = api_key
  credential_ref = str(provider.get("credential_ref") or "").strip()
  if credential_ref:
    runtime["credential_ref"] = credential_ref
  return runtime


def attach_model_test_provider_secret(
    owner,
    *,
    job_id: str,
    sanitized_config: dict,
    tested_model: dict,
    tested_model_secret_payload: dict | None,
    evaluator_model: dict | None,
    evaluator_model_secret_payload: dict | None,
):
  """Persist provider runtime material separately and return persisted config."""
  persisted = deepcopy(sanitized_config or {})
  payload = {
    "tested_model": _runtime_provider(tested_model, tested_model_secret_payload),
    "evaluator_model": _runtime_provider(evaluator_model, evaluator_model_secret_payload)
    if evaluator_model
    else {},
  }
  store = R1fsSecretStore(owner)
  ref = store.save_model_test_provider_credentials(job_id, payload)
  if not ref:
    return None, ""
  key_metadata = store.last_key_metadata if isinstance(store.last_key_metadata, dict) else {}
  persisted[MODEL_TEST_PROVIDER_SECRET_REF] = ref
  persisted["model_provider_secret_store_key_id"] = key_metadata.get("key_id", "")
  persisted["model_provider_secret_store_key_version"] = key_metadata.get("key_version", "")
  persisted["model_provider_secret_store_key_source"] = key_metadata.get("key_source", "")
  persisted["model_provider_secret_store_unsafe_fallback"] = bool(key_metadata.get("unsafe_fallback", False))
  return persisted, ref


def resolve_model_test_runtime_config(owner, config_dict: dict) -> dict:
  """Resolve provider runtime material for worker execution only."""
  resolved = deepcopy(config_dict or {})
  job_id = str(resolved.get("job_id") or "")
  secret_ref = str(resolved.get(MODEL_TEST_PROVIDER_SECRET_REF) or "").strip()
  if not secret_ref:
    raise ValueError("credential_unavailable")
  payload = R1fsSecretStore(owner).load_model_test_provider_credentials(
    secret_ref,
    expected_job_id=job_id,
  )
  if not isinstance(payload, dict):
    raise ValueError("credential_unavailable")
  for role in ("tested_model", "evaluator_model"):
    runtime_provider = payload.get(role)
    if isinstance(runtime_provider, dict) and runtime_provider:
      resolved[role] = {
        **dict(resolved.get(role) or {}),
        **runtime_provider,
      }
  return resolved


def sanitize_model_test_job_config_for_archive(config_dict: dict) -> dict:
  sanitized = deepcopy(config_dict or {})
  for key in _ARCHIVE_STRIP_KEYS:
    sanitized.pop(key, None)
  for role in ("tested_model", "evaluator_model"):
    provider = sanitized.get(role)
    if not isinstance(provider, dict):
      continue
    provider.pop("base_url", None)
    provider.pop("api_key", None)
    provider.pop("credential_ref", None)
  return sanitized
