from copy import deepcopy
import os

from ..models import JobConfig
from ..repositories import ArtifactRepository
from ..graybox.models.target_config import (
  collect_target_config_secret_refs,
  resolve_target_config_secret_refs,
)
from .config import get_attestation_config


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


class R1fsSecretStore:
  """Secret-store adapter backed by a protected R1FS JSON object."""

  def __init__(self, owner):
    self.owner = owner
    self.last_key_metadata = {}

  @staticmethod
  def _normalize_secret_key(value):
    if not isinstance(value, str):
      return ""
    value = value.strip()
    return value if len(value) >= 8 else ""

  @staticmethod
  def _truthy(value) -> bool:
    if isinstance(value, bool):
      return value
    if isinstance(value, str):
      return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False

  def _unsafe_fallback_allowed(self) -> bool:
    return any([
      self._truthy(os.environ.get("REDMESH_ALLOW_UNSAFE_SECRET_STORE_FALLBACK", "")),
      self._truthy(getattr(self.owner, "cfg_allow_unsafe_secret_store_fallback", False)),
      self._truthy(getattr(self.owner, "cfg_redmesh_allow_unsafe_secret_store_fallback", False)),
    ])

  def _dedicated_secret_store_key(self):
    env_key = self._normalize_secret_key(os.environ.get("REDMESH_SECRET_STORE_KEY", ""))
    if env_key:
      return env_key, {
        "key_id": os.environ.get("REDMESH_SECRET_STORE_KEY_ID", "env:REDMESH_SECRET_STORE_KEY"),
        "key_version": os.environ.get(
          "REDMESH_SECRET_STORE_KEY_VERSION",
          str(getattr(self.owner, "cfg_redmesh_secret_store_key_version", "") or "v1"),
        ),
        "key_source": "environment",
        "unsafe_fallback": False,
      }
    cfg_key = self._normalize_secret_key(getattr(self.owner, "cfg_redmesh_secret_store_key", ""))
    if cfg_key:
      return cfg_key, {
        "key_id": str(getattr(
          self.owner,
          "cfg_redmesh_secret_store_key_id",
          "config:cfg_redmesh_secret_store_key",
        ) or "config:cfg_redmesh_secret_store_key"),
        "key_version": str(getattr(
          self.owner,
          "cfg_redmesh_secret_store_key_version",
          "v1",
        ) or "v1"),
        "key_source": "config",
        "unsafe_fallback": False,
      }
    return "", {}

  def _unsafe_fallback_secret_store_key(self):
    if not self._unsafe_fallback_allowed():
      return "", {}
    comms_key = self._normalize_secret_key(getattr(self.owner, "cfg_comms_host_key", ""))
    if comms_key:
      return comms_key, {
        "key_id": "unsafe-dev:cfg_comms_host_key",
        "key_version": "unsafe-dev",
        "key_source": "unsafe_dev_fallback_comms",
        "unsafe_fallback": True,
      }
    attestation_key = self._normalize_secret_key(
      get_attestation_config(self.owner)["PRIVATE_KEY"]
    )
    if attestation_key:
      return attestation_key, {
        "key_id": "unsafe-dev:attestation_private_key",
        "key_version": "unsafe-dev",
        "key_source": "unsafe_dev_fallback_attestation",
        "unsafe_fallback": True,
      }
    return "", {}

  def _resolve_secret_store_key(self):
    key, metadata = self._dedicated_secret_store_key()
    if key:
      return key, metadata
    return self._unsafe_fallback_secret_store_key()

  def _get_secret_store_key(self) -> str:
    key, _metadata = self._resolve_secret_store_key()
    return key

  def save_graybox_credentials(self, job_id: str, payload: dict) -> str:
    secret_key, key_metadata = self._resolve_secret_store_key()
    self.last_key_metadata = dict(key_metadata or {})
    if not secret_key:
      self.owner.P(
        "No dedicated RedMesh secret-store key is configured. "
        "Set REDMESH_SECRET_STORE_KEY or cfg_redmesh_secret_store_key. "
        "Development fallback requires REDMESH_ALLOW_UNSAFE_SECRET_STORE_FALLBACK=1.",
        color='r',
      )
      return ""
    secret_doc = {
      "kind": "redmesh_graybox_credentials",
      "job_id": job_id,
      "storage_mode": "encrypted_r1fs_json_v1",
      "key_id": key_metadata.get("key_id", ""),
      "key_version": key_metadata.get("key_version", ""),
      "key_source": key_metadata.get("key_source", ""),
      "unsafe_key_fallback": bool(key_metadata.get("unsafe_fallback", False)),
      "payload": payload,
    }
    return _artifact_repo(self.owner).put_json(secret_doc, show_logs=False, secret=secret_key)

  def load_graybox_credentials(self, secret_ref: str, *, expected_job_id: str = "") -> dict | None:
    if not secret_ref:
      return None
    repo = _artifact_repo(self.owner)
    secret_key, key_metadata = self._resolve_secret_store_key()
    self.last_key_metadata = dict(key_metadata or {})
    if not secret_key:
      self.owner.P("No dedicated RedMesh secret-store key is configured; cannot resolve graybox secret_ref", color='r')
      return None
    secret_doc = repo.get_json(secret_ref, secret=secret_key)
    if not isinstance(secret_doc, dict):
      self.owner.P(f"Failed to fetch graybox secret payload from R1FS (CID: {secret_ref})", color='r')
      return None
    if secret_doc.get("kind") != "redmesh_graybox_credentials":
      self.owner.P(f"Invalid graybox secret kind for ref {secret_ref}", color='r')
      return None
    if secret_doc.get("storage_mode") != "encrypted_r1fs_json_v1":
      self.owner.P(f"Invalid graybox secret storage mode for ref {secret_ref}", color='r')
      return None
    if expected_job_id and secret_doc.get("job_id") != expected_job_id:
      self.owner.P(
        f"Graybox secret ref {secret_ref} belongs to job_id={secret_doc.get('job_id')}, expected {expected_job_id}",
        color='r',
      )
      return None
    payload = secret_doc.get("payload")
    if not isinstance(payload, dict):
      self.owner.P(f"Invalid graybox secret payload for ref {secret_ref}", color='r')
      return None
    return payload

  def delete_secret(self, secret_ref: str) -> bool:
    if not secret_ref:
      return True
    try:
      return bool(_artifact_repo(self.owner).delete(secret_ref, show_logs=False, raise_on_error=False))
    except Exception as exc:
      self.owner.P(f"Failed to delete graybox secret ref {secret_ref}: {exc}", color='y')
      return False


def _blank_graybox_secret_fields(config_dict: dict) -> dict:
  sanitized = dict(config_dict)
  sanitized["official_username"] = ""
  sanitized["official_password"] = ""
  sanitized["regular_username"] = ""
  sanitized["regular_password"] = ""
  # OWASP API Top 10 (Subphase 1.5 commit #8) — header-auth secrets.
  sanitized["bearer_token"] = ""
  sanitized["api_key"] = ""
  sanitized["bearer_refresh_token"] = ""
  sanitized["regular_bearer_token"] = ""
  sanitized["regular_api_key"] = ""
  sanitized["regular_bearer_refresh_token"] = ""
  sanitized.pop("target_config_secrets", None)
  sanitized.pop("weak_candidates", None)
  return sanitized


def _coerce_job_config_dict(config_dict: dict) -> dict:
  raw = deepcopy(config_dict or {})
  raw.setdefault("target", raw.get("target_url", ""))
  raw.setdefault("start_port", 0)
  raw.setdefault("end_port", 0)
  return JobConfig.from_dict(raw).to_dict()


def build_graybox_secret_payload(
  *,
  official_username="",
  official_password="",
  regular_username="",
  regular_password="",
  weak_candidates=None,
  bearer_token="",
  api_key="",
  bearer_refresh_token="",
  regular_bearer_token="",
  regular_api_key="",
  regular_bearer_refresh_token="",
  target_config_secrets=None,
):
  return {
    "official_username": official_username or "",
    "official_password": official_password or "",
    "regular_username": regular_username or "",
    "regular_password": regular_password or "",
    "weak_candidates": list(weak_candidates) if isinstance(weak_candidates, list) else weak_candidates,
    # OWASP API Top 10 (Subphase 1.5 commit #8): API-native auth secrets.
    "bearer_token": bearer_token or "",
    "api_key": api_key or "",
    "bearer_refresh_token": bearer_refresh_token or "",
    "regular_bearer_token": regular_bearer_token or "",
    "regular_api_key": regular_api_key or "",
    "regular_bearer_refresh_token": regular_bearer_refresh_token or "",
    "target_config_secrets": dict(target_config_secrets) if isinstance(target_config_secrets, dict) else {},
  }


def persist_job_config_with_secrets(
  owner,
  *,
  job_id: str,
  config_dict: dict,
):
  """
  Persist durable job config with secrets split into a separate secret object.

  Returns
  -------
  tuple[dict, str]
    Persisted config dict and resulting job_config_cid.
  """
  raw_config = deepcopy(config_dict or {})
  target_config_secrets = raw_config.get("target_config_secrets")
  persisted_config = _coerce_job_config_dict(raw_config)
  scan_type = persisted_config.get("scan_type", "network")
  if scan_type == "webapp":
    payload = build_graybox_secret_payload(
      official_username=persisted_config.get("official_username", ""),
      official_password=persisted_config.get("official_password", ""),
      regular_username=persisted_config.get("regular_username", ""),
      regular_password=persisted_config.get("regular_password", ""),
      weak_candidates=persisted_config.get("weak_candidates"),
      bearer_token=persisted_config.get("bearer_token", ""),
      api_key=persisted_config.get("api_key", ""),
      bearer_refresh_token=persisted_config.get("bearer_refresh_token", ""),
      regular_bearer_token=persisted_config.get("regular_bearer_token", ""),
      regular_api_key=persisted_config.get("regular_api_key", ""),
      regular_bearer_refresh_token=persisted_config.get("regular_bearer_refresh_token", ""),
      target_config_secrets=target_config_secrets,
    )
    has_secret_payload = any([
      payload["official_username"],
      payload["official_password"],
      payload["regular_username"],
      payload["regular_password"],
      payload["weak_candidates"],
      payload["bearer_token"],
      payload["api_key"],
      payload["bearer_refresh_token"],
      payload["regular_bearer_token"],
      payload["regular_api_key"],
      payload["regular_bearer_refresh_token"],
      payload["target_config_secrets"],
    ])
    if has_secret_payload:
      store = R1fsSecretStore(owner)
      secret_ref = store.save_graybox_credentials(job_id, payload)
      if not secret_ref:
        owner.P("Failed to persist graybox secret payload in R1FS — aborting launch", color='r')
        return persisted_config, ""
      persisted_config["secret_ref"] = secret_ref
      key_metadata = store.last_key_metadata if isinstance(store.last_key_metadata, dict) else {}
      persisted_config["secret_store_key_id"] = key_metadata.get("key_id", "")
      persisted_config["secret_store_key_version"] = key_metadata.get("key_version", "")
      persisted_config["secret_store_key_source"] = key_metadata.get("key_source", "")
      persisted_config["secret_store_unsafe_fallback"] = bool(key_metadata.get("unsafe_fallback", False))
      persisted_config["has_regular_credentials"] = bool(payload["regular_username"] or payload["regular_password"])
      persisted_config["has_weak_candidates"] = bool(payload["weak_candidates"])
      # OWASP API Top 10 (Subphase 1.5 commit #8) — non-secret capability flags.
      persisted_config["has_bearer_token"] = bool(payload["bearer_token"])
      persisted_config["has_api_key"] = bool(payload["api_key"])
      persisted_config["has_bearer_refresh_token"] = bool(payload["bearer_refresh_token"])
      persisted_config["has_regular_bearer_token"] = bool(payload["regular_bearer_token"])
      persisted_config["has_regular_api_key"] = bool(payload["regular_api_key"])
      persisted_config["has_regular_bearer_refresh_token"] = bool(payload["regular_bearer_refresh_token"])
      persisted_config = _blank_graybox_secret_fields(persisted_config)

  job_config_cid = _artifact_repo(owner).put_job_config(persisted_config, show_logs=False)
  return persisted_config, job_config_cid


def resolve_job_config_secrets(
  owner,
  config_dict: dict,
  include_secret_metadata: bool = True,
  expected_job_id: str = "",
) -> dict:
  """
  Resolve secret_ref into runtime-only inline credentials for worker execution.

  Backward compatibility:
  - configs without secret_ref are returned unchanged
  - legacy inline secrets remain supported
  """
  raw = deepcopy(config_dict or {})
  expected_job_id = expected_job_id or raw.get("job_id", "")
  resolved = _coerce_job_config_dict(raw)
  secret_ref = resolved.get("secret_ref")
  if not secret_ref:
    return resolved

  payload = R1fsSecretStore(owner).load_graybox_credentials(
    secret_ref, expected_job_id=expected_job_id,
  )
  if not payload:
    raise ValueError(f"Failed to resolve graybox secret_ref for job_id={expected_job_id or '<unknown>'}")

  resolved.update({
    "official_username": payload.get("official_username", ""),
    "official_password": payload.get("official_password", ""),
    "regular_username": payload.get("regular_username", ""),
    "regular_password": payload.get("regular_password", ""),
    "weak_candidates": payload.get("weak_candidates"),
    # OWASP API Top 10 (Subphase 1.5 commit #8) — API-native auth secrets.
    "bearer_token": payload.get("bearer_token", ""),
    "api_key": payload.get("api_key", ""),
    "bearer_refresh_token": payload.get("bearer_refresh_token", ""),
    "regular_bearer_token": payload.get("regular_bearer_token", ""),
    "regular_api_key": payload.get("regular_api_key", ""),
    "regular_bearer_refresh_token": payload.get("regular_bearer_refresh_token", ""),
  })
  target_config_secrets = payload.get("target_config_secrets") or {}
  target_config_secret_refs = []
  if isinstance(resolved.get("target_config"), dict):
    target_config_secret_refs = collect_target_config_secret_refs(
      resolved["target_config"]
    )
  if target_config_secret_refs and not target_config_secrets:
    raise ValueError(
      "Failed to resolve target_config secret_ref value(s) "
      f"{', '.join(target_config_secret_refs)} for "
      f"job_id={expected_job_id or '<unknown>'}"
    )
  if target_config_secret_refs:
    try:
      resolved["target_config"] = resolve_target_config_secret_refs(
        resolved["target_config"],
        target_config_secrets,
      )
    except KeyError as exc:
      raise ValueError(
        f"Failed to resolve target_config secret_ref {exc.args[0]!r} "
        f"for job_id={expected_job_id or '<unknown>'}"
      ) from exc
  if not include_secret_metadata:
    resolved.pop("secret_ref", None)
  return resolved


def collect_secret_refs_from_job_config(job_config: dict) -> list[str]:
  secret_ref = (job_config or {}).get("secret_ref")
  if isinstance(secret_ref, str) and secret_ref:
    return [secret_ref]
  return []
