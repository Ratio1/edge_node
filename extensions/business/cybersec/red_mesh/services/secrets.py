from copy import deepcopy
import os

from ..models import JobConfig
from ..repositories import ArtifactRepository
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

  @staticmethod
  def _normalize_secret_key(value):
    if not isinstance(value, str):
      return ""
    value = value.strip()
    return value if len(value) >= 8 else ""

  def _get_secret_store_key(self) -> str:
    candidates = [
      os.environ.get("REDMESH_SECRET_STORE_KEY", ""),
      getattr(self.owner, "cfg_redmesh_secret_store_key", ""),
      getattr(self.owner, "cfg_comms_host_key", ""),
      get_attestation_config(self.owner)["PRIVATE_KEY"],
    ]
    for candidate in candidates:
      key = self._normalize_secret_key(candidate)
      if key:
        return key
    return ""

  def save_graybox_credentials(self, job_id: str, payload: dict) -> str:
    secret_key = self._get_secret_store_key()
    if not secret_key:
      self.owner.P(
        "No strong RedMesh secret-store key is configured. "
        "Graybox launch credentials cannot be persisted safely.",
        color='r',
      )
      return ""
    secret_doc = {
      "kind": "redmesh_graybox_credentials",
      "job_id": job_id,
      "storage_mode": "encrypted_r1fs_json_v1",
      "payload": payload,
    }
    return _artifact_repo(self.owner).put_json(secret_doc, show_logs=False, secret=secret_key)

  def load_graybox_credentials(self, secret_ref: str, *, expected_job_id: str = "") -> dict | None:
    if not secret_ref:
      return None
    repo = _artifact_repo(self.owner)
    secret_key = self._get_secret_store_key()
    if not secret_key:
      self.owner.P("No RedMesh secret-store key is configured; cannot resolve graybox secret_ref", color='r')
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
  persisted_config = _coerce_job_config_dict(config_dict)
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
    ])
    if has_secret_payload:
      store = R1fsSecretStore(owner)
      secret_ref = store.save_graybox_credentials(job_id, payload)
      if not secret_ref:
        owner.P("Failed to persist graybox secret payload in R1FS — aborting launch", color='r')
        return persisted_config, ""
      persisted_config["secret_ref"] = secret_ref
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


def resolve_job_config_secrets(owner, config_dict: dict, include_secret_metadata: bool = True) -> dict:
  """
  Resolve secret_ref into runtime-only inline credentials for worker execution.

  Backward compatibility:
  - configs without secret_ref are returned unchanged
  - legacy inline secrets remain supported
  """
  resolved = _coerce_job_config_dict(config_dict)
  secret_ref = resolved.get("secret_ref")
  if not secret_ref:
    return resolved

  expected_job_id = resolved.get("job_id", "")
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
  if not include_secret_metadata:
    resolved.pop("secret_ref", None)
  return resolved


def collect_secret_refs_from_job_config(job_config: dict) -> list[str]:
  secret_ref = (job_config or {}).get("secret_ref")
  if isinstance(secret_ref, str) and secret_ref:
    return [secret_ref]
  return []
