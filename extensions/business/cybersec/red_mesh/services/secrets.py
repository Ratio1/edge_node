from copy import deepcopy


class R1fsSecretStore:
  """Minimal secret-store adapter backed by a separate R1FS object."""

  def __init__(self, owner):
    self.owner = owner

  def save_graybox_credentials(self, job_id: str, payload: dict) -> str:
    secret_doc = {
      "kind": "redmesh_graybox_credentials",
      "job_id": job_id,
      "payload": payload,
    }
    return self.owner.r1fs.add_json(secret_doc, show_logs=False)

  def load_graybox_credentials(self, secret_ref: str) -> dict | None:
    if not secret_ref:
      return None
    secret_doc = self.owner.r1fs.get_json(secret_ref)
    if not isinstance(secret_doc, dict):
      self.owner.P(f"Failed to fetch graybox secret payload from R1FS (CID: {secret_ref})", color='r')
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
      return bool(self.owner.r1fs.delete_file(secret_ref, show_logs=False, raise_on_error=False))
    except Exception as exc:
      self.owner.P(f"Failed to delete graybox secret ref {secret_ref}: {exc}", color='y')
      return False


def _blank_graybox_secret_fields(config_dict: dict) -> dict:
  sanitized = dict(config_dict)
  sanitized["official_username"] = ""
  sanitized["official_password"] = ""
  sanitized["regular_username"] = ""
  sanitized["regular_password"] = ""
  sanitized.pop("weak_candidates", None)
  return sanitized


def build_graybox_secret_payload(
  *,
  official_username="",
  official_password="",
  regular_username="",
  regular_password="",
  weak_candidates=None,
):
  return {
    "official_username": official_username or "",
    "official_password": official_password or "",
    "regular_username": regular_username or "",
    "regular_password": regular_password or "",
    "weak_candidates": list(weak_candidates) if isinstance(weak_candidates, list) else weak_candidates,
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
  persisted_config = deepcopy(config_dict)
  scan_type = persisted_config.get("scan_type", "network")
  if scan_type == "webapp":
    payload = build_graybox_secret_payload(
      official_username=persisted_config.get("official_username", ""),
      official_password=persisted_config.get("official_password", ""),
      regular_username=persisted_config.get("regular_username", ""),
      regular_password=persisted_config.get("regular_password", ""),
      weak_candidates=persisted_config.get("weak_candidates"),
    )
    has_secret_payload = any([
      payload["official_username"],
      payload["official_password"],
      payload["regular_username"],
      payload["regular_password"],
      payload["weak_candidates"],
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
      persisted_config = _blank_graybox_secret_fields(persisted_config)

  job_config_cid = owner.r1fs.add_json(persisted_config, show_logs=False)
  return persisted_config, job_config_cid


def resolve_job_config_secrets(owner, config_dict: dict, include_secret_metadata: bool = True) -> dict:
  """
  Resolve secret_ref into runtime-only inline credentials for worker execution.

  Backward compatibility:
  - configs without secret_ref are returned unchanged
  - legacy inline secrets remain supported
  """
  resolved = deepcopy(config_dict or {})
  secret_ref = resolved.get("secret_ref")
  if not secret_ref:
    return resolved

  payload = R1fsSecretStore(owner).load_graybox_credentials(secret_ref)
  if not payload:
    return resolved

  resolved.update({
    "official_username": payload.get("official_username", ""),
    "official_password": payload.get("official_password", ""),
    "regular_username": payload.get("regular_username", ""),
    "regular_password": payload.get("regular_password", ""),
    "weak_candidates": payload.get("weak_candidates"),
  })
  if not include_secret_metadata:
    resolved.pop("secret_ref", None)
  return resolved


def collect_secret_refs_from_job_config(job_config: dict) -> list[str]:
  secret_ref = (job_config or {}).get("secret_ref")
  if isinstance(secret_ref, str) and secret_ref:
    return [secret_ref]
  return []
