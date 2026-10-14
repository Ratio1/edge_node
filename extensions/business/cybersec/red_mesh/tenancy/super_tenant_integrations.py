"""RM-139 phase 2: the Super-Tenant Admin's override of one deployment integration.

One record per integration (kind `super_tenant_integration`, `ids = [integration_id]`) holding three
independent overrides: `config`, a partial block of the Deeploy keys that wins field by field;
`sharing_groups` (MISP only), tenant id -> MISP sharing group id; and `auto_export` (MISP only).
Clearing one never clears another. Vocabulary, the stored-record validator, the change rules and
the DTO; no storage I/O (contract: `multi-tenant-workspaces.md` §Deployment integrations).

Two rules keep a deployment credential with the deployment's own destination:

- An override never names an environment variable (`TOKEN_ENV`, `PASSWORD_ENV`): an STA-chosen name
  would read any secret in the node's environment.
- An override that sets a destination must carry that integration's credentials (400 otherwise),
  and config resolution never merges a Deeploy credential under an overridden destination, so a
  row that lost its secrets (a restored backup) is "not configured", never a leak.

Credential values stay in the record (I-052) and never leave it through the DTO.
"""
from datetime import datetime, timezone
import json

from .engagement_drafts import valid_tenant_id
from .identity import canonical_account_id
from .integrations import CREDENTIAL_KEYS, normalize_integration_config, valid_integration_id

KIND = "super_tenant_integration"
DESTINATION_KEYS = {
  "misp": ("MISP_URL",),
  "opencti": ("URL",),
  "taxii": ("SERVER_URL",),
  # wazuh_jwt posts USERNAME/PASSWORD to LOGIN_URL, so it is a destination for credentials too.
  "wazuh": ("HTTP_URL", "LOGIN_URL"),
}
ENV_KEYS = ("TOKEN_ENV", "PASSWORD_ENV")
# `AUTO_EXPORT` is the record's own `auto_export` field: one source for the toggle, not two.
_REFUSED_CONFIG_KEYS = (*ENV_KEYS, "AUTO_EXPORT")
_MISP_ONLY = ("sharing_groups", "auto_export")
_CHANGE_KEYS = ("config", "clear_secrets", "sharing_groups", "auto_export")
_MAX_SHARING_GROUPS = 1000


class OverrideInvalid(ValueError):
  """A change the STA cannot make; `code` is the public 400 error."""

  def __init__(self, code="invalid_request"):
    super().__init__(code)
    self.code = code


def empty_override(integration_id):
  return {"integration_id": integration_id, "config": None, "sharing_groups": None,
          "auto_export": None, "updated_by": None, "updated_at": None}


def destination_overridden(integration_id, config):
  return isinstance(config, dict) and any(config.get(key) for key in DESTINATION_KEYS[integration_id])


def has_credentials(integration_id, config):
  return isinstance(config, dict) and any(config.get(key) for key in CREDENTIAL_KEYS[integration_id])


def _override_config(integration_id, config):
  config = normalize_integration_config(integration_id, config)
  # An empty override is a clear, which is `None`.
  if not config or any(key in config for key in _REFUSED_CONFIG_KEYS):
    raise OverrideInvalid()
  # An empty secret is neither a value nor a clear (`clear_secrets` is): refused, not guessed.
  if any(key in config and not config[key] for key in CREDENTIAL_KEYS[integration_id]):
    raise OverrideInvalid()
  return config


def _sharing_groups(value):
  if (not isinstance(value, dict) or not value or len(value) > _MAX_SHARING_GROUPS
      or any(not valid_tenant_id(key) or type(group) is not int or group < 1 for key, group in value.items())):
    raise OverrideInvalid()
  return dict(value)


def apply_changes(row, integration_id, changes):
  """The row with `changes` applied and the names of what changed, `config.<KEY>` per key.

  `changes` holds any of: `config` (a partial block, or None to fall back to the Deeploy config; a
  credential it omits keeps the stored one), `clear_secrets` (credential keys to drop),
  `sharing_groups` (a map, or None) and `auto_export` (a bool, or None). Raises OverrideInvalid.
  """
  if (not isinstance(changes, dict) or not changes or any(key not in _CHANGE_KEYS for key in changes)
      or (integration_id != "misp" and any(key in changes for key in _MISP_ONLY))):
    raise OverrideInvalid()
  try:
    credentials = CREDENTIAL_KEYS[integration_id]
    stored = row["config"] or {}
    config = stored
    if "config" in changes:
      if changes["config"] is None:
        config = {}
      else:
        config = _override_config(integration_id, changes["config"])
        config.update({key: stored[key] for key in credentials if key in stored and key not in config})
    if "clear_secrets" in changes:
      cleared = changes["clear_secrets"]
      if (not isinstance(cleared, list) or not cleared
          or any(not isinstance(key, str) or key not in credentials for key in cleared)):
        raise OverrideInvalid()
      config = {key: value for key, value in config.items() if key not in cleared}
  except (ValueError, TypeError, RecursionError) as exc:
    raise exc if isinstance(exc, OverrideInvalid) else OverrideInvalid() from None
  if destination_overridden(integration_id, config) and not has_credentials(integration_id, config):
    raise OverrideInvalid("credentials_required")
  merged = dict(row, config=config or None)
  if "sharing_groups" in changes:
    merged["sharing_groups"] = None if changes["sharing_groups"] is None else _sharing_groups(changes["sharing_groups"])
  if "auto_export" in changes:
    if changes["auto_export"] is not None and type(changes["auto_export"]) is not bool:
      raise OverrideInvalid()
    merged["auto_export"] = changes["auto_export"]
  before, after = row["config"] or {}, merged["config"] or {}
  changed = sorted({f"config.{key}" for key in set(before) | set(after) if before.get(key) != after.get(key)}
                   | {key for key in _MISP_ONLY if row[key] != merged[key]})
  return merged, changed


def is_empty(row):
  return all(row[key] is None for key in ("config", "sharing_groups", "auto_export"))


def integration_dto(integration_id, row, deployment, effective, deployment_configured, configured):
  """What the STA reads. `deployment` and `effective` are the resolved blocks without and with the
  override; a credential reads as `{set, source}`, never as its value."""
  config = (row or {}).get("config") or {}
  if config:
    source = "override"
  elif deployment_configured:
    source = "deployment_config"
  else:
    source = "none"
  credentials = CREDENTIAL_KEYS[integration_id]
  fields, secrets = {}, {}
  for key, value in effective.items():
    if key == "AUTO_EXPORT":
      continue
    origin = "override" if key in config else "deployment_config"
    if key in credentials:
      secrets[key] = {"set": bool(value), "source": origin if value else "none"}
    else:
      fields[key] = {"value": value, "source": origin}
  dto = {"integrationId": integration_id, "enabled": bool(effective.get("ENABLED")),
         "configured": bool(configured), "source": source, "fields": fields, "secrets": secrets,
         "updatedBy": (row or {}).get("updated_by"), "updatedAt": (row or {}).get("updated_at")}
  if integration_id == "misp":
    auto_export = (row or {}).get("auto_export")
    dto["autoExport"] = {"value": bool(effective["AUTO_EXPORT"]),
                         "source": "deployment_config" if auto_export is None else "override"}
    dto["sharingGroups"] = dict((row or {}).get("sharing_groups") or {})
  return dto


def withheld_for_backup(row):
  """The stored row without its credential values: no plaintext credential leaves the node
  (owner, 2026-09-29). A restored override needs its secrets re-entered."""
  if isinstance(row, (str, bytes, bytearray)):
    try:
      row = json.loads(row)
    except (ValueError, UnicodeError, RecursionError):
      return None
  if not isinstance(row, dict) or not isinstance(row.get("config"), dict):
    return row
  credentials = CREDENTIAL_KEYS.get(row.get("integration_id"), ())
  return {**row, "config": {key: value for key, value in row["config"].items() if key not in credentials}}


def validate_super_tenant_integration(row, ids):
  """Refuse a stored override the operations could not have written. A row without the credentials
  its destination needs is kept (a restored backup): resolution treats it as not configured."""
  if len(ids) != 1 or not valid_integration_id(ids[0]) or row.get("integration_id") != ids[0]:
    raise ValueError("Invalid super-tenant integration record")
  integration_id = ids[0]
  config = row.get("config")
  if config is not None:
    if not isinstance(config, dict) or not config:
      raise ValueError("Invalid super-tenant integration record")
    _override_config(integration_id, config)
  if integration_id != "misp" and any(row.get(key) is not None for key in _MISP_ONLY):
    raise ValueError("Invalid super-tenant integration record")
  if row.get("sharing_groups") is not None:
    _sharing_groups(row["sharing_groups"])
  if row.get("auto_export") is not None and type(row["auto_export"]) is not bool:
    raise ValueError("Invalid super-tenant integration record")
  if is_empty({key: row.get(key) for key in ("config", "sharing_groups", "auto_export")}):
    raise ValueError("Invalid super-tenant integration record")
  updated_by = row.get("updated_by")
  if not updated_by or canonical_account_id(updated_by) != updated_by:
    raise ValueError("Invalid super-tenant integration record")
  updated_at = datetime.fromisoformat(row.get("updated_at"))
  if updated_at.tzinfo != timezone.utc:
    raise ValueError("Invalid super-tenant integration record")
  return row
