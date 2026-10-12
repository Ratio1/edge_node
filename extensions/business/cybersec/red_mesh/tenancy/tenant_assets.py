"""RM-125 phase 1: the tenant asset, a target registered before any engagement picks it.

It lives under a live tenant (`parent: {tenant_id}`) or a tenant draft (`parent: {draft_id}`) and is
re-homed to the tenant with the engagement drafts when that draft is closed. An engagement keeps its
own signed copy of each asset it picks (ADR 0003), so its target is never read at launch; only the
environment is (RM-131, below). Vocabulary,
formats, the stored-record validator, the derived status and the DTO; no storage I/O (contract:
`tenant-assets.md`). Its id (`ta_<uuid>`) is global; the parent is a field of the row. The row has no
`kind` of its own (the storage envelope's `kind` is the record kind): the DTO answers `target.kind`.

RM-131: the asset's `environment` names where the target lives. It is required on create and locked
with the target once an engagement or engagement draft names the asset. A row written before RM-131
has none, and the launch policy reads that as `prod`.
"""
from datetime import datetime

from .assets import canonical_digest, normalize_name, normalize_target, valid_digest
from .drafts import _UUID, _nonempty_text
from .engagement_drafts import valid_parent

KIND = "tenant_asset"
NAME_MAX = 200
NOTES_MAX = 2000
CHANGE_FIELDS = ("display_name", "notes", "target", "environment")
ENVIRONMENTS = ("dev", "test", "qa", "staging", "prod")
# RM-131: per-environment launch limits. `dune_floor`: Dune sand walking stays on and its delays
# stay at or above the scan type's defaults (they may only be raised).
ENVIRONMENT_POLICY = {"prod": {"dune_floor": True}}
UNSET_ENVIRONMENT = "prod"
STATUSES = ("testable", "scheduled", "expired", "unlinked")
DTO_FIELDS = ("asset_id", "parent", "display_name", "target", "target_digest", "notes", "archived_at",
              "archived_by", "created_by", "created_at", "updated_by", "updated_at")


class TenantAssetInvalid(Exception):
  def __init__(self, code="invalid_request"):
    super().__init__(code)
    self.code = code


def asset_id_for(request_id):
  return "ta_" + request_id


def valid_asset_id(value):
  return isinstance(value, str) and value.startswith("ta_") and _UUID.match(value[3:]) is not None


def normalize_display_name(value):
  try:
    return normalize_name(value, maximum=NAME_MAX)
  except (ValueError, TypeError, UnicodeError):
    raise TenantAssetInvalid() from None


def normalize_notes(value):
  """Free text, empty allowed; line breaks and tabs are the only control characters kept."""
  if not isinstance(value, str):
    raise TenantAssetInvalid()
  try:
    value.encode("utf-8", errors="strict")
  except UnicodeError:
    raise TenantAssetInvalid() from None
  if any((ord(ch) < 32 and ch not in "\n\t") or 127 <= ord(ch) <= 159 or ch == "﻿" for ch in value):
    raise TenantAssetInvalid()
  value = value.strip()
  if len(value) > NOTES_MAX:
    raise TenantAssetInvalid()
  return value


def normalize_asset_target(value):
  try:
    return normalize_target(value)
  except (ValueError, TypeError, UnicodeError):
    raise TenantAssetInvalid("asset_target_invalid") from None


def normalize_environment(value):
  if not isinstance(value, str) or value not in ENVIRONMENTS:
    raise TenantAssetInvalid("asset_environment_invalid")
  return value


def launch_environment(value):
  """The environment a launch is held to: an unset (pre-RM-131) or unknown one is `prod`."""
  return value if isinstance(value, str) and value in ENVIRONMENTS else UNSET_ENVIRONMENT


def new_asset(asset_id, parent, display_name, target, notes, actor_id, now, environment=None):
  target = normalize_asset_target(target)
  return {"asset_id": asset_id, "parent": dict(parent), "display_name": normalize_display_name(display_name),
          "target": target, "target_digest": canonical_digest(target),
          "environment": normalize_environment(environment),
          "notes": normalize_notes("" if notes is None else notes), "archived_at": None, "archived_by": None,
          "created_by": actor_id, "created_at": now, "updated_by": actor_id, "updated_at": now}


def apply_changes(row, changes):
  """The row with `changes` applied (`update_tenant_asset`); the caller checks the target and
  environment lock."""
  if not isinstance(changes, dict) or not changes or any(key not in CHANGE_FIELDS for key in changes):
    raise TenantAssetInvalid()
  row = dict(row)
  if "display_name" in changes:
    row["display_name"] = normalize_display_name(changes["display_name"])
  if "notes" in changes:
    row["notes"] = normalize_notes(changes["notes"])
  if "target" in changes:
    target = normalize_asset_target(changes["target"])
    row.update(target=target, target_digest=canonical_digest(target))
  if "environment" in changes:
    row["environment"] = normalize_environment(changes["environment"])
  return row


def _same(normalize, value):
  try:
    return normalize(value) == value
  except TenantAssetInvalid:
    return False


def validate_tenant_asset(row, ids):
  """Refuse a stored asset the operations could not have written. Unknown fields are kept."""
  archived = row.get("archived_at")
  if (len(ids) != 1 or row.get("asset_id") != ids[0] or not valid_asset_id(ids[0])
      or not valid_parent(row.get("parent"))
      or not _same(normalize_display_name, row.get("display_name"))
      or not _same(normalize_notes, row.get("notes"))
      or not _same(normalize_asset_target, row.get("target"))
      or not valid_digest(row.get("target_digest")) or row["target_digest"] != canonical_digest(row["target"])
      or ("environment" in row and row["environment"] not in ENVIRONMENTS)
      or (archived is None) != (row.get("archived_by") is None)
      or (archived is not None and not (_nonempty_text(archived) and _nonempty_text(row["archived_by"])))
      or not all(_nonempty_text(row.get(key)) for key in ("created_by", "created_at", "updated_by", "updated_at"))):
    raise ValueError("Invalid tenant asset record")
  return row


def entry_references(entries, asset_id):
  return any(isinstance(entry, dict) and entry.get("asset_id") == asset_id for entry in entries)


def engagement_link_state(row, now):
  """`active` (inside its window), `scheduled`, `ended` or `revoked`, at `now`."""
  if not row["active"]:
    return "revoked"
  if now < datetime.fromisoformat(row["valid_from"]):
    return "scheduled"
  if now >= datetime.fromisoformat(row["valid_until"]):
    return "ended"
  return "active"


def links(asset_id, engagements, engagement_drafts, now):
  """The engagements and engagement drafts whose entries name `asset_id`, engagements first."""
  found = [{"source": "engagement", "id": row["engagement_id"], "display_name": row["display_name"],
            "state": engagement_link_state(row, now)}
           for row in engagements if entry_references(row["assets"], asset_id)]
  found += [{"source": "engagement_draft", "id": row["engagement_draft_id"], "display_name": row["display_name"],
             "state": "draft"}
            for row in engagement_drafts if entry_references(row["assets"], asset_id)]
  return found


def status(asset_links):
  states = {link["state"] for link in asset_links}
  if "active" in states:
    return "testable"
  if "scheduled" in states:
    return "scheduled"
  if any(link["source"] == "engagement" for link in asset_links):
    return "expired"
  return "unlinked"


def asset_dto(row, asset_links):
  return {**{key: row[key] for key in DTO_FIELDS}, "environment": row.get("environment"),
          "kind": row["target"]["kind"], "links": asset_links,
          "status": status(asset_links)}
