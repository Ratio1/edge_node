"""RM-120 phase 10b: the tenant's assessments of one framework pack (list, create, archive).

Contract: `project-red-mesh:docs/resources/redmesh/contracts/framework-assessment.md`
§"Several assessments per framework pack". The default assessment sits on the legacy 4-element
key; every other one on a 5-element key `fa_<uuid>`. Rows are found by key scan, never by an index
record (CStore is last-writer-wins across nodes). Like `compliance.py`, these functions run under
the administration lock through `TenantAdministrationService` wrappers.

A listing carries summary fields only: never a document reference, a score or pack text.
"""
from __future__ import annotations

import unicodedata

from ..references.framework_packs import (
  list_framework_pack_ids,
  load_framework_pack,
  load_manifest,
  manifest_pack,
  pack_levels,
  pack_rules,
)
from ..services.framework_scoring import scorer_for
from . import compliance
from .assets import canonical_uuid

# `compliance` is only reached through the module at call time: it imports this module lazily, and
# `administration` imports both at its end, so a name import here would hit a half-built module.
MAX_ASSESSMENTS = 20  # per tenant and pack, archived included


def assessment_id_for(request_id):
  return "fa_" + canonical_uuid(request_id)


def _stored_rows(service, tenant_id, pack_id="", unavailable=None):
  """The tenant's stored rows (validated), optionally of one pack. Only this tenant's fields are read.
  A row the validator refuses is skipped; `unavailable`, when given, collects it as a list entry."""
  store = compliance._store(service)
  rows = []
  for ids in store.tenant_record_ids(compliance.KIND, tenant_id):
    if not pack_id or ids[1] == pack_id:
      row, reason = compliance.read_row(store, ids)
      if row is not None:
        rows.append(row)
      elif reason and unavailable is not None:
        unavailable.append({"assessmentId": ids[2] if len(ids) == 3 else compliance.DEFAULT_ID, "packId": ids[1],
                            "unavailable": True, "unavailable_reason": reason})
  return rows


def _name_key(name):
  return " ".join(unicodedata.normalize("NFKC", name).split()).casefold()


def name_taken(service, tenant_id, pack_id, name, *, exclude_id=None, rows=None):
  """409 `assessment_name_taken` when a non-archived assessment of the pack already carries the name.
  `rows` are the pack's stored rows when the caller has read them already."""
  wanted = _name_key(name)
  if not wanted:
    return
  for row in _stored_rows(service, tenant_id, pack_id) if rows is None else rows:
    if ((row.get("assessment_id") or compliance.DEFAULT_ID) != exclude_id and not row.get("archived")
        and _name_key(row.get("name") or "") == wanted):
      raise compliance._denied(409, "assessment_name_taken")


def status_of(row):
  if row.get("pending") is not None:
    return "pending"
  if row["state"] == "submitted":
    return "submitted"
  return "draft" if row.get("scores") or row["submissions"] else "not_started"


def _summary(row, names, can_manage):
  return {
    "assessmentId": row.get("assessment_id") or compliance.DEFAULT_ID, "packId": row["pack_id"], "name": row.get("name") or "",
    "assuranceLevel": row.get("assurance_level"), "status": status_of(row),
    "latestRevision": compliance.latest_revision(row), "assessmentRevision": row["assessment_revision"],
    "archived": bool(row.get("archived")), "updatedBy": row["updated_by"], "updatedByName": names(row["updated_by"]),
    "updatedAt": row["updated_at"], "createdAt": row["created_at"], "canManage": can_manage,
  }


def list_assessments(service, actor, tenant_id, pack_id="", include_archived=False):
  tenant, account = service._authorized_tenant(actor, tenant_id, compliance.VIEW)
  if type(include_archived) is not bool:
    raise compliance._denied(400, "invalid_request")
  if pack_id:
    compliance.pack_for(pack_id)
  names, can_manage = compliance.name_resolver(service), service._permission(account, tenant, compliance.MANAGE)
  unavailable = []
  rows = [row for row in _stored_rows(service, tenant_id, pack_id, unavailable)
          if include_archived or not row.get("archived")]
  rows.sort(key=lambda row: (row["updated_at"], row.get("assessment_id") or compliance.DEFAULT_ID), reverse=True)
  unavailable.sort(key=lambda entry: (entry["packId"], entry["assessmentId"]))
  return [_summary(row, names, can_manage) for row in rows] + unavailable


def list_packs(service, actor, tenant_id):
  """The active packs of the manifest, for the pack picker (view permission; no retired pack)."""
  service._authorized_tenant(actor, tenant_id, compliance.VIEW)
  packs = []
  for pack_id in list_framework_pack_ids():
    entry, pack = manifest_pack(pack_id), load_framework_pack(pack_id)
    rules = {key: value for key, value in entry["rules"].items() if key != "exports"}
    licence = entry["licence"]
    packs.append({"packId": pack_id, "title": entry["title"], "scoring": entry["scoring"],
                  "packSha256": entry["pack_sha256"],
                  "levels": list(pack_levels(pack)), "rules": rules, "exports": list(entry["rules"]["exports"]),
                  "licence": {"id": licence["id"], "attribution": licence["attribution"],
                              "shipText": licence["ship_text"]},
                  "languages": list(entry["languages"]), "status": entry["status"],
                  "entries": [{k: v for k, v in e.items() if k != "verified_by"} for e in entry["entries"]], "capabilities": scorer_for(pack).capabilities()})
  return {"schema": "redmesh.framework_pack_list.v1", "manifestVersion": load_manifest()["manifest_version"],
          "packs": packs}


def create_assessment(service, actor, tenant_id, pack_id, request_id, name, assurance_level=None,
                      level_provenance=None, country=None):
  """Order: authorization, pack, input shape, replay, cap, name. A replay returns the stored row
  (archived too) before the cap and the name are looked at."""
  from .administration import _request_id
  tenant, account = service._authorized_tenant(actor, tenant_id, compliance.MANAGE)
  pack = compliance.pack_for(pack_id)
  request_id = _request_id(request_id)
  try:
    name = compliance.normalize_name(name, required=True)
    level = compliance.normalize_level(assurance_level, pack)
    if level is None and pack_levels(pack):  # a null level is accepted only for a pack with no levels
      raise compliance.AssessmentInvalid("invalid_level")
    if level is None and level_provenance is not None:  # no level, nothing to give a provenance for: refused
      raise compliance.AssessmentInvalid("invalid_request")
    if level_provenance is None and level is not None:
      level_provenance = {"kind": "declared"}
    provenance = compliance.normalize_level_provenance(level_provenance, actor=account.account_id,
                                                       kinds=pack_rules(pack)["level_provenance_kinds"])
    country = compliance.resolve_country(pack_id, country)
  except compliance.AssessmentInvalid as exc:
    raise compliance._denied(400, "assessment_invalid", errors=[exc.as_error()]) from None
  inputs = {"name": name, "assurance_level": level, "level_provenance": provenance, "country": country}
  assessment_id = assessment_id_for(request_id)
  names = compliance.name_resolver(service)
  existing = compliance._store(service).get(compliance.KIND, tenant_id, pack_id, assessment_id)
  if existing is not None:
    if existing.get("created_by") != account.account_id or existing.get("create_request") != inputs:
      raise compliance._denied(409, "conflict")
    return {**compliance.assessment_view(existing, pack, can_manage=True, names=names, tenant=tenant),
            "replayed": True}
  compliance.require_active(pack)
  stored_rows = _stored_rows(service, tenant_id, pack_id)
  if len(stored_rows) >= MAX_ASSESSMENTS:
    raise compliance._denied(409, "assessment_limit", limit=MAX_ASSESSMENTS)
  name_taken(service, tenant_id, pack_id, name, rows=stored_rows)
  now = compliance._now_iso()
  row = {**compliance.new_row(tenant_id, pack, actor=account.account_id, now=now, country=country),
         "assessment_id": assessment_id,
         "name": name, "assurance_level": level, "level_provenance": provenance,
         "create_request_id": request_id, "create_request": inputs}
  stored = compliance._put(service, row)
  return {**compliance.assessment_view(stored, pack, can_manage=True, names=names, tenant=tenant),
          "replayed": False}


def archive_assessment(service, actor, tenant_id, pack_id, assessment_id, archived, expected_assessment_revision):
  """Set or clear the archived flag under a revision check. Repeating the current state is a no-op."""
  tenant, account = service._authorized_tenant(actor, tenant_id, compliance.MANAGE)
  pack = compliance.pack_for(pack_id)
  if type(archived) is not bool:
    raise compliance._denied(400, "invalid_request")
  row = compliance._row(service, tenant_id, pack_id, assessment_id)
  if row is None:
    raise compliance._denied(404, "assessment_not_found")
  names = compliance.name_resolver(service)
  compliance._expected_revision(row, expected_assessment_revision)
  if bool(row.get("archived")) == archived:
    return {**compliance.assessment_view(row, pack, can_manage=True, names=names, tenant=tenant), "changed": False}
  if row.get("pending") is not None:
    raise compliance._denied(409, "assessment_submit_pending", pending=compliance._pending_view(row["pending"], names))
  if not archived:
    name_taken(service, tenant_id, pack_id, row.get("name") or "", exclude_id=assessment_id)
  updated = compliance._stamp({**row, "archived": archived, "assessment_revision": row["assessment_revision"] + 1},
                              account.account_id)
  stored = compliance._put(service, updated)
  return {**compliance.assessment_view(stored, pack, can_manage=True, names=names, tenant=tenant), "changed": True}
