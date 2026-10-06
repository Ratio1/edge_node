"""RM-120 phase 5: evidence suggestions for the framework maturity self-assessment.

A tenant's finalized scans are read through the tenant read seam (`reports:view`, ownership and
finalization decided there), the latest completed pass of each is classified by the shared evidence
engine, and every control the pack maps to a signal kind gets at most a few suggestions naming the
job and pass (`job:<job_id>:<pass_nr>`, the evidence-ref grammar of the contract). Suggestions
never set or change a score (contract invariant 4); the person links them and keeps the
justification. Bounded to the most recent `MAX_JOBS` finalized jobs and cached per draft
revision for a short while, as the contract rows say.
"""
import hashlib
import json
import re
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone

from ..references.framework_packs import controls_for_level
from ..tenancy.compliance import JOB_REF as _JOB_REF
from .evidence_engine import SIGNAL_KINDS, actionable_findings, classify
from .rulebook_assessment import _job_repo, _resolve_scan_context

MAX_JOBS = 20
PER_CONTROL = 3
CACHE_TTL_SECONDS = 60
CACHE_MAX = 64
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")

# Which control of which pack a scan signal speaks to. Curated from the official requirement text
# (DNSC Order 1/2026 Annex 1): a RedMesh pass shows open vulnerabilities, access and transport
# weaknesses, that a technical assessment took place, and whether SOC export or detection
# correlation ran. Controls about policy, training, supply chain or physical matters are not
# mapped: a scan says nothing about them.
CONTROL_SIGNALS = {
  "ro.dnsc.o1-2026": {
    # Vulnerabilities identified, reviewed, remediated; patches installed.
    "ID.RA-01.1": "vulnerability_management", "ID.RA-01.2": "vulnerability_management",
    "ID.RA-01.3": "vulnerability_management", "ID.RA-01.6": "vulnerability_management",
    "ID.RA-08.1": "vulnerability_management", "ID.RA-08.2": "vulnerability_management",
    "ID.AM-08.2": "vulnerability_management",
    # Identities, MFA, privileges.
    "PR.AA-01.1": "auth_access_findings", "PR.AA-01.2": "auth_access_findings",
    "PR.AA-01.4": "auth_access_findings", "PR.AA-03.2": "auth_access_findings",
    "PR.AA-05.3": "auth_access_findings", "PR.AA-05.4": "auth_access_findings",
    "PR.AA-05.7": "auth_access_findings", "PR.AA-05.9": "auth_access_findings",
    # Cryptographic mechanisms for remote access and data in transit.
    "PR.AA-03.4": "crypto_transport_findings", "PR.DS-02.2": "crypto_transport_findings",
    # A technical assessment took place: risk assessment inputs, security tests, scan analysis.
    "ID.RA-01.5": "assessment_performed", "ID.RA-05.1": "assessment_performed",
    "ID.RA-05.2": "assessment_performed", "ID.IM-02.1": "assessment_performed",
    "DE.AE-03.3": "assessment_performed",
    # Logging, monitoring and automated event review.
    "DE.AE-03.1": "soc_incident_evidence", "DE.AE-02.2": "soc_incident_evidence",
    "DE.CM-09.1": "soc_incident_evidence",
  },
}

_SUMMARIES = {
  "gap": "{gap} unresolved medium-or-higher finding(s) in pass {pass_nr} match this control.",
  "needs_review": "{review} lower-severity or inconclusive finding(s) in pass {pass_nr} need interpretation.",
  "supported": "No unresolved matching finding in pass {pass_nr}.",
  "assessment_performed": "Finalized scan pass {pass_nr} is retained as technical assessment evidence.",
  "soc_supported": "SOC export or detection correlation completed for this job.",
  "soc_needs_review": "No completed SOC export or detection correlation is recorded for this job.",
}

_cache = {}
_cache_lock = threading.Lock()


def reset_cache():
  with _cache_lock:
    _cache.clear()


def mapped_controls(pack_id, pack, level):
  """`{ref_id: signal_kind}` for the controls counted at `level` that a scan signal speaks to."""
  mapping = CONTROL_SIGNALS.get(pack_id) or {}
  return {c["ref_id"]: mapping[c["ref_id"]] for c in controls_for_level(pack, level) if c["ref_id"] in mapping}


def job_refs(patch):
  """The `job:` evidence refs a draft patch carries, as `(ref, job_id)` pairs, in order."""
  scores = patch.get("scores") if isinstance(patch, dict) else None
  found = []
  for entry in (scores or {}).values() if isinstance(scores, dict) else []:
    refs = entry.get("evidence_refs") if isinstance(entry, dict) else None
    for item in refs if isinstance(refs, list) else []:
      ref = item.get("ref") if isinstance(item, dict) else item
      match = _JOB_REF.match(ref) if isinstance(ref, str) else None
      if match:
        found.append((ref, match.group(1)))
  return found


def invalid_job_refs(refs, jobs):
  """The refs among `refs` whose job the tenant does not own as a finalized scan.

  `jobs` is the tenant read seam's ownership-checked listing, so a job missing from it is foreign,
  deleted or unattributed: all three read the same to the tenant.
  """
  invalid = []
  for ref, job_id in refs:
    record = jobs.get(job_id) if isinstance(jobs, dict) else None
    if not isinstance(record, dict) or record.get("job_status") != "FINALIZED":
      invalid.append(ref)
  return sorted(set(invalid))


def empty(pack_id, level=None, *, reason="level_missing"):
  return {"packId": pack_id, "assuranceLevel": level, "jobsAvailable": 0, "jobsConsidered": 0, "jobsSkipped": 0,
          "generatedAt": _iso(time.time()), "reason": reason, "suggestions": {}, "overriding": []}


def suggest(owner, tenant_id, pack_id, pack, level, assessment_revision, jobs, *, now=None):
  """Suggestions for one draft from the tenant's most recent finalized scans; cached briefly."""
  now = time.time() if now is None else now
  selected = _finalized(jobs)[:MAX_JOBS]
  key = (getattr(owner, "cfg_tenancy_namespace", None), tenant_id, pack_id,
         _digest(level, assessment_revision, selected))
  with _cache_lock:
    hit = _cache.get(key)
    if hit is not None and hit[0] > now:
      return deepcopy(hit[1])
  data = _compute(owner, pack_id, pack, level, selected, now)
  data["jobsAvailable"] = len(_finalized(jobs))
  with _cache_lock:
    if len(_cache) >= CACHE_MAX:
      _cache.clear()
    _cache[key] = (now + CACHE_TTL_SECONDS, deepcopy(data))
  return data


def _finalized(jobs):
  records = [(job_id, record) for job_id, record in (jobs or {}).items()
             if isinstance(record, dict) and record.get("job_status") == "FINALIZED"
             and isinstance(job_id, str) and _JOB_ID.match(job_id)]
  return sorted(records, key=lambda item: (-_number(item[1].get("date_completed") or item[1].get("date_created")), item[0]))


def _number(value):
  try:
    return float(value)
  except (TypeError, ValueError):
    return 0.0


def _iso(epoch):
  try:
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")
  except (TypeError, ValueError, OverflowError, OSError):
    return None


def _digest(level, assessment_revision, selected):
  material = json.dumps([level, assessment_revision,
                         [(job_id, record.get("date_completed"), record.get("job_cid")) for job_id, record in selected]],
                        sort_keys=True, default=str)
  return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _compute(owner, pack_id, pack, level, selected, now):
  mapped = mapped_controls(pack_id, pack, level)
  kinds = sorted(set(mapped.values()))
  suggestions = {ref_id: [] for ref_id in mapped}
  overriding = []
  considered = skipped = 0
  for job_id, record in selected:
    ctx, err = _resolve_scan_context(owner, job_id, checked_job=record)
    if err:
      skipped += 1
      continue
    considered += 1
    try:
      triage_map = _job_repo(owner).list_job_triage(job_id) or {}
    except Exception:
      triage_map = {}
    pass_data = ctx["pass_data"]
    pass_nr = pass_data.get("pass_nr") if type(pass_data.get("pass_nr")) is int else 1
    findings = actionable_findings(pass_data.get("findings"), triage_map)
    metadata = {
      "soc_event_status": ctx["job_specs"].get("soc_event_status") or ctx["archive"].get("soc_event_status"),
      "detection_correlation": ctx["job_specs"].get("detection_correlation") or ctx["archive"].get("detection_correlation"),
    }
    results = {kind: classify(kind, findings, metadata) for kind in kinds}
    completed_at = _iso(record.get("date_completed"))
    ref = f"job:{job_id}:{pass_nr}"
    for ref_id, kind in mapped.items():
      result = results[kind]
      if result["status"] == "not_observable" or len(suggestions[ref_id]) >= PER_CONTROL:
        continue
      suggestions[ref_id].append({
        "ref": ref, "signal_kind": kind, "status": result["status"], "summary": _summary(kind, result, pass_nr),
        "job_id": job_id, "pass_nr": pass_nr, "completed_at": completed_at,
        "counts": {"gap": result["gap"], "review": result["review"]},
      })
      if result["severities"] and not any(item["control_id"] == ref_id for item in overriding):
        overriding.append({"control_id": ref_id, "ref": ref, "job_id": job_id, "pass_nr": pass_nr,
                           "severities": dict(result["severities"])})
  return {"packId": pack_id, "assuranceLevel": level, "jobsAvailable": len(selected), "jobsConsidered": considered,
          "jobsSkipped": skipped, "generatedAt": _iso(now), "reason": None,
          "suggestions": {ref_id: items for ref_id, items in suggestions.items() if items},
          "overriding": overriding}


def _summary(kind, result, pass_nr):
  if kind == "assessment_performed":
    return _SUMMARIES["assessment_performed"].format(pass_nr=pass_nr)
  if kind == "soc_incident_evidence":
    return _SUMMARIES["soc_supported" if result["status"] == "supported" else "soc_needs_review"]
  return _SUMMARIES[result["status"]].format(gap=result["gap"], review=result["review"], pass_nr=pass_nr)


assert all(kind in SIGNAL_KINDS for mapping in CONTROL_SIGNALS.values() for kind in mapping.values())
