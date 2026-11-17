"""`cve_view`: the listing, rollup and possible rows of CVE findings (RM-169; report-findings.md, `cve_view`).

A pure function of the flat finding dicts, the scan-local not-applicable records and the host triage map. It
is computed, never stored. It applies to CVE findings of the `generated` source only (they carry
`vulndb_build_id`); with none, `build_cve_view` returns None and the flat list stands.
"""

import re
import time

from .cve_db import _compare_versions, _parse_version
from .models.finding_schema import is_coverage_result

MAX_LISTED = 10
MAX_POSSIBLE_TOP = 3
LISTED_CVSS = 9.0
CLOSED_STATUSES = frozenset({"false_positive", "remediated"})

# The matched constraint and the product are read from the finding text `cve_db._build_finding` writes
# (`evidence`: "Detected version: V, affected: C"; `description`: "P V is vulnerable to CVE."); a test pins both.
_AFFECTED = re.compile(r"affected: (.+)$")
_SUBJECT = re.compile(r"^(\S+) (.*?) is vulnerable to CVE-")


def is_view_finding(f):
  """A CVE finding of the `generated` source."""
  return isinstance(f, dict) and bool(f.get("cve")) and bool(f.get("vulndb_build_id")) and bool(f.get("finding_id"))


def _subject(f):
  m = _SUBJECT.match(str(f.get("description") or ""))
  return (m.group(1), m.group(2)) if m else ("", "")


def _score(f):
  value = f.get("cvss_score")
  return value if isinstance(value, (int, float)) else -1.0


def triage_record(f, triage):
  """The host triage record of finding `f`, from the live map only: a record embedded on the finding is a
  read-time stamp, never a source (a removed record must not read closed)."""
  return (triage or {}).get(f.get("finding_id"))


def effective_status(record, now):
  """The status a record reads as: `accepted_risk` past `review_at` is `reopened` (the stored one is unchanged)."""
  status = record.get("status") if isinstance(record, dict) else record
  if status == "accepted_risk":
    review_at = record.get("review_at") if isinstance(record, dict) else None
    if isinstance(review_at, (int, float)) and review_at <= now:
      return "reopened"
  return status


def _is_closed(f, triage, now):
  status = effective_status(triage_record(f, triage), now)
  return status in CLOSED_STATUSES or status == "accepted_risk"  # past `review_at` the status reads `reopened`


def drop_closed(findings, triage, now=None):
  """`findings` without any finding (CVE or not) the live host triage map reads closed.

  For scoring, ranking and the LLM input only; exports keep closed findings. An empty map changes nothing.
  A coverage row is not a finding: triage never drops it, so `coverage_counts` does not depend on the map.
  """
  if not triage:
    return list(findings)
  now = time.time() if now is None else now
  return [f for f in findings if not (isinstance(f, dict) and not is_coverage_result(f) and _is_closed(f, triage, now))]


def apply_triage(findings, triage):
  """`findings` with the host triage embedded as `triage`, and a confirmed tentative finding made certain.

  A copy: the input is not touched. A record with `confirmed` on a tentative finding gives it
  `confidence=certain`, `confidence_reason=triage_confirmed`, `verified_by=<actor>`; a stored archive is not
  rewritten, so an archived pass keeps its score and the next rerun scores the finding certain.
  """
  result = []
  for f in findings or ():
    record = (triage or {}).get(f.get("finding_id")) if isinstance(f, dict) else None
    if record is None:
      result.append(f)
      continue
    f = {**f, "triage": record}
    if isinstance(record, dict) and record.get("confirmed") is True and f.get("confidence") == "tentative":
      f.update(confidence="certain", confidence_reason="triage_confirmed", verified_by=record.get("confirmed_by") or "")
    result.append(f)
  return result


# A tentative row with one of these reasons is not shown as KEV: the version is untrusted, or the CVE may not apply
# to this host at all (RM-200). The `kev` field stays: it is reference data about the CVE.
KEV_SUPPRESSING_REASONS = frozenset({"platform_dependent", "banner_unverified", "local_vector"})


def effective_kev(f):
  """True when `f` is a KEV CVE that this finding may raise."""
  return bool(f.get("kev")) and not (f.get("confidence") == "tentative" and f.get("confidence_reason") in KEV_SUPPRESSING_REASONS)


def _is_listed(f):
  """KEV, or one v3.x/v4.0 `cvss[]` entry with AV:N and PR:N scoring 9.0 or higher (v2.0 never counts)."""
  if effective_kev(f):
    return True
  for entry in f.get("cvss") or ():
    vector = str(entry.get("vector") or "").split("/")
    if (str(entry.get("version")) in ("3.0", "3.1", "4.0") and "AV:N" in vector and "PR:N" in vector
        and isinstance(entry.get("score"), (int, float)) and entry["score"] >= LISTED_CVSS):
      return True
  return False


def _rank(f):
  """Sort key: KEV first, then displayed score, then EPSS, then `cve_id`."""
  epss = f.get("epss_score")
  return (not effective_kev(f), -_score(f), -(epss if isinstance(epss, (int, float)) else 0.0), f["cve"][0])


def _fix_version(product, members):
  """Highest `<` upper bound among the members' constraints; None when a member has none."""
  best = None
  for f in members:
    match = _AFFECTED.search(str(f.get("evidence") or ""))
    bounds = []
    for clause in (match.group(1).split(",") if match else ()):
      clause = clause.strip()
      parsed = _parse_version(clause[1:], product) if clause.startswith("<") and not clause.startswith("<=") else None
      if parsed is not None:
        bounds.append((parsed, clause[1:]))
    if not bounds:
      return None
    top = None
    for parsed, text in bounds:
      if top is None or _compare_versions(parsed, top[0]) > 0:
        top = (parsed, text)
    if best is None or _compare_versions(top[0], best[0]) > 0:
      best = top
  return best[1] if best else None


def _service_order(port, product):
  """Numeric port order, a missing or non-numeric port last."""
  return (0, port, product) if isinstance(port, int) else (1, 0, str(port), product)


def _rollup(product, members):
  top = max(members, key=_score)
  score = _score(top)
  return {
    "fix_version": _fix_version(product, members),
    "cve_count": len(members),
    # Ranking and `max_cvss` stay on the v3 display label in v1; a 4.0 display ranking is RM-170.
    "max_cvss": {"score": score if score >= 0 else None,
                 "version": (top.get("cvss_version") or None) if score >= 0 else None,
                 "source": (top.get("cvss_source") or None) if score >= 0 else None},
    "kev_count": sum(1 for f in members if effective_kev(f)),
    "member_finding_ids": sorted(f["finding_id"] for f in members),
  }


def _possible(members):
  reasons = {}
  for f in members:
    reason = f.get("confidence_reason") or ""
    reasons[reason] = reasons.get(reason, 0) + 1
  top = sorted(members, key=_rank)[:MAX_POSSIBLE_TOP]
  return {
    "count": len(members),
    "reasons": dict(sorted(reasons.items())),
    "top": [{"finding_id": f["finding_id"], "cve_id": f["cve"][0], "score": f.get("cvss_score")} for f in top],
    "member_finding_ids": sorted(f["finding_id"] for f in members),
  }


def build_cve_view(findings, not_applicable=(), triage=None, now=None):
  """The view of `findings` (flat dicts), or None when none is a generated CVE finding.

  `not_applicable`: the scan-local records of CVEs matched and skipped (client side, backport fixed), counted as
  `dropped`. `triage`: finding_id -> status or `{status, review_at}`; a closed member is counted in `closed` only.
  Conservation: `listed + rolled_up + possible + closed + dropped == raw` (`possible_kev` rows are inside `possible`).

  Notes: with only `not_applicable` records and no generated finding the result is None (no view, no counts). In a
  mixed job every collector record counts as `dropped`, whichever source made it. A finding whose description does
  not parse forms the service `(port, "")`; one whose evidence has no constraint gives its rollup `fix_version` None.
  The output does not depend on the input order.
  """
  now = time.time() if now is None else now
  items = [f for f in findings or () if is_view_finding(f)]
  if not items:
    return None
  groups = {}
  closed = 0
  for f in items:
    if _is_closed(f, triage, now):
      closed += 1
    else:
      groups.setdefault((f.get("port"), _subject(f)[0]), []).append(f)
  eol = {(f.get("port"), f["tags"][1]): f["finding_id"] for f in findings
         if isinstance(f, dict) and f.get("vulndb_build_id") and f.get("finding_id")
         and len(f.get("tags") or ()) > 1 and f["tags"][0] == "vulndb_eol"}
  services = []
  totals = {"listed": 0, "rolled_up": 0, "possible": 0}
  for (port, product), members in sorted(groups.items(), key=lambda kv: _service_order(*kv[0])):
    firm = sorted((f for f in members if f.get("confidence") != "tentative"), key=_rank)
    tentative = [f for f in members if f.get("confidence") == "tentative"]
    candidates = [f for f in firm if _is_listed(f)]
    listed, overflow = candidates[:MAX_LISTED], candidates[MAX_LISTED:]
    rest = [f for f in firm if not _is_listed(f)] + overflow
    kev_possible = sorted((f for f in tentative if effective_kev(f)), key=_rank)
    services.append({
      "port": port,
      "product": product,
      "version": _subject(min(members, key=_rank))[1],
      "listed": [f["finding_id"] for f in listed],
      "rollup": _rollup(product, sorted(rest, key=_rank)) if rest else None,
      "possible": _possible(tentative) if tentative else None,
      "possible_kev": [f["finding_id"] for f in kev_possible],
      "unsupported": eol.get((port, product)),  # the end-of-life finding, outside `raw`
    })
    totals["listed"] += len(listed)
    totals["rolled_up"] += len(rest)
    totals["possible"] += len(tentative)
  dropped = len(list(not_applicable or ()))
  return {
    "services": services,
    "counts": {"raw": len(items) + dropped, **totals, "closed": closed, "dropped": dropped},
  }


def view_members(view):
  """`(listed ids, ids folded into a rollup or a possible row)` of a view."""
  listed, folded = set(), set()
  for service in view["services"]:
    listed.update(service["listed"])
    folded.update((service["rollup"] or {}).get("member_finding_ids", ()))
    folded.update((service["possible"] or {}).get("member_finding_ids", ()))
  return listed, folded


def filter_listed(findings, not_applicable=(), triage=None, view=None):
  """`findings` keeping a generated CVE finding only when the view lists it.

  Folded (rollup, possible) and closed findings leave. For the surfaces that show listed findings only
  (`top_findings`, the LLM input, the score walk). Without a view, unchanged.
  """
  view = view or build_cve_view(findings, not_applicable, triage)
  if view is None:
    return list(findings)
  listed = view_members(view)[0]
  return [f for f in findings if not is_view_finding(f) or f["finding_id"] in listed]


def summarize_view(view):
  """The view as the LLM input carries it: counts, one line per rollup, the possible summary per service."""
  rollups, possible = [], []
  for service in view["services"]:
    where = {"port": service["port"], "product": service["product"]}
    if service["rollup"]:
      r = service["rollup"]
      rollups.append({**where, **{k: r[k] for k in ("fix_version", "cve_count", "kev_count", "max_cvss")}})
    if service["possible"]:
      p = service["possible"]
      possible.append({**where, "count": p["count"], "reasons": p["reasons"], "top": p["top"]})
  return {"counts": dict(view["counts"]), "rollups": rollups, "possible": possible}
