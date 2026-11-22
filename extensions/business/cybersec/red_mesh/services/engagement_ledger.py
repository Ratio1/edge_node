"""RM-121: the engagement finding ledger, as pure functions.

One ledger per engagement asset: a row per `(finding_id, occurrence)` that every pass of every job
on the asset updates (`continuous-monitoring.md` §2-§5). `apply_pass` is the shared diff function
(database mode, RM-097, applies the same one); `fold` is the CStore-mode fold of §2.1 over write-once
pass entries, with the pass-changes artifacts read through an injected loader. No I/O here.

The ledger decides nothing: no lifecycle status, no triage (RM-076).
"""
from collections import namedtuple
from copy import deepcopy
import re

from ..connection_metrics import RESPONSIVE_CONNECTION_OUTCOMES

SCHEMA_VERSION = 1
LEDGER_SCAN_TYPES = ("network", "webapp")
DEFAULT_GRACE = 1  # N: covered misses before `not_observed_since` (tenant setting, default 1)
REPLAY_READ_CAP = 500  # R1FS reads per asset hkey per fold (§2.1)
# The flat walk (`_compute_risk_and_findings`, mixins/risk.py) names every correlation finding `_correlation`,
# whatever probe id the worker stamped (`_post_scan_correlate`).
CORRELATION_PROBE = "_correlation"
_FINDING_FIELDS = ("finding_id", "finding_signature", "title", "severity", "port", "probe", "scenario_id")

_ENGAGEMENT_ASSET_ID = re.compile(r"ea_[1-9][0-9]*")
# `lost`: the passes whose pass-changes artifact data maintenance declared lost; folded as skipped.
FoldResult = namedtuple("FoldResult", "checkpoint events replayed pending lost", defaults=((),))


class LedgerFoldError(Exception):
  """A pass the fold must apply cannot be read."""


def valid_engagement_asset_id(value):
  """`ea_<n>`, the engagement asset id a ledger hkey is keyed by."""
  return isinstance(value, str) and _ENGAGEMENT_ASSET_ID.fullmatch(value) is not None


def port_ranges(ports):
  """A worker's port set as sorted `[start, end]` runs (a comparison-mode slice is not contiguous)."""
  runs = []
  for port in sorted({int(port) for port in ports}):
    if runs and port == runs[-1][1] + 1:
      runs[-1][1] = port
    else:
      runs.append([port, port])
  return runs


def empty_checkpoint():
  return {"schema_version": SCHEMA_VERSION, "rows": {}, "gap": {}, "included": {}, "through": None,
          "skipped": [], "lost": []}


def row_key(finding_id, occurrence):
  return f"{finding_id}:{occurrence}"


def pass_changes(*, job_id, pass_nr, date_completed, scan_type, pass_report_cid, flat_findings,
                 aggregated, pass_metrics, abort_state, job_config, completed_ranges):
  """The pass-changes artifact (§1, §5.2): pass facts, coverage facts, the reported findings and the
  exposure observations (network: the open ports and the service identified on each, as the
  aggregated report holds them; no exposure ledger reads them yet, RM-146).

  `completed_ranges` are the `[start, end]` port ranges of the workers whose report the pass
  collected. Change events are not stored here: the fold derives them.
  """
  config = job_config if isinstance(job_config, dict) else {}
  findings = [{name: finding.get(name) for name in _FINDING_FIELDS}
              for finding in flat_findings or [] if isinstance(finding, dict) and finding.get("finding_id")]
  counts = {}
  for finding in findings:
    severity = str(finding.get("severity") or "UNKNOWN")
    counts[severity] = counts.get(severity, 0) + 1
  completed_tests = (aggregated or {}).get("completed_tests") or []
  outcomes = (pass_metrics or {}).get("connection_outcomes") if isinstance(pass_metrics, dict) else None
  responsive = any(int((outcomes or {}).get(name) or 0) > 0 for name in RESPONSIVE_CONNECTION_OUTCOMES)
  network = scan_type == "network"
  protocols = (aggregated or {}).get("port_protocols") or {}
  open_ports = sorted({port for port in (aggregated or {}).get("open_ports") or []
                       if isinstance(port, int) and not isinstance(port, bool)}) if network else []
  return {
    "schema_version": SCHEMA_VERSION,
    "job_id": job_id, "pass_nr": pass_nr, "date_completed": date_completed, "scan_type": scan_type,
    "pass_report_cid": pass_report_cid,
    "severity_counts": counts,
    "coverage": {
      "aborted": bool(abort_state),
      "abort_reason_class": (abort_state or {}).get("abort_reason_class"),
      "ports_step_completed": network and "scan_ports_step_completed" in completed_tests,
      "host_responsive": responsive if network else None,
      "port_range": [config.get("start_port"), config.get("end_port")] if network else None,
      "port_exceptions": list(config.get("exceptions") or []) if network else [],
      "completed_ranges": [list(r) for r in completed_ranges or []] if network else [],
      "enabled_features": list(config.get("enabled_features") or []),
      "excluded_features": list(config.get("excluded_features") or []),
      "assigned_scenario_ids": (None if config.get("assigned_scenario_ids") is None
                                else list(config["assigned_scenario_ids"])),
    },
    "findings": findings,
    "exposure": [{"port": port, "service": protocols.get(str(port), protocols.get(port))} for port in open_ports],
  }


def _ref(changes):
  return {"job_id": changes["job_id"], "pass_nr": changes["pass_nr"], "at": changes["date_completed"]}


def _in_scope(row, changes):
  """§3 step 1: same scan type, the finding's probe enabled, (network) its port in the range."""
  if row["scan_type"] != changes["scan_type"]:
    return False
  coverage = changes["coverage"]
  excluded = set(coverage["excluded_features"])
  probe = row.get("probe") or ""
  if changes["scan_type"] == "webapp":
    assigned = coverage["assigned_scenario_ids"]
    if "graybox" in excluded or probe in excluded or (not probe and excluded):
      return False
    return assigned is None or row.get("scenario_id") in assigned
  if probe != CORRELATION_PROBE and probe in excluded:
    return False
  # A probe that is no feature of its own (or none at all) is in scope only when nothing was excluded.
  if probe != CORRELATION_PROBE and probe not in coverage["enabled_features"] and excluded:
    return False
  port = row.get("port")
  if port:
    start, end = coverage["port_range"] or (None, None)
    if not (isinstance(start, int) and isinstance(end, int) and start <= port <= end):
      return False
    if port in coverage["port_exceptions"]:
      return False
  return True


def _pass_gap_cause(changes):
  """§3 step 2, the pass-level failures: every in-scope row of the pass is a gap row."""
  coverage = changes["coverage"]
  if coverage["aborted"]:
    if changes["scan_type"] == "webapp" and coverage["abort_reason_class"] == "auth_failed":
      return "graybox_auth_failed"
    return "aborted"
  if changes["scan_type"] == "network":
    if not coverage["ports_step_completed"]:
      return "port_scan_incomplete"
    if not coverage["host_responsive"]:
      return "host_unresponsive"
  return None


def _row_gap_cause(row, changes, pass_cause):
  if pass_cause:
    return pass_cause
  port = row.get("port")
  if changes["scan_type"] == "network" and port and not any(
      start <= port <= end for start, end in changes["coverage"]["completed_ranges"]):
    return "port_scan_incomplete"  # its port lay in a failed worker's slice
  return None


def _event(asset_id, kind, ref, *, key=None, detail=None, alert=None, digest_only=False):
  event = {"kind": kind, "key": key, **ref, "detail": detail or {}}
  if alert is not None:
    # §2.1: names what happened, not which pass saw it, so two folds crediting it to different passes
    # give one alert id.
    event["alert_id"] = "|".join(str(part) for part in (asset_id, kind, *alert))
  if digest_only:
    event["digest_only"] = True
  return event


def _version(finding, changes):
  return {"finding_signature": finding.get("finding_signature"), "title": finding.get("title"),
          "severity": finding.get("severity"), "first_pass_report_cid": changes["pass_report_cid"],
          "last_pass_report_cid": changes["pass_report_cid"]}


def _match(rows, findings):
  """§2: within a `finding_id` group, signature first, then position; the rest are new occurrences."""
  groups = {}
  for finding in findings:
    groups.setdefault(finding["finding_id"], []).append(finding)
  existing = {}
  for row in rows.values():
    existing.setdefault(row["finding_id"], []).append(row)
  pairs = []
  for finding_id, group in groups.items():
    free = sorted(existing.get(finding_id, []), key=lambda row: row["occurrence"])
    next_occurrence = max((row["occurrence"] for row in free), default=-1) + 1
    assigned = [None] * len(group)
    for index, finding in enumerate(group):
      for row in free:
        if row["current_version"]["finding_signature"] == finding.get("finding_signature"):
          assigned[index] = row
          free.remove(row)
          break
    for index, finding in enumerate(group):
      if assigned[index] is None and free:
        assigned[index] = free.pop(0)
      key = (row_key(finding_id, assigned[index]["occurrence"]) if assigned[index] is not None
             else row_key(finding_id, next_occurrence))
      if assigned[index] is None:
        next_occurrence += 1
      pairs.append((key, finding))
  return pairs


def apply_pass(checkpoint, changes, *, asset_id, late=False, grace=DEFAULT_GRACE):
  """Apply one pass to the ledger state; returns `(state, events)`. Pure: the input is not changed.

  A late pass (§3 "Late passes") only adds sightings, plus a digest-only `new` row for a finding never
  seen; it applies no miss, no gap and no version change, and does not move `through`.
  """
  state = deepcopy(checkpoint) if checkpoint else empty_checkpoint()
  rows = state["rows"]
  ref = _ref(changes)
  scan_type = changes["scan_type"]
  events = []
  seen = set()
  pass_cause = _pass_gap_cause(changes)
  for key, finding in _match(rows, changes["findings"]):
    seen.add(key)
    row = rows.get(key)
    if row is None:
      occurrence = int(key.rsplit(":", 1)[1])
      tested = None if _row_gap_cause(finding, changes, pass_cause) else ref
      rows[key] = {
        "finding_id": finding["finding_id"], "occurrence": occurrence, "scan_type": scan_type,
        "port": finding.get("port"), "probe": finding.get("probe"), "scenario_id": finding.get("scenario_id"),
        "first_seen": ref, "episode_opened": ref, "last_seen": ref, "last_tested": tested,
        "times_seen": 1, "job_ids": [ref["job_id"]], "missed_streak": 0, "not_observed_since": None,
        "last_coverage_gap": None, "reappeared_count": 0, "current_version": _version(finding, changes),
      }
      events.append(_event(asset_id, "new", ref, key=key, alert=(key,), digest_only=late))
      continue
    row["times_seen"] += 1
    if ref["job_id"] not in row["job_ids"]:
      row["job_ids"].append(ref["job_id"])
    if late:
      if ref["at"] < row["first_seen"]["at"]:
        row["first_seen"] = ref
      if ref["at"] > row["last_seen"]["at"]:
        row["last_seen"] = ref
      continue
    row["last_seen"] = ref
    if not _row_gap_cause(row, changes, pass_cause):
      row["last_tested"] = ref  # a sighting on a gap pass is a sighting, not a covered pass (§2)
    row["missed_streak"] = 0
    if row["not_observed_since"] is not None:
      row["not_observed_since"] = None
      row["reappeared_count"] += 1
      row["episode_opened"] = ref
      events.append(_event(asset_id, "reappeared", ref, key=key, alert=(key, row["reappeared_count"])))
    version = row["current_version"]
    if version["finding_signature"] != finding.get("finding_signature"):
      new_version = _version(finding, changes)
      # §4: the replaced version stays one R1FS read away.
      events.append(_event(asset_id, "changed", ref, key=key, detail={
        "old_severity": version["severity"], "new_severity": new_version["severity"],
        "old_finding_signature": version["finding_signature"],
        "old_first_pass_report_cid": version["first_pass_report_cid"],
        "old_last_pass_report_cid": version["last_pass_report_cid"]}))
      row["current_version"] = new_version
    else:
      version["last_pass_report_cid"] = changes["pass_report_cid"]
  if late:
    return state, events

  in_scope_rows = bool(seen)
  row_cause = None
  for key in sorted(rows):
    row = rows[key]
    if key in seen or not _in_scope(row, changes):
      continue
    in_scope_rows = True
    cause = _row_gap_cause(row, changes, pass_cause)
    if cause:
      row["last_coverage_gap"] = ref
      row_cause = row_cause or cause
      continue
    row["last_tested"] = ref
    if row["not_observed_since"] is not None:
      continue  # already not observed: no further miss, no further event
    row["missed_streak"] += 1
    if row["missed_streak"] >= grace:
      row["not_observed_since"] = ref
      events.append(_event(asset_id, "not_observed", ref, key=key))
    else:
      events.append(_event(asset_id, "missed", ref, key=key, detail={"missed_streak": row["missed_streak"]}))

  if in_scope_rows:
    gap = state["gap"].setdefault(scan_type, {"state": None, "count": 0})
    cause = pass_cause or row_cause
    if cause and gap["state"] is None:
      gap["count"] += 1
      gap["state"] = {"cause": cause, "streak": 1, "since": ref}
      events.append(_event(asset_id, "coverage_gap", ref, detail={"scan_type": scan_type, "cause": cause},
                           alert=(scan_type, gap["count"])))
    elif cause:
      gap["state"]["streak"] += 1
    elif gap["state"] is not None:
      gap["state"] = None
      events.append(_event(asset_id, "coverage_restored", ref, detail={"scan_type": scan_type}))
  if state["through"] is None or ref["at"] > state["through"]:
    state["through"] = ref["at"]
  return state, events


def _contiguous(entries, included):
  """Per job, the pass entries after `included[job]` up to the first missing pass number."""
  run = []
  for job_id in sorted({job for job, _ in entries}):
    pass_nr = included.get(job_id, 0) + 1
    while (job_id, pass_nr) in entries:
      run.append((job_id, pass_nr))
      pass_nr += 1
  return run


def _overtaken(base, entries, run):
  through = base["through"]
  for key in run:
    entry = entries[key]
    if not entry.get("skipped") and not entry.get("late") and through is not None \
        and entry["date_completed"] <= through:
      return True
  # A real entry that replaced a `skipped` one this checkpoint already folded.
  return any(tuple(key) in entries and not entries[tuple(key)].get("skipped") for key in base["skipped"])


def _lost(checkpoint):
  """The passes data maintenance declared lost, as `(job_id, pass_nr)` keys (older checkpoints: none)."""
  return {tuple(key) for key in checkpoint.get("lost") or ()}


def _apply_run(base, entries, run, load_changes, *, asset_id, grace, may_lose, declared, overtaken_as_late=False):
  """`declared`: passes already declared lost; folded as skipped, their artifact never read again."""
  state = deepcopy(base)
  state["lost"] = sorted([job_id, pass_nr] for job_id, pass_nr in declared)
  through = base["through"]
  events = {}
  lost = []
  real = [key for key in run if not entries[key].get("skipped") and key not in declared]
  real.sort(key=lambda key: (entries[key]["date_completed"], key[0], key[1]))
  for key in real:
    entry = entries[key]
    try:
      changes = load_changes(entry["pass_changes_cid"])
    except Exception as exc:
      raise LedgerFoldError(f"pass-changes artifact of {key[0]} pass {key[1]} unreadable") from exc
    if changes is None:
      # R1FS answers None on a transient failure too: only data maintenance may call it lost (24 h).
      if may_lose is None or not may_lose(entry):
        raise LedgerFoldError(f"pass-changes artifact of {key[0]} pass {key[1]} unavailable")
      lost.append(key)
      continue
    if not isinstance(changes, dict) or changes.get("schema_version") != SCHEMA_VERSION:
      raise LedgerFoldError(f"pass-changes artifact of {key[0]} pass {key[1]} unavailable")
    late = bool(entry.get("late")) or (
      overtaken_as_late and through is not None and entry["date_completed"] <= through)
    state, events[key] = apply_pass(state, changes, asset_id=asset_id, late=late, grace=grace)
  for job_id, pass_nr in run:
    state["included"][job_id] = max(state["included"].get(job_id, 0), pass_nr)
    if entries[(job_id, pass_nr)].get("skipped") and [job_id, pass_nr] not in state["skipped"]:
      state["skipped"].append([job_id, pass_nr])
  state["lost"] = sorted(state["lost"] + [list(key) for key in lost])
  return state, events, lost


def fold(checkpoint, entries, load_changes, *, asset_id, grace=DEFAULT_GRACE, read_cap=REPLAY_READ_CAP,
         may_lose=None):
  """The §2.1 fold. `entries` maps `(job_id, pass_nr)` to its pass entry; `load_changes(cid)` returns
  a pass-changes artifact. Each job is folded along its contiguous pass numbers only, in the order
  `(date_completed, job_id, pass_nr)`. An overtaken pass replays the asset from empty; a replay over
  `read_cap` artifact reads is left pending (the result is the checkpoint plus the contiguous fold,
  with overtaken passes applied as late, and must not be written). An artifact that reads as None
  fails the fold (`LedgerFoldError`), unless `may_lose(entry)` (data maintenance only) declares it lost:
  that pass is then folded as skipped, listed in `lost` and kept in the checkpoint's `lost`, so every
  later fold and replay skips it without reading its artifact.
  """
  base = checkpoint or empty_checkpoint()
  declared = _lost(base)
  run = _contiguous(entries, base["included"])
  if not _overtaken(base, entries, run):
    state, events, lost = _apply_run(base, entries, run, load_changes, asset_id=asset_id, grace=grace,
                                     may_lose=may_lose, declared=declared)
    return FoldResult(state, events, False, False, tuple(lost))
  full = _contiguous(entries, {})
  reads = sum(1 for key in full if not entries[key].get("skipped") and key not in declared)
  if read_cap is None or reads <= read_cap:
    state, events, lost = _apply_run(empty_checkpoint(), entries, full, load_changes, asset_id=asset_id,
                                     grace=grace, may_lose=may_lose, declared=declared)
    return FoldResult(state, events, True, False, tuple(lost))
  state, events, lost = _apply_run(base, entries, run, load_changes, asset_id=asset_id, grace=grace,
                                   may_lose=may_lose, declared=declared, overtaken_as_late=True)
  return FoldResult(state, events, False, True, tuple(lost))


def covers(state, other):
  """True when `state` has folded every pass `other` has."""
  included = (state or {}).get("included") or {}
  return all(included.get(job_id, 0) >= pass_nr for job_id, pass_nr in ((other or {}).get("included") or {}).items())
