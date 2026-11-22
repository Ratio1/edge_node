"""RM-121: `list_engagement_findings`, the server-side read of an engagement's finding ledger.

Shape, filters, paging and errors: `contracts/engagement-finding-ledger.md`. The caller has already
authorized the read as `get_engagement` and passes the engagement row it returned, so every asset id
read here comes from that record, never from the request. Each asset hkey is read once and the entries
not yet in its checkpoint are folded; the read writes nothing except the one-time repair of an
overtaken fold (§2.1). Triage is joined at read from the host triage record, never stored.
"""
import base64
import binascii
import json
import time

from ..cve_view import effective_status
from ..tenancy.execution import _URL_AUTHORITY
from .engagement_ledger import REPLAY_READ_CAP, LedgerFoldError, empty_checkpoint, fold, valid_engagement_asset_id
from .engagement_ledger_store import EngagementLedgerRecorder, EngagementLedgerStore, LedgerStoreError, artifact_loader

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
STATES = ("active", "not_observed")


class _Invalid(Exception):
  pass


def _error(status_code, error):
  return {"success": False, "status": "error", "status_code": status_code, "error": error}


def _order(asset_id, finding_id, occurrence):
  return int(asset_id[3:]), finding_id, occurrence


def _encode_cursor(key):
  return base64.urlsafe_b64encode(json.dumps(list(key), separators=(",", ":")).encode("utf-8")).decode("ascii")


def _decode_cursor(cursor):
  if cursor is None or cursor == "":
    return None
  try:
    asset_id, finding_id, occurrence = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
  except (AttributeError, ValueError, TypeError, UnicodeError, binascii.Error):
    raise _Invalid() from None
  if (not valid_engagement_asset_id(asset_id) or not isinstance(finding_id, str)
      or type(occurrence) is not int or occurrence < 0):
    raise _Invalid()
  return _order(asset_id, finding_id, occurrence)


def _filters(state, severity, limit):
  if state not in (None, "", *STATES):
    raise _Invalid()
  if severity is not None and (not isinstance(severity, list)
                               or any(not isinstance(item, str) or not item for item in severity)):
    raise _Invalid()
  limit = DEFAULT_LIMIT if limit is None else limit
  if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
    raise _Invalid()
  return state or None, set(severity or ()), limit


def _host(target):
  """The triage host of an engagement asset, as `triage_scope` derives it from a binding."""
  if not isinstance(target, dict):
    return None
  if target.get("kind") == "network":
    return target.get("address")
  if target.get("kind") == "webapp":
    match = _URL_AUTHORITY.match(target.get("url") or "")
    return match[1].lower() if match else None
  return None


def _ref(value):
  return None if value is None else {"jobId": value["job_id"], "passNr": value["pass_nr"], "at": value["at"]}


def _row(asset_id, row, triage):
  version = row["current_version"]
  return {
    "engagementAssetId": asset_id, "findingId": row["finding_id"], "occurrence": row["occurrence"],
    "firstSeen": _ref(row["first_seen"]), "episodeOpened": _ref(row["episode_opened"]),
    "lastSeen": _ref(row["last_seen"]), "lastTested": _ref(row["last_tested"]),
    "timesSeen": row["times_seen"], "jobIds": list(row["job_ids"]), "missedStreak": row["missed_streak"],
    "notObservedSince": _ref(row["not_observed_since"]), "lastCoverageGap": _ref(row["last_coverage_gap"]),
    "reappearedCount": row["reappeared_count"],
    "currentVersion": {"findingSignature": version["finding_signature"], "title": version["title"],
                       "severity": version["severity"], "firstPassReportCid": version["first_pass_report_cid"],
                       "lastPassReportCid": version["last_pass_report_cid"]},
    "triage": triage,
  }


def _asset_state(owner, artifacts, namespace, tenant_id, engagement_id, asset_id):
  """`(checkpoint, pending)` of one asset: the stored checkpoint plus the fold of the entries it lacks.
  A replay within the cap is written once as the repair (that fold, not a second one); one over the
  cap writes nothing. A repair write that fails is logged and the folded result served. A pass-changes
  artifact that cannot be read (R1FS answers None on a transient failure too) serves the stored
  checkpoint as pending, and writes nothing."""
  store = EngagementLedgerStore(owner, namespace, tenant_id, engagement_id, asset_id)
  snapshot = store.read()
  try:
    result = fold(snapshot["checkpoint"], snapshot["entries"], artifact_loader(artifacts), asset_id=asset_id,
                  read_cap=REPLAY_READ_CAP)
    if result.replayed and snapshot["rebuilding"] is None:
      try:
        EngagementLedgerRecorder(owner, store, None).fold_and_write(artifacts, folded=(snapshot, result))
      except LedgerStoreError as exc:
        owner.P(f"[LEDGER] {store.hkey}: repair write failed ({exc}); serving the folded result", color='y')
  except LedgerFoldError:
    owner.P(f"[LEDGER] {store.hkey}: a pass-changes artifact is unreadable; serving the stored checkpoint",
            color='y')
    return snapshot["checkpoint"] or empty_checkpoint(), True
  return result.checkpoint, result.pending


class _Triage:
  """Point reads of the host triage record per finding, checked to name its key."""

  def __init__(self, owner, tenant_id):
    self._repo = owner._get_job_state_repository()
    self._tenant_id = tenant_id
    clock = getattr(owner, "time", None)
    self._now = clock() if callable(clock) else time.time()
    self._cache = {}

  def get(self, host, finding_id):
    if host is None:
      return None
    key = (host, finding_id)
    if key not in self._cache:
      record = self._repo.get_host_triage(self._tenant_id, host, finding_id)
      if record is not None and not (isinstance(record, dict) and record.get("tenant_id") == self._tenant_id
                                     and record.get("host") == host and record.get("finding_id") == finding_id):
        raise LedgerStoreError("Invalid finding state identity")
      self._cache[key] = None if record is None else {
        "status": record.get("status"), "effectiveStatus": effective_status(record, self._now)}
    return self._cache[key]


def list_engagement_findings(owner, namespace, engagement, *, engagement_asset_id=None, state=None,
                             severity=None, limit=None, cursor=None):
  """One page of the engagement's ledger rows in `(engagement_asset_id, finding_id, occurrence)` order.

  `engagement` is the row `get_engagement` returned for the authorized caller.
  """
  try:
    state, severities, limit = _filters(state, severity, limit)
    after = _decode_cursor(cursor)
    if engagement_asset_id not in (None, "") and not isinstance(engagement_asset_id, str):
      raise _Invalid()
  except _Invalid:
    return _error(400, "invalid_request")
  assets = {asset["engagementAssetId"]: asset for asset in engagement["assets"]}
  if engagement_asset_id:
    if engagement_asset_id not in assets:
      return _error(404, "not_found")  # one code: the asset is not in this engagement
    selected = [engagement_asset_id]
  else:
    selected = sorted(assets, key=lambda asset_id: int(asset_id[3:]))
  if after is not None:
    selected = [asset_id for asset_id in selected if int(asset_id[3:]) >= after[0]]
  tenant_id, engagement_id = engagement["tenantId"], engagement["engagementId"]
  artifacts = owner._get_artifact_repository()
  triage = _Triage(owner, tenant_id)
  rows, gap_state, pending = [], {}, []
  try:
    for asset_id in selected:
      checkpoint, replay_pending = _asset_state(owner, artifacts, namespace, tenant_id, engagement_id, asset_id)
      if replay_pending:
        pending.append(asset_id)
      gap = checkpoint["gap"].get(assets[asset_id]["kind"]) or {}
      gap_state[asset_id] = (None if gap.get("state") is None
                             else {"cause": gap["state"]["cause"], "streak": gap["state"]["streak"]})
      host = _host(assets[asset_id]["target"])
      for row in sorted(checkpoint["rows"].values(), key=lambda r: (r["finding_id"], r["occurrence"])):
        if after is not None and _order(asset_id, row["finding_id"], row["occurrence"]) <= after:
          continue
        if state == "active" and row["not_observed_since"] is not None:
          continue
        if state == "not_observed" and row["not_observed_since"] is None:
          continue
        if severities and row["current_version"]["severity"] not in severities:
          continue
        rows.append((asset_id, host, row))
      if len(rows) > limit:
        break
    page = [_row(asset_id, row, triage.get(host, row["finding_id"])) for asset_id, host, row in rows[:limit]]
  except (LedgerStoreError, KeyError, TypeError, ValueError) as exc:
    # A malformed checkpoint or artifact (a restore) fails the fold or the row build: unavailable, not a 500.
    owner.P(f"[LEDGER] Engagement findings of {engagement_id} unavailable: {type(exc).__name__}", color='r')
    return _error(503, "unavailable")
  next_cursor = (_encode_cursor((page[-1]["engagementAssetId"], page[-1]["findingId"], page[-1]["occurrence"]))
                 if len(rows) > limit else None)
  return {"success": True, "status_code": 200, "data": {
    "tenantId": tenant_id, "engagementId": engagement_id, "rows": page, "gapState": gap_state,
    "nextCursor": next_cursor, "replayPending": pending}}
