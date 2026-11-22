"""RM-121: the CStore side of the engagement finding ledger (`continuous-monitoring.md` §2.1).

One hkey per engagement asset, `{namespace}:engagement_findings:{tenant_id}:{engagement_id}:{engagement_asset_id}`,
outside the tenancy namespace hash so it never counts against its enumeration cap. Fields:
`pass:{job_id}:{pass_nr}` (write-once pass entries), `checkpoint` (the derived state),
`events:{job_id}:{pass_nr}` (the change events of a folded pass) and `rebuilding` (§5.3, read only).
No compare-and-set: every field has one writer or a content any writer computes the same way.
"""
import re

from ..tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from ..tenancy.engagement_drafts import valid_tenant_id
from ..tenancy.engagements import valid_engagement_id
from ..tenancy.execution import binding_from_record
from .engagement_ledger import (
  LEDGER_SCAN_TYPES, REPLAY_READ_CAP, SCHEMA_VERSION, covers, fold, pass_changes, valid_engagement_asset_id,
)

CHECKPOINT_FIELD = "checkpoint"
REBUILDING_FIELD = "rebuilding"
_PASS_FIELD = re.compile(r"(pass|events):(.+):([1-9][0-9]*)")
_FOLD_ATTEMPTS = 3
SKIPPED_FILL_AFTER = 24 * 3600  # seconds a later pass's entry waits before data maintenance fills a gap
ARTIFACT_READ_TIMEOUT = 10  # seconds per pass-changes read; R1FS defaults to 90 s and would stall finalization


def artifact_loader(artifacts):
  """Pass-changes reader for a fold: short R1FS timeout; None (unreadable) fails the fold."""
  return lambda cid: artifacts.get_json(cid, timeout=ARTIFACT_READ_TIMEOUT)


class LedgerStoreError(Exception):
  """The ledger hkey cannot be addressed, read, written or verified."""


def _number(value):
  return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_pass_entry(entry):
  if not isinstance(entry, dict):
    raise LedgerStoreError("Invalid ledger pass entry")
  if entry.get("skipped") is True:
    if set(entry) - {"skipped", "date_completed"} or (
        "date_completed" in entry and not _number(entry["date_completed"])):
      raise LedgerStoreError("Invalid ledger pass entry")
    return entry
  if (set(entry) != {"date_completed", "scan_type", "pass_report_cid", "pass_changes_cid", "late"}
      or not _number(entry["date_completed"]) or entry["scan_type"] not in LEDGER_SCAN_TYPES
      or not isinstance(entry["late"], bool)
      or any(not isinstance(entry[name], str) or not entry[name] for name in ("pass_report_cid", "pass_changes_cid"))):
    raise LedgerStoreError("Invalid ledger pass entry")
  return entry


def validate_checkpoint(checkpoint):
  if (not isinstance(checkpoint, dict) or checkpoint.get("schema_version") != SCHEMA_VERSION
      or not isinstance(checkpoint.get("rows"), dict) or not isinstance(checkpoint.get("gap"), dict)
      or not isinstance(checkpoint.get("included"), dict) or not isinstance(checkpoint.get("skipped"), list)
      or not isinstance(checkpoint.get("lost", []), list)
      or not (checkpoint.get("through") is None or _number(checkpoint.get("through")))
      or any(not isinstance(job, str) or type(nr) is not int or nr < 1 for job, nr in checkpoint["included"].items())):
    raise LedgerStoreError("Invalid ledger checkpoint")
  return checkpoint


def validate_events(events):
  if not isinstance(events, list) or any(not isinstance(e, dict) or not isinstance(e.get("kind"), str) for e in events):
    raise LedgerStoreError("Invalid ledger events")
  return events


def valid_field(field, value):
  """True when `value` is what the adapter stores under `field` (data maintenance classifies by it)."""
  try:
    if field == CHECKPOINT_FIELD:
      validate_checkpoint(value)
      return True
    if field == REBUILDING_FIELD:
      return True
    match = _PASS_FIELD.fullmatch(field) if isinstance(field, str) else None
    if match is None:
      return False
    (validate_pass_entry if match.group(1) == "pass" else validate_events)(value)
    return True
  except LedgerStoreError:
    return False


class EngagementLedgerStore:
  """The fields of one asset hkey, validated on read and verified after each write."""

  def __init__(self, owner, namespace, tenant_id, engagement_id, engagement_asset_id):
    # The tenant is in the key: an engagement id is unique only within its tenant.
    if (not isinstance(namespace, str) or not namespace.strip() or ":" in namespace
        or not valid_tenant_id(tenant_id) or not valid_engagement_id(engagement_id)
        or not valid_engagement_asset_id(engagement_asset_id)):
      raise LedgerStoreError("Invalid ledger binding")
    self._owner = owner
    self.engagement_asset_id = engagement_asset_id
    self.hkey = f"{namespace}:engagement_findings:{tenant_id}:{engagement_id}:{engagement_asset_id}"

  @staticmethod
  def pass_field(job_id, pass_nr):
    return f"pass:{job_id}:{pass_nr}"

  @staticmethod
  def events_field(job_id, pass_nr):
    return f"events:{job_id}:{pass_nr}"

  def read(self):
    """The whole hkey: `{"checkpoint", "entries": {(job, nr): entry}, "events": {(job, nr): list},
    "rebuilding"}`. Tombstones are skipped; an invalid field fails the read."""
    try:
      raw = self._owner.chainstore_hgetall(hkey=self.hkey) or {}
    except Exception as exc:
      raise LedgerStoreError("Ledger cannot be read") from exc
    snapshot = {"checkpoint": None, "entries": {}, "events": {}, "rebuilding": None}
    for field, value in raw.items():
      if value is None:
        continue
      if field == CHECKPOINT_FIELD:
        snapshot["checkpoint"] = validate_checkpoint(value)
      elif field == REBUILDING_FIELD:
        snapshot["rebuilding"] = value
      else:
        match = _PASS_FIELD.fullmatch(field) if isinstance(field, str) else None
        if match is None:
          raise LedgerStoreError("Invalid ledger field")
        key = (match.group(2), int(match.group(3)))
        if match.group(1) == "pass":
          snapshot["entries"][key] = validate_pass_entry(value)
        else:
          snapshot["events"][key] = validate_events(value)
    return snapshot

  def _get(self, field):
    try:
      return self._owner.chainstore_hget(hkey=self.hkey, key=field)
    except Exception as exc:
      raise LedgerStoreError("Ledger cannot be read") from exc

  def rebuilding(self):
    return self._get(REBUILDING_FIELD)

  def checkpoint(self):
    value = self._get(CHECKPOINT_FIELD)
    return None if value is None else validate_checkpoint(value)

  def entry(self, job_id, pass_nr):
    value = self._get(self.pass_field(job_id, pass_nr))
    return None if value is None else validate_pass_entry(value)

  def _put(self, field, value):
    try:
      written = self._owner.chainstore_hset(hkey=self.hkey, key=field, value=value)
    except Exception as exc:
      raise LedgerStoreError("Ledger write could not be verified") from exc
    if written is not True or self._get(field) != value:
      raise LedgerStoreError("Ledger write could not be verified")

  def put_entry(self, job_id, pass_nr, entry):
    """Write-once; a real entry may replace a `skipped` one (§2.1). Returns False when an entry stays."""
    validate_pass_entry(entry)
    current = self.entry(job_id, pass_nr)
    if current is not None and (entry.get("skipped") or not current.get("skipped")):
      return False
    self._put(self.pass_field(job_id, pass_nr), entry)
    return True

  def put_events(self, job_id, pass_nr, events):
    self._put(self.events_field(job_id, pass_nr), validate_events(events) if events else None)

  def put_checkpoint(self, checkpoint):
    self._put(CHECKPOINT_FIELD, validate_checkpoint(checkpoint))

  def purge(self, artifacts):
    """Tenant delete (§2.1): read the hkey once, delete the pass-changes artifacts its pass entries
    list, then tombstone every field. Raw fields, so an invalid one never blocks the delete. A file
    whose delete is not confirmed but that no longer reads counts as gone (a retried delete)."""
    try:
      raw = self._owner.chainstore_hgetall(hkey=self.hkey) or {}
    except Exception as exc:
      raise LedgerStoreError("Ledger cannot be read") from exc
    cids = sorted({value["pass_changes_cid"] for field, value in raw.items()
                   if isinstance(field, str) and field.startswith("pass:") and isinstance(value, dict)
                   and isinstance(value.get("pass_changes_cid"), str) and value["pass_changes_cid"]})
    for cid in cids:
      if artifacts.delete(cid, show_logs=False, raise_on_error=False, purge=True) is not True \
          and artifacts.get_json(cid) is not None:
        raise LedgerStoreError("Pass-changes artifact could not be deleted")
    for field, value in raw.items():
      if value is not None:
        self._put(field, None)
    return len(cids)


def log_lost(owner, hkey, result):
  if result.lost:
    owner.P(f"[LEDGER] {hkey}: {len(result.lost)} pass-changes artifact(s) unreadable for over 24 hours; "
            "declared lost and folded as skipped",
            color='y')


class EngagementLedgerRecorder:
  """The post-pass writes of one job's pass to its engagement asset ledger (launcher only)."""

  def __init__(self, owner, store, scan_type):
    self._owner = owner
    self.store = store
    self.scan_type = scan_type

  @classmethod
  def for_job(cls, owner, job_specs):
    """The recorder for a job, or None when the pass writes nothing: no engagement binding, a scan type
    the ledger does not take (model tests), a tenant marked deleting, or an engagement record gone."""
    binding = binding_from_record(job_specs)
    scan_type = job_specs.get("scan_type") or "network"
    if binding is None or scan_type not in LEDGER_SCAN_TYPES:
      return None
    facts = binding.to_dict()
    tenancy = CstoreTenantAdministrationStore(owner, facts["namespace"])
    tenant = tenancy.raw_record("tenant", facts["tenant_id"])
    if tenant is None or isinstance(tenant.get("deleting"), dict):
      return None
    if tenancy.raw_record("engagement", facts["tenant_id"], facts["engagement_id"]) is None:
      return None
    store = EngagementLedgerStore(owner, facts["namespace"], facts["tenant_id"], facts["engagement_id"],
                                  facts["engagement_asset_id"])
    return cls(owner, store, scan_type)

  def store_pass_changes(self, artifacts, **facts):
    """Write the pass-changes artifact to R1FS; returns its CID."""
    cid = artifacts.put_json(pass_changes(scan_type=self.scan_type, **facts), show_logs=False)
    if not cid:
      raise LedgerStoreError("Pass-changes artifact could not be stored")
    return cid

  def record_pass(self, artifacts, *, job_id, pass_nr, date_completed, pass_report_cid, pass_changes_cid):
    """Write the pass entry once (marked `late` against the checkpoint read just before), then fold."""
    checkpoint = self.store.checkpoint()
    through = (checkpoint or {}).get("through")
    self.store.put_entry(job_id, pass_nr, {
      "date_completed": date_completed, "scan_type": self.scan_type, "pass_report_cid": pass_report_cid,
      "pass_changes_cid": pass_changes_cid, "late": through is not None and date_completed < through,
    })
    if self.store.rebuilding() is not None:
      return  # §5.3: a rebuild applies the deferred passes itself
    if self.fold_and_write(artifacts) and not covers(self.store.checkpoint(), self._last_written):
      self.fold_and_write(artifacts)  # one repair after a checkpoint replaced ours

  def record_skipped(self, *, job_id, pass_nr, date_completed=None):
    """A pass with no stored report, or whose hook failed: a `skipped` entry, only when none exists."""
    entry = {"skipped": True}
    if date_completed is not None:
      entry["date_completed"] = date_completed
    return self.store.put_entry(job_id, pass_nr, entry)

  def maintain(self, artifacts, now):
    """Data maintenance for one asset (§2.1): write `skipped` for every missing pass of a job once a
    later pass of that job has had an entry for 24 hours, then fold with no replay cap and write the
    result when it differs from the stored checkpoint. Only here may an artifact be declared lost: one
    that reads as None for a pass completed over 24 hours ago is folded as skipped; a younger one fails
    the fold as transient. Returns `(skipped_filled, written)`."""
    snapshot = self.store.read()
    if snapshot["rebuilding"] is not None:
      return 0, False
    filled = 0
    entries = snapshot["entries"]
    for job_id in sorted({job for job, _ in entries}):
      numbers = sorted(nr for job, nr in entries if job == job_id)
      aged = [nr for nr in numbers if _number(entries[(job_id, nr)].get("date_completed"))
              and now - entries[(job_id, nr)]["date_completed"] >= SKIPPED_FILL_AFTER]
      for pass_nr in range(1, max(aged, default=0)):
        if (job_id, pass_nr) not in entries:
          filled += bool(self.record_skipped(job_id=job_id, pass_nr=pass_nr))
    snapshot = self.store.read()
    if not snapshot["entries"]:
      return filled, False
    may_lose = lambda entry: now - entry["date_completed"] >= SKIPPED_FILL_AFTER
    result = fold(snapshot["checkpoint"], snapshot["entries"], artifact_loader(artifacts),
                  asset_id=self.store.engagement_asset_id, read_cap=None, may_lose=may_lose)
    if result.checkpoint == snapshot["checkpoint"]:
      return filled, False
    return filled, self.fold_and_write(artifacts, read_cap=None, folded=(snapshot, result), may_lose=may_lose)

  def fold_and_write(self, artifacts, read_cap=REPLAY_READ_CAP, folded=None, may_lose=None):
    """Fold, re-read the checkpoint and fold again on a newer one (at most 3 times), then write the
    folded passes' events and the checkpoint. `folded` is a `(snapshot, result)` the caller already
    computed, used as the first attempt. False when nothing was written (a pending replay)."""
    load = artifact_loader(artifacts)
    for attempt in range(_FOLD_ATTEMPTS):
      if attempt == 0 and folded is not None:
        snapshot, result = folded
      else:
        snapshot = self.store.read()
        result = fold(snapshot["checkpoint"], snapshot["entries"], load,
                      asset_id=self.store.engagement_asset_id, read_cap=read_cap, may_lose=may_lose)
      log_lost(self._owner, self.store.hkey, result)
      if result.pending:
        self._owner.P(f"[LEDGER] {self.store.hkey}: replay over {REPLAY_READ_CAP} reads left to data maintenance",
                      color='y')
        return False
      if covers(result.checkpoint, self.store.checkpoint()):
        break
    else:
      return False
    for (job_id, pass_nr), events in result.events.items():
      if events or (job_id, pass_nr) in snapshot["events"]:
        self.store.put_events(job_id, pass_nr, events)
    self.store.put_checkpoint(result.checkpoint)
    self._last_written = result.checkpoint
    return True
