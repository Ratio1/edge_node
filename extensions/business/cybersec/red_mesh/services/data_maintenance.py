"""RM-108. Temporary data maintenance: one inventory for backup, old-format cleanup and restore.

Remove this module, its endpoints and its tests when RedMesh has versioned migrations. Nothing
permanent imports it.

The inventory starts from a fixed registry of hkeys (CStore hashes hkey names, so they cannot be
listed), classifies every row as current, old, orphan or tombstone, and follows the file
references a row carries. A row is current only under the rule of its hkey
(docs: contracts/data-maintenance.md, Classification); the rule checks identity and format
version, never every field, so a current row is not deleted because an optional model rejects it.

Files are read and written through the node's `ipfs` binary, not the R1FS engine: the engine
encrypts on every add with a random nonce under a random file name, so it can neither return the
stored bytes nor give a restored file its old CID.
"""
import base64
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import re
import subprocess
import tempfile

from ..constants import JOB_STATUS_FAILED, JOB_STATUS_FINALIZED, JOB_STATUS_STOPPED
from ..tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from ..tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from ..tenancy.execution import BINDING_SCHEMA_VERSION, ExecutionBinding
from .integration_status import _STATUS_BUILDERS


CURRENT, OLD, ORPHAN, TOMBSTONE = "current", "old", "orphan", "tombstone"
BACKUP_SCHEMA = "redmesh.backup/1"
MAX_PAGE = 50
MAX_TARGETS = 100
MAX_FILE_BYTES = 50 * 1024 * 1024
IPFS_TIMEOUT = 60
# Files a row's own files point to are read to find more references; a job has a handful.
MAX_NESTED_READS = 256

_TERMINAL = (JOB_STATUS_FINALIZED, JOB_STATUS_STOPPED, JOB_STATUS_FAILED)
_CID = re.compile(r"(?:Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})\Z")
_FILENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}\Z")
_TENANT_STATUS_HKEY = re.compile(r":integrations:(tn_[0-9a-f-]{36})\Z")
# Keys that hold a file reference. `ref` is a tenant document; `cid` a rulebook submission.
_REFERENCE_KEYS = frozenset({"cid", "ref", "secret_ref", "model_provider_secret_ref", "authorization_ref"})
# Per-job hkeys: suffix, the stored value type, and whether the field is `<job_id>:<rest>`.
_PER_JOB = (
  (":live", dict, True),
  (":triage", dict, True),
  (":triage:audit", list, True),
  (":model_test_raw_evidence", dict, False),
  (":rulebook_review", dict, True),
  (":rulebook_review:audit", list, True),
  (":rulebook_review:submissions", dict, True),
  (":report_review", dict, True),
  (":report_review:audit", list, False),
)
_TENANCY_KINDS = ("tenant", "receipt", "domain", "tenant_node", "integration", "engagement", "tenant_draft")
# Graybox credentials that job configs held inline before they moved to an encrypted secret file.
# Such a config is stored under the engine's fixed default secret, so its bytes are as good as
# plaintext: it is withheld from the backup (owner, 2026-09-29: no plaintext credential leaves the node).
_INLINE_CREDENTIALS = frozenset({
  "official_password", "regular_password", "bearer_token", "api_key", "bearer_refresh_token",
  "regular_bearer_token", "regular_api_key", "regular_bearer_refresh_token", "gateway_api_key",
  "gateway_bearer_token", "gateway_bearer_refresh_token", "target_config_secrets", "weak_candidates"})
_ENGAGEMENT_V1_FIELDS = ("engagement_kind", "roe_document", "authorization_document")


class MaintenanceError(Exception):
  def __init__(self, status_code, code):
    super().__init__(code)
    self.status_code = status_code
    self.code = code


def valid_cid(value):
  return isinstance(value, str) and _CID.match(value) is not None


def row_sha256(value):
  """The hash the operator saw: over the canonical JSON of the stored value."""
  text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
  return hashlib.sha256(text.encode("utf-8")).hexdigest()


def references(value, path=""):
  """Every file reference inside a stored value, as (cid, role). Explicit keys only."""
  if isinstance(value, dict):
    for key, item in value.items():
      role = f"{path}.{key}" if path else str(key)
      if (isinstance(key, str) and (key.endswith("_cid") or key in _REFERENCE_KEYS)
          and isinstance(item, str)):
        if valid_cid(item):
          yield item, role
      elif isinstance(key, str) and key.endswith("_cids") and isinstance(item, list):
        for index, entry in enumerate(item):
          if valid_cid(entry):
            yield entry, f"{role}[{index}]"
      else:
        yield from references(item, role)
  elif isinstance(value, (list, tuple)):
    for index, item in enumerate(value):
      yield from references(item, f"{path}[{index}]")


class Inventory:
  """One read of the stores. Built per request; nothing is cached between requests."""

  def __init__(self, owner, namespace, read_json, pinned=None):
    self._owner = owner
    # cid -> True (pinned here), False (definitely not pinned: gone), None (cannot tell).
    self._pinned = pinned or (lambda cid: None)
    # Referenced files that are no longer on the node: left out of every file list, so they are
    # neither backed up nor deleted. What only they referenced is not found.
    self.gone = set()
    self._instance = owner.cfg_instance_id
    self._store = CstoreTenantAdministrationStore(owner, namespace)
    self._namespace = namespace
    self._read_json = read_json
    self._tenancy_hkey = json.dumps(["redmesh", "tenancy", 1, namespace], separators=(",", ":"))
    self._account_hkey = CstoreAuthAccountReader(owner)._hkey()
    self._rows = {}
    self._files = {}
    self._tenancy = None
    self._live = None
    # Files are content-addressed: one read per CID per request, whatever asks for it.
    self._json = {}
    self._withheld = set()
    self._kept = None
    # Files the job-reading walk opened: a cleanup deletes them last, so a failure part-way leaves
    # them readable and the row's file list complete for the retry.
    self._containers = set()
    self._tenants = None
    # Files this request deleted: another old row that shares one does not delete it again.
    self.deleted = set()

  # -- registry ---------------------------------------------------------------------------------

  def refresh(self, hkey, field, value):
    """Record what a fresh read or a delete found, so the rest of the request sees it."""
    self.rows(hkey)[field] = value
    self._files.pop((hkey, field), None)
    if hkey == self._tenancy_hkey:
      self._tenancy = None
      self._live = None

  def _job_running(self, hkey, field):
    job_id = self.job_of(hkey, field)
    job = self.rows(self._instance).get(job_id) if job_id is not None else None
    return job is not None and not job_is_terminal(job)

  def is_container(self, cid):
    return cid in self._containers

  def instance(self):
    return self._instance

  def job_of(self, hkey, field):
    """The job a row belongs to: the job record itself or a per-job row; None otherwise."""
    if not isinstance(field, str):
      return None
    if hkey == self._instance:
      return field
    for suffix, _, prefixed in _PER_JOB:
      if hkey == self._instance + suffix:
        return field.split(":", 1)[0] if prefixed else field
    return None

  def rows(self, hkey):
    if hkey not in self._rows:
      rows = self._owner.chainstore_hgetall(hkey=hkey)
      if rows is None:
        rows = {}
      if not isinstance(rows, dict):
        raise MaintenanceError(503, "unavailable")
      self._rows[hkey] = rows
    return self._rows[hkey]

  def _tenancy_fields(self):
    if self._tenancy is None:
      self._tenancy = []
      for field, value in self.rows(self._tenancy_hkey).items():
        try:
          decoded = json.loads(field) if isinstance(field, str) else None
        except (ValueError, RecursionError):
          decoded = None
        if (isinstance(decoded, list) and len(decoded) >= 3
            and all(isinstance(item, str) for item in decoded) and decoded[1] == self._namespace):
          self._tenancy.append((field, decoded[0], decoded[2:], value))
        else:
          self._tenancy.append((field, None, None, value))
    return self._tenancy

  def tenant_ids(self):
    """Every tenant id a stored row names, present or not: its status hkey may still hold rows.

    Fixed for the request: a row deleted by this request must not take a status hkey out of the
    registry while the request still works on it.
    """
    if self._tenants is not None:
      return self._tenants
    found = set()
    for _, kind, ids, value in self._tenancy_fields():
      if kind in ("tenant", "tenant_node", "integration", "engagement", "asset") and ids:
        found.add(ids[0])
      if kind == "receipt" and isinstance(value, dict) and isinstance(value.get("tenant_id"), str):
        found.add(value["tenant_id"])
    for value in self.rows(self._instance).values():
      binding = value.get("execution_binding") if isinstance(value, dict) else None
      if isinstance(binding, dict) and isinstance(binding.get("tenant_id"), str):
        found.add(binding["tenant_id"])
    self._tenants = sorted(item for item in found if _TENANT_STATUS_HKEY.match(f":integrations:{item}"))
    return self._tenants

  def hkeys(self):
    """The registry, in a stable order. The index into it is the export's paging cursor."""
    names = [self._instance] + [self._instance + suffix for suffix, _, _ in _PER_JOB]
    names.append(f"{self._instance}:integrations")
    names.extend(f"{self._instance}:integrations:{tenant}" for tenant in self.tenant_ids())
    names.extend([self._tenancy_hkey, self._account_hkey])
    return names

  def accepts(self, hkey):
    """Restore writes only into registry hkeys, a deleted tenant's status hkey included."""
    if hkey == self._account_hkey or not isinstance(hkey, str):
      return False
    prefix = f"{self._instance}:integrations:"
    return (hkey in self.hkeys()
            or hkey.startswith(prefix) and _TENANT_STATUS_HKEY.match(hkey[len(self._instance):]) is not None)

  def is_account_hkey(self, hkey):
    return hkey == self._account_hkey

  def is_job_hkey(self, hkey):
    return hkey == self._instance

  # -- classification ---------------------------------------------------------------------------

  def _job_class(self, field, value):
    if not isinstance(value, dict):
      return OLD, "unrecognized"
    if "execution_binding" not in value:
      return OLD, "unbound_job"
    binding = value["execution_binding"]
    if isinstance(binding, dict) and binding.get("schema_version") == 1:
      return OLD, "binding_schema_1"
    try:
      if ExecutionBinding(binding).to_dict()["schema_version"] != BINDING_SCHEMA_VERSION:
        return OLD, "unrecognized"
    except Exception:
      return OLD, "unrecognized"
    if value.get("job_id") != field:
      return OLD, "legacy_job_key"
    return CURRENT, ""

  def _per_job_class(self, field, value, kind, prefixed):
    job_id = field.split(":", 1)[0] if prefixed and isinstance(field, str) else field
    job = self.rows(self._instance).get(job_id)
    if job is None:
      return ORPHAN, "job_gone"
    if self._job_class(job_id, job)[0] != CURRENT:
      return OLD, "old_job"
    return (CURRENT, "") if isinstance(value, kind) else (OLD, "unrecognized")

  def _live_tenants(self):
    if self._live is None:
      self._live = {ids[0] for field, kind, ids, value in self._tenancy_fields()
                    if kind == "tenant" and value is not None and len(ids) == 1
                    and self._tenancy_class(field, kind, ids, value, related=False)[0] == CURRENT}
    return self._live

  def _tenancy_class(self, field, kind, ids, value, related=True):
    if kind == "asset":
      return OLD, "asset_row"
    if kind not in _TENANCY_KINDS:
      return OLD, "unrecognized"
    if kind == "tenant" and isinstance(value, dict) and "kind" not in value and "ids" not in value:
      return OLD, "foundation_projection"
    if kind == "engagement" and isinstance(value, dict) and any(
        name in value for name in _ENGAGEMENT_V1_FIELDS):
      return OLD, "engagement_v1"
    try:
      if field != self._store._location(kind, ids)[1]:
        return OLD, "unrecognized"
      row = self._store._validate(value, kind, ids)
    except Exception:
      return OLD, "unrecognized"
    if kind == "tenant_draft":
      # RM-109: a draft has no tenant; its id is not one, so the related-tenant check below would
      # call every draft an orphan. Current while the store reads it, never orphan or old_tenant.
      return CURRENT, ""
    if kind in ("tenant", "receipt"):
      if not isinstance(row.get("contract"), dict) or not isinstance(row.get("legal"), dict):
        return OLD, "tenant_without_contract"
      if kind == "tenant" and (type(row.get("active")) is not bool
                               or type(row.get("allow_pentester")) is not bool):
        return OLD, "unrecognized"
    if not related or kind in ("tenant", "domain"):
      # A domain reservation outlives its tenant on purpose (`delete_tenant` keeps it).
      return CURRENT, ""
    tenant_id = row.get("tenant_id") if kind == "receipt" else ids[0]
    live = self._live_tenants()
    if tenant_id not in live:
      known = any(k == "tenant" and i == [tenant_id] and v is not None
                  for _, k, i, v in self._tenancy_fields())
      return (OLD, "old_tenant") if known else (ORPHAN, "tenant_gone")
    return CURRENT, ""

  def _status_class(self, hkey, field, value):
    # The stored status row carries no version: it is current when it is a dict under the id of
    # an integration this release has.
    match = _TENANT_STATUS_HKEY.search(hkey)
    if match and match.group(1) not in self._live_tenants():
      stored = any(kind == "tenant" and ids == [match.group(1)] and row is not None
                   for _, kind, ids, row in self._tenancy_fields())
      return (OLD, "old_tenant") if stored else (ORPHAN, "tenant_gone")
    if not isinstance(value, dict) or field not in _STATUS_BUILDERS:
      return OLD, "unrecognized"
    return CURRENT, ""

  def is_status_hkey(self, hkey):
    return isinstance(hkey, str) and hkey.startswith(f"{self._instance}:integrations")

  def classify(self, hkey, field, value):
    if value is None:
      return TOMBSTONE, ""
    if hkey == self._account_hkey:
      return CURRENT, "account"
    if hkey == self._instance:
      return self._job_class(field, value)
    for suffix, kind, prefixed in _PER_JOB:
      if hkey == self._instance + suffix:
        return self._per_job_class(field, value, kind, prefixed)
    if hkey == self._tenancy_hkey:
      for name, kind, ids, _ in self._tenancy_fields():
        if name == field:
          if kind is None:
            return OLD, "unrecognized"
          return self._tenancy_class(field, kind, ids, value)
      return OLD, "unrecognized"
    if self.is_status_hkey(hkey):
      return self._status_class(hkey, field, value)
    raise MaintenanceError(400, "invalid_request")

  # -- files ------------------------------------------------------------------------------------

  def files(self, hkey, field, value):
    """(files, complete): every file the row references, through the files it points to.

    `complete` is False when a file that names further files could not be read. Such a row is not
    backed up as complete and is not cleaned.
    """
    key = (hkey, field)
    if key in self._files:
      return self._files[key]
    found, complete = {}, True
    if value is not None and hkey != self._account_hkey:
      for cid, role in references(value):
        found.setdefault(cid, role)
      self._withheld |= fallback_key_files(value)
      if hkey == self._instance and isinstance(value, dict):
        complete = self._nested(value, found)
    result = ([{"cid": cid, "role": role, "withheld": cid in self._withheld}
               for cid, role in sorted(found.items()) if cid not in self.gone], complete)
    self._files[key] = result
    return result

  def _nested(self, job, found):
    """Follow a job's config, archive and pass reports. Secrets and leaf reports are not read."""
    complete, reads = True, 0
    queue = [(job.get("job_config_cid"), "config"), (job.get("job_cid"), "archive")]
    queue += [(ref.get("report_cid"), "pass") for ref in job.get("pass_reports") or []
              if isinstance(ref, dict)]
    seen = set()
    while queue:
      cid, kind = queue.pop(0)
      if not valid_cid(cid) or cid in seen:
        continue
      seen.add(cid)
      reads += 1
      if reads > MAX_NESTED_READS:
        return False
      payload = self.read_json(cid)
      if not isinstance(payload, dict):
        if self._pinned(cid) is False:
          self.gone.add(cid)
        else:
          complete = False
        continue
      self._containers.add(cid)
      # A job config held graybox credentials inline before they moved to a secret file; an
      # archive embeds the config as it was. Reports are not checked: a finding may name a key.
      config = payload if kind == "config" else payload.get("job_config") if kind == "archive" else None
      if has_inline_credentials(config):
        self._withheld.add(cid)
      self._withheld |= fallback_key_files(payload)
      for nested, role in references(payload, kind):
        found.setdefault(nested, role)
    return complete

  def read_json(self, cid):
    if cid not in self._json:
      try:
        self._json[cid] = self._read_json(cid)
      except Exception:
        self._json[cid] = None
    return self._json[cid]

  def describe(self, hkey, field, value):
    group, reason = self.classify(hkey, field, value)
    files, complete = self.files(hkey, field, value)
    return {"hkey": hkey, "field": field, "value": value, "sha256": row_sha256(value),
            "class": group, "reason": reason, "cids": files, "files_complete": complete}

  def kept_files(self):
    """(files, complete): the files a current row, or any row of a running job, references; a
    cleanup never deletes them.

    Computed once per request. `complete` is False when a current row's file list could not be
    read in full: a file only it names might then be missing here, so nothing with files is
    deleted. An integration status row only remembers the last file it delivered and does not own
    it (`purge_job` deletes such files too), so it keeps nothing.
    """
    if self._kept is None:
      kept, complete = set(), True
      for hkey in self.hkeys():
        if hkey == self._account_hkey or self.is_status_hkey(hkey):
          continue
        for field, value in self.rows(hkey).items():
          if value is None or (self.classify(hkey, field, value)[0] != CURRENT
                               and not self._job_running(hkey, field)):
            continue
          found, whole = self.files(hkey, field, value)
          kept.update(item["cid"] for item in found)
          complete = complete and whole
      self._kept = (kept, complete)
    return self._kept


def has_inline_credentials(value):
  """True when a stored JSON value carries a graybox credential inline (a pre-split job config)."""
  if isinstance(value, dict):
    for key, item in value.items():
      if key in _INLINE_CREDENTIALS and item not in (None, "", [], {}):
        return True
      if has_inline_credentials(item):
        return True
  elif isinstance(value, list):
    return any(has_inline_credentials(item) for item in value)
  return False


# A credential file (or raw model-test evidence) encrypted with the plugin's built-in fallback key,
# which is the same on every node and public in the source: its ciphertext is as good as
# plaintext. The value that points at the file records the fallback beside the pointer.
_FALLBACK_POINTERS = (
  ("secret_store_unsafe_fallback", "secret_ref"),
  ("model_provider_secret_store_unsafe_fallback", "model_provider_secret_ref"),
  ("unsafe_key_fallback", "artifact_cid"),
)


def fallback_key_files(value):
  """CIDs a stored value points at that are encrypted with the built-in fallback key."""
  found = set()
  if isinstance(value, dict):
    for flag, pointer in _FALLBACK_POINTERS:
      if value.get(flag) is True and valid_cid(value.get(pointer)):
        found.add(value[pointer])
    for item in value.values():
      found |= fallback_key_files(item)
  elif isinstance(value, list):
    for item in value:
      found |= fallback_key_files(item)
  return found


def job_is_terminal(value):
  return isinstance(value, dict) and value.get("job_status") in _TERMINAL


# -- raw files -----------------------------------------------------------------------------------

def _ipfs(arguments, ipfs_home, *, cwd=None, timeout=IPFS_TIMEOUT):
  environment = dict(os.environ)
  if ipfs_home:
    environment["IPFS_PATH"] = ipfs_home
  try:
    done = subprocess.run(["ipfs", *arguments], cwd=cwd, env=environment, timeout=timeout,
                          capture_output=True, check=False)
  except (OSError, subprocess.SubprocessError):
    raise MaintenanceError(503, "file_unavailable") from None
  if done.returncode != 0:
    raise MaintenanceError(503, "file_unavailable")
  return done.stdout.decode("utf-8", errors="replace")


def pinned_locally(cid, ipfs_home):
  """True when the node pins the file, False when `ipfs` says it does not, None otherwise."""
  if not valid_cid(cid):
    return None
  environment = dict(os.environ)
  if ipfs_home:
    environment["IPFS_PATH"] = ipfs_home
  try:
    done = subprocess.run(["ipfs", "pin", "ls", "--type=recursive", "--", cid], env=environment,
                          timeout=IPFS_TIMEOUT, capture_output=True, check=False)
  except (OSError, subprocess.SubprocessError):
    return None
  if done.returncode == 0 and cid.encode() in done.stdout:
    return True
  if done.returncode != 0 and b"is not pinned" in done.stderr:
    return False
  return None


def read_stored_file(cid, ipfs_home):
  """The stored bytes and file name of one R1FS file (a directory wrapping one file)."""
  if not valid_cid(cid):
    raise MaintenanceError(400, "invalid_request")
  entries = [line.split() for line in _ipfs(["ls", "--", cid], ipfs_home).splitlines() if line.strip()]
  if len(entries) != 1 or len(entries[0]) != 3 or not _FILENAME.match(entries[0][2]):
    raise MaintenanceError(503, "file_unavailable")
  _, size, filename = entries[0]
  if not size.isdigit() or int(size) > MAX_FILE_BYTES:
    raise MaintenanceError(413, "file_too_large")
  with tempfile.TemporaryDirectory(prefix="redmesh-export-") as folder:
    _ipfs(["get", "-o", "file", "--", f"{cid}/{filename}"], ipfs_home, cwd=folder)
    path = os.path.join(folder, "file")
    if not os.path.isfile(path) or os.path.islink(path) or os.path.getsize(path) > MAX_FILE_BYTES:
      raise MaintenanceError(503, "file_unavailable")
    with open(path, "rb") as handle:
      data = handle.read()
  return {"cid": cid, "filename": filename, "content_b64": base64.b64encode(data).decode("ascii"),
          "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


def write_stored_file(cid, filename, content_b64, sha256, ipfs_home):
  """Add the bytes back under their file name, only when that gives the CID the records hold."""
  if (not valid_cid(cid) or not isinstance(filename, str) or not _FILENAME.match(filename)
      or not isinstance(content_b64, str) or not isinstance(sha256, str)):
    raise MaintenanceError(400, "invalid_request")
  try:
    data = base64.b64decode(content_b64, validate=True)
  except (ValueError, TypeError):
    raise MaintenanceError(400, "invalid_request") from None
  if len(data) > MAX_FILE_BYTES:
    raise MaintenanceError(413, "file_too_large")
  if hashlib.sha256(data).hexdigest() != sha256:
    raise MaintenanceError(400, "hash_mismatch")
  with tempfile.TemporaryDirectory(prefix="redmesh-restore-") as folder:
    with open(os.path.join(folder, filename), "wb") as handle:
      handle.write(data)
    computed = _ipfs(["add", "-q", "-w", "--only-hash", "--", filename], ipfs_home, cwd=folder)
    if (computed.strip().splitlines() or [""])[-1].strip() != cid:
      raise MaintenanceError(409, "cid_mismatch")
    added = _ipfs(["add", "-q", "-w", "--", filename], ipfs_home, cwd=folder)
    if (added.strip().splitlines() or [""])[-1].strip() != cid:
      raise MaintenanceError(409, "cid_mismatch")
  return {"cid": cid, "outcome": "written"}


# -- operations ----------------------------------------------------------------------------------

def export_records(inventory, hkey_index, offset, limit):
  hkeys = inventory.hkeys()
  if (type(hkey_index) is not int or type(offset) is not int or type(limit) is not int
      or not 0 <= hkey_index < len(hkeys) or offset < 0 or not 1 <= limit <= MAX_PAGE):
    raise MaintenanceError(400, "invalid_request")
  hkey = hkeys[hkey_index]
  fields = sorted(inventory.rows(hkey), key=str)
  page = fields[offset:offset + limit]
  following = None
  if offset + limit < len(fields):
    following = {"hkey_index": hkey_index, "offset": offset + limit}
  elif hkey_index + 1 < len(hkeys):
    following = {"hkey_index": hkey_index + 1, "offset": 0}
  return {
    "schema": BACKUP_SCHEMA,
    "instance_id": inventory.instance(),
    "hkeys": [{"index": index, "hkey": name, "total": len(inventory.rows(name)),
               "account": inventory.is_account_hkey(name)} for index, name in enumerate(hkeys)],
    "rows": [inventory.describe(hkey, field, inventory.rows(hkey)[field]) for field in page],
    "next": following,
  }


def export_file(inventory, hkey, field, cid, ipfs_home):
  """One file of one row. A CID the row does not reference is not served."""
  if not isinstance(hkey, str) or hkey not in inventory.hkeys() or not valid_cid(cid):
    raise MaintenanceError(400, "invalid_request")
  value = inventory.rows(hkey).get(field)
  found = {item["cid"]: item for item in inventory.files(hkey, field, value)[0]}
  if cid not in found:
    raise MaintenanceError(404, "file_not_in_inventory")
  if found[cid]["withheld"]:
    raise MaintenanceError(409, "file_withheld")
  try:
    return read_stored_file(cid, ipfs_home)
  except MaintenanceError as exc:
    if exc.code == "file_unavailable" and pinned_locally(cid, ipfs_home) is False:
      raise MaintenanceError(410, "file_gone") from None
    raise


def _checked_targets(targets):
  if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
    raise MaintenanceError(400, "invalid_request")
  seen = set()
  for target in targets:
    if (not isinstance(target, dict) or set(target) != {"hkey", "field", "expected_sha256"}
        or not all(isinstance(target[name], str) and target[name] for name in target)
        or (target["hkey"], target["field"]) in seen):
      raise MaintenanceError(400, "invalid_request")
    seen.add((target["hkey"], target["field"]))
  return targets


def cleanup(owner, inventory, targets, delete_file, job_lock):
  """Delete rows that are still old or orphan and unchanged since the operator's scan.

  Each target is exactly one row: a job's other rows are targets of their own, each with the hash
  the operator saw. `delete_file(cid)` returns True when the file is gone; `job_lock(job_id)` is
  the context manager `purge_job` serializes on, held for every row of a job.
  """
  targets = _checked_targets(targets)
  outcomes = []
  for target in targets:
    hkey, field = target["hkey"], target["field"]
    if hkey not in inventory.hkeys() or inventory.is_account_hkey(hkey):
      outcomes.append({"hkey": hkey, "field": field, "outcome": "refused",
                       "files_deleted": 0, "files_kept": 0, "files_unverified": 0})
      continue
    job_id = inventory.job_of(hkey, field)
    if job_id is None:
      outcomes.append(_clean_row(owner, inventory, target, delete_file))
    else:
      with job_lock(job_id):
        outcomes.append(_clean_row(owner, inventory, target, delete_file, job_id=job_id))
  return {"outcomes": outcomes}


def _clean_row(owner, inventory, target, delete_file, job_id=None):
  hkey, field = target["hkey"], target["field"]
  result = {"hkey": hkey, "field": field, "outcome": "deleted", "files_deleted": 0, "files_kept": 0,
            "files_unverified": 0}
  value = owner.chainstore_hget(hkey=hkey, key=field)
  inventory.refresh(hkey, field, value)
  if value is None:
    return {**result, "outcome": "absent"}
  if row_sha256(value) != target["expected_sha256"]:
    return {**result, "outcome": "changed"}
  if inventory.classify(hkey, field, value)[0] not in (OLD, ORPHAN):
    return {**result, "outcome": "not_old"}
  if job_id is not None:
    job = owner.chainstore_hget(hkey=inventory.instance(), key=job_id)
    if job is not None and not job_is_terminal(job):
      return {**result, "outcome": "running"}
  found, complete = inventory.files(hkey, field, value)
  if not complete:
    return {**result, "outcome": "files_unknown"}
  files = {item["cid"] for item in found}
  kept, kept_complete = inventory.kept_files()
  if files and not kept_complete:
    return {**result, "outcome": "files_unknown"}
  result["files_kept"] = len(files & kept)
  # Leaf files first, the config, archive and pass reports last; stop at the first failure.
  for cid in sorted(files - kept, key=lambda item: (inventory.is_container(item), item)):
    if cid in inventory.deleted:
      continue
    try:
      state = delete_file(cid)
    except Exception:
      state = "failed"
    if state not in ("deleted", "unverified"):
      return {**result, "outcome": "partial"}
    inventory.deleted.add(cid)
    result["files_deleted" if state == "deleted" else "files_unverified"] += 1
  owner.chainstore_hset(hkey=hkey, key=field, value=None)
  remaining = owner.chainstore_hget(hkey=hkey, key=field)
  inventory.refresh(hkey, field, remaining)
  if remaining is not None:
    return {**result, "outcome": "resurrected"}
  return result


def restore_records(owner, inventory, rows):
  if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TARGETS:
    raise MaintenanceError(400, "invalid_request")
  outcomes = []
  for row in rows:
    if (not isinstance(row, dict) or set(row) != {"hkey", "field", "value"}
        or not isinstance(row["hkey"], str) or not isinstance(row["field"], str)
        or not row["field"] or row["value"] is None):
      raise MaintenanceError(400, "invalid_request")
  for row in rows:
    hkey, field, value = row["hkey"], row["field"], row["value"]
    outcome = "written"
    if not inventory.accepts(hkey):
      outcome = "refused"
    else:
      stored = owner.chainstore_hget(hkey=hkey, key=field)
      if stored is not None:
        outcome = "same" if row_sha256(stored) == row_sha256(value) else "conflict"
      else:
        owner.chainstore_hset(hkey=hkey, key=field, value=value)
    outcomes.append({"hkey": hkey, "field": field, "outcome": outcome})
  return {"outcomes": outcomes}


# -- endpoint glue -------------------------------------------------------------------------------

@contextmanager
def _purge_lock(owner, job_id):
  """The locks `purge_job` holds: every rulebook review mutation of the job waits."""
  from .rulebook_assessment import _submission_lock, list_rulebook_profiles
  with ExitStack() as stack:
    for profile in sorted(list_rulebook_profiles(), key=lambda item: item["profile_id"]):
      stack.enter_context(_submission_lock(owner, job_id, profile["profile_id"]))
    yield


def run(owner, namespace, operation, **arguments):
  """One authorized maintenance call, in the tenant-administration envelope."""
  def ipfs_home():
    return getattr(getattr(owner, "r1fs", None), "ipfs_home", None) or os.environ.get("IPFS_PATH")

  def pinned(cid):
    return pinned_locally(cid, ipfs_home())

  def inventory():
    return Inventory(owner, namespace, owner._get_artifact_repository().get_json, pinned)

  def delete_file(cid):
    """`deleted`, `unverified` (gone from this node, the relay's unpin was not confirmed: a file an
    earlier cleanup deleted, one only this node held, or a relay error), or `failed`."""
    if owner._get_artifact_repository().delete(cid, show_logs=False, raise_on_error=False, purge=True) is True:
      return "deleted"
    return "unverified" if pinned(cid) is False else "failed"

  try:
    if operation == "export_records":
      data = export_records(inventory(), **arguments)
    elif operation == "export_file":
      data = export_file(inventory(), ipfs_home=ipfs_home(), **arguments)
    elif operation == "cleanup":
      if arguments.pop("confirm", None) is not True:
        raise MaintenanceError(400, "invalid_request")
      data = cleanup(owner, inventory(), arguments["targets"], delete_file,
                     lambda job_id: _purge_lock(owner, job_id))
    elif operation == "restore_file":
      data = write_stored_file(ipfs_home=ipfs_home(), **arguments)
    elif operation == "restore_records":
      data = restore_records(owner, inventory(), arguments["rows"])
    else:
      raise MaintenanceError(400, "invalid_request")
  except MaintenanceError as exc:
    return {"success": False, "status": "error", "status_code": exc.status_code, "error": exc.code}
  except Exception as exc:
    owner.P(f"[DATA] {operation} failed: {type(exc).__name__}", color='r')
    return {"success": False, "status": "error", "status_code": 503, "error": "unavailable"}
  return {"success": True, "status_code": 200, "data": data}


def audit_counts(outcomes):
  counts = {}
  for item in outcomes:
    counts[item["outcome"]] = counts.get(item["outcome"], 0) + 1
  return counts
