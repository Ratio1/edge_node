"""Checked job artifact integrity, not requester authorization or an authorization lease.

Only explicit producer edges are followed. Each operation is limited to 128 JSON reads and
10,000 reference occurrences; limits fail unavailable rather than returning partial content.
"""
from copy import deepcopy

from .administration import AdministrationDenied
from .execution import binding_from_record
from .ports import TenantStoreError


MAX_ARTIFACT_FETCHES = 128
MAX_ARTIFACT_REFERENCES = 10000


def _unavailable():
  raise TenantStoreError("Tenant job artifacts are unavailable") from None


def _copy(value):
  try:
    return deepcopy(value)
  except Exception:
    _unavailable()


def validate_snapshot_mode(snapshot_mode, *, snapshot_supplied=True):
  """Explicit compatibility mode never selects an unchecked storage fallback."""
  if (not isinstance(snapshot_mode, str) or snapshot_mode not in ("tenant_bound", "legacy_unbound")
      or snapshot_mode == "legacy_unbound" and not snapshot_supplied):
    _unavailable()


def checked_job_snapshot(checked_job, job_id=None, *, snapshot_mode="tenant_bound"):
  """Validate the detached value supplied by the trusted current-reader boundary."""
  validate_snapshot_mode(snapshot_mode)
  snapshot = _copy(checked_job)
  try:
    if (not isinstance(snapshot, dict) or not isinstance(snapshot.get("job_id"), str)
        or not snapshot["job_id"].strip() or job_id is not None and snapshot["job_id"] != job_id):
      _unavailable()
    if (snapshot_mode == "legacy_unbound" and "execution_binding" in snapshot
        or snapshot_mode == "tenant_bound" and binding_from_record(snapshot) is None):
      _unavailable()
  except Exception:
    _unavailable()
  return snapshot


def _cid(value):
  if value is None or value == "":
    return ""
  if not isinstance(value, str) or not value.strip():
    _unavailable()
  return value


def _pass_number(value):
  if type(value) is not int or value < 1:
    _unavailable()
  return value


class TenantJobArtifacts:
  def __init__(self, checked_job, read_json, *, snapshot_mode="tenant_bound"):
    self._job = checked_job_snapshot(checked_job, snapshot_mode=snapshot_mode)
    self._job_id = self._job["job_id"]
    self._binding = binding_from_record(self._job)
    self._worker = None
    if self._binding is not None:
      facts = self._binding.to_dict()
      self._model = facts["asset_target"]["kind"] == "model"
      if self._model and len(facts["participant_order"]) != 1:
        _unavailable()
      self._worker = facts["participant_order"][0] if self._model else None
    else:
      from ..model_testing.constants import is_model_test_job
      self._model = is_model_test_job(self._job)
    self._read_json = read_json
    self._archive_cid = _cid(self._job.get("job_cid"))
    self._config_cid = _cid(self._job.get("job_config_cid"))
    self._references = {}
    self._cache = {}
    self._fetches = 0
    self._reference_count = 0
    self._passes = []
    self._indexed = False
    if self._archive_cid:
      self._count(1)
      self._edge(self._archive_cid, "archive")
    else:
      refs = self._collection(self._job, "pass_reports", list)
      self._count(len(refs))
      for ref in refs:
        if not isinstance(ref, dict):
          _unavailable()
        number = _pass_number(ref.get("pass_nr"))
        cid = self._edge(ref.get("report_cid"), "pass", number)
        self._passes.append((number, cid, None))
      self._workers(self._job, "workers")

  def _count(self, count):
    self._reference_count += count
    if self._reference_count > MAX_ARTIFACT_REFERENCES:
      _unavailable()

  @staticmethod
  def _collection(parent, field, kind):
    value = parent.get(field, kind())
    if not isinstance(value, kind):
      _unavailable()
    return value

  def _edge(self, value, kind, identity=None):
    cid = _cid(value)
    if not cid:
      return ""
    expected = (kind, identity)
    if cid == self._config_cid or cid in self._references and self._references[cid] != expected:
      _unavailable()
    self._references[cid] = expected
    return cid

  def _model_worker(self):
    if self._binding is not None:
      return self._worker
    workers = self._collection(self._job, "workers", dict)
    selection = self._collection(self._job, "model_test_node_selection", dict)
    selected = selection.get("selected_execution_node")
    if (selected is not None and (not isinstance(selected, str) or not selected.strip())
        or len(workers) > 1
        or any(not isinstance(key, str) or not key.strip() or not isinstance(value, dict)
               for key, value in workers.items())):
      _unavailable()
    worker = next(iter(workers), None)
    if worker and selected and worker != selected:
      _unavailable()
    if not (worker or selected):
      _unavailable()
    return worker or selected

  def _workers(self, parent, field):
    workers = self._collection(parent, field, dict)
    self._count(len(workers))
    for address, meta in workers.items():
      if not isinstance(address, str) or not address.strip() or not isinstance(meta, dict):
        _unavailable()
      cid = _cid(meta.get("report_cid"))
      if self._model and cid and address != self._model_worker():
        _unavailable()
      self._edge(cid, "worker", address if self._model else None)

  def _present_identity(self, payload):
    # Local import avoids the model-testing package's service initialization cycle.
    from ..model_testing.raw_evidence import is_restricted_raw_evidence_artifact
    if is_restricted_raw_evidence_artifact(payload):
      _unavailable()
    if "job_id" in payload and payload["job_id"] != self._job_id:
      _unavailable()
    if "execution_binding" in payload:
      try:
        if binding_from_record(payload) != self._binding:
          _unavailable()
      except Exception:
        _unavailable()

  def _pass(self, payload, expected):
    if not isinstance(payload, dict) or _pass_number(payload.get("pass_nr")) != expected:
      _unavailable()
    self._present_identity(payload)
    aggregate = _cid(payload.get("aggregated_report_cid"))
    if aggregate:
      self._count(1)
      self._edge(aggregate, "aggregate")
    self._workers(payload, "worker_reports")

  def _validate_archive(self, payload):
    from ..constants import JOB_ARCHIVE_VERSION
    from ..model_testing.artifacts import MODEL_TEST_ARCHIVE_SCHEMA
    version = payload.get("archive_version", JOB_ARCHIVE_VERSION)
    if type(version) is not int or version != JOB_ARCHIVE_VERSION:
      _unavailable()
    if self._model and payload.get("schema_version", MODEL_TEST_ARCHIVE_SCHEMA) != MODEL_TEST_ARCHIVE_SCHEMA:
      _unavailable()
    config = payload.get("job_config")
    if payload.get("job_id") != self._job_id or not isinstance(config, dict):
      _unavailable()
    try:
      if binding_from_record(config) != self._binding:
        _unavailable()
    except Exception:
      _unavailable()
    if self._model and self._binding is not None and config.get("job_id") != self._job_id:
      _unavailable()
    self._present_identity(config)
    if self._model:
      aggregate = self._collection(payload, "ui_aggregate", dict)
      worker = _cid(aggregate.get("worker_result_cid"))
      if worker:
        self._count(1)
        self._edge(worker, "worker", self._model_worker())
    else:
      passes = self._collection(payload, "passes", list)
      self._count(len(passes))
      for entry in passes:
        if not isinstance(entry, dict):
          _unavailable()
        number = _pass_number(entry.get("pass_nr"))
        self._pass(entry, number)
        self._passes.append((number, "", entry))

  def _get(self, cid):
    if cid in self._cache:
      return self._cache[cid]
    self._fetches += 1
    if self._fetches > MAX_ARTIFACT_FETCHES:
      _unavailable()
    try:
      payload = _copy(self._read_json(cid))
      if not isinstance(payload, dict):
        _unavailable()
      self._present_identity(payload)
      kind, identity = self._references[cid]
      if kind == "archive":
        self._validate_archive(payload)
      elif kind == "pass":
        self._pass(payload, identity)
      elif kind == "worker":
        if payload.get("job_id") != self._job_id:
          _unavailable()
        if self._model and (payload.get("worker_addr") != identity
            or not isinstance(payload.get("model_test_results"), dict)
            or not isinstance(payload.get("model_test_summary"), dict)):
          _unavailable()
        if self._model:
          from ..model_testing.artifacts import MODEL_TEST_WORKER_RESULT_SCHEMA
          if payload.get("schema_version", MODEL_TEST_WORKER_RESULT_SCHEMA) != MODEL_TEST_WORKER_RESULT_SCHEMA:
            _unavailable()
      elif kind == "aggregate":
        for field, expected in (("open_ports", list), ("service_info", dict),
                                ("web_tests_info", dict), ("completed_tests", list)):
          if not isinstance(payload.get(field), expected):
            _unavailable()
      self._cache[cid] = payload
      return payload
    except Exception:
      _unavailable()

  def _index(self):
    if self._indexed:
      return
    if self._archive_cid:
      self._get(self._archive_cid)
    else:
      for _, cid, _ in self._passes:
        if not cid:
          _unavailable()
        self._get(cid)
    self._indexed = True

  def archive(self):
    """Internal raw archive; the query layer owns its safe public serialization."""
    if not self._archive_cid:
      return None
    return _copy(self._get(self._archive_cid))

  def report(self, cid):
    if not isinstance(cid, str) or not cid.strip() or cid in (self._archive_cid, self._config_cid):
      raise AdministrationDenied(404, "not_found")
    self._index()
    if cid not in self._references or self._references[cid][0] not in ("pass", "aggregate", "worker"):
      raise AdministrationDenied(404, "not_found")
    return _copy(self._get(cid))

  def analysis_pass(self, pass_nr=None, cid=""):
    if (pass_nr is not None and (type(pass_nr) is not int or pass_nr < 1)
        or not isinstance(cid, str)):
      raise AdministrationDenied(404, "not_found")
    self._index()
    if not self._passes or self._archive_cid and cid:
      raise AdministrationDenied(404, "not_found")
    matches = [entry for entry in self._passes
               if (pass_nr is None or entry[0] == pass_nr) and (not cid or entry[1] == cid)]
    if not matches:
      raise AdministrationDenied(404, "not_found")
    _, report_cid, inline = matches[-1]
    payload = inline if self._archive_cid else self._get(report_cid)
    return {"pass": _copy(payload),
            "report_cid": payload.get("aggregated_report_cid") if self._archive_cid else report_cid,
            "total_passes": len(self._passes), "archived": bool(self._archive_cid)}
