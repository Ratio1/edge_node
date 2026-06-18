"""Model Testing artifact serializers.

Model-test payloads deliberately avoid the scan JobConfig/JobArchive
dataclasses. They share CStore/R1FS plumbing, but their schema is separate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ..models.shared import _strip_none


MODEL_TEST_JOB_CONFIG_SCHEMA = "model_test_job_config_v1"
MODEL_TEST_ARCHIVE_SCHEMA = "model_test_archive_v1"
MODEL_TEST_WORKER_RESULT_SCHEMA = "model_test_worker_result_v1"


@dataclass(frozen=True)
class ModelTestJobConfig:
  schema_version: str
  job_type: str
  task_name: str
  task_description: str
  created_by_name: str
  created_by_id: str
  test_set_id: str
  tested_model: dict
  evaluator_model: dict
  limits: dict
  raw_evidence: dict
  selected_peers: list
  model_test_node_selection: dict
  job_id: str = ""
  scan_type: str = "model_test"

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> ModelTestJobConfig:
    return cls(
      schema_version=d.get("schema_version", MODEL_TEST_JOB_CONFIG_SCHEMA),
      job_type=d["job_type"],
      scan_type=d.get("scan_type", "model_test"),
      job_id=d.get("job_id", ""),
      task_name=d.get("task_name", ""),
      task_description=d.get("task_description", ""),
      created_by_name=d.get("created_by_name", ""),
      created_by_id=d.get("created_by_id", ""),
      test_set_id=d.get("test_set_id", ""),
      tested_model=dict(d.get("tested_model") or {}),
      evaluator_model=dict(d.get("evaluator_model") or {}),
      limits=dict(d.get("limits") or {}),
      raw_evidence=dict(d.get("raw_evidence") or {}),
      selected_peers=list(d.get("selected_peers") or []),
      model_test_node_selection=dict(d.get("model_test_node_selection") or {}),
    )


@dataclass(frozen=True)
class ModelTestWorkerResult:
  job_id: str
  worker_addr: str
  status: str
  model_test_results: dict
  model_test_summary: dict
  schema_version: str = MODEL_TEST_WORKER_RESULT_SCHEMA
  started_at: float = None
  completed_at: float = None
  error_class: str = None
  error_message: str = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> ModelTestWorkerResult:
    return cls(
      schema_version=d.get("schema_version", MODEL_TEST_WORKER_RESULT_SCHEMA),
      job_id=d["job_id"],
      worker_addr=d["worker_addr"],
      status=d.get("status", "unknown"),
      model_test_results=dict(d.get("model_test_results") or {}),
      model_test_summary=dict(d.get("model_test_summary") or {}),
      started_at=d.get("started_at"),
      completed_at=d.get("completed_at"),
      error_class=d.get("error_class"),
      error_message=d.get("error_message"),
    )


@dataclass(frozen=True)
class ModelTestArchive:
  job_id: str
  job_type: str
  job_config: dict
  timeline: list
  model_test_results: dict
  model_test_summary: dict
  model_test_node_selection: dict
  ui_aggregate: dict
  duration: float
  date_created: float
  date_completed: float
  schema_version: str = MODEL_TEST_ARCHIVE_SCHEMA
  archive_version: int = 1

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> ModelTestArchive:
    return cls(
      schema_version=d.get("schema_version", MODEL_TEST_ARCHIVE_SCHEMA),
      archive_version=d.get("archive_version", 1),
      job_id=d["job_id"],
      job_type=d.get("job_type", "model_test"),
      job_config=dict(d.get("job_config") or {}),
      timeline=list(d.get("timeline") or []),
      model_test_results=dict(d.get("model_test_results") or {}),
      model_test_summary=dict(d.get("model_test_summary") or {}),
      model_test_node_selection=dict(d.get("model_test_node_selection") or {}),
      ui_aggregate=dict(d.get("ui_aggregate") or {}),
      duration=d.get("duration", 0),
      date_created=d.get("date_created", 0),
      date_completed=d.get("date_completed", 0),
    )


class ModelTestArtifactRepository:
  """R1FS helper for model-test-specific JSON artifacts."""

  def __init__(self, owner):
    self.owner = owner

  def put_json(self, payload, *, show_logs=False, secret=None):
    if secret:
      return self.owner.r1fs.add_json(payload, show_logs=show_logs, secret=secret)
    return self.owner.r1fs.add_json(payload, show_logs=show_logs)

  def get_json(self, cid, *, secret=None):
    if not cid:
      return None
    if secret:
      return self.owner.r1fs.get_json(cid, secret=secret)
    return self.owner.r1fs.get_json(cid)

  def put_job_config(self, job_config, *, show_logs=False):
    payload = (
      job_config.to_dict()
      if isinstance(job_config, ModelTestJobConfig)
      else ModelTestJobConfig.from_dict(job_config).to_dict()
    )
    return self.put_json(payload, show_logs=show_logs)

  def put_worker_result(self, worker_result, *, show_logs=False):
    payload = (
      worker_result.to_dict()
      if isinstance(worker_result, ModelTestWorkerResult)
      else ModelTestWorkerResult.from_dict(worker_result).to_dict()
    )
    return self.put_json(payload, show_logs=show_logs)

  def put_archive(self, archive, *, show_logs=False):
    payload = (
      archive.to_dict()
      if isinstance(archive, ModelTestArchive)
      else ModelTestArchive.from_dict(archive).to_dict()
    )
    return self.put_json(payload, show_logs=show_logs)
