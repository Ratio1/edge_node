"""
CStore models — ephemeral orchestration state.

  CStoreWorker       — worker entry during job execution
  PassReportRef      — lightweight pass index entry
  CStoreJobRunning   — full CStore state while job is active
  CStoreJobFinalized — pruned CStore stub after close
  WorkerProgress     — real-time progress (separate hset)
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

from extensions.business.cybersec.red_mesh.models.shared import _strip_none
from extensions.business.cybersec.red_mesh.model_test_sanitization import (
  MODEL_TEST_JOB_TYPE,
  MODEL_TEST_PROGRESS_SCHEMA,
  sanitize_model_test_error_class,
  sanitize_model_test_results,
  sanitize_model_test_summary,
  sanitize_raw_evidence_metadata,
)


def _sanitize_raw_evidence_if_present(metadata):
  if not isinstance(metadata, dict):
    return None
  return sanitize_raw_evidence_metadata(metadata)


@dataclass(frozen=True)
class CStoreWorker:
  """
  Launcher-owned worker assignment state in CStore during job execution.

  Runtime liveness belongs in the separate ``:live`` namespace. The main job
  record keeps durable orchestration metadata such as assignment revisions,
  retry tracking, and final report references.
  """
  start_port: int
  end_port: int
  finished: bool = False
  canceled: bool = False
  report_cid: str = None
  result: dict = None               # fallback: inline report if R1FS is down
  assignment_revision: int = 1
  assigned_at: float = None
  reannounce_count: int = 0
  last_reannounce_at: float = None
  retry_reason: str = None
  terminal_reason: str = None
  error: str = None
  unreachable_at: float = None
  graybox_assignment_strategy: str = None
  assigned_scenario_ids: list = None
  assigned_request_budget: int = None
  budget_scope: str = None
  assignment_hash: str = None
  stateful_policy: str = None
  worker_type: str = None
  model_test_worker_status: str = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> CStoreWorker:
    return cls(
      start_port=d["start_port"],
      end_port=d["end_port"],
      finished=d.get("finished", False),
      canceled=d.get("canceled", False),
      report_cid=d.get("report_cid"),
      result=d.get("result"),
      assignment_revision=d.get("assignment_revision", 1),
      assigned_at=d.get("assigned_at"),
      reannounce_count=d.get("reannounce_count", 0),
      last_reannounce_at=d.get("last_reannounce_at"),
      retry_reason=d.get("retry_reason"),
      terminal_reason=d.get("terminal_reason"),
      error=d.get("error"),
      unreachable_at=d.get("unreachable_at"),
      graybox_assignment_strategy=d.get("graybox_assignment_strategy"),
      assigned_scenario_ids=d.get("assigned_scenario_ids"),
      assigned_request_budget=d.get("assigned_request_budget"),
      budget_scope=d.get("budget_scope"),
      assignment_hash=d.get("assignment_hash"),
      stateful_policy=d.get("stateful_policy"),
      worker_type=d.get("worker_type"),
      model_test_worker_status=d.get("model_test_worker_status"),
    )


@dataclass(frozen=True)
class PassReportRef:
  """Lightweight pass index entry stored in CStore."""
  pass_nr: int
  report_cid: str
  risk_score: float = 0

  def to_dict(self) -> dict:
    return asdict(self)

  @classmethod
  def from_dict(cls, d: dict) -> PassReportRef:
    return cls(
      pass_nr=d["pass_nr"],
      report_cid=d["report_cid"],
      risk_score=d.get("risk_score", 0),
    )


@dataclass(frozen=True)
class CStoreJobRunning:
  """
  CStore representation of a running job.

  Contains orchestration state, listing fields, and CID references.
  This is the full working state while the job is active.
  """
  job_id: str
  job_status: str                   # RUNNING | SCHEDULED_FOR_STOP
  job_pass: int
  run_mode: str                     # SINGLEPASS | CONTINUOUS_MONITORING
  launcher: str
  launcher_alias: str
  target: str
  scan_type: str
  target_url: str
  task_name: str
  start_port: int
  end_port: int
  date_created: float
  job_config_cid: str
  workers: dict                     # { addr: CStoreWorker.to_dict() }
  timeline: list                    # [ TimelineEvent.to_dict() ]
  pass_reports: list                # [ PassReportRef.to_dict() ]
  next_pass_at: float = None
  risk_score: float = 0
  job_revision: int = 0
  redmesh_job_start_attestation: dict = None
  last_attestation_at: float = None
  soc_event_status: dict = None
  detection_correlation: dict = None
  stix_export: dict = None
  opencti_export: dict = None
  taxii_export: dict = None
  graybox_assignment_summary: dict = None
  blockchain_attestation_enabled: bool = False
  start_attestation_required: bool = False
  end_attestation_required: bool = False
  failure_class: str = ""
  failure_message: str = ""
  job_type: str = None
  model_test_summary: dict = None
  model_test_node_selection: dict = None
  model_test_raw_evidence: dict = None

  def to_dict(self) -> dict:
    payload = asdict(self)
    if payload.get("model_test_raw_evidence") is not None:
      payload["model_test_raw_evidence"] = sanitize_raw_evidence_metadata(
        payload.get("model_test_raw_evidence")
      )
    return _strip_none(payload)

  @classmethod
  def from_dict(cls, d: dict) -> CStoreJobRunning:
    return cls(
      job_id=d["job_id"],
      job_status=d["job_status"],
      job_pass=d.get("job_pass", 1),
      run_mode=d["run_mode"],
      launcher=d["launcher"],
      launcher_alias=d.get("launcher_alias", ""),
      target=d["target"],
      scan_type=d.get("scan_type", "network"),
      target_url=d.get("target_url", ""),
      task_name=d.get("task_name", ""),
      start_port=d["start_port"],
      end_port=d["end_port"],
      date_created=d["date_created"],
      job_config_cid=d["job_config_cid"],
      workers=d.get("workers", {}),
      timeline=d.get("timeline", []),
      pass_reports=d.get("pass_reports", []),
      next_pass_at=d.get("next_pass_at"),
      risk_score=d.get("risk_score", 0),
      job_revision=d.get("job_revision", 0),
      redmesh_job_start_attestation=d.get("redmesh_job_start_attestation"),
      last_attestation_at=d.get("last_attestation_at"),
      soc_event_status=d.get("soc_event_status"),
      detection_correlation=d.get("detection_correlation"),
      stix_export=d.get("stix_export"),
      opencti_export=d.get("opencti_export"),
      taxii_export=d.get("taxii_export"),
      graybox_assignment_summary=d.get("graybox_assignment_summary"),
      blockchain_attestation_enabled=d.get("blockchain_attestation_enabled", False),
      start_attestation_required=d.get("start_attestation_required", False),
      end_attestation_required=d.get("end_attestation_required", False),
      failure_class=d.get("failure_class", ""),
      failure_message=d.get("failure_message", ""),
      job_type=d.get("job_type"),
      model_test_summary=d.get("model_test_summary"),
      model_test_node_selection=d.get("model_test_node_selection"),
      model_test_raw_evidence=_sanitize_raw_evidence_if_present(
        d.get("model_test_raw_evidence") or d.get("model_test_raw_evidence_metadata")
      ),
    )


@dataclass(frozen=True)
class CStoreJobFinalized:
  """
  CStore stub for a completed job.

  Minimal footprint — everything else is in the Job Archive (job_cid).
  Contains only what's needed for the job listing page.
  """
  job_id: str
  job_status: str                   # FINALIZED | STOPPED
  target: str
  scan_type: str
  target_url: str
  task_name: str
  risk_score: float
  run_mode: str
  duration: float
  pass_count: int
  launcher: str
  launcher_alias: str
  worker_count: int
  start_port: int
  end_port: int
  date_created: float
  date_completed: float
  job_cid: str                      # the one CID -> JobArchive
  job_config_cid: str               # standalone config CID (needed for purge cleanup)
  misp_export: dict = None          # MISP export metadata (event_uuid, passes_exported, etc.)
  soc_event_status: dict = None
  detection_correlation: dict = None
  stix_export: dict = None
  opencti_export: dict = None
  taxii_export: dict = None
  graybox_assignment_summary: dict = None
  blockchain_attestation_enabled: bool = False
  start_attestation_required: bool = False
  end_attestation_required: bool = False
  failure_class: str = ""
  failure_message: str = ""
  job_type: str = None
  model_test_summary: dict = None
  model_test_node_selection: dict = None
  model_test_raw_evidence: dict = None

  def to_dict(self) -> dict:
    payload = asdict(self)
    if payload.get("model_test_raw_evidence") is not None:
      payload["model_test_raw_evidence"] = sanitize_raw_evidence_metadata(
        payload.get("model_test_raw_evidence")
      )
    return _strip_none(payload)

  @classmethod
  def from_dict(cls, d: dict) -> CStoreJobFinalized:
    return cls(
      job_id=d["job_id"],
      job_status=d["job_status"],
      target=d["target"],
      scan_type=d.get("scan_type", "network"),
      target_url=d.get("target_url", ""),
      task_name=d.get("task_name", ""),
      risk_score=d.get("risk_score", 0),
      run_mode=d["run_mode"],
      duration=d.get("duration", 0),
      pass_count=d.get("pass_count", 0),
      launcher=d["launcher"],
      launcher_alias=d.get("launcher_alias", ""),
      worker_count=d.get("worker_count", 0),
      start_port=d["start_port"],
      end_port=d["end_port"],
      date_created=d["date_created"],
      date_completed=d["date_completed"],
      job_cid=d["job_cid"],
      job_config_cid=d["job_config_cid"],
      misp_export=d.get("misp_export"),
      soc_event_status=d.get("soc_event_status"),
      detection_correlation=d.get("detection_correlation"),
      stix_export=d.get("stix_export"),
      opencti_export=d.get("opencti_export"),
      taxii_export=d.get("taxii_export"),
      graybox_assignment_summary=d.get("graybox_assignment_summary"),
      blockchain_attestation_enabled=d.get("blockchain_attestation_enabled", False),
      start_attestation_required=d.get("start_attestation_required", False),
      end_attestation_required=d.get("end_attestation_required", False),
      failure_class=d.get("failure_class", ""),
      failure_message=d.get("failure_message", ""),
      job_type=d.get("job_type"),
      model_test_summary=d.get("model_test_summary"),
      model_test_node_selection=d.get("model_test_node_selection"),
      model_test_raw_evidence=_sanitize_raw_evidence_if_present(
        d.get("model_test_raw_evidence") or d.get("model_test_raw_evidence_metadata")
      ),
    )


@dataclass(frozen=True)
class WorkerProgress:
  """
  Ephemeral real-time progress published by each worker node.

  Stored in a separate CStore hset (hkey = f"{instance_id}:live",
  key = f"{job_id}:{worker_addr}"). Cleaned up opportunistically when the pass
  completes, but reconciliation must remain correct even if stale rows linger.

  These records are worker-owned liveness truth. Launcher retry logic should
  match them by ``job_id``, ``pass_nr``, ``worker_addr``, and
  ``assignment_revision_seen``.
  """
  job_id: str
  worker_addr: str
  pass_nr: int
  assignment_revision_seen: int
  progress: float                   # 0.0 - 100.0 (stage-based: completed_stages/total * 100)
  phase: str                        # port_scan | fingerprint | service_probes | web_tests | correlation
  ports_scanned: int
  ports_total: int
  open_ports_found: list            # [int] — discovered so far
  completed_tests: list             # [str] — which probes finished
  updated_at: float                 # unix timestamp
  event_id: str = None
  progress_sequence: int = 0
  started_at: float = None
  first_seen_live_at: float = None
  last_seen_at: float = None
  error: str = None
  error_class: str = None
  error_message: str = None
  report_cid: str = None
  scan_type: str = "network"        # network | webapp | model_test compatibility shim
  job_type: str = None
  schema_version: str = None
  phase_index: int = 0              # 1-based current stage index; 0 when unknown
  total_phases: int = 0             # number of stages in the active phase family
  finished: bool = False
  canceled: bool = False
  live_metrics: dict = None         # ScanMetrics.to_dict() — partial snapshot, progressively fills in
  model_test_results: dict = None
  model_test_summary: dict = None
  threads: dict = None              # {thread_id: {phase, ports_scanned, ports_total, open_ports_found}}

  def to_dict(self) -> dict:
    payload = asdict(self)
    if self._is_model_test_progress():
      payload["scan_type"] = MODEL_TEST_JOB_TYPE
      payload["job_type"] = MODEL_TEST_JOB_TYPE
      payload["schema_version"] = payload.get("schema_version") or MODEL_TEST_PROGRESS_SCHEMA
      payload["ports_scanned"] = 0
      payload["ports_total"] = 0
      payload["open_ports_found"] = []
      payload["model_test_results"] = sanitize_model_test_results(payload.get("model_test_results"))
      payload["model_test_summary"] = sanitize_model_test_summary(payload.get("model_test_summary"))
      error_class = sanitize_model_test_error_class(payload.get("error_class"))
      if error_class:
        payload["error_class"] = error_class
      else:
        payload.pop("error_class", None)
      payload.pop("error", None)
      payload.pop("error_message", None)
    return _strip_none(payload)

  def _is_model_test_progress(self) -> bool:
    return (
      self.job_type == MODEL_TEST_JOB_TYPE
      or self.scan_type == MODEL_TEST_JOB_TYPE
      or self.schema_version == MODEL_TEST_PROGRESS_SCHEMA
    )

  @classmethod
  def from_dict(cls, d: dict) -> WorkerProgress:
    return cls(
      job_id=d["job_id"],
      worker_addr=d["worker_addr"],
      pass_nr=d.get("pass_nr", 1),
      assignment_revision_seen=d.get("assignment_revision_seen", 1),
      event_id=d.get("event_id"),
      progress_sequence=d.get("progress_sequence", 0),
      progress=d.get("progress", 0),
      phase=d.get("phase", ""),
      started_at=d.get("started_at"),
      first_seen_live_at=d.get("first_seen_live_at"),
      last_seen_at=d.get("last_seen_at", d.get("updated_at", 0)),
      error=d.get("error"),
      error_class=d.get("error_class"),
      error_message=d.get("error_message"),
      report_cid=d.get("report_cid"),
      scan_type=d.get("scan_type", "network"),
      job_type=d.get("job_type"),
      schema_version=d.get("schema_version"),
      phase_index=d.get("phase_index", 0),
      total_phases=d.get("total_phases", 0),
      ports_scanned=d.get("ports_scanned", 0),
      ports_total=d.get("ports_total", 0),
      open_ports_found=d.get("open_ports_found", []),
      completed_tests=d.get("completed_tests", []),
      updated_at=d.get("updated_at", 0),
      finished=d.get("finished", False),
      canceled=d.get("canceled", False),
      live_metrics=d.get("live_metrics"),
      model_test_results=d.get("model_test_results"),
      model_test_summary=d.get("model_test_summary"),
      threads=d.get("threads"),
    )
