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


@dataclass(frozen=True)
class CStoreWorker:
  """Worker entry in CStore during job execution."""
  start_port: int
  end_port: int
  finished: bool = False
  canceled: bool = False
  report_cid: str = None
  result: dict = None               # fallback: inline report if R1FS is down

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
  redmesh_job_start_attestation: dict = None
  last_attestation_at: float = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

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
      redmesh_job_start_attestation=d.get("redmesh_job_start_attestation"),
      last_attestation_at=d.get("last_attestation_at"),
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

  def to_dict(self) -> dict:
    return asdict(self)

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
    )


@dataclass(frozen=True)
class WorkerProgress:
  """
  Ephemeral real-time progress published by each worker node.

  Stored in a separate CStore hset (hkey = f"{instance_id}:live",
  key = f"{job_id}:{worker_addr}").  Cleaned up when the pass completes.
  """
  job_id: str
  worker_addr: str
  pass_nr: int
  progress: float                   # 0.0 - 100.0 (stage-based: completed_stages/total * 100)
  phase: str                        # port_scan | fingerprint | service_probes | web_tests | correlation
  ports_scanned: int
  ports_total: int
  open_ports_found: list            # [int] — discovered so far
  completed_tests: list             # [str] — which probes finished
  updated_at: float                 # unix timestamp
  live_metrics: dict = None         # ScanMetrics.to_dict() — partial snapshot, progressively fills in
  threads: dict = None              # {thread_id: {phase, ports_scanned, ports_total, open_ports_found}}

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> WorkerProgress:
    return cls(
      job_id=d["job_id"],
      worker_addr=d["worker_addr"],
      pass_nr=d.get("pass_nr", 1),
      progress=d.get("progress", 0),
      phase=d.get("phase", ""),
      ports_scanned=d.get("ports_scanned", 0),
      ports_total=d.get("ports_total", 0),
      open_ports_found=d.get("open_ports_found", []),
      completed_tests=d.get("completed_tests", []),
      updated_at=d.get("updated_at", 0),
      live_metrics=d.get("live_metrics"),
      threads=d.get("threads"),
    )
