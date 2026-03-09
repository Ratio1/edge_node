"""
R1FS persistent models — job config, pass reports, and job archive.

  JobConfig        — immutable config written once at launch
  WorkerReportMeta — per-worker summary inside PassReport
  PassReport       — consolidated pass report (one CID per pass)
  UiAggregate      — pre-computed aggregate for frontend
  JobArchive       — complete job archive (the one CID)
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

from extensions.business.cybersec.red_mesh.models.shared import _strip_none
from extensions.business.cybersec.red_mesh.constants import (
  DISTRIBUTION_SLICE, PORT_ORDER_SEQUENTIAL, RUN_MODE_SINGLEPASS,
)


@dataclass(frozen=True)
class JobConfig:
  """
  Static job configuration stored in R1FS.

  Written once at launch, never modified. Referenced by job_config_cid.
  """
  target: str
  start_port: int
  end_port: int
  exceptions: list                  # [int]
  distribution_strategy: str        # SLICE | MIRROR
  port_order: str                   # SHUFFLE | SEQUENTIAL
  nr_local_workers: int
  enabled_features: list            # [str]
  excluded_features: list           # [str]
  run_mode: str                     # SINGLEPASS | CONTINUOUS_MONITORING
  scan_min_delay: float = 0
  scan_max_delay: float = 0
  ics_safe_mode: bool = False
  redact_credentials: bool = True
  scanner_identity: str = ""
  scanner_user_agent: str = ""
  task_name: str = ""
  task_description: str = ""
  monitor_interval: int = 0
  selected_peers: list = None       # [str] or None
  created_by_name: str = ""
  created_by_id: str = ""
  authorized: bool = False

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> JobConfig:
    return cls(
      target=d["target"],
      start_port=d["start_port"],
      end_port=d["end_port"],
      exceptions=d.get("exceptions", []),
      distribution_strategy=d.get("distribution_strategy", DISTRIBUTION_SLICE),
      port_order=d.get("port_order", PORT_ORDER_SEQUENTIAL),
      nr_local_workers=d.get("nr_local_workers", 2),
      enabled_features=d.get("enabled_features", []),
      excluded_features=d.get("excluded_features", []),
      run_mode=d.get("run_mode", RUN_MODE_SINGLEPASS),
      scan_min_delay=d.get("scan_min_delay", 0),
      scan_max_delay=d.get("scan_max_delay", 0),
      ics_safe_mode=d.get("ics_safe_mode", False),
      redact_credentials=d.get("redact_credentials", True),
      scanner_identity=d.get("scanner_identity", ""),
      scanner_user_agent=d.get("scanner_user_agent", ""),
      task_name=d.get("task_name", ""),
      task_description=d.get("task_description", ""),
      monitor_interval=d.get("monitor_interval", 0),
      selected_peers=d.get("selected_peers"),
      created_by_name=d.get("created_by_name", ""),
      created_by_id=d.get("created_by_id", ""),
      authorized=d.get("authorized", False),
    )


@dataclass(frozen=True)
class WorkerReportMeta:
  """
  Per-worker summary inside a PassReport.

  Lightweight metadata for attribution. The full raw report
  is available via report_cid (Layer 3).
  """
  report_cid: str                   # nested CID -> WorkerReport in R1FS
  start_port: int
  end_port: int
  ports_scanned: int = 0
  open_ports: list = None           # [int]
  nr_findings: int = 0
  node_ip: str = ""                 # worker node's IP address

  def to_dict(self) -> dict:
    d = asdict(self)
    if d["open_ports"] is None:
      d["open_ports"] = []
    return d

  @classmethod
  def from_dict(cls, d: dict) -> WorkerReportMeta:
    return cls(
      report_cid=d["report_cid"],
      start_port=d["start_port"],
      end_port=d["end_port"],
      ports_scanned=d.get("ports_scanned", 0),
      open_ports=d.get("open_ports", []),
      nr_findings=d.get("nr_findings", 0),
      node_ip=d.get("node_ip", ""),
    )


@dataclass(frozen=True)
class PassReport:
  """
  Consolidated pass report stored in R1FS (one CID per pass).

  Contains aggregated scan data from all workers, risk assessment,
  LLM analysis (inline), and per-worker attribution with nested CIDs.
  """
  pass_nr: int
  date_started: float
  date_completed: float
  duration: float

  # Aggregated scan data — stored as separate CID, not inline
  aggregated_report_cid: str        # CID -> AggregatedScanData in R1FS

  # Per-worker attribution
  worker_reports: dict              # { addr: WorkerReportMeta.to_dict() }

  # Risk
  risk_score: float = 0
  risk_breakdown: dict = None       # RiskBreakdown.to_dict()

  # LLM (inline text)
  llm_analysis: str = None          # markdown
  quick_summary: str = None         # 2-4 sentences
  llm_failed: bool = None           # True if LLM API was unavailable — absent on success (_strip_none)

  # Flat findings (enriched dicts extracted from service_info/web_tests_info/correlation_findings)
  findings: list = None             # [ { severity, confidence, port, protocol, probe, category, evidence, ... } ]

  # Scan metrics (pass-level aggregate across all nodes)
  scan_metrics: dict = None         # ScanMetrics.to_dict()

  # Per-node scan metrics (node_address -> ScanMetrics.to_dict())
  worker_scan_metrics: dict = None

  # Attestation
  redmesh_test_attestation: dict = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> PassReport:
    return cls(
      pass_nr=d["pass_nr"],
      date_started=d["date_started"],
      date_completed=d["date_completed"],
      duration=d.get("duration", 0),
      aggregated_report_cid=d["aggregated_report_cid"],
      worker_reports=d.get("worker_reports", {}),
      risk_score=d.get("risk_score", 0),
      risk_breakdown=d.get("risk_breakdown"),
      llm_analysis=d.get("llm_analysis"),
      quick_summary=d.get("quick_summary"),
      llm_failed=d.get("llm_failed"),
      findings=d.get("findings"),
      scan_metrics=d.get("scan_metrics"),
      worker_scan_metrics=d.get("worker_scan_metrics"),
      redmesh_test_attestation=d.get("redmesh_test_attestation"),
    )


@dataclass(frozen=True)
class UiAggregate:
  """
  Pre-computed aggregate view for the frontend.

  Embedded inside JobArchive so the detail page renders
  without client-side recomputation.
  """
  total_open_ports: list            # sorted unique [int]
  total_services: int
  total_findings: int
  latest_risk_score: float
  latest_risk_breakdown: dict = None  # RiskBreakdown.to_dict()
  latest_quick_summary: str = None
  findings_count: dict = None       # { CRITICAL: int, HIGH: int, MEDIUM: int, LOW: int, INFO: int }
  top_findings: list = None         # top 10 CRITICAL+HIGH findings for dashboard display
  finding_timeline: dict = None     # { finding_id: { first_seen, last_seen, pass_count } }
  worker_activity: list = None      # [ { id, start_port, end_port, open_ports } ]

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> UiAggregate:
    return cls(
      total_open_ports=d.get("total_open_ports", []),
      total_services=d.get("total_services", 0),
      total_findings=d.get("total_findings", 0),
      latest_risk_score=d.get("latest_risk_score", 0),
      latest_risk_breakdown=d.get("latest_risk_breakdown"),
      latest_quick_summary=d.get("latest_quick_summary"),
      findings_count=d.get("findings_count"),
      top_findings=d.get("top_findings"),
      finding_timeline=d.get("finding_timeline"),
      worker_activity=d.get("worker_activity"),
    )


@dataclass(frozen=True)
class JobArchive:
  """
  Complete job archive stored in R1FS.

  Written once when job reaches FINALIZED or STOPPED.
  The CStore stub holds only job_cid pointing here.
  One fetch gives the frontend everything it needs.
  """
  job_id: str
  job_config: dict                  # JobConfig.to_dict()
  timeline: list                    # [ TimelineEvent.to_dict() ]
  passes: list                      # [ PassReport.to_dict() ]
  ui_aggregate: dict                # UiAggregate.to_dict()
  duration: float
  date_created: float
  date_completed: float
  start_attestation: dict = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> JobArchive:
    return cls(
      job_id=d["job_id"],
      job_config=d.get("job_config", {}),
      timeline=d.get("timeline", []),
      passes=d.get("passes", []),
      ui_aggregate=d.get("ui_aggregate", {}),
      duration=d.get("duration", 0),
      date_created=d.get("date_created", 0),
      date_completed=d.get("date_completed", 0),
      start_attestation=d.get("start_attestation"),
    )
