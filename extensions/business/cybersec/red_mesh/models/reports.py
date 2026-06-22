"""
Scan report models — the aggregation pipeline.

  ThreadReport       — single PentestLocalWorker thread output (transient)
  NodeReport         — per-node aggregate stored in R1FS
  AggregatedScanData — network-wide pass aggregate stored in R1FS (CID ref in PassReport)

Pipeline:
  ThreadReport ──(merge threads)──> NodeReport ──(merge nodes)──> AggregatedScanData
    has: local_worker_id,            has: job_id, target,          has: just scan data
         progress, done, canceled         initiator                     (no identity)
    transient (in-memory only)       stored in R1FS (CID)          stored in R1FS (CID ref in PassReport)
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

from extensions.business.cybersec.red_mesh.models.shared import _strip_none


@dataclass(frozen=True)
class ThreadReport:
  """
  Single PentestLocalWorker thread output (get_status).

  Transient — only exists while the job is running.  Multiple thread
  reports are merged into one NodeReport per node at close time.

  Loosely typed — port-keyed internals stay as plain dicts.
  """
  job_id: str
  target: str
  local_worker_id: str              # identifies this thread
  start_port: int
  end_port: int
  open_ports: list                  # [int]
  service_info: dict                # { "80/tcp": { "_service_info_http": { ... } } }
  web_tests_info: dict              # { "80/tcp": { "_web_test_xss": { ... } } }
  completed_tests: list             # [str]
  done: bool
  canceled: bool = False
  progress: str = ""                # e.g. "87.5%"
  initiator: str = ""
  ports_scanned: int = 0
  nr_open_ports: int = 0
  exceptions: list = None           # [int]
  web_tested: bool = False
  port_protocols: dict = None       # { "80": "http", "22": "ssh" }
  port_banners: dict = None         # { "22": "SSH-2.0-OpenSSH_8.9" }
  scan_metrics: dict = None         # ScanMetrics.to_dict() — raw thread-level metrics
  correlation_findings: list = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> ThreadReport:
    return cls(
      job_id=d.get("job_id", ""),
      target=d.get("target", ""),
      local_worker_id=d.get("local_worker_id", ""),
      start_port=d.get("start_port", 0),
      end_port=d.get("end_port", 0),
      open_ports=d.get("open_ports", []),
      service_info=d.get("service_info", {}),
      web_tests_info=d.get("web_tests_info", {}),
      completed_tests=d.get("completed_tests", []),
      done=d.get("done", False),
      canceled=d.get("canceled", False),
      progress=d.get("progress", ""),
      initiator=d.get("initiator", ""),
      ports_scanned=d.get("ports_scanned", 0),
      nr_open_ports=d.get("nr_open_ports", 0),
      exceptions=d.get("exceptions"),
      web_tested=d.get("web_tested", False),
      port_protocols=d.get("port_protocols"),
      port_banners=d.get("port_banners"),
      scan_metrics=d.get("scan_metrics"),
      correlation_findings=d.get("correlation_findings"),
    )


@dataclass(frozen=True)
class NodeReport:
  """
  Per-node aggregate stored in R1FS (one CID per node per pass).

  Produced by merging multiple ThreadReports on each worker node at close time.
  No thread identity — local_worker_id is meaningless after merge.
  """
  job_id: str
  target: str
  initiator: str
  start_port: int
  end_port: int
  open_ports: list                  # [int] — merged from all threads
  service_info: dict                # merged across threads
  web_tests_info: dict              # merged across threads
  completed_tests: list             # [str] — union of all threads
  ports_scanned: int = 0
  nr_open_ports: int = 0
  exceptions: list = None           # [int]
  web_tested: bool = False
  port_protocols: dict = None
  port_banners: dict = None
  scan_metrics: dict = None         # ScanMetrics.to_dict() — aggregated across threads
  correlation_findings: list = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> NodeReport:
    return cls(
      job_id=d.get("job_id", ""),
      target=d.get("target", ""),
      initiator=d.get("initiator", ""),
      start_port=d.get("start_port", 0),
      end_port=d.get("end_port", 0),
      open_ports=d.get("open_ports", []),
      service_info=d.get("service_info", {}),
      web_tests_info=d.get("web_tests_info", {}),
      completed_tests=d.get("completed_tests", []),
      ports_scanned=d.get("ports_scanned", 0),
      nr_open_ports=d.get("nr_open_ports", 0),
      exceptions=d.get("exceptions"),
      web_tested=d.get("web_tested", False),
      port_protocols=d.get("port_protocols"),
      port_banners=d.get("port_banners"),
      scan_metrics=d.get("scan_metrics"),
      correlation_findings=d.get("correlation_findings"),
    )


@dataclass(frozen=True)
class AggregatedScanData:
  """
  Network-wide scan data aggregated across all nodes for a single pass.

  Produced by _get_aggregated_report on the launcher, merging multiple NodeReports.
  No node/thread identity — just the combined scan results.
  Stored in R1FS as a separate CID, referenced by PassReport.aggregated_report_cid.
  """
  open_ports: list                  # [int] — sorted unique across all nodes
  service_info: dict                # merged across all nodes
  web_tests_info: dict              # merged across all nodes
  completed_tests: list             # [str] — union across all nodes
  ports_scanned: int = 0
  nr_open_ports: int = 0
  port_protocols: dict = None
  port_banners: dict = None
  scan_metrics: dict = None         # ScanMetrics.to_dict() — aggregated across all nodes
  correlation_findings: list = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> AggregatedScanData:
    return cls(
      open_ports=d.get("open_ports", []),
      service_info=d.get("service_info", {}),
      web_tests_info=d.get("web_tests_info", {}),
      completed_tests=d.get("completed_tests", []),
      ports_scanned=d.get("ports_scanned", 0),
      nr_open_ports=d.get("nr_open_ports", 0),
      port_protocols=d.get("port_protocols"),
      port_banners=d.get("port_banners"),
      scan_metrics=d.get("scan_metrics"),
      correlation_findings=d.get("correlation_findings"),
    )
