"""
RedMesh data models for structured job storage.

Three-layer architecture:
  Layer 1 (CStore)  — CStoreJobRunning / CStoreJobFinalized
  Layer 2 (R1FS)    — JobArchive (one CID per completed job)
  Layer 3 (R1FS)    — Scan reports (ThreadReport → NodeReport → AggregatedScanData)

All models are frozen dataclasses with to_dict() / from_dict().

Package layout:
  shared.py   — foundational types (TimelineEvent, RiskBreakdown, ScanMetrics)
  cstore.py   — CStore orchestration state (CStoreWorker, CStoreJobRunning, ...)
  reports.py  — scan data aggregation pipeline (ThreadReport → NodeReport → AggregatedScanData)
  archive.py  — R1FS persistent structures (JobConfig, PassReport, JobArchive, ...)
"""

# shared
from extensions.business.cybersec.red_mesh.models.shared import (
  _strip_none,
  TimelineEvent,
  RiskBreakdown,
  ScanMetrics,
)

# cstore
from extensions.business.cybersec.red_mesh.models.cstore import (
  CStoreWorker,
  PassReportRef,
  CStoreJobRunning,
  CStoreJobFinalized,
  WorkerProgress,
)

# reports
from extensions.business.cybersec.red_mesh.models.reports import (
  ThreadReport,
  NodeReport,
  AggregatedScanData,
)

# archive
from extensions.business.cybersec.red_mesh.models.archive import (
  JobConfig,
  WorkerReportMeta,
  PassReport,
  UiAggregate,
  JobArchive,
)

__all__ = [
  # shared
  "_strip_none",
  "TimelineEvent",
  "RiskBreakdown",
  "ScanMetrics",
  # cstore
  "CStoreWorker",
  "PassReportRef",
  "CStoreJobRunning",
  "CStoreJobFinalized",
  "WorkerProgress",
  # reports
  "ThreadReport",
  "NodeReport",
  "AggregatedScanData",
  # archive
  "JobConfig",
  "WorkerReportMeta",
  "PassReport",
  "UiAggregate",
  "JobArchive",
]
