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
from extensions.business.cybersec.red_mesh.models.triage import (
  FindingTriageAuditEntry,
  FindingTriageState,
  VALID_TRIAGE_STATUSES,
)
from extensions.business.cybersec.red_mesh.models.engagement import (
  ASSET_EXPOSURES,
  AuthorizationRef,
  Contact,
  DATA_CLASSIFICATIONS,
  EngagementContext,
  KickoffQuestionnaire,
  POST_EXPLOIT_RULES,
  RulesOfEngagement,
  STRENGTH_OF_TEST,
)
from extensions.business.cybersec.red_mesh.models.event_schema import (
  REDMESH_EVENT_SCHEMA,
  REDMESH_EVENT_SCHEMA_VERSION,
  REQUIRED_EVENT_FIELDS,
  RedMeshEvent,
  validate_event_dict,
)
from extensions.business.cybersec.red_mesh.models.llm_output import (
  LlmReportSections,
  ROADMAP_BUCKETS,
  ROADMAP_LONG_TERM,
  ROADMAP_MID_TERM,
  ROADMAP_NEAR_TERM,
  SEVERITY_ERROR,
  SEVERITY_WARNING,
  ValidationIssue,
  ValidationResult,
  validate_llm_output,
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
  "FindingTriageState",
  "FindingTriageAuditEntry",
  "VALID_TRIAGE_STATUSES",
  # engagement
  "Contact",
  "EngagementContext",
  "RulesOfEngagement",
  "AuthorizationRef",
  "KickoffQuestionnaire",
  "DATA_CLASSIFICATIONS",
  "ASSET_EXPOSURES",
  "STRENGTH_OF_TEST",
  "POST_EXPLOIT_RULES",
  "REDMESH_EVENT_SCHEMA",
  "REDMESH_EVENT_SCHEMA_VERSION",
  "REQUIRED_EVENT_FIELDS",
  "RedMeshEvent",
  "validate_event_dict",
  # llm output (Phase 4)
  "LlmReportSections",
  "ROADMAP_BUCKETS",
  "ROADMAP_LONG_TERM",
  "ROADMAP_MID_TERM",
  "ROADMAP_NEAR_TERM",
  "SEVERITY_ERROR",
  "SEVERITY_WARNING",
  "ValidationIssue",
  "ValidationResult",
  "validate_llm_output",
]
