from __future__ import annotations

from dataclasses import asdict, dataclass


REDMESH_EVENT_SCHEMA = "redmesh.event.v1"
REDMESH_EVENT_SCHEMA_VERSION = "1.0.0"

EVENT_OUTCOMES = {"success", "failure", "partial", "skipped", "unknown"}
EVENT_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
EVENT_TLP_VALUES = {"clear", "green", "amber", "amber_strict", "red"}

REQUIRED_EVENT_FIELDS = {
  "schema",
  "schema_version",
  "event_id",
  "timestamp",
  "producer",
  "tenant_id",
  "environment",
  "job_id",
  "pass_nr",
  "scan_type",
  "run_mode",
  "event_type",
  "event_action",
  "event_outcome",
  "severity",
  "authorized",
  "authorization_id",
  "authorization_ref",
  "redaction_mode",
  "dedupe_key",
  "tlp",
  "labels",
}


@dataclass(frozen=True)
class RedMeshEvent:
  """Canonical RedMesh event payload shared by SOC and CTI adapters."""

  schema: str
  schema_version: str
  event_id: str
  timestamp: str
  producer: dict
  tenant_id: str
  environment: str
  job_id: str
  pass_nr: int | None
  scan_type: str
  run_mode: str | None
  event_type: str
  event_action: str
  event_outcome: str
  severity: str
  authorized: bool
  authorization_id: str | None
  authorization_ref: str | None
  redaction_mode: str
  dedupe_key: str
  tlp: str
  labels: list
  target: dict | None = None
  worker: dict | None = None
  window: dict | None = None
  observation: dict | None = None
  finding: dict | None = None
  artifact_refs: dict | None = None
  attestation: dict | None = None
  destination: dict | None = None
  correlation: dict | None = None
  redaction: dict | None = None

  def to_dict(self) -> dict:
    return asdict(self)

  @classmethod
  def from_dict(cls, payload: dict) -> "RedMeshEvent":
    return cls(**{field: payload.get(field) for field in cls.__dataclass_fields__})


def validate_event_dict(payload: dict) -> list[str]:
  """Return validation errors for required schema invariants."""
  errors = []
  if not isinstance(payload, dict):
    return ["event must be a dict"]

  for field in sorted(REQUIRED_EVENT_FIELDS):
    if field not in payload:
      errors.append(f"missing required field: {field}")

  if payload.get("schema") != REDMESH_EVENT_SCHEMA:
    errors.append("schema must be redmesh.event.v1")
  if payload.get("schema_version") != REDMESH_EVENT_SCHEMA_VERSION:
    errors.append("schema_version must be 1.0.0")
  if payload.get("event_outcome") not in EVENT_OUTCOMES:
    errors.append("event_outcome is invalid")
  if payload.get("severity") not in EVENT_SEVERITIES:
    errors.append("severity is invalid")
  if payload.get("tlp") not in EVENT_TLP_VALUES:
    errors.append("tlp is invalid")
  producer = payload.get("producer")
  if not isinstance(producer, dict) or not producer.get("name"):
    errors.append("producer.name is required")
  labels = payload.get("labels")
  if not isinstance(labels, list) or "redmesh" not in labels:
    errors.append("labels must include redmesh")
  redaction = payload.get("redaction")
  if not isinstance(redaction, dict):
    errors.append("redaction proof is required")

  return errors
