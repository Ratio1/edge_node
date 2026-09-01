"""The canonical flat-finding contract.

`PassReport.findings` was `list` — an untyped list of dicts produced by two code
paths that share no type, no version, and no validation: the blackbox path
assembles its dict in a closure inside `mixins/risk.py`, the graybox path in
`GrayboxFinding.to_flat_finding`. `from_dict` whitelists then dropped whatever
the two disagreed on, silently, at a layer with no way to report the loss.

Modelled on `event_schema.py`, the package's only other validated schema: a
`schema` / `schema_version` pair, a `validate_*` entry point returning a list of
errors rather than raising, and a frozen dataclass.

The contract deliberately does **not** enumerate every field. Findings carry
probe-specific data, and a closed field list is what caused the silent drops in
the first place — so known fields are typed and everything else is preserved
verbatim in `extra`. Validation covers the fields consumers actually depend on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


REDMESH_FINDING_SCHEMA = "redmesh.finding.v1"
REDMESH_FINDING_SCHEMA_VERSION = "1.0.0"

FINDING_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
# The three the risk model actually weights. An unknown value used to fall
# through to a 0.5 multiplier, so a probe's typo scored as a real
# half-confidence finding with nothing anywhere saying it was not understood.
FINDING_CONFIDENCES = ("certain", "firm", "tentative")

REQUIRED_FINDING_FIELDS = (
  "finding_id",
  "title",
  "severity",
  "confidence",
  "probe",
  "category",
)

# Typed because a consumer reads them by name. Everything else round-trips
# through `extra`.
_KNOWN_FIELDS = (
  "schema",
  "schema_version",
  "finding_id",
  "finding_signature",
  "title",
  "description",
  "severity",
  "confidence",
  "probe",
  "probe_type",
  "category",
  "port",
  "protocol",
  "evidence",
  "remediation",
  "owasp_id",
  "cwe_id",
  "cvss_score",
  "cvss_vector",
  # What the probe said, beside what took effect. `not_vulnerable` overwrites
  # severity with INFO, and the original was simply gone — so "we checked for a
  # CRITICAL issue and it was absent" and "we checked for an INFO nicety and it
  # was absent" became the same record.
  "declared_severity",
  "declared_confidence",
  "affected_assets",
  "evidence_items",
  "evidence_artifacts",
  "references",
  "replay_steps",
  "status",
)


def normalize_confidence(value: Any) -> tuple[str, bool]:
  """Return `(confidence, was_recognised)`.

  An unrecognised value used to fall through
  `RISK_CONFIDENCE_MULTIPLIERS.get(value, 0.5)` to the same weight as
  `tentative`, while the finding kept the unrecognised string — so the score and
  the record disagreed and neither said why. Landing on `tentative` is
  defensible; doing it invisibly is not, so the caller is told.
  """
  text = str(value or "").strip().lower()
  if text in FINDING_CONFIDENCES:
    return text, True
  return "tentative", False


# Scenario outcomes that report test coverage rather than a finding. A graybox
# probe emits one result per scenario whatever the outcome, so counting these as
# findings made "how many findings" and "how many scenarios ran" the same number.
COVERAGE_STATUSES = ("not_vulnerable", "inconclusive")


def is_coverage_result(finding: Any) -> bool:
  """True when this entry reports test coverage rather than a finding.

  One predicate for every counter. `total_findings` was `len(findings)` in three
  separate places — the UI aggregate, the LLM input and the risk breakdown — so
  a clean graybox scan reported dozens of findings to all three.
  """
  if not isinstance(finding, dict):
    return False
  return str(finding.get("status") or "").lower() in COVERAGE_STATUSES


@dataclass(frozen=True)
class FlatFinding:
  """One finding, as it is archived and as every consumer reads it."""

  finding_id: str
  title: str
  severity: str
  confidence: str
  probe: str
  category: str

  schema: str = REDMESH_FINDING_SCHEMA
  schema_version: str = REDMESH_FINDING_SCHEMA_VERSION
  finding_signature: str = ""
  description: str = ""
  probe_type: str = ""
  port: int | None = None
  protocol: str = ""
  evidence: str = ""
  remediation: str = ""
  owasp_id: str = ""
  cwe_id: str = ""
  cvss_score: float | None = None
  cvss_vector: str = ""
  declared_severity: str = ""
  declared_confidence: str = ""
  affected_assets: tuple = ()
  evidence_items: tuple = ()
  evidence_artifacts: tuple = ()
  references: tuple = ()
  replay_steps: tuple = ()
  status: str = ""
  # Verbatim carrier for anything the contract does not name. Not a dumping
  # ground: it is what makes "the contract does not know this field" different
  # from "this field did not exist", which is the distinction the whitelists
  # erased.
  extra: dict = field(default_factory=dict)

  def to_dict(self) -> dict:
    """Round-trip back to the archived shape, losing nothing.

    Only keys that were present survive: a producer that never set `remediation`
    must not gain an empty one, or the two producers' outputs stop being
    comparable and every consumer sees fields nobody emitted.
    """
    out: dict[str, Any] = {}
    for name in _KNOWN_FIELDS:
      if name in self._present:
        value = getattr(self, name)
        out[name] = list(value) if isinstance(value, tuple) else value
    out.update(self.extra)
    return out

  # Which known fields the source payload actually carried. Kept out of
  # `to_dict` itself so the round trip stays exact.
  _present: frozenset = field(default_factory=frozenset, repr=False, compare=False)


def validate_flat_finding(payload: Any) -> list[str]:
  """Return validation errors. Empty list means valid."""
  if not isinstance(payload, dict):
    return ["finding must be a dict"]

  errors = []
  for name in REQUIRED_FINDING_FIELDS:
    if name not in payload:
      errors.append(f"missing required field: {name}")

  schema = payload.get("schema", REDMESH_FINDING_SCHEMA)
  if schema != REDMESH_FINDING_SCHEMA:
    errors.append(f"schema must be {REDMESH_FINDING_SCHEMA}")
  # Absent is fine — a finding written before the stamp existed is a v0 finding,
  # not an invalid one, and historical archives must stay readable. A *wrong*
  # version is refused rather than read under the wrong assumptions.
  version = payload.get("schema_version", REDMESH_FINDING_SCHEMA_VERSION)
  if version != REDMESH_FINDING_SCHEMA_VERSION:
    errors.append(
      f"schema_version must be {REDMESH_FINDING_SCHEMA_VERSION}, got {version}"
    )

  if "severity" in payload and payload["severity"] not in FINDING_SEVERITIES:
    errors.append(f"severity is invalid: {payload['severity']}")
  if "confidence" in payload and payload["confidence"] not in FINDING_CONFIDENCES:
    errors.append(f"confidence is invalid: {payload['confidence']}")

  return errors


def flat_finding_from_dict(payload: dict) -> FlatFinding:
  """Build a `FlatFinding` from an archived dict without discarding anything."""
  if not isinstance(payload, dict):
    raise TypeError("finding must be a dict")

  known = {name: payload[name] for name in _KNOWN_FIELDS if name in payload}
  present = frozenset(known)
  for name in ("affected_assets", "evidence_items", "evidence_artifacts",
               "references", "replay_steps"):
    if name in known and isinstance(known[name], list):
      known[name] = tuple(known[name])
  known.setdefault("schema", REDMESH_FINDING_SCHEMA)
  known.setdefault("schema_version", REDMESH_FINDING_SCHEMA_VERSION)
  for name in REQUIRED_FINDING_FIELDS:
    known.setdefault(name, "")

  extra = {key: value for key, value in payload.items() if key not in _KNOWN_FIELDS}
  return FlatFinding(**known, extra=extra, _present=present)
