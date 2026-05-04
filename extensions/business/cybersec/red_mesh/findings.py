"""
Structured vulnerability findings for RedMesh probes.

Every probe returns a plain dict via ``probe_result()`` so that the
aggregator pipeline (merge_objects_deep, R1FS serialization) keeps working
unchanged.  The ``Finding`` dataclass and ``Severity`` enum provide
type-safe construction and JSON-safe serialization.

Phase 1 (PR-1.1) extends the schema with new fields required for
PTES-aligned reporting: content-addressed identity, CVE list, structured
references / affected assets / impact / repro steps, CVSS Environmental
metrics, KEV / EPSS, plus forward-compat fields anticipating manual
findings (source / created_by / triage_state / exploitability_status).

The new fields are ADDITIVE with safe defaults so existing probe call
sites continue to produce valid Finding instances. Subsequent phase 1
PRs (PR-1.3 through PR-1.5) migrate probes to populate the new fields
from the @register_probe decorator metadata + dynamic CVE DB lookup.
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
  CRITICAL = "CRITICAL"
  HIGH = "HIGH"
  MEDIUM = "MEDIUM"
  LOW = "LOW"
  INFO = "INFO"


_VULN_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM})


# Allowed values for forward-compat fields. Defined as module-level
# constants so callers (and CI) can validate without magic strings.
SOURCE_AUTOMATED = "automated"
SOURCE_AI = "ai"
SOURCE_MANUAL = "manual"
ALLOWED_SOURCES = frozenset({SOURCE_AUTOMATED, SOURCE_AI, SOURCE_MANUAL})

TRIAGE_NEW = "new"
TRIAGE_CONFIRMED = "confirmed"
TRIAGE_FALSE_POSITIVE = "false_positive"
TRIAGE_WONT_FIX = "wont_fix"
TRIAGE_FIXED = "fixed"
ALLOWED_TRIAGE_STATES = frozenset({
  TRIAGE_NEW, TRIAGE_CONFIRMED, TRIAGE_FALSE_POSITIVE,
  TRIAGE_WONT_FIX, TRIAGE_FIXED,
})

# Forward-compat for VEX export (Phase 8).
EXPLOITABILITY_CONFIRMED = "confirmed"
EXPLOITABILITY_LIKELY = "likely"
EXPLOITABILITY_THEORETICAL = "theoretical"
EXPLOITABILITY_NOT = "not_exploitable"


@dataclass(frozen=True)
class AffectedAsset:
  """A specific asset (host / port / URL / parameter) where a finding
  manifests. PTES requires this for traceability — a finding may apply
  to multiple assets across a scan.
  """
  host: str
  port: int | None = None
  url: str | None = None
  parameter: str | None = None
  method: str | None = None  # GET / POST / PUT / DELETE / etc.


@dataclass(frozen=True)
class Remediation:
  """Three-part remediation per PTES Tech Guidelines §6.2.

  Probes typically populate `primary` only; `mitigation` and
  `compensating` come from the CVE DB or are added by analysts.
  """
  primary: str            # the recommended fix (upgrade, patch, config)
  mitigation: str = ""    # alternative / interim measure
  compensating: str = ""  # WAF rule, network ACL, etc.


@dataclass(frozen=True)
class Evidence:
  """Structured evidence reference. Inline `snippet` is a short,
  PII-redacted excerpt for the PDF; `cid` points to full content in
  R1FS for the appendix.
  """
  kind: str               # request_response | screenshot | log | banner | raw
  caption: str = ""
  cid: str | None = None  # R1FS content identifier
  snippet: str | None = None  # truncated, PII-redacted


@dataclass(frozen=True)
class Finding:
  # === Existing minimum-required fields ===
  severity: Severity
  title: str
  description: str
  evidence: str = ""        # legacy string evidence — migrated to evidence_items by PR-1.3-1.5
  remediation: str = ""     # legacy string — migrated to remediation_structured by PR-1.3-1.5
  owasp_id: str = ""        # e.g. "A07:2021"
  cwe_id: str = ""          # e.g. "CWE-287" — migrated to cwe[] (list of int) by PR-1.3-1.5
  confidence: str = "firm"  # certain | firm | tentative
  cvss_score: float | None = None
  cvss_vector: str = ""

  # === Phase 1 (PR-1.1) additions ===

  # Identity (P15) — finding_signature is content-addressed; display_id
  # is set by the report generator at render time.
  finding_signature: str = ""

  # Risk scoring extensions
  cvss_version: str = "3.1"
  cvss_score_env: float | None = None    # Environmental score
  cvss_vector_env: str = ""              # Environmental vector
  cvss_data_freshness: str = ""          # ISO 8601 — when CVSS was fetched from NVD
  kev: bool = False                      # CISA Known Exploited Vulnerabilities
  epss_score: float | None = None        # FIRST EPSS score 0.0-1.0

  # Classification (modern)
  cwe: tuple[int, ...] = ()              # multiple CWEs allowed (NVD often lists 2-3)
  cve: tuple[str, ...] = ()              # CVEs this finding maps to
  owasp_top10: tuple[str, ...] = ()      # ("A01:2021",) — list form of owasp_id
  references: tuple[str, ...] = ()       # vendor advisories, CVE links, OWASP cheatsheet

  # Structured replacements for legacy str fields (populated incrementally)
  affected_assets: tuple[AffectedAsset, ...] = ()
  evidence_items: tuple[Evidence, ...] = ()
  remediation_structured: Remediation | None = None
  impact: str = ""                       # business-language consequence
  steps_to_reproduce: tuple[str, ...] = ()
  severity_justification: str = ""
  ease_of_resolution: str = ""           # trivial | simple | moderate | difficult | infeasible

  # Forward-compat (anticipates manual findings, AI-derived findings,
  # triage workflow, VEX export — none of these are populated yet by
  # automated probes but the schema accepts them so future migrations
  # are additive, not breaking).
  source: str = SOURCE_AUTOMATED
  created_by: str = ""                   # node alias (automated) or user id (manual)
  verified_by: str = ""
  triage_state: str = TRIAGE_NEW
  exploitability_status: str = ""        # forward-compat for VEX export

  # Metadata
  ai_generated: bool = False             # P12 invariant — must stay False for finding data
  tags: tuple[str, ...] = ()
  first_seen: str = ""                   # ISO 8601
  last_seen: str = ""

  # =====================================================================
  # Methods
  # =====================================================================

  def compute_signature(
    self,
    *,
    probe_id: str,
    asset_canonical: str | None = None,
  ) -> str:
    """Compute a stable content-addressed signature.

    A finding's signature is sha256 over (probe_id, asset_canonical,
    title, description, severity). Two scans of the same target
    producing the same vulnerability yield the same signature, which
    is what makes Phase 0's worker dedup and future longitudinal
    tracking possible.

    Per-worker chain-of-custody fields (set by mixins/report.py
    _stamp_worker_source) are NOT in the signature — they vary across
    workers but represent the same underlying finding.
    """
    asset_str = asset_canonical or _canonical_asset_string(self.affected_assets)
    parts = [
      probe_id or "",
      asset_str,
      self.title or "",
      self.description or "",
      self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
    ]
    return hashlib.sha256("\x1e".join(parts).encode("utf-8")).hexdigest()

  def with_signature(self, signature: str) -> "Finding":
    """Return a new Finding with finding_signature set (frozen-safe)."""
    data = asdict(self)
    data["finding_signature"] = signature
    return Finding(**_revive_finding_dict(data))


def _canonical_asset_string(assets: tuple[AffectedAsset, ...]) -> str:
  """Stable string representation of a list of AffectedAsset entries.

  Order-independent (sorted), and includes only fields that uniquely
  identify the asset. Used inside compute_signature so two probes
  emitting findings for the same target produce the same signature
  regardless of probe-internal asset ordering.
  """
  if not assets:
    return ""
  parts = []
  for a in assets:
    parts.append("|".join([
      a.host or "",
      str(a.port if a.port is not None else ""),
      a.url or "",
      a.parameter or "",
      (a.method or "").upper(),
    ]))
  return "\x1f".join(sorted(parts))


def _revive_finding_dict(data: dict) -> dict:
  """Convert a flat dict (from asdict) back into kwargs for Finding()
  by re-constructing nested dataclasses where needed."""
  out = dict(data)
  if isinstance(out.get("severity"), str):
    out["severity"] = Severity(out["severity"])
  # affected_assets / evidence_items come back as lists of dicts
  if isinstance(out.get("affected_assets"), (list, tuple)):
    out["affected_assets"] = tuple(
      AffectedAsset(**a) if isinstance(a, dict) else a
      for a in out["affected_assets"]
    )
  if isinstance(out.get("evidence_items"), (list, tuple)):
    out["evidence_items"] = tuple(
      Evidence(**e) if isinstance(e, dict) else e
      for e in out["evidence_items"]
    )
  if isinstance(out.get("remediation_structured"), dict):
    out["remediation_structured"] = Remediation(**out["remediation_structured"])
  # tuples stored as lists in JSON
  for k in ("cwe", "cve", "owasp_top10", "references", "steps_to_reproduce", "tags"):
    if isinstance(out.get(k), list):
      out[k] = tuple(out[k])
  return out


def finding_from_dict(data: dict) -> Finding:
  """Reconstruct a Finding from its serialized dict form (e.g. from
  R1FS or test fixtures). The inverse of asdict + the severity enum
  string conversion done by probe_result()."""
  return Finding(**_revive_finding_dict(data))


def probe_result(*, raw_data: dict = None, findings: list = None) -> dict:
  """Build a probe return dict: JSON-safe, merge_objects_deep-safe, backward-compat.

  Each finding is asdict()'d with the severity enum converted to its
  string value for JSON serialization. The returned dict shape is
  unchanged from before Phase 1 — new fields appear alongside old.
  """
  result = dict(raw_data or {})
  f_list = findings or []
  result["findings"] = [_finding_to_jsonable(f) for f in f_list]
  result["vulnerabilities"] = [f.title for f in f_list if f.severity in _VULN_SEVERITIES]
  return result


def _finding_to_jsonable(f: Finding) -> dict:
  """asdict() with the severity enum and nested dataclasses normalized
  to JSON-safe primitives. Tuples become lists for canonical JSON."""
  d: dict[str, Any] = asdict(f)
  d["severity"] = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
  # Normalize tuples → lists so json.dumps doesn't trip on them later
  for k in ("cwe", "cve", "owasp_top10", "references", "steps_to_reproduce", "tags",
            "affected_assets", "evidence_items"):
    if isinstance(d.get(k), tuple):
      d[k] = list(d[k])
  return d


def probe_error(target: str, port: int, probe_name: str, exc: Exception) -> None:
  """Log-level error — returns None so failed probes are not stored in results."""
  return None
