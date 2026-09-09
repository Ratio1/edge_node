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

import inspect
import json
from dataclasses import dataclass, field, asdict, replace
from enum import Enum
from typing import Any

from .models.finding_identity import (
  content_hash as _content_hash,
  dedup_key as _dedup_key,
  parse_cwe_list as _parse_cwe_list,
)


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
  # The identity key, stamped beside the content hash rather than derived from
  # it (`finding_signature[:16]` made identity content-addressed, so rewording
  # a description handed the finding a new id). Named `finding_id` — the name
  # every consumer reads — rather than a `dedup_key` twin that existed only to
  # derive it: two names for one concept is how "two identities for one
  # finding, disagreeing in the same dict" happened twice on this branch. Both
  # keys are stamped at probe time, on unredacted values, which is what keeps
  # them stable across `_redact_report`.
  finding_id: str = ""

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

    Computed by `models.finding_identity.content_hash`: the finding's
    dedup key plus its presentation fields. Two scans of the same target
    producing the same vulnerability yield the same signature, which is
    what makes worker dedup and longitudinal tracking possible, and a
    reworded finding keeps its `dedup_key` while this value moves.

    Per-worker chain-of-custody fields (set by mixins/report.py
    _stamp_worker_source) are NOT in the signature — they vary across
    workers but represent the same underlying finding.
    """
    # Delegates to the shared identity model rather than reimplementing it.
    # This was the fourth implementation of the same idea, and it had already
    # drifted from the flat-path one, which read a raw severity string where
    # this reads `Severity.value` — so the same finding could carry two
    # different signatures depending on which layer computed it.
    return _content_hash(
      self._identity_payload(probe_id), asset_canonical=asset_canonical,
    )

  def _identity_payload(self, probe_id: str) -> dict:
    """The one projection both identity keys are computed from.

    `content_hash` internally starts from `dedup_key(payload)`, so the two
    methods must read the same fields or the keys silently decouple — add a
    field to one projection and not the other and a finding's dedup key stops
    being the one its signature was built over. One payload, two consumers.
    """
    # Every field `finding_identity._CONTENT_FIELDS` names has to be here, or
    # the content hash is blind to content. It carried seven of the nine and
    # omitted `confidence`, `status`, `evidence`, `remediation`, `cvss_score`
    # and `cvss_vector` — so two findings differing only in their evidence, or
    # only in a CVSS 9.8 against a 4.3, hashed identically and content-keyed
    # dedup deleted one of them. `dedup_key` reads only the identity subset from
    # this same payload, so widening it does not move any identity.
    return {
      "probe": probe_id or "",
      "title": self.title or "",
      "description": self.description or "",
      "severity": (
        self.severity.value if isinstance(self.severity, Severity)
        else str(self.severity)
      ),
      "confidence": self.confidence or "",
      "status": getattr(self, "status", "") or "",
      "evidence": self.evidence or "",
      "remediation": self.remediation or "",
      "cvss_score": self.cvss_score,
      "cvss_vector": self.cvss_vector or "",
      "owasp_id": self.owasp_id,
      "cwe_id": self.cwe_id,
      "affected_assets": [_asset_as_dict(asset) for asset in self.affected_assets],
    }

  def compute_dedup_key(
    self,
    *,
    probe_id: str,
    asset_canonical: str | None = None,
  ) -> str:
    """Compute the identity key over the same payload the signature uses.

    Identity, not content: `models.finding_identity.dedup_key` reads probe,
    normalised asset and classification from that payload, and ignores
    `description` and `severity`.

    It does **not** yet ignore the title, and the difference matters here. No
    blackbox probe sets `affected_assets`, so every `Finding` reaching this
    method falls to `dedup_key`'s last-resort branch, which folds in the
    lowercased title to keep two genuinely different findings from one probe
    from colliding. So rewording a *description* preserves the key — the defect
    B2 exists to fix — while rewording a *title* still forks it. RM-061 owns
    giving blackbox findings a url and parameter; until it lands, this is as
    stable as identity can honestly be.
    """
    return _dedup_key(
      self._identity_payload(probe_id), asset_canonical=asset_canonical,
    )

  def with_identity(self, *, finding_signature: str, finding_id: str) -> "Finding":
    """Return a new Finding carrying both identity keys (frozen-safe).

    Replaces `with_signature`, which stamped only the content hash. Its one
    caller — the CVE matcher — passes an `asset_canonical` override, because a
    CVE finding is identified by `product:version:cve_id` rather than by an
    `AffectedAsset`. Stamping only the signature left the dedup key to be
    recomputed downstream from the *probe* name with no override, so the finding
    carried a signature built over one identity basis and a dedup key built over
    another. The keys are stamped together so they cannot disagree.
    """
    data = asdict(self)
    data["finding_signature"] = finding_signature
    data["finding_id"] = finding_id
    return Finding(**_revive_finding_dict(data))


def _asset_as_dict(asset) -> dict:
  """One `AffectedAsset` in the dict shape the shared identity model reads."""
  if isinstance(asset, dict):
    return asset
  return {
    "host": getattr(asset, "host", "") or "",
    "port": getattr(asset, "port", None),
    "url": getattr(asset, "url", "") or "",
    "parameter": getattr(asset, "parameter", "") or "",
    "method": getattr(asset, "method", "") or "",
  }


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


def probe_result(*, raw_data: dict = None, findings: list = None, probe_id: str | None = None) -> dict:
  """Build a probe return dict: JSON-safe, merge_objects_deep-safe, backward-compat.

  Each finding is asdict()'d with the severity enum converted to its
  string value for JSON serialization. The returned dict shape is
  unchanged from before Phase 1 — new fields appear alongside old.
  """
  result = dict(raw_data or {})
  f_list = findings or []
  resolved_probe_id = probe_id or _infer_calling_probe_id()
  enriched = [
    enrich_finding_for_probe(f, resolved_probe_id)
    for f in f_list
  ]
  result["findings"] = [_finding_to_jsonable(f) for f in enriched]
  result["vulnerabilities"] = [f.title for f in enriched if f.severity in _VULN_SEVERITIES]
  return result


def enrich_finding_for_probe(f: Finding, probe_id: str | None) -> Finding:
  """Fill additive PTES fields from registered probe metadata.

  Legacy probe call sites can keep constructing minimal ``Finding``
  objects; this helper makes the registry metadata load-bearing at the
  serialization boundary without mutating frozen dataclasses.
  """
  if not isinstance(f, Finding):
    return f

  cwe_values = _normalize_cwe_values(f.cwe)
  if not cwe_values and f.cwe_id:
    # The joined display form parses here too. The single-value parser this
    # replaced returned 0 for `"CWE-639, CWE-862"`, so the lookup fell through to
    # the probe registry's `default_cwe` and stamped the finding with *that* —
    # a finding carrying `cwe_id: "CWE-639, CWE-862"` and `cwe: (200,)`, wrong
    # rather than merely absent, all the way to the archive and the exports.
    cwe_values = tuple(_parse_cwe_list(f.cwe_id))

  owasp_values = tuple(x for x in f.owasp_top10 if x)
  if not owasp_values and f.owasp_id:
    owasp_values = (f.owasp_id,)
  references = tuple(x for x in f.references if x)
  cvss_vector = f.cvss_vector

  metadata = _get_probe_metadata_safe(probe_id)
  if metadata is not None:
    if not cwe_values:
      cwe_values = tuple(metadata.default_cwe)
    if not owasp_values:
      owasp_values = tuple(metadata.default_owasp)
    if not cvss_vector and metadata.cvss_template and _carries_a_weakness(f):
      cvss_vector = metadata.cvss_template
    references = _merge_unique(references, metadata.references)

  updates: dict[str, Any] = {}
  if cwe_values and not f.cwe:
    updates["cwe"] = cwe_values
  if cwe_values and not f.cwe_id:
    updates["cwe_id"] = f"CWE-{cwe_values[0]}"
  if owasp_values and not f.owasp_top10:
    updates["owasp_top10"] = owasp_values
  if owasp_values and not f.owasp_id:
    updates["owasp_id"] = owasp_values[0]
  if cvss_vector and not f.cvss_vector:
    updates["cvss_vector"] = cvss_vector
  if references != f.references:
    updates["references"] = references
  if f.remediation_structured is None:
    primary = f.remediation or "Review the probe evidence and apply the vendor or platform hardening guidance for this finding."
    updates["remediation_structured"] = Remediation(primary=primary)

  enriched = replace(f, **updates) if updates else f
  # Both identity keys are stamped here, at probe time, on unredacted values.
  #
  # `finding_signature` alone was stamped, and the flat walk then derived the
  # dedup key from it as `finding_signature[:16]` — which made identity
  # content-addressed, exactly what the two-key split exists to prevent.
  # Rewording a description handed the finding a new id, so triage state and
  # longitudinal tracking did not survive an edit. Stamping both keeps them
  # independent, and keeps both stable across `_redact_report`.
  identity = {}
  if probe_id and not enriched.finding_signature:
    identity["finding_signature"] = enriched.compute_signature(probe_id=probe_id)
  if probe_id and not enriched.finding_id:
    identity["finding_id"] = enriched.compute_dedup_key(probe_id=probe_id)
  return replace(enriched, **identity) if identity else enriched


def _infer_calling_probe_id() -> str:
  """Infer a probe id from the call stack for legacy probe_result callers."""
  frame = inspect.currentframe()
  if frame is not None:
    frame = frame.f_back
  prefixes = ("_service_info_", "_web_test_", "_post_scan_", "_correlate_", "_graybox_")
  while frame is not None:
    name = frame.f_code.co_name
    if name.startswith(prefixes):
      return name
    frame = frame.f_back
  return ""


def _carries_a_weakness(f) -> bool:
  """
  True when a finding describes a weakness a CVSS vector could score.

  The probe registry's `cvss_template` is that probe's *worst case*, applied
  when a finding brings no vector of its own. Applying it unconditionally gave
  maximum-impact vectors to findings whose entire point is that a control
  worked: "MySQL default credentials rejected" at INFO under a 9.8 CRITICAL
  template, "TLS configuration adequate." at INFO under a 7.5 HIGH one. The
  reader then sees a severity badge contradicted by the vector printed beside
  it — measured at 55 INFO/LOW findings carrying a high-impact vector on the
  client job, none of them with a numeric score to arbitrate.

  INFO is the marker: probes use it both for "we checked and it was fine" and
  for purely descriptive output. Neither has a weakness to score.
  """
  severity = getattr(f, "severity", None)
  severity = getattr(severity, "value", severity)
  return str(severity or "").upper() != "INFO"


def _get_probe_metadata_safe(probe_id: str | None):
  if not probe_id:
    return None
  try:
    from .worker.probe_registry import get_probe_metadata
    return get_probe_metadata(probe_id)
  except Exception:
    return None


def _normalize_cwe_values(values) -> tuple[int, ...]:
  out = []
  for value in values or ():
    try:
      parsed = int(value)
    except (TypeError, ValueError):
      continue
    if parsed > 0 and parsed not in out:
      out.append(parsed)
  return tuple(out)


def _merge_unique(existing, extra) -> tuple[str, ...]:
  out = []
  seen = set()
  for value in tuple(existing or ()) + tuple(extra or ()):
    if not value or value in seen:
      continue
    seen.add(value)
    out.append(value)
  return tuple(out)


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
