"""Finding identity: one dedup key, one content hash.

Three competing keys coexisted, none documented as *the* identity:

  * `Finding.compute_signature` (64-hex) over probe + asset + title +
    description + severity;
  * `compute_flat_signature` in `mixins/risk.py`, the same idea reimplemented
    over a dict and free to drift — and it had, reading a raw severity string
    where the other read `Severity.value`;
  * `_compact_finding_signature` in `mixins/report.py`, a whole-dict hash with
    an exclusion list.

All three folded free-text into identity, so a reworded finding became a
different finding: triage did not survive an edit to a probe's wording, and
longitudinal tracking broke with nothing to report it.

The split here separates the two questions that were being answered by one
value:

  `dedup_key`    — *is this the same finding?* Probe, scenario, the normalised
                   asset (including url and parameter, so two endpoints
                   exhibiting one scenario stay two findings), and
                   classification. No free text.
  `content_hash` — *has this finding changed?* The presentation fields too,
                   minus per-worker custody, which varies across nodes for one
                   underlying finding.
"""

from __future__ import annotations

import hashlib
from typing import Any


# 16 hex, because `finding_id` *is* this key rather than a truncation of it:
# the archived contract and the triage store both key on a 16-char id, and
# deriving one identity from another is how the previous model ended up with
# `finding_id = signature[:16]` and no way to change either independently.
DEDUP_KEY_LENGTH = 16

# Set after the fact by `_stamp_worker_source`. One finding seen from two
# vantages differs in all of these and is still one finding.
_WORKER_ATTRIBUTION_FIELDS = frozenset({
  "worker_source",
  "worker_sources",
  "observed_at",
  "node_ip",
  "node_address",
  "ee_addr",
  "initiator",
  "local_worker_id",
  "finding_id",
  "finding_signature",
  "dedup_key",
  "content_hash",
  "display_id",
})

_CONTENT_FIELDS = (
  "title",
  "description",
  "severity",
  "confidence",
  "status",
  "evidence",
  "remediation",
  "cvss_score",
  "cvss_vector",
)

_UNIT = "\x1f"
_RECORD = "\x1e"


def _text(value: Any) -> str:
  return "" if value is None else str(value)


def canonical_asset_string(assets: Any) -> str:
  """One asset list, one string, order-independent.

  `url` and `parameter` are load-bearing: without them every endpoint
  exhibiting one scenario collapsed into a single finding, so a scanner that
  found the same IDOR on twelve endpoints reported it once.

  A `{host, port}`-only asset contributes nothing — it is not a location, it
  is where the scan pointed (`_has_specific_location` draws the same line).
  Including it forked identity between the two representations of one finding:
  stamped at probe time over empty assets, versus a raw dict whose asset the
  flat walk synthesised — so the pair never deduplicated against each other.
  """
  if not isinstance(assets, (list, tuple)):
    return ""
  parts = []
  for asset in assets:
    if not isinstance(asset, dict):
      continue
    if not (asset.get("url") or asset.get("parameter")):
      continue
    parts.append(_UNIT.join([
      _text(asset.get("host")),
      _text(asset.get("port")),
      _text(asset.get("url")),
      _text(asset.get("parameter")),
      _text(asset.get("method")).upper(),
    ]))
  return _RECORD.join(sorted(parts))


def _canonical_cwe(value: Any) -> str:
  """Order-independent. `CWE-639, CWE-862` and `CWE-862, CWE-639` classify the
  same weakness set, and NVD routinely lists them in either order."""
  if isinstance(value, (list, tuple)):
    items = [_text(item) for item in value]
  else:
    items = _text(value).split(",")
  return ", ".join(sorted({item.strip() for item in items if item.strip()}))


def parse_cwe_list(value: Any) -> list[int]:
  """Every CWE in `value`, as ints, in order, deduplicated.

  Accepts a list, or the joined display form `"CWE-639, CWE-862"`. The consumer
  used to strip one `CWE-` prefix and call `int()` on the rest, so a multi-CWE
  finding parsed to nothing at all and reached the report, the exports and the
  LLM with no weakness classification. Single-CWE findings parsed fine, which is
  why it survived — and NVD lists two or three for a large share of entries.
  """
  if isinstance(value, (list, tuple)):
    items = [str(item) for item in value]
  else:
    items = _text(value).split(",")
  out = []
  for item in items:
    cleaned = item.strip().upper()
    if cleaned.startswith("CWE-"):
      cleaned = cleaned[4:]
    try:
      parsed = int(cleaned)
    except (TypeError, ValueError):
      continue
    if parsed > 0 and parsed not in out:
      out.append(parsed)
  return out


def _classification(finding: dict) -> str:
  return _UNIT.join([
    _text(finding.get("owasp_id")),
    _canonical_cwe(finding.get("cwe_id") or finding.get("cwe")),
  ])


def _has_specific_location(assets: Any) -> bool:
  """Whether any asset names *where* the finding is, not just which host.

  The blackbox producer synthesises `{host, port}` for every finding, so an
  asset list being non-empty says nothing about whether two findings are
  distinguishable by location.
  """
  if not isinstance(assets, (list, tuple)):
    return False
  return any(
    isinstance(asset, dict) and (asset.get("url") or asset.get("parameter"))
    for asset in assets
  )


def dedup_key(finding: dict, *, asset_canonical: str | None = None) -> str:
  """Stable identity for a finding. Survives rewording; splits on location.

  Deliberately *not* a truncation of `content_hash`: they answer different
  questions, and deriving one from the other is how the previous model ended up
  with `finding_id = signature[:16]` and no way to change either independently.

  The title is a *last-resort discriminator*, used only when a finding carries
  neither a scenario id nor a specific location. Blackbox probes do not yet
  attach url/parameter — RM-061 owns that — so for them the title is the only
  thing separating "reflected XSS in search" from "stored XSS in comment": same
  port, same probe, same CWE, same synthesised `{host, port}` asset. Dropping it
  unconditionally would merge two real findings into one, which is a worse
  failure than the wording-fork it avoids. Findings that do carry a location or
  a scenario id — every graybox finding, and every blackbox finding once RM-061
  lands — get the clean property with no free text in their identity at all.
  """
  if not isinstance(finding, dict):
    raise TypeError("finding must be a dict")
  assets = finding.get("affected_assets")
  # An explicit override for callers whose asset is not an `AffectedAsset` at
  # all — the CVE matcher identifies by `product:version:cve_id`, which is what
  # separates two CVEs on one service and has no url or parameter to canonicalise.
  asset_str = asset_canonical if asset_canonical is not None else canonical_asset_string(assets)
  parts = [
    _text(finding.get("probe")),
    _text(finding.get("scenario_id")),
    asset_str,
    _classification(finding),
  ]
  if (not finding.get("scenario_id") and asset_canonical is None
      and not _has_specific_location(assets)):
    parts.append(_text(finding.get("title")).strip().lower())
  digest = hashlib.sha256(_RECORD.join(parts).encode("utf-8")).hexdigest()
  return digest[:DEDUP_KEY_LENGTH]


def content_hash(finding: dict, *, asset_canonical: str | None = None) -> str:
  """Change detection over the whole finding, minus per-worker attribution."""
  if not isinstance(finding, dict):
    raise TypeError("finding must be a dict")
  parts = [dedup_key(finding, asset_canonical=asset_canonical)]
  parts.extend(_text(finding.get(name)) for name in _CONTENT_FIELDS)
  return hashlib.sha256(_RECORD.join(parts).encode("utf-8")).hexdigest()


def worker_attribution_fields() -> frozenset:
  """Exposed so report-layer dedup excludes the same fields this hash does."""
  return _WORKER_ATTRIBUTION_FIELDS
