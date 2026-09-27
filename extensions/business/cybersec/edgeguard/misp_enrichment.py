"""MISP enrichment block, v1 (contract §7, no network).

Builds the `misp_enrichment` block from `raw_data` already in Neo4j (the
flattened `SOURCED_FROM` source payload, a JSON string) plus the node's own
MISP id lists. Read by one internal, parameterised, read-only Cypher query
keyed on node element ids -- never a model-generated query, never fed to any
model (contract §7.4; that wiring is a later slice). Every function here is
pure or takes an already-open Neo4j session; `edgeguard_api.py` owns the
fail-open wrapper, the config switch and the response wiring.

The block validator and its policy regex (`FORBIDDEN_PACKET_PROPERTY_RE`)
also live here: `edgeguard_api.py` imports the regex back under the same
name for its own (unrelated) packet-property checks, and calls
`validate_misp_enrichment_block` as the fail-closed backstop for the block
this module builds.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

try:  # pragma: no cover - neo4j is an optional runtime dependency in tests.
  from neo4j import Query
except Exception:  # noqa: BLE001 - exercised by the test suite (no neo4j installed).
  Query = None

MISP_ENRICHMENT_SCHEMA_VERSION = "edgeguard.misp_enrichment.v1"
MISP_ENRICHMENT_SOURCE = "neo4j_raw_data"
MISP_EVENT_URL_TEMPLATE = "https://misp.edgeguard.org/events/view/{event_id}"

# Contract §7.1/§7.3: bounded to 50 nodes per response, 64 KiB per node.
MAX_NODES = 50
MAX_NODE_BYTES = 65_536
MAX_STRING_CHARS = 500
MAX_ARRAY_ITEMS = 20
# Id lists (event/attribute/url) get their own, wider cap -- distinct from
# the §7.2 `fields` array cap above.
MAX_ID_LIST_ITEMS = 100
ATTRIBUTE_ID_MAX_CHARS = 64
# An individual `raw_data` payload this large is skipped before
# `json.loads` -- never parsed, never counted against a node.
MAX_RAW_DATA_CHARS = 65_536
# The internal read gets its own bounded timeout, independent of
# `cfg_neo4j_query_timeout_seconds`.
DEFAULT_TIMEOUT_SECONDS = 5

# The packet-property and MISP-enrichment-field policy regex; imported back
# under the same name in `edgeguard_api.py`.
FORBIDDEN_PACKET_PROPERTY_RE = re.compile(
  r"(raw|payload|body|content|header|authorization|cookie|password|secret|token|api_key|"
  r"credential|log|screenshot|stack|request|response)",
  re.IGNORECASE,
)

MISP_ENRICHMENT_ALLOWED_BLOCK_KEYS = {
  "schema_version", "source", "fetched_at", "sha256", "nodes", "truncated", "omitted_nodes",
}
# Contract §7.3: exactly these six keys, always present.
MISP_ENRICHMENT_ALLOWED_NODE_KEYS = {
  "node_ref", "label", "misp_event_ids", "misp_attribute_ids", "misp_event_urls", "fields",
}
MISP_ENRICHMENT_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVENT_ID_RE = re.compile(r"^(?:0|[1-9]\d{0,9})$")

# Contract §7.3: nodes with neither a MISP id nor a `SOURCED_FROM` edge
# (Campaign, per the phase-3 probe) are omitted from the block entirely.
_SKIPPED_LABELS = {"Campaign"}
_KNOWN_LABEL_PRIORITY = (
  "CVE", "Indicator", "Malware", "ThreatActor", "Technique", "Tactic", "Tool", "Campaign",
)

# Contract §7.2: whitelist keyed by (label, `Source.source_id`), lower-cased.
# Sources not listed here (`abuseipdb`, `ssl_blacklist`, `feodo_tracker`,
# `virustotal`, `mitre_attck`) are envelope-only -- no `fields` entries.
_CVE_NVD_FIELDS = (
  "cwe", "reference_urls", "affected_products",
  "cisa_exploit_add", "cisa_action_due", "cisa_vulnerability_name",
)
FIELD_WHITELIST: Dict[Tuple[str, str], Tuple[str, ...]] = {
  ("CVE", "nvd"): _CVE_NVD_FIELDS,
  ("CVE", "cisa_kev"): _CVE_NVD_FIELDS,
  ("CVE", "alienvault_otx"): _CVE_NVD_FIELDS,
  ("Indicator", "alienvault_otx"): (
    "pulse_name", "pulse_references", "pulse_tlp", "otx_industries", "indicator_role",
  ),
  ("Indicator", "threatfox"): (
    "threat_type", "threat_type_desc", "tf_tags", "reference", "malware_alias",
  ),
  ("Indicator", "urlhaus"): (
    "threat_type", "threat_type_desc", "tf_tags", "reference", "malware_alias",
  ),
}
# `source`/`last_imported_from` are envelope fields (§7.2) that move into
# `fields` as flat scalars -- allowed for every label.
ENVELOPE_FIELD_KEYS = frozenset({"source", "last_imported_from"})
# URL-shaped fields keep only `http(s)://` values.
_URL_FIELD_NAMES = frozenset({"reference_urls", "pulse_references", "reference"})
_HTTP_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

_ALLOWED_FIELDS_BY_LABEL: Dict[str, FrozenSet[str]] = {}
for _label_key, _source_key in FIELD_WHITELIST:
  _ALLOWED_FIELDS_BY_LABEL[_label_key] = (
    _ALLOWED_FIELDS_BY_LABEL.get(_label_key, frozenset()) | frozenset(FIELD_WHITELIST[(_label_key, _source_key)])
  )
for _label_key in list(_ALLOWED_FIELDS_BY_LABEL):
  _ALLOWED_FIELDS_BY_LABEL[_label_key] = _ALLOWED_FIELDS_BY_LABEL[_label_key] | ENVELOPE_FIELD_KEYS


def allowed_fields_for_label(label: str) -> FrozenSet[str]:
  """Contract §7.2: the whitelist for one node's label, unioned over every
  source that whitelists fields for it, plus the two envelope keys (allowed
  for every label, whitelisted or not)."""
  return _ALLOWED_FIELDS_BY_LABEL.get(label, ENVELOPE_FIELD_KEYS)


# Contract §7.1: internal, parameterised, read-only, keyed on node element
# ids; one query per response, never per node, never model-generated.
# `elementId()` is the Neo4j 5 identity function (the deprecated `id()`
# integer form is not used). At most 10 `SOURCED_FROM` edges per node,
# ordered by `source_id` for determinism.
MISP_ENRICHMENT_QUERY = """
MATCH (n)
WHERE elementId(n) IN $element_ids
CALL {
  WITH n
  OPTIONAL MATCH (n)-[r:SOURCED_FROM]->(s:Source)
  WITH r, s
  ORDER BY s.source_id
  LIMIT 10
  RETURN collect(
    CASE WHEN r IS NULL THEN null ELSE {source_id: s.source_id, raw_data: r.raw_data} END
  ) AS sourced
}
RETURN
  elementId(n) AS element_id,
  labels(n) AS labels,
  n.misp_event_ids AS misp_event_ids,
  n.misp_attribute_ids AS misp_attribute_ids,
  n.source AS source,
  n.last_imported_from AS last_imported_from,
  [item IN sourced WHERE item IS NOT NULL] AS sourced
"""


def fetch_misp_enrichment_rows(
  session: Any,
  element_ids: Sequence[str],
  *,
  timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> List[Dict[str, Any]]:
  """Runs the one internal query for this response. `session` is any object
  exposing Neo4j's `.run(query, **params)` (a real driver session or a
  fixture double); raises on any driver error -- the caller fails open."""
  if not element_ids:
    return []
  query = Query(MISP_ENRICHMENT_QUERY, timeout=timeout_seconds) if Query is not None else MISP_ENRICHMENT_QUERY
  result = session.run(query, element_ids=list(element_ids))
  return [dict(record) for record in result]


def _is_scalar(value: Any) -> bool:
  return value is None or isinstance(value, (str, int, float, bool))


def _to_list(value: Any) -> List[Any]:
  if value is None:
    return []
  if isinstance(value, (str, int, float, bool)):
    return [value]
  if isinstance(value, (list, tuple)):
    return list(value)
  return []


def _clean_event_ids(value: Any) -> List[str]:
  ids: List[str] = []
  for item in _to_list(value):
    if not _is_scalar(item):
      continue
    text = str(item).strip()
    if EVENT_ID_RE.match(text):
      ids.append(text)
  return ids[:MAX_ID_LIST_ITEMS]


def _clean_attribute_ids(value: Any) -> List[str]:
  ids: List[str] = []
  for item in _to_list(value):
    if not _is_scalar(item):
      continue
    text = str(item).strip()
    if text and len(text) <= ATTRIBUTE_ID_MAX_CHARS:
      ids.append(text)
  return ids[:MAX_ID_LIST_ITEMS]


def _string_is_raw_json(value: str) -> bool:
  stripped = value.strip()
  if stripped[:1] not in "{[":
    return False
  try:
    parsed = json.loads(stripped)
  except (TypeError, ValueError):
    return False
  return isinstance(parsed, (dict, list))


def _clean_scalar(value: Any) -> Any:
  """A flat scalar, or `None` when the value does not qualify: too long, or
  a string that itself parses as a JSON object/array (a raw payload
  smuggled through as a "clean" scalar). Dropping it here at the builder
  keeps the rest of a node's `fields` intact -- the validator's own check
  (`_field_value_is_clean`) is the fail-closed backstop for whatever slips
  past this."""
  if value is None:
    return None
  if isinstance(value, bool):
    return value
  if isinstance(value, str):
    text = value.strip()
    if not text or len(text) > MAX_STRING_CHARS or _string_is_raw_json(text):
      return None
    return text
  if isinstance(value, (int, float)):
    return value
  return None


def _field_value_is_clean(value: Any) -> bool:
  """One `fields[key]` value -- a flat scalar or a flat array of scalars
  only, never a list inside a list, never a dict, and never a string
  (scalar or array item) that itself parses as a JSON object or array (a
  raw payload smuggled through as a "clean" scalar). The validator's
  fail-closed backstop behind `_clean_scalar`/`_normalize_field_value`,
  which already drop such values at build time."""
  if isinstance(value, bool):
    return True
  if isinstance(value, str):
    return bool(value) and len(value) <= MAX_STRING_CHARS and not _string_is_raw_json(value)
  if isinstance(value, (int, float)):
    return True
  if isinstance(value, list):
    if not value or len(value) > MAX_ARRAY_ITEMS:
      return False
    return all(
      not isinstance(item, (list, dict)) and _field_value_is_clean(item)
      for item in value
    )
  return False


def _normalize_field_value(field_name: str, value: Any) -> Any:
  if field_name == "tf_tags":
    # Probe finding 3: `tf_tags` is a list on `threatfox`, a scalar on
    # `urlhaus` -- normalised to one list-of-strings shape.
    if isinstance(value, (str, int, float, bool)):
      value = [value]
    if not isinstance(value, (list, tuple)):
      return None
    items = [str(item).strip() for item in value if _is_scalar(item) and str(item).strip()]
    items = [
      item for item in items
      if len(item) <= MAX_STRING_CHARS and not _string_is_raw_json(item)
    ][:MAX_ARRAY_ITEMS]
    return items or None
  if field_name in _URL_FIELD_NAMES:
    # Keep only `http(s)://` values; a bare scalar source field
    # (`reference`) stays scalar when it survives filtering.
    was_scalar = not isinstance(value, (list, tuple))
    cleaned: List[str] = []
    for item in _to_list(value):
      candidate = _clean_scalar(item)
      if isinstance(candidate, str) and _HTTP_URL_RE.match(candidate):
        cleaned.append(candidate)
    cleaned = cleaned[:MAX_ARRAY_ITEMS]
    if not cleaned:
      return None
    return cleaned[0] if was_scalar and len(cleaned) == 1 else cleaned
  if isinstance(value, (list, tuple)):
    items = []
    for item in value:
      cleaned = _clean_scalar(item)
      if cleaned is not None and cleaned != "":
        items.append(cleaned)
    items = items[:MAX_ARRAY_ITEMS]
    return items or None
  return _clean_scalar(value)


def _primary_label(labels: Any) -> Optional[str]:
  label_set = set(labels or [])
  for candidate in _KNOWN_LABEL_PRIORITY:
    if candidate in label_set:
      return candidate
  for label in labels or []:
    if isinstance(label, str) and label:
      return label
  return None


def build_misp_enrichment_block(
  rows: Sequence[Mapping[str, Any]],
  node_ref_by_element_id: Mapping[str, str],
  *,
  truncated: bool = False,
  omitted_nodes: int = 0,
  now: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
  """Contract §7.3. Returns `None` (block absent) when no supplied row
  carries any MISP-derived content, so an all-empty or all-Campaign result
  never emits a block instead of an empty one.

  A node whose emitted JSON exceeds the 64 KiB per-node cap is skipped
  (folded into `omitted_nodes`/`truncated`), not fatal to the whole block;
  the validator stays as a backstop. A row whose element id is not in
  `node_ref_by_element_id` (never reached the digest) is skipped entirely,
  not emitted with a fallback ref."""
  nodes_out: List[Dict[str, Any]] = []
  oversize_skipped = 0
  for row in rows[:MAX_NODES]:
    element_id = row.get("element_id")
    if element_id is None or element_id not in node_ref_by_element_id:
      continue
    label = _primary_label(row.get("labels"))
    if label is None or label in _SKIPPED_LABELS:
      continue
    misp_event_ids = _clean_event_ids(row.get("misp_event_ids"))
    misp_attribute_ids = _clean_attribute_ids(row.get("misp_attribute_ids"))
    sourced_entries = [
      entry for entry in (row.get("sourced") or [])
      if (
        isinstance(entry, Mapping)
        and entry.get("source_id")
        and isinstance(entry.get("raw_data"), str)
        and entry["raw_data"]
        and len(entry["raw_data"]) <= MAX_RAW_DATA_CHARS
      )
    ]
    if not misp_event_ids and not misp_attribute_ids and not sourced_entries:
      # Consequence #4 (probe report): no MISP id and no `SOURCED_FROM`
      # edge -- Campaign in practice, but the check is label-agnostic.
      continue
    fields: Dict[str, Any] = {}
    for entry in sourced_entries:
      source_id = str(entry.get("source_id") or "").strip().lower()
      try:
        parsed = json.loads(entry["raw_data"])
      except (TypeError, ValueError):
        continue
      if not isinstance(parsed, Mapping):
        continue
      allowed_fields = FIELD_WHITELIST.get((label, source_id), ())
      for field_name in allowed_fields:
        if field_name in fields:
          continue
        normalized = _normalize_field_value(field_name, parsed.get(field_name))
        if normalized is None:
          continue
        fields[field_name] = normalized
    # `source`/`last_imported_from` move into `fields` as flat scalars
    # instead of top-level node keys.
    source_value = _clean_scalar(row.get("source"))
    if source_value is not None:
      fields["source"] = source_value
    last_imported_value = _clean_scalar(row.get("last_imported_from"))
    if last_imported_value is not None:
      fields["last_imported_from"] = last_imported_value

    # Contract §7.3: exactly these six keys, always present.
    node_out: Dict[str, Any] = {
      "node_ref": node_ref_by_element_id[element_id],
      "label": label,
      "misp_event_ids": misp_event_ids,
      "misp_attribute_ids": misp_attribute_ids,
      "misp_event_urls": [
        MISP_EVENT_URL_TEMPLATE.format(event_id=event_id) for event_id in misp_event_ids
      ],
      "fields": fields,
    }
    try:
      node_size = len(json.dumps(
        node_out, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
      ).encode("utf-8"))
    except (TypeError, ValueError):
      node_size = MAX_NODE_BYTES + 1
    if node_size > MAX_NODE_BYTES:
      oversize_skipped += 1
      continue
    nodes_out.append(node_out)

  if not nodes_out:
    return None

  caller_truncated = bool(truncated)
  caller_omitted = max(int(omitted_nodes), 0) if caller_truncated else 0
  is_truncated = caller_truncated or oversize_skipped > 0
  safe_omitted = caller_omitted + oversize_skipped

  canonical = json.dumps(nodes_out, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
  fetched_at_dt = now or datetime.now(timezone.utc)
  fetched_at = fetched_at_dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

  return {
    "schema_version": MISP_ENRICHMENT_SCHEMA_VERSION,
    "source": MISP_ENRICHMENT_SOURCE,
    "fetched_at": fetched_at,
    "sha256": digest,
    "nodes": nodes_out,
    "truncated": is_truncated,
    "omitted_nodes": safe_omitted,
  }


def _field_key_is_clean(key: Any) -> bool:
  """A field key must be a non-empty string that does not match the
  packet-property policy regex -- the one check `misp_block_contains_raw_payload`
  and `_validate_misp_enrichment_node` share on every `fields` key."""
  return isinstance(key, str) and not FORBIDDEN_PACKET_PROPERTY_RE.search(key)


def misp_block_contains_raw_payload(block: Any) -> bool:
  """True if a nested object, a list-inside-list, a forbidden key, or a raw
  JSON string ever reached the block's `fields` -- the signal
  `redaction.contains_raw_misp_payload` would take for the block that
  accompanies a model input, if one ever did (never in slice 3a: the
  graph-evidence packet never carries `misp_enrichment`, so that flag stays
  the v0.1 hard-coded `False`). Used by `validate_misp_enrichment_block` to
  fail closed."""
  if not isinstance(block, dict):
    return True
  nodes = block.get("nodes")
  if not isinstance(nodes, list):
    return True
  for node in nodes:
    if not isinstance(node, dict):
      return True
    fields = node.get("fields")
    if fields is None:
      continue
    if not isinstance(fields, dict):
      return True
    for key, value in fields.items():
      if not _field_key_is_clean(key):
        return True
      if not _field_value_is_clean(value):
        return True
  return False


def _validate_event_ids(values: Any) -> bool:
  if not isinstance(values, list) or len(values) > MAX_ID_LIST_ITEMS:
    return False
  return all(isinstance(value, str) and EVENT_ID_RE.match(value) for value in values)


def _validate_attribute_ids(values: Any) -> bool:
  if not isinstance(values, list) or len(values) > MAX_ID_LIST_ITEMS:
    return False
  return all(isinstance(value, str) and 0 < len(value) <= ATTRIBUTE_ID_MAX_CHARS for value in values)


def _validate_event_urls(event_ids: Any, urls: Any) -> bool:
  if not isinstance(event_ids, list) or not isinstance(urls, list):
    return False
  if len(urls) != len(event_ids):
    return False
  expected = [MISP_EVENT_URL_TEMPLATE.format(event_id=event_id) for event_id in event_ids]
  return urls == expected


def _validate_misp_enrichment_node(node: Any) -> bool:
  """Contract §7.3: exactly the six keys, always present; §7.2: flat,
  whitelisted, bounded, parity-checked; the 64 KiB per-node cap stays as a
  backstop behind the builder's own oversize skip."""
  if not isinstance(node, dict) or set(node) != MISP_ENRICHMENT_ALLOWED_NODE_KEYS:
    return False
  node_ref = node.get("node_ref")
  if not isinstance(node_ref, str) or not node_ref:
    return False
  label = node.get("label")
  if not isinstance(label, str) or not label:
    return False
  event_ids = node.get("misp_event_ids")
  if not _validate_event_ids(event_ids):
    return False
  if not _validate_attribute_ids(node.get("misp_attribute_ids")):
    return False
  if not _validate_event_urls(event_ids, node.get("misp_event_urls")):
    return False
  fields = node.get("fields")
  if not isinstance(fields, dict) or len(fields) > 20:
    return False
  allowed_fields = allowed_fields_for_label(label)
  for key, value in fields.items():
    if not isinstance(key, str) or not key or len(key) > 64 or key not in allowed_fields:
      return False
    if not _field_key_is_clean(key):
      return False
    if not _field_value_is_clean(value):
      return False
  try:
    encoded = json.dumps(node, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
  except (TypeError, ValueError):
    return False
  return len(encoded) <= MAX_NODE_BYTES


def validate_misp_enrichment_block(block: Any) -> bool:
  """Contract §7.3/§7.5: reuses `FORBIDDEN_PACKET_PROPERTY_RE` on every key,
  enforces the caps, flatness and whitelist rules, recomputes `sha256`, and
  fails closed -- any violation drops the whole block rather than emitting
  a partially invalid one."""
  if misp_block_contains_raw_payload(block):
    return False
  if not isinstance(block, dict) or set(block) != MISP_ENRICHMENT_ALLOWED_BLOCK_KEYS:
    return False
  if block.get("schema_version") != MISP_ENRICHMENT_SCHEMA_VERSION:
    return False
  if block.get("source") != MISP_ENRICHMENT_SOURCE:
    return False
  fetched_at = block.get("fetched_at")
  if not isinstance(fetched_at, str) or not fetched_at.endswith("Z"):
    return False
  nodes = block.get("nodes")
  if not isinstance(nodes, list) or not nodes or len(nodes) > MAX_NODES:
    return False
  truncated = block.get("truncated")
  omitted_nodes = block.get("omitted_nodes")
  if not isinstance(truncated, bool):
    return False
  if isinstance(omitted_nodes, bool) or not isinstance(omitted_nodes, int) or omitted_nodes < 0:
    return False
  if not truncated and omitted_nodes != 0:
    return False
  if not all(_validate_misp_enrichment_node(node) for node in nodes):
    return False
  sha256_value = block.get("sha256")
  if not isinstance(sha256_value, str) or not MISP_ENRICHMENT_SHA256_RE.match(sha256_value):
    return False
  canonical = json.dumps(nodes, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
  return recomputed == sha256_value
