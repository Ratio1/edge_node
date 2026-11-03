"""MISP enrichment block, v1 (contract §7, no network).

Builds the `misp_enrichment` block from `raw_data` already in Neo4j (the
flattened `SOURCED_FROM` source payload, a JSON string) plus the node's own
MISP id lists. Read by one internal, parameterised, read-only Cypher query
keyed on node element ids -- never a model-generated query. Explanation
spec v0.2 (approved 2026-09-28) admits the validated block, as the compact
`build_model_view`, into EAB/1 and EGX/2 model input only. Every function here is
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
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

try:  # pragma: no cover - neo4j is an optional runtime dependency in tests.
  from neo4j import Query
except Exception:  # noqa: BLE001 - exercised by the test suite (no neo4j installed).
  Query = None

MISP_ENRICHMENT_SCHEMA_VERSION = "edgeguard.misp_enrichment.v1"
MISP_ENRICHMENT_SOURCE = "neo4j_raw_data"
# Explanation spec v0.3 §4: the default event URL template; the plugin config
# `MISP_ENRICHMENT_EVENT_URL_TEMPLATE` overrides it per request and every
# build/validate path takes the resolved value as `event_url_template`.
DEFAULT_EVENT_URL_TEMPLATE = "https://misp.edgeguard.org/events/view/{event_id}"
EVENT_URL_PLACEHOLDER = "{event_id}"
EVENT_URL_TEMPLATE_MAX_CHARS = 200

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
    "pulse_id",
  ),
  ("Indicator", "threatfox"): (
    "threat_type", "threat_type_desc", "tf_tags", "reference", "malware_alias",
    "ioc_id",
  ),
  ("Indicator", "urlhaus"): (
    "threat_type", "threat_type_desc", "tf_tags", "reference", "malware_alias",
    "ioc_id",
  ),
}
# `source`/`last_imported_from` are envelope fields (§7.2) that move into
# `fields` as flat scalars -- allowed for every label.
ENVELOPE_FIELD_KEYS = frozenset({"source", "last_imported_from"})
# Explanation spec v0.3 §3.1: freshness timestamps, built from every sourced
# entry of any label (envelope-only sources included), allowed for every label.
SOURCE_TIMESTAMP_FIELDS = ("first_seen_at_source", "last_seen_at_source")
# Spec v0.3 §3.2: fields shown to playground users only; no model view
# (EAB/1 or EGX/2) ever carries them.
UI_ONLY_FIELDS = frozenset({*SOURCE_TIMESTAMP_FIELDS, "pulse_id", "ioc_id"})
SOURCE_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", re.ASCII)
_SOURCE_TIMESTAMP_INPUT_RE = re.compile(
  r"^(\d{4})-(\d{2})-(\d{2})"
  r"(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,]\d+)?)?"
  r"(Z|z|[+-]\d{2}(?::?\d{2})?)?)?$",
  re.ASCII,
)
# URL-shaped fields keep only `http(s)://` values.
_URL_FIELD_NAMES = frozenset({"reference_urls", "pulse_references", "reference"})
_HTTP_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

_ALLOWED_FIELDS_BY_LABEL: Dict[str, FrozenSet[str]] = {}
for _label_key, _source_key in FIELD_WHITELIST:
  _ALLOWED_FIELDS_BY_LABEL[_label_key] = (
    _ALLOWED_FIELDS_BY_LABEL.get(_label_key, frozenset()) | frozenset(FIELD_WHITELIST[(_label_key, _source_key)])
  )
for _label_key in list(_ALLOWED_FIELDS_BY_LABEL):
  _ALLOWED_FIELDS_BY_LABEL[_label_key] = _ALLOWED_FIELDS_BY_LABEL[_label_key] | ENVELOPE_FIELD_KEYS | frozenset(SOURCE_TIMESTAMP_FIELDS)


def allowed_fields_for_label(label: str) -> FrozenSet[str]:
  """Contract §7.2: the whitelist for one node's label, unioned over every
  source that whitelists fields for it, plus the two envelope keys (allowed
  for every label, whitelisted or not)."""
  return _ALLOWED_FIELDS_BY_LABEL.get(label, ENVELOPE_FIELD_KEYS | frozenset(SOURCE_TIMESTAMP_FIELDS))


# Explanation spec v0.3 §4: the URL language of an expanded template, written
# once and shared (as `tests/fixtures/misp_event_url_template_cases.json`) with
# the playground validator: lowercase `https`, an ASCII host, an optional port,
# non-empty path segments, the event id last. No userinfo, query or fragment.
_EVENT_URL_RE = re.compile(
  r"https://[A-Za-z0-9][A-Za-z0-9.-]*(?::(?P<port>[1-9][0-9]{0,4}))?(?:/[A-Za-z0-9._~%-]+)*/[0-9]+",
  re.ASCII,
)


def validate_event_url_template(value: Any) -> bool:
  """Explanation spec v0.3 §4: at most 200 printable ASCII characters, with
  `{event_id}` exactly once as the last path segment, and the expansion with a
  sample id inside the playground's event URL language (port 1-65535)."""
  if not isinstance(value, str) or not 0 < len(value) <= EVENT_URL_TEMPLATE_MAX_CHARS:
    return False
  if value.count(EVENT_URL_PLACEHOLDER) != 1 or not value.endswith("/" + EVENT_URL_PLACEHOLDER):
    return False
  return event_url_is_valid(value.replace(EVENT_URL_PLACEHOLDER, "123"), "123")


def _event_url(template: str, event_id: str) -> str:
  return template.replace(EVENT_URL_PLACEHOLDER, event_id)


def event_url_is_valid(url: Any, event_id: str) -> bool:
  """Explanation spec v0.4 §5.2: an emitted event URL is inside the v0.3 §4
  URL language, at most 200 characters, and ends in its own event id."""
  if not isinstance(url, str) or not 0 < len(url) <= EVENT_URL_TEMPLATE_MAX_CHARS:
    return False
  match = _EVENT_URL_RE.fullmatch(url)
  if match is None or not url.endswith("/" + event_id):
    return False
  port = match.group("port")
  return port is None or 1 <= int(port) <= 65535


def parse_source_timestamp(value: Any) -> Optional[datetime]:
  """Explanation spec v0.3 §3.1: an ISO 8601 date or date-time (`T` or space
  separator, optional fraction, optional offset; naive = UTC; date-only =
  00:00:00Z) as an aware UTC datetime, whole seconds. Anything else -- empty,
  garbage, epoch numbers, non-strings -- is `None`."""
  if not isinstance(value, str):
    return None
  match = _SOURCE_TIMESTAMP_INPUT_RE.fullmatch(value.strip())
  if match is None:
    return None
  year, month, day, hour, minute, second, zone = match.groups()
  try:
    moment = datetime(
      int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0),
      tzinfo=timezone.utc,
    )
    if zone and zone not in {"Z", "z"}:
      digits = zone[1:].replace(":", "")
      offset_hours, offset_minutes = int(digits[:2]), int(digits[2:] or 0)
      if offset_hours > 23 or offset_minutes > 59:
        return None
      offset = timedelta(hours=offset_hours, minutes=offset_minutes)
      moment = moment - offset if zone[0] == "+" else moment + offset
  except (ValueError, OverflowError):
    return None
  return moment


def _format_source_timestamp(moment: datetime) -> str:
  return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


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
  if field_name in {"pulse_id", "ioc_id"}:
    # Source-record ids: a non-empty string, or (ioc_id) an integer; never a
    # float, bool or container.
    if isinstance(value, bool) or not isinstance(value, (str, int)):
      return None
    if isinstance(value, int):
      return value if field_name == "ioc_id" else str(value)
    return _clean_scalar(value)
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
  event_url_template: str = DEFAULT_EVENT_URL_TEMPLATE,
) -> Optional[Dict[str, Any]]:
  """Contract §7.3. Returns `None` (block absent) when no supplied row
  carries any MISP-derived content, so an all-empty or all-Campaign result
  never emits a block instead of an empty one.

  A node whose emitted JSON exceeds the 64 KiB per-node cap is skipped
  (folded into `omitted_nodes`/`truncated`), not fatal to the whole block;
  the validator stays as a backstop. A row whose element id is not in
  `node_ref_by_element_id` (never reached the digest) is skipped entirely,
  not emitted with a fallback ref."""
  if not validate_event_url_template(event_url_template):
    raise ValueError("invalid event url template")
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
    first_seen: List[datetime] = []
    last_seen: List[datetime] = []
    for entry in sourced_entries:
      source_id = str(entry.get("source_id") or "").strip().lower()
      try:
        parsed = json.loads(entry["raw_data"])
      except (TypeError, ValueError):
        continue
      if not isinstance(parsed, Mapping):
        continue
      for timestamps, key in ((first_seen, SOURCE_TIMESTAMP_FIELDS[0]), (last_seen, SOURCE_TIMESTAMP_FIELDS[1])):
        moment = parse_source_timestamp(parsed.get(key))
        if moment is not None:
          timestamps.append(moment)
      allowed_fields = FIELD_WHITELIST.get((label, source_id), ())
      for field_name in allowed_fields:
        if field_name in fields:
          continue
        normalized = _normalize_field_value(field_name, parsed.get(field_name))
        if normalized is None:
          continue
        fields[field_name] = normalized
    # Spec v0.3 §3.1: earliest first-seen, latest last-seen across entries.
    if first_seen:
      fields[SOURCE_TIMESTAMP_FIELDS[0]] = _format_source_timestamp(min(first_seen))
    if last_seen:
      fields[SOURCE_TIMESTAMP_FIELDS[1]] = _format_source_timestamp(max(last_seen))
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
        _event_url(event_url_template, event_id) for event_id in misp_event_ids
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
  JSON string ever reached the block's `fields`. Used by
  `validate_misp_enrichment_block` to fail closed; the model-admission flag
  itself is `contains_raw_misp_payload` below (the full validator)."""
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


def _validate_event_urls(event_ids: Any, urls: Any, event_url_template: str) -> bool:
  if not isinstance(event_ids, list) or not isinstance(urls, list):
    return False
  if len(urls) != len(event_ids):
    return False
  expected = [_event_url(event_url_template, event_id) for event_id in event_ids]
  return urls == expected


def _validate_misp_enrichment_node(node: Any, event_url_template: str) -> bool:
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
  if not _validate_event_urls(event_ids, node.get("misp_event_urls"), event_url_template):
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
    if key in SOURCE_TIMESTAMP_FIELDS and not (isinstance(value, str) and SOURCE_TIMESTAMP_RE.fullmatch(value)):
      return False
  try:
    encoded = json.dumps(node, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
  except (TypeError, ValueError):
    return False
  return len(encoded) <= MAX_NODE_BYTES


def validate_misp_enrichment_block(block: Any, event_url_template: str = DEFAULT_EVENT_URL_TEMPLATE) -> bool:
  """Contract §7.3/§7.5: reuses `FORBIDDEN_PACKET_PROPERTY_RE` on every key,
  enforces the caps, flatness and whitelist rules, recomputes `sha256`, and
  fails closed -- any violation drops the whole block rather than emitting
  a partially invalid one."""
  if not validate_event_url_template(event_url_template):
    return False
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
  if not all(_validate_misp_enrichment_node(node, event_url_template) for node in nodes):
    return False
  sha256_value = block.get("sha256")
  if not isinstance(sha256_value, str) or not MISP_ENRICHMENT_SHA256_RE.match(sha256_value):
    return False
  canonical = json.dumps(nodes, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
  return recomputed == sha256_value


def contains_raw_misp_payload(block: Any, event_url_template: str = DEFAULT_EVENT_URL_TEMPLATE) -> bool:
  """Explanation spec v0.2 §4: `redaction.contains_raw_misp_payload`,
  computed against the block that would accompany a model input -- `False`
  when no block accompanies it, `True` when the block breaks any
  validation rule. Never declared by the producer."""
  if block is None:
    return False
  return not validate_misp_enrichment_block(block, event_url_template)


# Explanation spec v0.2 §5: the compact, model-facing view of a validated
# block. Event URLs and attribute ids are omitted (derivable / bookkeeping),
# `last_imported_from` is ingest bookkeeping, and array fields are cut to a
# few items. The view is then fitted to the caller's byte budget greedily, in
# block order: a node that does not fit whole loses its largest fields first,
# and a node whose envelope alone does not fit is omitted.
MODEL_VIEW_SCHEMA_VERSION = "edgeguard.misp_enrichment_model_view.v1"
MODEL_VIEW_ARRAY_ITEMS = 5
_MODEL_VIEW_EXCLUDED_FIELDS = frozenset({"last_imported_from"}) | UI_ONLY_FIELDS


def _model_view_bytes(view: Mapping[str, Any]) -> int:
  return len(json.dumps(view, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def build_model_view(
  block: Any,
  *,
  max_bytes: int,
  entity_by_ref: Optional[Mapping[str, str]] = None,
  fields_by_label: Optional[Mapping[str, Any]] = None,
  event_url_template: str = DEFAULT_EVENT_URL_TEMPLATE,
) -> Optional[Dict[str, Any]]:
  """The model view of `block`, or `None` when there is no valid block or
  not even one node fits `max_bytes` (canonical JSON, sorted keys). Values
  are copied verbatim from the block, never shortened, so any value the
  model quotes from the view is a verbatim block value. With
  `entity_by_ref`, only nodes it names are kept and each carries its
  `entity` display name (EGX/2 links enrichment to sheet entities); with
  `fields_by_label`, only the fields it lists for a node's label are kept
  (the EGX/2 field catalog). Deterministic for a given block and budget."""
  if block is None or not validate_misp_enrichment_block(block, event_url_template):
    return None
  truncated = bool(block["truncated"])
  candidates: List[Dict[str, Any]] = []
  for node in block["nodes"]:
    if entity_by_ref is not None and node["node_ref"] not in entity_by_ref:
      continue
    fields: Dict[str, Any] = {}
    for key in sorted(node["fields"]):
      if key in _MODEL_VIEW_EXCLUDED_FIELDS:
        continue
      if fields_by_label is not None and key not in (fields_by_label.get(node["label"]) or ()):
        continue
      value = node["fields"][key]
      if isinstance(value, list) and len(value) > MODEL_VIEW_ARRAY_ITEMS:
        value = value[:MODEL_VIEW_ARRAY_ITEMS]
        truncated = True
      fields[key] = value
    entry: Dict[str, Any] = {
      "node_ref": node["node_ref"],
      "label": node["label"],
      "misp_event_ids": list(node["misp_event_ids"]),
      "fields": fields,
    }
    if entity_by_ref is not None:
      entry["entity"] = entity_by_ref[node["node_ref"]]
    candidates.append(entry)
  omitted = int(block["omitted_nodes"]) + (len(block["nodes"]) - len(candidates))

  def view_of(nodes: List[Dict[str, Any]], omitted_count: int, is_truncated: bool) -> Dict[str, Any]:
    return {
      "schema_version": MODEL_VIEW_SCHEMA_VERSION,
      "nodes": nodes,
      "omitted_nodes": omitted_count,
      "truncated": bool(is_truncated or omitted_count > 0),
    }

  # Measured against the final `omitted_nodes` upper bound, and one byte
  # short of the budget (`false` is one byte longer than `true`), so the
  # final counters can only shrink the view, never push it over the budget.
  worst_omitted = omitted + len(candidates)
  kept: List[Dict[str, Any]] = []
  for entry in candidates:
    fields = dict(entry["fields"])
    while True:
      trial = {**entry, "fields": fields}
      if _model_view_bytes(view_of(kept + [trial], worst_omitted, True)) <= max_bytes - 1:
        kept.append(trial)
        if len(fields) < len(entry["fields"]):
          truncated = True
        break
      if not fields:
        break
      largest = max(sorted(fields), key=lambda key: len(json.dumps(fields[key], ensure_ascii=False)))
      fields = {key: value for key, value in fields.items() if key != largest}
  if not kept:
    return None
  view = view_of(kept, omitted + len(candidates) - len(kept), truncated)
  return view if _model_view_bytes(view) <= max_bytes else None


# Explanation spec v0.2 §5: the one lexical grounding rule set shared by
# EAB/1 (`analyst_brief`) and EGX/2 (`egx2.brief_gates`). Fail-closed; it
# also runs without a block, so a model can never invent a URL or CWE id.
URL_TOKEN_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
# `javascript:` / `vbscript:` followed, after optional whitespace, by any
# non-space (browsers tolerate `javascript: alert(1)`); `data:` only when a
# MIME type or `,` / `;` follows (optional whitespace), so prose such as
# "source data: one CVE" still passes.
UNSAFE_SCHEME_RE = re.compile(
  r"(?<![a-z0-9+.-])(?:(?:javascript|vbscript):(?=\s*\S)"
  r"|data:\s*(?:[a-z0-9.+-]+/[a-z0-9.+-]+|[,;]))",
  re.IGNORECASE,
)
CWE_TOKEN_RE = re.compile(r"(?<![a-z0-9-])cwe-\d+(?!\d)", re.IGNORECASE)
# Values shorter than this, and closed-vocabulary category fields (feed
# name, roles, types, TLP, industries, tags), are shared vocabulary, not a
# fact about one node, so they are never attributed to a node.
ATTRIBUTION_MIN_CHARS = 6
ATTRIBUTION_EXCLUDED_FIELDS = frozenset({
  "source", "indicator_role", "threat_type", "pulse_tlp", "otx_industries",
})


def url_tokens(text: str) -> List[str]:
  """Complete `http(s)://` URL tokens in `text`, trailing punctuation cut."""
  return [match.group(0).rstrip(".,;:!?") for match in URL_TOKEN_RE.finditer(text or "")]


def cwe_tokens(text: str) -> List[str]:
  return [match.group(0).lower() for match in CWE_TOKEN_RE.finditer(text or "")]


def mentions(text: str, name: str) -> bool:
  """`name` occurs in `text` as a whole token (case-insensitive), so
  `203.0.113.7` is not found inside `203.0.113.70`."""
  if not name:
    return False
  return re.search(rf"(?<![a-z0-9]){re.escape(name.lower())}(?![a-z0-9])", (text or "").lower()) is not None


def view_node_values(node: Mapping[str, Any], *, attributable_only: bool = False) -> List[str]:
  """The string values under one model-view node's `fields`, verbatim.
  `attributable_only` keeps the distinctive ones (the mismatch rule)."""
  values: List[str] = []
  for key, value in (node.get("fields") or {}).items():
    if attributable_only and key in ATTRIBUTION_EXCLUDED_FIELDS:
      continue
    for item in value if isinstance(value, list) else [value]:
      if isinstance(item, str) and (not attributable_only or len(item) >= ATTRIBUTION_MIN_CHARS):
        values.append(item)
  return values


def enrichment_grounding_error(
  claims: Sequence[Tuple[str, Any]],
  *,
  evidence_texts: Sequence[str],
  view: Optional[Mapping[str, Any]],
  names_by_ref: Mapping[str, Any],
  known_names: Sequence[str] = (),
) -> Optional[str]:
  """Spec v0.2 §5 for one model output. `claims` is every output text with
  the names of the result nodes it is typed to be about (EGX/2 exemplars;
  may be empty); each text is also about every `known_names` entry (every
  digest identity, or every sheet and view entity) it mentions, enriched or
  not. `evidence_texts` is every non-enrichment evidence string (digest,
  projection, question or sheet); `names_by_ref` names each view node the
  way `claims` do. Returns a fixed error code, or `None`:

  - `unsafe_url_scheme`: a `javascript:` / `data:` / `vbscript:` token;
  - `ungrounded_url`: a URL token that is not exactly a URL token of the
    evidence or the view (no prefix or substring matches);
  - `ungrounded_cwe`: a CWE id absent from the evidence and the view;
  - `enrichment_node_mismatch`: a claim about some nodes carries a CWE id or
    distinctive enrichment value that belongs only to another node's view
    entry (the node the claim is about must own the value). Values match
    as whole tokens (`mentions`), and a value that also occurs in the
    evidence or in the view entry of a node the claim is about is exempt.
  """
  nodes = [
    node for node in ((view or {}).get("nodes") or [])
    if isinstance(node, Mapping) and isinstance(node.get("node_ref"), str)
  ]
  view_texts = [value for node in nodes for value in view_node_values(node)]
  allowed_urls = {url for text in list(evidence_texts) + view_texts for url in url_tokens(text)}
  base_cwes = {token for text in evidence_texts for token in cwe_tokens(text)}
  allowed_cwes = base_cwes | {token for text in view_texts for token in cwe_tokens(text)}
  for text, _about in claims:
    if UNSAFE_SCHEME_RE.search(text or ""):
      return "unsafe_url_scheme"
    if any(url not in allowed_urls for url in url_tokens(text)):
      return "ungrounded_url"
    if any(token not in allowed_cwes for token in cwe_tokens(text)):
      return "ungrounded_cwe"
  evidence_joined = "\n".join(evidence_texts)
  known = {str(name).lower() for name in known_names if name}
  for text, about in claims:
    about = {str(name).lower() for name in about or () if name}
    about |= {name for name in known if mentions(text, name)}
    if not about:
      continue
    owned = [node for node in nodes if about & {str(n).lower() for n in names_by_ref.get(node["node_ref"], ())}]
    others = [node for node in nodes if node not in owned]
    own_values = {value.lower() for node in owned for value in view_node_values(node)}
    own_cwes = {token for value in own_values for token in cwe_tokens(value)}
    for token in cwe_tokens(text):
      if token in own_cwes or token in base_cwes:
        continue
      if any(token in cwe_tokens(value) for node in others for value in view_node_values(node)):
        return "enrichment_node_mismatch"
    for node in others:
      for value in view_node_values(node, attributable_only=True):
        if (
          mentions(text, value)
          and value.lower() not in own_values
          and not mentions(evidence_joined, value)
        ):
          return "enrichment_node_mismatch"
  return None
