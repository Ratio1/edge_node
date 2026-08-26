"""EGM-049 Phase 1: curated per-label field relevance catalog.

Defined up front, before any data reaches the model: only catalogued fields are
ever projected, and each carries a role and a short human meaning the 4B model
will narrate but cannot infer (e.g. cisa_kev = actively exploited in the wild).
Uncatalogued fields — including any newly appearing schema field — are invisible
by construction until deliberately added here.

The corpus audit (EGM-049 Phase 1) showed the `description` field is not prose
but a prefixed structured blob (`OTX_META:{...}`, `MITRE_USES_TECHNIQUES:{...}`,
`MITRE_TACTIC_PHASES:{...}`, `NVD_META:{...}`), sometimes followed by real prose.
`decode_description` parses the blob into derived fields and keeps any trailing
prose; the raw blob is never shown to the model.
"""
from __future__ import annotations

import hashlib
import json
import re

# --------------------------------------------------------------------------
# Catalog: label -> {field: (role, human meaning)}. Order is display order.
# role is a machine tag the insight layer/prompt use; meaning is for the model.
# --------------------------------------------------------------------------

CATALOG = {
    "Indicator": {
        "value": ("identity", "the indicator of compromise (domain, hash, URL, or IP)"),
        "indicator_type": ("kind", "what kind of IOC this is: domain, hash, url, ipv4"),
        "confidence_score": ("confidence", "source confidence in this indicator, 0-1"),
        "active": ("status", "whether the indicator is still considered active"),
        "zone": ("targets", "sectors/zones this indicator is associated with"),
        "first_imported_at": ("ingested", "when EdgeGuard first ingested it (ingest time, not activity time)"),
    },
    "Malware": {
        "name": ("identity", "the malware family name"),
        "uses_techniques": ("techniques", "MITRE ATT&CK techniques this malware uses"),
        "malware_types": ("kind", "malware category"),
        "zone": ("targets", "sectors/zones associated with this malware"),
        "confidence_score": ("confidence", "source confidence, 0-1"),
    },
    "ThreatActor": {
        "name": ("identity", "the threat actor / group name"),
        "aliases": ("aliases", "other names for this actor"),
        "uses_techniques": ("techniques", "MITRE ATT&CK techniques this actor employs"),
        "zone": ("targets", "sectors/zones this actor is associated with"),
        "confidence_score": ("confidence", "source confidence, 0-1"),
    },
    "Technique": {
        "name": ("identity", "the ATT&CK technique name"),
        "mitre_id": ("identity", "the ATT&CK technique ID"),
        "tactic_phases": ("tactic", "which ATT&CK tactic phases this technique belongs to"),
        "is_subtechnique": ("kind", "whether this is a sub-technique"),
    },
    "CVE": {
        "cve_id": ("identity", "the CVE identifier"),
        "cvss_score": ("severity", "CVSS base score, 0-10 (higher is worse)"),
        "severity": ("severity", "qualitative severity rating"),
        "cisa_kev": ("exploited", "on CISA's Known Exploited Vulnerabilities list = actively exploited in the wild"),
        "cwe": ("weakness", "the CWE weakness class"),
        "zone": ("targets", "sectors/zones associated with this CVE"),
    },
    "CVSSv31": {
        "cve_id": ("identity", "the CVE this scoring record belongs to"),
        "base_score": ("severity", "CVSS v3.1 base score, 0-10"),
        "base_severity": ("severity", "qualitative severity"),
        "attack_vector": ("vector", "how the vulnerability is exploited (network/local/etc.)"),
        "exploitability_score": ("severity", "CVSS exploitability sub-score"),
    },
    "Source": {
        "name": ("identity", "the intelligence source name"),
        "reliability": ("confidence", "source reliability, 0-1"),
        "type": ("kind", "kind of source (framework, feed, etc.)"),
    },
    "Sector": {
        "name": ("identity", "the sector name"),
    },
}

# Fields the catalog derives from the `description` blob, per label. Derived
# values only fill in when the same field is absent from the real properties.
DERIVED = {
    "CVE": ("attack_techniques", "cwe"),
    "Technique": ("tactic_phases", "prose"),
    "Malware": ("attack_techniques",),
    "ThreatActor": ("attack_techniques",),
}

# --------------------------------------------------------------------------
# Description-blob decoder
# --------------------------------------------------------------------------

_PREFIX_RE = re.compile(r"^([A-Z_]+):(\{.*)$", re.DOTALL)


def decode_description(raw):
    """Parse a prefixed description blob into derived fields plus any trailing
    prose. Returns {} for a plain string (kept as prose by the caller only when
    the label catalogs `prose`). Never returns the raw blob."""
    if not isinstance(raw, str) or not raw:
        return {}
    out = {}
    text = raw
    m = _PREFIX_RE.match(raw)
    if m:
        prefix = m.group(1)
        # The JSON object may be followed by trailing prose after a newline.
        rest = m.group(2)
        decoded, end = _scan_json_object(rest)
        trailing = rest[end:].lstrip("\n ").strip()
        if decoded is not None:
            if prefix == "OTX_META":
                ids = decoded.get("attack_ids")
                if isinstance(ids, list):
                    out["attack_techniques"] = [str(x) for x in ids]
            elif prefix == "MITRE_USES_TECHNIQUES":
                ids = decoded.get("t")
                if isinstance(ids, list):
                    out["attack_techniques"] = [str(x) for x in ids]
            elif prefix == "MITRE_TACTIC_PHASES":
                ph = decoded.get("p")
                if isinstance(ph, list):
                    out["tactic_phases"] = [str(x) for x in ph]
            elif prefix == "NVD_META":
                cwe = decoded.get("cwe")
                if isinstance(cwe, list) and cwe:
                    out["cwe"] = [str(x) for x in cwe]
        text = trailing
    # Any remaining plain text is prose (used only where catalogued).
    if text and not _PREFIX_RE.match(text):
        out["prose"] = text
    return out


def _scan_json_object(s):
    """Return (parsed_obj_or_None, index_after_object) for a JSON object at the
    start of s, tolerating trailing text. Brace-depth scan, string-aware."""
    if not s or s[0] != "{":
        return None, 0
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(s[: i + 1]), i + 1
                    except ValueError:
                        return None, i + 1
    return None, len(s)


# --------------------------------------------------------------------------
# Projection: node -> catalogued view (drops everything uncatalogued)
# --------------------------------------------------------------------------

def label_of(node):
    labels = node.get("labels") or []
    return labels[0] if labels else "?"


_HEXISH = re.compile(r"^[0-9a-fA-F]{32,}$")
_DOMAINISH = re.compile(r"^(https?://|[a-z0-9-]+\.[a-z]{2,})", re.IGNORECASE)
_IPISH = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_nameable_value(s):
    """A value worth naming in prose (CVE id, actor/malware/technique/sector name)
    vs a raw IOC value (hash, domain, URL, IP, WINDIR path) that should be
    described by type and count, never recited. Raw values are long, hex, or
    look like network artifacts."""
    s = str(s)
    if _HEXISH.match(s) or _DOMAINISH.match(s) or _IPISH.match(s):
        return False
    if "\\" in s or "%" in s or "/" in s:  # WINDIR paths, URLs
        return False
    return len(s) <= 48


def kev_flag(props):
    """CVE known-exploited signal, detectable two ways in the corpus."""
    if "cisa_kev" in (props.get("tags") or []):
        return True
    return bool(props.get("cisa_exploit_add") or props.get("cisa_vulnerability_name"))


def project(node):
    """Return {field: value} for catalogued + derived fields only, in catalog
    order. Uncatalogued fields are omitted. `description` is decoded, never
    passed through raw."""
    label = label_of(node)
    spec = CATALOG.get(label)
    props = node.get("properties") or {}
    if spec is None:
        # Unknown label: expose identity-ish fields only, nothing sensitive.
        name = props.get("name") or props.get("value") or node.get("caption")
        return {"name": name} if name else {}
    decoded = decode_description(props.get("description"))
    view = {}
    for field in spec:
        if field == "cisa_kev":
            view["cisa_kev"] = kev_flag(props)
        elif field == "cwe":
            if decoded.get("cwe"):
                view["cwe"] = decoded["cwe"]
        elif field in props and props[field] not in (None, "", [], {}):
            view[field] = props[field]
    # Derived, catalogued-per-label fields (fill in only if absent from props)
    for d in DERIVED.get(label, ()):  # e.g. CVE attack_techniques, Technique prose
        if d not in view and decoded.get(d):
            view[d] = decoded[d]
    return view


def catalog_meanings(labels_present):
    """Return the {field: meaning} legend for the labels actually in a result,
    so the prompt can teach the model only the relevant field semantics."""
    out = {}
    for label in labels_present:
        for field, (_role, meaning) in CATALOG.get(label, {}).items():
            out.setdefault(field, meaning)
    out.setdefault("cisa_kev", CATALOG["CVE"]["cisa_kev"][1])
    return out


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


CATALOG_SHA256 = hashlib.sha256(
    _canonical({label: {f: list(v) for f, v in spec.items()} for label, spec in CATALOG.items()}).encode()
).hexdigest()
