"""
Structured findings for authenticated webapp (graybox) probes.

GrayboxFinding is the probe-level finding type. It is converted to a
unified flat finding dict (matching blackbox findings) at the report
level via to_flat_finding(). The blackbox Finding in findings.py is
NOT modified.

Subphase 1.6 (centralised evidence scrubber): every finding traversing
to_flat_finding() passes through `scrub_graybox_secrets`, which strips
Authorization/Cookie/JWT/`password=…`/api_key/etc. patterns from the
evidence list, evidence_artifacts request/response snapshots, finding
description, title, and replay_steps. Probes still SHOULD redact at
emission time (via ProbeBase.emit_*), but the storage-boundary
scrubber is defense-in-depth — one forgetful probe author cannot leak
secrets into the archive, LLM input, or PDF.
"""

from __future__ import annotations

import re
import contextvars
from dataclasses import dataclass, asdict, field
from typing import Any

from ..references import reference_urls as _reference_urls
from ..models.finding_schema import (
  REDMESH_FINDING_SCHEMA,
  REDMESH_FINDING_SCHEMA_VERSION,
  normalize_confidence as _normalize_confidence,
)
from ..models.finding_identity import (
  content_hash as _content_hash,
  dedup_key as _dedup_key,
  parse_cwe_list as _parse_cwe_list,
)


# ── Centralised secret scrubber (Subphase 1.6 commit #2) ────────────────

# Generic patterns applied to every flat finding regardless of which
# AuthDescriptor was active. Configured names (X-Custom-Key, custom query
# params) are added to the per-call scrub via ``secret_field_names``
# when ProbeBase.emit_* invokes the scrubber with the live AuthDescriptor.
# Every value-consuming pattern refuses a value that is already `<redacted>`.
# Without that the scrubber is not a fixed point: a second pass over
# `Authorization: <redacted>'` re-matches and swallows the trailing quote,
# because the placeholder is just as consumable as the secret it replaced. That
# is how a shell-safe curl reproduction came out with unbalanced quoting — the
# line is scrubbed once at assembly, again at emission, and again at the storage
# boundary, and only the first pass was ever meant to change it.
_ALREADY_REDACTED = r"(?!\s*<redacted>)"

# `Set-Cookie` attributes, which are policy metadata rather than credential
# material. `probes/misconfig.py` reports `missing_Secure` / `missing_HttpOnly` /
# `weak_SameSite`, so these have to survive the scrubber or the cookie-hardening
# scenarios lose the evidence for the finding they just raised.
#
# Only meaningful in a `Set-Cookie` *response*, and only after the first pair:
# a request `Cookie:` header is a flat list where `path` and `secure` are
# ordinary cookie names, and the first pair of a `Set-Cookie` is the cookie
# itself however it happens to be named. Applying this set outside those bounds
# hands real values a free pass.
# `comment` and `version` are deliberately absent. They are RFC 2965, effectively
# dead, and their values are free server-chosen text — keeping them whole meant
# `Set-Cookie: sid=x; Comment=<anything>` walked through. Every name here has a
# structured or enumerated value instead.
_COOKIE_ATTRIBUTES = frozenset({
  "path", "domain", "expires", "max-age", "samesite",
  "secure", "httponly", "partitioned", "priority",
})

_REDACTED = "<redacted>"


def _redacted_in_place(segment: str) -> str:
  """Replace a whole segment, preserving the separator spacing around it."""
  lead = segment[:len(segment) - len(segment.lstrip())]
  return f"{lead}{_REDACTED}"


def _is_a_cookie_header_value(value: str) -> bool:
  """Whether text after a `cookie:` actually introduces a cookie header.

  `probes/misconfig.py` writes its cookie-hardening evidence as
  `f"{cookie.name}:missing_Secure"` from a *target-controlled* cookie name, and
  `_flat_evidence_summary` joins those with "; ". A cookie called
  `session-cookie` therefore produces text shaped exactly like a header, and a
  target that can make this rule fire on its own evidence can redact the finding
  it is the evidence for.

  Two tests, because neither alone holds:

  * The first pair of a real cookie header is a `name=value` (or a lone opaque
    value). Requiring a separator after the colon instead — the first attempt —
    stopped redacting a spaceless `Cookie:sessionid=…`, which RFC 7230 permits
    and which no other pattern covers; `sessionid`, `PHPSESSID` and `connect.sid`
    appear in none of them.
  * The name of that first pair must not itself contain a colon. `http.cookiejar`
    accepts a cookie literally named `Cookie: y`, which makes
    `Cookie: y:missing_Secure` satisfy both the separator and the `name=value`
    shape further along the line. A cookie name is the one part of this text the
    target writes, so the check has to survive the target choosing it.

  Two residuals, both narrow, both preferred to another layer of heuristic:

  * A cookie named exactly `cookie` (or `*-cookie`) whose first reported issue
    carries a value — `Cookie:weak_SameSite=absent` — still reads as a header,
    and that one token is redacted. One token of degraded evidence.
  * A spaceless `Cookie:` whose *first* pair has no `=` (`Cookie:OPAQUETOKEN`)
    is not redacted, though `Cookie: OPAQUETOKEN` is. Separating it from
    `cookie:missing_Secure` needs a signal neither string carries. It is a
    malformed header — RFC 6265 requires `name "=" value` — reachable only by
    appearing inside a target response body. Closing it would mean guessing, and
    guessing wrong destroys evidence a target chose the name of.
  """
  first = value.split(";")[0]
  if ":" in first.split("=")[0]:
    return False
  return value[:1] in (" ", "\t") or "=" in first


def _redact_cookie_header(match: "re.Match") -> str:
  """Redact every cookie value in a header, keeping names and attribute flags.

  A cookie header is a `;`-separated list, and `;` is its *internal* pair
  delimiter — not a field separator. The previous pattern stopped there, so only
  the first pair was redacted and a session id in any later position survived
  verbatim into the archive, the LLM input, the PDF and the exports. Analytics
  and preference cookies are routinely sent first, which made "any later
  position" the ordinary case rather than the corner one.

  Per pair rather than whole-header, so the `Set-Cookie` attributes survive for
  `misconfig` to report on and cookie *names* stay legible in evidence. Names are
  not secrets; values are, so a pair loses its value regardless of what it is
  called — `sessionid`, `PHPSESSID` and `connect.sid` are in no generic
  `name=value` pattern and would otherwise have no second line of defence.

  Everything below is a defect this had before review found it, kept as the
  reason each rule is shaped the way it is:

  * A segment with no `=` is an opaque *value*, not a free pass. Only a
    `Set-Cookie` attribute flag past the first pair is safe to keep whole.
  * The attribute allowlist belongs to the response direction alone, and only
    past the first pair. In a request header `secure=…` is a cookie like any
    other, and a `Set-Cookie`'s first pair is the cookie however it is named.
  * An attribute value carrying a comma is not trusted, because `urllib3` folds
    duplicate `Set-Cookie` headers with `", "` — so `Path=/, sessionid=…` is two
    cookies wearing one segment, and keeping it whole hid the second.
  * The already-redacted guard tests that the value *is* the placeholder, not
    that it starts with one: a target picks its own cookie values, and
    `sid=<redacted>SECRET` walked straight through a prefix test.

  The match stops at an argument-closing `'`, and that is what makes the rest
  safe. This runs four to six times over one string — assembly, emission,
  persist, aggregate — and `_curl_reproduction` embeds an already-scrubbed header
  inside a `shlex.quote`d argument. Reading past the closing quote let a trailing
  pair swallow the rest of the command: the URL, the later `-H`s and the quote
  itself, leaving a replay step that will not parse. An empty cookie value
  (`csrftoken=`, which `http.cookiejar` emits for any cleared cookie) was enough
  to trigger it. Bounding there makes the value's end the header's end, and that
  is what lets the guard above be an equality test rather than the prefix test
  that leaked.

  *Argument-closing*, not any `'`, because the target picks cookie values and
  `'` is inside RFC 6265's `cookie-octet`. Stopping at the first quote handed a
  target the same suppression `_is_a_cookie_header_value` exists to deny: one
  cookie holding a quote ended the match early and every pair after it — the
  session id among them — reached the archive verbatim. `Set-Cookie: a=x',
  b=SESSIONSECRET` did it in one response header, no cookiejar round trip.

  `shlex.quote` renders an embedded quote as `'"'"'`, so a `'` that closes an
  argument is always followed by whitespace or end of string and one inside a
  value never is. The residue is a cookie value containing `'` immediately before
  a space, which `cookie-octet` excludes.
  """
  name, colon, value = match.group(1), match.group(2), match.group(3)
  if not _is_a_cookie_header_value(value):
    return match.group(0)
  is_response = name.strip().lower() == "set-cookie"
  segments = []
  for index, segment in enumerate(value.split(";")):
    key, assigned, raw = segment.partition("=")
    if (is_response and index and "," not in raw
        and key.strip().lower() in _COOKIE_ATTRIBUTES):
      segments.append(segment)
      continue
    if assigned:
      keep = not raw.strip() or raw.strip() == _REDACTED
      segments.append(segment if keep else f"{key}={_REDACTED}")
      continue
    keep = not segment.strip() or segment.strip() == _REDACTED
    segments.append(segment if keep else _redacted_in_place(segment))
  return f"{name}{colon}{';'.join(segments)}"


_SCRUB_PATTERNS = (
  # Whole-header redaction: redact the full value, which spans until the
  # next field separator (comma/newline) or end of string. Cookies are handled
  # separately below — a semicolon does not end their value.
  (re.compile(r"(?i)\b(authorization)\s*:" + _ALREADY_REDACTED + r"\s*[^,\r\n;]+"),
   r"\1: <redacted>"),
  # Both cookie headers, to end of line. `set-cookie` is listed first so that
  # leftmost-match plus alternation order claims it whole rather than leaving the
  # bare `cookie` branch to match its tail — a lookbehind for `-` does the same
  # job but also stops matching `X-Auth-Cookie:` and friends, which `\b` catches.
  #
  # Whether the match is really a header is decided in `_is_a_cookie_header_value`
  # — `misconfig` writes evidence shaped like one from a target-controlled cookie
  # name, and a target must not be able to suppress its own finding by naming a
  # cookie. The value stops at an *argument-closing* quote so an already-scrubbed
  # header embedded in a `shlex.quote`d curl argument cannot swallow the rest of
  # the command — see `_redact_cookie_header` for why the quote alone is not it.
  (re.compile(r"(?i)\b(set-cookie|cookie)(\s*:)((?:[^\r\n']|'(?!\s|$))*)"),
   _redact_cookie_header),
  # JWT (3 base64url chunks separated by dots, leading eyJ).
  (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
   "<jwt-redacted>"),
  # Bearer schema in body / URL: keep prefix only.
  (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer <redacted>"),
  # Common name=value forms (cookie / form / URL query).
  (re.compile(r"(?i)\b(password|secret|token|api_key|apikey)=" + _ALREADY_REDACTED
              + r"([^&\s\";,]+)"),
   r"\1=<redacted>"),
  # JSON-style key:value.
  (re.compile(r'(?i)"(password|secret|token|api_key|bearer_token|api[\w_-]*key)"\s*:\s*"[^"]+"'),
   r'"\1": "<redacted>"'),
)


# `endpoint=<url>` is the established convention across the probes and was the
# de-facto location before GrayboxFinding carried a typed one. The first key
# found wins, scanning evidence items in order.
#
# Lives here rather than in `probes/base.py` — where it started, and where it
# only reached probes emitting through `emit_*` — because it is a finding-shaping
# concern and `to_flat_finding` has to apply it too. The four probes that append
# `GrayboxFinding(...)` directly never populate `url`, so without this at the
# normalisation boundary their findings reach `dedup_key` with no location and
# collapse onto one identity. The import direction settles the placement anyway:
# `probes/base.py` imports from here.
_LOCATION_EVIDENCE_KEYS = ("endpoint=", "path=", "protected_path=", "token_path=")
_PARAMETER_EVIDENCE_KEYS = ("parameter=", "param=")


def location_from_evidence(evidence):
  """Return ``(url, parameter)`` recovered from evidence strings, or (None, None).

  Reads the structured `key=value` prefixes only. This is deliberately *not* the
  free-text evidence string that pre-RM-062 identity hashed: promoting a known
  key to a typed field keeps identity stable under rewording, where hashing the
  string re-identified every finding whenever a probe changed its phrasing.

  Read from the **first `;`-separated clause of each evidence item only**, and
  only when the whole list agrees on one location. Both halves are deliberate,
  and each replaced something that was worse:

  *Only the first clause*, because 16 of the 65 location-bearing literals are
  composites like `endpoint={path}; param={p}; payload={payload}`. Taking the
  whole item swept the tail into the location, and the tail is routinely
  target-derived — `probed_len={len(response.text)}`, the reflected `Location`
  header, a `repr()` of a record owner field, a status code. Hashed into the
  asset, that gave a finding a new identity whenever the target's response moved.

  *Only the first clause*, also, because scanning every clause let the target
  write its own identity. Items like `server_returned={body!r}` and
  `first_token={token}` carry verbatim target output, nothing escapes `;` or `=`,
  and a body containing `; param=…` therefore injected a clause straight into the
  hash — enough to rotate a finding's id every scan, or to merge two distinct
  findings. Confining the match to the clause the probe itself opened closes that.
  The cost is that a location written after some other clause is not seen; those
  findings keep the empty asset they had before, which is the status quo rather
  than a regression.

  *One location or none*, because several probes emit a single finding
  aggregating N locations (`evidence=reachable` over every reachable admin path).
  Taking the first would key that finding on whichever path the target exposed
  first, so remediating one of three would rotate the id of the finding covering
  the other two — recurring churn rather than the one-time rotation this change
  otherwise causes. An ambiguous list gets no asset, exactly as before.
  """
  urls, parameter = [], None
  for item in evidence or ():
    if not isinstance(item, str):
      continue
    clause = item.split(";")[0].strip()
    for key in _LOCATION_EVIDENCE_KEYS:
      if clause.startswith(key):
        found = clause[len(key):].strip()
        if found and found not in urls:
          urls.append(found)
        break
    else:
      if parameter is None:
        for key in _PARAMETER_EVIDENCE_KEYS:
          if clause.startswith(key):
            parameter = clause[len(key):].strip() or None
            break
  return (urls[0] if len(urls) == 1 else None), parameter


_FINDING_SECRET_FIELD_NAMES = contextvars.ContextVar(
  "redmesh_graybox_finding_secret_field_names",
  default=(),
)


def _merged_secret_field_names(extra=()) -> tuple[str, ...]:
  names = []
  for name in tuple(_FINDING_SECRET_FIELD_NAMES.get(()) or ()) + tuple(extra or ()):
    if isinstance(name, str) and name and name not in names:
      names.append(name)
  return tuple(names)


class FindingRedactionContext:
  """Temporarily add configured auth field names to finding serialization."""

  def __init__(self, *, secret_field_names=()):
    self.secret_field_names = tuple(
      name for name in (secret_field_names or ())
      if isinstance(name, str) and name
    )
    self._token = None

  def __enter__(self):
    self._token = _FINDING_SECRET_FIELD_NAMES.set(self.secret_field_names)
    return self

  def __exit__(self, exc_type, exc, tb):
    if self._token is not None:
      _FINDING_SECRET_FIELD_NAMES.reset(self._token)
    return False


def current_finding_secret_field_names() -> tuple[str, ...]:
  """Return configured names currently active for finding redaction."""
  return tuple(_FINDING_SECRET_FIELD_NAMES.get(()) or ())


def scrub_graybox_secrets(value: Any, *, secret_field_names: tuple[str, ...] = ()) -> Any:
  """Recursively redact known secret patterns from ``value``.

  Accepts strings, lists, tuples, dicts. Non-string leaves pass through.
  ``secret_field_names`` is a tuple of additional case-insensitive names
  (e.g. configured API-key header / query param names) to scrub on top of
  the generic pattern set.
  """
  secret_field_names = tuple(secret_field_names or ())
  if isinstance(value, str):
    out = value
    for pat, repl in _SCRUB_PATTERNS:
      out = pat.sub(repl, out)
    for name in secret_field_names:
      if not name:
        continue
      esc = re.escape(name)
      # name=val → name=<redacted>
      out = re.sub(
        rf"(?i)\b({esc})={_ALREADY_REDACTED}([^&\s\";]+)", r"\1=<redacted>", out,
      )
      # name: val (header form) → name: <redacted>
      out = re.sub(
        rf"(?i)\b({esc})\s*:{_ALREADY_REDACTED}\s*\S+", r"\1: <redacted>", out,
      )
      # JSON "name":"val"
      out = re.sub(rf'(?i)"({esc})"\s*:\s*"[^"]+"', r'"\1": "<redacted>"', out)
    return out
  if isinstance(value, list):
    return [scrub_graybox_secrets(v, secret_field_names=secret_field_names) for v in value]
  if isinstance(value, tuple):
    return tuple(scrub_graybox_secrets(v, secret_field_names=secret_field_names) for v in value)
  if isinstance(value, dict):
    return {k: scrub_graybox_secrets(v, secret_field_names=secret_field_names) for k, v in value.items()}
  return value


def _scrub_flat_finding(flat: dict, *, secret_field_names=()) -> dict:
  """Final storage-boundary pass on a flat finding dict.

  Targets the fields most likely to carry secret values:
    - title, description, evidence, replay_steps
    - evidence_artifacts (request/response snapshots, evidence_items)
  Other fields (severity, owasp_id, scenario_id, etc.) are policy-bound
  and pass through unchanged.
  """
  secret_field_names = _merged_secret_field_names(secret_field_names)
  for key in ("title", "description", "evidence", "replay_steps", "remediation"):
    if key in flat:
      flat[key] = scrub_graybox_secrets(
        flat[key], secret_field_names=secret_field_names,
      )
  # Both evidence keys. `evidence_items` is the same payload re-keyed for the
  # LLM input builder, and it was added here without being added to this list —
  # so the artifacts were scrubbed while the copy handed to the model was not.
  # A new field that carries target output has to be registered here or the
  # storage-boundary scrubber silently does not cover it.
  # `affected_assets` carries a copy of `url`/`parameter`, which is the one
  # location pair a probe may set straight from target-controlled input rather
  # than deriving from already-scrubbed evidence. It was emitted without being
  # registered here, so the operator-configured secret names — the whole point
  # of `secret_field_names` — never reached it, and the value went to the LLM,
  # the archive, the PDF and the exports in clear.
  for key in ("evidence_artifacts", "evidence_items", "affected_assets"):
    if key in flat and isinstance(flat[key], list):
      flat[key] = scrub_graybox_secrets(
        flat[key], secret_field_names=secret_field_names,
      )
  return flat


@dataclass(frozen=True)
class GrayboxEvidenceArtifact:
  """Typed graybox evidence payload kept alongside legacy string summaries."""
  summary: str = ""
  request_snapshot: str = ""
  response_snapshot: str = ""
  captured_at: str = ""
  raw_evidence_cid: str = ""
  sensitive: bool = False
  # How long the triggering request took, and a hash over the captured
  # request/response pair. The hash is evidence custody: it lets a reader check
  # an archived snapshot is the one the probe saw, independently of the R1FS
  # cid, which addresses the blob rather than this record.
  latency_ms: int = 0
  content_sha256: str = ""

  @classmethod
  def from_value(cls, value: Any) -> "GrayboxEvidenceArtifact":
    if isinstance(value, GrayboxEvidenceArtifact):
      return value
    if isinstance(value, dict):
      return cls(
        summary=value.get("summary", "") or "",
        request_snapshot=value.get("request_snapshot", "") or "",
        response_snapshot=value.get("response_snapshot", "") or "",
        captured_at=value.get("captured_at", "") or "",
        raw_evidence_cid=value.get("raw_evidence_cid", "") or "",
        sensitive=bool(value.get("sensitive", False)),
        latency_ms=int(value.get("latency_ms") or 0),
        content_sha256=value.get("content_sha256", "") or "",
      )
    if isinstance(value, str):
      return cls(summary=value)
    return cls()

  def to_dict(self) -> dict[str, Any]:
    return asdict(self)


def _asset_host(url) -> str:
  """Host component of a finding's URL, for the affected-asset record."""
  if not isinstance(url, str) or not url:
    return ""
  try:
    from urllib.parse import urlsplit
    return (urlsplit(url).hostname or "") or ""
  except Exception:
    return ""


@dataclass(frozen=True)
class GrayboxFinding:
  """
  Structured finding from an authenticated web-application probe.

  Uses structured evidence (list of key=value strings), multiple CWEs,
  MITRE ATT&CK IDs, and explicit status outcomes. Separate type from
  blackbox Finding — the two are normalized into a unified flat finding
  dict at the report level by _compute_risk_and_findings().
  """
  scenario_id: str                                  # e.g. "PT-A01-01"
  title: str
  status: str                                       # "vulnerable" | "not_vulnerable" | "inconclusive"
  severity: str                                     # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
  owasp: str                                        # e.g. "A01:2021"
  cwe: list[str] = field(default_factory=list)      # e.g. ["CWE-639", "CWE-862"]
  attack: list[str] = field(default_factory=list)   # MITRE ATT&CK IDs e.g. ["T1078"]
  evidence: list[str] = field(default_factory=list) # ["endpoint=http://...", "status=200"]
  evidence_artifacts: list[GrayboxEvidenceArtifact | dict] = field(default_factory=list)
  replay_steps: list[str] = field(default_factory=list)  # reproducibility steps
  remediation: str = ""
  error: str | None = None                          # non-None if probe had an error
  cvss_score: float | None = None
  cvss_vector: str = ""
  # OWASP API Top 10 — Subphase 1.8. Stateful-probe rollback outcome.
  # Populated by ProbeBase.run_stateful; remains "" for non-stateful
  # findings. Renders as a badge in the Navigator UI (Phase 8.3) and in
  # the PDF report when revert_failed (Phase 8.4 red-bordered note).
  rollback_status: str = ""                         # "" | "reverted" | "revert_failed" | "no_revert_needed"
  # Where the finding manifests. This previously existed only inside a free-text
  # `evidence` entry (`endpoint=http://...`) that nothing parsed, so a finding
  # reached the report with no machine-readable answer to "where" — and two
  # different endpoints could collapse to one finding id. Mapped to
  # `affected_assets[].url` / `.parameter` by `to_flat_finding`, which is the
  # shape RM-062's typed contract and dedup key are designed against.
  url: str | None = None
  parameter: str | None = None
  method: str | None = None

  @classmethod
  def from_dict(cls, payload: dict[str, Any]) -> "GrayboxFinding":
    """Compatibility-safe constructor for persisted finding dicts."""
    if not isinstance(payload, dict):
      raise TypeError("GrayboxFinding payload must be a dict")
    data = {k: v for k, v in payload.items() if k in cls.__dataclass_fields__}
    data["evidence_artifacts"] = [
      GrayboxEvidenceArtifact.from_value(item)
      for item in data.get("evidence_artifacts", []) or []
    ]
    return cls(**data)

  def to_dict(self, *, secret_field_names=()) -> dict[str, Any]:
    """JSON-safe serialization."""
    payload = asdict(self)
    payload["evidence_artifacts"] = [
      GrayboxEvidenceArtifact.from_value(item).to_dict()
      for item in self.evidence_artifacts
    ]
    return scrub_graybox_secrets(
      payload,
      secret_field_names=_merged_secret_field_names(secret_field_names),
    )

  def _normalized_evidence_artifacts(self) -> list[GrayboxEvidenceArtifact]:
    return [GrayboxEvidenceArtifact.from_value(item) for item in self.evidence_artifacts]

  def _flat_evidence_summary(self) -> str:
    evidence_lines = [line for line in self.evidence if isinstance(line, str) and line]
    if evidence_lines:
      return "; ".join(evidence_lines)
    artifact_summaries = [
      artifact.summary for artifact in self._normalized_evidence_artifacts()
      if artifact.summary
    ]
    return "; ".join(artifact_summaries)

  def to_flat_finding(self, port: int, protocol: str, probe_name: str,
                      *, secret_field_names=()) -> dict:
    """
    Normalize to the unified flat finding dict schema used in PassReport.findings.

    Converts structured graybox fields to the common schema that
    _compute_risk_and_findings() produces for all finding types.
    """
    cwe_joined = ", ".join(self.cwe)

    # Recover the location from evidence for probes that never set one. Four
    # probes append `GrayboxFinding(...)` directly instead of going through
    # `ProbeBase.emit_*`, which is where this derivation used to happen alone —
    # 87 of the 93 constructions in the tree — so their findings arrived with an
    # empty `affected_assets` and `dedup_key` reduced to probe + scenario_id +
    # classification. Two endpoints exhibiting one scenario then shared a
    # `finding_id`, and triage keys on `finding_id` alone: marking one remediated
    # marked the other. Doing it here covers both producers at one site.
    #
    # An explicit value always wins; a finding with no location key still gets no
    # asset, which is what a coverage record should have.
    url, parameter = self.url, self.parameter
    if not url or not parameter:
      derived_url, derived_parameter = location_from_evidence(self.evidence)
      # Scrubbed before it is promoted, exactly as `emit_vulnerable` does it: a
      # URL can carry a token in its query string, and turning evidence into a
      # typed field must not reintroduce what the scrubber removes elsewhere.
      # `affected_assets` is scrubbed again at the storage boundary, but identity
      # is computed before that pass and would otherwise hash the secret.
      names = _merged_secret_field_names(secret_field_names)
      if not url and derived_url:
        url = scrub_graybox_secrets(derived_url, secret_field_names=names)
      if not parameter and derived_parameter:
        parameter = scrub_graybox_secrets(derived_parameter, secret_field_names=names)

    # Map status -> confidence and effective severity
    confidence_map = {
      "vulnerable": "certain",
      "not_vulnerable": "firm",
      "inconclusive": "tentative",
    }
    # not_vulnerable findings contribute zero to risk score —
    # override severity to INFO so they don't inflate finding_counts
    declared_severity = self.severity.upper()
    effective_severity = "INFO" if self.status == "not_vulnerable" else declared_severity
    confidence, confidence_recognised = _normalize_confidence(
      confidence_map.get(self.status, "tentative"),
    )

    flat = {
      # Both producers stamp the same contract. Until they did, "the finding
      # schema" was whatever the reader happened to test against, and a
      # consumer had no way to tell a v0 archive from a current one.
      "schema": REDMESH_FINDING_SCHEMA,
      "schema_version": REDMESH_FINDING_SCHEMA_VERSION,
      "probe_type": "graybox",
      "severity": effective_severity,
      # The declared value survives the INFO override, so coverage evidence can
      # still say how much the check that passed was worth.
      "declared_severity": declared_severity,
      "title": self.title,
      "description": f"Scenario {self.scenario_id}: {self.title}",
      "owasp_id": self.owasp,
      "cwe_id": cwe_joined,
      # The typed list beside the display string. `cwe_id` alone is a joined
      # form no consumer could parse past the first entry.
      "cwe": _parse_cwe_list(self.cwe),
      "evidence": self._flat_evidence_summary(),
      "evidence_artifacts": [
        artifact.to_dict() for artifact in self._normalized_evidence_artifacts()
      ],
      # The same artifacts under the key the LLM input builder actually reads.
      # It consumes `evidence_items` and deliberately does not forward the
      # legacy `evidence` string ("raw probe output. Use evidence_items
      # instead"), so with `evidence_artifacts` as the only producer the model
      # received no evidence at all and wrote its narrative without any.
      "evidence_items": [
        {
          "kind": "request_response",
          "caption": artifact.summary,
          "snippet": artifact.response_snapshot,
          "cid": artifact.raw_evidence_cid,
        }
        for artifact in self._normalized_evidence_artifacts()
      ],
      "remediation": self.remediation,
      # Canonical documentation links for the category and weaknesses. The flat
      # finding carried none, so a reader saw "A01:2021" with nowhere to go —
      # and `references` is a key the LLM input builder, the PDF and the
      # exports all read.
      "references": _reference_urls(self.owasp, self.cwe),
      "confidence": confidence,
      "port": port,
      "protocol": protocol,
      "probe": probe_name,
      "category": "graybox",
      # graybox-only fields
      "scenario_id": self.scenario_id,
      "status": self.status,
      "replay_steps": list(self.replay_steps),
      "attack_ids": list(self.attack),
      "cvss_score": self.cvss_score,
      "cvss_vector": self.cvss_vector,
      "rollback_status": self.rollback_status,
      # Structured location, in the same shape the blackbox `AffectedAsset`
      # uses, so both finding types answer "where" the same way. Empty rather
      # than absent when a probe has not set one, so consumers can distinguish
      # "no location recorded" from "field missing".
      "affected_assets": (
        [{
          "host": _asset_host(url),
          "port": port,
          "url": url,
          "parameter": parameter,
          "method": self.method,
        }]
        if (url or parameter) else []
      ),
    }
    # Identity is computed from the assembled finding rather than from a
    # hand-rolled string, and by the same function the blackbox producer uses.
    # The old input folded in the lowercased title and a selection of evidence
    # strings, so rewording a probe's title — or changing how it phrased its
    # evidence — silently re-identified every finding it had ever produced.
    #
    # Computed before `_scrub_flat_finding` runs, and carried rather than
    # recomputed downstream: the report layer redacts the very fields the hash
    # is over, so a value re-derived after redaction would never match the one
    # archived with the finding.
    # Two fields, not four: `finding_id` is the identity, `finding_signature`
    # the content. The `dedup_key`/`content_hash` twins existed only to derive
    # these and let the pairs disagree.
    flat["finding_id"] = _dedup_key(flat)
    flat["finding_signature"] = _content_hash(flat)
    return _scrub_flat_finding(flat, secret_field_names=secret_field_names)

  @classmethod
  def flat_from_dict(cls, payload: dict[str, Any], port: int, protocol: str,
                     probe_name: str, *, secret_field_names=()) -> dict[str, Any]:
    """Normalize a persisted graybox finding dict into the flat report contract."""
    flat = cls.from_dict(payload).to_flat_finding(
      port, protocol, probe_name, secret_field_names=secret_field_names,
    )
    # Identity stamped at production wins over anything recomputed here. This
    # runs on a *persisted* finding, which may already have been through the
    # report layer's redaction — and redaction rewrites exactly the fields the
    # hashes are over, so recomputing would hand the same finding a new identity
    # and every consumer would read it as a new one.
    # `dedup_key`/`content_hash` are the pre-collapse names for the same two
    # values; archives written before the collapse carry only those.
    flat["finding_id"] = (
      payload.get("finding_id") or payload.get("dedup_key") or flat["finding_id"]
    )
    flat["finding_signature"] = (
      payload.get("finding_signature") or payload.get("content_hash")
      or flat["finding_signature"]
    )
    return flat
