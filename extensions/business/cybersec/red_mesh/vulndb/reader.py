"""Read-only reader for the generated vulnerability database (contract: vulndb.md, Node consumption).

`VulndbReader.query(product, version)` returns the matched rows; `cve_db.check_cves` reads it under `generated`.
Constraints are pre-parsed once at load with the node matcher (`cve_db._parse_version`,
`_compare_versions`), so the comparison semantics are the matcher's.
"""

import hashlib
import json
import re
import sqlite3
import sys
from bisect import bisect_left, bisect_right
from collections import namedtuple
from pathlib import Path

from ..cve_db import _compare_versions, _parse_version
from .models import SUPPORTED_MODELS

DB_PATH = Path(__file__).resolve().parent / "vulndb.sqlite"
PIN_PATH = Path(__file__).resolve().parent / "pin.json"

_CLAUSE = re.compile(r"(>=|<=|>|<|==)(.+)")
# Numeric parts of a full version, where a banner can be shorter than that: `Apache/2.4` is not 2.4.0. Default 3.
_FULL_DEPTH = {"openssh": 2, "postgresql": 2, "exim": 2, "dropbear": 2, "wordpress": 2}

Match = namedtuple("Match", (
  "cve_id", "product", "constraint", "source", "confidence", "reason", "platform_dependent", "client_side",
  "title", "cwe", "published", "severity", "kev", "kev_date_added", "epss", "epss_percentile",
  "cvss_version", "cvss_score", "cvss_source", "cvss",
))


class VulndbError(Exception):
  """Load failure; `args[0]` is the cause code reported as `vulndb_load_error`."""


def _norm(numbers):
  """Numbers without trailing zeros: the matcher pads, so `2.4` and `2.4.0` are equal."""
  numbers = list(numbers)
  while numbers and numbers[-1] == 0:
    numbers.pop()
  return tuple(numbers)


def _parse_constraint(product, text, cache=None):
  """Clauses `[(op, parsed version)]`, or None when one does not parse. `cache` shares equal versions."""
  cache = {} if cache is None else cache
  clauses = []
  for part in text.split(","):
    m = _CLAUSE.match(part.strip())
    if not m:
      return None
    key = (product, m.group(2))
    if key not in cache:
      cache[key] = _parse_version(m.group(2), product)
    if cache[key] is None:
      return None
    clauses.append((sys.intern(m.group(1)), cache[key]))
  return tuple(clauses)


def _merged(rows):
  """One row for a CVE: the first, `platform_dependent` and `client_side` when any of its rows is."""
  row = rows[0][1]
  return row[:6] + (max(r[6] for _, r in rows), max(r[7] for _, r in rows))


def _lower_at_or_above(clauses, oldest):
  """True when the constraint has a lower bound (`>=`, `>`, `==`) at or above `oldest`; unparsed (None): no."""
  if clauses is None:
    return False
  lowers = [target for op, target in clauses if op in (">=", ">", "==")]
  return any(_compare_versions(t, oldest) >= 0 for t in lowers)


def _holds(op, cmp):
  return {"<": cmp < 0, "<=": cmp <= 0, ">": cmp > 0, ">=": cmp >= 0, "==": cmp == 0}[op]


class VulndbReader:
  def __init__(self, vulns, rows, build_id, schema, cvss=None, eol=None, built_at=None):
    """`vulns`: cve_id -> vuln fields (title .. cvss_source); `rows`: affected rows in `Match` order.

    `cvss`: cve_id -> tuple of `{version, vector, score, source}` sorted by `(version, source, vector)`;
    `eol`: product -> oldest supported version; `built_at`: pin `built_at`, None for a local build.
    """
    self.build_id = build_id
    self.schema = schema
    self.built_at = built_at
    self.eol = dict(eol or {})
    self._cvss = cvss or {}
    self.dropped = 0
    self.row_count = 0
    self._vulns = vulns
    self._exact = {}   # (product, normalised numbers, tail) -> [affected row]
    self._ranges = {}  # product -> [(clauses, affected row)]
    self._exact_sorted = {}  # product -> [(key, affected row)] sorted by key, built on the first span query
    rows_by_cve = {}   # (product, cve_id) -> [clauses or None (unparsed), affected row], for the end-of-life rules
    cache = {}
    for row in rows:
      row = tuple(sys.intern(v) if isinstance(v, str) and i != 2 else v for i, v in enumerate(row))
      clauses = _parse_constraint(row[1], row[2], cache)
      if row[1] in self.eol:
        rows_by_cve.setdefault((row[1], row[0]), []).append((clauses, row))
      if clauses is None:
        self.dropped += 1
        continue
      self.row_count += 1
      if len(clauses) == 1 and clauses[0][0] == "==":
        numbers, tail = clauses[0][1]
        self._exact.setdefault((row[1], _norm(numbers), tail), []).append(row)
      else:
        self._ranges.setdefault(row[1], []).append((clauses, row))
    # product -> (oldest supported, [one row per CVE the vendor never assessed for the branch below it])
    self._eol = {}
    for product, text in self.eol.items():
      oldest = _parse_version(text, product)
      if oldest is not None:
        self._eol[product] = (oldest, text, [_merged(rows) for (p, _), rows in rows_by_cve.items()
                                             if p == product and all(_lower_at_or_above(c, oldest) for c, _ in rows)])

  def _match(self, row):
    vuln = self._vulns[row[0]]
    return Match(*row, *vuln, self._cvss.get(row[0], ()))

  def kev(self, cve_id):
    """KEV flag of `cve_id` in this build; None when the build has no `vuln` row for it."""
    vuln = self._vulns.get(cve_id)
    return None if vuln is None else bool(vuln[Match._fields.index("kev") - Match._fields.index("title")])

  def unsupported(self, product, version):
    """The `oldest_supported` text when `version` is older than it, else None (no `eol` row: None)."""
    entry = self._eol.get(product)
    parsed = _parse_version(version, product) if entry else None
    return entry[1] if parsed is not None and _compare_versions(parsed, entry[0]) < 0 else None

  def _found(self, product, parsed):
    """Rows of `product` whose constraint holds for one parsed version."""
    found = list(self._exact.get((product, _norm(parsed[0]), parsed[1]), ()))
    for clauses, row in self._ranges.get(product, ()):
      if all(_holds(op, _compare_versions(parsed, target)) for op, target in clauses):
        found.append(row)
    return found

  def _span(self, product, version, inferred_span):
    """`(low, high)` parsed versions the evidence covers, or None when `version` is one exact version.

    `inferred_span`: two versions a probe proved (Heartbleed: `1.0.1`, `1.0.1f`). A banner with fewer numeric parts than the
    product's full precision (`Apache/2.4`) covers `2.4.0` up to `2.4.999999`.
    """
    if inferred_span:
      low, high = (_parse_version(v, product) for v in inferred_span)
      return (low, high) if low is not None and high is not None else None
    parsed = _parse_version(version, product)
    depth = _FULL_DEPTH.get(product, 3)
    if parsed is None or parsed[1] != (0, 0, 0) or len(parsed[0]) >= depth:
      return None
    return parsed, (parsed[0] + [999999] * (depth - len(parsed[0])), parsed[1])

  def _sorted_exact(self, product):
    """`(keys, rows)` of the `==` rows of a product, sorted by `(normalised numbers, tail)` as the matcher compares."""
    if product not in self._exact_sorted:
      pairs = sorted(((key[1], key[2]), row) for key, rows in self._exact.items() if key[0] == product for row in rows)
      pairs.sort(key=lambda e: e[0])
      self._exact_sorted[product] = ([e[0] for e in pairs], [e[1] for e in pairs])
    return self._exact_sorted[product]

  def _inside(self, product, low, high, seen):
    """Rows not in `seen` whose constraint names a version strictly between `low` and `high`: possible, not provable."""
    out = []
    for clauses, row in self._ranges.get(product, ()):
      if row not in seen and any(_compare_versions(low, t) < 0 < _compare_versions(high, t) for _, t in clauses):
        out.append(row)
    keys, rows = self._sorted_exact(product)
    start, end = bisect_right(keys, (_norm(low[0]), low[1])), bisect_left(keys, (_norm(high[0]), high[1]))
    out.extend(row for row in rows[start:end] if row not in seen)
    return out

  def query(self, product, version, inferred_span=None):
    """Rows of `product` whose constraint holds for `version`, one per CVE.

    Over a span (see `_span`) a row that holds at both ends keeps its confidence. A row that holds at one end only, or whose
    constraint names a version strictly inside the span, cannot be told apart at this precision and is returned tentative with
    reason `inferred_version`. Any other row is dropped.
    """
    parsed = _parse_version(version, product)
    if parsed is None:
      return []
    span = self._span(product, version, inferred_span)
    if span is None:
      found, partial = self._found(product, parsed), []
    else:
      low, high = (self._found(product, p) for p in span)
      high_set, low_set = set(high), set(low)
      found = [row for row in low if row in high_set]
      seen = low_set | high_set
      partial = [row for row in low + high if row not in found] + self._inside(product, span[0], span[1], seen)
      partial = [row[:4] + ("tentative", "inferred_version") + row[6:] for row in partial]
    best = {}  # one row per CVE: firm/certain over tentative, then platform-independent over dependent
    for row in found + partial:
      rank = (row[4] == "tentative", row[6])
      if row[0] not in best or rank < best[row[0]][0]:
        best[row[0]] = (rank, row)
    if self.unsupported(product, version):
      # `eol_unassessed`: the vendor's ranges for this CVE all start inside the supported line.
      for row in self._eol[product][2]:
        if row[0] not in best:
          best[row[0]] = (None, row[:4] + ("tentative", "eol_unassessed") + row[6:])
    return [self._match(row) for _, row in best.values()]


_VULNS = (
  "SELECT cve_id, title, cwe, published, severity, kev, kev_date_added, epss, epss_percentile, "
  "display_cvss_version, display_cvss_score, display_cvss_source FROM vuln WHERE state != 'REJECTED'"
)
_AFFECTED = (
  'SELECT cve_id, product, "constraint", source, confidence, reason, platform_dependent, client_side '
  "FROM affected ORDER BY product, cve_id, \"constraint\""
)
_CVSS = "SELECT cve_id, version, vector, score, source FROM cvss ORDER BY cve_id, version, source, vector"
_EOL = "SELECT product, oldest_supported FROM eol"


def _optional(conn, sql):
  """Rows of a table the file may not have: an older ADDITION lacks `eol`, a tiny test file lacks `cvss`."""
  try:
    return conn.execute(sql).fetchall()
  except sqlite3.OperationalError:
    return []


def load_reader(db_path=DB_PATH, pin_path=PIN_PATH):
  """Verify and open the database. Returns `(reader, info)`; raises `VulndbError(cause)`."""
  try:
    pin = json.loads(Path(pin_path).read_text())
  except FileNotFoundError:
    raise VulndbError("no_pin")
  except (OSError, ValueError):
    raise VulndbError("pin_unreadable")
  db_path = Path(db_path)
  if not db_path.is_file():
    raise VulndbError("file_missing")
  try:
    if isinstance(pin, dict) and pin.get("size") is not None and db_path.stat().st_size != pin["size"]:
      raise VulndbError("hash_mismatch")
    data = db_path.read_bytes()  # the one read: hashed and loaded from these bytes
  except OSError:
    raise VulndbError("file_unreadable")
  if not isinstance(pin, dict) or hashlib.sha256(data).hexdigest() != pin.get("sha256_sqlite"):
    raise VulndbError("hash_mismatch")
  try:
    conn = sqlite3.connect(":memory:")
    conn.deserialize(data)
    del data
    conn.execute("PRAGMA trusted_schema = OFF")
    conn.execute("PRAGMA query_only = ON")
    try:
      model = conn.execute("PRAGMA user_version").fetchone()[0]
      if model not in SUPPORTED_MODELS:
        raise VulndbError("unknown_model")
      meta = dict(conn.execute("SELECT k, v FROM meta"))
      schema = meta.get("schema")
      if schema is not None and str(schema).split(".")[0] != str(model):
        raise VulndbError("schema_mismatch")
      build_id = meta.get("build_id")
      if not build_id or (pin.get("origin") != "local" and build_id != pin.get("build_id")):
        raise VulndbError("build_id_mismatch")
      vulns = {row[0]: row[1:] for row in conn.execute(_VULNS)}
      rows = (row for row in conn.execute(_AFFECTED) if row[0] in vulns)
      cvss = {}
      for cve_id, version, vector, score, source in _optional(conn, _CVSS):
        cvss.setdefault(cve_id, []).append(
          {"version": version, "vector": vector, "score": score, "source": source})
      cvss = {k: tuple(v) for k, v in cvss.items()}
      eol = dict(_optional(conn, _EOL))
      origin = pin.get("origin")
      reader = VulndbReader(vulns, rows, build_id, schema, cvss, eol, None if origin == "local" else pin.get("built_at"))
    finally:
      conn.close()
  except VulndbError:
    raise
  except Exception as exc:
    raise VulndbError("load_failed:%s" % type(exc).__name__)
  origin = pin.get("origin")
  info = {
    "build_id": build_id,
    "built_at": None if origin == "local" else pin.get("built_at"),
    "origin": origin,
  }
  return reader, info


def load_vulndb(requested, db_path=DB_PATH, pin_path=PIN_PATH):
  """Resolve the flag. Returns `(reader or None, capability_keys)`; never raises (fall back to static)."""
  keys = {"vulndb_source": "static", "vulndb_build_id": None, "vulndb_built_at": None,
          "vulndb_origin": None, "vulndb_load_error": None}
  if requested == "static":
    return None, keys
  if requested != "generated":
    keys["vulndb_load_error"] = "unknown_source"
    return None, keys
  try:
    reader, info = load_reader(db_path, pin_path)
  except VulndbError as exc:
    keys["vulndb_load_error"] = str(exc.args[0])
    return None, keys
  except Exception as exc:  # RecursionError in a hostile pin, MemoryError, ...
    keys["vulndb_load_error"] = "load_failed:%s" % type(exc).__name__
    return None, keys
  keys.update(vulndb_source="generated", vulndb_build_id=info["build_id"],
              vulndb_built_at=info["built_at"], vulndb_origin=info["origin"])
  return reader, keys
