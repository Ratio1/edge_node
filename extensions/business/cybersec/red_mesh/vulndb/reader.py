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
from collections import namedtuple
from pathlib import Path

from ..cve_db import _compare_versions, _parse_version
from .models import SUPPORTED_MODELS

DB_PATH = Path(__file__).resolve().parent / "vulndb.sqlite"
PIN_PATH = Path(__file__).resolve().parent / "pin.json"

_CLAUSE = re.compile(r"(>=|<=|>|<|==)(.+)")

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
    cache = {}
    for row in rows:
      row = tuple(sys.intern(v) if isinstance(v, str) and i != 2 else v for i, v in enumerate(row))
      clauses = _parse_constraint(row[1], row[2], cache)
      if clauses is None:
        self.dropped += 1
        continue
      self.row_count += 1
      if len(clauses) == 1 and clauses[0][0] == "==":
        numbers, tail = clauses[0][1]
        self._exact.setdefault((row[1], _norm(numbers), tail), []).append(row)
      else:
        self._ranges.setdefault(row[1], []).append((clauses, row))

  def _match(self, row):
    vuln = self._vulns[row[0]]
    return Match(*row, *vuln, self._cvss.get(row[0], ()))

  def query(self, product, version):
    """Rows of `product` whose constraint holds for `version`, one per CVE."""
    parsed = _parse_version(version, product)
    if parsed is None:
      return []
    found = list(self._exact.get((product, _norm(parsed[0]), parsed[1]), ()))
    for clauses, row in self._ranges.get(product, ()):
      if all(_holds(op, _compare_versions(parsed, target)) for op, target in clauses):
        found.append(row)
    best = {}  # one row per CVE: firm/certain over tentative, then platform-independent over dependent
    for row in found:
      rank = (row[4] == "tentative", row[6])
      if row[0] not in best or rank < best[row[0]][0]:
        best[row[0]] = (rank, row)
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
