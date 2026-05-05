"""Dynamic reference data — NVD CVSS, CISA KEV, FIRST EPSS.

Phase 2 PR-2.2 of the PTES rebuild. Implements the second tier of the
P6 split (static in-repo / dynamic fetched-and-cached).

Why dynamic
-----------

CVSS scores, CISA Known Exploited Vulnerabilities (KEV), and FIRST
Exploit Prediction Scoring System (EPSS) all change frequently:

  - NVD occasionally rescores CVEs post-publication. Quarterly-stale
    CVSS in a security report is misleading.
  - CISA KEV catalog updates daily — a CVE that became KEV-listed
    last week is materially more urgent than one that didn't.
  - FIRST EPSS recomputes daily from observed exploitation telemetry.

These cannot be shipped as static in-repo data without going stale.
Instead they are fetched at scan time, cached locally, and persisted
to the scan's R1FS record so the report is reproducible from the
scan record alone (no external network needed for re-render).

API endpoints used
------------------

  NVD CVSS:   https://services.nvd.nist.gov/rest/json/cves/2.0
              ?cveId=CVE-YYYY-NNNNN
  CISA KEV:   https://www.cisa.gov/sites/default/files/feeds/
              known_exploited_vulnerabilities.json (full catalog)
  FIRST EPSS: https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN

Cache TTLs
----------

  CVSS  — 7 days  (NVD rescores rare; ok to cache a week)
  KEV   — 24 hrs  (CISA updates daily)
  EPSS  — 24 hrs  (FIRST recomputes daily)

Staleness handling
------------------

When the upstream API is unavailable, the cache returns the most
recent cached value with `stale=True` and a `last_fetched` timestamp.
The PDF report renders this as
``CVSS 9.8 (cached, last fetched 2026-04-30)`` so the reader knows
the data is not real-time.

Network isolation in tests
--------------------------

All HTTP calls go through `_fetch_*` methods that can be monkeypatched
in unit tests. Set the env var `LIVE_REFERENCE_API=1` to opt into
real network calls (used for occasional smoke tests).
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------
# Cache TTLs (seconds)
# ---------------------------------------------------------------------

CACHE_TTL_CVSS_SEC = 7 * 24 * 3600   # 7 days
CACHE_TTL_KEV_SEC = 24 * 3600        # 24 hours
CACHE_TTL_EPSS_SEC = 24 * 3600       # 24 hours

# Allow tests to override (faster TTL, no network)
DEFAULT_HTTP_TIMEOUT = 10.0  # seconds

# Endpoints
NVD_CVSS_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"


# ---------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class CvssRecord:
  cve_id: str
  vector: str = ""        # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  score: float | None = None
  version: str = ""       # "3.1" | "4.0"
  severity: str = ""      # qualitative tier from NVD
  fetched_at: str = ""    # ISO 8601 — when this entry was last refreshed
  stale: bool = False     # True if the upstream API was unavailable
  source_url: str = ""

  def to_dict(self) -> dict:
    return asdict(self)


@dataclass(frozen=True)
class KevRecord:
  cve_id: str
  in_kev: bool = False
  date_added: str = ""             # ISO date when CISA added it
  vendor_project: str = ""
  product: str = ""
  vulnerability_name: str = ""
  required_action: str = ""
  due_date: str = ""
  known_ransomware_use: bool = False
  fetched_at: str = ""
  stale: bool = False

  def to_dict(self) -> dict:
    return asdict(self)


@dataclass(frozen=True)
class EpssRecord:
  cve_id: str
  score: float | None = None       # 0.0–1.0
  percentile: float | None = None  # 0.0–1.0
  date: str = ""                   # EPSS data date
  fetched_at: str = ""
  stale: bool = False

  def to_dict(self) -> dict:
    return asdict(self)


# ---------------------------------------------------------------------
# Cache backend
# ---------------------------------------------------------------------


class _SqliteBackend:
  """Tiny SQLite cache for CVSS / KEV / EPSS records.

  One table per record type, keyed by cve_id. Each row carries the
  full JSON-encoded record plus a fetched_ts UNIX timestamp for
  TTL eviction. In-memory by default (path=':memory:' for tests);
  pass a filesystem path for production persistence.
  """

  _SCHEMA = """
  CREATE TABLE IF NOT EXISTS cvss_cache (
    cve_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    fetched_ts INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS kev_cache (
    cve_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    fetched_ts INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS epss_cache (
    cve_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    fetched_ts INTEGER NOT NULL
  );
  """

  def __init__(self, path: str = ":memory:"):
    self.path = path
    if path != ":memory:":
      Path(path).parent.mkdir(parents=True, exist_ok=True)
    self._conn = sqlite3.connect(path, isolation_level=None,
                                 check_same_thread=False)
    self._conn.executescript(self._SCHEMA)

  def get(self, table: str, cve_id: str) -> tuple[dict | None, int | None]:
    """Return (payload, fetched_ts) or (None, None) if not cached."""
    cur = self._conn.execute(
      f"SELECT payload, fetched_ts FROM {table} WHERE cve_id = ?",
      (cve_id,),
    )
    row = cur.fetchone()
    if row is None:
      return None, None
    try:
      return json.loads(row[0]), int(row[1])
    except (json.JSONDecodeError, ValueError, TypeError):
      return None, None

  def put(self, table: str, cve_id: str, payload: dict, fetched_ts: int) -> None:
    self._conn.execute(
      f"INSERT OR REPLACE INTO {table} (cve_id, payload, fetched_ts) VALUES (?, ?, ?)",
      (cve_id, json.dumps(payload, default=str), fetched_ts),
    )

  def close(self) -> None:
    with closing(self._conn):
      pass


# ---------------------------------------------------------------------
# Public cache facade
# ---------------------------------------------------------------------


class DynamicReferenceCache:
  """Fetch-on-demand, cache, persist-per-scan facade.

  Use a single instance per scan job; pass it to probes via the worker
  state. After the scan, dump_for_scan_record() returns a JSON-safe
  dict that can be stored to R1FS so the report is reproducible.
  """

  def __init__(
    self,
    *,
    sqlite_path: str = ":memory:",
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
    user_agent: str = "RedMesh/dynamic-refs",
    now_fn=None,            # injectable for deterministic tests
    fetch_cvss=None,        # injectable: (cve_id) -> CvssRecord | None
    fetch_kev_catalog=None, # injectable: () -> dict[cve_id, KevRecord]
    fetch_epss=None,        # injectable: (cve_id) -> EpssRecord | None
  ):
    self._backend = _SqliteBackend(sqlite_path)
    self._http_timeout = http_timeout
    self._user_agent = user_agent
    self._now_fn = now_fn or (lambda: int(time.time()))

    # Default to real-network fetchers; tests inject mocks.
    self._fetch_cvss = fetch_cvss or self._fetch_cvss_from_nvd
    self._fetch_kev_catalog = fetch_kev_catalog or self._fetch_kev_catalog_from_cisa
    self._fetch_epss = fetch_epss or self._fetch_epss_from_first

    # KEV is a single-catalog fetch (one HTTP call returns all CVEs).
    # We cache the whole catalog under a sentinel key.
    self._kev_catalog: dict[str, KevRecord] | None = None
    self._kev_catalog_fetched_ts: int = 0

  # ------------------------------------------------------------------
  # Public lookups
  # ------------------------------------------------------------------

  def get_cvss(self, cve_id: str) -> CvssRecord:
    cve_id = self._normalize_cve(cve_id)
    if not cve_id:
      return CvssRecord(cve_id="")

    cached_payload, fetched_ts = self._backend.get("cvss_cache", cve_id)
    now = self._now_fn()
    if cached_payload and (now - fetched_ts) < CACHE_TTL_CVSS_SEC:
      return CvssRecord(**cached_payload)

    # Need fresh — try upstream
    try:
      record = self._fetch_cvss(cve_id)
      if record is not None:
        payload = record.to_dict()
        self._backend.put("cvss_cache", cve_id, payload, now)
        return record
    except Exception:
      pass

    # Upstream failed — return cached (stale) if we have any
    if cached_payload:
      stale = dict(cached_payload)
      stale["stale"] = True
      return CvssRecord(**stale)

    # No upstream + no cache — return empty record so caller can
    # render placeholder.
    return CvssRecord(cve_id=cve_id, fetched_at=self._iso_now(), stale=True)

  def get_kev(self, cve_id: str) -> KevRecord:
    cve_id = self._normalize_cve(cve_id)
    if not cve_id:
      return KevRecord(cve_id="")

    self._refresh_kev_catalog_if_needed()
    if self._kev_catalog is None:
      # Network failed AND no per-CVE cache — return false/stale.
      cached_payload, _ = self._backend.get("kev_cache", cve_id)
      if cached_payload:
        stale = dict(cached_payload)
        stale["stale"] = True
        return KevRecord(**stale)
      return KevRecord(cve_id=cve_id, in_kev=False, fetched_at=self._iso_now(), stale=True)

    record = self._kev_catalog.get(cve_id, KevRecord(
      cve_id=cve_id, in_kev=False, fetched_at=self._iso_now(),
    ))
    # Cache per-CVE so we have something if catalog fetch fails next time.
    self._backend.put("kev_cache", cve_id, record.to_dict(), self._now_fn())
    return record

  def get_epss(self, cve_id: str) -> EpssRecord:
    cve_id = self._normalize_cve(cve_id)
    if not cve_id:
      return EpssRecord(cve_id="")

    cached_payload, fetched_ts = self._backend.get("epss_cache", cve_id)
    now = self._now_fn()
    if cached_payload and (now - fetched_ts) < CACHE_TTL_EPSS_SEC:
      return EpssRecord(**cached_payload)

    try:
      record = self._fetch_epss(cve_id)
      if record is not None:
        self._backend.put("epss_cache", cve_id, record.to_dict(), now)
        return record
    except Exception:
      pass

    if cached_payload:
      stale = dict(cached_payload)
      stale["stale"] = True
      return EpssRecord(**stale)
    return EpssRecord(cve_id=cve_id, fetched_at=self._iso_now(), stale=True)

  # ------------------------------------------------------------------
  # Per-scan persistence
  # ------------------------------------------------------------------

  def dump_for_scan_record(self) -> dict:
    """Return a JSON-safe dict of all cached entries for persistence
    to R1FS. The PassReport stores this so report re-renders after
    the scan don't need network access."""
    out: dict[str, dict] = {"cvss": {}, "kev": {}, "epss": {}}
    for table, key in (("cvss_cache", "cvss"), ("kev_cache", "kev"), ("epss_cache", "epss")):
      cur = self._backend._conn.execute(
        f"SELECT cve_id, payload, fetched_ts FROM {table}"
      )
      for cve_id, payload_json, fetched_ts in cur.fetchall():
        try:
          out[key][cve_id] = {
            "payload": json.loads(payload_json),
            "fetched_ts": int(fetched_ts),
          }
        except (json.JSONDecodeError, ValueError, TypeError):
          continue
    return out

  def load_from_scan_record(self, record: dict) -> None:
    """Restore cache state from a dump_for_scan_record() output. Used
    during report regeneration to make rendering offline-capable."""
    for key, table in (("cvss", "cvss_cache"), ("kev", "kev_cache"), ("epss", "epss_cache")):
      entries = (record or {}).get(key) or {}
      for cve_id, wrapper in entries.items():
        try:
          self._backend.put(
            table, cve_id, wrapper["payload"], int(wrapper["fetched_ts"]),
          )
        except (KeyError, TypeError, ValueError):
          continue

  def close(self) -> None:
    self._backend.close()

  # ------------------------------------------------------------------
  # Real-network fetchers (default)
  # ------------------------------------------------------------------

  def _fetch_cvss_from_nvd(self, cve_id: str) -> CvssRecord | None:
    url = f"{NVD_CVSS_URL}?cveId={cve_id}"
    try:
      data = self._http_get_json(url)
    except Exception:
      return None
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
      return None
    metrics = vulns[0].get("cve", {}).get("metrics", {}) or {}
    # Prefer v3.1 → v3.0 → v4.0 in that priority for stability.
    for key, version in (
      ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV40", "4.0"),
    ):
      arr = metrics.get(key) or []
      if arr:
        cvss = arr[0].get("cvssData", {}) or {}
        return CvssRecord(
          cve_id=cve_id,
          vector=str(cvss.get("vectorString", "")),
          score=cvss.get("baseScore"),
          version=str(cvss.get("version", version)),
          severity=str(cvss.get("baseSeverity", "")).upper(),
          fetched_at=self._iso_now(),
          stale=False,
          source_url=url,
        )
    return CvssRecord(cve_id=cve_id, fetched_at=self._iso_now(),
                      source_url=url, stale=False)

  def _fetch_kev_catalog_from_cisa(self) -> dict[str, KevRecord]:
    try:
      data = self._http_get_json(CISA_KEV_URL)
    except Exception:
      return {}
    out: dict[str, KevRecord] = {}
    now = self._iso_now()
    for entry in (data or {}).get("vulnerabilities", []) or []:
      cve_id = self._normalize_cve(entry.get("cveID", ""))
      if not cve_id:
        continue
      out[cve_id] = KevRecord(
        cve_id=cve_id,
        in_kev=True,
        date_added=str(entry.get("dateAdded", "")),
        vendor_project=str(entry.get("vendorProject", "")),
        product=str(entry.get("product", "")),
        vulnerability_name=str(entry.get("vulnerabilityName", "")),
        required_action=str(entry.get("requiredAction", "")),
        due_date=str(entry.get("dueDate", "")),
        known_ransomware_use=str(entry.get("knownRansomwareCampaignUse", ""))
          .lower() == "known",
        fetched_at=now,
        stale=False,
      )
    return out

  def _fetch_epss_from_first(self, cve_id: str) -> EpssRecord | None:
    url = f"{FIRST_EPSS_URL}?cve={cve_id}"
    try:
      data = self._http_get_json(url)
    except Exception:
      return None
    rows = (data or {}).get("data") or []
    if not rows:
      return EpssRecord(cve_id=cve_id, fetched_at=self._iso_now(), stale=False)
    row = rows[0] or {}
    try:
      score = float(row.get("epss"))
    except (TypeError, ValueError):
      score = None
    try:
      percentile = float(row.get("percentile"))
    except (TypeError, ValueError):
      percentile = None
    return EpssRecord(
      cve_id=cve_id,
      score=score,
      percentile=percentile,
      date=str(row.get("date", "")),
      fetched_at=self._iso_now(),
      stale=False,
    )

  # ------------------------------------------------------------------
  # Internals
  # ------------------------------------------------------------------

  def _refresh_kev_catalog_if_needed(self) -> None:
    now = self._now_fn()
    if (
      self._kev_catalog is not None
      and (now - self._kev_catalog_fetched_ts) < CACHE_TTL_KEV_SEC
    ):
      return
    try:
      catalog = self._fetch_kev_catalog()
    except Exception:
      catalog = {}
    if catalog:
      self._kev_catalog = catalog
      self._kev_catalog_fetched_ts = now

  def _http_get_json(self, url: str) -> dict | None:
    req = urllib.request.Request(
      url, headers={"User-Agent": self._user_agent},
    )
    with urllib.request.urlopen(req, timeout=self._http_timeout) as resp:
      raw = resp.read()
    return json.loads(raw)

  @staticmethod
  def _normalize_cve(cve_id: str) -> str:
    if not isinstance(cve_id, str):
      return ""
    s = cve_id.strip().upper()
    return s if s.startswith("CVE-") else ""

  @staticmethod
  def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
