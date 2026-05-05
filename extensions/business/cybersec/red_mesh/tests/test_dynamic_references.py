"""Phase 2 PR-2.2 — DynamicReferenceCache tests.

Tests use injected mock fetchers (not real network) — set the env
variable LIVE_REFERENCE_API=1 to opt into a real-network smoke test.

Coverage:
  - get_cvss/get_kev/get_epss happy path (cache miss → upstream →
    cache hit on second call).
  - Cache TTL eviction (force time advance, verify re-fetch).
  - Graceful degradation (upstream failure → return cached with
    stale=True; no cache + failure → empty record with stale=True).
  - dump_for_scan_record / load_from_scan_record round-trip
    (offline report regeneration scenario).
  - CVE normalization (case, whitespace, non-CVE rejection).
  - KEV catalog fetched once and shared across multiple CVE lookups.
"""
from __future__ import annotations

import unittest
from typing import Any

from extensions.business.cybersec.red_mesh.references.dynamic import (
  CACHE_TTL_CVSS_SEC,
  CACHE_TTL_EPSS_SEC,
  CACHE_TTL_KEV_SEC,
  CvssRecord,
  DynamicReferenceCache,
  EpssRecord,
  KevRecord,
)


# ---------------------------------------------------------------------
# Mock fetcher fixtures
# ---------------------------------------------------------------------


class _MockClock:
  def __init__(self, t: int = 1_700_000_000):
    self.t = t

  def __call__(self) -> int:
    return self.t

  def advance(self, seconds: int) -> None:
    self.t += seconds


def _make_cvss_record(cve_id: str, score: float = 7.5,
                     vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                     stale: bool = False) -> CvssRecord:
  return CvssRecord(
    cve_id=cve_id, vector=vector, score=score, version="3.1",
    severity="HIGH", fetched_at="2026-05-04T00:00:00Z", stale=stale,
    source_url="mock://nvd",
  )


# ---------------------------------------------------------------------
# CVSS lookups
# ---------------------------------------------------------------------


class TestCvssLookup(unittest.TestCase):

  def setUp(self):
    self.fetch_calls: list[str] = []
    self.clock = _MockClock()
    def fetch_cvss(cve_id: str) -> CvssRecord | None:
      self.fetch_calls.append(cve_id)
      return _make_cvss_record(cve_id, score=9.8)
    self.cache = DynamicReferenceCache(
      sqlite_path=":memory:", now_fn=self.clock,
      fetch_cvss=fetch_cvss,
      fetch_kev_catalog=lambda: {},
      fetch_epss=lambda cve_id: None,
    )

  def tearDown(self):
    self.cache.close()

  def test_cache_miss_calls_upstream(self):
    rec = self.cache.get_cvss("CVE-2021-41773")
    self.assertEqual(rec.score, 9.8)
    self.assertFalse(rec.stale)
    self.assertEqual(self.fetch_calls, ["CVE-2021-41773"])

  def test_cache_hit_does_not_call_upstream(self):
    self.cache.get_cvss("CVE-2021-41773")
    self.cache.get_cvss("CVE-2021-41773")
    self.cache.get_cvss("CVE-2021-41773")
    self.assertEqual(len(self.fetch_calls), 1)

  def test_ttl_expiry_triggers_refetch(self):
    self.cache.get_cvss("CVE-2021-41773")
    self.clock.advance(CACHE_TTL_CVSS_SEC + 1)
    self.cache.get_cvss("CVE-2021-41773")
    self.assertEqual(len(self.fetch_calls), 2)

  def test_upstream_failure_returns_empty_stale_record(self):
    def boom(cve_id):
      raise RuntimeError("network down")
    cache = DynamicReferenceCache(
      sqlite_path=":memory:", now_fn=self.clock,
      fetch_cvss=boom, fetch_kev_catalog=lambda: {},
      fetch_epss=lambda x: None,
    )
    rec = cache.get_cvss("CVE-2021-41773")
    self.assertTrue(rec.stale)
    self.assertIsNone(rec.score)
    cache.close()

  def test_upstream_failure_returns_cached_stale_when_available(self):
    self.cache.get_cvss("CVE-2021-41773")  # populate cache
    self.clock.advance(CACHE_TTL_CVSS_SEC + 1)  # force expiry
    # Replace fetcher with one that fails
    def boom(cve_id):
      raise RuntimeError("network down")
    self.cache._fetch_cvss = boom
    rec = self.cache.get_cvss("CVE-2021-41773")
    self.assertTrue(rec.stale)
    self.assertEqual(rec.score, 9.8)  # value preserved from cache

  def test_normalizes_cve_id(self):
    self.cache.get_cvss("cve-2021-41773")
    self.cache.get_cvss("  CVE-2021-41773  ")
    self.cache.get_cvss("CVE-2021-41773")
    # All three normalize to the same key — only one upstream call.
    self.assertEqual(len(self.fetch_calls), 1)

  def test_rejects_non_cve_strings(self):
    rec = self.cache.get_cvss("not-a-cve")
    self.assertEqual(rec.cve_id, "")
    self.assertEqual(self.fetch_calls, [])


# ---------------------------------------------------------------------
# KEV lookups (catalog-shaped fetcher)
# ---------------------------------------------------------------------


class TestKevLookup(unittest.TestCase):

  def setUp(self):
    self.catalog_fetches = 0
    self.clock = _MockClock()
    def fetch_catalog():
      self.catalog_fetches += 1
      return {
        "CVE-2021-41773": KevRecord(
          cve_id="CVE-2021-41773", in_kev=True,
          date_added="2021-11-03",
          vendor_project="Apache",
          product="HTTP Server",
          vulnerability_name="Apache HTTP Server Path Traversal",
          required_action="Apply patches.",
          due_date="2021-11-17",
          known_ransomware_use=False,
          fetched_at="2026-05-04T00:00:00Z", stale=False,
        ),
      }
    self.cache = DynamicReferenceCache(
      sqlite_path=":memory:", now_fn=self.clock,
      fetch_cvss=lambda x: None,
      fetch_kev_catalog=fetch_catalog,
      fetch_epss=lambda x: None,
    )

  def tearDown(self):
    self.cache.close()

  def test_in_kev_returns_true_for_known_cve(self):
    rec = self.cache.get_kev("CVE-2021-41773")
    self.assertTrue(rec.in_kev)
    self.assertEqual(rec.product, "HTTP Server")

  def test_unlisted_cve_returns_in_kev_false(self):
    rec = self.cache.get_kev("CVE-2099-99999")
    self.assertFalse(rec.in_kev)

  def test_catalog_fetched_once_across_many_lookups(self):
    self.cache.get_kev("CVE-2021-41773")
    self.cache.get_kev("CVE-2099-99999")
    self.cache.get_kev("CVE-2024-12345")
    self.assertEqual(self.catalog_fetches, 1)

  def test_catalog_refetched_after_ttl(self):
    self.cache.get_kev("CVE-2021-41773")
    self.clock.advance(CACHE_TTL_KEV_SEC + 1)
    self.cache.get_kev("CVE-2021-41773")
    self.assertEqual(self.catalog_fetches, 2)

  def test_catalog_failure_falls_back_to_per_cve_cache(self):
    # First successful lookup — populates per-CVE cache
    self.cache.get_kev("CVE-2021-41773")
    self.clock.advance(CACHE_TTL_KEV_SEC + 1)
    # Now make catalog-fetch fail — should use per-CVE cache
    def boom():
      raise RuntimeError("network down")
    self.cache._fetch_kev_catalog = boom
    self.cache._kev_catalog = None
    self.cache._kev_catalog_fetched_ts = 0
    rec = self.cache.get_kev("CVE-2021-41773")
    self.assertTrue(rec.in_kev)
    self.assertTrue(rec.stale)


# ---------------------------------------------------------------------
# EPSS lookups
# ---------------------------------------------------------------------


class TestEpssLookup(unittest.TestCase):

  def setUp(self):
    self.fetch_calls: list[str] = []
    self.clock = _MockClock()
    def fetch_epss(cve_id):
      self.fetch_calls.append(cve_id)
      return EpssRecord(
        cve_id=cve_id, score=0.94, percentile=0.99,
        date="2026-05-04",
        fetched_at="2026-05-04T00:00:00Z", stale=False,
      )
    self.cache = DynamicReferenceCache(
      sqlite_path=":memory:", now_fn=self.clock,
      fetch_cvss=lambda x: None,
      fetch_kev_catalog=lambda: {},
      fetch_epss=fetch_epss,
    )

  def tearDown(self):
    self.cache.close()

  def test_basic_epss_fetch(self):
    rec = self.cache.get_epss("CVE-2021-41773")
    self.assertEqual(rec.score, 0.94)
    self.assertEqual(rec.percentile, 0.99)

  def test_caches_subsequent_calls(self):
    self.cache.get_epss("CVE-2021-41773")
    self.cache.get_epss("CVE-2021-41773")
    self.assertEqual(len(self.fetch_calls), 1)

  def test_ttl_expiry(self):
    self.cache.get_epss("CVE-2021-41773")
    self.clock.advance(CACHE_TTL_EPSS_SEC + 1)
    self.cache.get_epss("CVE-2021-41773")
    self.assertEqual(len(self.fetch_calls), 2)


# ---------------------------------------------------------------------
# Per-scan persistence (R1FS reproducibility)
# ---------------------------------------------------------------------


class TestPersistencePerScan(unittest.TestCase):

  def test_dump_and_load_round_trip(self):
    clock = _MockClock()
    cache_a = DynamicReferenceCache(
      sqlite_path=":memory:", now_fn=clock,
      fetch_cvss=lambda x: _make_cvss_record(x, score=9.8),
      fetch_kev_catalog=lambda: {
        "CVE-2021-41773": KevRecord(
          cve_id="CVE-2021-41773", in_kev=True,
          fetched_at="2026-05-04T00:00:00Z",
        )
      },
      fetch_epss=lambda x: EpssRecord(
        cve_id=x, score=0.5, percentile=0.7,
        fetched_at="2026-05-04T00:00:00Z",
      ),
    )
    cache_a.get_cvss("CVE-2021-41773")
    cache_a.get_kev("CVE-2021-41773")
    cache_a.get_epss("CVE-2021-41773")
    dump = cache_a.dump_for_scan_record()
    cache_a.close()

    self.assertIn("CVE-2021-41773", dump["cvss"])
    self.assertIn("CVE-2021-41773", dump["kev"])
    self.assertIn("CVE-2021-41773", dump["epss"])

    # Reconstruct in a fresh cache without any network access
    def boom(*a, **kw):
      raise RuntimeError("MUST NOT TOUCH NETWORK")
    cache_b = DynamicReferenceCache(
      sqlite_path=":memory:", now_fn=clock,
      fetch_cvss=boom, fetch_kev_catalog=boom, fetch_epss=boom,
    )
    cache_b.load_from_scan_record(dump)
    cvss = cache_b.get_cvss("CVE-2021-41773")
    self.assertEqual(cvss.score, 9.8)
    cache_b.close()

  def test_dump_with_no_data_returns_empty_buckets(self):
    cache = DynamicReferenceCache(
      sqlite_path=":memory:",
      fetch_cvss=lambda x: None,
      fetch_kev_catalog=lambda: {},
      fetch_epss=lambda x: None,
    )
    dump = cache.dump_for_scan_record()
    self.assertEqual(dump, {"cvss": {}, "kev": {}, "epss": {}})
    cache.close()


# ---------------------------------------------------------------------
# Live API smoke test (opt-in via env)
# ---------------------------------------------------------------------


import os
@unittest.skipUnless(os.environ.get("LIVE_REFERENCE_API"),
                     "set LIVE_REFERENCE_API=1 to hit real NVD/CISA/EPSS")
class TestLiveSmoke(unittest.TestCase):

  def test_real_nvd_lookup(self):
    cache = DynamicReferenceCache(sqlite_path=":memory:")
    try:
      rec = cache.get_cvss("CVE-2021-41773")
      self.assertEqual(rec.cve_id, "CVE-2021-41773")
      self.assertIsNotNone(rec.score)
      self.assertTrue(rec.vector.startswith("CVSS:"))
    finally:
      cache.close()


if __name__ == "__main__":
  unittest.main()
