"""Phase 2 PR-2.2b — check_cves enrichment via DynamicReferenceCache.

Verifies that Finding instances emitted by cve_db.check_cves() pick
up CVSS / KEV / EPSS / freshness from the injected cache when one
is provided, and fall back gracefully (legacy behavior) when not.
"""
from __future__ import annotations

import unittest

from extensions.business.cybersec.red_mesh.cve_db import (
  check_cves,
  reset_dynamic_reference_cache,
  set_dynamic_reference_cache,
)
from extensions.business.cybersec.red_mesh.findings import Severity
from extensions.business.cybersec.red_mesh.references.dynamic import (
  CvssRecord,
  DynamicReferenceCache,
  EpssRecord,
  KevRecord,
)


def _make_cache(*, cvss_score=9.8, kev_listed=True, epss=0.94,
                cvss_severity="CRITICAL"):
  return DynamicReferenceCache(
    sqlite_path=":memory:",
    fetch_cvss=lambda cve_id: CvssRecord(
      cve_id=cve_id,
      vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      score=cvss_score,
      version="3.1",
      severity=cvss_severity,
      fetched_at="2026-05-04T22:00:00Z",
      stale=False,
      source_url=f"mock://nvd/{cve_id}",
    ),
    fetch_kev_catalog=lambda: (
      {"CVE-2021-41773": KevRecord(
        cve_id="CVE-2021-41773", in_kev=True,
        date_added="2021-11-03",
        product="HTTP Server",
        fetched_at="2026-05-04T22:00:00Z",
      )} if kev_listed else {}
    ),
    fetch_epss=lambda cve_id: EpssRecord(
      cve_id=cve_id, score=epss, percentile=0.99,
      date="2026-05-04",
      fetched_at="2026-05-04T22:00:00Z",
    ),
  )


class TestLegacyBehavior(unittest.TestCase):
  """Without a cache, behavior matches pre-Phase-2."""

  def test_no_cache_no_cvss_data(self):
    findings = check_cves("openssh", "8.0")
    self.assertGreater(len(findings), 0)
    # Pick one to inspect
    f = findings[0]
    self.assertIsNone(f.cvss_score)
    self.assertEqual(f.cvss_vector, "")
    self.assertFalse(f.kev)
    self.assertIsNone(f.epss_score)
    self.assertEqual(f.cvss_data_freshness, "")
    # Legacy fields preserved
    self.assertTrue(f.cwe_id)
    self.assertEqual(len(f.cve), 1)


class TestEnrichmentWhenCachePresent(unittest.TestCase):

  def test_cvss_score_and_vector_populated(self):
    cache = _make_cache(cvss_score=9.8)
    try:
      findings = check_cves("apache", "2.4.49", dynamic_cache=cache)
      if not findings:
        self.skipTest("apache not in CVE_DB — pick another product")
      f = findings[0]
      self.assertEqual(f.cvss_score, 9.8)
      self.assertTrue(f.cvss_vector.startswith("CVSS:3.1/"))
      self.assertEqual(f.cvss_version, "3.1")
      self.assertTrue(f.cvss_data_freshness)
    finally:
      cache.close()

  def test_kev_flag_populated_for_listed_cve(self):
    cache = _make_cache(kev_listed=True)
    try:
      # Find a finding that includes CVE-2021-41773
      findings = check_cves("apache", "2.4.49", dynamic_cache=cache)
      target = next((f for f in findings if "CVE-2021-41773" in f.cve), None)
      if target is None:
        self.skipTest("CVE-2021-41773 not in CVE_DB for this product/version")
      self.assertTrue(target.kev)
    finally:
      cache.close()

  def test_epss_score_populated(self):
    cache = _make_cache(epss=0.85)
    try:
      findings = check_cves("openssh", "8.0", dynamic_cache=cache)
      f = findings[0]
      self.assertEqual(f.epss_score, 0.85)
    finally:
      cache.close()

  def test_owasp_top10_populated_from_static_table(self):
    cache = _make_cache()
    try:
      findings = check_cves("openssh", "8.0", dynamic_cache=cache)
      f = findings[0]
      # OpenSSH CVEs map to various CWEs; the static table should
      # produce some OWASP code as long as the CWE has a mapping.
      # Several CWEs in cve_db (e.g., 287, 326) have mappings.
      # Don't assert a specific value — just that *some* mapping
      # came through when the CWE has one.
      cwe_int = int(f.cwe_id.replace("CWE-", "")) if f.cwe_id else 0
      from extensions.business.cybersec.red_mesh.references import cwe_to_owasp
      expected = cwe_to_owasp(cwe_int)
      self.assertEqual(tuple(f.owasp_top10), expected)
    finally:
      cache.close()

  def test_cve_field_carries_the_cve_id(self):
    cache = _make_cache()
    try:
      findings = check_cves("openssh", "8.0", dynamic_cache=cache)
      for f in findings:
        self.assertEqual(len(f.cve), 1)
        self.assertTrue(f.cve[0].startswith("CVE-"))
    finally:
      cache.close()

  def test_severity_uses_nvd_when_available(self):
    """When NVD reports a different severity, prefer it over the
    static one (NVD often adjusts post-publication)."""
    cache = _make_cache(cvss_severity="HIGH")
    try:
      findings = check_cves("openssh", "8.0", dynamic_cache=cache)
      for f in findings:
        # All emitted findings should now carry HIGH severity
        # (since the mock returns HIGH for every CVE id), regardless
        # of the static entry.severity.
        self.assertEqual(f.severity, Severity.HIGH)
    finally:
      cache.close()

  def test_references_includes_nvd_url(self):
    cache = _make_cache()
    try:
      findings = check_cves("openssh", "8.0", dynamic_cache=cache)
      f = findings[0]
      self.assertTrue(any("mock://nvd/" in r for r in f.references))
    finally:
      cache.close()

  def test_context_cache_used_when_argument_omitted(self):
    cache = _make_cache(epss=0.77)
    token = set_dynamic_reference_cache(cache)
    try:
      findings = check_cves("openssh", "8.0")
      self.assertGreater(len(findings), 0)
      self.assertEqual(findings[0].epss_score, 0.77)
      self.assertEqual(len(findings[0].finding_signature), 64)
    finally:
      reset_dynamic_reference_cache(token)
      cache.close()


class TestGracefulDegradation(unittest.TestCase):

  def test_cache_with_failing_fetchers_does_not_raise(self):
    """If the cache returns empty/stale records, check_cves should
    still emit findings (just without the dynamic enrichment)."""
    def boom(*args, **kwargs):
      raise RuntimeError("network down")
    cache = DynamicReferenceCache(
      sqlite_path=":memory:",
      fetch_cvss=boom,
      fetch_kev_catalog=boom,
      fetch_epss=boom,
    )
    try:
      findings = check_cves("openssh", "8.0", dynamic_cache=cache)
      self.assertGreater(len(findings), 0)
      # Findings still emit; CVSS fields just stay empty
      for f in findings:
        self.assertIsNone(f.cvss_score)
        self.assertEqual(f.cvss_vector, "")
        # CVE id still propagates from the static entry
        self.assertEqual(len(f.cve), 1)
    finally:
      cache.close()


if __name__ == "__main__":
  unittest.main()
