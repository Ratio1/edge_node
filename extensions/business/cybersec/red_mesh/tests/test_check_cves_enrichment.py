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


class TestCatalogConstraintWidening(unittest.TestCase):
  """Regression for CVE-2021-42013 — must fire on both 2.4.49 and 2.4.50.

  Vulhub ships ``httpd:2.4.50`` as the CVE-2021-42013 image because the
  bypass also works on 2.4.50 (the original CVE-2021-41773 fix in 2.4.50
  was incomplete). The original catalog row pinned ``==2.4.49`` and
  silently missed the 2.4.50 case.
  """

  def test_cve_2021_42013_fires_on_2_4_49(self):
    findings = check_cves("apache", "2.4.49")
    cves = {c for f in findings for c in (f.cve or ())}
    self.assertIn(
      "CVE-2021-42013", cves,
      "CVE-2021-42013 must fire on Apache 2.4.49",
    )

  def test_cve_2021_42013_fires_on_2_4_50(self):
    findings = check_cves("apache", "2.4.50")
    cves = {c for f in findings for c in (f.cve or ())}
    self.assertIn(
      "CVE-2021-42013", cves,
      "CVE-2021-42013 must also fire on Apache 2.4.50 (vulhub's image)",
    )

  def test_cve_2021_42013_does_not_fire_on_2_4_51(self):
    findings = check_cves("apache", "2.4.51")
    cves = {c for f in findings for c in (f.cve or ())}
    self.assertNotIn(
      "CVE-2021-42013", cves,
      "CVE-2021-42013 must not fire on 2.4.51 (the actual fix release)",
    )


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


class TestCveApplicability(unittest.TestCase):
  """
  `CveEntry` had no component/role dimension, so every CVE tagged `openssh`
  fired on any OpenSSH artifact — including client-side ones matched off a
  *listening sshd banner*: SCP client-side file overwrite, client
  VerifyHostKeyDNS, ssh-add, forwarded ssh-agent. A server banner cannot
  evidence a client-side weakness.
  """

  def _ids(self, version, **kwargs):
    return {
      cve_id
      for finding in check_cves("openssh", version, **kwargs)
      for cve_id in (getattr(finding, "cve", None) or ())
    }

  def test_a_listening_server_banner_does_not_raise_client_side_cves(self):
    fired = self._ids("OpenSSH_8.9p1")
    # CVE-2019-6111 is an scp *client* file-overwrite; CVE-2025-26465 is a
    # client-side VerifyHostKeyDNS bypass. Neither is evidenced by sshd.
    self.assertNotIn("CVE-2019-6111", fired)
    self.assertNotIn("CVE-2025-26465", fired)

  def test_client_side_cves_are_still_reachable_when_asked_for(self):
    # 7.9 is inside CVE-2019-6111's `<8.1` range; the gate hides it from a
    # server query rather than dropping it from the catalog.
    self.assertNotIn("CVE-2019-6111", self._ids("OpenSSH_7.9"))
    self.assertIn("CVE-2019-6111", self._ids("OpenSSH_7.9", applicability="client"))


class TestRegreSSHionConstraint(unittest.TestCase):
  """
  CVE-2024-6387 was encoded as `openssh <9.3`. The published scope is
  `<4.4p1` plus `>=8.5p1,<9.8p1`, so the single range both over-matched
  (4.4p1 through 8.5p1 are not vulnerable) and under-matched (9.3 through
  9.8p1 are).
  """

  def _fires(self, version):
    return "CVE-2024-6387" in {
      cve_id
      for finding in check_cves("openssh", version)
      for cve_id in (getattr(finding, "cve", None) or ())
    }

  def test_the_vulnerable_ranges_fire(self):
    for version in ("OpenSSH_4.3", "OpenSSH_8.5p1", "OpenSSH_8.9p1", "OpenSSH_9.7"):
      with self.subTest(version=version):
        self.assertTrue(self._fires(version), f"{version} is in the published scope")

  def test_the_unaffected_middle_range_does_not_fire(self):
    # Over-matching: these sit between the two vulnerable ranges.
    for version in ("OpenSSH_4.4p1", "OpenSSH_5.0", "OpenSSH_7.4", "OpenSSH_8.4"):
      with self.subTest(version=version):
        self.assertFalse(self._fires(version), f"{version} is not in the published scope")

  def test_the_upper_range_is_not_truncated_at_9_3(self):
    # Under-matching: 9.3 to 9.8p1 are vulnerable and were being missed.
    for version in ("OpenSSH_9.3", "OpenSSH_9.6"):
      with self.subTest(version=version):
        self.assertTrue(self._fires(version), f"{version} is in the published scope")

  def test_the_fixed_release_does_not_fire(self):
    self.assertFalse(self._fires("OpenSSH_9.8p1"))

  def test_the_boundaries_hold_for_the_version_the_matcher_actually_receives(self):
    # `_SSH_LIBRARY_PATTERNS` captures `(\d+\.\d+(?:\.\d+)?)`, so the matcher
    # is handed "9.8", never "9.8p1". Writing the published `p`-suffixed bounds
    # shifted both boundaries by a release: a patched 9.8 reported CRITICAL and
    # a vulnerable 8.5 was missed.
    self.assertFalse(self._fires("9.8"), "9.8 is the fixed release")
    self.assertTrue(self._fires("8.5"), "8.5 is inside the published scope")
    self.assertTrue(self._fires("9.7"))
    self.assertFalse(self._fires("8.4"))

  def test_a_client_side_critical_does_not_fire_from_a_server_banner(self):
    # CVE-2016-1908 is an OpenSSH *client* X11-cookie weakness, and CRITICAL —
    # the highest-severity instance of the over-match the applicability gate
    # exists to stop.
    fired = {
      cve_id
      for finding in check_cves("openssh", "4.4")
      for cve_id in (getattr(finding, "cve", None) or ())
    }
    self.assertNotIn("CVE-2016-1908", fired)


class TestPackageVersionParsing(unittest.TestCase):
  """
  `_parse_version` matched the first numeric run in the string, so a
  Debian/RPM epoch was read as the upstream version: `1:8.9p1-3ubuntu0.10`
  returned (1,), making an OpenSSH 8.9 host match every CVE for 1.x.

  Latent while `_ssh_identify_library` reduces the banner to "8.9" before the
  matcher sees it, but live the moment the full distribution package string is
  carried through — which is the remaining half of RM-064 item 5.
  """

  def test_an_epoch_is_not_read_as_the_upstream_version(self):
    from extensions.business.cybersec.red_mesh.cve_db import _parse_version
    self.assertEqual(_parse_version("1:8.9p1-3ubuntu0.10"), _parse_version("8.9p1"))
    self.assertEqual(_parse_version("2:1.2.3"), (1, 2, 3))

  def test_ordinary_version_strings_are_unaffected(self):
    from extensions.business.cybersec.red_mesh.cve_db import _parse_version
    self.assertEqual(_parse_version("OpenSSH_8.9p1"), (8, 9, 16, 1))
    self.assertEqual(_parse_version("1.4.3-beta"), (1, 4, 3))
    self.assertEqual(_parse_version("Apache/2.4.57 (Ubuntu)"), (2, 4, 57))

  def test_an_epoch_prefixed_package_no_longer_matches_1_x_cves(self):
    fired = {
      cve_id
      for finding in check_cves("openssh", "1:8.9p1-3ubuntu0.10")
      for cve_id in (getattr(finding, "cve", None) or ())
    }
    # 8.9p1 is inside the regreSSHion upper range and outside the ancient ones.
    self.assertIn("CVE-2024-6387", fired)
    self.assertNotIn("CVE-2016-6210", fired)   # openssh <7.0
    self.assertNotIn("CVE-2017-15906", fired)  # openssh <7.6


if __name__ == "__main__":
  unittest.main()
