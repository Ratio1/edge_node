"""Server-header co-disclosure: extract OpenSSL package version.

Apache `ServerTokens Full` and some nginx builds expose the OpenSSL
package version alongside the primary product, e.g.
``Server: Apache/2.4.50 (Unix) OpenSSL/1.0.2k``.

Without dedicated extraction, only the Apache CVEs fired and the
co-disclosed OpenSSL CVEs were silently missed. The probe now runs a
second `OpenSSL/<version>` regex pass and feeds the version through
``check_cves("openssl", version)``.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.worker.service.common import _ServiceCommonMixin


def _fake_response(server_header: str, status: int = 200):
  resp = MagicMock()
  resp.status_code = status
  resp.reason = "OK"
  resp.headers = {"Server": server_header}
  resp.text = "<html><title>idx</title></html>"
  return resp


class TestOpenSslServerHeaderExtraction(unittest.TestCase):
  """When the Server header co-discloses OpenSSL, both products' CVEs
  must fire — not just the primary product (Apache/nginx).
  """

  def _make_probe(self):
    probe = _ServiceCommonMixin.__new__(_ServiceCommonMixin)
    probe.P = lambda *a, **kw: None
    probe.scanner_user_agent = ""
    # _emit_metadata is normally injected by the probe runtime; stub it.
    probe._emit_metadata = lambda *a, **kw: None
    return probe

  def _findings_cve_set(self, result):
    """Extract the union of CVE ids from a probe_result findings list."""
    return {
      c
      for f in result.get("findings", [])
      for c in (f.get("cve") or [])
      if c
    }

  def test_http_probe_extracts_apache_and_openssl_cves(self):
    probe = self._make_probe()
    fake = _fake_response("Apache/2.4.50 (Unix) OpenSSL/1.0.2k")

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.get",
      return_value=fake,
    ):
      result = probe._service_info_http("10.0.0.1", 80)

    cves = self._findings_cve_set(result)
    # Apache CVEs must fire on 2.4.50 (e.g. CVE-2021-42013 after T1.2 widening).
    self.assertIn(
      "CVE-2021-42013", cves,
      f"Apache CVEs should fire from 2.4.50; got {sorted(cves)}",
    )
    # OpenSSL 1.0.2k is vulnerable to several CVEs whose constraint covers it
    # (CVE-2020-1971 <1.1.1, CVE-2022-3602 <3.0.7, CVE-2024-4741 <3.0.14, etc.).
    openssl_post_heartbleed = {
      "CVE-2020-1971", "CVE-2022-3602", "CVE-2024-4741",
    }
    self.assertTrue(
      openssl_post_heartbleed & cves,
      f"OpenSSL co-disclosed CVEs should fire on 1.0.2k; got {sorted(cves)}",
    )

  def test_openssl_1_0_2k_does_not_fire_heartbleed(self):
    """Sanity inversion: the 1.0.2k extraction must not produce Heartbleed.

    Heartbleed only affects 1.0.1 < 1.0.1g, not 1.0.2.x. If the version
    parser misclassifies 1.0.2k, this would silently mis-fire.
    """
    from extensions.business.cybersec.red_mesh.cve_db import check_cves

    cves = {c for f in check_cves("openssl", "1.0.2k") for c in (f.cve or ())}
    self.assertNotIn(
      "CVE-2014-0160", cves,
      "OpenSSL 1.0.2k must not match Heartbleed (1.0.1<g only)",
    )

  def test_http_probe_with_only_openssl_token_fires_openssl_cves(self):
    """The OpenSSL extraction must work even when the primary product
    line itself isn't recognised — e.g. weird custom Server strings.
    """
    probe = self._make_probe()
    # 'Frobozz/1.0' is not in _HTTP_PRODUCT_MAP, so primary CVE matching
    # is a no-op. The OpenSSL token should still produce CVEs.
    fake = _fake_response("Frobozz/1.0 OpenSSL/1.0.1c")

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.get",
      return_value=fake,
    ):
      result = probe._service_info_http("10.0.0.1", 80)

    cves = self._findings_cve_set(result)
    self.assertIn(
      "CVE-2014-0160", cves,
      f"OpenSSL 1.0.1c is Heartbleed-vulnerable; Server header co-disclosure "
      f"must trigger it. Got {sorted(cves)}",
    )

  def test_https_probe_extracts_openssl_cves(self):
    """Same logic for the HTTPS variant (_service_info_https)."""
    probe = self._make_probe()
    fake = _fake_response("Apache/2.4.50 (Unix) OpenSSL/1.0.1c")

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.get",
      return_value=fake,
    ):
      result = probe._service_info_https("10.0.0.1", 443)

    cves = self._findings_cve_set(result)
    self.assertIn(
      "CVE-2014-0160", cves,
      "HTTPS probe must also extract co-disclosed OpenSSL token",
    )


if __name__ == "__main__":
  unittest.main()
