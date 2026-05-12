"""Phase 2 of PR 388 remediation — LLM payload shape traversal.

Covers audit #3 (findings extraction) and #9 (service summary):
nested {port: {probe: {findings:[...]}}} shape is traversed correctly,
probe-rank conflict resolution picks the right metadata winner, legacy
flat shapes still work, and every emitted finding carries source
attribution fields.
"""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.mixins.redmesh_llm_agent import (
  _RedMeshLlmAgentMixin,
)
from extensions.business.cybersec.red_mesh.tests.fixtures.multi_probe_report import (
  build_aggregated_report,
)


class _Host(_RedMeshLlmAgentMixin):
  def __init__(self):
    super().__init__()
    self.P = MagicMock()
    self.Pd = MagicMock()


class TestExtractReportFindings(unittest.TestCase):

  def test_extracts_nested_network_findings(self):
    """Every finding under {port: {probe: {findings:[]}}} surfaces.

    Port 443 has two probes (https + tls) with 1 and 2 findings.
    Port 8080 has generic + web_test with 1 + 1. Port 22 is legacy
    flat shape with 1 finding. Port 9999 is malformed (findings is a
    string) and must be quarantined, contributing 0 findings.
    Expected total: 1 + 2 + 1 + 1 + 1 = 6.
    """
    host = _Host()
    report = build_aggregated_report()

    findings = host._extract_report_findings(report)

    self.assertEqual(len(findings), 6)

  def test_stamps_source_probe_and_port_on_every_finding(self):
    """Chain-of-custody: every finding carries _source_probe and
    _source_port. No finding escapes extraction without attribution.
    """
    host = _Host()
    findings = host._extract_report_findings(build_aggregated_report())

    for f in findings:
      self.assertIn("_source_probe", f)
      self.assertIn("_source_port", f)
      self.assertTrue(f["_source_probe"])

  def test_source_probe_reflects_actual_nested_key(self):
    """A TLSv1.0 finding on port 443 is stamped as coming from
    _service_info_tls, not the neighbor _service_info_https.
    """
    host = _Host()
    findings = host._extract_report_findings(build_aggregated_report())

    tls_findings = [f for f in findings if "TLSv1.0" in (f.get("title") or "")]
    self.assertEqual(len(tls_findings), 1)
    self.assertEqual(tls_findings[0]["_source_probe"], "_service_info_tls")
    self.assertEqual(tls_findings[0]["_source_port"], 443)

  def test_legacy_flat_shape_still_surfaces_findings(self):
    """Port 22 uses the flat test-only shape. Its SSH finding must
    still reach the extracted list (no silent drop).
    """
    host = _Host()
    findings = host._extract_report_findings(build_aggregated_report())
    ssh_findings = [f for f in findings if "OpenSSH 7.4" in (f.get("title") or "")]
    self.assertEqual(len(ssh_findings), 1)
    self.assertEqual(ssh_findings[0]["_source_port"], 22)

  def test_malformed_probe_is_quarantined_not_raised(self):
    """Port 9999 has findings="oops_not_a_list". Extraction must NOT
    raise, NOT treat the string as an iterable of findings, and must
    record the entry in _last_llm_malformed.
    """
    host = _Host()
    findings = host._extract_report_findings(build_aggregated_report())

    malformed = host._last_llm_malformed
    self.assertTrue(any(
      m["method"] == "_service_info_generic" and m["port"] == 9999
      for m in malformed
    ))
    # And the string is not shredded into per-character findings.
    self.assertFalse(any(
      (f.get("title") or "") in ("o", "p", "s", "_")
      for f in findings
    ))

  def test_graybox_results_findings_are_stamped(self):
    """graybox_results probes get _source_probe = probe name."""
    host = _Host()
    report = {
      "graybox_results": {
        "443": {
          "_graybox_access_control": {
            "findings": [
              {"severity": "HIGH", "title": "IDOR",
               "port": 443, "protocol": "https"},
            ],
          },
        },
      },
    }
    findings = host._extract_report_findings(report)
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["_source_probe"], "_graybox_access_control")

  def test_missing_service_info_does_not_crash(self):
    """Empty report returns [] with no exception."""
    host = _Host()
    self.assertEqual(host._extract_report_findings({}), [])
    self.assertEqual(host._extract_report_findings({"service_info": None}), [])


class TestBuildNetworkServiceSummary(unittest.TestCase):

  def test_probe_rank_picks_protocol_match_over_tls(self):
    """On port 443, _service_info_https has rank 0 (matches the
    port_proto "https") and _service_info_tls has rank 1. The https
    probe's server "nginx/1.18.0" must win over tls's "legacy-cn".
    """
    host = _Host()
    services, _ = host._build_network_service_summary(
      build_aggregated_report(), "security_assessment",
    )
    port_443 = next(s for s in services if s["port"] == 443)
    # product wraps the server string via sanitizer — strip wrapper.
    open_tag = "<untrusted_target_data>"
    close_tag = "</untrusted_target_data>"
    product = port_443["product"]
    self.assertTrue(product.startswith(open_tag))
    unwrapped = product[len(open_tag):-len(close_tag)]
    self.assertEqual(unwrapped, "nginx/1.18.0")

  def test_legacy_flat_shape_produces_summary_entry(self):
    """Port 22 (flat shape) still produces a services entry with
    banner, product, version and protocol populated.
    """
    host = _Host()
    services, _ = host._build_network_service_summary(
      build_aggregated_report(), "security_assessment",
    )
    port_22 = next(s for s in services if s["port"] == 22)
    self.assertIn("OpenSSH", port_22["product"])
    self.assertIn("7.4", port_22["version"])
    self.assertIn("SSH-2.0-OpenSSH_7.4", port_22["banner"])

  def test_finding_count_reflects_merged_probe_findings(self):
    """Port 443 has 1 https + 2 tls findings = 3 in the summary."""
    host = _Host()
    services, _ = host._build_network_service_summary(
      build_aggregated_report(), "security_assessment",
    )
    port_443 = next(s for s in services if s["port"] == 443)
    self.assertEqual(port_443["finding_count"], 3)


if __name__ == '__main__':
  unittest.main()
