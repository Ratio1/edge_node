"""Phase 1 PR-1.1 — Finding schema extensions.

Verifies the new fields added in Phase 1 (content-addressed identity,
structured remediation/evidence/affected_assets, CVSS Environmental,
KEV/EPSS, forward-compat triage state etc.) work end-to-end:

  - default values do not break existing probe call sites
  - signature is content-addressed and stable
  - serialization round-trips cleanly
  - new aux dataclasses (AffectedAsset, Remediation, Evidence)
    construct and serialize
"""

import unittest

from extensions.business.cybersec.red_mesh.findings import (
  AffectedAsset,
  Evidence,
  Finding,
  Remediation,
  Severity,
  finding_from_dict,
  probe_result,
  EXPLOITABILITY_CONFIRMED,
  EXPLOITABILITY_NOT,
  SOURCE_AUTOMATED,
  SOURCE_MANUAL,
  TRIAGE_NEW,
  TRIAGE_CONFIRMED,
  ALLOWED_SOURCES,
  ALLOWED_TRIAGE_STATES,
)


class TestFindingDefaults(unittest.TestCase):
  """New fields all have safe defaults — minimal-args construction works."""

  def test_minimal_construction(self):
    f = Finding(severity=Severity.HIGH, title="t", description="d")
    self.assertEqual(f.severity, Severity.HIGH)
    self.assertEqual(f.cwe, ())
    self.assertEqual(f.cve, ())
    self.assertEqual(f.references, ())
    self.assertEqual(f.affected_assets, ())
    self.assertEqual(f.evidence_items, ())
    self.assertIsNone(f.remediation_structured)
    self.assertEqual(f.source, SOURCE_AUTOMATED)
    self.assertEqual(f.triage_state, TRIAGE_NEW)
    self.assertFalse(f.kev)
    self.assertIsNone(f.epss_score)
    self.assertEqual(f.cvss_version, "3.1")
    self.assertFalse(f.ai_generated)


class TestFindingSignature(unittest.TestCase):

  def test_signature_is_stable_for_same_inputs(self):
    f = Finding(
      severity=Severity.HIGH, title="IDOR",
      description="Object-level authz bypass on /api/records/1",
    )
    sig1 = f.compute_signature(probe_id="_graybox_access_control",
                               asset_canonical="10.132.0.3:10000/api/records/1")
    sig2 = f.compute_signature(probe_id="_graybox_access_control",
                               asset_canonical="10.132.0.3:10000/api/records/1")
    self.assertEqual(sig1, sig2)
    self.assertEqual(len(sig1), 64)  # sha256 hex

  def test_signature_differs_for_different_titles(self):
    a = Finding(severity=Severity.HIGH, title="IDOR", description="d")
    b = Finding(severity=Severity.HIGH, title="CSRF", description="d")
    self.assertNotEqual(
      a.compute_signature(probe_id="x"),
      b.compute_signature(probe_id="x"),
    )

  def test_signature_differs_for_different_probes(self):
    f = Finding(severity=Severity.HIGH, title="t", description="d")
    self.assertNotEqual(
      f.compute_signature(probe_id="_graybox_access_control"),
      f.compute_signature(probe_id="_graybox_misconfig"),
    )

  def test_signature_uses_affected_assets_when_no_canonical_passed(self):
    f1 = Finding(
      severity=Severity.HIGH, title="t", description="d",
      affected_assets=(AffectedAsset(host="10.0.0.1", port=80, url="/a"),),
    )
    f2 = Finding(
      severity=Severity.HIGH, title="t", description="d",
      affected_assets=(AffectedAsset(host="10.0.0.1", port=443, url="/a"),),
    )
    self.assertNotEqual(
      f1.compute_signature(probe_id="x"),
      f2.compute_signature(probe_id="x"),
    )

  def test_with_signature_returns_new_finding(self):
    f = Finding(severity=Severity.HIGH, title="t", description="d")
    sig = f.compute_signature(probe_id="x")
    f2 = f.with_signature(sig)
    self.assertEqual(f2.finding_signature, sig)
    self.assertEqual(f.finding_signature, "")  # original immutable


class TestStructuredFields(unittest.TestCase):

  def test_remediation_three_part_construction(self):
    r = Remediation(
      primary="Upgrade Apache to 2.4.51 or later",
      mitigation="Disable mod_cgi if not required",
      compensating="WAF rule blocking ...%2e... patterns",
    )
    self.assertEqual(r.primary, "Upgrade Apache to 2.4.51 or later")
    self.assertEqual(r.mitigation, "Disable mod_cgi if not required")

  def test_remediation_only_primary_required(self):
    r = Remediation(primary="Upgrade")
    self.assertEqual(r.mitigation, "")
    self.assertEqual(r.compensating, "")

  def test_affected_asset_optional_fields(self):
    a = AffectedAsset(host="10.0.0.1")
    self.assertEqual(a.host, "10.0.0.1")
    self.assertIsNone(a.port)
    self.assertIsNone(a.method)

  def test_evidence_kinds(self):
    e = Evidence(kind="request_response", caption="Path traversal proof",
                 cid="QmFakeCid", snippet="GET /icons/.%2e/etc/passwd")
    self.assertEqual(e.kind, "request_response")
    self.assertEqual(e.cid, "QmFakeCid")


class TestForwardCompatFields(unittest.TestCase):

  def test_source_constants_in_allowed_set(self):
    self.assertIn(SOURCE_AUTOMATED, ALLOWED_SOURCES)
    self.assertIn(SOURCE_MANUAL, ALLOWED_SOURCES)

  def test_triage_state_constants_in_allowed_set(self):
    self.assertIn(TRIAGE_NEW, ALLOWED_TRIAGE_STATES)
    self.assertIn(TRIAGE_CONFIRMED, ALLOWED_TRIAGE_STATES)

  def test_exploitability_status_can_be_set(self):
    f = Finding(severity=Severity.HIGH, title="t", description="d",
                exploitability_status=EXPLOITABILITY_CONFIRMED)
    self.assertEqual(f.exploitability_status, EXPLOITABILITY_CONFIRMED)
    f2 = Finding(severity=Severity.HIGH, title="t", description="d",
                 exploitability_status=EXPLOITABILITY_NOT)
    self.assertEqual(f2.exploitability_status, EXPLOITABILITY_NOT)

  def test_p12_invariant_ai_generated_default_false(self):
    """P12: AI never writes finding data. Default must reflect that."""
    f = Finding(severity=Severity.HIGH, title="t", description="d")
    self.assertFalse(f.ai_generated)


class TestSerialization(unittest.TestCase):

  def test_probe_result_returns_jsonable_dict(self):
    f = Finding(
      severity=Severity.HIGH, title="t", description="d",
      cwe=(287,), cve=("CVE-2021-41773",),
      remediation_structured=Remediation(primary="Upgrade"),
      affected_assets=(AffectedAsset(host="h", port=80),),
    )
    result = probe_result(findings=[f])
    self.assertIn("findings", result)
    self.assertEqual(len(result["findings"]), 1)
    raw = result["findings"][0]
    # Severity enum normalized to string
    self.assertEqual(raw["severity"], "HIGH")
    # Tuples become lists for canonical JSON
    self.assertIsInstance(raw["cwe"], list)
    self.assertEqual(raw["cwe"], [287])
    self.assertEqual(raw["cve"], ["CVE-2021-41773"])
    self.assertIsInstance(raw["affected_assets"], list)

  def test_round_trip_through_dict(self):
    """asdict + finding_from_dict produces an equal Finding."""
    f = Finding(
      severity=Severity.HIGH, title="IDOR", description="d",
      cwe=(639,), cve=("CVE-2024-12345",),
      affected_assets=(AffectedAsset(host="10.0.0.1", port=10000, url="/api/records/1"),),
      evidence_items=(Evidence(kind="request_response", caption="proof"),),
      remediation_structured=Remediation(primary="fix"),
    )
    raw = probe_result(findings=[f])["findings"][0]
    revived = finding_from_dict(raw)
    self.assertEqual(revived.severity, Severity.HIGH)
    self.assertEqual(revived.cwe, (639,))
    self.assertEqual(revived.affected_assets[0].host, "10.0.0.1")
    self.assertEqual(revived.affected_assets[0].port, 10000)
    self.assertEqual(revived.evidence_items[0].kind, "request_response")
    self.assertEqual(revived.remediation_structured.primary, "fix")

  def test_legacy_probe_result_shape_unchanged(self):
    """Probes that emit only legacy-shape findings still produce
    a result dict with the expected legacy fields."""
    f = Finding(
      severity=Severity.HIGH, title="t", description="d",
      evidence="some text", remediation="patch", owasp_id="A07:2021",
      cwe_id="CWE-287", cvss_score=8.1, cvss_vector="CVSS:...",
    )
    raw = probe_result(findings=[f])["findings"][0]
    for key in ("severity", "title", "description", "evidence",
                "remediation", "owasp_id", "cwe_id", "confidence",
                "cvss_score", "cvss_vector"):
      self.assertIn(key, raw, f"legacy field missing: {key}")

  def test_probe_result_enriches_legacy_finding_when_probe_known(self):
    f = Finding(
      severity=Severity.HIGH,
      title="legacy",
      description="legacy description",
      remediation="patch",
      cwe_id="CWE-287",
      owasp_id="A07:2021",
    )
    raw = probe_result(findings=[f], probe_id="_web_test_example")["findings"][0]
    self.assertEqual(raw["cwe"], [287])
    self.assertEqual(raw["owasp_top10"], ["A07:2021"])
    self.assertEqual(raw["remediation_structured"]["primary"], "patch")
    self.assertEqual(len(raw["finding_signature"]), 64)


if __name__ == "__main__":
  unittest.main()
