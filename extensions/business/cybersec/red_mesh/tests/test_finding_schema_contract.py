"""RM-062 B1: one typed, versioned finding contract.

`PassReport.findings` is `list` — an untyped list of dicts assembled by two
independent code paths that agree on nothing. The blackbox path builds its dict
in a closure inside `mixins/risk.py`; the graybox path builds a different one in
`GrayboxFinding.to_flat_finding`. Neither declares a schema, neither validates,
and `from_dict` whitelists silently drop any key they disagree on — so a field
one producer emits and the other does not simply vanishes somewhere downstream,
with nothing to say it ever existed.

This file pins the contract itself: the version stamp, what validation rejects,
and the property the whitelist broke — a round trip must not lose data.
"""

import unittest

from extensions.business.cybersec.red_mesh.models.finding_schema import (
  REDMESH_FINDING_SCHEMA,
  REDMESH_FINDING_SCHEMA_VERSION,
  FlatFinding,
  flat_finding_from_dict,
  validate_flat_finding,
)


def _minimal(**overrides):
  payload = {
    "schema": REDMESH_FINDING_SCHEMA,
    "schema_version": REDMESH_FINDING_SCHEMA_VERSION,
    "finding_id": "0123456789abcdef",
    "finding_signature": "a" * 64,
    "title": "Default credentials accepted",
    "severity": "HIGH",
    "confidence": "certain",
    "probe": "_service_info_http",
    "probe_type": "blackbox",
    "category": "service",
    "port": 443,
    "protocol": "https",
  }
  payload.update(overrides)
  return payload


class TestTheContractIsVersioned(unittest.TestCase):

  def test_a_finding_carries_the_schema_and_its_version(self):
    finding = flat_finding_from_dict(_minimal())
    self.assertEqual(finding.schema, REDMESH_FINDING_SCHEMA)
    self.assertEqual(finding.schema_version, REDMESH_FINDING_SCHEMA_VERSION)

  def test_an_unstamped_finding_is_accepted_and_stamped(self):
    """Historical archives predate the stamp and must stay readable.

    `JobArchive.from_dict` already version-gates this way. A finding with no
    schema is a v0 finding, not an invalid one.
    """
    payload = _minimal()
    del payload["schema"]
    del payload["schema_version"]
    finding = flat_finding_from_dict(payload)
    self.assertEqual(finding.schema_version, REDMESH_FINDING_SCHEMA_VERSION)

  def test_a_future_schema_version_is_refused_rather_than_misread(self):
    errors = validate_flat_finding(_minimal(schema_version="9.0.0"))
    self.assertTrue(any("schema_version" in error for error in errors))


class TestValidationRejectsRatherThanDiscards(unittest.TestCase):

  def test_a_valid_finding_has_no_errors(self):
    self.assertEqual(validate_flat_finding(_minimal()), [])

  def test_a_missing_required_field_is_named(self):
    payload = _minimal()
    del payload["severity"]
    self.assertIn("missing required field: severity", validate_flat_finding(payload))

  def test_an_unknown_severity_is_rejected(self):
    errors = validate_flat_finding(_minimal(severity="SEVERE"))
    self.assertTrue(any("severity" in error for error in errors))

  def test_an_unknown_confidence_is_rejected_not_silently_defaulted(self):
    """`mixins/risk.py` maps an unknown confidence to 0.5 without comment.

    A typo in a probe therefore scores as a real half-confidence finding, and
    nothing anywhere says the value was not understood.
    """
    errors = validate_flat_finding(_minimal(confidence="probably"))
    self.assertTrue(any("confidence" in error for error in errors))

  def test_a_non_dict_is_rejected(self):
    self.assertTrue(validate_flat_finding(["not", "a", "finding"]))


class TestTheRoundTripLosesNothing(unittest.TestCase):

  def test_a_known_field_survives(self):
    payload = _minimal(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    self.assertEqual(
      flat_finding_from_dict(payload).to_dict()["cvss_vector"],
      payload["cvss_vector"],
    )

  def test_a_field_the_contract_does_not_know_is_preserved_not_dropped(self):
    """The whitelist behaviour this contract exists to end.

    A producer-specific key — a new probe's field, or one half of the model
    emitting something the other does not — was silently discarded on the way
    through, so the loss was invisible at every layer that could have reported
    it.
    """
    payload = _minimal(some_new_probe_field="matters to whoever emitted it")
    restored = flat_finding_from_dict(payload).to_dict()
    self.assertEqual(restored["some_new_probe_field"], "matters to whoever emitted it")

  def test_a_full_round_trip_is_byte_identical(self):
    payload = _minimal(
      description="Scenario PT-A01-01: IDOR",
      evidence="endpoint=https://app.test/x",
      affected_assets=[{"host": "app.test", "port": 443, "url": "https://app.test/x"}],
      cwe=[639],
      unexpected={"nested": ["structure"]},
    )
    self.assertEqual(flat_finding_from_dict(payload).to_dict(), payload)

  def test_the_dataclass_is_hashable_and_frozen(self):
    finding = flat_finding_from_dict(_minimal())
    with self.assertRaises(Exception):
      finding.severity = "LOW"      # type: ignore[misc]
    self.assertIsInstance(finding, FlatFinding)
    # Actually hashable, not just named so: `extra` is a dict, and leaving it in
    # the comparison set made every instance unhashable while this test passed.
    self.assertIsInstance(hash(finding), int)

  def test_a_directly_constructed_finding_serialises_its_fields(self):
    """`to_dict` filtered on the source payload's key set, which is empty for a
    direct construction — so it returned `{}` from the method whose docstring
    promises to lose nothing, silently, for the API B1 tells consumers to use.
    """
    finding = FlatFinding(
      finding_id="0123456789abcdef", title="Weak TLS", severity="MEDIUM",
      confidence="certain", probe="_service_info_ssl", category="service",
    )
    payload = finding.to_dict()
    self.assertEqual(payload["title"], "Weak TLS")
    self.assertEqual(payload["severity"], "MEDIUM")
    self.assertEqual(payload["schema"], REDMESH_FINDING_SCHEMA)
    self.assertEqual(validate_flat_finding(payload), [])

  def test_a_directly_constructed_finding_does_not_invent_empty_fields(self):
    finding = FlatFinding(
      finding_id="0123456789abcdef", title="t", severity="LOW",
      confidence="firm", probe="_p", category="service",
    )
    self.assertNotIn("remediation", finding.to_dict())


class TestBothProducersEmitTheContract(unittest.TestCase):
  """The point of the contract: one shape, from both halves of the scanner.

  A benchmark harness, the SIEM export and the report all consume
  `PassReport.findings` without knowing which producer wrote each entry. Until
  now the two producers agreed on no field list and declared no version, so
  "the finding schema" was whatever the reader happened to test against.
  """

  def test_a_graybox_finding_validates_against_the_contract(self):
    from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding

    flat = GrayboxFinding(
      scenario_id="PT-A01-01", title="IDOR", status="vulnerable",
      severity="HIGH", owasp="A01:2021", cwe=["CWE-639"],
      url="https://app.test/api/records/99",
    ).to_flat_finding(port=443, protocol="https", probe_name="_graybox_access_control")

    self.assertEqual(flat["schema"], REDMESH_FINDING_SCHEMA)
    self.assertEqual(validate_flat_finding(flat), [])

  def test_a_blackbox_finding_validates_against_the_contract(self):
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    report = {
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": [{
        "title": "Default credentials accepted",
        "severity": "HIGH",
        "confidence": "certain",
        "description": "admin login accepted",
      }]}}},
    }
    _, flat_findings = MockHost()._compute_risk_and_findings(report)
    self.assertTrue(flat_findings, "no flat findings were produced")
    for flat in flat_findings:
      self.assertEqual(flat["schema"], REDMESH_FINDING_SCHEMA)
      self.assertEqual(validate_flat_finding(flat), [], flat)

  def test_a_probe_specific_field_survives_the_blackbox_path(self):
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    report = {
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": [{
        "title": "t", "severity": "LOW", "confidence": "firm",
        "probe_specific_detail": "kept",
      }]}}},
    }
    _, flat_findings = MockHost()._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["probe_specific_detail"], "kept")


if __name__ == "__main__":
  unittest.main()
