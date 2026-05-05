"""Phase 3 PR-3.1 — engagement-context model tests.

Verifies:
  - Default construction (legacy/quick-launch path) produces empty
    instances with is_empty() returning True.
  - Validation accepts known enum values, rejects unknown ones.
  - Round-trip through to_dict / from_dict preserves all fields.
  - Empty / null serialized input round-trips to None or empty
    instance per the documented contract.
  - KickoffQuestionnaire bundles the three sub-models correctly.
"""
from __future__ import annotations

import unittest

from extensions.business.cybersec.red_mesh.models.engagement import (
  ASSET_EXPOSURES,
  AuthorizationRef,
  Contact,
  DATA_CLASSIFICATIONS,
  EngagementContext,
  KickoffQuestionnaire,
  POST_EXPLOIT_RULES,
  RulesOfEngagement,
  STRENGTH_OF_TEST,
)


class TestContact(unittest.TestCase):

  def test_default_construction_is_empty(self):
    c = Contact()
    self.assertTrue(c.is_empty())

  def test_round_trip_through_dict(self):
    c = Contact(name="Jane Doe", email="jane@acme.example",
                phone="+1-555-0000", role="Security Lead")
    d = c.to_dict()
    self.assertEqual(d["name"], "Jane Doe")
    restored = Contact.from_dict(d)
    self.assertEqual(restored, c)

  def test_from_dict_returns_none_for_empty(self):
    self.assertIsNone(Contact.from_dict(None))
    self.assertIsNone(Contact.from_dict({}))

  def test_from_dict_coerces_to_strings(self):
    # Numeric or other non-string inputs get coerced
    c = Contact.from_dict({"name": 12345, "phone": None, "email": ""})
    self.assertEqual(c.name, "12345")
    self.assertEqual(c.phone, "None")  # str(None) — caller responsibility


class TestEngagementContext(unittest.TestCase):

  def test_default_construction_is_empty(self):
    ctx = EngagementContext()
    self.assertTrue(ctx.is_empty())

  def test_default_methodology_set(self):
    ctx = EngagementContext()
    self.assertIn("PTES", ctx.methodology)
    self.assertIn("OWASP", ctx.methodology)

  def test_round_trip(self):
    ctx = EngagementContext(
      client_name="ACME Corp",
      engagement_code="ENG-2026-001",
      primary_objective="External perimeter assessment",
      secondary_objective="PCI DSS 11.3 compliance",
      scope_rationale="Annual penetration test per insurance requirement",
      data_classification="PCI",
      asset_exposure="external",
      point_of_contact=Contact(name="Jane", email="jane@acme.example",
                              role="Security Lead"),
      emergency_contact=Contact(name="Ops", phone="+1-555-0000",
                              role="On-call Engineer"),
    )
    d = ctx.to_dict()
    restored = EngagementContext.from_dict(d)
    self.assertEqual(restored.client_name, "ACME Corp")
    self.assertEqual(restored.data_classification, "PCI")
    self.assertEqual(restored.asset_exposure, "external")
    self.assertEqual(restored.point_of_contact.email, "jane@acme.example")
    self.assertEqual(restored.emergency_contact.phone, "+1-555-0000")

  def test_validate_accepts_known_classifications(self):
    for cls_val in DATA_CLASSIFICATIONS:
      ctx = EngagementContext(data_classification=cls_val)
      self.assertEqual(ctx.validate(), [], f"rejected known: {cls_val}")

  def test_validate_rejects_unknown_classification(self):
    ctx = EngagementContext(data_classification="HIPAA")  # not in enum
    errors = ctx.validate()
    self.assertEqual(len(errors), 1)
    self.assertIn("data_classification", errors[0])

  def test_validate_accepts_known_asset_exposures(self):
    for exp in ASSET_EXPOSURES:
      ctx = EngagementContext(asset_exposure=exp)
      self.assertEqual(ctx.validate(), [], f"rejected known: {exp}")

  def test_validate_rejects_unknown_asset_exposure(self):
    ctx = EngagementContext(asset_exposure="cloud")
    errors = ctx.validate()
    self.assertEqual(len(errors), 1)
    self.assertIn("asset_exposure", errors[0])

  def test_empty_engagement_passes_validation(self):
    """Quick-launch UX: blank engagement is acceptable."""
    ctx = EngagementContext()
    self.assertEqual(ctx.validate(), [])

  def test_from_dict_handles_none(self):
    self.assertIsNone(EngagementContext.from_dict(None))
    self.assertIsNone(EngagementContext.from_dict({}))


class TestRulesOfEngagement(unittest.TestCase):

  def test_default_is_empty_and_safe(self):
    roe = RulesOfEngagement()
    self.assertTrue(roe.is_empty())
    # Safe defaults
    self.assertEqual(roe.strength_of_test, "standard")
    self.assertFalse(roe.dos_allowed)
    self.assertEqual(roe.post_exploit_rules, "va_only")

  def test_round_trip(self):
    roe = RulesOfEngagement(
      strength_of_test="aggressive",
      dos_allowed=True,
      post_exploit_rules="pivot",
      blackout_windows=[("2026-05-04T22:00:00Z", "2026-05-05T06:00:00Z")],
      retest_window_end="2026-06-30",
    )
    d = roe.to_dict()
    restored = RulesOfEngagement.from_dict(d)
    self.assertEqual(restored.strength_of_test, "aggressive")
    self.assertTrue(restored.dos_allowed)
    self.assertEqual(restored.post_exploit_rules, "pivot")
    self.assertEqual(restored.blackout_windows, [
      ("2026-05-04T22:00:00Z", "2026-05-05T06:00:00Z"),
    ])
    self.assertEqual(restored.retest_window_end, "2026-06-30")

  def test_validate_rejects_unknown_strength(self):
    roe = RulesOfEngagement(strength_of_test="brutal")
    errors = roe.validate()
    self.assertEqual(len(errors), 1)
    self.assertIn("strength_of_test", errors[0])

  def test_validate_rejects_unknown_post_exploit(self):
    roe = RulesOfEngagement(post_exploit_rules="lateral_movement")
    errors = roe.validate()
    self.assertEqual(len(errors), 1)
    self.assertIn("post_exploit_rules", errors[0])

  def test_blackout_windows_coercion(self):
    """Lists vs. tuples both accepted on input."""
    roe = RulesOfEngagement.from_dict({
      "blackout_windows": [
        ["2026-05-01T00:00:00Z", "2026-05-02T00:00:00Z"],
        ("2026-05-10T00:00:00Z", "2026-05-11T00:00:00Z"),
      ]
    })
    self.assertEqual(len(roe.blackout_windows), 2)
    self.assertEqual(roe.blackout_windows[0],
                     ("2026-05-01T00:00:00Z", "2026-05-02T00:00:00Z"))

  def test_blackout_windows_drops_malformed(self):
    """1-element or 3-element lists are dropped, not crashed."""
    roe = RulesOfEngagement.from_dict({
      "blackout_windows": [
        ["only-one"],
        ["a", "b", "c"],
        ["good-start", "good-end"],
      ]
    })
    self.assertEqual(len(roe.blackout_windows), 1)


class TestAuthorizationRef(unittest.TestCase):

  def test_default_is_empty_no_doc(self):
    a = AuthorizationRef()
    self.assertTrue(a.is_empty())
    self.assertFalse(a.has_document())

  def test_with_document(self):
    a = AuthorizationRef(
      document_cid="QmFakeAuthCID",
      document_thumbnail_cid="QmFakeThumbCID",
      authorized_signer_name="John Doe",
      authorized_signer_role="CISO",
      third_party_auth_cids=["QmCloudAuthCID"],
    )
    self.assertFalse(a.is_empty())
    self.assertTrue(a.has_document())

  def test_round_trip(self):
    a = AuthorizationRef(
      document_cid="QmFakeAuthCID",
      authorized_signer_name="John Doe",
      authorized_signer_role="CISO",
      third_party_auth_cids=["QmCID1", "QmCID2"],
    )
    d = a.to_dict()
    restored = AuthorizationRef.from_dict(d)
    self.assertEqual(restored.document_cid, "QmFakeAuthCID")
    self.assertEqual(restored.third_party_auth_cids, ["QmCID1", "QmCID2"])

  def test_third_party_auth_cids_filters_falsy(self):
    a = AuthorizationRef.from_dict({
      "third_party_auth_cids": ["QmCID1", "", None, "QmCID2"],
    })
    self.assertEqual(a.third_party_auth_cids, ["QmCID1", "QmCID2"])


class TestKickoffQuestionnaire(unittest.TestCase):

  def test_empty_questionnaire_round_trip(self):
    q = KickoffQuestionnaire()
    self.assertTrue(q.is_empty())
    d = q.to_dict()
    restored = KickoffQuestionnaire.from_dict(d)
    self.assertTrue(restored.is_empty())

  def test_full_questionnaire_round_trip(self):
    q = KickoffQuestionnaire(
      engagement=EngagementContext(
        client_name="ACME", data_classification="PCI",
        asset_exposure="external",
      ),
      roe=RulesOfEngagement(strength_of_test="aggressive", dos_allowed=True),
      authorization=AuthorizationRef(
        document_cid="QmAuthCID", authorized_signer_name="Jane",
      ),
      schema_version="1.0",
      created_at="2026-05-05T10:00:00Z",
    )
    d = q.to_dict()
    restored = KickoffQuestionnaire.from_dict(d)
    self.assertEqual(restored.engagement.client_name, "ACME")
    self.assertTrue(restored.roe.dos_allowed)
    self.assertEqual(restored.authorization.document_cid, "QmAuthCID")
    self.assertEqual(restored.created_at, "2026-05-05T10:00:00Z")

  def test_partial_questionnaire(self):
    """User filled engagement context but not RoE or authorization."""
    q = KickoffQuestionnaire(
      engagement=EngagementContext(client_name="ACME"),
    )
    self.assertFalse(q.is_empty())
    d = q.to_dict()
    self.assertIsNone(d["roe"])
    self.assertIsNone(d["authorization"])

  def test_from_dict_returns_none_for_none(self):
    self.assertIsNone(KickoffQuestionnaire.from_dict(None))
    self.assertIsNone(KickoffQuestionnaire.from_dict({}))


class TestEnumExports(unittest.TestCase):
  """Verify the module exposes the enum constants for the form layer."""

  def test_data_classifications_exported(self):
    self.assertIn("PII", DATA_CLASSIFICATIONS)
    self.assertIn("PCI", DATA_CLASSIFICATIONS)
    self.assertIn("Public", DATA_CLASSIFICATIONS)

  def test_asset_exposures_exported(self):
    self.assertIn("external", ASSET_EXPOSURES)
    self.assertIn("internal", ASSET_EXPOSURES)
    self.assertIn("airgapped", ASSET_EXPOSURES)

  def test_strength_levels_exported(self):
    self.assertEqual(set(STRENGTH_OF_TEST), {"light", "standard", "aggressive"})

  def test_post_exploit_rules_exported(self):
    self.assertIn("va_only", POST_EXPLOIT_RULES)
    self.assertIn("pivot", POST_EXPLOIT_RULES)


if __name__ == "__main__":
  unittest.main()
