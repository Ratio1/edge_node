"""Phase 3 PR-3.3 — JobConfig engagement-context wiring tests.

Verifies:
  - JobConfig accepts the new typed `engagement` / `roe` /
    `authorization` dict fields.
  - get_engagement() / get_roe() / get_authorization() resolve the
    typed accessors correctly.
  - Backward-compat: when only the legacy `engagement_metadata` /
    `authorization_ref` fields are populated, the accessors still
    return useful values.
  - Round-trip through to_dict / from_dict preserves the typed shape.
  - get_kickoff_questionnaire() bundles the three sub-models.
"""
from __future__ import annotations

import unittest

from extensions.business.cybersec.red_mesh.models.archive import JobConfig
from extensions.business.cybersec.red_mesh.models.engagement import (
  AuthorizationRef,
  Contact,
  EngagementContext,
  RulesOfEngagement,
)


def _base_jobconfig_kwargs() -> dict:
  """Minimum required JobConfig fields for tests."""
  return dict(
    target="10.0.0.1",
    start_port=1, end_port=1024,
    exceptions=[],
    distribution_strategy="SLICE",
    port_order="SEQUENTIAL",
    nr_local_workers=2,
    enabled_features=[],
    excluded_features=[],
    run_mode="SINGLEPASS",
  )


class TestEngagementFieldsDefault(unittest.TestCase):

  def test_no_engagement_data_means_none(self):
    cfg = JobConfig(**_base_jobconfig_kwargs())
    self.assertIsNone(cfg.engagement)
    self.assertIsNone(cfg.roe)
    self.assertIsNone(cfg.authorization)
    self.assertIsNone(cfg.get_engagement())
    self.assertIsNone(cfg.get_roe())
    self.assertIsNone(cfg.get_authorization())
    self.assertIsNone(cfg.get_kickoff_questionnaire())


class TestEngagementFieldsTyped(unittest.TestCase):

  def test_with_typed_engagement_dict(self):
    eng = EngagementContext(
      client_name="ACME",
      data_classification="PCI",
      asset_exposure="external",
      point_of_contact=Contact(name="Jane", email="jane@acme.example"),
    )
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement=eng.to_dict(),
    )
    resolved = cfg.get_engagement()
    self.assertIsNotNone(resolved)
    self.assertEqual(resolved.client_name, "ACME")
    self.assertEqual(resolved.data_classification, "PCI")
    self.assertEqual(resolved.point_of_contact.email, "jane@acme.example")

  def test_with_typed_roe_dict(self):
    roe = RulesOfEngagement(
      strength_of_test="aggressive", dos_allowed=True,
      post_exploit_rules="pivot",
      blackout_windows=[("2026-05-04T22:00:00Z", "2026-05-05T06:00:00Z")],
    )
    cfg = JobConfig(**_base_jobconfig_kwargs(), roe=roe.to_dict())
    resolved = cfg.get_roe()
    self.assertEqual(resolved.strength_of_test, "aggressive")
    self.assertTrue(resolved.dos_allowed)
    self.assertEqual(resolved.post_exploit_rules, "pivot")
    self.assertEqual(len(resolved.blackout_windows), 1)

  def test_with_typed_authorization_dict(self):
    auth = AuthorizationRef(
      document_cid="QmAuthCID",
      authorized_signer_name="John CISO",
      authorized_signer_role="CISO",
    )
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      authorization=auth.to_dict(),
    )
    resolved = cfg.get_authorization()
    self.assertEqual(resolved.document_cid, "QmAuthCID")
    self.assertEqual(resolved.authorized_signer_name, "John CISO")

  def test_round_trip_through_to_dict_from_dict(self):
    eng = EngagementContext(client_name="ACME", asset_exposure="dmz")
    roe = RulesOfEngagement(dos_allowed=True)
    auth = AuthorizationRef(document_cid="QmAuthCID")
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement=eng.to_dict(),
      roe=roe.to_dict(),
      authorization=auth.to_dict(),
    )
    payload = cfg.to_dict()
    restored = JobConfig.from_dict(payload)
    self.assertEqual(restored.get_engagement().client_name, "ACME")
    self.assertEqual(restored.get_engagement().asset_exposure, "dmz")
    self.assertTrue(restored.get_roe().dos_allowed)
    self.assertEqual(restored.get_authorization().document_cid, "QmAuthCID")


class TestEngagementBackwardCompat(unittest.TestCase):
  """Pre-Phase-3 archives stored engagement-adjacent data in legacy
  fields. The typed accessors fall back gracefully so existing
  archives still surface usable engagement context."""

  def test_legacy_engagement_metadata_dict_resolves(self):
    """An archive with only `engagement_metadata` (free-form dict) and
    no typed `engagement` field should still produce an
    EngagementContext via get_engagement()."""
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement_metadata={"client_name": "Legacy Co.",
                           "primary_objective": "old format"},
    )
    resolved = cfg.get_engagement()
    self.assertIsNotNone(resolved)
    self.assertEqual(resolved.client_name, "Legacy Co.")
    self.assertEqual(resolved.primary_objective, "old format")

  def test_legacy_authorization_ref_str_resolves(self):
    """An archive with only `authorization_ref` (just a CID string)
    resolves to an AuthorizationRef with document_cid set and
    everything else empty."""
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      authorization_ref="QmLegacyAuthCID",
    )
    resolved = cfg.get_authorization()
    self.assertIsNotNone(resolved)
    self.assertEqual(resolved.document_cid, "QmLegacyAuthCID")
    self.assertEqual(resolved.authorized_signer_name, "")

  def test_typed_field_takes_precedence_over_legacy(self):
    """When both shapes are present, the typed field wins."""
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement={"client_name": "Typed Co."},
      engagement_metadata={"client_name": "Legacy Co."},
    )
    self.assertEqual(cfg.get_engagement().client_name, "Typed Co.")


class TestKickoffQuestionnaireBundle(unittest.TestCase):

  def test_questionnaire_bundles_all_three(self):
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement=EngagementContext(client_name="ACME").to_dict(),
      roe=RulesOfEngagement(dos_allowed=True).to_dict(),
      authorization=AuthorizationRef(document_cid="QmAuthCID").to_dict(),
    )
    q = cfg.get_kickoff_questionnaire()
    self.assertIsNotNone(q)
    self.assertEqual(q.engagement.client_name, "ACME")
    self.assertTrue(q.roe.dos_allowed)
    self.assertEqual(q.authorization.document_cid, "QmAuthCID")

  def test_returns_none_when_all_empty(self):
    """No engagement context at all means no kickoff questionnaire to
    persist (avoids cluttering R1FS with empty records)."""
    cfg = JobConfig(**_base_jobconfig_kwargs())
    self.assertIsNone(cfg.get_kickoff_questionnaire())

  def test_returns_none_when_all_default_objects(self):
    """Default-constructed engagement/roe/auth are still 'empty' for
    persistence purposes."""
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement=EngagementContext().to_dict(),
      roe=RulesOfEngagement().to_dict(),
      authorization=AuthorizationRef().to_dict(),
    )
    self.assertIsNone(cfg.get_kickoff_questionnaire())

  def test_returns_questionnaire_when_only_authorization_set(self):
    """If only the authorization document is uploaded (engagement /
    RoE skipped), the questionnaire still wraps it for persistence."""
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      authorization=AuthorizationRef(document_cid="QmAuthCID").to_dict(),
    )
    q = cfg.get_kickoff_questionnaire()
    self.assertIsNotNone(q)
    self.assertEqual(q.authorization.document_cid, "QmAuthCID")
    self.assertTrue(q.engagement is None or q.engagement.is_empty())


if __name__ == "__main__":
  unittest.main()
