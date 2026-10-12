"""Phase 3 PR-3.3 — JobConfig engagement-context wiring tests.

Verifies:
  - JobConfig accepts the new typed `engagement` / `authorization` dict fields.
  - get_engagement() / get_authorization() resolve the typed accessors correctly.
  - RM-108 phase 5: the legacy `engagement_metadata` / `authorization_ref`
    fields are no longer read by the accessors.
  - Round-trip through to_dict / from_dict preserves the typed shape.
  - get_kickoff_questionnaire() bundles engagement and authorization.
"""
from __future__ import annotations

import unittest

from extensions.business.cybersec.red_mesh.models.archive import JobConfig
from extensions.business.cybersec.red_mesh.models.engagement import (
  AuthorizationRef,
  Contact,
  EngagementContext,
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
    self.assertIsNone(cfg.authorization)
    self.assertIsNone(cfg.get_engagement())
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

  def test_engagement_fields_round_trip_and_stay_absent_on_old_jobs(self):
    fields = {"engagement_id": "en_00000000-0000-4000-8000-000000000003", "engagement_hash": "a" * 64,
              "contract_sha256": "c" * 64}
    restored = JobConfig.from_dict(JobConfig(**_base_jobconfig_kwargs(), **fields).to_dict())
    self.assertEqual({key: getattr(restored, key) for key in fields}, fields)
    self.assertFalse(set(fields) & set(JobConfig(**_base_jobconfig_kwargs()).to_dict()))

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
    auth = AuthorizationRef(document_cid="QmAuthCID")
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement=eng.to_dict(),
      authorization=auth.to_dict(),
    )
    payload = cfg.to_dict()
    restored = JobConfig.from_dict(payload)
    self.assertEqual(restored.get_engagement().client_name, "ACME")
    self.assertEqual(restored.get_engagement().asset_exposure, "dmz")
    self.assertEqual(restored.get_authorization().document_cid, "QmAuthCID")


class TestRemovedFieldsStillLoad(unittest.TestCase):
  """RM-128: an archive written with the dropped `roe` / `authorized_ports` / `authorization_update`
  keys still loads; `from_dict` reads named keys, so the stray keys are ignored."""

  def test_an_old_archive_with_roe_and_ports_loads(self):
    payload = {**JobConfig(**_base_jobconfig_kwargs()).to_dict(),
               "roe": {"authenticated_action": True, "stateful_probes_allowed": True,
                       "ics_safe_mode_required": False},
               "authorized_ports": "1-1024",
               "authorization_update": {"reference": "AUTH-1"}}
    restored = JobConfig.from_dict(payload)
    self.assertFalse(hasattr(restored, "roe"))
    self.assertNotIn("roe", restored.to_dict())
    self.assertNotIn("authorized_ports", restored.to_dict())
    self.assertNotIn("authorization_update", restored.to_dict())
    self.assertIsNone(restored.get_kickoff_questionnaire())


class TestEngagementLegacyFieldsAreIgnored(unittest.TestCase):
  """RM-108 phase 5: the pre-PR-3.3 free-form fallback fields are still stored (backward-compat
  with old field names) but no longer read. Storage holds no archive that needs them."""

  def test_legacy_engagement_metadata_dict_is_not_resolved(self):
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement_metadata={"client_name": "Legacy Co.",
                           "primary_objective": "old format"},
    )
    self.assertIsNone(cfg.get_engagement())

  def test_legacy_authorization_ref_str_is_not_resolved(self):
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      authorization_ref="QmLegacyAuthCID",
    )
    self.assertIsNone(cfg.get_authorization())

  def test_typed_field_is_the_only_source(self):
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement={"client_name": "Typed Co."},
      engagement_metadata={"client_name": "Legacy Co."},
    )
    self.assertEqual(cfg.get_engagement().client_name, "Typed Co.")


class TestKickoffQuestionnaireBundle(unittest.TestCase):

  def test_questionnaire_bundles_engagement_and_authorization(self):
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement=EngagementContext(client_name="ACME").to_dict(),
      authorization=AuthorizationRef(document_cid="QmAuthCID").to_dict(),
    )
    q = cfg.get_kickoff_questionnaire()
    self.assertIsNotNone(q)
    self.assertEqual(q.engagement.client_name, "ACME")
    self.assertEqual(q.authorization.document_cid, "QmAuthCID")

  def test_returns_none_when_all_empty(self):
    """No engagement context at all means no kickoff questionnaire to
    persist (avoids cluttering R1FS with empty records)."""
    cfg = JobConfig(**_base_jobconfig_kwargs())
    self.assertIsNone(cfg.get_kickoff_questionnaire())

  def test_returns_none_when_all_default_objects(self):
    """Default-constructed engagement/auth are still 'empty' for
    persistence purposes."""
    cfg = JobConfig(
      **_base_jobconfig_kwargs(),
      engagement=EngagementContext().to_dict(),
      authorization=AuthorizationRef().to_dict(),
    )
    self.assertIsNone(cfg.get_kickoff_questionnaire())

  def test_returns_questionnaire_when_only_authorization_set(self):
    """If only the authorization document is uploaded (engagement skipped),
    the questionnaire still wraps it for persistence."""
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
