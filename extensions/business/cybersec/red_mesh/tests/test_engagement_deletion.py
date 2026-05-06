"""Phase 3 PR-3.4 — engagement-deletion service tests.

Covers:
  - Typed engagement fields (PR-3.3) cleared.
  - Legacy free-form fields cleared.
  - Authorization documents deleted from R1FS (when delete_documents=True).
  - Documents preserved when delete_documents=False (legal-hold).
  - Idempotency: deleting twice produces fields_cleared=0 the second time.
  - Audit entry appended to timeline with no PII echoed back.
  - Error paths: missing job_id, missing config_cid, R1FS failures.
  - Technical scan record (target/ports/findings) preserved.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.engagement_deletion import (
  DeleteEngagementError,
  DeleteEngagementResult,
  delete_engagement_data,
)

from .conftest import mock_plugin_modules


# ---------------------------------------------------------------------
# Mock R1FS repo
# ---------------------------------------------------------------------


class _MockArtifactRepo:
  """In-memory R1FS substitute for engagement-deletion tests."""

  def __init__(self, configs: dict | None = None):
    self.configs: dict[str, dict] = dict(configs or {})
    self.deleted: list[str] = []
    self.delete_failures: set = set()  # CIDs that should fail to delete
    self._next_cid = 100

  def get_job_config(self, job_specs):
    cid = job_specs.get("job_config_cid", "")
    return self.configs.get(cid)

  def put_job_config(self, config: dict, *, show_logs=False):
    self._next_cid += 1
    new_cid = f"QmSanitized{self._next_cid}"
    self.configs[new_cid] = dict(config)
    return new_cid

  def delete(self, cid: str, *, show_logs=False, raise_on_error=False):
    if cid in self.delete_failures:
      if raise_on_error:
        raise RuntimeError(f"R1FS delete failed for {cid}")
      return False
    self.deleted.append(cid)
    return True


def _build_specs(*, config_cid="QmInitial1", config: dict | None = None):
  """Construct a job-specs dict + a repo with the matching config."""
  default_config = {
    "target": "10.0.0.1",
    "start_port": 1, "end_port": 1024,
    "engagement": {
      "client_name": "ACME Corp",
      "data_classification": "PCI",
      "asset_exposure": "external",
      "point_of_contact": {"name": "Jane", "email": "jane@acme.example"},
    },
    "roe": {
      "strength_of_test": "aggressive",
      "dos_allowed": True,
    },
    "authorization": {
      "document_cid": "QmAuthDoc1",
      "document_thumbnail_cid": "QmAuthThumb1",
      "authorized_signer_name": "John CISO",
      "third_party_auth_cids": ["QmCloudAuth1", "QmMsspAuth1"],
    },
    "engagement_metadata": {"legacy_field": "legacy_value"},
    "authorization_ref": "QmLegacyAuthRef",
    "scope_id": "scope-123",
    "target_allowlist": ["10.0.0.1"],
  }
  cfg = config if config is not None else default_config
  specs = {
    "job_id": "abc123",
    "job_config_cid": config_cid,
    "timeline": [
      {"type": "created", "label": "Job created", "actor": "user1"},
    ],
  }
  repo = _MockArtifactRepo(configs={config_cid: cfg})
  return specs, repo


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


class TestHappyPath(unittest.TestCase):

  def test_typed_engagement_fields_cleared(self):
    specs, repo = _build_specs()
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
      requested_by="alice@redmesh",
    )
    self.assertTrue(result.ok)
    sanitized = repo.configs[result.new_job_config_cid]
    self.assertIsNone(sanitized["engagement"])
    self.assertIsNone(sanitized["roe"])
    self.assertIsNone(sanitized["authorization"])

  def test_legacy_engagement_fields_cleared(self):
    specs, repo = _build_specs()
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    sanitized = repo.configs[result.new_job_config_cid]
    self.assertIsNone(sanitized["engagement_metadata"])
    self.assertEqual(sanitized["authorization_ref"], "")
    self.assertEqual(sanitized["scope_id"], "")
    self.assertIsNone(sanitized["target_allowlist"])

  def test_technical_scan_record_preserved(self):
    """Target / ports / mode must survive the deletion."""
    specs, repo = _build_specs()
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    sanitized = repo.configs[result.new_job_config_cid]
    self.assertEqual(sanitized["target"], "10.0.0.1")
    self.assertEqual(sanitized["start_port"], 1)
    self.assertEqual(sanitized["end_port"], 1024)

  def test_authorization_documents_deleted(self):
    specs, repo = _build_specs()
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    self.assertEqual(result.documents_deleted, 5)
    self.assertEqual(result.documents_failed, 0)
    # All five CIDs deleted: doc, thumb, two third-party, one legacy
    expected = {"QmAuthDoc1", "QmAuthThumb1", "QmCloudAuth1",
                "QmMsspAuth1", "QmLegacyAuthRef"}
    self.assertEqual(set(repo.deleted), expected)

  def test_job_specs_updated_to_new_cid(self):
    specs, repo = _build_specs()
    old_cid = specs["job_config_cid"]
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    self.assertNotEqual(specs["job_config_cid"], old_cid)
    self.assertEqual(specs["job_config_cid"], result.new_job_config_cid)


# ---------------------------------------------------------------------
# Document preservation (legal-hold)
# ---------------------------------------------------------------------


class TestDocumentPreservation(unittest.TestCase):

  def test_documents_preserved_when_flag_off(self):
    specs, repo = _build_specs()
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
      delete_documents=False,
    )
    self.assertEqual(result.documents_deleted, 0)
    self.assertEqual(repo.deleted, [])
    # Engagement fields still cleared even when documents preserved
    sanitized = repo.configs[result.new_job_config_cid]
    self.assertIsNone(sanitized["authorization"])

  def test_partial_document_delete_failure_counted(self):
    specs, repo = _build_specs()
    repo.delete_failures = {"QmAuthDoc1", "QmCloudAuth1"}
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    self.assertFalse(result.ok)
    self.assertEqual(result.documents_failed, 2)
    self.assertEqual(result.documents_deleted, 3)


# ---------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------


class TestIdempotency(unittest.TestCase):

  def test_second_delete_clears_zero_fields(self):
    specs, repo = _build_specs()
    first = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    self.assertGreater(first.fields_cleared, 0)
    second = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    self.assertEqual(second.fields_cleared, 0)
    self.assertEqual(second.documents_deleted, 0)
    self.assertTrue(second.ok)


# ---------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------


class TestAuditEntry(unittest.TestCase):

  def test_audit_entry_appended_to_timeline(self):
    specs, repo = _build_specs()
    delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
      requested_by="alice@redmesh",
    )
    # Timeline goes from 1 entry to 2
    self.assertEqual(len(specs["timeline"]), 2)
    audit = specs["timeline"][-1]
    self.assertEqual(audit["type"], "engagement_redacted")
    self.assertEqual(audit["actor"], "alice@redmesh")
    self.assertEqual(audit["actor_type"], "user")
    self.assertIn("GDPR", audit["meta"]["reason"])

  def test_audit_does_not_echo_pii(self):
    """Verify the audit payload doesn't contain client_name, contact
    email, etc. — only counts."""
    specs, repo = _build_specs()
    delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
      requested_by="alice@redmesh",
    )
    audit = specs["timeline"][-1]
    audit_str = repr(audit)
    self.assertNotIn("ACME", audit_str)
    self.assertNotIn("jane@acme", audit_str)
    self.assertNotIn("PCI", audit_str)
    self.assertNotIn("John CISO", audit_str)

  def test_system_actor_when_no_requested_by(self):
    specs, repo = _build_specs()
    delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    audit = specs["timeline"][-1]
    self.assertEqual(audit["actor"], "system")
    self.assertEqual(audit["actor_type"], "system")


# ---------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------


class TestErrorPaths(unittest.TestCase):

  def test_missing_job_id_raises(self):
    specs, repo = _build_specs()
    with self.assertRaises(DeleteEngagementError) as ctx:
      delete_engagement_data(job_id="", job_specs=specs, artifact_repo=repo)
    self.assertEqual(ctx.exception.code, "job_not_found")

  def test_invalid_job_specs_raises(self):
    repo = _MockArtifactRepo()
    with self.assertRaises(DeleteEngagementError) as ctx:
      delete_engagement_data(
        job_id="abc", job_specs="not-a-dict", artifact_repo=repo,  # type: ignore
      )
    self.assertEqual(ctx.exception.code, "job_not_found")

  def test_missing_config_cid_raises(self):
    specs = {"job_id": "abc", "job_config_cid": ""}
    repo = _MockArtifactRepo()
    with self.assertRaises(DeleteEngagementError) as ctx:
      delete_engagement_data(job_id="abc", job_specs=specs, artifact_repo=repo)
    self.assertEqual(ctx.exception.code, "config_not_found")

  def test_config_load_failure_raises(self):
    specs = {"job_id": "abc", "job_config_cid": "QmMissing"}
    repo = _MockArtifactRepo()  # no configs
    with self.assertRaises(DeleteEngagementError) as ctx:
      delete_engagement_data(job_id="abc", job_specs=specs, artifact_repo=repo)
    self.assertEqual(ctx.exception.code, "config_not_found")

  def test_storage_failure_raises(self):
    specs, repo = _build_specs()
    def boom(*args, **kwargs):
      raise RuntimeError("R1FS down")
    repo.put_job_config = boom
    with self.assertRaises(DeleteEngagementError) as ctx:
      delete_engagement_data(job_id="abc123", job_specs=specs, artifact_repo=repo)
    self.assertEqual(ctx.exception.code, "storage_failed")

  def test_storage_returning_empty_cid_raises(self):
    specs, repo = _build_specs()
    repo.put_job_config = lambda config, **kwargs: ""
    with self.assertRaises(DeleteEngagementError) as ctx:
      delete_engagement_data(job_id="abc123", job_specs=specs, artifact_repo=repo)
    self.assertEqual(ctx.exception.code, "storage_failed")


# ---------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------


class TestEdgeCases(unittest.TestCase):

  def test_empty_engagement_still_succeeds(self):
    """Job with no engagement context at all: deletion is a no-op
    that still rewrites a clean JobConfig and returns ok=True."""
    specs, repo = _build_specs(config={
      "target": "10.0.0.1",
      "start_port": 1, "end_port": 1024,
    })
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    self.assertTrue(result.ok)
    self.assertEqual(result.fields_cleared, 0)
    self.assertEqual(result.documents_deleted, 0)

  def test_only_legacy_authorization_ref_set(self):
    """Pre-Phase-3 archive: only authorization_ref string set."""
    specs, repo = _build_specs(config={
      "target": "10.0.0.1",
      "start_port": 1, "end_port": 1024,
      "authorization_ref": "QmLegacyOnly",
    })
    result = delete_engagement_data(
      job_id="abc123", job_specs=specs, artifact_repo=repo,
    )
    self.assertEqual(result.documents_deleted, 1)
    self.assertEqual(repo.deleted, ["QmLegacyOnly"])
    self.assertEqual(result.fields_cleared, 1)


class _EndpointOwner:
  """Small JobStateRepository host for delete_job_engagement endpoint tests."""

  cfg_instance_id = "test-instance"

  def __init__(self, jobs: dict | None = None):
    self.jobs = dict(jobs or {})
    self.messages: list[str] = []
    self.fail_put = False
    self.chainstore_hset = MagicMock(side_effect=self._chainstore_hset)

  def chainstore_hget(self, *, hkey, key):
    return self.jobs.get(key)

  def _chainstore_hset(self, *, hkey, key, value):
    if self.fail_put:
      raise RuntimeError("CStore write failed")
    self.jobs[key] = value

  def P(self, message, **kwargs):
    self.messages.append(message)


class TestDeleteJobEngagementEndpoint(unittest.TestCase):

  def _plugin_class(self):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_endpoint_updates_cstore_and_deletes_documents_after_state_persist(self):
    Plugin = self._plugin_class()
    specs, repo = _build_specs()
    owner = _EndpointOwner(jobs={"abc123": specs})

    with patch.object(Plugin, "_get_artifact_repository", return_value=repo):
      result = Plugin.delete_job_engagement(
        owner, job_id="abc123", delete_documents=True, requested_by="alice",
      )

    self.assertTrue(result["ok"])
    self.assertEqual(result["documents_deleted"], 5)
    self.assertEqual(result["documents_failed"], 0)
    self.assertEqual(owner.jobs["abc123"]["job_config_cid"], result["new_job_config_cid"])
    audit = owner.jobs["abc123"]["timeline"][-1]
    self.assertEqual(audit["meta"]["documents_deleted"], 5)
    self.assertEqual(audit["meta"]["documents_failed"], 0)
    self.assertEqual(set(repo.deleted), {
      "QmAuthDoc1", "QmAuthThumb1", "QmCloudAuth1",
      "QmMsspAuth1", "QmLegacyAuthRef",
    })

  def test_endpoint_does_not_delete_documents_when_state_persist_fails(self):
    Plugin = self._plugin_class()
    specs, repo = _build_specs()
    owner = _EndpointOwner(jobs={"abc123": specs})
    owner.fail_put = True

    with patch.object(Plugin, "_get_artifact_repository", return_value=repo):
      result = Plugin.delete_job_engagement(
        owner, job_id="abc123", delete_documents=True, requested_by="alice",
      )

    self.assertEqual(result["error"], "state_persist_failed")
    self.assertEqual(repo.deleted, [])

  def test_endpoint_reports_document_delete_failures(self):
    Plugin = self._plugin_class()
    specs, repo = _build_specs()
    repo.delete_failures = {"QmAuthDoc1"}
    owner = _EndpointOwner(jobs={"abc123": specs})

    with patch.object(Plugin, "_get_artifact_repository", return_value=repo):
      result = Plugin.delete_job_engagement(
        owner, job_id="abc123", delete_documents=True, requested_by="alice",
      )

    self.assertFalse(result["ok"])
    self.assertEqual(result["documents_deleted"], 4)
    self.assertEqual(result["documents_failed"], 1)
    audit = owner.jobs["abc123"]["timeline"][-1]
    self.assertEqual(audit["meta"]["documents_failed"], 1)

  def test_endpoint_explicitly_rejects_finalized_job_archives(self):
    Plugin = self._plugin_class()
    repo = _MockArtifactRepo()
    owner = _EndpointOwner(jobs={
      "fin123": {"job_id": "fin123", "job_cid": "QmArchive"},
    })

    with patch.object(Plugin, "_get_artifact_repository", return_value=repo):
      result = Plugin.delete_job_engagement(owner, job_id="fin123")

    self.assertEqual(result["error"], "unsupported_finalized_job")
    self.assertEqual(repo.deleted, [])


if __name__ == "__main__":
  unittest.main()
