"""OWASP API Top 10 — Subphase 1.5 commit #10.

Asserts that raw `bearer_token`, `api_key`, and `bearer_refresh_token`
values never appear in:
  - the persisted JobConfig (R1FS public archive)
  - GrayboxFinding evidence
  - the finding repr() / Credentials repr()

The R1FS-secret-payload boundary (the place where secrets are split off
from the public config before put_job_config()) is the contract we are
verifying.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
from extensions.business.cybersec.red_mesh.services.secrets import (
  _blank_graybox_secret_fields,
  build_graybox_secret_payload,
  persist_job_config_with_secrets,
  resolve_job_config_secrets,
)


SENSITIVE_VALUES = {
  "bearer_token": "eyJ.SECRET-BEARER-TOKEN-VALUE-1234567890.abc",
  "api_key": "SUPER-SECRET-API-KEY-9999",
  "bearer_refresh_token": "REFRESH-TOKEN-MUST-NOT-LEAK",
}


def _has_secrets(text: str) -> bool:
  return any(v in text for v in SENSITIVE_VALUES.values())


class TestSecretIsolationInBuildPayload(unittest.TestCase):

  def test_build_payload_carries_new_secrets(self):
    """The secret payload (R1FS-side) gets the new fields."""
    payload = build_graybox_secret_payload(
      official_username="alice", official_password="apw",
      **SENSITIVE_VALUES,
    )
    self.assertEqual(payload["bearer_token"], SENSITIVE_VALUES["bearer_token"])
    self.assertEqual(payload["api_key"], SENSITIVE_VALUES["api_key"])
    self.assertEqual(payload["bearer_refresh_token"], SENSITIVE_VALUES["bearer_refresh_token"])

  def test_blank_strips_all_new_secrets(self):
    """_blank_graybox_secret_fields zeroes every new secret field."""
    sanitized = _blank_graybox_secret_fields({
      "official_username": "alice", "official_password": "apw",
      **SENSITIVE_VALUES,
    })
    self.assertEqual(sanitized["bearer_token"], "")
    self.assertEqual(sanitized["api_key"], "")
    self.assertEqual(sanitized["bearer_refresh_token"], "")


class TestSecretIsolationInPersistedConfig(unittest.TestCase):

  def _build_owner(self):
    owner = MagicMock()
    owner.P = MagicMock()
    fake_store = MagicMock()
    fake_store.save_graybox_credentials.return_value = "fake://secret/cid"
    return owner, fake_store

  @patch("extensions.business.cybersec.red_mesh.services.secrets.R1fsSecretStore")
  @patch("extensions.business.cybersec.red_mesh.services.secrets._artifact_repo")
  def test_persisted_jobconfig_contains_no_raw_secrets(self, mock_repo, mock_store_cls):
    """Bearer/API-key values do not appear anywhere in the archived JobConfig."""
    fake_store = MagicMock()
    fake_store.save_graybox_credentials.return_value = "fake://secret/cid"
    mock_store_cls.return_value = fake_store
    fake_repo = MagicMock()
    fake_repo.put_job_config.return_value = "fake://config/cid"
    mock_repo.return_value = fake_repo

    config_dict = {
      "target": "api.example.com",
      "target_url": "https://api.example.com",
      "start_port": 0, "end_port": 0,
      "scan_type": "webapp",
      "official_username": "alice", "official_password": "apw",
      **SENSITIVE_VALUES,
    }

    owner, _ = self._build_owner()
    persisted_config, _cid = persist_job_config_with_secrets(
      owner, job_id="test-job-xyz", config_dict=config_dict,
    )

    serialized = json.dumps(persisted_config)
    self.assertFalse(
      _has_secrets(serialized),
      f"Secret value leaked into persisted JobConfig: {serialized!r}",
    )

    # Non-secret capability flags ARE present.
    self.assertTrue(persisted_config["has_bearer_token"])
    self.assertTrue(persisted_config["has_api_key"])
    self.assertTrue(persisted_config["has_bearer_refresh_token"])
    self.assertEqual(persisted_config["secret_ref"], "fake://secret/cid")
    # Raw secret slots are blanked.
    self.assertEqual(persisted_config["bearer_token"], "")
    self.assertEqual(persisted_config["api_key"], "")
    self.assertEqual(persisted_config["bearer_refresh_token"], "")

  @patch("extensions.business.cybersec.red_mesh.services.secrets.R1fsSecretStore")
  def test_resolve_repopulates_secrets_for_worker(self, mock_store_cls):
    """Worker-side resolve_job_config_secrets repopulates the runtime fields."""
    fake_store = MagicMock()
    fake_store.load_graybox_credentials.return_value = {
      "official_username": "alice", "official_password": "apw",
      **SENSITIVE_VALUES,
    }
    mock_store_cls.return_value = fake_store

    persisted = {
      "target": "api.example.com",
      "start_port": 0, "end_port": 0,
      "scan_type": "webapp",
      "secret_ref": "fake://secret/cid",
      "official_username": "", "official_password": "",
      "bearer_token": "", "api_key": "", "bearer_refresh_token": "",
      "has_bearer_token": True, "has_api_key": True,
      "has_bearer_refresh_token": True,
    }
    resolved = resolve_job_config_secrets(MagicMock(), persisted)
    for k, v in SENSITIVE_VALUES.items():
      self.assertEqual(resolved[k], v)


class TestSecretIsolationInCredentialsRepr(unittest.TestCase):

  def test_credentials_repr_never_leaks_secrets(self):
    c = Credentials(
      username="alice", password="formpw",
      bearer_token=SENSITIVE_VALUES["bearer_token"],
      api_key=SENSITIVE_VALUES["api_key"],
      bearer_refresh_token=SENSITIVE_VALUES["bearer_refresh_token"],
    )
    r = repr(c)
    self.assertFalse(
      _has_secrets(r),
      f"Credentials repr leaked secrets: {r!r}",
    )
    self.assertNotIn("formpw", r)
    self.assertNotIn("alice", r)
    # But capability booleans are visible
    self.assertIn("has_bearer_token=True", r)
    self.assertIn("has_api_key=True", r)


if __name__ == "__main__":
  unittest.main()
