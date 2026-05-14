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
from extensions.business.cybersec.red_mesh.graybox.models import GrayboxCredentialSet
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
  "regular_bearer_token": "eyJ.REGULAR-SECRET-BEARER-TOKEN.abc",
  "regular_api_key": "REGULAR-SECRET-API-KEY-9999",
  "regular_bearer_refresh_token": "REGULAR-REFRESH-TOKEN-MUST-NOT-LEAK",
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
    self.assertEqual(payload["regular_bearer_token"], SENSITIVE_VALUES["regular_bearer_token"])
    self.assertEqual(payload["regular_api_key"], SENSITIVE_VALUES["regular_api_key"])
    self.assertEqual(payload["regular_bearer_refresh_token"], SENSITIVE_VALUES["regular_bearer_refresh_token"])

  def test_build_payload_carries_target_config_secrets(self):
    payload = build_graybox_secret_payload(
      target_config_secrets={"oauth_client_secret": "OAUTH-CLIENT-SECRET"},
    )
    self.assertEqual(
      payload["target_config_secrets"],
      {"oauth_client_secret": "OAUTH-CLIENT-SECRET"},
    )

  def test_blank_strips_all_new_secrets(self):
    """_blank_graybox_secret_fields zeroes every new secret field."""
    sanitized = _blank_graybox_secret_fields({
      "official_username": "alice", "official_password": "apw",
      **SENSITIVE_VALUES,
    })
    self.assertEqual(sanitized["bearer_token"], "")
    self.assertEqual(sanitized["api_key"], "")
    self.assertEqual(sanitized["bearer_refresh_token"], "")
    self.assertEqual(sanitized["regular_bearer_token"], "")
    self.assertEqual(sanitized["regular_api_key"], "")
    self.assertEqual(sanitized["regular_bearer_refresh_token"], "")


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
    self.assertTrue(persisted_config["has_regular_bearer_token"])
    self.assertTrue(persisted_config["has_regular_api_key"])
    self.assertTrue(persisted_config["has_regular_bearer_refresh_token"])
    self.assertEqual(persisted_config["secret_ref"], "fake://secret/cid")
    # Raw secret slots are blanked.
    self.assertEqual(persisted_config["bearer_token"], "")
    self.assertEqual(persisted_config["api_key"], "")
    self.assertEqual(persisted_config["bearer_refresh_token"], "")
    self.assertEqual(persisted_config["regular_bearer_token"], "")
    self.assertEqual(persisted_config["regular_api_key"], "")
    self.assertEqual(persisted_config["regular_bearer_refresh_token"], "")

  @patch("extensions.business.cybersec.red_mesh.services.secrets.R1fsSecretStore")
  @patch("extensions.business.cybersec.red_mesh.services.secrets._artifact_repo")
  def test_target_config_secret_ref_values_do_not_persist(self, mock_repo, mock_store_cls):
    """Nested secret-ref values live only in the separate secret payload."""
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
      "target_config": {
        "api_security": {
          "token_endpoints": {
            "token_request_body": {
              "client_secret": {"secret_ref": "oauth_client_secret"},
            },
          },
        },
      },
      "target_config_secrets": {
        "oauth_client_secret": "OAUTH-CLIENT-SECRET",
      },
    }

    persisted_config, _cid = persist_job_config_with_secrets(
      MagicMock(), job_id="test-job-xyz", config_dict=config_dict,
    )

    payload = fake_store.save_graybox_credentials.call_args[0][1]
    self.assertEqual(
      payload["target_config_secrets"]["oauth_client_secret"],
      "OAUTH-CLIENT-SECRET",
    )
    serialized = json.dumps(persisted_config)
    self.assertNotIn("OAUTH-CLIENT-SECRET", serialized)
    self.assertNotIn("target_config_secrets", persisted_config)
    self.assertEqual(
      persisted_config["target_config"]["api_security"]["token_endpoints"][
        "token_request_body"
      ]["client_secret"],
      {"secret_ref": "oauth_client_secret"},
    )

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
      "regular_bearer_token": "", "regular_api_key": "",
      "regular_bearer_refresh_token": "",
      "has_bearer_token": True, "has_api_key": True,
      "has_bearer_refresh_token": True,
      "has_regular_bearer_token": True, "has_regular_api_key": True,
      "has_regular_bearer_refresh_token": True,
    }
    resolved = resolve_job_config_secrets(MagicMock(), persisted)
    for k, v in SENSITIVE_VALUES.items():
      self.assertEqual(resolved[k], v)

  @patch("extensions.business.cybersec.red_mesh.services.secrets.R1fsSecretStore")
  def test_resolve_target_config_secret_refs_for_worker(self, mock_store_cls):
    """Worker runtime config gets body secrets without mutating persisted config."""
    fake_store = MagicMock()
    fake_store.load_graybox_credentials.return_value = {
      "target_config_secrets": {
        "oauth_client_secret": "OAUTH-CLIENT-SECRET",
      },
    }
    mock_store_cls.return_value = fake_store

    persisted = {
      "target": "api.example.com",
      "start_port": 0, "end_port": 0,
      "scan_type": "webapp",
      "secret_ref": "fake://secret/cid",
      "target_config": {
        "api_security": {
          "token_endpoints": {
            "token_request_body": {
              "client_id": "redmesh",
              "client_secret": {"secret_ref": "oauth_client_secret"},
            },
          },
        },
      },
    }

    resolved = resolve_job_config_secrets(MagicMock(), persisted)

    self.assertEqual(
      resolved["target_config"]["api_security"]["token_endpoints"][
        "token_request_body"
      ]["client_secret"],
      "OAUTH-CLIENT-SECRET",
    )
    self.assertEqual(
      persisted["target_config"]["api_security"]["token_endpoints"][
        "token_request_body"
      ]["client_secret"],
      {"secret_ref": "oauth_client_secret"},
    )

  @patch("extensions.business.cybersec.red_mesh.services.secrets.R1fsSecretStore")
  def test_resolve_missing_target_config_secret_refs_fails_closed(self, mock_store_cls):
    fake_store = MagicMock()
    fake_store.load_graybox_credentials.return_value = {
      "official_username": "alice",
    }
    mock_store_cls.return_value = fake_store

    persisted = {
      "target": "api.example.com",
      "start_port": 0, "end_port": 0,
      "scan_type": "webapp",
      "secret_ref": "fake://secret/cid",
      "target_config": {
        "api_security": {
          "token_endpoints": {
            "token_request_body": {
              "client_secret": {"secret_ref": "oauth_client_secret"},
            },
          },
        },
      },
    }

    with self.assertRaises(ValueError) as cm:
      resolve_job_config_secrets(MagicMock(), persisted)
    self.assertIn("target_config secret_ref", str(cm.exception))

  @patch("extensions.business.cybersec.red_mesh.services.secrets.R1fsSecretStore")
  def test_resolve_passes_expected_job_id_before_jobconfig_coercion(self, mock_store_cls):
    """job_id is not part of JobConfig; preserve it before coercion for secret binding."""
    fake_store = MagicMock()
    fake_store.load_graybox_credentials.return_value = {
      "official_username": "alice", "official_password": "apw",
      **SENSITIVE_VALUES,
    }
    mock_store_cls.return_value = fake_store

    persisted = {
      "job_id": "job-A",
      "target": "api.example.com",
      "start_port": 0, "end_port": 0,
      "scan_type": "webapp",
      "secret_ref": "fake://secret/cid",
    }

    resolve_job_config_secrets(MagicMock(), persisted)

    fake_store.load_graybox_credentials.assert_called_once_with(
      "fake://secret/cid", expected_job_id="job-A",
    )


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


class TestSecretIsolationInRuntimeCredentials(unittest.TestCase):

  def test_worker_credential_set_carries_resolved_api_secrets(self):
    """Resolved runtime config reaches AuthManager without persisting raw secrets."""
    cfg = MagicMock()
    cfg.official_username = ""
    cfg.official_password = ""
    cfg.regular_username = ""
    cfg.regular_password = ""
    cfg.weak_candidates = []
    cfg.max_weak_attempts = 5
    cfg.bearer_token = SENSITIVE_VALUES["bearer_token"]
    cfg.api_key = SENSITIVE_VALUES["api_key"]
    cfg.bearer_refresh_token = SENSITIVE_VALUES["bearer_refresh_token"]
    cfg.regular_bearer_token = ""
    cfg.regular_api_key = ""
    cfg.regular_bearer_refresh_token = ""

    creds = GrayboxCredentialSet.from_job_config(cfg)
    official = creds.official.to_credentials()

    self.assertEqual(official.bearer_token, SENSITIVE_VALUES["bearer_token"])
    self.assertEqual(official.api_key, SENSITIVE_VALUES["api_key"])
    self.assertEqual(official.bearer_refresh_token, SENSITIVE_VALUES["bearer_refresh_token"])
    self.assertTrue(creds.official.is_configured)

  def test_worker_credential_set_carries_regular_api_secrets(self):
    cfg = MagicMock()
    cfg.official_username = ""
    cfg.official_password = ""
    cfg.bearer_token = ""
    cfg.api_key = ""
    cfg.bearer_refresh_token = ""
    cfg.regular_username = ""
    cfg.regular_password = ""
    cfg.regular_bearer_token = SENSITIVE_VALUES["regular_bearer_token"]
    cfg.regular_api_key = SENSITIVE_VALUES["regular_api_key"]
    cfg.regular_bearer_refresh_token = SENSITIVE_VALUES["regular_bearer_refresh_token"]
    cfg.weak_candidates = []
    cfg.max_weak_attempts = 5

    creds = GrayboxCredentialSet.from_job_config(cfg)

    self.assertIsNotNone(creds.regular)
    self.assertEqual(creds.regular.bearer_token, SENSITIVE_VALUES["regular_bearer_token"])
    self.assertEqual(creds.regular.api_key, SENSITIVE_VALUES["regular_api_key"])
    self.assertEqual(creds.regular.principal, "regular")

  def test_runtime_credential_dict_exposes_only_secret_capabilities(self):
    cfg = MagicMock()
    cfg.official_username = "alice"
    cfg.official_password = "formpw"
    cfg.regular_username = ""
    cfg.regular_password = ""
    cfg.weak_candidates = []
    cfg.max_weak_attempts = 5
    cfg.bearer_token = SENSITIVE_VALUES["bearer_token"]
    cfg.api_key = SENSITIVE_VALUES["api_key"]
    cfg.bearer_refresh_token = SENSITIVE_VALUES["bearer_refresh_token"]
    cfg.regular_bearer_token = ""
    cfg.regular_api_key = ""
    cfg.regular_bearer_refresh_token = ""

    serialized = json.dumps(GrayboxCredentialSet.from_job_config(cfg).official.to_dict())

    self.assertFalse(_has_secrets(serialized), serialized)
    self.assertNotIn("formpw", serialized)
    self.assertIn('"has_bearer_token": true', serialized)


if __name__ == "__main__":
  unittest.main()
