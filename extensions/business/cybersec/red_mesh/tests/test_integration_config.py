import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.services.config import (
  DEFAULT_EVENT_EXPORT_CONFIG,
  DEFAULT_OPENCTI_EXPORT_CONFIG,
  DEFAULT_STIX_EXPORT_CONFIG,
  DEFAULT_SURICATA_CORRELATION_CONFIG,
  DEFAULT_TAXII_EXPORT_CONFIG,
  DEFAULT_WAZUH_EXPORT_CONFIG,
  get_event_export_config,
  get_opencti_export_config,
  get_stix_export_config,
  get_suricata_correlation_config,
  get_taxii_export_config,
  get_wazuh_export_config,
)


class TestIntegrationConfig(unittest.TestCase):

  def _owner(self, block_name=None, override=None):
    owner = MagicMock()
    owner.CONFIG = {}
    if block_name:
      setattr(owner, f"cfg_{block_name.lower()}", override)
    return owner

  def test_defaults_are_disabled_and_redacted(self):
    owner = self._owner()

    event_cfg = get_event_export_config(owner)
    wazuh_cfg = get_wazuh_export_config(owner)
    suricata_cfg = get_suricata_correlation_config(owner)
    stix_cfg = get_stix_export_config(owner)
    opencti_cfg = get_opencti_export_config(owner)
    taxii_cfg = get_taxii_export_config(owner)

    self.assertFalse(event_cfg["ENABLED"])
    self.assertEqual(event_cfg["REDACTION_MODE"], "hash_only")
    self.assertEqual(event_cfg["DESTINATION_TRUST_PROFILE"], "restricted_redacted")
    self.assertFalse(event_cfg["INCLUDE_TARGET_DISPLAY"])
    self.assertFalse(event_cfg["INCLUDE_WORKER_SOURCE_IP"])
    self.assertFalse(event_cfg["INCLUDE_EGRESS_IP"])
    self.assertFalse(event_cfg["INCLUDE_SERVICE_BANNERS"])
    self.assertFalse(event_cfg["INCLUDE_RAW_RESPONSES"])
    self.assertFalse(event_cfg["INCLUDE_CREDENTIALS"])
    self.assertTrue(event_cfg["SIGN_PAYLOADS"])
    self.assertFalse(wazuh_cfg["ENABLED"])
    self.assertFalse(wazuh_cfg["PERSIST_FAILED_PAYLOADS"])
    self.assertEqual(wazuh_cfg["FAILED_PAYLOAD_SAMPLE_BYTES"], 2048)
    self.assertFalse(suricata_cfg["ENABLED"])
    self.assertFalse(stix_cfg["ENABLED"])
    self.assertFalse(opencti_cfg["ENABLED"])
    self.assertFalse(taxii_cfg["ENABLED"])

  def test_default_integration_blocks_are_disabled(self):
    for config in (
      DEFAULT_EVENT_EXPORT_CONFIG,
      DEFAULT_WAZUH_EXPORT_CONFIG,
      DEFAULT_SURICATA_CORRELATION_CONFIG,
      DEFAULT_STIX_EXPORT_CONFIG,
      DEFAULT_OPENCTI_EXPORT_CONFIG,
      DEFAULT_TAXII_EXPORT_CONFIG,
    ):
      self.assertFalse(config["ENABLED"])

  def test_event_export_normalizes_choices_and_never_exports_credentials(self):
    owner = self._owner("EVENT_EXPORT", {
      "ENABLED": True,
      "REDACTION_MODE": "bad",
      "DESTINATION_TRUST_PROFILE": "bad",
      "DEFAULT_TLP": "bad",
      "INCLUDE_CREDENTIALS": True,
      "SIGN_PAYLOADS": False,
      "HMAC_SECRET_ENV": "",
    })

    cfg = get_event_export_config(owner)

    self.assertTrue(cfg["ENABLED"])
    self.assertEqual(cfg["REDACTION_MODE"], "hash_only")
    self.assertEqual(cfg["DESTINATION_TRUST_PROFILE"], "restricted_redacted")
    self.assertEqual(cfg["DEFAULT_TLP"], "amber")
    self.assertFalse(cfg["INCLUDE_CREDENTIALS"])
    self.assertFalse(cfg["SIGN_PAYLOADS"])
    self.assertEqual(cfg["HMAC_SECRET_ENV"], "REDMESH_EVENT_HMAC_SECRET")

  def test_wazuh_config_rejects_url_userinfo_and_bounds_values(self):
    owner = self._owner("WAZUH_EXPORT", {
      "ENABLED": True,
      "MODE": "http",
      "SYSLOG_PORT": 70000,
      "HTTP_URL": "https://user:pass@wazuh.example/ingest",
      "MIN_SEVERITY": "bad",
      "TIMEOUT_SECONDS": 0,
      "RETRY_ATTEMPTS": -1,
      "PERSIST_FAILED_PAYLOADS": True,
      "FAILED_PAYLOAD_SAMPLE_BYTES": 1,
    })

    cfg = get_wazuh_export_config(owner)

    self.assertTrue(cfg["ENABLED"])
    self.assertEqual(cfg["MODE"], "http")
    self.assertEqual(cfg["SYSLOG_PORT"], 514)
    self.assertEqual(cfg["HTTP_URL"], "")
    self.assertEqual(cfg["MIN_SEVERITY"], "INFO")
    self.assertEqual(cfg["TIMEOUT_SECONDS"], 5.0)
    self.assertEqual(cfg["RETRY_ATTEMPTS"], 2)
    self.assertTrue(cfg["PERSIST_FAILED_PAYLOADS"])
    self.assertEqual(cfg["FAILED_PAYLOAD_SAMPLE_BYTES"], 2048)

  def test_suricata_config_keeps_suppression_disabled(self):
    owner = self._owner("SURICATA_CORRELATION", {
      "ENABLED": True,
      "MATCH_WINDOW_SECONDS": -10,
      "CLOCK_SKEW_SECONDS": -1,
      "AUTO_SUPPRESS": True,
    })

    cfg = get_suricata_correlation_config(owner)

    self.assertTrue(cfg["ENABLED"])
    self.assertEqual(cfg["MATCH_WINDOW_SECONDS"], 300)
    self.assertEqual(cfg["CLOCK_SKEW_SECONDS"], 60)
    self.assertFalse(cfg["AUTO_SUPPRESS"])

  def test_cti_configs_reject_url_userinfo(self):
    opencti_owner = self._owner("OPENCTI_EXPORT", {
      "URL": "https://token:secret@opencti.example",
      "MIN_SEVERITY": "critical",
    })
    taxii_owner = self._owner("TAXII_EXPORT", {
      "SERVER_URL": "https://token:secret@taxii.example",
      "COLLECTION_ID": "collection-1",
    })

    opencti_cfg = get_opencti_export_config(opencti_owner)
    taxii_cfg = get_taxii_export_config(taxii_owner)

    self.assertEqual(opencti_cfg["URL"], "")
    self.assertEqual(opencti_cfg["MIN_SEVERITY"], "CRITICAL")
    self.assertEqual(taxii_cfg["SERVER_URL"], "")
    self.assertEqual(taxii_cfg["COLLECTION_ID"], "collection-1")

  def test_stix_config_normalizes_tlp_and_indicator_mode(self):
    owner = self._owner("STIX_EXPORT", {
      "ENABLED": True,
      "DEFAULT_TLP": "bad",
      "INCLUDE_OBSERVED_DATA": False,
      "INCLUDE_INDICATORS": "bad",
    })

    cfg = get_stix_export_config(owner)

    self.assertTrue(cfg["ENABLED"])
    self.assertEqual(cfg["DEFAULT_TLP"], "amber")
    self.assertFalse(cfg["INCLUDE_OBSERVED_DATA"])
    self.assertEqual(cfg["INCLUDE_INDICATORS"], "ioc_only")

  def test_wazuh_auth_fields_have_defaults(self):
    cfg = get_wazuh_export_config(self._owner())
    self.assertEqual(cfg["AUTH_MODE"], "static")
    self.assertEqual(cfg["TOKEN_ENV"], "REDMESH_WAZUH_TOKEN")
    self.assertEqual(cfg["PASSWORD_ENV"], "REDMESH_WAZUH_PASSWORD")
    self.assertEqual(cfg["LOGIN_PATH"], "/security/user/authenticate?raw=true")
    self.assertEqual(cfg["JWT_TTL_OVERRIDE_SECONDS"], 0)
    self.assertEqual(cfg["USERNAME"], "")
    self.assertEqual(cfg["LOGIN_URL"], "")

  def test_wazuh_http_token_env_field_removed(self):
    # Regression guard: the legacy HTTP_TOKEN_ENV field must be gone.
    cfg = get_wazuh_export_config(self._owner())
    self.assertNotIn("HTTP_TOKEN_ENV", cfg)
    self.assertNotIn("HTTP_TOKEN_ENV", DEFAULT_WAZUH_EXPORT_CONFIG)

  def test_wazuh_auth_mode_clamps_to_allowed_enum(self):
    owner = self._owner("WAZUH_EXPORT", {"AUTH_MODE": "basic"})  # not allowed for Wazuh
    cfg = get_wazuh_export_config(owner)
    self.assertEqual(cfg["AUTH_MODE"], "static")

    owner = self._owner("WAZUH_EXPORT", {"AUTH_MODE": "wazuh_jwt"})
    cfg = get_wazuh_export_config(owner)
    self.assertEqual(cfg["AUTH_MODE"], "wazuh_jwt")

  def test_wazuh_jwt_ttl_override_negative_resets_to_default(self):
    owner = self._owner("WAZUH_EXPORT", {"JWT_TTL_OVERRIDE_SECONDS": -10})
    cfg = get_wazuh_export_config(owner)
    self.assertEqual(cfg["JWT_TTL_OVERRIDE_SECONDS"], 0)

  def test_wazuh_login_url_rejects_userinfo(self):
    owner = self._owner("WAZUH_EXPORT", {
      "LOGIN_URL": "https://user:secret@wazuh.example",
    })
    cfg = get_wazuh_export_config(owner)
    self.assertEqual(cfg["LOGIN_URL"], "")

  def test_taxii_auth_mode_clamps_and_credentials_visible(self):
    owner = self._owner("TAXII_EXPORT", {
      "AUTH_MODE": "wazuh_jwt",  # invalid for TAXII
      "USERNAME": "redmesh",
      "PASSWORD_ENV": "REDMESH_TAXII_PASSWORD",
    })
    cfg = get_taxii_export_config(owner)
    self.assertEqual(cfg["AUTH_MODE"], "static")
    self.assertEqual(cfg["USERNAME"], "redmesh")
    self.assertEqual(cfg["PASSWORD_ENV"], "REDMESH_TAXII_PASSWORD")

    owner = self._owner("TAXII_EXPORT", {"AUTH_MODE": "basic"})
    cfg = get_taxii_export_config(owner)
    self.assertEqual(cfg["AUTH_MODE"], "basic")

  def test_opencti_auth_mode_only_static_allowed(self):
    for attempt in ("basic", "wazuh_jwt", "oauth2", ""):
      owner = self._owner("OPENCTI_EXPORT", {"AUTH_MODE": attempt})
      cfg = get_opencti_export_config(owner)
      self.assertEqual(cfg["AUTH_MODE"], "static")


if __name__ == "__main__":
  unittest.main()
