"""RM-139 phase 2: the STA override of the deployment integrations, through the real plugin endpoints,
service and adapters."""
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.services import misp_export
from extensions.business.cybersec.red_mesh.services.config import IntegrationOverrideUnavailable
from extensions.business.cybersec.red_mesh.services.misp_config import get_misp_export_config
from extensions.business.cybersec.red_mesh.services.config import get_opencti_export_config
from .test_tenant_administration import FakeAdministrationStore
from .test_tenant_drafts import TENANCY_HKEY, ok, refused

SECRETS = ("deeploy-misp-key", "sta-misp-key", "sta-octi-token", "deeploy-octi-token")
DEEPLOY = {
  "MISP_EXPORT": {"ENABLED": True, "AUTO_EXPORT": False, "MISP_URL": "https://deploy-misp.example",
                  "MISP_API_KEY": "deeploy-misp-key"},
  "OPENCTI_EXPORT": {"ENABLED": True, "URL": "https://deploy-octi.example", "TOKEN": "deeploy-octi-token"},
}


def row_key(integration_id):
  return (TENANCY_HKEY, json.dumps(["super_tenant_integration", "deployment", integration_id], separators=(",", ":")))


class _Case(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = FakeAdministrationStore()
    self.store.account("pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.tenant = "tn_" + str(uuid4())
    self.store.account("scoped-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": self.tenant}])
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.cfg_instance_id = "jobs"
    self.plugin.config_data = json.loads(json.dumps(DEEPLOY))
    self.plugin.P = lambda *args, **kwargs: None
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.store, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.actor = {"account_id": "creator"}

  def listed(self, actor=None):
    result = self.plugin.list_super_tenant_integrations(actor or self.actor)
    return {item["integrationId"]: item for item in ok(self, result)["integrations"]}

  def put(self, integration_id, changes, expected_version=None, actor=None):
    return self.plugin.put_super_tenant_integration(actor or self.actor, integration_id, changes, expected_version)

  def version(self, integration_id):
    return self.listed()[integration_id]["version"]

  def assert_no_secret(self, payload):
    rendered = json.dumps(payload)
    for secret in SECRETS:
      self.assertNotIn(secret, rendered)


class TestRead(_Case):
  def test_the_deeploy_config_alone_reads_as_configured_from_the_deployment_config(self):
    listed = self.listed()
    self.assertEqual(set(listed), {"misp", "opencti", "taxii", "wazuh"})
    misp = listed["misp"]
    self.assertEqual((misp["enabled"], misp["configured"], misp["source"], misp["version"]),
                     (True, True, "deployment_config", None))
    self.assertEqual(misp["fields"]["MISP_URL"], {"value": "https://deploy-misp.example", "source": "deployment_config"})
    self.assertEqual(misp["secrets"], {"MISP_API_KEY": {"set": True, "source": "deployment_config"}})
    self.assertEqual(misp["autoExport"], {"value": False, "source": "deployment_config"})
    self.assertEqual(misp["sharingGroups"], {})
    self.assertEqual((listed["taxii"]["configured"], listed["taxii"]["source"]), (False, "none"))
    self.assertNotIn("autoExport", listed["opencti"])
    self.assert_no_secret(listed)
    # A read never writes.
    self.assertNotIn(row_key("misp"), self.store.data)

  def test_an_override_reports_its_fields_and_secrets_by_source_and_never_a_value(self):
    ok(self, self.put("misp", {"config": {"MISP_URL": "https://sta-misp.example", "MISP_API_KEY": "sta-misp-key"},
                               "auto_export": True, "sharing_groups": {self.tenant: 7}}))
    misp = self.listed()["misp"]
    self.assertEqual((misp["configured"], misp["source"]), (True, "override"))
    self.assertEqual(misp["fields"]["MISP_URL"], {"value": "https://sta-misp.example", "source": "override"})
    self.assertEqual(misp["fields"]["MISP_DISTRIBUTION"]["source"], "deployment_config")
    self.assertEqual(misp["secrets"], {"MISP_API_KEY": {"set": True, "source": "override"}})
    self.assertEqual(misp["autoExport"], {"value": True, "source": "override"})
    self.assertEqual(misp["sharingGroups"], {self.tenant: 7})
    self.assertEqual(misp["updatedBy"], "creator")
    self.assert_no_secret(misp)

  def test_only_a_full_portfolio_super_tenant_admin_reads_or_writes(self):
    # The profile pattern: an account without the platform role is forbidden, and one whose only
    # membership names no tenant of this deployment is not found.
    for account, status_code, error in (("pentester", 403, "forbidden"), ("initial", 403, "forbidden"),
                                        ("scoped-sta", 404, "not_found"), ("nobody", 404, "not_found")):
      actor = {"account_id": account}
      result = self.plugin.list_super_tenant_integrations(actor)
      self.assertEqual((result["success"], result["status_code"]), (False, status_code), (account, result))
      result = self.put("misp", {"auto_export": True}, actor=actor)
      self.assertEqual((result["success"], result["status_code"]), (False, status_code), (account, result))
      self.assertNotIn("data", result)
    self.assertNotIn(row_key("misp"), self.store.data)

  def test_an_unreadable_override_fails_closed(self):
    original = self.store.chainstore_hget

    def failing(*, hkey, key):
      if "super_tenant_integration" in key:
        raise RuntimeError("cstore down")
      return original(hkey=hkey, key=key)
    self.plugin.chainstore_hget = failing
    refused(self, self.plugin.list_super_tenant_integrations(self.actor), 503, "unavailable")
    with self.assertRaises(IntegrationOverrideUnavailable):
      get_misp_export_config(self.plugin)
    # An export never goes out with the Deeploy values instead.
    self.plugin._get_job_from_cstore = lambda job_id: {"job_id": job_id}
    with patch.object(misp_export, "PyMISP") as client, self.assertRaises(IntegrationOverrideUnavailable):
      misp_export.push_to_misp(self.plugin, "job-1")
    client.assert_not_called()


class TestEnvCredential(_Case):
  def test_a_deeploy_credential_named_by_an_env_var_reads_as_set(self):
    # Review E7: the Deeploy block may name the credential's env var instead of carrying it.
    self.plugin.config_data["OPENCTI_EXPORT"] = {"ENABLED": True, "URL": "https://deploy-octi.example",
                                                 "TOKEN": "", "TOKEN_ENV": "RM_TEST_OCTI_TOKEN"}
    with patch.dict("os.environ", {"RM_TEST_OCTI_TOKEN": "deeploy-octi-token"}):
      octi = self.listed()["opencti"]
      self.assertEqual(octi["secrets"]["TOKEN"], {"set": True, "source": "deployment_config"})
      self.assert_no_secret(octi)
    with patch.dict("os.environ", {"RM_TEST_OCTI_TOKEN": ""}):
      self.assertEqual(self.listed()["opencti"]["secrets"]["TOKEN"], {"set": False, "source": "none"})


class TestWrite(_Case):
  def test_an_override_wins_for_export_and_clearing_it_falls_back_to_the_deeploy_config(self):
    ok(self, self.put("opencti", {"config": {"URL": "https://sta-octi.example", "TOKEN": "sta-octi-token"}}))
    cfg = get_opencti_export_config(self.plugin)
    self.assertEqual((cfg["URL"], cfg["TOKEN"]), ("https://sta-octi.example", "sta-octi-token"))
    self.assertEqual(self.events, [("super_tenant_integration_updated",
                                    {"actor": "creator", "integration_id": "opencti",
                                     "changed": ["config.TOKEN", "config.URL"]})])
    cleared = ok(self, self.put("opencti", {"config": None}, self.version("opencti")))
    self.assertEqual((cleared["source"], cleared["version"]), ("deployment_config", None))
    # A row with nothing left is deleted, not kept empty.
    self.assertIsNone(self.store.data.get(row_key("opencti")))
    cfg = get_opencti_export_config(self.plugin)
    self.assertEqual((cfg["URL"], cfg["TOKEN"]), ("https://deploy-octi.example", "deeploy-octi-token"))

  def test_a_stale_or_missing_version_is_a_conflict(self):
    refused(self, self.put("misp", {"auto_export": True}, "a" * 64), 409, "conflict")
    first = ok(self, self.put("misp", {"auto_export": True}))
    refused(self, self.put("misp", {"auto_export": False}), 409, "conflict")
    refused(self, self.put("misp", {"auto_export": False}, "b" * 64), 409, "conflict")
    second = ok(self, self.put("misp", {"auto_export": False}, first["version"]))
    refused(self, self.put("misp", {"auto_export": True}, first["version"]), 409, "conflict")
    self.assertNotEqual(first["version"], second["version"])

  def test_a_destination_without_its_credentials_is_refused(self):
    refused(self, self.put("misp", {"config": {"MISP_URL": "https://sta-misp.example"}}), 400, "credentials_required")
    refused(self, self.put("opencti", {"config": {"URL": "https://sta-octi.example"}}), 400, "credentials_required")
    refused(self, self.put("wazuh", {"config": {"LOGIN_URL": "https://sta-login.example"}}), 400,
            "credentials_required")
    self.assertNotIn(row_key("misp"), self.store.data)

  def test_an_omitted_secret_is_kept_and_a_clear_is_explicit(self):
    ok(self, self.put("misp", {"config": {"MISP_URL": "https://sta-misp.example", "MISP_API_KEY": "sta-misp-key"}}))
    kept = ok(self, self.put("misp", {"config": {"MISP_URL": "https://sta-misp-2.example"}}, self.version("misp")))
    self.assertEqual(kept["secrets"]["MISP_API_KEY"], {"set": True, "source": "override"})
    self.assertEqual(get_misp_export_config(self.plugin)["MISP_API_KEY"], "sta-misp-key")
    # Clearing the secret of an overridden destination would leave it without credentials.
    refused(self, self.put("misp", {"clear_secrets": ["MISP_API_KEY"]}, self.version("misp")), 400,
            "credentials_required")
    ok(self, self.put("misp", {"config": {"MIN_SEVERITY": "HIGH"}}, self.version("misp")))
    cleared = ok(self, self.put("misp", {"clear_secrets": ["MISP_API_KEY"]}, self.version("misp")))
    # Back to the Deeploy credential, for the Deeploy destination.
    self.assertEqual(cleared["secrets"]["MISP_API_KEY"], {"set": True, "source": "deployment_config"})
    self.assertEqual(get_misp_export_config(self.plugin)["MISP_URL"], "https://deploy-misp.example")

  def test_the_three_overrides_clear_independently(self):
    ok(self, self.put("misp", {"config": {"MIN_SEVERITY": "HIGH"}, "auto_export": True,
                               "sharing_groups": {self.tenant: 3}}))
    after = ok(self, self.put("misp", {"config": None}, self.version("misp")))
    self.assertEqual((after["source"], after["autoExport"]["source"], after["sharingGroups"]),
                     ("deployment_config", "override", {self.tenant: 3}))
    after = ok(self, self.put("misp", {"sharing_groups": None}, self.version("misp")))
    self.assertEqual((after["autoExport"], after["sharingGroups"]), ({"value": True, "source": "override"}, {}))
    after = ok(self, self.put("misp", {"auto_export": None}, self.version("misp")))
    self.assertEqual(after["autoExport"], {"value": False, "source": "deployment_config"})
    self.assertIsNone(self.store.data.get(row_key("misp")))

  def test_invalid_changes_are_refused(self):
    for integration_id, changes in (
        ("misp", {}), ("misp", None), ("misp", {"theme": "dark"}),
        ("misp", {"config": {"NOT_A_KEY": 1}}), ("misp", {"config": {"AUTO_EXPORT": True}}),
        ("opencti", {"config": {"TOKEN_ENV": "WALLET_KEY"}}), ("misp", {"config": {"MISP_API_KEY": ""}}),
        ("misp", {"config": {}}), ("misp", {"auto_export": "yes"}),
        ("misp", {"sharing_groups": {}}), ("misp", {"sharing_groups": {"tn_bad": 3}}),
        ("misp", {"sharing_groups": {self.tenant: 0}}), ("misp", {"sharing_groups": {self.tenant: True}}),
        ("misp", {"clear_secrets": ["MISP_URL"]}), ("opencti", {"auto_export": True}),
        ("opencti", {"sharing_groups": {self.tenant: 3}}),
        # Review E6: the distribution an override may set is 0-3; 4 needs a sharing group.
        ("misp", {"config": {"MISP_DISTRIBUTION": 4}}), ("misp", {"config": {"MISP_DISTRIBUTION": -1}}),
        ("misp", {"config": {"MISP_DISTRIBUTION": 9}}),
        # Review E8: a URL never carries userinfo.
        ("misp", {"config": {"MISP_URL": "https://user:pw@sta-misp.example", "MISP_API_KEY": "k"}}),
        ("opencti", {"config": {"URL": "https://user@sta-octi.example", "TOKEN": "t"}}),
        ("taxii", {"config": {"SERVER_URL": "https://u:p@taxii.example", "TOKEN": "t"}}),
        ("wazuh", {"config": {"LOGIN_URL": "https://u:p@login.example", "PASSWORD": "p"}})):
      refused(self, self.put(integration_id, changes), 400, "invalid_request")
    refused(self, self.put("stix", {"auto_export": True}), 404, "not_found")
    refused(self, self.put("misp", {"auto_export": True}, "not-a-digest"), 400, "invalid_request")
    self.assertEqual(self.events, [])

  def test_a_distribution_in_range_is_accepted(self):
    for distribution in (0, 3):
      result = ok(self, self.put("misp", {"config": {"MISP_DISTRIBUTION": distribution}},
                                 self.version("misp")))
      self.assertEqual(result["fields"]["MISP_DISTRIBUTION"], {"value": distribution, "source": "override"})

  def test_an_unchanged_write_is_not_written_or_audited(self):
    first = ok(self, self.put("misp", {"auto_export": True}))
    writes = len(self.store.writes)
    again = ok(self, self.put("misp", {"auto_export": True}, first["version"]))
    self.assertEqual((again["version"], len(self.store.writes), len(self.events)), (first["version"], writes, 1))


class TestBackup(_Case):
  def backup(self):
    self.plugin._get_artifact_repository = lambda: type("Files", (), {"get_json": lambda self, ref, **kw: None})()
    rows, cursor = [], {"hkey_index": 0, "offset": 0}
    while cursor:
      page = ok(self, self.plugin.export_redmesh_records(self.actor, cursor["hkey_index"], cursor["offset"], 50))
      rows += page["rows"]
      cursor = page["next"]
    return rows

  def restore(self, row):
    restored = ok(self, self.plugin.restore_redmesh_records(
      self.actor, [{"hkey": row["hkey"], "field": row["field"], "value": row["value"]}]))
    return restored["outcomes"][0]["outcome"]

  def test_a_backup_withholds_the_override_credentials(self):
    ok(self, self.put("misp", {"config": {"MISP_URL": "https://sta-misp.example", "MISP_API_KEY": "sta-misp-key"},
                               "sharing_groups": {self.tenant: 7}}))
    rows = self.backup()
    row = next(item for item in rows if (item["hkey"], item["field"]) == row_key("misp"))
    self.assertEqual((row["class"], row["reason"]), ("current", ""))
    self.assertEqual(row["value"]["config"], {"MISP_URL": "https://sta-misp.example"})
    self.assertEqual(row["value"]["sharing_groups"], {self.tenant: 7})
    self.assert_no_secret(rows)
    # Restored into an empty deployment, the row has no credentials: it never borrows the Deeploy key.
    del self.store.data[row_key("misp")]
    restored = ok(self, self.plugin.restore_redmesh_records(
      self.actor, [{"hkey": row["hkey"], "field": row["field"], "value": row["value"]}]))
    self.assertEqual(restored["outcomes"][0]["outcome"], "written")
    cfg = get_misp_export_config(self.plugin)
    self.assertEqual((cfg["MISP_URL"], cfg["MISP_API_KEY"]), ("https://sta-misp.example", ""))
    misp = self.listed()["misp"]
    self.assertEqual((misp["configured"], misp["secrets"]["MISP_API_KEY"]),
                     (False, {"set": False, "source": "none"}))

  def test_a_credential_only_override_restores_as_a_valid_row(self):
    # Review E1: stripping the only config keys left `config: {}`, a row the store refuses, so every
    # read of it failed and the STA could not even overwrite it.
    ok(self, self.put("misp", {"config": {"MISP_API_KEY": "sta-misp-key"}, "sharing_groups": {self.tenant: 7}}))
    row = next(item for item in self.backup() if (item["hkey"], item["field"]) == row_key("misp"))
    self.assertIsNone(row["value"]["config"])
    self.assertEqual(row["value"]["sharing_groups"], {self.tenant: 7})
    del self.store.data[row_key("misp")]
    self.assertEqual(self.restore(row), "written")
    misp = self.listed()["misp"]
    self.assertEqual((misp["source"], misp["secrets"]["MISP_API_KEY"], misp["sharingGroups"]),
                     ("deployment_config", {"set": True, "source": "deployment_config"}, {self.tenant: 7}))
    self.assertEqual(get_misp_export_config(self.plugin)["MISP_API_KEY"], "deeploy-misp-key")
    again = ok(self, self.put("misp", {"config": {"MISP_API_KEY": "sta-misp-key"}}, misp["version"]))
    self.assertEqual(again["secrets"]["MISP_API_KEY"], {"set": True, "source": "override"})

  def test_an_override_left_empty_by_the_backup_is_not_restored(self):
    ok(self, self.put("opencti", {"config": {"TOKEN": "sta-octi-token"}}))
    rows = self.backup()
    self.assert_no_secret(rows)
    row = next(item for item in rows if (item["hkey"], item["field"]) == row_key("opencti"))
    self.assertIsNone(row["value"]["config"])
    del self.store.data[row_key("opencti")]
    self.assertEqual(self.restore(row), "refused")
    self.assertIsNone(self.store.data.get(row_key("opencti")))
    octi = self.listed()["opencti"]
    self.assertEqual((octi["source"], octi["version"]), ("deployment_config", None))
    ok(self, self.put("opencti", {"config": {"TOKEN": "sta-octi-token"}}))

  def test_the_backup_hash_and_the_version_are_not_computed_over_a_credential(self):
    # Review E4: an unsalted hash over the credential-bearing row is an offline guessing oracle.
    from extensions.business.cybersec.red_mesh.services.data_maintenance import row_sha256
    from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
    ok(self, self.put("misp", {"config": {"MISP_URL": "https://sta-misp.example", "MISP_API_KEY": "sta-misp-key"}}))
    stored = self.store.data[row_key("misp")]
    version = self.version("misp")
    self.assertNotEqual(version, canonical_digest(stored))
    self.assertEqual(version, stored["revision"])
    row = next(item for item in self.backup() if (item["hkey"], item["field"]) == row_key("misp"))
    self.assertNotEqual(row["sha256"], row_sha256(stored))
    self.assertEqual(row["sha256"], row_sha256(row["value"]))
    # The backup row restored over the live one is `same`, and the live credential stays.
    self.assertEqual(self.restore(row), "same")
    self.assertEqual(get_misp_export_config(self.plugin)["MISP_API_KEY"], "sta-misp-key")
    # Writing back an earlier value still gets a new version.
    ok(self, self.put("misp", {"config": {"MISP_API_KEY": "sta-misp-key-2"}}, version))
    changed = self.version("misp")
    ok(self, self.put("misp", {"config": {"MISP_API_KEY": "sta-misp-key"}}, changed))
    self.assertNotIn(self.version("misp"), (version, changed))


class TestTestEventExportAuthority(_Case):
  def test_only_a_full_portfolio_super_tenant_admin_may_test_a_destination(self):
    with patch("extensions.business.cybersec.red_mesh.pentester_api_01.test_event_export") as probe:
      probe.return_value = {"status": "ok", "integration_id": "stix", "dry_run": True}
      for account in ("pentester", "initial", "scoped-sta"):
        result = self.plugin.test_event_export("stix", {"account_id": account}, self.tenant)
        self.assertFalse(result["success"], result)
        self.assertIn(result["status_code"], (403, 404), result)
      probe.assert_not_called()
      result = self.plugin.test_event_export("stix", self.actor)
    self.assertEqual(result["status"], "ok", result)
    probe.assert_called_once()


if __name__ == "__main__":
  unittest.main()
