"""The effective config of a deployment integration: the Deeploy block, then the STA override (RM-139)."""
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import event_hooks, integration_status, soc_export_policy
from extensions.business.cybersec.red_mesh.services.config import (
  DEFAULT_OPENCTI_EXPORT_CONFIG, IntegrationOverrideUnavailable, get_opencti_export_config,
  get_taxii_export_config, get_wazuh_export_config, job_tenant_id, resolve_config_block)
from extensions.business.cybersec.red_mesh.services.misp_config import get_misp_export_config
from .test_execution_binding_models import binding_payload


class Owner:
  """Duck-types the plugin: the Deeploy blocks, the override accessor and the status hash."""

  cfg_instance_id = "pdev5"

  def __init__(self, blocks=None, overrides=None, raises=False):
    self.config_data = dict(blocks or {})
    self._overrides = dict(overrides or {})
    self._raises = raises
    self.reads = []
    self.hsets = {}

  def _get_super_tenant_integration_override(self, integration_id):
    self.reads.append(integration_id)
    if self._raises:
      raise RuntimeError("storage unavailable")
    return self._overrides.get(integration_id)

  def chainstore_hget(self, *, hkey, key):
    return self.hsets.get(hkey, {}).get(key)

  def chainstore_hset(self, *, hkey, key, value, **kwargs):
    self.hsets.setdefault(hkey, {})[key] = value
    return True


def override(config=None, **fields):
  return {"config": config, "sharing_groups": None, "auto_export": None, **fields}


DEEPLOY = {
  "MISP_EXPORT": {"ENABLED": True, "MISP_URL": "https://deploy-misp.example", "MISP_API_KEY": "deploy"},
  "WAZUH_EXPORT": {"ENABLED": True, "MODE": "http", "HTTP_URL": "https://deploy-wazuh.example",
                   "TOKEN": "deploy"},
  "OPENCTI_EXPORT": {"ENABLED": True, "URL": "https://deploy-octi.example", "TOKEN": "deploy"},
  "TAXII_EXPORT": {"ENABLED": True, "SERVER_URL": "https://deploy-taxii.example", "TOKEN": "deploy",
                   "COLLECTION_ID": "c"},
}


class TestMergeOrder(unittest.TestCase):
  def test_the_override_wins_over_the_deeploy_block_which_wins_over_the_default(self):
    defaults = {"URL": "", "AUTH_MODE": "static", "ENABLED": False}
    self.assertEqual(
      resolve_config_block(Owner({"B": {"URL": "https://deploy.example", "ENABLED": True}}),
                           "B", defaults, override={"URL": "https://sta.example"}),
      {"URL": "https://sta.example", "AUTH_MODE": "static", "ENABLED": True})

  def test_a_partial_override_keeps_the_deeploy_values_it_does_not_name(self):
    defaults = {"URL": "", "TIMEOUT": 1}
    self.assertEqual(
      resolve_config_block(Owner({"B": {"URL": "https://deploy.example", "TIMEOUT": 9}}),
                           "B", defaults, override={"TIMEOUT": 3}),
      {"URL": "https://deploy.example", "TIMEOUT": 3})


class TestEffectiveConfig(unittest.TestCase):
  def test_without_an_override_every_integration_is_the_deeploy_block(self):
    owner = Owner(DEEPLOY)
    self.assertEqual(get_misp_export_config(owner)["MISP_URL"], "https://deploy-misp.example")
    self.assertEqual(get_wazuh_export_config(owner)["HTTP_URL"], "https://deploy-wazuh.example")
    self.assertEqual(get_opencti_export_config(owner)["URL"], "https://deploy-octi.example")
    self.assertEqual(get_taxii_export_config(owner)["SERVER_URL"], "https://deploy-taxii.example")
    self.assertEqual(owner.reads, ["misp", "wazuh", "opencti", "taxii"])

  def test_an_override_replaces_the_destination_and_credentials(self):
    owner = Owner(DEEPLOY, {
      "misp": override({"MISP_URL": "https://sta-misp.example", "MISP_API_KEY": "sta"}),
      "wazuh": override({"HTTP_URL": "https://sta-wazuh.example", "TOKEN": "sta"}),
      "opencti": override({"URL": "https://sta-octi.example", "TOKEN": "sta"}),
      "taxii": override({"SERVER_URL": "https://sta-taxii.example", "TOKEN": "sta"})})
    misp = get_misp_export_config(owner)
    self.assertEqual((misp["MISP_URL"], misp["MISP_API_KEY"]), ("https://sta-misp.example", "sta"))
    self.assertEqual(get_wazuh_export_config(owner)["HTTP_URL"], "https://sta-wazuh.example")
    self.assertEqual(get_opencti_export_config(owner)["URL"], "https://sta-octi.example")
    self.assertEqual(get_taxii_export_config(owner)["SERVER_URL"], "https://sta-taxii.example")

  def test_an_override_without_a_destination_keeps_the_deeploy_destination(self):
    owner = Owner(DEEPLOY, {"opencti": override({"MIN_SEVERITY": "HIGH", "TOKEN": "rotated"})})
    cfg = get_opencti_export_config(owner)
    self.assertEqual((cfg["URL"], cfg["TOKEN"], cfg["MIN_SEVERITY"]),
                     ("https://deploy-octi.example", "rotated", "HIGH"))

  def test_a_row_without_config_falls_back_to_the_deeploy_block(self):
    owner = Owner(DEEPLOY, {"misp": override(None, auto_export=False)})
    cfg = get_misp_export_config(owner)
    self.assertEqual((cfg["MISP_URL"], cfg["MISP_API_KEY"]), ("https://deploy-misp.example", "deploy"))

  def test_the_normalizer_still_runs_over_an_override_value(self):
    owner = Owner(DEEPLOY, {"opencti": override({"MIN_SEVERITY": "not-a-severity"})})
    self.assertEqual(get_opencti_export_config(owner)["MIN_SEVERITY"],
                     DEFAULT_OPENCTI_EXPORT_CONFIG["MIN_SEVERITY"])

  def test_an_owner_without_the_accessor_resolves_the_deeploy_block(self):
    class Bare:
      config_data = DEEPLOY
    self.assertEqual(get_misp_export_config(Bare())["MISP_URL"], "https://deploy-misp.example")

  def test_an_unreadable_override_raises_and_never_falls_back(self):
    owner = Owner(DEEPLOY, raises=True)
    for getter in (get_misp_export_config, get_wazuh_export_config, get_opencti_export_config,
                   get_taxii_export_config):
      with self.assertRaises(IntegrationOverrideUnavailable, msg=getter.__name__):
        getter(owner)

  def test_a_malformed_override_is_unavailable_not_absent(self):
    owner = Owner(DEEPLOY, {"misp": "not-a-row"})
    with self.assertRaises(IntegrationOverrideUnavailable):
      get_misp_export_config(owner)

  def test_an_explicit_row_skips_the_store_read(self):
    owner = Owner(DEEPLOY, raises=True)
    self.assertEqual(get_misp_export_config(owner, override=None)["MISP_URL"], "https://deploy-misp.example")
    self.assertEqual(owner.reads, [])


class TestDeploymentCredentialsStayHome(unittest.TestCase):
  """An overridden destination never receives a Deeploy credential, inline or through the env."""

  def test_an_overridden_destination_without_credentials_reads_as_missing_them(self):
    # A restored backup row: its secrets were withheld, its URL was not.
    owner = Owner(DEEPLOY, {"misp": override({"MISP_URL": "https://sta-misp.example"}),
                            "opencti": override({"URL": "https://sta-octi.example"})})
    self.assertEqual(get_misp_export_config(owner)["MISP_API_KEY"], "")
    cfg = get_opencti_export_config(owner)
    self.assertEqual((cfg["TOKEN"], cfg["TOKEN_ENV"]), ("", ""))

  def test_no_environment_indirection_applies_under_an_overridden_destination(self):
    owner = Owner({"TAXII_EXPORT": {"ENABLED": True, "AUTH_MODE": "basic", "USERNAME": "u",
                                    "PASSWORD_ENV": "DEPLOY_TAXII_PASSWORD"}},
                  {"taxii": override({"SERVER_URL": "https://sta-taxii.example", "TOKEN": "sta"})})
    with patch.dict("os.environ", {"DEPLOY_TAXII_PASSWORD": "deploy-secret", "REDMESH_TAXII_TOKEN": "env"}):
      cfg = get_taxii_export_config(owner)
    self.assertEqual((cfg["PASSWORD"], cfg["PASSWORD_ENV"], cfg["TOKEN_ENV"]), ("", "", ""))

  def test_a_wazuh_login_url_is_a_destination_too(self):
    owner = Owner(DEEPLOY, {"wazuh": override({"LOGIN_URL": "https://sta-login.example"})})
    cfg = get_wazuh_export_config(owner)
    self.assertEqual((cfg["TOKEN"], cfg["PASSWORD"]), ("", ""))


class TestAutoExport(unittest.TestCase):
  def test_the_override_toggle_wins_and_clearing_it_restores_the_deeploy_value(self):
    blocks = {"MISP_EXPORT": {**DEEPLOY["MISP_EXPORT"], "AUTO_EXPORT": False}}
    self.assertTrue(get_misp_export_config(Owner(blocks, {"misp": override(auto_export=True)}))["AUTO_EXPORT"])
    self.assertFalse(get_misp_export_config(Owner(blocks, {"misp": override(sharing_groups={})}))["AUTO_EXPORT"])


class TestJobTenantId(unittest.TestCase):
  def test_a_bound_job_names_its_tenant(self):
    binding = binding_payload()
    self.assertEqual(job_tenant_id({"execution_binding": binding}), binding["tenant_id"])

  def test_anything_else_names_no_tenant(self):
    for job in (None, {}, {"execution_binding": None}, {"execution_binding": "text"},
                {"execution_binding": {"tenant_id": "tn_a"}}):
      self.assertIsNone(job_tenant_id(job), job)


class TestDeploymentKeyedStatus(unittest.TestCase):
  def test_status_and_cooldown_live_under_the_deployment_key_only(self):
    owner = Owner(DEEPLOY)
    owner.hsets["pdev5:integrations:tn_a"] = {"wazuh": {"last_event_id": "rm-081-tenant-history"}}
    for _ in range(2):
      integration_status.record_integration_status(owner, "wazuh", outcome="failure", error_class="timeout")
    self.assertEqual(integration_status._status_hkey(owner), soc_export_policy._status_hkey(owner))
    self.assertEqual(set(owner.hsets), {"pdev5:integrations", "pdev5:integrations:tn_a"})
    self.assertIsNotNone(soc_export_policy.current_integration_cooldown(owner, "wazuh"))
    # The RM-081 per-tenant history is left alone and never read.
    self.assertNotEqual(integration_status.get_integration_status(owner)["integrations"]["wazuh"]
                        .get("last_event_id"), "rm-081-tenant-history")
    self.assertEqual(owner.hsets["pdev5:integrations:tn_a"], {"wazuh": {"last_event_id": "rm-081-tenant-history"}})


class TestRequiredSocLaunchGate(unittest.TestCase):
  def setUp(self):
    # Without the signing secret every readiness check reports missing_hmac_secret.
    env = patch.dict("os.environ", {"REDMESH_EVENT_HMAC_SECRET": "secret"})
    env.start()
    self.addCleanup(env.stop)

  def blocks(self, **wazuh):
    return {"EVENT_EXPORT": {"ENABLED": True}, "WAZUH_EXPORT": {**DEEPLOY["WAZUH_EXPORT"], **wazuh}}

  def test_nothing_required_gates_nothing(self):
    self.assertIsNone(soc_export_policy.required_soc_launch_error(Owner(self.blocks(IS_REQUIRED=False))))

  def test_a_required_deployment_destination_gates_every_launch(self):
    self.assertIsNone(soc_export_policy.required_soc_launch_error(Owner(self.blocks(IS_REQUIRED=True))))
    unready = Owner(self.blocks(IS_REQUIRED=True, HTTP_URL="", TOKEN=""))
    self.assertEqual(soc_export_policy.required_soc_launch_error(unready)["error"], "soc_export_required_unavailable")

  def test_the_override_decides_the_requirement_and_the_destination(self):
    owner = Owner(self.blocks(IS_REQUIRED=False), {"wazuh": override({"IS_REQUIRED": True, "ENABLED": True,
                                                                     "HTTP_URL": "https://sta.example"})})
    # Required by the override, and its destination has no credentials of its own.
    self.assertEqual(soc_export_policy.required_soc_launch_error(owner)["error_class"], "missing_token")

  def test_an_unreadable_override_refuses_the_launch(self):
    error = soc_export_policy.required_soc_launch_error(Owner(self.blocks(IS_REQUIRED=False), raises=True))
    self.assertEqual((error["error"], error["error_class"]),
                     ("soc_export_required_unavailable", "integration_config_unavailable"))


class TestAutomaticEmission(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"REDMESH_EVENT_HMAC_SECRET": "secret"})
    env.start()
    self.addCleanup(env.stop)

  def emit(self, owner, job_specs):
    with patch.object(event_hooks, "deliver_redmesh_event") as deliver:
      deliver.return_value = {"status": "sent", "integration_id": "wazuh", "event_id": "ev-1"}
      result = event_hooks.emit_redmesh_event(owner, job_specs, {"event_id": "ev-1"})
    return result, deliver

  def test_every_job_bound_or_not_delivers_to_the_deployment(self):
    for job in ({"job_id": "j", "execution_binding": binding_payload()}, {"job_id": "j"}):
      result, deliver = self.emit(Owner({"EVENT_EXPORT": {"ENABLED": True}, **DEEPLOY}), job)
      self.assertEqual(result["status"], "sent")
      deliver.assert_called_once()
      self.assertNotIn("tenant_id", deliver.call_args.kwargs)

  def test_an_override_that_disables_wazuh_skips_the_emission(self):
    owner = Owner({"EVENT_EXPORT": {"ENABLED": True}, **DEEPLOY}, {"wazuh": override({"ENABLED": False})})
    result, deliver = self.emit(owner, {"job_id": "j"})
    self.assertEqual((result["status"], result["error"]), ("skipped", "wazuh_disabled"))
    deliver.assert_not_called()

  def test_an_unreadable_override_skips_without_a_failure_signature(self):
    owner = Owner({"EVENT_EXPORT": {"ENABLED": True}, **DEEPLOY}, raises=True)
    job = {"job_id": "j"}
    result, deliver = self.emit(owner, job)
    self.assertEqual((result["status"], result["error"]), ("skipped", "integration_config_unavailable"))
    deliver.assert_not_called()
    self.assertEqual(job["soc_event_status"]["integration_status"], "unavailable")
    self.assertIsNone(job["soc_event_status"].get("last_failure_signature"))


if __name__ == "__main__":
  unittest.main()
