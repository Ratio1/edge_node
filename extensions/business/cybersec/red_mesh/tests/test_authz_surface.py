"""Paired RM-075 contract: original model tokens and account-derived launch attribution."""
import inspect
import unittest
from unittest.mock import MagicMock, patch

from .conftest import mock_plugin_modules

TEST_CHANNEL_TOKEN = "test-model-token-material-at-least-32-bytes"
EXPECTED_ENDPOINTS = 52
TOKEN_ENDPOINTS = {"launch_model_test", "preflight_model_test_provider"}
LAUNCH_ENDPOINTS = ("launch_network_scan", "launch_webapp_scan", "launch_test", "launch_model_test")
# Pre-RM-075 public positional contract; account actor fields are appended to launches.
ENDPOINT_FIRST_ARGS = {
  'list_features': 'scan_type',
  'get_feature_catalog': 'scan_type',
  'launch_network_scan': 'target',
  'launch_webapp_scan': 'target_url',
  'launch_test': 'target',
  'launch_model_test': 'token',
  'preflight_model_test_provider': 'token',
  'get_model_test_catalog': None,
  'get_job_status': 'job_id',
  'get_job_data': 'job_id',
  'get_job_archive': 'job_id',
  'get_job_triage': 'job_id',
  'update_finding_triage': 'job_id',
  'get_job_progress': 'job_id',
  'upload_authorization': 'filename',
  'delete_job_engagement': 'job_id',
  'list_network_jobs': None,
  'list_local_jobs': None,
  'export_misp': 'job_id',
  'export_misp_json': 'job_id',
  'get_misp_export_status': 'job_id',
  'get_misp_export_config_status': None,
  'get_integration_status': None,
  'get_capability_status': None,
  'test_event_export': 'integration_id',
  'get_detection_correlation': 'job_id',
  'correlate_suricata_eve': 'job_id',
  'export_stix_bundle': 'job_id',
  'get_stix_export_status': 'job_id',
  'generate_rulebook_assessment': 'job_id',
  'get_rulebook_assessment_status': 'job_id',
  'get_rulebook_review': 'job_id',
  'save_rulebook_review_draft': 'job_id',
  'submit_rulebook_review': 'job_id',
  'reopen_rulebook_review': 'job_id',
  'update_rulebook_review': 'job_id',
  'dry_run_opencti_export': 'job_id',
  'push_to_opencti': 'job_id',
  'get_opencti_export_status': 'job_id',
  'dry_run_taxii_export': 'job_id',
  'publish_to_taxii': 'job_id',
  'get_taxii_export_status': 'job_id',
  'stop_and_delete_job': 'job_id',
  'purge_job': 'job_id',
  'purge_all_redmesh_data': 'confirm',
  'get_report': 'cid',
  'get_raw_model_test_evidence': 'job_id',
  'get_audit_log': 'limit',
  'stop_monitoring': 'job_id',
  'analyze_job': 'job_id',
  'get_analysis': 'job_id',
  'llm_health': None,
}


def _call_launch(endpoint, plugin, **kwargs):
  args = (TEST_CHANNEL_TOKEN,) if endpoint.__name__ == "launch_model_test" else ()
  return endpoint(plugin, *args, **kwargs)


def _endpoints(plugin_cls):
  found = {}
  for name, member in inspect.getmembers(plugin_cls, predicate=inspect.isfunction):
    if getattr(member, "__endpoint__", False):
      found[name] = member
  return found


class TestAuthzSurface(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin
    cls.endpoints = _endpoints(PentesterApi01Plugin)

  def test_the_surface_is_the_size_we_think_it_is(self):
    # A new endpoint must be added here consciously, not silently.
    self.assertEqual(len(self.endpoints), EXPECTED_ENDPOINTS, sorted(self.endpoints))

  def test_exact_inventory_and_original_first_arguments_are_preserved(self):
    actual = {}
    for name, fn in self.endpoints.items():
      parameters = list(inspect.signature(fn).parameters)[1:]
      actual[name] = parameters[0] if parameters else None
    self.assertEqual(actual, ENDPOINT_FIRST_ARGS)

  def test_only_the_original_model_endpoints_require_the_bearer(self):
    protected = {n for n, fn in self.endpoints.items() if getattr(fn, "__require_token__", False)}
    self.assertEqual(protected, TOKEN_ENDPOINTS)

  def test_model_endpoints_have_token_first_and_ordinary_endpoints_have_no_token(self):
    # Mirrors fast_api_web_app.py registration: all_params[0] must be 'token' under require_token.
    bad = []
    for name, fn in self.endpoints.items():
      params = [p.name for p in inspect.signature(fn).parameters.values()
                if p.kind is not inspect.Parameter.VAR_KEYWORD]
      if (name in TOKEN_ENDPOINTS and params[:2] != ["self", "token"]) or (name not in TOKEN_ENDPOINTS and "token" in params):
        bad.append((name, params[:3]))
    self.assertEqual(bad, [])

  def test_wrong_token_is_denied_before_any_body_runs(self):
    for name in TOKEN_ENDPOINTS:
      fn = self.endpoints[name]
      with self.subTest(endpoint=name):
        plugin = MagicMock()
        with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
          result = fn(plugin, "not-the-channel-token")
        self.assertEqual(result["status_code"], 403, name)
        self.assertEqual(result["error_class"], "backend_auth_invalid", name)
        # The body of every endpoint starts by touching the plugin (self.*); a denial must not.
        self.assertEqual(plugin.method_calls, [], name)
        self.assertNotIn(TEST_CHANNEL_TOKEN, str(result), name)

  def test_missing_token_is_401_and_unconfigured_deployment_fails_closed(self):
    for name in TOKEN_ENDPOINTS:
      fn = self.endpoints[name]
      with self.subTest(endpoint=name):
        plugin = MagicMock()
        with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
          self.assertEqual(fn(plugin, "")["status_code"], 401)
        with patch.dict("os.environ", {}, clear=True):
          self.assertEqual(fn(plugin, TEST_CHANNEL_TOKEN)["error_class"], "backend_auth_unavailable")
        self.assertEqual(plugin.method_calls, [])

  def test_ordinary_calls_work_without_any_token_configuration(self):
    plugin = MagicMock()
    plugin._get_job_status.return_value = {"job_id": "job-123"}
    with patch.dict("os.environ", {}, clear=True), \
         patch("extensions.business.cybersec.red_mesh.pentester_api_01.get_capability_status", return_value={"ok": True}):
      self.assertEqual(self.Plugin.get_capability_status(plugin), {"ok": True})
      self.assertEqual(self.Plugin.get_job_status(plugin, "job-123"), {"job_id": "job-123"})
    plugin._get_job_status.assert_called_once_with("job-123")

  def test_protected_operations_deny_before_the_real_account_store_or_downstream_call(self):
    for name in TOKEN_ENDPOINTS:
      for token, configured, expected_status in (("", TEST_CHANNEL_TOKEN, 401),
                                               ("wrong-token", TEST_CHANNEL_TOKEN, 403),
                                               (TEST_CHANNEL_TOKEN, "", 401)):
        with self.subTest(endpoint=name, status=expected_status, configured=bool(configured)):
          plugin = object.__new__(self.Plugin)
          plugin.chainstore_hget = MagicMock(side_effect=AssertionError("must not read the store"))
          with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": configured, "R1EN_CSTORE_AUTH_HKEY": "app:auth"}, clear=True), \
               patch(f"extensions.business.cybersec.red_mesh.pentester_api_01.{name}") as downstream:
            kwargs = {"actor": {"account_id": "ops.user"}} if name == "launch_model_test" else {}
            result = self.endpoints[name](plugin, token, **kwargs)
          self.assertEqual(result["status_code"], expected_status)
          plugin.chainstore_hget.assert_not_called()
          downstream.assert_not_called()

  def test_launch_endpoints_deny_a_missing_or_unknown_actor_before_launching(self):
    from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView

    for name in ("launch_network_scan", "launch_webapp_scan", "launch_test", "launch_model_test"):
      with self.subTest(endpoint=name):
        plugin = MagicMock()
        plugin._resolve_launch_actor = lambda actor=None: (None, {"status_code": 404, "error_class": "actor_not_found"})
        with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
          result = _call_launch(self.endpoints[name], plugin)
        self.assertEqual(result["status_code"], 404, name)

        # And a resolved actor overrides whatever created_by_* the request carried.
        seen = {}
        plugin = MagicMock()
        plugin._resolve_launch_actor = lambda actor=None: (AccountView("ops.user", "admin", None, True), None)
        target = {
          "launch_network_scan": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_network_scan",
          "launch_webapp_scan": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_webapp_scan",
          "launch_test": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_test",
          "launch_model_test": "extensions.business.cybersec.red_mesh.pentester_api_01.launch_model_test",
        }[name]
        with patch(target, side_effect=lambda self_, **kw: seen.update(kw) or {"ok": True}), \
             patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN}):
          _call_launch(self.endpoints[name], plugin, created_by_name="spoofed", created_by_id="spoofed")
        self.assertEqual((seen.get("created_by_name"), seen.get("created_by_id")), ("ops.user", "ops.user"), name)

  def test_the_production_actor_seam_reads_the_account_store(self):
    # The seam resolves through cstore-auth; a MagicMock store yields "not found", never "allowed".
    plugin = MagicMock()
    with patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "app:auth"}):
      view, err = self.Plugin._resolve_launch_actor(plugin, {"account_id": "someone"})
    self.assertIsNone(view)
    self.assertEqual(err["status_code"], 404)

  def test_launch_endpoints_reject_explicitly_non_active_stored_accounts(self):
    for name in ("launch_network_scan", "launch_webapp_scan", "launch_test", "launch_model_test"):
      for state in (None, "deleting", "", False, 0, [], {}):
        with self.subTest(endpoint=name, state=state):
          plugin = object.__new__(self.Plugin)
          plugin.chainstore_hget = MagicMock(return_value={
            "type": "simple", "role": "user", "metadata": {"navigatorAccountState": state},
          })
          target = f"extensions.business.cybersec.red_mesh.pentester_api_01.{name}"
          with patch(target, return_value={"unexpected_launch": True}) as launch, \
               patch.dict("os.environ", {
                 "REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN,
                 "R1EN_CSTORE_AUTH_HKEY": "app:auth",
               }):
            result = _call_launch(self.endpoints[name], plugin, actor={"account_id": "ops.user"})
          self.assertEqual(result.get("status_code"), 404)
          self.assertEqual(result.get("error_class"), "actor_not_found")
          launch.assert_not_called()

  def test_real_reader_denials_stop_all_four_launchers(self):
    cases = (
      ("missing actor", None, None, None, "app:auth", 404),
      ("unknown actor", {"account_id": "ops.user"}, None, None, "app:auth", 404),
      ("tombstoned actor", {"account_id": "ops.user"}, "null", None, "app:auth", 404),
      ("missing hkey", {"account_id": "ops.user"}, {}, None, "", 503),
      ("store failure", {"account_id": "ops.user"}, None, ConnectionError("private store detail"), "app:auth", 503),
    )
    for name in LAUNCH_ENDPOINTS:
      for label, actor, record, failure, hkey, status in cases:
        with self.subTest(endpoint=name, case=label):
          plugin = object.__new__(self.Plugin)
          plugin.chainstore_hget = MagicMock(return_value=record, side_effect=failure)
          env = {"R1EN_CSTORE_AUTH_HKEY": hkey}
          if name == "launch_model_test":
            env["REDMESH_BACKEND_TOKEN"] = TEST_CHANNEL_TOKEN
          with patch.dict("os.environ", env, clear=True), \
               patch(f"extensions.business.cybersec.red_mesh.pentester_api_01.{name}") as launch:
            result = _call_launch(self.endpoints[name], plugin, actor=actor)
          self.assertEqual(result["status_code"], status)
          self.assertEqual(result["error_class"], "actor_not_found" if status == 404 else "identity_store_unavailable")
          self.assertNotIn("private store detail", str(result))
          launch.assert_not_called()
          if actor is None or not hkey:
            plugin.chainstore_hget.assert_not_called()
          else:
            plugin.chainstore_hget.assert_called_once_with(hkey=hkey, key="ops.user")

  def test_real_active_account_overrides_request_attribution_without_new_token(self):
    for name in LAUNCH_ENDPOINTS:
      for metadata in ({}, {"navigatorAccountState": "active"}):
        with self.subTest(endpoint=name, metadata=metadata):
          plugin = object.__new__(self.Plugin)
          plugin.chainstore_hget = MagicMock(return_value={"type": "simple", "role": "user", "metadata": metadata})
          env = {"R1EN_CSTORE_AUTH_HKEY": "app:auth"}
          if name == "launch_model_test":
            env["REDMESH_BACKEND_TOKEN"] = TEST_CHANNEL_TOKEN + "\n"
          with patch.dict("os.environ", env, clear=True), \
               patch(f"extensions.business.cybersec.red_mesh.pentester_api_01.{name}", return_value={"ok": True}) as launch:
            result = _call_launch(self.endpoints[name], plugin, actor={"account_id": " Ops.User ", "role": "admin"},
                                  created_by_name="spoofed", created_by_id="spoofed")
          self.assertEqual(result, {"ok": True})
          plugin.chainstore_hget.assert_called_once_with(hkey="app:auth", key="ops.user")
          self.assertEqual(launch.call_args.kwargs["created_by_name"], "ops.user")
          self.assertEqual(launch.call_args.kwargs["created_by_id"], "ops.user")

  def test_real_reader_rejects_malformed_schema_versions_before_launch(self):
    for name in LAUNCH_ENDPOINTS:
      for version in ([], {}, True, False, 1.0, 0.0, "1", None):
        with self.subTest(endpoint=name, version=version):
          plugin = object.__new__(self.Plugin)
          plugin.chainstore_hget = MagicMock(return_value={"type": "simple", "schemaVersion": version})
          env = {"R1EN_CSTORE_AUTH_HKEY": "app:auth"}
          if name == "launch_model_test":
            env["REDMESH_BACKEND_TOKEN"] = TEST_CHANNEL_TOKEN
          with patch.dict("os.environ", env, clear=True), \
               patch(f"extensions.business.cybersec.red_mesh.pentester_api_01.{name}") as launch:
            result = _call_launch(self.endpoints[name], plugin, actor={"account_id": "ops.user"})
          self.assertEqual(result["status_code"], 404)
          self.assertEqual(result["error_class"], "actor_not_found")
          launch.assert_not_called()

  def test_preflight_accepts_trimmed_configured_token(self):
    with patch.dict("os.environ", {"REDMESH_BACKEND_TOKEN": TEST_CHANNEL_TOKEN + "\n"}, clear=True), \
         patch("extensions.business.cybersec.red_mesh.pentester_api_01.preflight_model_test_provider", return_value={"ok": True}) as preflight:
      self.assertEqual(self.Plugin.preflight_model_test_provider(MagicMock(), TEST_CHANNEL_TOKEN), {"ok": True})
    preflight.assert_called_once()



class TestInternalCallersDoNotReenterEndpoints(unittest.TestCase):
  """Internal calls use module implementations after the public entrypoint checks. Review found
  three such re-entries that
  the surface test above cannot see (it enumerates decorators, not callers)."""

  ENDPOINT_HOSTS = ("pentester_api_01.py", "services", "mixins", "api_mixins", "worker")

  def test_no_plugin_code_calls_an_endpoint_method(self):
    import pathlib
    import re

    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    names = "|".join(sorted(_endpoints(PentesterApi01Plugin)))
    pattern = re.compile(r"\b(owner|self|plugin)\.(%s)\s*\(" % names)
    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
      rel = path.relative_to(root)
      if rel.parts[0] == "tests" or not (rel.parts[0] in self.ENDPOINT_HOSTS or str(rel) in self.ENDPOINT_HOSTS):
        continue
      for lineno, line in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(line) and not line.lstrip().startswith(("def ", "#")):
          offenders.append(f"{rel}:{lineno}: {line.strip()}")
    self.assertEqual(offenders, [])

  def test_launch_test_compat_shim_reaches_the_module_launcher_with_attribution(self):
    from extensions.business.cybersec.red_mesh.services import launch_api
    from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView

    plugin = MagicMock()
    plugin._resolve_launch_actor = lambda actor=None: (AccountView("ops.user", "admin", None, True), None)
    seen = {}
    with patch.object(launch_api, "launch_network_scan", side_effect=lambda owner, **kw: seen.update(kw) or {"ok": True}):
      result = self.Plugin.launch_test(
        plugin, target="example.com", scan_type="network", authorized=True,
        actor={"account_id": "ops.user"},
      )
    self.assertEqual(result, {"ok": True})
    self.assertEqual((seen.get("created_by_name"), seen.get("created_by_id")), ("ops.user", "ops.user"))

  @classmethod
  def setUpClass(cls):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin


if __name__ == "__main__":
  unittest.main()
