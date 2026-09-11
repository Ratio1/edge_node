"""Production finalizers retain the original execution binding through archive and stub writes."""
from copy import deepcopy
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest

from . import test_api as archive_fixtures
from .test_execution_binding_models import binding_payload
from .test_model_testing import _owner, _provider, PUBLIC_TEST_IP


PLUGIN = "extensions.business.cybersec.red_mesh.pentester_api_01."


class TestTenantExecutionArchive(unittest.TestCase):
  def storage(self, plugin, job_specs, get_original_artifact):
    """Exercise actual repositories with read-back of exactly what the finalizer writes."""
    records = {(plugin.cfg_instance_id, job_specs["job_id"]): deepcopy(job_specs)}
    artifacts = {}

    def set_record(*, hkey, key, value, **kwargs):
      records[(hkey, key)] = deepcopy(value)
      return True

    def put_artifact(payload, **kwargs):
      cid = "archive-" + str(len(artifacts) + 1)
      artifacts[cid] = deepcopy(payload)
      return cid

    plugin.chainstore_hget = MagicMock(side_effect=lambda *, hkey, key: deepcopy(records.get((hkey, key))))
    plugin.chainstore_hset = MagicMock(side_effect=set_record)
    plugin.r1fs.add_json = MagicMock(side_effect=put_artifact)
    plugin.r1fs.get_json = MagicMock(side_effect=lambda cid: deepcopy(
      artifacts[cid] if cid in artifacts else get_original_artifact(cid)))
    plugin.cfg_archive_verify_retries = 1
    plugin._write_job_record = lambda job_id, value, **kwargs: self.Plugin._write_job_record(
      plugin, job_id, value, **kwargs)
    return records, artifacts

  def ready(self, kind):
    fixture = archive_fixtures.TestPhase3Archive()
    self.Plugin = fixture._get_plugin_class()
    binding = {**binding_payload(), "original_launcher": "launcher-node", "participant_order": ["worker-A"]}
    if kind == "network":
      plugin, specs, _, config = fixture._build_archive_plugin()
      config.update(scan_type="network", target=binding["asset_target"]["address"], target_url="")
      specs.update(scan_type="network", target=binding["asset_target"]["address"], target_url="")
      get_artifact = plugin.r1fs.get_json.side_effect
    else:
      target = {"kind": "model", "adapter": "openai_compatible", "model": "unit-model",
                "endpointUrl": f"https://{PUBLIC_TEST_IP}/v1/chat/completions"}
      binding = {**binding, "asset_target": target, "asset_target_digest": canonical_digest(target)}
      plugin = _owner(P=MagicMock(), cfg_model_testing={"ENABLED": True})
      specs = {"job_id": "model-job", "job_status": "RUNNING", "job_type": "model_test", "scan_type": "model_test",
        "job_pass": 1, "run_mode": "SINGLEPASS", "launcher": "launcher-node", "launcher_alias": "Launcher",
        "target": "Unit Provider / unit-model", "task_name": "Test", "start_port": 0, "end_port": 0,
        "date_created": 100.0, "job_config_cid": "model-config", "timeline": [],
        "workers": {"worker-A": {"finished": True, "assignment_revision": 1}},
        "model_test_node_selection": {"selected_execution_node": "worker-A"}}
      config = {"job_id": "model-job", "job_type": "model_test", "scan_type": "model_test",
        "tested_model": {**_provider(), "api_key": "test-only-secret"}, "evaluator_model": {},
        "raw_evidence": {"requested": False}, "model_provider_secret_ref": "test-only-secret-cid"}
      get_artifact = lambda cid: config if cid == "model-config" else None
    config["execution_binding"] = deepcopy(binding)
    specs["execution_binding"] = deepcopy(binding)
    records, artifacts = self.storage(plugin, specs, get_artifact)
    return plugin, specs, config, binding, records, artifacts

  def finalize(self, kind, plugin, specs, job_id=None):
    job_id = specs["job_id"] if job_id is None else job_id
    if kind == "network":
      return self.Plugin._build_job_archive(plugin, job_id, specs)
    return self.Plugin._finalize_model_test_job(plugin, job_id, specs,
      {"model_test_results": {"overall_status": "complete", "cases": []},
       "model_test_summary": {"overall_status": "complete"}}, "worker-report")

  def assert_denied_without_writes(self, kind, plugin, specs, job_id=None):
    with patch(PLUGIN + "write_raw_evidence_artifact") as raw_evidence, \
         patch("extensions.business.cybersec.red_mesh.services.secrets.R1fsSecretStore") as secrets:
      try:
        result = self.finalize(kind, plugin, specs, job_id=job_id)
      except ValueError:
        result = False
      self.assertFalse(result)
      raw_evidence.assert_not_called()
      secrets.assert_not_called()
    plugin.r1fs.add_json.assert_not_called()
    plugin.chainstore_hset.assert_not_called()

  def test_original_binding_roundtrips_through_production_archive_and_finalized_repository(self):
    for kind in ("network", "model"):
      with self.subTest(kind=kind):
        plugin, specs, config, binding, _, artifacts = self.ready(kind)
        original = deepcopy(config)
        self.finalize(kind, plugin, specs)
        self.assertEqual(len(artifacts), 1)
        archive = artifacts["archive-1"]
        self.assertEqual(archive["job_config"]["execution_binding"], binding)
        repo = self.Plugin._get_job_state_repository(plugin)
        self.assertIsInstance(repo, JobStateRepository)
        stub = repo.get_finalized_job(specs["job_id"]).to_dict()
        self.assertEqual(stub["execution_binding"], binding)
        self.assertEqual(stub["job_cid"], "archive-1")
        self.assertEqual(plugin.r1fs.get_json(stub["job_config_cid"]), original)
        self.assertEqual(config, original)
        self.assertEqual(archive["job_config"]["execution_binding"]["node_failure_policy"], "stop")
        if kind == "model":
          self.assertNotIn("model_provider_secret_ref", archive["job_config"])
          self.assertNotIn("api_key", archive["job_config"]["tested_model"])
        else:
          self.assertNotIn("super-secret", str(archive))

  def test_cached_archive_requires_matching_requested_supplied_and_stored_job_ids(self):
    for kind in ("network", "model"):
      for side in ("stored", "supplied"):
        for value in ("different-job", "", None):
          with self.subTest(kind=kind, side=side, value=value):
            plugin, specs, _, _, records, _ = self.ready(kind)
            job_id = specs["job_id"]
            current = records[(plugin.cfg_instance_id, job_id)]
            current["job_cid"] = "cached-archive"
            record = current if side == "stored" else specs
            if value is None:
              record.pop("job_id")
            else:
              record["job_id"] = value
            self.assert_denied_without_writes(kind, plugin, specs, job_id=job_id)
            plugin.r1fs.get_json.assert_not_called()

  def test_boolean_counters_cannot_alias_the_captured_integer_snapshot(self):
    for kind in ("network", "model"):
      for field in ("job_pass", "job_revision"):
        with self.subTest(kind=kind, field=field):
          plugin, specs, _, _, records, _ = self.ready(kind)
          specs[field] = 1
          records[(plugin.cfg_instance_id, specs["job_id"])][field] = True
          self.assert_denied_without_writes(kind, plugin, specs)

  def test_invalid_present_counters_deny_on_either_snapshot_even_when_values_match(self):
    for kind in ("network", "model"):
      for field in ("job_pass", "job_revision"):
        invalid_values = (True, False, 1.0, "1", None, -1) + ((0,) if field == "job_pass" else ())
        for value in invalid_values:
          for side in ("stored", "supplied", "both"):
            for cached in (False, True):
              with self.subTest(kind=kind, field=field, value=value, side=side, cached=cached):
                plugin, specs, _, _, records, _ = self.ready(kind)
                current = records[(plugin.cfg_instance_id, specs["job_id"])]
                plugin._clear_live_progress = MagicMock()
                if cached:
                  current["job_cid"] = "cached-archive"
                if side in ("stored", "both"):
                  current[field] = value
                if side in ("supplied", "both"):
                  specs[field] = value
                self.assert_denied_without_writes(kind, plugin, specs)
                plugin.r1fs.get_json.assert_not_called()
                plugin.r1fs.delete_file.assert_not_called()
                plugin._clear_live_progress.assert_not_called()

  def test_real_finalized_stub_and_original_live_snapshot_can_reuse_the_same_archive(self):
    for kind in ("network", "model"):
      with self.subTest(kind=kind):
        plugin, specs, _, _, records, artifacts = self.ready(kind)
        specs.update(job_pass=1, job_revision=0)
        records[(plugin.cfg_instance_id, specs["job_id"])].update(job_pass=1, job_revision=0)
        original_live_snapshot = deepcopy(specs)
        self.finalize(kind, plugin, specs)
        self.assertEqual(len(artifacts), 1)
        repo = self.Plugin._get_job_state_repository(plugin)
        finalized = repo.get_finalized_job(specs["job_id"]).to_dict()
        self.assertNotIn("job_pass", finalized)
        self.assertNotIn("job_revision", finalized)
        plugin.r1fs.get_json.reset_mock()
        plugin.r1fs.add_json.reset_mock()
        plugin.chainstore_hset.reset_mock()
        for snapshot in (original_live_snapshot, finalized):
          self.assertEqual(self.finalize(kind, plugin, snapshot), "archive-1" if kind == "network" else True)
        plugin.r1fs.get_json.assert_not_called()
        plugin.r1fs.add_json.assert_not_called()
        plugin.chainstore_hset.assert_not_called()

  def test_counter_types_are_rechecked_after_slow_archive_reads(self):
    for kind in ("network", "model"):
      for field in ("job_pass", "job_revision"):
        with self.subTest(kind=kind, field=field):
          plugin, specs, _, _, records, artifacts = self.ready(kind)
          current = records[(plugin.cfg_instance_id, specs["job_id"])]
          specs[field] = current[field] = 1
          original_read = plugin.r1fs.get_json.side_effect

          def read(cid):
            result = original_read(cid)
            if cid == specs["job_config_cid"]:
              current[field] = True
            return result

          plugin.r1fs.get_json.side_effect = read
          self.assert_denied_without_writes(kind, plugin, specs)
          self.assertEqual(artifacts, {})

  def test_config_binding_mismatch_denies_before_archive_raw_evidence_or_secret_writes(self):
    for kind in ("network", "model"):
      for mutation in ("missing", "null", "changed_policy", "changed_actor"):
        with self.subTest(kind=kind, mutation=mutation):
          plugin, specs, config, _, _, _ = self.ready(kind)
          if mutation == "missing":
            config.pop("execution_binding")
          elif mutation == "null":
            config["execution_binding"] = None
          elif mutation == "changed_policy":
            config["execution_binding"]["node_failure_policy"] = "continue"
          else:
            config["execution_binding"]["actor_id"] = "replacement"
          self.assert_denied_without_writes(kind, plugin, specs)

  def test_redaction_must_not_drop_or_change_the_original_binding(self):
    for kind in ("network", "model"):
      with self.subTest(kind=kind):
        plugin, specs, config, _, _, _ = self.ready(kind)
        redacted = {key: value for key, value in config.items() if key != "execution_binding"}
        if kind == "network":
          plugin._redact_job_config = lambda value: redacted
          self.assert_denied_without_writes(kind, plugin, specs)
        else:
          with patch(PLUGIN + "sanitize_model_test_job_config_for_archive", return_value=redacted):
            self.assert_denied_without_writes(kind, plugin, specs)

  def test_stale_supplied_binding_cannot_overwrite_different_current_job_binding(self):
    for kind in ("network", "model"):
      for mutation in ("changed_binding", "missing_current", "changed_owner"):
        with self.subTest(kind=kind, mutation=mutation):
          plugin, specs, _, _, records, _ = self.ready(kind)
          key = (plugin.cfg_instance_id, specs["job_id"])
          if mutation == "changed_binding":
            records[key]["execution_binding"]["node_failure_policy"] = "continue"
          elif mutation == "missing_current":
            records.pop(key)
          else:
            records[key]["launcher"] = "replacement-owner"
          self.assert_denied_without_writes(kind, plugin, specs)

  def test_slow_archive_reads_cannot_publish_a_stale_execution_snapshot(self):
    for kind in ("network", "model"):
      for mutation in ("owner", "binding", "pass", "revision", "config"):
        with self.subTest(kind=kind, mutation=mutation):
          plugin, specs, _, _, records, artifacts = self.ready(kind)
          plugin._log_audit_event = MagicMock()
          plugin._clear_live_progress = MagicMock()
          original_read = plugin.r1fs.get_json.side_effect
          current = records[(plugin.cfg_instance_id, specs["job_id"])]

          def read(cid):
            result = original_read(cid)
            if cid == specs["job_config_cid"]:
              if mutation == "owner":
                current["launcher"] = "replacement-owner"
              elif mutation == "binding":
                current["execution_binding"]["node_failure_policy"] = "continue"
              elif mutation == "pass":
                current["job_pass"] = current.get("job_pass", 1) + 1
              elif mutation == "revision":
                current["job_revision"] = current.get("job_revision", 0) + 1
              else:
                current["job_config_cid"] = "replacement-config"
            return result

          plugin.r1fs.get_json.side_effect = read
          self.assert_denied_without_writes(kind, plugin, specs)
          self.assertEqual(artifacts, {})
          plugin._clear_live_progress.assert_not_called()
          plugin.r1fs.delete_file.assert_not_called()

  def test_archive_verification_or_rejected_commit_never_clears_live_rows_or_claims_success(self):
    for kind in ("network", "model"):
      for phase in ("archive_write", "archive_verify", "stub_commit"):
        with self.subTest(kind=kind, phase=phase):
          plugin, specs, _, _, records, artifacts = self.ready(kind)
          plugin._log_audit_event = MagicMock()
          plugin._clear_live_progress = MagicMock()
          key = (plugin.cfg_instance_id, specs["job_id"])
          original_read = plugin.r1fs.get_json.side_effect
          original_add = plugin.r1fs.add_json.side_effect
          original_commit = self.Plugin._write_job_record

          def change_owner():
            records[key]["launcher"] = "replacement-owner"

          def read(cid):
            result = original_read(cid)
            if phase == "archive_verify" and cid in artifacts:
              change_owner()
            return result

          def add(payload, **kwargs):
            result = original_add(payload, **kwargs)
            if phase == "archive_write":
              change_owner()
            return result

          def commit(owner, job_id, value, **kwargs):
            if phase == "stub_commit":
              change_owner()
            return original_commit(owner, job_id, value, **kwargs)

          plugin.r1fs.get_json.side_effect = read
          plugin.r1fs.add_json.side_effect = add
          with patch.object(self.Plugin, "_write_job_record", new=commit):
            result = self.finalize(kind, plugin, specs)
          self.assertFalse(result)
          self.assertEqual(len(artifacts), 1)
          self.assertFalse(records[key].get("job_cid"))
          plugin.chainstore_hset.assert_not_called()
          plugin._clear_live_progress.assert_not_called()
          plugin.r1fs.delete_file.assert_not_called()

  def test_archive_commit_rechecks_the_full_snapshot_on_its_own_current_read(self):
    mutations = (("job_id", "different-job"), ("job_id", None),
      ("job_pass", 2), ("job_config_cid", "different-config"), ("job_cid", "foreign-archive"))
    mutations += tuple((field, value) for field in ("job_pass", "job_revision")
      for value in (True, False, 1.0, "1", None, -1))
    for kind in ("network", "model"):
      for field, value in mutations:
        with self.subTest(kind=kind, field=field, value=value):
          plugin, specs, _, _, records, artifacts = self.ready(kind)
          key = (plugin.cfg_instance_id, specs["job_id"])
          specs.update(job_pass=1, job_revision=1)
          records[key].update(job_pass=1, job_revision=1)
          plugin._log_audit_event = MagicMock()
          plugin._clear_live_progress = MagicMock()
          original_commit = self.Plugin._write_job_record

          def commit(owner, job_id, incoming, **kwargs):
            records[key][field] = value
            return original_commit(owner, job_id, incoming, **kwargs)

          with patch.object(self.Plugin, "_write_job_record", new=commit):
            result = self.finalize(kind, plugin, specs)
          self.assertFalse(result)
          self.assertEqual(len(artifacts), 1)
          self.assertEqual(records[key].get("job_cid"), value if field == "job_cid" else None)
          plugin.chainstore_hset.assert_not_called()
          plugin._clear_live_progress.assert_not_called()
          plugin.r1fs.delete_file.assert_not_called()

  def test_bound_archive_writer_requires_a_bound_snapshot_and_valid_incoming_identity(self):
    for kind in ("network", "model"):
      for mutation in ("missing_snapshot", "unbound_snapshot", "foreign_incoming_id", "boolean_incoming_pass"):
        with self.subTest(kind=kind, mutation=mutation):
          plugin, specs, _, _, records, _ = self.ready(kind)
          key = (plugin.cfg_instance_id, specs["job_id"])
          snapshot = deepcopy(specs)
          self.finalize(kind, plugin, specs)
          incoming = deepcopy(records[key])
          records[key] = deepcopy(snapshot)
          if mutation == "missing_snapshot":
            snapshot = None
          elif mutation == "unbound_snapshot":
            snapshot.pop("execution_binding")
          elif mutation == "foreign_incoming_id":
            incoming["job_id"] = "different-job"
          else:
            incoming["job_pass"] = True
          plugin.chainstore_hset.reset_mock()
          result = self.Plugin._write_job_record(plugin, specs["job_id"], incoming,
            context="archive_prune" if kind == "network" else "model_test_archive_prune",
            expected_revision=0, reject_stale=True, expected_archive_snapshot=snapshot)
          self.assertIsNone(result)
          plugin.chainstore_hset.assert_not_called()

  def test_bound_network_cleanup_follows_confirmed_commit_and_stops_after_owner_change(self):
    plugin, specs, _, binding, records, _ = self.ready("network")
    key = (plugin.cfg_instance_id, specs["job_id"])

    def clear_live(job_id, workers):
      self.assertEqual(job_id, specs["job_id"])
      self.assertEqual(records[key]["job_cid"], "archive-1")
      self.assertEqual(records[key]["execution_binding"], binding)
      self.assertEqual(workers, list(specs["workers"]))
      records[key]["launcher"] = "replacement-owner"

    plugin._clear_live_progress = MagicMock(side_effect=clear_live)
    self.finalize("network", plugin, specs)
    plugin._clear_live_progress.assert_called_once()
    plugin.r1fs.delete_file.assert_not_called()
