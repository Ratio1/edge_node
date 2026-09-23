"""Strict binding preservation across public model/repository serialization seams."""
import unittest
import copy
from dataclasses import FrozenInstanceError
from uuid import uuid4

from extensions.business.cybersec.red_mesh.models import JobConfig, JobArchive, CStoreJobRunning, CStoreJobFinalized
from extensions.business.cybersec.red_mesh.model_testing.artifacts import ModelTestJobConfig, ModelTestArchive
from extensions.business.cybersec.red_mesh.repositories.cstore import JobStateRepository
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.execution import ExecutionBinding
from .test_tenant_administration import FakeAdministrationStore


def binding_payload():
  target = {"kind": "network", "address": "192.0.2.10"}
  return {"schema_version": 1, "namespace": "deployment", "tenant_id": "tn_" + str(uuid4()),
          "asset_id": "as_" + str(uuid4()), "asset_target": target,
          "asset_target_digest": canonical_digest(target), "actor_id": "actor",
          "actor_generation": "generation-1", "node_failure_policy": "stop",
          "original_launcher": "coordinator", "participant_order": ["node-b", "node-a"]}


class TestExecutionBindingModels(unittest.TestCase):
  def test_scan_config_preserves_binding_and_rejects_present_null(self):
    binding = binding_payload()
    config = {"target": "192.0.2.10", "start_port": 1, "end_port": 100, "execution_binding": binding}
    self.assertEqual(JobConfig.from_dict(config).to_dict()["execution_binding"], binding)
    with self.assertRaises(ValueError):
      JobConfig.from_dict({**config, "execution_binding": None})

  def payloads(self, binding):
    scan = {"target": "192.0.2.10", "start_port": 1, "end_port": 100}
    running = {**scan, "job_id": "job-1", "job_status": "RUNNING", "run_mode": "SINGLEPASS",
               "launcher": "coordinator", "date_created": 1, "job_config_cid": "config"}
    finalized = {**running, "job_status": "FINALIZED", "job_cid": "archive", "date_completed": 2}
    return [(JobConfig, {**scan, "execution_binding": binding}),
            (ModelTestJobConfig, {"job_type": "model_test", "execution_binding": binding}),
            (CStoreJobRunning, {**running, "execution_binding": binding}),
            (CStoreJobFinalized, {**finalized, "execution_binding": binding})]

  def test_all_typed_models_roundtrip_and_legacy_absence(self):
    for target in ({"kind": "network", "address": "192.0.2.10"},
                   {"kind": "webapp", "url": "https://example.com/api", "allowedPathPrefix": "/api"},
                   {"kind": "model", "adapter": "openai_compatible", "endpointUrl": "https://example.com/v1/chat/completions", "model": "model-A"}):
      binding = {**binding_payload(), "asset_target": target, "asset_target_digest": canonical_digest(target)}
      for model, raw in self.payloads(binding):
        with self.subTest(target=target["kind"], model=model.__name__):
          original = copy.deepcopy(raw)
          value = model.from_dict(raw)
          raw["execution_binding"]["participant_order"].append("injected")
          self.assertEqual(value.to_dict()["execution_binding"], original["execution_binding"])
          self.assertEqual(model.from_dict(value.to_dict()).to_dict(), value.to_dict())
          self.assertNotIn("_snapshot", str(value.to_dict()))
          raw["execution_binding"]["participant_order"].pop()
          raw.pop("execution_binding")
          self.assertNotIn("execution_binding", model.from_dict(raw).to_dict())

  def test_exact_wire_fields_and_malformed_present_values_reject(self):
    good = binding_payload()
    invalid = [None, {}, [], "binding"]
    invalid += [{key: value for key, value in good.items() if key != missing} for missing in good]
    invalid += [{**good, "extra": True}]
    for name, values in {
      "schema_version": (True, False, 1.0, "1", 2),
      "namespace": (None, "", " "), "actor_id": (None, [], " ACTOR "),
      "actor_generation": (None, "", 1), "tenant_id": ("tenant", "tn_bad"),
      "asset_id": ("asset", "as_bad"), "asset_target_digest": (None, "0" * 64),
      "node_failure_policy": (None, "STOP", True), "original_launcher": (None, "node with space"),
      "participant_order": ([], ["node-a", "node-a"], [None], "node-a"),
    }.items():
      invalid.extend({**good, name: value} for value in values)
    noncanonical = {"kind": "webapp", "url": "https://EXAMPLE.com/api", "allowedPathPrefix": "/api"}
    invalid.append({**good, "asset_target": noncanonical, "asset_target_digest": canonical_digest(noncanonical)})
    for malformed in invalid:
      with self.subTest(malformed=malformed):
        with self.assertRaises((ValueError, TypeError)):
          ExecutionBinding(malformed)
        for model, raw in self.payloads(malformed):
          with self.assertRaises((ValueError, TypeError)):
            model.from_dict(raw)

  def test_value_is_frozen_and_defensively_copied(self):
    raw = binding_payload()
    expected = copy.deepcopy(raw)
    value = ExecutionBinding(raw)
    raw["asset_target"]["address"] = "192.0.2.99"
    value.to_dict()["participant_order"].clear()
    self.assertEqual(value.to_dict(), expected)
    with self.assertRaises(FrozenInstanceError):
      value._snapshot = "{}"

  def test_nested_archives_validate_only_additive_field(self):
    binding = binding_payload()
    for model in (JobArchive, ModelTestArchive):
      raw = {"job_id": "job-1", "job_config": {"legacy_partial": True, "execution_binding": binding}}
      with self.subTest(model=model.__name__):
        value = model.from_dict(raw)
        raw["job_config"]["execution_binding"]["participant_order"].append("injected")
        self.assertNotIn("injected", value.to_dict()["job_config"]["execution_binding"]["participant_order"])
        binding["participant_order"].pop()
        self.assertEqual(model.from_dict(value.to_dict()).to_dict(), value.to_dict())
        output = value.to_dict()
        self.assertNotIn("_execution_binding", output)
        self.assertNotIn("_snapshot", str(output))
        output["job_config"]["execution_binding"]["actor_id"] = "output-change"
        output["job_config"].pop("execution_binding")
        self.assertEqual(value.to_dict()["job_config"]["execution_binding"], binding)
        for malformed in (None, {}, {**binding, "schema_version": True}):
          with self.assertRaises(ValueError):
            model.from_dict({**raw, "job_config": {"execution_binding": malformed}})
        raw["job_config"].pop("execution_binding")
        self.assertEqual(model.from_dict(raw).to_dict()["job_config"], {"legacy_partial": True})

  def test_repository_coercion_never_discards_malformed_binding_into_legacy(self):
    owner = FakeAdministrationStore()
    owner.cfg_instance_id = "jobs"
    repo = JobStateRepository(owner)
    for model, raw in self.payloads(binding_payload())[2:]:
      with self.subTest(model=model.__name__):
        repo.put_job("job-1", raw)
        self.assertEqual(repo.get_job("job-1")["execution_binding"], raw["execution_binding"])
        getter = repo.get_running_job if model is CStoreJobRunning else repo.get_finalized_job
        self.assertIsNotNone(getter("job-1"))
        for malformed in (None, {}, {**binding_payload(), "schema_version": True}):
          repo.put_job("job-1", {**raw, "execution_binding": malformed})
          self.assertIn("execution_binding", repo.get_job("job-1"))
          self.assertEqual(repo.get_job("job-1")["execution_binding"], malformed)
          self.assertIsNone(getter("job-1"))

  def test_archive_public_config_cannot_change_or_remove_immutable_binding(self):
    for model in (JobArchive, ModelTestArchive):
      for mutation in ("actor", "replace", "remove"):
        with self.subTest(model=model.__name__, mutation=mutation):
          original = binding_payload()
          archive = model.from_dict({"job_id": "job-1", "job_config": {"execution_binding": original}})
          if mutation == "actor":
            archive.job_config["execution_binding"]["actor_id"] = "different"
          elif mutation == "replace":
            archive.job_config["execution_binding"] = binding_payload()
          else:
            archive.job_config.pop("execution_binding")
          with self.assertRaises(ValueError):
            archive.to_dict()
      with self.subTest(model=model.__name__, mutation="legacy_injection"):
        archive = model.from_dict({"job_id": "job-1", "job_config": {"legacy_partial": True}})
        archive.job_config["execution_binding"] = binding_payload()
        with self.assertRaises(ValueError):
          archive.to_dict()


class TestResolvedContextCarriesThePortScope(unittest.TestCase):
  """The asset's authorized port scope reaches the launch gate through the resolved context and
  stays out of the stored binding: the scope is launch-time policy, not execution identity."""

  def setUp(self):
    self.facts = {key: value for key, value in binding_payload().items()
                  if key not in ("schema_version", "original_launcher", "participant_order")}

  def _context(self, **extra):
    from extensions.business.cybersec.red_mesh.tenancy.execution import ResolvedExecutionContext
    return ResolvedExecutionContext({**self.facts, "selected_candidates": ["node-a"], **extra})

  def test_the_scope_is_carried_and_kept_out_of_the_binding(self):
    context = self._context(asset_authorized_ports="1-1024")
    self.assertEqual(context.to_dict()["asset_authorized_ports"], "1-1024")
    binding = context.build_binding("coordinator", ["node-a"]).to_dict()
    self.assertNotIn("asset_authorized_ports", binding)
    self.assertEqual(binding, self._context().build_binding("coordinator", ["node-a"]).to_dict())

  def test_a_non_canonical_or_null_scope_is_refused(self):
    for scope in ("1024-1", "22, 80", None, 80):
      with self.subTest(scope=scope), self.assertRaises(ValueError):
        self._context(asset_authorized_ports=scope)
