"""Write discipline of the coordinator worker, replayed on a fake clock.

The scenarios drive the real worker body (``_reconcile_coordinator_operations``)
every 2 s and count the coordinator's CStore operation writes. They reproduce
the 2026-11 CStore saturation: a node_relink stuck in ``restoring_previous``
without a runtime image binding, a ``finalizing`` commit rejected on every
retry, and a CStore outage. Set DEEPLOY_LEGACY_OPERATIONS to a copy of the
previous ``deployment_operations.py`` to replay them on that engine as well and
print the comparison (``LegacyComparisonTests``).
"""
import copy
import hashlib
import importlib.util
import json
import os
import pickle
import unittest
from unittest.mock import Mock

from extensions.business.deeploy.deeploy_const import CONTAINERIZED_APPS_SIGNATURES
from extensions.business.deeploy.deployment_operations import (
  _DeploymentOperationsMixin, OPERATIONS_HKEY, NODE_OPERATIONS_HKEY, required_instances,
)
from extensions.business.deeploy.tests.test_deployment_operations import Coordinator


TICK = 2
HOUR = 3600
CONTAINER = CONTAINERIZED_APPS_SIGNATURES[0]
BLOCKED = "Previous runtime image binding is unavailable; restoration is blocked."
REJECTED = "dAuth rejected secret reconciliation."


def legacy_mixin():
  """Load the engine named by DEEPLOY_LEGACY_OPERATIONS as a separate module."""
  path = os.environ.get("DEEPLOY_LEGACY_OPERATIONS")
  if not path:
    return None
  spec = importlib.util.spec_from_file_location("extensions.business.deeploy._legacy_deployment_operations", path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module._DeploymentOperationsMixin


class Simulation:
  """One coordinator double, a fake clock, simulated nodes and a write ledger."""

  def __init__(self, mixin=_DeploymentOperationsMixin, readiness_timeout=60):
    cls = Coordinator
    if mixin is not _DeploymentOperationsMixin:
      members = {key: value for key, value in vars(Coordinator).items()
                 if not key.startswith("__") or key == "__init__"}
      cls = type("LegacyCoordinator", (mixin,), members)
    self.plugin = plugin = cls()
    plugin.cfg_deployment_readiness_timeout = readiness_timeout
    self.logs = []
    plugin.P = lambda message, *args, **kwargs: self.logs.append(str(message))
    self.writes = []    # one dict per coordinator write to DEEPLOY_OPERATIONS
    self.peers = {}     # what peers hold: confirmed operation writes only
    self.outage = None  # None, "unconfirmed" (kept locally, not confirmed) or "raise"
    self.node_latency = None
    self.pending = []
    self.published = {}
    self.sizes = {}
    store, dispatch = plugin.chainstore_hset, plugin.cmdapi_start_pipeline

    def chainstore_hset(namespace, key, value, **kwargs):
      if self.outage == "raise":
        self.record(namespace, key, value, False)
        raise RuntimeError("CStore is unavailable.")
      plugin.replicate = self.outage is None
      accepted = store(namespace, key, value, **kwargs)
      self.record(namespace, key, value, accepted)
      return accepted

    def cmdapi_start_pipeline(config, node_address):
      dispatch(config, node_address)
      if self.node_latency is not None:
        meta = config["DEEPLOY_OPERATION"]
        status = "stopped" if meta["action"] in ("stop", "retire") else "ready"
        self.pending.append((plugin.now + self.node_latency, node_address, meta["attempt"], status))

    def chainstore_hgetall(namespace):
      # Same copy semantics as the double (and CStore reads), faster for long runs.
      return pickle.loads(pickle.dumps({key: value for (name, key), value in plugin.storage.items()
                                        if name == namespace}))

    plugin.chainstore_hset = chainstore_hset
    plugin.chainstore_hgetall = chainstore_hgetall
    plugin.cmdapi_start_pipeline = cmdapi_start_pipeline

  def record(self, namespace, key, value, accepted):
    if namespace != OPERATIONS_HKEY:
      return
    events = value.get("events") or [{}]
    marker = (key, value["sequence"], value.get("updated_at"), len(events), events[-1].get("message"))
    if marker not in self.sizes:
      self.sizes[marker] = len(json.dumps(value, default=str, separators=(",", ":")))
    self.writes.append(dict(time=self.plugin.now, sequence=value["sequence"], phase=value["phase"],
                            recovery=value.get("recovery"), message=events[-1].get("message"),
                            bytes=self.sizes[marker], accepted=accepted))
    if accepted:
      self.peers[key] = copy.deepcopy(value)

  def publish(self, operation_id, node, attempt, status):
    """Publish a node's signed attempt report once per status, as nodes do."""
    operation = self.plugin._operation_records()[operation_id]
    key = "{}|{}|{}".format(operation_id, attempt, node)
    if self.published.get(key, (0, None))[1] == status:
      return
    sequence = self.published.get(key, (0, None))[0] + 1
    self.published[key] = (sequence, status)
    plan = self.plugin.plan["configs" if attempt == "deploy" else "previous_configs"]
    instances = [dict(signature=signature, instance_id=instance, status=status)
                 for signature, instance in required_instances(plan[node])]
    self.plugin.storage[NODE_OPERATIONS_HKEY, key] = dict(
      operation_id=operation_id, coordinator="oracle", app_id="app", node_addr=node, attempt=attempt,
      revision=operation["target_revision"] if attempt == "deploy" else operation["previous_revision"],
      status=status, sequence=sequence, updated_at=self.plugin.now, instances=instances,
      EE_SIGN="valid", EE_SENDER=node,
    )

  def run(self, seconds, until=None):
    """Advance the clock tick by tick through the worker; stop early on ``until``."""
    end = self.plugin.now + seconds
    while self.plugin.now < end:
      self.plugin.now += TICK
      due = [item for item in self.pending if item[0] <= self.plugin.now]
      self.pending = [item for item in self.pending if item[0] > self.plugin.now]
      for _, node, attempt, status in due:
        self.publish(self.operation_id, node, attempt, status)
      self.plugin._reconcile_coordinator_operations()
      if until is not None and until():
        return True
    return False

  def latest(self):
    return self.plugin._operation_records()[self.operation_id]

  def phase_is(self, phase):
    return lambda: self.latest()["phase"] == phase

  def ledger(self, since=0):
    """Writes, snapshot bytes and new sequences since a time."""
    writes = [write for write in self.writes if write["time"] > since]
    return dict(writes=len(writes), bytes=sum(write["bytes"] for write in writes),
                sequences=len({write["sequence"] for write in writes} - self.sequences_before(since)))

  def sequences_before(self, since):
    return {write["sequence"] for write in self.writes if write["time"] <= since}

  def phases(self):
    """Externally visible phase order of the confirmed snapshots."""
    phases = []
    for write in sorted((write for write in self.writes if write["accepted"]), key=lambda write: write["sequence"]):
      if not phases or phases[-1] != write["phase"]:
        phases.append(write["phase"])
    return phases

  # Scenario fixtures ---------------------------------------------------------

  def relink_stuck_in_restore(self):
    """Job 66: a containerized node_relink whose restore has no image binding."""
    plugin = self.plugin
    self.operation_id = oid = hashlib.sha256(b"oracle").hexdigest()[:16] + "-relink"

    def config(revision, attempt):
      return {"NAME": "app", "TYPE": "Void", "OWNER": "owner",
              "DEEPLOY_SPECS": {"job_id": 66, "revision": revision, "secret_revision": oid + ":" + attempt},
              "PLUGINS": [{"SIGNATURE": CONTAINER, "INSTANCES": [{"INSTANCE_ID": "inst"}]}]}

    plugin.plan = {"configs": {"N": config(2, "deploy")}, "previous_configs": {"N": config(1, "restore")}}
    now = plugin.now
    history = [("preparing", "Preparing durable deployment data."), ("accepted", "Deployment accepted."),
               ("retiring_previous", "Preparing target nodes."),
               ("waiting_for_readiness", "Previous instances stopped; starting target nodes."),
               ("stopping_failed_rollout", "Stopping the failed rollout on all targets."),
               ("restoring_previous", "Restoring the previous revision.")]
    operation = dict(
      operation_id=oid, request_id="node-relink-66", request_hash="hash", kind="update", mutation="node_relink",
      job_id=66, app_id="app", owner="owner", network="test", coordinator="oracle", target_revision=2,
      previous_revision=1, previous_operation_id=None, previous_secret_revision=None, previous_pipeline_cid="legacy",
      plan_cid="plan", nodes=["N"], previous_nodes=["N"], instances={"N": [(CONTAINER, "inst")]},
      previous_instances={"N": [(CONTAINER, "inst")]}, phase="restoring_previous", outcome=None,
      recovery="in_progress", created_at=now, updated_at=now, deadline=now, recovery_started_at=now,
      restore_deadline=now + plugin.cfg_deployment_readiness_timeout, retired_runtime={"N": {}},
      error=dict(code="INSTANCE_FAILED", message="A required instance failed.", retryable=False),
      sequence=len(history) - 1, sent_at={},
      events=[dict(sequence=index + 1, time=now, phase=phase, message=message)
              for index, (phase, message) in enumerate(history)],
    )
    plugin._save_operation(operation)
    return oid

  def healthy(self, kind="create", phase="accepted"):
    """A three-node create (or update of two nodes) that nodes answer."""
    plugin = self.plugin
    operation = plugin.operation(kind)
    operation.update(phase=phase, deadline=plugin.now + plugin.cfg_deployment_readiness_timeout)
    self.operation_id = operation["operation_id"]
    plugin._save_operation(operation)
    return operation["operation_id"]


# Scenarios: each returns the measurements reported for old and new engines. ---

def scenario_incident(mixin, hours=32):
  sim = Simulation(mixin)
  sim.relink_stuck_in_restore()
  start = sim.plugin.now
  sim.run(hours * HOUR)
  latest = sim.latest()
  blocked_events = [event for event in latest["events"] if event["message"] == BLOCKED]
  return sim, dict(sim.ledger(start), blocked_events=len(blocked_events), commands=len(sim.plugin.commands),
                   snapshot_bytes=len(json.dumps(latest, default=str)))


def scenario_outage(mixin, mode, outage=600):
  sim = Simulation(mixin, readiness_timeout=HOUR)
  sim.healthy()
  sim.node_latency = 6
  sim.run(60, until=lambda: bool(sim.plugin.commands))
  sim.outage, start = mode, sim.plugin.now
  sim.run(outage)
  during = sim.ledger(start)
  sim.outage, recovered = None, sim.plugin.now
  completed = sim.run(2 * HOUR, until=sim.phase_is("completed"))
  return sim, dict(sim.ledger(start), during=during["writes"], completed=completed,
                   completion_delay=sim.plugin.now - recovered)


def scenario_rejected_commit(mixin, hours=6.5):
  sim = Simulation(mixin)
  sim.healthy(phase="finalizing")
  end = sim.plugin.now + hours * HOUR

  def commit(operation, configs):
    if sim.plugin.now < end:
      raise RuntimeError(REJECTED)

  sim.plugin._commit_operation_revision = Mock(side_effect=commit)
  start = sim.plugin.now
  sim.run(hours * HOUR)
  rejected = sim.ledger(start)
  rejected.update(commits=sim.plugin._commit_operation_revision.call_count,
                  logged=sum(REJECTED in line for line in sim.logs))
  completed = sim.run(2 * HOUR, until=sim.phase_is("completed"))
  return sim, dict(rejected, completed=completed, completion_delay=sim.plugin.now - end)


def scenario_stuck_delete(mixin, hours=2):
  """A whole-job delete whose second node never confirms its stop (job 49 / op 8529 pattern)."""
  from extensions.business.deeploy.tests.test_deployment_admission import Admission
  from extensions.business.deeploy.tests.test_deployment_mutations import Mutations
  cls = Mutations
  if mixin is not _DeploymentOperationsMixin:
    # Legacy engine methods, keeping the harness's own overrides (such as _operation_peers).
    harness = set(vars(Mutations)) | set(vars(Admission))
    cls = type("LegacyMutations", (Mutations,), {key: value for key, value in vars(mixin).items()
                                                 if callable(value) and key not in harness and not key.startswith("__")})
  plugin = cls()
  plugin.P = lambda *args, **kwargs: None
  sizes, store = [], plugin.chainstore_hset

  def chainstore_hset(namespace, key, value, **kwargs):
    if namespace == OPERATIONS_HKEY:
      sizes.append((value["sequence"], len(json.dumps(value, default=str, separators=(",", ":")))))
    return store(namespace, key, value, **kwargs)

  plugin.chainstore_hset = chainstore_hset
  operation_id = plugin.delete()["operation_id"]
  operation = plugin._operation_records()[operation_id]
  plugin.stop_report(operation, "A")
  admitted = len(sizes)
  for _ in range(int(hours * HOUR) // TICK):
    plugin.now += TICK
    plugin._reconcile_coordinator_operations()
  latest = plugin._operation_records()[operation["operation_id"]]
  writes = sizes[admitted:]
  return plugin, dict(writes=len(writes), bytes=sum(size for _, size in writes),
                      sequences=latest["sequence"] - operation["sequence"],
                      commands=len(plugin.commands), recovery=latest["recovery"])


def scenario_healthy(mixin, kind):
  sim = Simulation(mixin)
  sim.healthy(kind)
  sim.node_latency = 4
  start = sim.plugin.now
  completed = sim.run(HOUR, until=sim.phase_is("completed"))
  return sim, dict(sim.ledger(start), completed=completed, duration=sim.plugin.now - start,
                   phases=sim.phases(), commands=len(sim.plugin.commands), outcome=sim.latest()["outcome"])


class WriteDisciplineTests(unittest.TestCase):
  def test_incident_relink_without_binding_writes_blocked_once_in_32_hours(self):
    sim, result = scenario_incident(_DeploymentOperationsMixin)
    # Legacy engine: ~80,640 writes (one replicate per pass, two snapshots per 10 s).
    # Now: the blocked transition once, then one re-publish per attempt at the
    # 600 s back-off ceiling: 32 h / 600 s = 192.
    self.assertLessEqual(result["writes"], 200)
    self.assertEqual(result["sequences"], 1)
    blocked = [write for write in sim.writes if write["recovery"] == "blocked" and write["message"] == BLOCKED]
    self.assertEqual(len({write["sequence"] for write in blocked}), 1)
    self.assertEqual(result["blocked_events"], 1)
    self.assertEqual(result["commands"], 0)
    self.assertEqual(sim.latest()["recovery"], "blocked")
    runtime = sim.plugin._operation_runtime(sim.operation_id)
    self.assertEqual(runtime["delay"], sim.plugin.OPERATION_RETRY_MAX_SECONDS)
    # The real cause is logged, rate limited per distinct message.
    reasons = [line for line in sim.logs if "Previous runtime artifacts are unavailable." in line]
    self.assertTrue(reasons and all(sim.operation_id in line and "restoring_previous" in line for line in reasons))
    self.assertLessEqual(len(reasons), 32 * HOUR // sim.plugin.OPERATION_LOG_SECONDS + 1)

  def test_stuck_operation_resumes_on_new_evidence_within_one_backoff_step(self):
    sim = Simulation()
    sim.relink_stuck_in_restore()
    sim.run(2 * HOUR)
    self.assertEqual(sim.plugin._operation_runtime(sim.operation_id)["delay"], sim.plugin.OPERATION_RETRY_MAX_SECONDS)
    arrived = sim.plugin.now
    sim.publish(sim.operation_id, "N", "restore", "ready")
    self.assertTrue(sim.run(HOUR, until=sim.phase_is("completed")))
    self.assertLessEqual(sim.plugin.now - arrived, sim.plugin.OPERATION_RETRY_MIN_SECONDS + 2 * TICK)
    self.assertEqual(sim.phases()[-3:], ["restoring_previous", "finalizing_recovery", "completed"])
    self.assertEqual((sim.latest()["outcome"], sim.latest()["recovery"]), ("failed", "completed"))
    sim.plugin._commit_operation_revision.assert_called_once()

  def test_operator_release_during_backoff_is_exempt_from_the_write_budget(self):
    sim = Simulation()
    sim.relink_stuck_in_restore()
    sim.run(2 * HOUR)
    plugin = sim.plugin
    plugin.OPERATION_FREE_WRITES, plugin.OPERATION_HOURLY_WRITES = 0, 0
    latest = copy.deepcopy(sim.latest())
    latest["error"] = dict(code="OPERATOR_NOTE", message="Inspecting.", retryable=True)
    with self.assertRaisesRegex(RuntimeError, "budget"):
      plugin._save_operation(latest)
    self.assertEqual(sum("exceeded its snapshot write budget" in line for line in sim.logs), 1)
    latest.update(outcome="failed", recovery="completed",
                  error=dict(code="OPERATOR_RELEASED", message="Released by an operator.", retryable=False))
    plugin._save_operation(latest, "completed", "Operator release: the relinked node cannot restore this job.")
    released = len(sim.writes)
    sim.run(HOUR)
    self.assertEqual(len(sim.writes), released)
    self.assertEqual(sim.latest()["phase"], "completed")
    plugin._assert_no_active_deployment(job_id=66)

  def test_out_of_band_release_stops_the_worker(self):
    sim = Simulation()
    sim.relink_stuck_in_restore()
    sim.run(HOUR)
    latest = copy.deepcopy(sim.latest())
    latest.update(phase="completed", outcome="failed", recovery="completed", sequence=latest["sequence"] + 64)
    sim.plugin.storage[OPERATIONS_HKEY, "{}|{}".format(sim.operation_id, latest["sequence"] % 8)] = latest
    before = len(sim.writes)
    sim.run(HOUR)
    self.assertEqual(len(sim.writes), before)
    self.assertEqual(sim.plugin.commands, [])

  def test_cstore_outage_keeps_the_final_state_and_bounds_writes(self):
    for mode in ("unconfirmed", "raise"):
      with self.subTest(mode=mode):
        sim, result = scenario_outage(_DeploymentOperationsMixin, mode)
        self.assertTrue(result["completed"])
        # Attempts at +10, +30, +70, +150, +310 s, then within the next step.
        self.assertLessEqual(result["during"], 8)
        self.assertLessEqual(result["completion_delay"], 320 + TICK)
        newest = max(sim.peers.values(), key=lambda record: record["sequence"])
        self.assertEqual(newest["phase"], "completed")
        self.assertEqual(newest["sequence"], max(write["sequence"] for write in sim.writes))
        self.assertEqual(sim.phases(), ["accepted", "waiting_for_readiness", "finalizing", "completed"])

  def test_rejected_commit_for_six_and_a_half_hours_is_bounded(self):
    sim, result = scenario_rejected_commit(_DeploymentOperationsMixin)
    # Legacy: one replicate and one commit (new R1FS object) per pass: ~11,700.
    hours = 6.5
    self.assertLessEqual(result["commits"], hours * HOUR / sim.plugin.OPERATION_RETRY_MAX_SECONDS + 7)
    self.assertLessEqual(result["writes"], result["commits"])
    self.assertEqual(result["sequences"], 0)
    self.assertLessEqual(result["logged"], hours * HOUR / sim.plugin.OPERATION_LOG_SECONDS + 1)
    self.assertTrue(any(sim.operation_id in line and "finalizing" in line and "RuntimeError: " + REJECTED in line
                        for line in sim.logs))
    self.assertTrue(result["completed"])
    self.assertLessEqual(result["completion_delay"], sim.plugin.OPERATION_RETRY_MAX_SECONDS + TICK)

  def test_stuck_delete_writes_blocked_once(self):
    plugin, result = scenario_stuck_delete(_DeploymentOperationsMixin)
    # Legacy engine: a replicate and a blocked save every pass plus a sent_at save per 10 s.
    self.assertEqual(result["sequences"], 1)
    self.assertEqual(result["recovery"], "blocked")
    self.assertLessEqual(result["writes"], 2 * HOUR // plugin.OPERATION_RETRY_MAX_SECONDS + 3)
    # Retire commands continue to the silent node: every 10 s until the 60 s
    # deadline, then at the back-off pace (6 doubling steps, then every 600 s).
    self.assertGreater(result["commands"], 1)
    self.assertLessEqual(result["commands"], 7 + 6 + 2 * HOUR // plugin.OPERATION_RETRY_MAX_SECONDS)

  def test_healthy_operations_are_not_slowed_and_journal_no_retries(self):
    expected = {
      "create": ["accepted", "waiting_for_readiness", "finalizing", "completed"],
      "update": ["accepted", "retiring_previous", "waiting_for_readiness", "finalizing", "completed"],
    }
    for kind, phases in expected.items():
      with self.subTest(kind=kind):
        sim, result = scenario_healthy(_DeploymentOperationsMixin, kind)
        self.assertTrue(result["completed"])
        self.assertEqual(result["phases"], phases)
        self.assertEqual(result["outcome"], "succeeded")
        # One snapshot per phase change, no replicate or sent_at snapshot.
        self.assertEqual(result["writes"], len(phases) - 1)
        self.assertLessEqual(result["duration"], 30)

  def test_command_resends_do_not_create_snapshots(self):
    sim = Simulation(readiness_timeout=HOUR)
    sim.healthy()
    sim.run(4)
    sequence = sim.latest()["sequence"]
    sim.run(120)
    self.assertEqual(sim.latest()["sequence"], sequence)
    self.assertEqual(len(sim.plugin.commands), 3 * 13)
    self.assertEqual(sim.latest()["sent_at"], {})

  def test_failed_replication_is_retried_not_forgotten(self):
    sim = Simulation(readiness_timeout=HOUR)
    sim.healthy()
    sim.outage = "unconfirmed"
    sim.run(4)
    self.assertEqual(sim.plugin.commands, [])
    stored = sim.latest()["sequence"]
    sim.outage = None
    sim.run(sim.plugin.OPERATION_RETRY_MIN_SECONDS + TICK)
    self.assertEqual(sim.peers["{}|{}".format(sim.operation_id, stored % 8)]["sequence"], stored)
    self.assertEqual(len(sim.plugin.commands), 3)

  def test_unchanged_snapshot_is_republished_only_periodically(self):
    sim = Simulation(readiness_timeout=10 * HOUR)
    sim.healthy()
    sim.run(4)
    writes = len(sim.writes)
    sim.run(HOUR)
    self.assertEqual(len(sim.writes) - writes, HOUR // sim.plugin.OPERATION_REPUBLISH_SECONDS)

  def test_write_budget_caps_a_loop_whatever_its_cause(self):
    sim = Simulation()
    plugin = sim.plugin
    # Re-enable the legacy write pattern; only the budget stays active.
    plugin.OPERATION_SKIP_UNCHANGED_SAVES = False
    plugin.OPERATION_RETRY_MIN_SECONDS = plugin.OPERATION_RETRY_MAX_SECONDS = 0
    plugin.OPERATION_REPUBLISH_SECONDS = 0
    sim.relink_stuck_in_restore()
    start = sim.plugin.now
    hours = 4
    sim.run(hours * HOUR)
    result = sim.ledger(start)
    self.assertLessEqual(result["sequences"], plugin.OPERATION_FREE_WRITES + plugin.OPERATION_HOURLY_WRITES * hours)
    self.assertGreaterEqual(result["sequences"], plugin.OPERATION_FREE_WRITES)
    budget_logs = [line for line in sim.logs if "exceeded its snapshot write budget" in line]
    self.assertTrue(all(sim.operation_id in line and "restoring_previous" in line for line in budget_logs))
    self.assertLessEqual(len(budget_logs), hours * HOUR // plugin.OPERATION_LOG_SECONDS + 1)
    sim.publish(sim.operation_id, "N", "restore", "ready")
    self.assertTrue(sim.run(HOUR, until=sim.phase_is("completed")))

  def test_signature_verdicts_are_cached_until_a_record_changes(self):
    plugin = Coordinator()
    verify = plugin.bc.verify
    plugin.bc.verify = Mock(side_effect=verify)
    base = plugin.operation()
    for index in range(5):
      operation = copy.deepcopy(base)
      operation["operation_id"] = base["operation_id"] + str(index)
      operation["job_id"] = index
      plugin._save_operation(operation)
    records = len(plugin.chainstore_hgetall(OPERATIONS_HKEY))
    for _ in range(10):
      self.assertEqual(len(plugin._operation_records()), 5)
    self.assertEqual(plugin.bc.verify.call_count, records)
    changed = copy.deepcopy(plugin._operation_records()[base["operation_id"] + "0"])
    changed["error"] = dict(code="CHANGED", message="Changed.", retryable=True)
    plugin._save_operation(changed)
    plugin._operation_records()
    self.assertEqual(plugin.bc.verify.call_count, records + 1)
    # A record replaced under the same key with a new signature is checked again.
    key = "{}|{}".format(changed["operation_id"], changed["sequence"] % 8)
    plugin.storage[OPERATIONS_HKEY, key] = dict(plugin.storage[OPERATIONS_HKEY, key], EE_SIGN="forged")
    self.assertNotIn(changed["operation_id"], {
      operation_id for operation_id, record in plugin._operation_records().items()
      if record["sequence"] == changed["sequence"]})
    self.assertEqual(plugin.bc.verify.call_count, records + 2)
    plugin.OPERATION_VERIFY_CACHE_SIZE = 0
    plugin._operation_records()
    plugin._operation_records()
    self.assertEqual(plugin.bc.verify.call_count, records + 2 + 2 * len(plugin.chainstore_hgetall(OPERATIONS_HKEY)))


LEGACY = legacy_mixin()


@unittest.skipUnless(LEGACY, "Set DEEPLOY_LEGACY_OPERATIONS to the previous deployment_operations.py.")
class LegacyComparisonTests(unittest.TestCase):
  def test_compare_with_legacy_engine(self):
    scenarios = [
      ("a. relink stuck in restore, 32 h", lambda mixin: scenario_incident(mixin)),
      ("c. CStore unconfirmed 10 min", lambda mixin: scenario_outage(mixin, "unconfirmed")),
      ("c. CStore raising 10 min", lambda mixin: scenario_outage(mixin, "raise")),
      ("d. commit rejected 6.5 h", lambda mixin: scenario_rejected_commit(mixin)),
      ("delete, one node silent, 2 h", lambda mixin: scenario_stuck_delete(mixin)),
      ("e. healthy create", lambda mixin: scenario_healthy(mixin, "create")),
      ("e. healthy update", lambda mixin: scenario_healthy(mixin, "update")),
    ]
    rows = []
    for name, scenario in scenarios:
      _, old = scenario(LEGACY)
      _, new = scenario(_DeploymentOperationsMixin)
      self.assertLessEqual(new["writes"], old["writes"], name)
      self.assertLessEqual(new["bytes"], old["bytes"], name)
      if "phases" in old:
        self.assertEqual(new["phases"], old["phases"], name)
        self.assertLessEqual(new["duration"], old["duration"], name)
      extra = {key: (old[key], new[key]) for key in ("sequences", "commits", "commands", "duration",
                                                     "completion_delay", "snapshot_bytes") if key in old}
      rows.append((name, old["writes"], new["writes"], old["bytes"], new["bytes"], extra))
    print()
    print("{:<36} {:>9} {:>7} {:>13} {:>11} {:>9}  {}".format(
      "scenario", "writes", "after", "bytes", "after", "reduction", "other (before, after)"))
    for name, old, new, old_bytes, new_bytes, extra in rows:
      print("{:<36} {:>9} {:>7} {:>13} {:>11} {:>8.1f}x  {}".format(
        name, old, new, old_bytes, new_bytes, old / max(new, 1), extra))


if __name__ == "__main__":
  unittest.main()
