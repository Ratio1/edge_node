"""A restarted dAuth oracle must sync both secret namespaces before it serves secrets."""
import threading
import time
import unittest
from copy import deepcopy

from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY as CURRENT, DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY as REVISIONS,
  DEEPLOY_JOBS_CSTORE_HKEY as POINTERS, _DauthMixin,
)
from extensions.business.dauth.deployment_secrets import _DauthDeploymentSecretsMixin
from extensions.business.dauth.test_dauth_registry_gating import (
  REQUEST_TIME, SOURCE_IP, _load_dauth_manager_class, _make_dauth_harness,
)

Manager = _load_dauth_manager_class(dauth_mixin=_DauthMixin)
SYNCING = "dAuth secret custody is syncing; retry later."
LATENCY = 1.0  # seconds for a peer snapshot to arrive


class _Clock:
  def __init__(self):
    self.now = float(REQUEST_TIME)


class _SecretNetwork:
  """dAuth peers' CStore replicas answering hsync requests (CStore level, independent of dAuth)."""

  def __init__(self, clock, replicas, answer_from=None):
    self.clock, self.replicas = clock, replicas
    self.answer_from = answer_from or {}

  def _answering(self, targets):
    return [peer for peer in targets if self.clock.now >= self.answer_from.get(peer, 0)]

  def hsync_for(self, local, own_address, new_core=True):
    def merge(hkey, sources, erase_revoked):
      merged = 0
      for peer in sources:
        for (namespace, key), value in self.replicas[peer].items():
          if namespace == hkey:
            local[namespace, key] = deepcopy(value)
            merged += 1
      if erase_revoked and hkey == REVISIONS:  # companion core change: a marker wins
        for namespace, key in list(local):
          if namespace == REVISIONS and key.endswith("|revoked"):
            base = (REVISIONS, key[:-len("|revoked")])
            if isinstance(local.get(base), dict) and not local[base].get("revoked"):
              local[base] = dict(local[(REVISIONS, key)], revoked=True)
      return merged

    def targets_of(extra_peers):
      return [peer for peer in extra_peers or [] if peer != own_address]

    def hsync(hkey, debug=False, extra_peers=None, include_default_peers=True,
              include_configured_peers=True, timeout=None, all_peers=False):
      targets = targets_of(extra_peers)
      answering = self._answering(targets)
      if not all_peers:
        answering = answering[:1]
      complete = bool(answering) and (not all_peers or len(answering) == len(targets))
      self.clock.now += LATENCY if complete else timeout
      if not answering:
        raise ValueError(f"hsync for '{hkey}' timed out after {timeout}s.")
      merged = merge(hkey, answering, erase_revoked=all_peers)
      if all_peers:
        return {"hkey": hkey, "source_peers": answering, "responses": len(answering), "merged_fields": merged}
      return {"hkey": hkey, "source_peer": answering[0], "merged_fields": merged}

    def old_core_hsync(hkey, debug=False, extra_peers=None, include_default_peers=True,
                       include_configured_peers=True, timeout=None):
      return hsync(hkey, debug=debug, extra_peers=extra_peers, timeout=timeout)

    return hsync if new_core else old_core_hsync


def _oracle(clock, own="node-self", peers=("peer-1", "peer-2", "peer-3")):
  """A dAuth manager with the real dAuth mixin, enabled, unsynced, syncing inline."""
  plugin = _make_dauth_harness()
  plugin.__class__ = Manager
  plugin.time = lambda: clock.now
  plugin.bc.address, plugin.bc.eth_address = own, "0x" + own.upper()
  plugin._messages = []
  plugin.P = lambda msg, *args, **kwargs: plugin._messages.append(msg)
  plugin._dauth_server_enabled = True
  plugin._dauth_registry_eth_oracles = ["0x" + node.upper() for node in (own, *peers)]
  plugin._dauth_registry_internal_peers = [own, *peers]
  plugin.cfg_dauth_job_secrets_hsync_interval = 600
  plugin.cfg_dauth_job_secrets_hsync_retry_interval = 15
  plugin.cfg_dauth_job_secrets_hsync_timeout = 30
  plugin.cfg_dauth_secrets_sync_fail_open_after = 0
  plugin._run_dauth_secrets_sync = lambda target: target()
  plugin._DauthManagerPlugin__get_response = lambda data: data
  plugin._mark_dauth_secrets_unsynced()  # what on_init does first
  return plugin


def _revision(job, rev):
  return {"job_id": job, "revision": rev, "job_secrets": {"TOKEN": f"{job}-{rev}"},
          "pipelines": {"node-runner": {"NAME": "app"}}}


def _restart_fixture(clock):
  """Stale replica: 4 revisions revoked by peers held in full, 8 newer revisions and 7 bundles missing."""
  plugin = _oracle(clock)
  peer_store = {}
  revoked = [("1", f"op{i}:deploy") for i in range(4)]
  newer = [("2", f"op{i}:deploy") for i in range(8)]
  current = [str(job) for job in range(10, 17)]
  for job, rev in revoked:
    plugin._chainstore[REVISIONS, f"{job}|{rev}"] = _revision(job, rev)
    peer_store[REVISIONS, f"{job}|{rev}|revoked"] = {"job_id": job, "revision": rev}
    peer_store[REVISIONS, f"{job}|{rev}"] = {"job_id": job, "revision": rev, "revoked": True}
  for job, rev in newer:
    peer_store[REVISIONS, f"{job}|{rev}"] = _revision(job, rev)
  for job in current:
    cid = f"cid-{job}"
    plugin._chainstore[POINTERS, job] = cid
    plugin._r1fs_data[cid] = {"DEEPLOY_SPECS": {"job_id": int(job), "current_target_nodes": ["node-runner"]}}
    peer_store[CURRENT, job] = {"job_id": job, "pipeline_cid": cid, "job_secrets": {"TOKEN": job}}
  replicas = {peer: deepcopy(peer_store) for peer in ("peer-1", "peer-2", "peer-3")}
  return plugin, replicas, revoked, newer, current


def _ask(plugin, clock, job, revision=None):
  body = {"EE_SENDER": "node-runner", "EE_ETH_SENDER": "0xRUNNER", "job_id": job,
          "nonce": hex(int(clock.now * 1000))}
  if revision is not None:
    body["revision"] = revision
  return plugin.get_secrets(body)


def _outcomes(plugin, clock, revoked, newer, current):
  responses = [_ask(plugin, clock, job, rev) for job, rev in revoked + newer] + [_ask(plugin, clock, job) for job in current]
  return responses[:len(revoked)], responses[len(revoked):len(revoked) + len(newer)], responses[-len(current):]


def _converge(test, plugin, clock, revoked, newer, current, limit=1800):
  """Tick the plugin loop every second; return seconds until every request gets its final answer."""
  start = clock.now
  while clock.now - start <= limit:
    plugin.process()
    rev_r, new_r, cur_r = _outcomes(plugin, clock, revoked, newer, current)
    if all(r.get("status") == "success" for r in new_r + cur_r):
      for response in rev_r:
        test.assertIn("revoked", response.get("error", ""))
        test.assertIs(response["retryable"], False)
      return clock.now - start
    for response in rev_r + new_r + cur_r:  # before convergence: only the retryable gate answer
      test.assertEqual((response.get("error"), response.get("retryable")), (SYNCING, True))
    clock.now = float(int(clock.now) + 1)
  test.fail("secret custody did not converge")


class RestartedOracleConvergenceTests(unittest.TestCase):
  def _run(self, answer_from=None, new_core=True):
    clock = _Clock()
    plugin, replicas, revoked, newer, current = _restart_fixture(clock)
    network = _SecretNetwork(clock, replicas, answer_from=answer_from)
    plugin.chainstore_hsync = network.hsync_for(plugin._chainstore, "node-self", new_core=new_core)
    # The stale replica would serve the revoked revisions without the gate.
    self.assertEqual(_ask(plugin, clock, *revoked[0])["error"], SYNCING)
    seconds = _converge(self, plugin, clock, revoked, newer, current)
    return seconds, plugin

  def test_a_healthy_peers(self):
    seconds, plugin = self._run()
    self.assertEqual(seconds, 2 * LATENCY)
    self.assertTrue(plugin._dauth_secrets_synced)

  def test_b_one_of_three_peers_answering(self):
    seconds, _ = self._run(answer_from={"peer-2": float("inf"), "peer-3": float("inf")})
    self.assertEqual(seconds, 2 * 30)  # all_peers waits out the timeout for the silent peers

  def test_c_no_peer_for_ten_minutes_then_recovery(self):
    recovered = REQUEST_TIME + 600
    seconds, plugin = self._run(answer_from={peer: recovered for peer in ("peer-1", "peer-2", "peer-3")})
    self.assertGreaterEqual(seconds, 600)
    self.assertLessEqual(seconds, 600 + 60 + 2 * LATENCY)
    warnings = [m for m in plugin._messages if m.startswith("Could not sync dAuth job secrets")]
    self.assertTrue(1 <= len(warnings) <= 3, warnings)  # one per 5 min
    self.assertIn("Last successful sync: never; refusing secret requests", warnings[0])

  def test_d_old_core_without_all_peers_keyword(self):
    seconds, plugin = self._run(new_core=False)
    self.assertEqual(seconds, 2 * LATENCY)
    self.assertFalse(plugin._dauth_hsync_all_peers)
    self.assertEqual(sum("no all_peers option" in m for m in plugin._messages), 1)


class SecretSyncGateTests(unittest.TestCase):
  def setUp(self):
    self.clock = _Clock()

  def _calls(self, plugin, fail=None, waits=True):
    calls = []
    def hsync(**kwargs):
      calls.append(kwargs)
      if fail is not None and fail():
        self.clock.now += kwargs["timeout"] if waits else 0
        raise ValueError("hsync timed out")
      return {"hkey": kwargs["hkey"], "source_peers": ["peer-1"], "responses": 1}
    plugin.chainstore_hsync = hsync
    return calls

  def test_single_oracle_registry_is_synced_without_peers(self):
    plugin = _oracle(self.clock, peers=())
    calls = self._calls(plugin)
    plugin.process()
    self.assertTrue(plugin._dauth_secrets_synced)
    self.assertEqual(calls, [])

  def test_unknown_registry_is_not_mistaken_for_a_single_oracle_network(self):
    plugin = _oracle(self.clock)
    plugin._dauth_registry_eth_oracles = None
    calls = self._calls(plugin)
    plugin.process()
    self.assertFalse(plugin._dauth_secrets_synced)
    self.assertEqual(calls, [])

  def test_registry_peers_that_do_not_resolve_keep_the_gate_closed(self):
    plugin = _oracle(self.clock)
    plugin._dauth_registry_internal_peers = ["node-self"]  # peers registered on-chain but not known yet
    calls = self._calls(plugin)
    plugin.process()
    self.assertFalse(plugin._dauth_secrets_synced)
    self.assertEqual(calls, [])
    self.assertIn("no other dAuth registry peer is resolvable", plugin._messages[-1])
    self.assertEqual(_ask(plugin, self.clock, "7", "op:deploy")["error"], SYNCING)

  def test_non_registry_node_has_no_gate_and_no_sync(self):
    plugin = _oracle(self.clock)
    plugin._dauth_server_enabled = False
    calls = self._calls(plugin)
    plugin.process()
    response = _ask(plugin, self.clock, "7", "op:deploy")
    self.assertEqual(response["error"], "dAuth server is not registered as a dAuth oracle")
    self.assertEqual(calls, [])

  def test_failing_sync_stays_closed_and_warns_every_five_minutes(self):
    plugin = _oracle(self.clock)
    calls = self._calls(plugin, fail=lambda: True)
    start = self.clock.now
    while self.clock.now - start < 1200:
      plugin.process()
      self.clock.now += 1
    self.assertFalse(plugin._dauth_secrets_synced)
    self.assertEqual({call["timeout"] for call in calls}, {30})
    self.assertTrue(all(call["all_peers"] for call in calls))
    self.assertEqual(len(calls), 2 * 20)  # each pass waits 2 x 30 s, then the next starts
    warnings = [m for m in plugin._messages if m.startswith("Could not sync dAuth job secrets")]
    self.assertEqual(len(warnings), 4)
    self.assertEqual(_ask(plugin, self.clock, "7", "op:deploy")["retryable"], True)

  def test_fail_open_option_serves_after_the_configured_time(self):
    plugin = _oracle(self.clock)
    plugin.cfg_dauth_secrets_sync_fail_open_after = 120
    plugin._chainstore[REVISIONS, "7|op:deploy"] = _revision("7", "op:deploy")
    self._calls(plugin, fail=lambda: True)
    plugin.process()
    self.assertEqual(_ask(plugin, self.clock, "7", "op:deploy")["error"], SYNCING)
    self.clock.now += 120
    self.assertEqual(_ask(plugin, self.clock, "7", "op:deploy")["status"], "success")
    plugin._dauth_secrets_sync_warned = None
    plugin.process()
    self.assertIn("serving from the local replica", plugin._messages[-1])

  def test_gate_closes_after_two_intervals_without_a_successful_sync(self):
    plugin = _oracle(self.clock)
    plugin._chainstore[REVISIONS, "7|op:deploy"] = _revision("7", "op:deploy")
    down = {"value": False}
    calls = self._calls(plugin, fail=lambda: down["value"], waits=False)
    plugin.process()
    self.assertTrue(plugin._dauth_secrets_synced)
    down["value"] = True
    start = self.clock.now
    while plugin._dauth_secrets_synced:
      plugin.process()
      self.clock.now += 1
    closed_after = self.clock.now - start
    self.assertGreater(closed_after, 1200)
    self.assertLessEqual(closed_after, 1202)
    self.assertEqual(_ask(plugin, self.clock, "7", "op:deploy")["error"], SYNCING)
    down["value"] = False
    self.clock.now += 60
    plugin.process()
    self.assertEqual(_ask(plugin, self.clock, "7", "op:deploy")["status"], "success")
    self.assertGreater(len(calls), 4)

  def test_all_oracles_restarting_together_sync_from_each_others_persisted_replicas(self):
    names = ("oracle-a", "oracle-b", "oracle-c")
    oracles = {name: _oracle(self.clock, own=name, peers=[n for n in names if n != name]) for name in names}
    for index, name in enumerate(names):  # each persisted a different part of the custody state
      oracles[name]._chainstore[REVISIONS, f"7|op{index}:deploy"] = _revision("7", f"op{index}:deploy")
    replicas = {name: oracle._chainstore for name, oracle in oracles.items()}
    snapshots = {name: deepcopy(store) for name, store in replicas.items()}
    for name, oracle in oracles.items():
      network = _SecretNetwork(self.clock, snapshots)
      oracle.chainstore_hsync = network.hsync_for(oracle._chainstore, name)
    for oracle in oracles.values():
      self.assertFalse(oracle._dauth_secrets_synced)  # peers answer while still unsynced themselves
    for oracle in oracles.values():
      oracle.process()
    for oracle in oracles.values():
      self.assertTrue(oracle._dauth_secrets_synced)
      for index in range(3):
        self.assertEqual(_ask(oracle, self.clock, "7", f"op{index}:deploy")["status"], "success")

  def test_sync_runs_off_the_request_thread(self):
    plugin = _oracle(self.clock)
    del plugin._run_dauth_secrets_sync  # the real background runner
    release, entered = threading.Event(), threading.Event()
    calls = []
    def blocking_hsync(**kwargs):
      calls.append(kwargs["hkey"])
      entered.set()
      release.wait(5)
      return {"hkey": kwargs["hkey"], "source_peers": ["peer-1"], "responses": 1}
    plugin.chainstore_hsync = blocking_hsync
    started = time.monotonic()
    plugin.process()
    self.assertTrue(entered.wait(2))
    self.assertEqual(_ask(plugin, self.clock, "7", "op:deploy")["error"], SYNCING)
    self.clock.now += 20
    plugin.process()  # retry is due, but a pass is still running: no second pass
    self.assertLess(time.monotonic() - started, 1.0)
    self.assertEqual(calls, [CURRENT])
    release.set()
    plugin._dauth_secrets_sync_thread.join(5)
    self.assertTrue(plugin._dauth_secrets_synced)

  def test_a_pass_started_before_a_reset_cannot_open_the_gate(self):
    plugin = _oracle(self.clock)
    generation = plugin._dauth_secrets_sync_generation
    plugin._mark_dauth_secrets_unsynced()  # e.g. on_resume while that pass ran
    plugin._record_dauth_secrets_sync(generation, self.clock.now, None)
    self.assertFalse(plugin._dauth_secrets_synced)

  def test_reveal_is_gated_like_get_secrets(self):
    plugin = _oracle(self.clock)
    plugin.process_dauth_reveal_secret_request = lambda body: self.fail("served while unsynced")
    self.assertEqual(plugin.reveal_job_secrets({"nonce": "n"})["error"], SYNCING)


class CustodyFailureLogTests(unittest.TestCase):
  def _manager(self):
    clock = _Clock()
    plugin = _oracle(clock)
    plugin._dauth_secrets_synced = True
    return plugin, clock

  def test_custody_write_failure_logs_type_site_message_and_operation(self):
    plugin, clock = self._manager()

    class _Custodian(_DauthDeploymentSecretsMixin):
      _dauth_registry_internal_peers = ["node-self", "peer-1"]
      def time(self):
        return clock.now
      def chainstore_hget(self, hkey, key):
        return None
      def chainstore_hset(self, **kwargs):
        return False  # write not confirmed by the registry peers

    operation = {"operation_id": "f00d-op", "phase": "cleaning_up_preparation", "kind": "create",
                 "preparation_deadline": 0}
    plan = {"configs": {"node-runner": {}}, "previous_configs": {}}
    plugin.process_dauth_reconcile_secrets_request = lambda body: _Custodian()._revoke_deployment_secret_revisions(
      "7", operation, plan, None,
    )
    body = {"nonce": "n", "job_id": "7", "action": "revoke", "operation": operation,
            "new_secrets": {"TOKEN": "plaintext-in-request"}}
    response = plugin.reconcile_job_secrets(body)
    self.assertEqual(response["error"], "dAuth secret reconciliation failed")
    line = plugin._messages[-1]
    self.assertIn(f"failed for request from {SOURCE_IP}: RuntimeError at deployment_secrets.py:", line)
    self.assertIn("Deployment secret revocation is pending.", line)
    self.assertIn("operation=f00d-op, action=revoke, job=7", line)
    self.assertNotIn("plaintext-in-request", "".join(plugin._messages))

  def test_dependency_exception_text_is_not_logged(self):
    plugin, _ = self._manager()
    def reconcile(body):
      raise KeyError("credential-in-dependency-error")
    plugin.process_dauth_reconcile_secrets_request = reconcile
    plugin.reconcile_job_secrets({"nonce": "n"})
    self.assertIn("KeyError at test_dauth_secret_sync_gate.py:", plugin._messages[-1])
    self.assertNotIn("credential-in-dependency-error", "".join(plugin._messages))


if __name__ == "__main__":
  unittest.main()
