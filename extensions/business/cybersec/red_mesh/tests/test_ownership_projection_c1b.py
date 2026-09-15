"""RM-026 C1b: the launcher heartbeat, and ownership as a projection.

C1a established the representation and its lifecycle but wired nothing. This places the write and
derives ownership from state that already exists -- `ExecutionBinding.original_launcher` and the
immutable `participant_order` (`tenancy/execution.py:13,102-104`) -- rather than inventing a
counter. The C1 architecture gate rejected an `ownership_revision`: `_write_job_record` fences on
`job_revision`, 38 of 40 call sites pass `expected_revision=None`, and a second counter vanishes
entirely at finalization because `CStoreJobFinalized` has no revision field.

D1's arithmetic is `slot=floor((now-deadline)/90)`, `candidate=order[slot modulo N]`. Everything it
needs is here: the order, the current owner, and a deadline derived from liveness.
"""
import pytest

from extensions.business.cybersec.red_mesh.models.cstore import LauncherLiveness


def _owner(now=1_000.0, instance="test-instance", addr="node-a"):
  from types import SimpleNamespace
  store = {}
  return SimpleNamespace(
    cfg_instance_id=instance, ee_addr=addr, time=lambda: now, store=store,
    P=lambda *a, **k: None,
    chainstore_hget=lambda *, hkey, key: store.get(hkey, {}).get(key),
    chainstore_hgetall=lambda *, hkey: dict(store.get(hkey, {})),
    chainstore_hset=lambda *, hkey, key, value, **kw: (
      store.setdefault(hkey, {}).pop(key, None) if value is None
      else store.setdefault(hkey, {}).__setitem__(key, value)),
  )


def _binding(order=("node-a", "node-b", "node-c"), launcher="node-a"):
  return {"namespace": "deployment", "tenant_id": "tn_x", "original_launcher": launcher,
          "participant_order": list(order)}


class TestHeartbeat:
  def test_the_launcher_publishes_its_own_liveness_for_a_job_it_owns(self):
    from extensions.business.cybersec.red_mesh.services.ownership import publish_launcher_liveness
    owner = _owner()
    publish_launcher_liveness(owner, "job-1", {"job_id": "job-1", "launcher": "node-a"})
    row = LauncherLiveness.from_dict(owner.store["test-instance:live:launcher"]["job-1"])
    assert row.launcher == "node-a"
    assert row.last_seen_at == 1_000.0

  def test_a_node_never_publishes_liveness_for_a_job_it_does_not_own(self):
    """A heartbeat is a claim to be the current controller. Publishing one for another node's job
    would make a bystander look like the owner to C2 and D1."""
    from extensions.business.cybersec.red_mesh.services.ownership import publish_launcher_liveness
    owner = _owner(addr="node-a")
    publish_launcher_liveness(owner, "job-1", {"job_id": "job-1", "launcher": "node-b"})
    assert owner.store.get("test-instance:live:launcher", {}) == {}

  def test_launcher_since_is_set_once_and_not_refreshed_by_later_heartbeats(self):
    """`launcher_since` answers "when did this node take ownership". Refreshing it on every
    heartbeat would make an owner of one hour indistinguishable from one of thirty seconds, and D1
    measures its takeover deadline from it."""
    from extensions.business.cybersec.red_mesh.services.ownership import publish_launcher_liveness
    owner = _owner(now=1_000.0)
    publish_launcher_liveness(owner, "job-1", {"job_id": "job-1", "launcher": "node-a"})
    owner.time = lambda: 1_600.0
    publish_launcher_liveness(owner, "job-1", {"job_id": "job-1", "launcher": "node-a"})
    row = LauncherLiveness.from_dict(owner.store["test-instance:live:launcher"]["job-1"])
    assert row.launcher_since == 1_000.0
    assert row.last_seen_at == 1_600.0

  def test_a_different_launcher_restarts_the_since_clock(self):
    """A successor is not a continuation of its predecessor's tenure."""
    from extensions.business.cybersec.red_mesh.services.ownership import publish_launcher_liveness
    owner = _owner(now=1_000.0, addr="node-a")
    publish_launcher_liveness(owner, "job-1", {"job_id": "job-1", "launcher": "node-a"})
    successor = _owner(now=2_000.0, addr="node-b")
    successor.store = owner.store
    successor.chainstore_hget = owner.chainstore_hget
    successor.chainstore_hset = owner.chainstore_hset
    publish_launcher_liveness(successor, "job-1", {"job_id": "job-1", "launcher": "node-b"})
    row = LauncherLiveness.from_dict(owner.store["test-instance:live:launcher"]["job-1"])
    assert (row.launcher, row.launcher_since) == ("node-b", 2_000.0)


class TestOwnershipProjection:
  def test_it_reports_the_order_and_the_owner_d1_needs(self):
    from extensions.business.cybersec.red_mesh.services.ownership import project_ownership
    owner = _owner()
    job = {"job_id": "job-1", "launcher": "node-a", "execution_binding": _binding()}
    owner.store["test-instance:live:launcher"] = {
      "job-1": LauncherLiveness("job-1", "node-a", 900.0, 995.0).to_dict()}
    view = project_ownership(owner, job, loss_after=600.0)
    assert view["launcher"] == "node-a"
    assert view["participant_order"] == ["node-a", "node-b", "node-c"]
    assert view["liveness"] == "live"
    assert view["launcher_since"] == 900.0

  def test_a_legacy_job_without_a_binding_reports_unavailable_not_invented_order(self):
    """A legacy unbound job has no participant_order. Reporting an empty order would read as "no
    candidates", which D1 treats as a decision; unavailable says the question cannot be answered."""
    from extensions.business.cybersec.red_mesh.services.ownership import project_ownership
    owner = _owner()
    view = project_ownership(owner, {"job_id": "job-1", "launcher": "node-a"}, loss_after=600.0)
    assert view["participant_order"] is None
    assert view["liveness"] == "unavailable"

  def test_a_job_whose_launcher_never_heartbeated_is_unavailable_not_lost(self):
    from extensions.business.cybersec.red_mesh.services.ownership import project_ownership
    owner = _owner()
    job = {"job_id": "job-1", "launcher": "node-a", "execution_binding": _binding()}
    view = project_ownership(owner, job, loss_after=600.0)
    assert view["liveness"] == "unavailable"

  def test_a_liveness_row_from_a_different_launcher_is_not_read_as_the_current_owner(self):
    """The row says node-b is alive; the job record says node-a controls it. That is a disagreement,
    not evidence that node-a is live -- and must not be projected as if it were."""
    from extensions.business.cybersec.red_mesh.services.ownership import project_ownership
    owner = _owner()
    job = {"job_id": "job-1", "launcher": "node-a", "execution_binding": _binding()}
    owner.store["test-instance:live:launcher"] = {
      "job-1": LauncherLiveness("job-1", "node-b", 900.0, 995.0).to_dict()}
    view = project_ownership(owner, job, loss_after=600.0)
    assert view["liveness"] == "unresolved", view
    assert view["launcher"] == "node-a"


class TestTheHeartbeatIsActuallyPublished:
  """A write site nothing calls is the signature-only defect this task has shipped twice. These run
  through the plugin's own periodic helper, not the service function."""

  def _plugin(self, jobs, addr="node-a", now=1_000.0):
    from unittest.mock import MagicMock
    from .test_api import TestPhase1ConfigCID
    TestPhase1ConfigCID._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    store = {}
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = addr
    plugin.time.return_value = now
    plugin.P = lambda *a, **k: None
    plugin._last_launcher_heartbeat = 0.0
    plugin.chainstore_hget.side_effect = lambda *, hkey, key: store.get(hkey, {}).get(key)
    plugin.chainstore_hgetall.side_effect = lambda *, hkey: dict(store.get(hkey, {}))

    def _hset(*, hkey, key, value, **_kw):
      if value is None:
        store.setdefault(hkey, {}).pop(key, None)
      else:
        store.setdefault(hkey, {})[key] = value

    plugin.chainstore_hset.side_effect = _hset
    plugin._get_all_network_jobs.return_value = jobs
    plugin._normalize_job_record.side_effect = lambda k, r, **kw: (k, r)
    return PentesterApi01Plugin, plugin, store

  def test_the_periodic_pass_publishes_for_owned_running_jobs_only(self):
    Plugin, plugin, store = self._plugin({
      "mine": {"job_id": "mine", "launcher": "node-a", "job_status": "RUNNING"},
      "theirs": {"job_id": "theirs", "launcher": "node-b", "job_status": "RUNNING"},
      "done": {"job_id": "done", "launcher": "node-a", "job_status": "FINALIZED"},
    })
    Plugin._maybe_publish_launcher_liveness(plugin)
    assert set(store.get("test-instance:live:launcher", {})) == {"mine"}

  def test_it_respects_its_interval_rather_than_writing_every_tick(self):
    """process() runs far more often than every 30s. Writing per tick would multiply CStore traffic
    for no extra information."""
    Plugin, plugin, store = self._plugin(
      {"mine": {"job_id": "mine", "launcher": "node-a", "job_status": "RUNNING"}})
    Plugin._maybe_publish_launcher_liveness(plugin)
    first = dict(store["test-instance:live:launcher"]["mine"])
    plugin.time.return_value = 1_005.0
    Plugin._maybe_publish_launcher_liveness(plugin)
    assert store["test-instance:live:launcher"]["mine"] == first
    plugin.time.return_value = 1_040.0
    Plugin._maybe_publish_launcher_liveness(plugin)
    assert store["test-instance:live:launcher"]["mine"]["last_seen_at"] == 1_040.0


def test_the_periodic_loop_actually_calls_the_publisher():
  """Asserting the helper works proves nothing about whether `process` runs it -- the defect that
  shipped in C1a's first draft and that an earlier review caught in the B9 tests.

  Structural, and deliberately so: `process` pulls in the whole plugin lifecycle, so driving it
  would test the mock harness more than the wiring. A source assertion is weaker than a behavioural
  one and is not a substitute; it is a ratchet against the call being dropped.
  """
  import ast
  import inspect
  import textwrap
  from .test_api import TestPhase1ConfigCID
  TestPhase1ConfigCID._mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

  tree = ast.parse(textwrap.dedent(inspect.getsource(PentesterApi01Plugin.process)))
  called = {node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
  assert "_maybe_publish_launcher_liveness" in called, sorted(called)


class TestTerminalJobsAndMalformedRows:
  """Three defects the round-2 architecture gate found in the committed C1a/C1b code, each
  contradicting a claim in my own commit messages."""

  def test_a_finalized_job_is_not_reported_as_a_lost_launcher(self):
    """C1b's message claimed a finalized job would not have C2 measuring a loss against it. The
    heartbeat guard only stops *refreshing* the row; nothing deleted it, so 600s after the job ended
    normally the projection read `lost` -- which is exactly the signal D1 acts on to take over a job
    that does not need taking over."""
    from extensions.business.cybersec.red_mesh.services.ownership import project_ownership
    owner = _owner(now=1_700.0)
    owner.store["test-instance:live:launcher"] = {
      "job-1": LauncherLiveness("job-1", "node-a", 900.0, 1_000.0).to_dict()}
    job = {"job_id": "job-1", "launcher": "node-a", "job_status": "FINALIZED",
           "execution_binding": _binding()}
    view = project_ownership(owner, job, loss_after=600.0)
    assert view["liveness"] == "terminal", view

  def test_a_stopped_job_is_terminal_too(self):
    from extensions.business.cybersec.red_mesh.services.ownership import project_ownership
    owner = _owner(now=1_700.0)
    owner.store["test-instance:live:launcher"] = {
      "job-1": LauncherLiveness("job-1", "node-a", 900.0, 1_000.0).to_dict()}
    job = {"job_id": "job-1", "launcher": "node-a", "job_status": "STOPPED",
           "execution_binding": _binding()}
    assert project_ownership(owner, job, loss_after=600.0)["liveness"] == "terminal"

  def test_a_non_finite_launcher_since_is_refused_not_carried_forward(self):
    """`launcher_since` was accepted as NaN, carried forward by every later heartbeat, and projected
    as a live launcher. D1 measures its deadline from it, and every NaN comparison is silently
    False -- so the takeover slot would never open."""
    import pytest
    for bad in (float("nan"), float("inf"), -1.0):
      with pytest.raises(ValueError):
        LauncherLiveness.from_dict({"job_id": "job-1", "launcher": "node-a",
                                    "launcher_since": bad, "last_seen_at": 1_000.0})

  def test_a_tenure_cannot_start_after_it_was_last_seen(self):
    import pytest
    with pytest.raises(ValueError):
      LauncherLiveness.from_dict({"job_id": "job-1", "launcher": "node-a",
                                  "launcher_since": 2_000.0, "last_seen_at": 1_000.0})
