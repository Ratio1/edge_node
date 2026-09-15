"""RM-026 C1a: launcher liveness.

C2's 600-second loss threshold and D1's takeover arithmetic both need something to measure from.
Today ownership is a bare `launcher` string compared by equality (`services/control.py:53`), with no
record of when it was taken or when it was last alive.

Where this lives is not a free choice. `models/cstore.py:38` already states that runtime liveness
belongs in the `:live` namespace and that the job record keeps durable orchestration metadata. The
C1 architecture gate confirmed the cost of ignoring that: a 30-second heartbeat in the job record is
120 full-record rewrites and 120 `job_revision` bumps on a one-hour job, which would starve the two
`reject_stale=True` archive-prune sites. It would also be unwritable by a successor at all, since
`_write_job_record` refuses writes where `current["launcher"]` is not this node -- which would make
D1 unbuildable.

A separate `:live:launcher` hset rather than a key inside `:live`: a launcher row then cannot
collide with a worker row (`{job_id}:{worker_addr}`) by construction, rather than by hoping no node
address is ever literally "launcher".
"""
import time

from extensions.business.cybersec.red_mesh.models.cstore import LauncherLiveness


def test_the_model_carries_what_c2_and_d1_need_to_measure():
  now = time.time()
  row = LauncherLiveness(job_id="job-1", launcher="node-a", launcher_since=now - 300,
                         last_seen_at=now)
  assert row.to_dict()["job_id"] == "job-1"
  restored = LauncherLiveness.from_dict(row.to_dict())
  assert restored == row


def test_a_row_is_attributable_to_the_launcher_that_wrote_it():
  """A heartbeat is evidence about its writer, not about the job. Without the launcher on the row a
  stale successor's heartbeat would read as the current owner being alive."""
  import dataclasses
  fields = {field.name for field in dataclasses.fields(LauncherLiveness)}
  assert "launcher" in fields
  assert "launcher_since" in fields


def test_a_malformed_row_is_refused_rather_than_partially_read():
  import pytest
  for payload in ({}, {"job_id": "job-1"}, {"job_id": "job-1", "launcher": "node-a"},
                  {"job_id": "", "launcher": "node-a", "launcher_since": 1.0, "last_seen_at": 2.0}):
    with pytest.raises((KeyError, TypeError, ValueError)):
      LauncherLiveness.from_dict(payload)


def test_liveness_is_derived_from_the_row_not_assumed():
  """`unavailable` is not `lost`. A job with no row at all has never had a heartbeat, which is a
  different statement from one whose heartbeat has aged out -- and C2 must not treat the first as a
  loss it can act on."""
  from extensions.business.cybersec.red_mesh.models.cstore import launcher_liveness_state
  now = 1_000.0
  assert launcher_liveness_state(None, now=now, loss_after=600.0) == "unavailable"
  fresh = LauncherLiveness("job-1", "node-a", launcher_since=now - 10, last_seen_at=now - 5)
  assert launcher_liveness_state(fresh, now=now, loss_after=600.0) == "live"
  aged = LauncherLiveness("job-1", "node-a", launcher_since=now - 900, last_seen_at=now - 601)
  assert launcher_liveness_state(aged, now=now, loss_after=600.0) == "lost"


def test_an_unresolved_timestamp_is_never_read_as_live_or_lost():
  """The parent design says invalid or future timing is unresolved. Treating a future timestamp as
  live would let a clock-skewed node hold ownership forever; treating it as lost would hand the job
  away on a skew."""
  from extensions.business.cybersec.red_mesh.models.cstore import launcher_liveness_state
  now = 1_000.0
  for last_seen in (now + 1, float("nan"), float("inf"), -1.0):
    row = LauncherLiveness("job-1", "node-a", launcher_since=now - 10, last_seen_at=last_seen)
    assert launcher_liveness_state(row, now=now, loss_after=600.0) == "unresolved", last_seen


def _repo(store):
  from types import SimpleNamespace
  from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
  owner = SimpleNamespace(
    cfg_instance_id="test-instance",
    chainstore_hget=lambda *, hkey, key: store.get(hkey, {}).get(key),
    chainstore_hgetall=lambda *, hkey: dict(store.get(hkey, {})),
    chainstore_hset=lambda *, hkey, key, value, **kw: (
      store.setdefault(hkey, {}).pop(key, None) if value is None
      else store.setdefault(hkey, {}).__setitem__(key, value)),
  )
  return JobStateRepository(owner)


def test_a_launcher_row_cannot_collide_with_a_worker_row():
  """Worker rows are keyed `{job_id}:{worker_addr}` in `<instance>:live`. Putting launcher liveness
  in its own hset makes collision impossible by construction rather than by assuming no node address
  is ever literally "launcher"."""
  store = {}
  repo = _repo(store)
  repo.put_live_progress("job-1:node-a", {"job_id": "job-1"})
  repo.put_launcher_liveness("job-1", LauncherLiveness("job-1", "node-a", 1.0, 2.0).to_dict())
  assert set(store["test-instance:live"]) == {"job-1:node-a"}
  assert set(store["test-instance:live:launcher"]) == {"job-1"}


def test_the_row_round_trips_through_the_repository():
  store = {}
  repo = _repo(store)
  row = LauncherLiveness("job-1", "node-a", 100.0, 200.0)
  repo.put_launcher_liveness("job-1", row.to_dict())
  assert repo.get_launcher_liveness_model("job-1") == row
  assert repo.get_launcher_liveness_model("absent") is None


def test_a_purged_job_leaves_no_launcher_row_behind():
  """A new hset the purge does not know about would leak a row naming the launcher and the job for
  every purged job.

  Driven through `purge_job` itself, not through the helper: asserting that the helper works proves
  nothing about whether the purge calls it, which is the defect an earlier review caught in the B9
  tests.
  """
  from unittest.mock import MagicMock, patch
  from .conftest import mock_plugin_modules
  mock_plugin_modules()
  from extensions.business.cybersec.red_mesh.services import control

  store = {"test-instance": {}, "test-instance:live": {}, "test-instance:live:launcher": {}}
  owner = MagicMock()
  owner.cfg_instance_id = "test-instance"
  owner.ee_addr = "node-a"
  owner.P = lambda *a, **k: None
  owner._log_audit_event = lambda *a, **k: None
  owner.chainstore_hgetall.side_effect = lambda *, hkey: dict(store.get(hkey, {}))
  owner.chainstore_hget.side_effect = lambda *, hkey, key: store.get(hkey, {}).get(key)

  def _hset(*, hkey, key, value, **_kw):
    if value is None:
      store.setdefault(hkey, {}).pop(key, None)
    else:
      store.setdefault(hkey, {})[key] = value

  owner.chainstore_hset.side_effect = _hset
  owner._normalize_job_record.side_effect = lambda k, r, **kw: (k, r)
  store["test-instance:live:launcher"]["job-1"] = LauncherLiveness(
    "job-1", "node-a", 1.0, 2.0).to_dict()
  store["test-instance:live:launcher"]["job-2"] = LauncherLiveness(
    "job-2", "node-a", 1.0, 2.0).to_dict()

  # purge_job imports these from rulebook_assessment INSIDE the function, so patching `control`
  # would bind nothing -- the vacuous-canary trap this task has hit twice.
  from extensions.business.cybersec.red_mesh.services import rulebook_assessment
  with patch.object(rulebook_assessment, "list_rulebook_profiles", return_value=[]):
    control.purge_job(owner, "job-1", checked_job={
      "job_id": "job-1", "job_status": "FINALIZED", "launcher": "node-a", "workers": {}})

  assert set(store["test-instance:live:launcher"]) == {"job-2"}, store["test-instance:live:launcher"]
