"""An open deployment operation whose snapshot stopped changing is re-sent to the peers every 600 s, not every 30 s."""
# The test framework.
import unittest

# The mixin that advances update and delete operations, which the base stand-in lacks.
from extensions.business.deeploy.deployment_mutations import _DeploymentMutationsMixin
# The name of the chain-store hash that holds the operation snapshots.
from extensions.business.deeploy.deployment_operations import OPERATIONS_HKEY
# The offline coordinating oracle of the operation tests.
from extensions.business.deeploy.tests.test_deployment_operations import Coordinator


# The time the coordinator stand-in starts at, and so the time of the first snapshot.
START = 100


class _Coordinator(_DeploymentMutationsMixin, Coordinator):
  """The offline coordinating oracle of the operation tests, able to advance a delete operation too."""


def _record_sends(plugin):
  """
  Record every write of an operation snapshot the coordinator makes from now on.

  Parameters
  ----------
  plugin : _Coordinator
    The coordinator stand-in; its chain-store write is wrapped.

  Returns
  -------
  list
    Receives `(seconds since START, sequence)` per write of a snapshot, confirmed or not.
  """
  # One entry per snapshot write, in the order of the writes.
  sends = []
  # The stand-in's own write, which the wrapper still calls.
  write = plugin.chainstore_hset

  def recording(namespace, key, value, **kwargs):
    """
    Note a snapshot write, then do it.

    Parameters
    ----------
    namespace : str
      The chain-store hash written to.
    key : str
      The field written.
    value : dict
      The record written.
    **kwargs
      Passed on to the real write.

    Returns
    -------
    bool
      What the real write returns: whether it was confirmed.
    """
    if namespace == OPERATIONS_HKEY:
      # Only operation snapshots are noted, by their age since START and their sequence.
      sends.append((plugin.now - START, value["sequence"]))
    # The write itself is unchanged, and so is its confirmation.
    return write(namespace, key, value, **kwargs)

  # From here on every write of the stand-in goes through the wrapper.
  plugin.chainstore_hset = recording
  # The list the wrapper fills.
  return sends


def _stuck_operation(kind="update", phase="retiring_previous"):
  """
  Build a coordinator with one open operation whose snapshot does not change by itself.

  Parameters
  ----------
  kind : str
    The operation kind, "update" or "delete".
  phase : str
    The phase the operation is saved in. The default waits for the previous nodes to stop.

  Returns
  -------
  tuple
    `(plugin, operation, sends)`: the stand-in, the operation as saved (sequence 1, written
    and confirmed at START) and the list that records every later snapshot write.
  """
  # The offline coordinator, whose clock starts at START.
  plugin = _Coordinator()
  # An update operation, which has previous nodes to stop.
  operation = plugin.operation("update")
  # The wanted kind and phase, with a deadline that never comes.
  operation.update(kind=kind, phase=phase, deadline=10 ** 9)
  # The first snapshot: signed, written and confirmed at START.
  plugin._save_operation(operation)
  # The sends are recorded only from here, so the first write is not among them.
  return plugin, operation, _record_sends(plugin)


def _passes(plugin, seconds, step):
  """
  Move the clock in worker-pass steps and run `step` at each.

  Parameters
  ----------
  plugin : _Coordinator
    The stand-in whose clock is moved.
  seconds : int
    How far to move the clock in all.
  step : callable
    Called with no argument after each 2 s move.

  Returns
  -------
  None
  """
  # One turn per 2 s, the pause between two passes of the worker.
  for _ in range(seconds // 2):
    # The clock moves by one pause.
    plugin.now += 2
    # What the worker does at this pass.
    step()


class OpenOperationRepairTests(unittest.TestCase):

  def test_unchanged_open_snapshot_is_resent_every_30_s_for_600_s_and_then_every_600_s(self):
    """Over two hours of worker passes an unchanged open snapshot is sent 30 times, not 240."""
    # One open operation whose snapshot never changes again.
    plugin, operation, sends = _stuck_operation()
    # Two hours of worker passes, each one asking for the repair of the same snapshot.
    _passes(plugin, 7200, lambda: plugin._replicate_operation(operation))
    # As before while the snapshot is younger than 600 s; then one send per 600 s.
    self.assertEqual([age for age, _ in sends], list(range(30, 600, 30)) + list(range(1170, 7201, 600)))
    # Every send is the same snapshot.
    self.assertEqual({sequence for _, sequence in sends}, {1})

  def test_longer_wait_applies_in_every_open_phase(self):
    """The wait depends on the age of the snapshot and not on the phase: every phase but "completed" gets the same send times."""
    # Every phase the worker handles before "completed".
    open_phases = (
      "preparing", "cleaning_up_preparation", "accepted", "retiring_previous", "waiting_for_readiness",
      "stopping_failed_rollout", "restoring_previous", "finalizing", "finalizing_recovery",
    )
    # Each phase in turn.
    for phase in open_phases:
      # Each phase reports on its own.
      with self.subTest(phase=phase):
        # One operation saved in that phase, whose snapshot never changes again.
        plugin, operation, sends = _stuck_operation(phase=phase)
        # Half an hour of worker passes, each one asking for the repair of the same snapshot.
        _passes(plugin, 1800, lambda: plugin._replicate_operation(operation))
        # Every 30 s while the snapshot is younger than 600 s, then 600 s after the send before.
        self.assertEqual([age for age, _ in sends], list(range(30, 600, 30)) + [1170, 1770])

  def test_snapshot_just_under_600_s_old_keeps_the_30_s_repair(self):
    """The longer wait starts when the snapshot is 600 s old, not earlier."""
    # One open operation whose snapshot never changes again.
    plugin, operation, sends = _stuck_operation()
    # The snapshot is 568 s old and was last sent at START.
    plugin.now = START + 568
    # More than 30 s after the last send: sent.
    plugin._replicate_operation(operation)
    # 30 s later the snapshot is 598 s old, still under 600 s.
    plugin.now = START + 598
    # The 30 s wait still applies: sent again.
    plugin._replicate_operation(operation)
    # 30 s after the send at 568 s, with the snapshot 598 s old: sent.
    self.assertEqual([age for age, _ in sends], [568, 598])
    # 32 s later the snapshot is 630 s old.
    plugin.now = START + 630
    # The wait is now 600 s after the send at 598 s.
    plugin._replicate_operation(operation)
    # 32 s after the last send, but the snapshot is now over 600 s old: held back.
    self.assertEqual(len(sends), 2)

  def test_old_snapshot_is_sent_at_once_after_a_restart_and_then_every_600_s(self):
    """A process that has not sent the snapshot yet sends it on the first pass, whatever its age."""
    # One open operation whose snapshot never changes again.
    plugin, operation, sends = _stuck_operation()
    # A restart: the times of the confirmed sends are kept in process memory only.
    plugin._operations_confirmed.clear()
    # The new process finds the snapshot two hours old.
    plugin.now = START + 7200
    # Its first pass sends it, since it knows of no earlier send.
    plugin._replicate_operation(operation)
    # Three more passes, 30 s, 300 s and 599 s after that send.
    for wait in (30, 270, 299):
      # The clock moves to the next of the three times.
      plugin.now += wait
      # A pass inside the 600 s wait.
      plugin._replicate_operation(operation)
    # One send at once, none 30, 300 and 599 s after it.
    self.assertEqual([age for age, _ in sends], [7200])
    # One more second: 600 s after the send.
    plugin.now += 1
    # The wait is over.
    plugin._replicate_operation(operation)
    # The second send comes exactly 600 s after the first.
    self.assertEqual([age for age, _ in sends], [7200, 7800])

  def test_snapshot_never_confirmed_is_sent_on_every_pass_and_raises(self):
    """An old snapshot this process never saw confirmed is still written on every pass, and the caller is stopped."""
    # One open operation whose snapshot never changes again.
    plugin, operation, sends = _stuck_operation()
    # This process holds no confirmation of the snapshot.
    plugin._operations_confirmed.clear()
    # From now on no write is confirmed by the peers.
    plugin.replicate = False
    # The snapshot is two hours old, far past 600 s.
    plugin.now = START + 7200
    # Three worker passes.
    for _ in range(3):
      # The pause between two passes.
      plugin.now += 2
      # Each pass raises, so the caller does not act on state the peers may lack.
      with self.assertRaisesRegex(RuntimeError, "replication is pending"):
        # The repair call of the pass.
        plugin._replicate_operation(operation)
    # Each pass wrote the snapshot: the 600 s wait does not apply to one never confirmed.
    self.assertEqual(len(sends), 3)

  def test_unconfirmed_snapshot_is_not_held_back_by_a_recent_send_of_the_previous_one(self):
    """The wait belongs to one snapshot: a newer one that was never confirmed is sent on every pass, however old it gets."""
    # One open operation, its first snapshot confirmed at START.
    plugin, operation, sends = _stuck_operation()
    # From now on no write is confirmed by the peers.
    plugin.replicate = False
    # A new snapshot (sequence 2) is written but not confirmed; the operation in hand stays at sequence 1.
    with self.assertRaisesRegex(RuntimeError, "replication is pending"):
      # The save that writes snapshot 2 and raises because it is not confirmed.
      plugin._save_operation(operation, message="Previous nodes asked to stop again.")
    # The stored record, which is snapshot 2.
    pending = next(iter(plugin._operation_records().values()))
    # The operation in hand is still snapshot 1, the stored one is snapshot 2.
    self.assertEqual((operation["sequence"], pending["sequence"]), (1, 2))
    # 690 s later the confirmed snapshot 1 is repaired once more, which records a recent send for this operation.
    plugin.replicate = True
    # The clock moves past the 600 s wait of snapshot 1.
    plugin.now += 690
    # The repair send of snapshot 1, confirmed.
    plugin._replicate_operation(operation)
    # Writes are unconfirmed again for snapshot 2.
    plugin.replicate = False
    # Only the sends from here on are counted.
    del sends[:]
    # Snapshot 2 is now over 600 s old and the last recorded send is seconds old: it is still sent, and still raises.
    for _ in range(3):
      # The pause between two passes.
      plugin.now += 2
      # Each pass raises for the unconfirmed snapshot.
      with self.assertRaisesRegex(RuntimeError, "replication is pending"):
        # The repair call for snapshot 2.
        plugin._replicate_operation(pending)
    # Three passes, three writes of snapshot 2.
    self.assertEqual([sequence for _, sequence in sends], [2, 2, 2])

  def test_new_snapshot_of_an_old_operation_gets_the_30_s_repair_again(self):
    """When the operation changes, its new snapshot is young again and is repaired every 30 s."""
    # One open operation whose first snapshot was confirmed at START.
    plugin, operation, sends = _stuck_operation()
    # Two hours later, with snapshot 1 long past 600 s.
    plugin.now = START + 7200
    # A new event makes a new signed snapshot (sequence 2), written and confirmed now.
    plugin._save_operation(operation, message="Previous nodes asked to stop again.")
    # 30 s after that write.
    plugin.now += 30
    # The repair of the young snapshot.
    plugin._replicate_operation(operation)
    # The write of snapshot 2 and its repair 30 s later, not 600 s later.
    self.assertEqual(sends, [(7200, 2), (7230, 2)])

  def test_completed_operation_keeps_its_own_repair_timing(self):
    """The longer wait is for open operations only: a completed one is still sent after 30 s, and at once with `every=0`."""
    # One open operation.
    plugin, operation, sends = _stuck_operation()
    # It is completed: a new snapshot in the phase the longer wait leaves out.
    plugin._save_operation(operation, "completed", "Done.")
    # Only the sends from here on are counted.
    del sends[:]
    # Two hours later the completed snapshot is far past 600 s.
    plugin.now += 7200
    # First send: more than 30 s after the save.
    plugin._replicate_operation(operation)
    # 30 s after that send.
    plugin.now += 30
    # Second send: the 30 s wait, not the 600 s one.
    plugin._replicate_operation(operation)
    # Third send: no wait at all when the caller passes 0.
    plugin._replicate_operation(operation, every=0)
    # All three were written.
    self.assertEqual(len(sends), 3)

  def test_blocked_update_and_delete_are_resent_six_times_an_hour_by_the_worker(self):
    """Through the worker, an update and a delete that wait for a stop that never comes cost 6 sends an hour each."""
    # The two kinds of operation that stop previous nodes.
    for kind in ("update", "delete"):
      # Each kind reports on its own.
      with self.subTest(kind=kind):
        # One open operation of that kind.
        plugin, operation, sends = _stuck_operation(kind)
        # The operation passes its deadline on the first pass and is marked blocked: its last change.
        operation["deadline"] = START
        # The snapshot with that deadline, written and confirmed.
        plugin._save_operation(operation)
        # Only the sends of the worker passes are counted.
        del sends[:]
        # Three hours of the worker's own pass over the coordinator's operations.
        _passes(plugin, 3 * 3600, plugin._reconcile_coordinator_operations)
        # The stored record after those passes.
        blocked = next(iter(plugin._operation_records().values()))
        # It still waits for the previous nodes and is marked blocked.
        self.assertEqual((blocked["phase"], blocked["recovery"]), ("retiring_previous", "blocked"))
        # In the third hour the blocked snapshot is long unchanged: 6 sends, 600 s apart.
        late = [age for age, sequence in sends if age > 7200]
        # Six sends in that hour.
        self.assertEqual(len(late), 6)
        # Each one 600 s after the one before.
        self.assertEqual({second - first for first, second in zip(late, late[1:])}, {600})
        # The stop commands to the previous nodes are not slowed down: they go on every 10 s.
        self.assertGreater(len(plugin.commands), 2 * 3 * 300)


if __name__ == "__main__":
  # Run this file's tests when it is started as a script.
  unittest.main()
