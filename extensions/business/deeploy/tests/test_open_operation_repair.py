"""An open deployment operation whose snapshot stopped changing is re-sent to the peers every 600 s, not every 30 s."""
import unittest

from extensions.business.deeploy.deployment_mutations import _DeploymentMutationsMixin
from extensions.business.deeploy.deployment_operations import OPERATIONS_HKEY
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
  sends = []
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
      sends.append((plugin.now - START, value["sequence"]))
    return write(namespace, key, value, **kwargs)

  plugin.chainstore_hset = recording
  return sends


def _stuck_operation(kind="update"):
  """
  Build a coordinator with one open operation that waits for its previous nodes to stop.

  Parameters
  ----------
  kind : str
    The operation kind, "update" or "delete".

  Returns
  -------
  tuple
    `(plugin, operation, sends)`: the stand-in, the operation as saved (sequence 1, written
    and confirmed at START) and the list that records every later snapshot write.
  """
  plugin = _Coordinator()
  operation = plugin.operation("update")
  operation.update(kind=kind, phase="retiring_previous", deadline=10 ** 9)
  plugin._save_operation(operation)
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
  for _ in range(seconds // 2):
    plugin.now += 2
    step()


class OpenOperationRepairTests(unittest.TestCase):

  def test_unchanged_open_snapshot_is_resent_every_30_s_for_600_s_and_then_every_600_s(self):
    """Over two hours of worker passes an unchanged open snapshot is sent 30 times, not 240."""
    plugin, operation, sends = _stuck_operation()
    _passes(plugin, 7200, lambda: plugin._replicate_operation(operation))
    # As before while the snapshot is younger than 600 s; then one send per 600 s.
    self.assertEqual([age for age, _ in sends], list(range(30, 600, 30)) + list(range(1170, 7201, 600)))
    # Every send is the same snapshot.
    self.assertEqual({sequence for _, sequence in sends}, {1})

  def test_snapshot_just_under_600_s_old_keeps_the_30_s_repair(self):
    """The longer wait starts when the snapshot is 600 s old, not earlier."""
    plugin, operation, sends = _stuck_operation()
    plugin.now = START + 568
    plugin._replicate_operation(operation)
    plugin.now = START + 598
    plugin._replicate_operation(operation)
    # 30 s after the send at 568 s, with the snapshot 598 s old: sent.
    self.assertEqual([age for age, _ in sends], [568, 598])
    plugin.now = START + 630
    plugin._replicate_operation(operation)
    # 32 s after the last send, but the snapshot is now over 600 s old: held back.
    self.assertEqual(len(sends), 2)

  def test_old_snapshot_is_sent_at_once_after_a_restart_and_then_every_600_s(self):
    """A process that has not sent the snapshot yet sends it on the first pass, whatever its age."""
    plugin, operation, sends = _stuck_operation()
    # A restart: the times of the confirmed sends are kept in process memory only.
    plugin._operations_confirmed.clear()
    plugin.now = START + 7200
    plugin._replicate_operation(operation)
    for wait in (30, 270, 299):
      plugin.now += wait
      plugin._replicate_operation(operation)
    # One send at once, none 30, 300 and 599 s after it.
    self.assertEqual([age for age, _ in sends], [7200])
    plugin.now += 1
    plugin._replicate_operation(operation)
    self.assertEqual([age for age, _ in sends], [7200, 7800])

  def test_snapshot_never_confirmed_is_sent_on_every_pass_and_raises(self):
    """An old snapshot this process never saw confirmed is still written on every pass, and the caller is stopped."""
    plugin, operation, sends = _stuck_operation()
    plugin._operations_confirmed.clear()
    plugin.replicate = False
    plugin.now = START + 7200
    for _ in range(3):
      plugin.now += 2
      with self.assertRaisesRegex(RuntimeError, "replication is pending"):
        plugin._replicate_operation(operation)
    self.assertEqual(len(sends), 3)

  def test_unconfirmed_snapshot_is_not_held_back_by_a_recent_send_of_the_previous_one(self):
    """The wait belongs to one snapshot: a newer one that was never confirmed is sent on every pass, however old it gets."""
    plugin, operation, sends = _stuck_operation()
    plugin.replicate = False
    # A new snapshot (sequence 2) is written but not confirmed; the operation in hand stays at sequence 1.
    with self.assertRaisesRegex(RuntimeError, "replication is pending"):
      plugin._save_operation(operation, message="Previous nodes asked to stop again.")
    pending = next(iter(plugin._operation_records().values()))
    self.assertEqual((operation["sequence"], pending["sequence"]), (1, 2))
    # 690 s later the confirmed snapshot 1 is repaired once more, which records a recent send for this operation.
    plugin.replicate = True
    plugin.now += 690
    plugin._replicate_operation(operation)
    plugin.replicate = False
    del sends[:]
    # Snapshot 2 is now over 600 s old and the last recorded send is seconds old: it is still sent, and still raises.
    for _ in range(3):
      plugin.now += 2
      with self.assertRaisesRegex(RuntimeError, "replication is pending"):
        plugin._replicate_operation(pending)
    self.assertEqual([sequence for _, sequence in sends], [2, 2, 2])

  def test_new_snapshot_of_an_old_operation_gets_the_30_s_repair_again(self):
    """When the operation changes, its new snapshot is young again and is repaired every 30 s."""
    plugin, operation, sends = _stuck_operation()
    plugin.now = START + 7200
    # A new event makes a new signed snapshot (sequence 2), written and confirmed now.
    plugin._save_operation(operation, message="Previous nodes asked to stop again.")
    plugin.now += 30
    plugin._replicate_operation(operation)
    self.assertEqual(sends, [(7200, 2), (7230, 2)])

  def test_completed_operation_keeps_its_own_repair_timing(self):
    """The longer wait is for open operations only: a completed one is still sent after 30 s, and at once with `every=0`."""
    plugin, operation, sends = _stuck_operation()
    plugin._save_operation(operation, "completed", "Done.")
    del sends[:]
    plugin.now += 7200
    plugin._replicate_operation(operation)
    plugin.now += 30
    plugin._replicate_operation(operation)
    plugin._replicate_operation(operation, every=0)
    self.assertEqual(len(sends), 3)

  def test_blocked_update_and_delete_are_resent_six_times_an_hour_by_the_worker(self):
    """Through the worker, an update and a delete that wait for a stop that never comes cost 6 sends an hour each."""
    for kind in ("update", "delete"):
      with self.subTest(kind=kind):
        plugin, operation, sends = _stuck_operation(kind)
        # The operation passes its deadline on the first pass and is marked blocked: its last change.
        operation["deadline"] = START
        plugin._save_operation(operation)
        del sends[:]
        _passes(plugin, 3 * 3600, plugin._reconcile_coordinator_operations)
        blocked = next(iter(plugin._operation_records().values()))
        self.assertEqual((blocked["phase"], blocked["recovery"]), ("retiring_previous", "blocked"))
        # In the third hour the blocked snapshot is long unchanged: 6 sends, 600 s apart.
        late = [age for age, sequence in sends if age > 7200]
        self.assertEqual(len(late), 6)
        self.assertEqual({second - first for first, second in zip(late, late[1:])}, {600})
        # The stop commands to the previous nodes are not slowed down: they go on every 10 s.
        self.assertGreater(len(plugin.commands), 2 * 3 * 300)


if __name__ == "__main__":
  unittest.main()
