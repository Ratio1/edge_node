# os.path: the path helper the R1FS retrieval uses.
import os
# The test framework the edge node tests run under.
import unittest
# Small attribute holders for the fake R1FS and the network monitor.
from types import SimpleNamespace

# The message field names of the oracle-sync plugin.
from extensions.business.oracle_sync.sync_mixins.ora_sync_constants import OracleSyncCt
# The mixin under test.
from extensions.business.oracle_sync.sync_mixins.ora_sync_utils_mixin import _OraSyncUtilsMixin

# A CID as a peer message would carry it.
CID = "QmPeerMessageCid"
# The data the fake R1FS file holds.
DATA = {"n1": 1}


class _Probe(_OraSyncUtilsMixin):
  """
  The oracle-sync utilities over a fake R1FS that records every fetch and every pickle load.

  Parameters
  ----------
  use_r1fs : bool
    Value of the plugin's ``USE_R1FS`` setting.

  Returns
  -------
  _Probe
    The probe, with ``fetched``, ``loaded`` and ``logged`` lists.

  Examples
  --------
  >>> _Probe(use_r1fs=True).r1fs_get_pickle(CID)
  {'n1': 1}
  """

  def __init__(self, use_r1fs):  # pylint: disable=super-init-not-called
    """
    Set the configuration and the fakes the R1FS helpers use.

    Parameters
    ----------
    use_r1fs : bool
      Value of the plugin's ``USE_R1FS`` setting.

    Returns
    -------
    None
    """
    # The settings the R1FS helpers and the received-data check read.
    self.cfg_use_r1fs, self.cfg_debug_sync, self.cfg_debug_sync_full = use_r1fs, False, False
    # The R1FS fetches, the pickle loads and the log lines seen so far.
    self.fetched, self.loaded, self.logged = [], [], []
    # A fake R1FS whose file fetch is recorded and returns a local path named by the CID.
    self.r1fs = SimpleNamespace(get_file=lambda cid, show_logs: self.fetched.append(cid) or "/tmp/" + cid)
    # The real path helper, as on the plugin.
    self.os_path = os.path
    # Only used to name the sender in log lines.
    self.netmon = SimpleNamespace(network_node_eeid=lambda addr: "peer")

  def diskapi_load_pickle_from_output(self, filename):
    """
    Record a pickle load and return the fake file's data.

    Parameters
    ----------
    filename : str
      Path of the file to load.

    Returns
    -------
    dict
      A copy of ``DATA``.
    """
    # Record the load, which must not happen while R1FS is disabled.
    self.loaded.append(filename)
    # The fake file's data.
    return dict(DATA)

  def P(self, msg, **kwargs):  # pylint: disable=unused-argument
    """
    Record one log line.

    Parameters
    ----------
    msg : str
      The log line.
    **kwargs
      Color and other log options, ignored.

    Returns
    -------
    None
    """
    # Keep the line for the test to count.
    self.logged.append(msg)

  def sleep(self, seconds):  # pylint: disable=unused-argument
    """
    Skip the retry pause.

    Parameters
    ----------
    seconds : float
      Pause length, ignored.

    Returns
    -------
    None
    """
    return

  def time(self):
    """
    Return a fixed clock value.

    Returns
    -------
    float
      Always 0.0.
    """
    # A fixed clock: the timing logs are not under test.
    return 0.0

  def shorten_address(self, address):
    """
    Shorten an address for log lines.

    Parameters
    ----------
    address : str
      Node address.

    Returns
    -------
    str
      Its first 8 characters.
    """
    # Enough to name the sender in a log line.
    return address[:8]


class OraSyncR1fsGuardTests(unittest.TestCase):
  """With USE_R1FS off, no file named by a peer message is fetched or loaded; with it on, nothing changes."""

  def test_with_r1fs_disabled_nothing_named_by_a_message_is_fetched_or_loaded(self):
    """With USE_R1FS off, r1fs_get_pickle returns None with one log line and no fetch or load."""
    # A plugin configured not to use R1FS.
    probe = _Probe(use_r1fs=False)
    # None, with nothing fetched or loaded and exactly one log line.
    self.assertEqual((probe.r1fs_get_pickle(cid=CID), probe.fetched, probe.loaded, len(probe.logged)),
                     (None, [], [], 1))

  def test_with_r1fs_enabled_the_retrieval_is_unchanged(self):
    """With USE_R1FS on, the CID is fetched and its file loaded as before."""
    # A plugin configured to use R1FS.
    probe = _Probe(use_r1fs=True)
    # The file named by the CID is fetched and loaded, and its data returned.
    self.assertEqual((probe.r1fs_get_pickle(cid=CID, debug=False), probe.fetched, probe.loaded),
                     (DATA, [CID], ["/tmp/" + CID]))

  def test_every_caller_treats_the_refusal_as_a_message_not_accepted(self):
    """With USE_R1FS off, a CID in a message makes each caller reject the message, still without loading."""
    # A plugin configured not to use R1FS.
    probe = _Probe(use_r1fs=False)
    # A message whose local table is given by a CID.
    message = {OracleSyncCt.LOCAL_TABLE: CID}
    # The single-value helper returns None and leaves None in the message.
    self.assertEqual(
      (probe.r1fs_get_data_from_message(message_dict=message, data_key=OracleSyncCt.LOCAL_TABLE), message),
      (None, {OracleSyncCt.LOCAL_TABLE: None}),
    )
    # The per-epoch helper reports failure, which its callers answer by ignoring the message.
    success, _ = probe.r1fs_get_data_from_nested_message(nested_message_dict={"5": CID}, debug=False)
    # Failure reported.
    self.assertFalse(success)
    # A received message whose local table is given by a CID.
    oracle_data = {OracleSyncCt.STAGE: "S2", OracleSyncCt.LOCAL_TABLE: CID}
    # The received-data check rejects it.
    self.assertFalse(probe._check_received_oracle_data_for_values(
      sender="0xai_peer", oracle_data=oracle_data,
      expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE], verify=False,
    ))
    # Through all three callers, nothing was fetched or loaded.
    self.assertEqual((probe.fetched, probe.loaded), ([], []))


if __name__ == "__main__":
  # Run the tests of this file.
  unittest.main()
