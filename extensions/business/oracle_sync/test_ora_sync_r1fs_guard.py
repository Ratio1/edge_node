# os.path: where the fake R1FS writes the file a CID names.
import os
# pickle: the files the fake R1FS serves are pickles, as oracle sync writes them.
import pickle
# tempfile: a folder of its own per test for those files.
import tempfile
# The test framework the edge node tests run under.
import unittest
# Small attribute holders for the network monitor.
from types import SimpleNamespace

# The SDK's R1FS engine, whose get_pickle (fetch, then its restricted load) the fake below runs unchanged.
from ratio1.ipfs.r1fs import R1FSEngine

# The message field names of the oracle-sync plugin.
from extensions.business.oracle_sync.sync_mixins.ora_sync_constants import OracleSyncCt
# The mixin under test.
from extensions.business.oracle_sync.sync_mixins.ora_sync_utils_mixin import _OraSyncUtilsMixin

# A CID as a peer message would carry it.
CID = "QmPeerMessageCid"
# The data the fake R1FS file holds.
DATA = {"n1": 1}
# The calls of _record_call; a full pickle load of a file built from _Callable adds one.
CALLS = []


def _record_call(word):
  """
  Record that a pickle load called this function.

  Parameters
  ----------
  word : str
    The argument the pickle passes.

  Returns
  -------
  str
    The same word.

  Examples
  --------
  >>> _record_call("called")
  'called'
  """
  # Leave a trace the test can check.
  CALLS.append(word)
  # A full load would return this as the file's data.
  return word


class _Callable:
  """
  An object whose pickle names `_record_call`, so a full pickle load calls that function.

  Returns
  -------
  _Callable
    The object to pickle.

  Examples
  --------
  >>> pickle.loads(pickle.dumps(_Callable()))   # a full load runs _record_call
  'called'
  """

  def __reduce__(self):
    """
    Tell pickle to rebuild this object by calling `_record_call("called")`.

    Returns
    -------
    tuple
      The function and its arguments.
    """
    # A file built from this names the function by module and name.
    return (_record_call, ("called",))


class _FakeR1fs:
  """
  An R1FS engine over files held in memory, with the SDK's own `get_pickle`.

  `get_file` writes the file a CID names into a folder and records the fetch; `get_pickle` is
  `R1FSEngine.get_pickle` unchanged, so the file is loaded by the SDK's restricted loader.

  Parameters
  ----------
  folder : str
    Folder the fetched files are written to.
  files : dict
    The pickle bytes of each CID.

  Returns
  -------
  _FakeR1fs
    The engine, with ``fetched`` listing every CID fetched.

  Examples
  --------
  >>> _FakeR1fs(tempfile.mkdtemp(), {CID: pickle.dumps(DATA)}).get_pickle(CID, raise_on_error=True)
  {'n1': 1}
  """
  # The SDK's get_pickle run on this fake: its fetch through get_file, then its restricted load.
  get_pickle = R1FSEngine.get_pickle
  # get_pickle runs only on a started engine.
  ipfs_started = True

  def __init__(self, folder, files):
    """
    Keep the folder and the files, with no fetch yet.

    Parameters
    ----------
    folder : str
      Folder the fetched files are written to.
    files : dict
      The pickle bytes of each CID.

    Returns
    -------
    None
    """
    # The folder, the file bytes by CID, and the CIDs fetched so far.
    self.folder, self.files, self.fetched = folder, files, []

  def get_file(self, cid, show_logs=True, return_absolute_path=False, **kwargs):  # pylint: disable=unused-argument
    """
    Record the fetch and write the file the CID names, as a download would.

    Parameters
    ----------
    cid : str
      The CID.
    show_logs : bool, optional
      Ignored.
    return_absolute_path : bool, optional
      Ignored; the path is absolute.
    **kwargs
      The other options of the real get_file, ignored.

    Returns
    -------
    str
      Path of the written file.
    """
    # Record the fetch, which must not happen while R1FS is disabled.
    self.fetched.append(cid)
    # The file lands under the CID's name in the folder.
    path = os.path.join(self.folder, cid)
    # Write the file's bytes.
    with open(path, "wb") as handle:
      # As the download leaves them.
      handle.write(self.files[cid])
    # Where get_pickle reads it.
    return path

  def P(self, msg, **kwargs):  # pylint: disable=unused-argument
    """
    Drop a log line of the engine.

    Parameters
    ----------
    msg : str
      The log line.
    **kwargs
      Log options.

    Returns
    -------
    None
    """
    return

  def Pd(self, msg, **kwargs):  # pylint: disable=unused-argument
    """
    Drop a debug log line of the engine.

    Parameters
    ----------
    msg : str
      The log line.
    **kwargs
      Log options.

    Returns
    -------
    None
    """
    return


class _Probe(_OraSyncUtilsMixin):
  """
  The oracle-sync utilities over a fake R1FS that records every fetch and loads with the SDK's loader.

  Parameters
  ----------
  use_r1fs : bool
    Value of the plugin's ``USE_R1FS`` setting.
  folder : str
    Folder the fake R1FS writes fetched files to.
  files : dict, optional
    The pickle bytes of each CID. Default: ``CID`` holding ``DATA``.

  Returns
  -------
  _Probe
    The probe, with ``r1fs.fetched``, ``logged`` and ``slept`` lists.

  Examples
  --------
  >>> _Probe(use_r1fs=True, folder=tempfile.mkdtemp()).r1fs_get_pickle(CID)
  {'n1': 1}
  """

  def __init__(self, use_r1fs, folder, files=None):  # pylint: disable=super-init-not-called
    """
    Set the configuration and the fakes the R1FS helpers use.

    Parameters
    ----------
    use_r1fs : bool
      Value of the plugin's ``USE_R1FS`` setting.
    folder : str
      Folder the fake R1FS writes fetched files to.
    files : dict, optional
      The pickle bytes of each CID. Default: ``CID`` holding ``DATA``.

    Returns
    -------
    None
    """
    # The settings the R1FS helpers and the received-data check read.
    self.cfg_use_r1fs, self.cfg_debug_sync, self.cfg_debug_sync_full = use_r1fs, False, False
    # The log lines and the retry pauses seen so far.
    self.logged, self.slept = [], []
    # The fake R1FS, serving a plain-data file under CID unless the test gives other files.
    self.r1fs = _FakeR1fs(folder, {CID: pickle.dumps(DATA)} if files is None else files)
    # Only used to name the sender in log lines.
    self.netmon = SimpleNamespace(network_node_eeid=lambda addr: "peer")

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

  def sleep(self, seconds):
    """
    Record the retry pause instead of waiting.

    Parameters
    ----------
    seconds : float
      Pause length.

    Returns
    -------
    None
    """
    # Keep the pause for the test to check.
    self.slept.append(seconds)

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
  """With USE_R1FS off, no file named by a peer message is fetched; with it on, files load as plain data only."""

  def setUp(self):
    """Give each test a folder of its own for the fetched files, removed after it."""
    # The folder, removed when the test ends.
    folder = tempfile.TemporaryDirectory()
    # Remove it whatever the test's outcome.
    self.addCleanup(folder.cleanup)
    # Its path, for the probes.
    self.folder = folder.name

  def test_with_r1fs_disabled_nothing_named_by_a_message_is_fetched_or_loaded(self):
    """With USE_R1FS off, r1fs_get_pickle returns None with one log line and no fetch, so no load."""
    # A plugin configured not to use R1FS.
    probe = _Probe(use_r1fs=False, folder=self.folder)
    # None, with nothing fetched and exactly one log line.
    self.assertEqual((probe.r1fs_get_pickle(cid=CID), probe.r1fs.fetched, len(probe.logged)), (None, [], 1))

  def test_with_r1fs_enabled_the_retrieval_is_unchanged(self):
    """With USE_R1FS on, the CID is fetched once and its plain-data file returned as before, through the SDK's
    restricted loader, with no pause."""
    # A plugin configured to use R1FS.
    probe = _Probe(use_r1fs=True, folder=self.folder)
    # The file named by the CID is fetched and loaded, and its data returned at the first try.
    self.assertEqual((probe.r1fs_get_pickle(cid=CID, debug=False), probe.r1fs.fetched, probe.slept),
                     (DATA, [CID], []))

  def test_a_file_that_names_a_callable_is_refused_and_nothing_of_it_runs(self):
    """A file whose pickle names a function is refused by the restricted loader: the function never runs, the
    three tries each end with the 3 s pause, the answer is None, and with debug each try's line gives the refusal."""
    # No call recorded by an earlier test.
    CALLS.clear()
    # A plugin using R1FS whose file under CID would call _record_call if fully loaded.
    probe = _Probe(use_r1fs=True, folder=self.folder, files={CID: pickle.dumps(_Callable())})
    # Refused: None after three fetches, each failed try followed by the 3 s pause, and nothing of the file ran.
    self.assertEqual((probe.r1fs_get_pickle(cid=CID, debug=True), probe.r1fs.fetched, probe.slept, CALLS),
                     (None, [CID] * 3, [3] * 3, []))
    # The three per-try lines name what the file asked for.
    tries = [line for line in probe.logged if line.startswith("Failed try")]
    # One per try, each giving the loader's refusal of _record_call.
    self.assertEqual([("R1FS pickle refused" in line, "_record_call" in line) for line in tries], [(True, True)] * 3)

  def test_a_refused_file_cannot_write_a_long_or_a_forged_log_line(self):
    """The per-try line of a refused file gives the error text escaped and cut to 200 characters: a file naming a
    module of over 5,000 characters that holds a newline leaves three lines of one line each, bounded in length."""
    # A module name holding a newline and a forged log text, then 5,000 more characters, and a function name.
    module, name = ("os\n[forged] oracle line" + "m" * 5000).encode(), b"system"
    # Its pickle (protocol 4): the two names as strings, then STACK_GLOBAL, which asks the loader for that function.
    crafted = (b"\x80\x04X" + len(module).to_bytes(4, "little") + module + b"X" + len(name).to_bytes(4, "little")
               + name + b"\x93.")
    # A plugin using R1FS whose file under CID is that pickle.
    probe = _Probe(use_r1fs=True, folder=self.folder, files={CID: crafted})
    # Refused: None after the three tries.
    self.assertIsNone(probe.r1fs_get_pickle(cid=CID, debug=True))
    # The fixed start of each per-try line, before the error text.
    start = "Failed try {}/3 to retrieve data from IPFS using CID " + CID + ": "
    # The error part of the three per-try lines.
    errors = [line[len(start.format(i + 1)):] for i, line in enumerate(probe.logged) if line.startswith("Failed try")]
    # Three, each escaped (it starts with the quote of a repr and holds no newline), at most 200 characters long
    # and still naming the refusal.
    self.assertEqual([(e[0], "\n" in e, len(e) <= 200, "R1FS pickle refused" in e) for e in errors],
                     [("'", False, True, True)] * 3)

  def test_every_caller_treats_the_refusal_as_a_message_not_accepted(self):
    """With USE_R1FS off, a CID in a message makes each caller reject the message, still without fetching."""
    # A plugin configured not to use R1FS.
    probe = _Probe(use_r1fs=False, folder=self.folder)
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
    # Through all three callers, nothing was fetched.
    self.assertEqual(probe.r1fs.fetched, [])


if __name__ == "__main__":
  # Run the tests of this file.
  unittest.main()
