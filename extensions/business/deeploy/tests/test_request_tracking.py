"""Every oracle must see the state-changing requests the others received, also while one hangs; a read costs nothing."""
import unittest
from datetime import datetime, timezone
# A host built from a few attributes, for the calls that need no plugin.
from types import SimpleNamespace
# The stand-in for the web app's on_init.
from unittest import mock

# The core's web app, whose request monitor calls the hook the Deeploy API overrides.
from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin

# Imported for the web-app base's stand-in it puts in place, before the dAuth and Deeploy modules below load: they are
# then built on the base every other Deeploy test file uses, whichever file one process imports first. Before, this
# file imported first built them on the core's base, whose ct has no setter, and the files on the stand-in then
# errored ("property 'ct' ... has no setter": 12 tests and sub-tests of test_process_request.py, 13 of
# test_secret_record_size_refusal.py, which borrows its _ProcessRequestStub).
import extensions.business.deeploy.tests.test_process_request
from extensions.business.dauth.dauth_manager import _CONFIG as DAUTH_CONFIG
# The module, for the base class its plugin calls on_init of.
from extensions.business.deeploy import deeploy_manager_api
from extensions.business.deeploy.deeploy_manager_api import _CONFIG as DEEPLOY_CONFIG
# The plugin class, for its own on_init, on_request_monitor_tick and process.
from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin
from extensions.business.mixins.request_tracking_mixin import _RequestTrackingMixin


class _Api(_RequestTrackingMixin):
  """The mixin on the smallest host that has what it uses, with a clock the test moves."""
  datetime = datetime
  timezone = timezone
  ee_id = "oracle-1"

  def __init__(self, config):
    """
    Build the host from a plugin's configuration and create the trace state.

    Parameters
    ----------
    config : dict
      A plugin's ``_CONFIG``; its five ``REQUESTS_*`` keys are read.

    Returns
    -------
    None

    Examples
    --------
    >>> api = _Api(DEEPLOY_CONFIG)
    >>> api.writes, api.waits
    ([], [])
    """
    # The five keys the mixin reads, as the plugin's cfg_ attributes.
    self.cfg_requests_cstore_hkey = config["REQUESTS_CSTORE_HKEY"]
    # The endpoints that are recorded.
    self.cfg_requests_tracked_endpoints = config["REQUESTS_TRACKED_ENDPOINTS"]
    # The least time between two writes.
    self.cfg_requests_save_interval = config["REQUESTS_SAVE_INTERVAL"]
    # How many requests the record holds.
    self.cfg_requests_max_records = config["REQUESTS_MAX_RECORDS"]
    # The time between two logs of every node's record.
    self.cfg_requests_log_interval = config["REQUESTS_LOG_INTERVAL"]
    # The clock, moved by tick() and lap().
    self.now = 1_000_000.0
    # What the other oracles would hold after each stored write: (request id, answered or not) per record.
    self.writes = []
    # The ``wait`` of every write call, the refused ones included.
    self.waits = []
    # The outcome word the store refuses a write with; None while it stores and queues every write.
    self.refusal = None
    # Something the plugin thread does while the monitor thread's next write is inside the store.
    self.during_write = None
    # Every log line as (text, colour).
    self.lines = []
    # The trace state, as the plugin's on_init creates it.
    self._init_request_tracking()

  def time(self):
    """
    The host's clock.

    Returns
    -------
    float
      ``self.now``, which only ``tick`` and ``lap`` move.

    Examples
    --------
    >>> _Api(DEEPLOY_CONFIG).time()
    1000000.0
    """
    return self.now

  def P(self, text, color=None, **kwargs):
    """
    Keep a log line with its colour.

    Parameters
    ----------
    text : str
      The line.
    color : str or None, optional
      Its colour; 'r' is the colour of a line that also goes to the error log.
    **kwargs
      Other options of the plugin's ``P``; not used.

    Returns
    -------
    None

    Examples
    --------
    >>> api = _Api(DEEPLOY_CONFIG)
    >>> api.P("line", color="r")
    >>> api.lines
    [('line', 'r')]
    """
    # Kept in the order written.
    self.lines.append((text, color))

  def json_dumps(self, value, **kwargs):
    """
    Text form of a value for the log of every node's record.

    Parameters
    ----------
    value : any
      The value.
    **kwargs
      Formatting options; not used.

    Returns
    -------
    str
      ``str(value)``.

    Examples
    --------
    >>> _Api(DEEPLOY_CONFIG).json_dumps({})
    '{}'
    """
    return str(value)

  def chainstore_hset(self, hkey, key, value, wait, result_info):
    """
    The chain store's hash write as the mixin uses it: every option the mixin passes is required.

    A stored write is kept as what the other oracles would then hold. A refused one (``self.refusal`` set) stores
    nothing. Either way the caller's dict gets the outcome word, as the chain store fills it. There is no
    ``debug`` option here: the trace write must not ask for the store's debug lines (a call that passes one
    fails), because each of them waits for the interpreter lock on a node at its CPU limit.

    Parameters
    ----------
    hkey : str
      The hash namespace.
    key : str
      The field: this node's id.
    value : list of dict
      The record: one dict per request.
    wait : bool
      Whether the caller waits for the other oracles' confirmations; kept in ``self.waits``.
    result_info : dict
      The caller's dict; its ``"outcome"`` is set.

    Returns
    -------
    bool
      True when stored and queued, False when refused.

    Examples
    --------
    >>> api, info = _Api(DEEPLOY_CONFIG), {}
    >>> api.chainstore_hset("DEEPLOY_REQUESTS", "oracle-1", [], wait=False, result_info=info), info
    (True, {'outcome': 'changed'})
    """
    # Whether this call waits, for the tests that require a non-blocking write.
    self.waits.append(wait)
    # What the store reads from the record when the call arrives: (request id, answered or not) per request.
    held = [(record["id"], record["date_complete"] is not None) for record in value]
    # The plugin thread's step that runs while this write is inside the store, taken once.
    during_write, self.during_write = self.during_write, None
    if during_write:
      # For example an endpoint returns and its answer is stamped.
      during_write()
    if self.refusal:
      # The store's word for the refusal; nothing is stored.
      result_info["outcome"] = self.refusal
      # Refused.
      return False
    # Stored here and queued for the other oracles.
    self.writes.append(held)
    # The word of a write that changed the replica.
    result_info["outcome"] = "changed"
    # Stored and queued.
    return True

  def chainstore_hgetall(self, hkey):
    """
    Every node's record as the local replica holds it: none in these tests.

    Parameters
    ----------
    hkey : str
      The hash namespace.

    Returns
    -------
    dict
      Empty.

    Examples
    --------
    >>> _Api(DEEPLOY_CONFIG).chainstore_hgetall("DEEPLOY_REQUESTS")
    {}
    """
    return {}

  def receive(self, request_id, endpoint):
    """
    The request monitor thread records a request as it queues it; nothing is written here.

    Parameters
    ----------
    request_id : str
      The request's id.
    endpoint : str
      The endpoint it calls.

    Returns
    -------
    None

    Examples
    --------
    >>> api = _Api(DEEPLOY_CONFIG)
    >>> api.receive("create-1", "create_pipeline")
    >>> api.waits
    []
    """
    # The request as the web-app base hands it to on_request.
    self._track_request({"id": request_id, "value": [endpoint, {}]})

  def answer(self, request_id, endpoint):
    """
    The plugin thread ran the endpoint and stamps the answer; nothing is written here.

    Parameters
    ----------
    request_id : str
      The answered request's id.
    endpoint : str
      Its endpoint.

    Returns
    -------
    None

    Examples
    --------
    >>> api = _Api(DEEPLOY_CONFIG)
    >>> api.receive("create-1", "create_pipeline")
    >>> api.answer("create-1", "create_pipeline")
    >>> api.waits
    []
    """
    # The response envelope as the web-app base hands it to on_response.
    self._track_response(endpoint, {"id": request_id})

  def tick(self, seconds=0):
    """
    One turn of the request monitor's loop, ``seconds`` later: the record is written when a write is due.

    Parameters
    ----------
    seconds : float, optional
      How far the clock moves before the turn. Default 0.

    Returns
    -------
    None

    Examples
    --------
    >>> api = _Api(DEEPLOY_CONFIG)
    >>> api.receive("create-1", "create_pipeline")
    >>> api.tick(0.25)
    >>> api.writes
    [[('create-1', False)]]
    """
    # The time of this turn.
    self.now += seconds
    # What the plugin's on_request_monitor_tick calls.
    self._maybe_publish_tracked_requests()

  def lap(self, seconds=0):
    """
    The end of a plugin lap, ``seconds`` later: ``process()`` logs every node's record when the log is due.

    Parameters
    ----------
    seconds : float, optional
      How far the clock moves before the lap ends. Default 0.

    Returns
    -------
    None

    Examples
    --------
    >>> api = _Api(DEEPLOY_CONFIG)
    >>> api.lap()
    >>> api.lines
    [('DEEPLOY_REQUESTS requests across all nodes: no data', None)]
    """
    # The time the lap ends.
    self.now += seconds
    # What the plugin's process() calls.
    self._maybe_log_tracked_requests()


class _InitOrderPlugin(DeeployManagerApiPlugin):
  """The Deeploy API's own ``on_init`` on a host without a node: only what that method and the trace use."""
  # The node id the trace is written under.
  ee_id = "oracle-1"
  # The date class the trace stamps a request with, also when a test double stands in for the web-app base.
  datetime = datetime
  # Its UTC zone.
  timezone = timezone
  # The addresses on_init logs; a class attribute, as the plugin's own ``bc`` is a property without a setter.
  bc = SimpleNamespace(address="0xai_oracle", eth_address="0xoracle")

  def __init__(self):
    """
    Give the host the configuration and the fields ``on_init`` reads, without the plugin's own constructor.

    Returns
    -------
    None

    Examples
    --------
    >>> _InitOrderPlugin().writes
    []
    """
    # The trace's configuration, as the Deeploy API's.
    self.cfg_requests_cstore_hkey = DEEPLOY_CONFIG["REQUESTS_CSTORE_HKEY"]
    # Its recorded endpoints.
    self.cfg_requests_tracked_endpoints = DEEPLOY_CONFIG["REQUESTS_TRACKED_ENDPOINTS"]
    # Its least time between two writes.
    self.cfg_requests_save_interval = DEEPLOY_CONFIG["REQUESTS_SAVE_INTERVAL"]
    # Its record size.
    self.cfg_requests_max_records = DEEPLOY_CONFIG["REQUESTS_MAX_RECORDS"]
    # Its log interval.
    self.cfg_requests_log_interval = DEEPLOY_CONFIG["REQUESTS_LOG_INTERVAL"]
    # The clock.
    self.now = 1_000_000.0
    # What the other oracles would hold after each write: (request id, answered or not) per record.
    self.writes = []

  def time(self):
    """
    The host's clock.

    Returns
    -------
    float
      ``self.now``.

    Examples
    --------
    >>> _InitOrderPlugin().time()
    1000000.0
    """
    # Moved by the test only.
    return self.now

  def P(self, *args, **kwargs):
    """
    Drop a log line.

    Parameters
    ----------
    *args
      The line.
    **kwargs
      Its options.

    Returns
    -------
    None

    Examples
    --------
    >>> _InitOrderPlugin().P("line")
    """
    return

  def _DeeployManagerApiPlugin__check_eth_balance(self):
    """
    Stand in for the web3 balance check of ``on_init``: the balance is enough.

    Returns
    -------
    bool
      True.

    Examples
    --------
    >>> _InitOrderPlugin()._DeeployManagerApiPlugin__check_eth_balance()
    True
    """
    # Enough, so on_init does not stop the tunnel engine.
    return True

  def _init_deployment_operations(self):
    """
    Stand in for the start of the deployment operations worker: no thread is started.

    Returns
    -------
    None

    Examples
    --------
    >>> _InitOrderPlugin()._init_deployment_operations()
    """
    return

  def chainstore_hset(self, hkey, key, value, wait, result_info):
    """
    The chain store's hash write as the trace uses it (no ``debug`` option): the write is stored and queued.

    Parameters
    ----------
    hkey : str
      The hash namespace.
    key : str
      The field: this node's id.
    value : list of dict
      The record: one dict per request.
    wait : bool
      Whether the caller waits for confirmations; not used.
    result_info : dict
      The caller's dict; its ``"outcome"`` is set.

    Returns
    -------
    bool
      True.

    Examples
    --------
    >>> plugin, info = _InitOrderPlugin(), {}
    >>> plugin.chainstore_hset("DEEPLOY_REQUESTS", "oracle-1", [], wait=False, result_info=info)
    True
    """
    # What the other oracles would now hold: (request id, answered or not) per request.
    self.writes.append([(record["id"], record["date_complete"] is not None) for record in value])
    # The word of a write that changed the replica.
    result_info["outcome"] = "changed"
    # Stored and queued.
    return True


class RequestTrackingTests(unittest.TestCase):

  def test_the_deeploy_api_records_the_requests_that_change_state_and_no_read(self):
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_CSTORE_HKEY"], "DEEPLOY_REQUESTS")
    # The commands to running apps, the CSP escrow reconciliation and the preferred-node save change
    # state too, and were recorded before the record was limited to a list.
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_TRACKED_ENDPOINTS"],
                     ["create_pipeline", "update_pipeline", "scale_up_job_workers", "delete_pipeline",
                      "send_instance_command", "send_app_command", "reconcile_csp_escrow_jobs",
                      "save_preferred_nodes"])
    self.assertEqual(DEEPLOY_CONFIG["REQUESTS_SAVE_INTERVAL"], 30)
    self.assertEqual(DAUTH_CONFIG["REQUESTS_TRACKED_ENDPOINTS"], [])

  def test_a_status_poll_every_two_seconds_writes_nothing(self):
    """A read is never written: 300 status polls and five other reads cause no write call, by tick or by lap."""
    # One client polled get_deployment_status about 25 times a minute for hours. Each poll was a
    # chain-store write that every oracle stored, confirmed and saved its whole replica for.
    api = _Api(DEEPLOY_CONFIG)
    # Ten minutes of polls, 2 s apart.
    for index in range(300):
      # The monitor records the poll as it queues it.
      api.receive("poll-%d" % index, "get_deployment_status")
      # The monitor's turn right after.
      api.tick()
      # The plugin lap answers the poll.
      api.answer("poll-%d" % index, "get_deployment_status")
      # The lap ends 2 s later.
      api.lap(2)
    # The other reads of the API.
    for endpoint in ("get_apps", "node_specs", "get_preferred_nodes", "get_r1fs_job_pipeline", "reveal_job_secrets"):
      # Received and queued.
      api.receive("read", endpoint)
      # The monitor's turn right after.
      api.tick()
      # Answered by the plugin lap.
      api.answer("read", endpoint)
      # The lap ends 2 s later.
      api.lap(2)
      # The monitor's turn after the answer.
      api.tick()
    # Not one write call, stored or refused.
    self.assertEqual(api.waits, [])

  def test_a_request_held_by_a_hung_endpoint_is_written_unanswered_by_the_tick_alone(self):
    """A request whose endpoint never returns is written as not answered by the monitor's tick, with wait=False,
    while no plugin lap runs at all; before, the plugin thread wrote the record, so nothing was written."""
    # The Deeploy API's trace.
    api = _Api(DEEPLOY_CONFIG)
    # The monitor records the request and queues it; its endpoint then holds the plugin thread for good.
    api.receive("create-1", "create_pipeline")
    # The monitor's next turn, at most about 0.25 s later. No lap() is called in this test.
    api.tick(0.25)
    # The other oracles hold the request as received and not answered.
    self.assertEqual(api.writes, [[("create-1", False)]])
    # The write did not wait for their confirmations: the monitor went back to admitting requests.
    self.assertEqual(api.waits, [False])
    # Ten more minutes of turns while the endpoint hangs.
    for _ in range(2400):
      # Nothing changed, so nothing is due.
      api.tick(0.25)
    # Still the one write.
    self.assertEqual(len(api.waits), 1)

  def test_the_trace_write_asks_the_chain_store_for_no_debug_lines(self):
    """The trace write passes only ``wait`` and ``result_info`` beside the key and the value, and no ``debug``:
    the four debug lines of a write each waited for the interpreter lock on a node at its CPU limit."""
    # The Deeploy API's trace.
    api = _Api(DEEPLOY_CONFIG)
    # The options of every write call, by name.
    seen = []

    def chainstore_hset(hkey, key, value, **options):
      """
      Take the write whatever options it passes, and keep their names.

      Parameters
      ----------
      hkey : str
        The hash namespace.
      key : str
        The field: this node's id.
      value : list of dict
        The record.
      **options
        Every other option of the call; ``result_info`` gets the outcome word.

      Returns
      -------
      bool
        True: stored and queued.

      Examples
      --------
      >>> chainstore_hset("DEEPLOY_REQUESTS", "oracle-1", [], wait=False, result_info={})
      True
      """
      # The names of the options this call passed.
      seen.append(sorted(options))
      # The word of a write that changed the replica.
      options["result_info"]["outcome"] = "changed"
      # Stored and queued.
      return True

    # The recording write in place of the host's own.
    api.chainstore_hset = chainstore_hset
    # A tracked request, then the monitor's turn that writes it.
    api.receive("create-1", "create_pipeline")
    # The write.
    api.tick()
    # One write, with these two options only.
    self.assertEqual(seen, [["result_info", "wait"]])

  def test_a_request_is_written_unanswered_at_once_and_its_answer_at_the_end_of_the_interval(self):
    """A request is written as not answered at the tick after it was queued; its answer, stamped by the plugin
    thread, is written by the first tick 30 s after that write, and nothing is written when nothing changed."""
    # The Deeploy API's trace.
    api = _Api(DEEPLOY_CONFIG)
    # Received and queued.
    api.receive("create-1", "create_pipeline")
    # The monitor's next turn writes it.
    api.tick()
    # Not answered yet.
    self.assertEqual(api.writes, [[("create-1", False)]])
    # The plugin lap answers it.
    api.answer("create-1", "create_pipeline")
    # A turn 29.75 s after the write: inside the interval.
    api.tick(29.75)
    # The answer waits for the end of the 30 s interval.
    self.assertEqual(len(api.writes), 1)
    # The turn at 30 s.
    api.tick(0.25)
    # The answer is out.
    self.assertEqual(api.writes[1:], [[("create-1", True)]])
    # Ten minutes later, nothing having changed.
    api.tick(600)
    # Nothing was written.
    self.assertEqual(len(api.writes), 2)

  def test_an_answer_stamped_during_a_write_is_written_by_the_next_one(self):
    """An answer the plugin thread stamps while the monitor thread's write is inside the store is not forgotten:
    the changed flag is cleared before the write, so the answer sets it again and the next write carries it."""
    # The Deeploy API's trace.
    api = _Api(DEEPLOY_CONFIG)
    # Received and queued.
    api.receive("create-1", "create_pipeline")
    # While the write is inside the store, the endpoint returns on the plugin thread.
    api.during_write = lambda: api.answer("create-1", "create_pipeline")
    # The monitor's turn: the write the answer falls into.
    api.tick()
    # That write held the request as not answered.
    self.assertEqual(api.writes, [[("create-1", False)]])
    # The first turn after the interval.
    api.tick(30)
    # The answer was written, although no other change came.
    self.assertEqual(api.writes[1:], [[("create-1", True)]])

  def test_a_burst_of_requests_is_one_write_now_and_one_after_the_interval(self):
    """However often a tracked endpoint is called, the record is written at most once per 30 s: 100 calls in 20 s
    are one write at the first and one after the interval."""
    # The request is recorded before it is authenticated: a caller must not be able to buy one
    # replicated write per call.
    api = _Api(DEEPLOY_CONFIG)
    # 100 calls, 0.2 s apart.
    for index in range(100):
      # Received and queued.
      api.receive("burst-%d" % index, "create_pipeline")
      # The monitor's turn after it.
      api.tick()
      # Answered by the plugin lap.
      api.answer("burst-%d" % index, "create_pipeline")
      # The monitor's next turn, 0.2 s later.
      api.tick(0.2)
    # One write, at the first call.
    self.assertEqual(len(api.writes), 1)
    # The first turn after the interval.
    api.tick(30)
    # The second write, with what the record holds then.
    self.assertEqual(len(api.writes), 2)

  def test_a_write_that_failed_for_a_transient_cause_is_tried_again_after_each_interval(self):
    """A write that failed for a transient cause (the store had not started or its lock was busy, the call raised,
    or the node saw no other oracle online) is not forgotten: one red line names the store's word, no further try
    is made inside the interval, a second failure in a row with the same word keeps the record for the interval
    after it without a second red line, and the first tick after the store takes writes again writes it."""
    # The three transient words; refused_no_peers clears once the node sees the oracles online again.
    for word in ("not_ready", "error", "refused_no_peers"):
      # One sub-test each.
      with self.subTest(outcome=word):
        # The Deeploy API's trace.
        api = _Api(DEEPLOY_CONFIG)
        # The write fails.
        api.refusal = word
        # Received and queued.
        api.receive("create-1", "create_pipeline")
        # The monitor's turn: the failed write.
        api.tick()
        # The red lines so far.
        red = [text for text, color in api.lines if color == "r"]
        # One non-blocking try, nothing stored, one red line.
        self.assertEqual((api.waits, api.writes, len(red)), ([False], [], 1))
        # The line names the store's word and says the record is tried again.
        self.assertEqual((word in red[0], "it is tried again in 30 s" in red[0]), (True, True))
        # 119 turns, 0.25 s apart: up to 29.75 s after the try.
        for _ in range(119):
          # Inside the interval nothing is tried.
          api.tick(0.25)
        # Still one try and one red line.
        self.assertEqual((len(api.waits), sum(color == "r" for _, color in api.lines)), (1, 1))
        # The turn at 30 s: the second try fails too, as with a store that has not started for over 30 s.
        api.tick(0.25)
        # Two tries and nothing stored, but still one red line: the word is the same, and a store whose lock a
        # merge keeps busy, or a seed with no other oracle, must not log the same line every 30 s.
        self.assertEqual((len(api.waits), sum(color == "r" for _, color in api.lines), api.writes), (2, 1, []))
        # The store takes writes again.
        api.refusal = None
        # The turn 30 s after the second try.
        api.tick(30)
        # The record is out, still not answered: the second failure did not drop it.
        self.assertEqual(api.writes, [[("create-1", False)]])

  def test_a_red_line_comes_again_only_when_a_write_ends_with_another_word(self):
    """The red line of a write the store did not take is logged again only when a write ends with another word
    than the write before it: a word that stays logs once, a new word logs, and a failure right after a stored
    write logs again, so the log still shows each new episode. The first stored write after a failure logs one
    plain line with the last failure's word, so the log shows that the record went out again; the first write
    and a stored write after a stored write log nothing."""
    # The Deeploy API's trace.
    api = _Api(DEEPLOY_CONFIG)
    # Per step: the store's word for that step's write (None: stored and queued), and the red and the plain lines
    # after it.
    steps = ((None, 0, 0), ("not_ready", 1, 0), ("not_ready", 1, 0), ("error", 2, 0), (None, 2, 1), (None, 2, 1),
             ("error", 3, 1))
    # One write per step, in this order.
    for word, red, plain in steps:
      # The store answers the next write with this word.
      api.refusal = word
      # A new request, so the record has a change to write also after a stored write.
      api.receive("create-%d" % len(api.waits), "create_pipeline")
      # The first turn after the interval makes the write.
      api.tick(30)
      # The red lines so far (none for a word the write before had too, none for a stored write) and the plain
      # ones (only for the stored write that follows a failure).
      self.assertEqual((sum(color == "r" for _, color in api.lines), sum(color is None for _, color in api.lines)),
                       (red, plain))
    # Seven writes were made, one per step, so every step above was a write and not a skipped turn.
    self.assertEqual(len(api.waits), 7)
    # The words the red lines name, read from the brackets of each line: the first not_ready, the first error,
    # and the error that followed the stored writes.
    self.assertEqual([text.split("(")[1].split(")")[0] for text, color in api.lines if color == "r"],
                     ["not_ready", "error", "error"])
    # The one plain line names the trace and the word of the last write the store did not take before it.
    self.assertEqual([text for text, color in api.lines if color is None],
                     ["Request trace DEEPLOY_REQUESTS was published again after error."])

  def test_a_write_the_store_refuses_for_good_is_logged_once_and_not_tried_again(self):
    """A write the store refuses by a final word (a field another owner holds) is logged in red once and not tried
    again, however long the record stays the same; a later change of the record is written as usual. Before, it
    was tried again with a red line every 30 s, for ever."""
    # Two of the final words.
    for word in ("refused_readonly", "refused_token"):
      # One sub-test each.
      with self.subTest(outcome=word):
        # The Deeploy API's trace.
        api = _Api(DEEPLOY_CONFIG)
        # The store refuses.
        api.refusal = word
        # Received and queued.
        api.receive("create-1", "create_pipeline")
        # The monitor's turn: the refused write.
        api.tick()
        # The red lines so far.
        red = [text for text, color in api.lines if color == "r"]
        # One try and one red line, which names the word and says the record is not tried again.
        self.assertEqual((len(api.waits), len(red), word in red[0], "is not tried again" in red[0]),
                         (1, 1, True, True))
        # Ten minutes of turns, a second apart.
        for _ in range(600):
          # Nothing changed, so nothing is tried.
          api.tick(1)
        # Still one try and one red line.
        self.assertEqual((len(api.waits), sum(color == "r" for _, color in api.lines)), (1, 1))
        # The store takes writes again, and a new request changes the record.
        api.refusal = None
        # Received and queued.
        api.receive("create-2", "create_pipeline")
        # The monitor's turn.
        api.tick()
        # The record is written, both requests in it.
        self.assertEqual(api.writes, [[("create-1", False), ("create-2", False)]])

  def test_the_plugin_lap_writes_nothing_and_logs_the_records_of_all_nodes_every_interval(self):
    """The plugin lap no longer writes the record: with a changed record and no tick, laps cause no write call
    and only log every node's record, once per REQUESTS_LOG_INTERVAL."""
    # The Deeploy API's trace.
    api = _Api(DEEPLOY_CONFIG)
    # A tracked request the monitor never gets a turn for in this test.
    api.receive("create-1", "create_pipeline")
    # The first lap logs.
    api.lap()
    # A lap 300 s later: the interval has not passed (it must be exceeded).
    api.lap(300)
    # The log lines so far.
    logged = [text for text, _ in api.lines if "requests across all nodes" in text]
    # One log, and no write call.
    self.assertEqual((len(logged), api.waits), (1, []))
    # One second later the log is due.
    api.lap(1)
    # Two logs, still no write call.
    self.assertEqual((sum("requests across all nodes" in text for text, _ in api.lines), api.waits), (2, []))

  def test_when_the_record_is_full_the_oldest_request_leaves_answered_or_not(self):
    """The record is first in, first out: a request never answered leaves it when two later ones arrived."""
    # First in, first out. A request refused with a 503 before it ran is never stamped; a rule that kept
    # unanswered requests first kept such a refusal in the record while any answered request was there
    # to leave in its place.
    api = _Api(DEEPLOY_CONFIG)  # the record holds two requests
    # A request that is never answered.
    api.receive("refused", "update_pipeline")
    # Two later requests, a minute apart.
    for index in range(2):
      # The monitor's turn a minute later writes what the record holds.
      api.tick(60)
      # The next request arrives.
      api.receive("later-%d" % index, "create_pipeline")
      # And is answered.
      api.answer("later-%d" % index, "create_pipeline")
    # The turn a minute after the last one.
    api.tick(60)
    # The unanswered request has left.
    self.assertEqual(api.writes[-1], [("later-0", True), ("later-1", True)])

  def test_when_no_request_was_answered_the_oldest_one_leaves(self):
    """With three requests none of which was answered, the record keeps the two newest."""
    # The Deeploy API's trace; its record holds two requests.
    api = _Api(DEEPLOY_CONFIG)
    # Three requests, a minute apart, none answered.
    for name in ("first", "second", "third"):
      # Received and queued.
      api.receive(name, "delete_pipeline")
      # The monitor's turn a minute later.
      api.tick(60)
    # The oldest has left.
    self.assertEqual(api.writes[-1], [("second", False), ("third", False)])

  def test_dauth_records_nothing(self):
    """dAuth tracks no endpoint: its requests cause no write call, by tick or by lap."""
    # dAuth's trace: no tracked endpoint.
    api = _Api(DAUTH_CONFIG)
    # Fifty requests, a second apart.
    for index in range(50):
      # Received.
      api.receive("auth-%d" % index, "get_auth_data")
      # The monitor's turn.
      api.tick()
      # Answered.
      api.answer("auth-%d" % index, "get_auth_data")
      # The lap ends a second later.
      api.lap(1)
    # Not one write call.
    self.assertEqual(api.waits, [])

  def test_the_deeploy_api_writes_from_the_monitor_tick_and_only_logs_from_its_lap(self):
    """The Deeploy API overrides the web app's monitor-tick hook with the write of the trace, and its process()
    only logs: the trace no longer depends on the plugin thread, which an endpoint that hangs holds."""
    # The core this runs on has the hook its request monitor calls; without it the override would never run and
    # the trace would never be written.
    self.assertTrue(callable(FastApiWebAppPlugin.on_request_monitor_tick))
    # The Deeploy class defines the hook itself, so it wins over the web app's no-op whatever the order of its bases.
    self.assertIn("on_request_monitor_tick", vars(DeeployManagerApiPlugin))
    # What the plugin's two entry points call, in order.
    calls = []
    # A host with the two trace steps, warmed up and with no relinked node.
    plugin = SimpleNamespace(
      _maybe_publish_tracked_requests=lambda: calls.append("write"),
      _maybe_log_tracked_requests=lambda: calls.append("log"),
      is_deeploy_warmed_up=lambda: True, _maybe_admit_node_relinks=lambda: None,
    )
    # The monitor's turn.
    DeeployManagerApiPlugin.on_request_monitor_tick(plugin)
    # It writes.
    self.assertEqual(calls, ["write"])
    # The end of a plugin lap.
    DeeployManagerApiPlugin.process(plugin)
    # It only logs.
    self.assertEqual(calls, ["write", "log"])

  def test_the_trace_state_exists_before_the_base_init_starts_the_monitor_thread(self):
    """The Deeploy API creates the trace state before the base on_init, which starts the request monitor thread:
    a request recorded and a tick made from inside the base on_init work, and the record is kept afterwards."""
    # The Deeploy API's on_init on a host without a node.
    plugin = _InitOrderPlugin()

    def base_on_init(self):
      """
      Stand in for the web app's ``on_init``: do what its request monitor thread does as soon as it starts.

      Parameters
      ----------
      self : _InitOrderPlugin
        The plugin being initialised.

      Returns
      -------
      None

      Examples
      --------
      >>> base_on_init(plugin)   # with the trace state missing this raises AttributeError
      """
      # The monitor hands the first request to the plugin.
      self.on_request({"id": "create-1", "value": ["create_pipeline", {}]})
      # And makes its next turn.
      self.on_request_monitor_tick()

    # The base on_init of the Deeploy class replaced by the stand-in (created if a test double has none).
    with mock.patch.object(deeploy_manager_api.BasePlugin, "on_init", base_on_init, create=True):
      # The plugin's own on_init, whole.
      plugin.on_init()
    # The request received during the base on_init was written, not answered.
    self.assertEqual(plugin.writes, [[("create-1", False)]])
    # The plugin thread answers it after on_init.
    plugin.on_response("create_pipeline", {"id": "create-1"})
    # The first turn after the interval.
    plugin.now += 30
    # The monitor's turn.
    plugin.on_request_monitor_tick()
    # The record survived the rest of on_init: its answer is written.
    self.assertEqual(plugin.writes[1:], [[("create-1", True)]])


if __name__ == "__main__":
  unittest.main()
