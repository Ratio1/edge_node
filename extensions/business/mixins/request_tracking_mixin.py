DEFAULT_REQUESTS_MAX_RECORDS = 2
DEFAULT_REQUESTS_LOG_INTERVAL = 5 * 60  # 300 seconds


class _RequestTrackingMixin(object):
  """
  Mixin that tells every node which node received a request, and whether it answered.

  A client call reaches one node. When that node does not finish it, the client cannot say
  which node it was, and the other nodes cannot know either. A plugin that uses this mixin
  records the requests it receives in the chain store, under its own node id, so every node
  holds the record of what the other nodes received.

  The record is written on the request monitor thread, from the web app's ``on_request_monitor_tick``
  hook (see ``_maybe_publish_tracked_requests``), and the write does not wait for the other nodes.
  The monitor thread is not held by an endpoint, so a request is published as not answered at the
  monitor's next turn after it was queued when no write was made in the last ``REQUESTS_SAVE_INTERVAL``
  seconds, else at the end of that interval, also when its endpoint then hangs and holds the plugin
  thread. The answer is stamped by the plugin thread and published at the end of the interval, so the
  other nodes can show a request as not answered for up to ``REQUESTS_SAVE_INTERVAL`` seconds after it
  was answered. Before, the plugin thread wrote the record at the end of its lap and waited for the
  other nodes: a request whose endpoint hung was never published while it hung. A plugin that does not
  call the publish from the hook writes nothing; the hook exists from the core release that has the
  chain store's ``wait=False`` write.

  Only the endpoints listed in ``REQUESTS_TRACKED_ENDPOINTS`` are recorded. The list is meant for
  the endpoints that change state; reads are left out. A chain-store write goes to every oracle
  and each one stores it and saves its replica again, so recording a read that a client repeats
  every two seconds made the whole network pay for every poll.

  Opt-in: set REQUESTS_CSTORE_HKEY in plugin config to enable. With it set, REQUESTS_TRACKED_ENDPOINTS and
  REQUESTS_SAVE_INTERVAL must be set too (they have no default); an empty REQUESTS_TRACKED_ENDPOINTS records
  nothing.
  When REQUESTS_CSTORE_HKEY is not set (None), all methods are no-ops.

  Config keys:
    REQUESTS_CSTORE_HKEY : str or None  -- chainstore hash key (None = disabled)
    REQUESTS_TRACKED_ENDPOINTS : list   -- names of the endpoints that are recorded; no other is (no default)
    REQUESTS_SAVE_INTERVAL : int        -- least seconds between two writes of the record (no default)
    REQUESTS_MAX_RECORDS : int          -- max requests kept in the record (default 2)
    REQUESTS_LOG_INTERVAL : int         -- seconds between cross-node log dumps (default 300)
  """

  @property
  def __rt_max_records(self):
    val = getattr(self, 'cfg_requests_max_records', None)
    if not isinstance(val, int) or val < 1:
      return DEFAULT_REQUESTS_MAX_RECORDS
    return val

  @property
  def __rt_log_interval(self):
    val = getattr(self, 'cfg_requests_log_interval', None)
    if not isinstance(val, (int, float)) or val <= 0:
      return DEFAULT_REQUESTS_LOG_INTERVAL
    return val

  @property
  def __rt_cstore_hkey(self):
    return getattr(self, 'cfg_requests_cstore_hkey', None)

  def _init_request_tracking(self):
    """
    Create the tracking state. Call from ``on_init()``.

    With ``REQUESTS_CSTORE_HKEY`` unset the record stays None and every other method of the
    mixin returns at once.

    Returns
    -------
    None

    Notes
    -----
    A plugin that publishes from ``on_request_monitor_tick`` calls this before the base ``on_init()``:
    the web-app base starts the request monitor thread there, and that thread calls ``_track_request``
    and the publish at once. It only reads the configuration and sets attributes, so it needs nothing
    the base ``on_init()`` creates.

    Examples
    --------
    >>> def on_init(self):
    ...   self._init_request_tracking()
    ...   super().on_init()
    """
    self.__rt_recent_requests = None
    self.__rt_last_log_time = 0
    self.__rt_dirty = False
    # Time of the last write of the record. 0 lets the first change be written at the request
    # monitor's next turn, without waiting for an interval.
    self.__rt_last_save_time = 0
    # The store's word for the last write, which the next write compares with: a refused one before its red line, a
    # stored one before its plain line. None before the first write, so the first refusal is logged and the first
    # stored write logs nothing.
    self.__rt_last_outcome = None
    if self.__rt_cstore_hkey:
      # A plain list, not a deque(maxlen): _track_request replaces it with a changed copy, so the
      # plugin thread, which iterates the record while the monitor thread adds to it, never
      # iterates a list that changes under it.
      self.__rt_recent_requests = []
    return

  def _track_request(self, request):
    """
    Record that a tracked endpoint received a request. Called from ``on_request``.

    Runs on the request monitor thread, before the endpoint and before any authentication.
    It only changes memory: the chain-store write is made by
    ``_maybe_publish_tracked_requests`` at the monitor's next turn.

    A request to an endpoint that is not in ``REQUESTS_TRACKED_ENDPOINTS`` is ignored. That is
    what keeps reads (a status poll every two seconds, a list of apps) out of the chain store.

    When the record is full, the oldest request leaves it, answered or not (first in, first out).

    A request refused with a 503 before it runs (refused when it arrived, or expired in the queue)
    is recorded here, because the web-app base calls ``on_request`` before it refuses, but it is
    never stamped, because the refusal does not call ``on_response``. It stays in the record as
    not answered until newer requests push it out.

    Parameters
    ----------
    request : dict
      The request as the web-app base hands it to ``on_request``: ``'id'`` is the request id
      and ``'value'`` is a list whose first item is the endpoint name.

    Returns
    -------
    None

    Notes
    -----
    The new list replaces the old one in a single assignment, so the plugin thread, which
    reads the record while this thread adds to it, sees either the old list or the new one.

    Examples
    --------
    >>> self._track_request({'id': 'ab12', 'value': ['create_pipeline', {...}]})   # recorded
    >>> self._track_request({'id': 'cd34', 'value': ['get_deployment_status', {...}]})   # ignored
    """
    if self.__rt_recent_requests is None:
      return
    try:
      value = request.get('value')
      request_id = request.get('id')
      endpoint = value[0] if isinstance(value, (list, tuple)) and len(value) > 0 else 'unknown'
      if endpoint not in self.cfg_requests_tracked_endpoints:
        # Not one of the tracked endpoints, which are the ones that change state: no record and no
        # write. A read repeated by a client must cost the network nothing.
        return
      record = {
        'id': request_id,
        'endpoint': endpoint,
        'date_start': self.datetime.now(self.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'date_complete': None,
      }
      # Work on a copy and swap it in below, so the plugin thread never sees a half-changed list.
      records = list(self.__rt_recent_requests)
      if len(records) >= self.__rt_max_records:
        # The record is full: the oldest request leaves, answered or not (first in, first out).
        records.pop(0)
      # The new request joins the record as "received, not answered yet".
      records.append(record)
      # One assignment: readers on the plugin thread get the old list or the new one.
      self.__rt_recent_requests = records
      self.__rt_dirty = True
    except Exception as e:
      self.P(f"Error tracking request in cstore: {e}", color='r')
    return

  def _track_response(self, method, response):
    """
    Stamp the time a tracked request was answered. Called from ``on_response``.

    Runs on the plugin thread. A response whose request was not recorded (an endpoint that is
    not tracked) changes nothing, so it causes no chain-store write.

    Parameters
    ----------
    method : str
      Endpoint name of the answered request; not used, the request id identifies the record.
    response : dict
      The response envelope; ``'id'`` is the id of the request it answers.

    Returns
    -------
    None

    Examples
    --------
    >>> self._track_response('create_pipeline', {'id': 'ab12', 'value': {...}})
    """
    if self.__rt_recent_requests is None:
      return
    try:
      request_id = response.get('id')
      for record in self.__rt_recent_requests:
        if record.get('id') == request_id:
          record['date_complete'] = self.datetime.now(self.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
          self.__rt_dirty = True
          break
    except Exception as e:
      self.P(f"Error tracking response in cstore: {e}", color='r')
    return

  def __rt_save(self):
    """
    Write the record to the chain store without waiting for the other oracles (request monitor thread).

    One replicated write with ``wait=False``: the record is stored in this node's replica and queued for
    every oracle under this node's id, and the call returns; the chain store sends it again while no
    oracle confirmed it. The changed flag is cleared before the record is copied, so an answer that the
    plugin thread stamps while the write runs sets it again and is written by the next save. A write the
    store does not take is logged in red with the store's word for it, when that word differs from the
    word of the write before it (a stored write's word included); the first stored write after one the
    store did not take logs one plain line with the word of the write not taken. Only the three transient words,
    ``not_ready`` (the store has not started or restarts, or another thread held the store's lock for
    more than 1 ms: the write waits at most 1 ms for it), ``error`` (the call raised) and
    ``refused_no_peers`` (this node sees no other oracle online, as while its broker link is down for
    over a minute; the store's peer list is refreshed every 60 s), leave the record marked as changed, so
    the save one interval later tries again. Every other refusal (``refused_readonly``, ``refused_token``
    and the other ``refused_*`` words) is final for this record: it is not tried again, and the record is
    written again only when it changes.

    Returns
    -------
    None

    Notes
    -----
    A word that stays logs one red line, not one per interval: a seed whose peer list holds only itself
    is refused with ``refused_no_peers`` at every try, and a store whose lock a namespace-sync merge keeps
    busy answers ``not_ready`` at every try while the merge runs. A stored write between two refusals, or
    another word, logs the next refusal again.

    The store does not count a ``not_ready`` write in its CSTORE_STATS line, so the plain line of the first
    stored write after a refusal (``... was published again after <word>.``) is what tells a trace that went
    out again from one still unsent. The first write, and a stored write after a stored write, log nothing.

    Examples
    --------
    >>> self.__rt_save()   # the chain store has not started: red line, tried again one interval later
    >>> self.__rt_save()   # not_ready again one interval later: tried again, no second red line
    >>> self.__rt_save()   # stored one interval later: one plain line, published again after not_ready
    >>> self.__rt_save()   # another owner holds the field (refused_readonly): one red line, not tried again
    """
    # Clear the flag before the copy below: clearing it after the write forgot a change made
    # during the write, which then stayed unwritten until another tracked change.
    self.__rt_dirty = False
    # The dict the chain store fills with its word for how the write ended; read for a write it did not take.
    info = {}
    # wait=False: stored here and queued for the other oracles, with no wait for their confirmations, so the
    # monitor thread goes back to admitting requests. Before, the plugin thread waited here for up to 3 x 10 s
    # and the result was not read. No debug=True any more: its four log lines per write each waited for the
    # interpreter lock on a node at its CPU limit, 22 ms a write (median) against 0.3 to 0.6 ms without them,
    # measured under a 0.35 CPU limit.
    if not self.chainstore_hset(
      hkey=self.__rt_cstore_hkey,
      key=self.ee_id,
      value=list(self.__rt_recent_requests),
      wait=False,
      result_info=info,
    ):
      # Not stored and not queued. A store that has not started (or restarts) or whose lock another thread held for
      # more than 1 ms, a call that raised, or a node that sees no other oracle online can take the same write later;
      # every other refused_* word is final for this record. refused_no_peers is retried: as a final word, the trace
      # of a request received while the node was cut off from the oracles stayed unsent after they came back online,
      # until the next tracked request.
      retry = info["outcome"] in ("not_ready", "error", "refused_no_peers")
      if retry:
        # The record stays marked as changed, so the save one interval later tries again. Before, every
        # refusal was tried again: a final one (a field another owner holds) every 30 s, for ever.
        self.__rt_dirty = True
      # One red line, for the operator reading the node log, only when this write's word differs from the last
      # write's. Before, a word that stayed (a seed with no other oracle, a lock a merge keeps busy) logged the same
      # line every 30 s.
      if info["outcome"] != self.__rt_last_outcome:
        # The store's word and whether the record is tried again.
        self.P(f"Request trace {self.__rt_cstore_hkey} was not published ({info['outcome']}); " + (
          f"it is tried again in {self.cfg_requests_save_interval} s." if retry else
          "it is not tried again until the record changes."), color='r')
    # A stored write right after a write the store did not take (the last word is neither None nor a stored write's
    # word): one plain line with that word, for the operator who read the red line. Before, nothing followed the red
    # line, and the store does not count a not_ready write in CSTORE_STATS, so the log read the same whether the
    # trace went out again or stayed unsent for hours.
    elif self.__rt_last_outcome not in (None, "changed", "identical"):
      self.P(f"Request trace {self.__rt_cstore_hkey} was published again after {self.__rt_last_outcome}.")
    # This write's word, which the next write compares with: a write the store does not take before its red line, a
    # stored one before its plain line. A stored write's word ("changed", "identical") differs from every refusal,
    # so the first refusal after it is logged again.
    self.__rt_last_outcome = info["outcome"]
    # Start of the quiet period that REQUESTS_SAVE_INTERVAL enforces before the next write.
    self.__rt_last_save_time = self.time()
    return

  def _maybe_publish_tracked_requests(self):
    """
    Write the record when it changed, at most once per interval.

    Call from ``on_request_monitor_tick()`` (request monitor thread): the web-app base calls that hook
    before each read of its request queue, about every 0.25 s while no request comes and right after
    each request was queued or refused. The record is written only when a tracked request arrived or
    was answered since the last write, and never more often than once every ``REQUESTS_SAVE_INTERVAL``
    seconds. The first change after a quiet period is written by the first call that sees it; a change
    inside the interval waits for its end.

    So a request is written as not answered right after it was queued when it ends a quiet period, else
    at the end of the interval, whatever its endpoint then does; a request that is answered is written
    a second time, with its answer, at the end of the interval. A request refused with a 503 before it
    ran is written as not answered too.

    Returns
    -------
    None

    Notes
    -----
    The interval bounds what the record can cost whatever a caller does. The request is
    recorded before it is authenticated, so without the bound anyone who can reach the API
    could make every oracle store a record, and save its whole replica, once per call. With
    it a node writes its record at most ``60 / REQUESTS_SAVE_INTERVAL`` times a minute.

    The monitor admits no request while this runs. The write does not wait for the other oracles, and it
    waits at most 1 ms for the chain store's lock, which a save's copy or a namespace-sync merge can hold
    for seconds: when the lock stays held, the write ends ``not_ready`` and is tried one interval later.

    Measured on the node image's interpreter under a 0.35 CPU limit, with the core's write path on its
    test harness (a replica of 5,700 records, 10 peers) and the node's logger, over 2,000 writes per run:
    one write takes 0.3 to 0.6 ms (median; the spread is from run to run) and under 1 ms (99th
    percentile), in an otherwise idle process and with one more thread that keeps the process at its CPU
    limit alike. The write passes no ``debug`` flag. With ``debug=True``, as it was first written, it
    took 1.1 ms (median) in an idle process and, at the CPU limit, 22 ms (median) and 32 ms (99th
    percentile): its four log lines each waited about 5 ms for the interpreter lock. A call with nothing
    due takes about 0.001 ms.

    Examples
    --------
    >>> def on_request_monitor_tick(self):
    ...   self._maybe_publish_tracked_requests()
    """
    if self.__rt_recent_requests is None:
      return
    # Write only a record that changed, and only once the interval since the last write has passed:
    # the first change after a quiet period goes out on this call, a burst of calls costs one write.
    if self.__rt_dirty and self.time() - self.__rt_last_save_time >= self.cfg_requests_save_interval:
      self.__rt_save()
    return

  def _maybe_log_tracked_requests(self):
    """
    Log every node's record now and then.

    Call from ``process()`` (plugin thread). Every ``REQUESTS_LOG_INTERVAL`` seconds the records of
    all nodes are read from the local replica and logged. Nothing is written here: the record is
    written by ``_maybe_publish_tracked_requests`` on the request monitor thread. Before, this function
    also wrote it (it was named ``_maybe_log_and_save_tracked_requests``).

    Returns
    -------
    None

    Examples
    --------
    >>> def process(self):
    ...   self._maybe_log_tracked_requests()
    """
    if self.__rt_recent_requests is None:
      return
    if (self.time() - self.__rt_last_log_time) > self.__rt_log_interval:
      try:
        hkey = self.__rt_cstore_hkey
        all_requests = self.chainstore_hgetall(hkey=hkey)
        if all_requests:
          self.P(f"{hkey} requests across all nodes:\n{self.json_dumps(all_requests, indent=2)}")
        else:
          self.P(f"{hkey} requests across all nodes: no data")
      except Exception as e:
        self.P(f"Error dumping requests from cstore: {e}", color='r')
      self.__rt_last_log_time = self.time()
    return
