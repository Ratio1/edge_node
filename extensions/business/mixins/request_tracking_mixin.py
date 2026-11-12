DEFAULT_REQUESTS_MAX_RECORDS = 2
DEFAULT_REQUESTS_LOG_INTERVAL = 5 * 60  # 300 seconds


class _RequestTrackingMixin(object):
  """
  Mixin that tells every node which node received a request, and whether it answered.

  A client call reaches one node. When that node does not finish it, the client cannot say
  which node it was, and the other nodes cannot know either. A plugin that uses this mixin
  records the requests it receives in the chain store, under its own node id, so every node
  holds the record of what the other nodes received.

  What the record can show is limited by where it is written. The write runs in ``process()``,
  on the plugin thread, after the web-app lap has run the queued requests. So a request is
  published as not answered only when a lap ends while it still waits in the queue (or when it
  was refused with a 503 before it ran, see ``_track_request``). A request whose endpoint hangs
  holds the plugin thread, so the record is not written while it hangs; a request that returns
  is usually written already answered. This was so before the record was limited to the
  tracked endpoints too.

  Only the endpoints listed in ``REQUESTS_TRACKED_ENDPOINTS`` are recorded. The list is meant for
  the endpoints that change state; reads are left out. A chain-store write goes to every oracle
  and each one stores it and saves its replica again, so recording a read that a client repeats
  every two seconds made the whole network pay for every poll.

  Opt-in: set REQUESTS_CSTORE_HKEY in plugin config to enable.
  When not set (None), all methods are no-ops.

  Config keys:
    REQUESTS_CSTORE_HKEY : str or None  -- chainstore hash key (None = disabled)
    REQUESTS_TRACKED_ENDPOINTS : list   -- names of the endpoints that are recorded; no other is
    REQUESTS_SAVE_INTERVAL : int        -- least seconds between two writes of the record
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

    Examples
    --------
    >>> def on_init(self):
    ...   super().on_init()
    ...   self._init_request_tracking()
    """
    self.__rt_recent_requests = None
    self.__rt_last_log_time = 0
    self.__rt_dirty = False
    # Time of the last write of the record. 0 lets the first change be written by the next
    # process() call, without waiting for an interval.
    self.__rt_last_save_time = 0
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
    It only changes memory: the chain-store write is left to
    ``_maybe_log_and_save_tracked_requests`` on the plugin thread.

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
    Write the record to the chain store (plugin thread only).

    One replicated write: the record goes to every oracle under this node's id. The changed flag
    is cleared before the record is copied, so a request that the monitor thread records while
    the write waits for the other oracles sets it again and is written by the next save.

    Returns
    -------
    None
    """
    # Clear the flag before the copy below: clearing it after the write forgot a request recorded
    # during the write, which then stayed unwritten until another tracked change.
    self.__rt_dirty = False
    self.chainstore_hset(
      hkey=self.__rt_cstore_hkey,
      key=self.ee_id,
      value=list(self.__rt_recent_requests),
      debug=True
    )
    # Start of the quiet period that REQUESTS_SAVE_INTERVAL enforces before the next write.
    self.__rt_last_save_time = self.time()
    return

  def _maybe_log_and_save_tracked_requests(self):
    """
    Write the record when it changed, and log every node's record now and then.

    Call from ``process()`` (plugin thread). The record is written only when a tracked request
    arrived or was answered since the last write, and never more often than once every
    ``REQUESTS_SAVE_INTERVAL`` seconds. The first change after a quiet period is written by the
    first call that sees it; a change inside the interval waits for its end. Every
    ``REQUESTS_LOG_INTERVAL`` seconds the records of all nodes are read from the local replica
    and logged.

    The web-app lap runs the queued requests before it calls ``process()``. So a write made here
    shows a request as answered, or as not answered in two cases: a lap ended while it still
    waited in the queue, or it was refused with a 503 before it ran. A request whose endpoint
    hangs holds the plugin thread, so nothing is written while it hangs.

    Returns
    -------
    None

    Notes
    -----
    The interval bounds what the record can cost whatever a caller does. The request is
    recorded before it is authenticated, so without the bound anyone who can reach the API
    could make every oracle store a record, and save its whole replica, once per call. With
    it a node writes its record at most ``60 / REQUESTS_SAVE_INTERVAL`` times a minute.

    Examples
    --------
    >>> def process(self):
    ...   self._maybe_log_and_save_tracked_requests()
    """
    if self.__rt_recent_requests is None:
      return
    # Write only a record that changed, and only once the interval since the last write has passed:
    # the first change after a quiet period goes out on this call, a burst of calls costs one write.
    if self.__rt_dirty and self.time() - self.__rt_last_save_time >= self.cfg_requests_save_interval:
      self.__rt_save()
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
