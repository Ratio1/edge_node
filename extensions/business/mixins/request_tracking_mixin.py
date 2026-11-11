DEFAULT_REQUESTS_MAX_RECORDS = 2
DEFAULT_REQUESTS_LOG_INTERVAL = 5 * 60  # 300 seconds


class _RequestTrackingMixin(object):
  """
  Mixin that tells every node which node received a request, and whether it answered.

  A client call reaches one node. When that node does not finish it, the client cannot say
  which node it was, and the other nodes cannot know either. A plugin that uses this mixin
  records the requests it receives in the chain store, under its own node id, so every node
  holds the record and the node that holds an unanswered request can be named.

  Only the endpoints listed in ``REQUESTS_TRACKED_ENDPOINTS`` are recorded: the ones that start
  something (a deployment, an update, a delete). A read is never recorded. A chain-store write
  goes to every oracle and each one stores it and saves its replica again, so recording a read
  that a client repeats every two seconds made the whole network pay for every poll.

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
    # Time of the last write of the record. 0 lets the first tracked request be written at once.
    self.__rt_last_save_time = 0
    if self.__rt_cstore_hkey:
      # A plain list, not a deque(maxlen): a full deque drops its oldest entry, which pushed a
      # request that was never answered out of the record as soon as two newer ones arrived.
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

    When the record is full, room is made by dropping the oldest request that was answered. A
    request that was never answered is dropped only when every request in the record is
    unanswered, so the entry that names the node holding a request stays visible.

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
        # Not an endpoint that starts something: no record and no write. A read repeated by a
        # client must cost the network nothing.
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
        # Requests that were answered, oldest first: they are the ones that may leave the record.
        answered = [item for item in records if item['date_complete'] is not None]
        # Make room with the oldest answered request. Only when none was answered does the oldest
        # unanswered one go, so a request a node never finished is not pushed out by later calls.
        records.remove(answered[0] if answered else records[0])
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

    One replicated write: the record goes to every oracle under this node's id.

    Returns
    -------
    None
    """
    self.chainstore_hset(
      hkey=self.__rt_cstore_hkey,
      key=self.ee_id,
      value=list(self.__rt_recent_requests),
      debug=True
    )
    self.__rt_dirty = False
    # Start of the quiet period that REQUESTS_SAVE_INTERVAL enforces before the next write.
    self.__rt_last_save_time = self.time()
    return

  def _maybe_log_and_save_tracked_requests(self):
    """
    Write the record when it changed, and log every node's record now and then.

    Call from ``process()`` (plugin thread). The record is written only when a tracked request
    arrived or was answered since the last write, and never more often than once every
    ``REQUESTS_SAVE_INTERVAL`` seconds. The first change after a quiet period is written at
    once, so a request that hangs is known to the other nodes right away; a change inside the
    interval waits for its end. Every ``REQUESTS_LOG_INTERVAL`` seconds the records of all nodes
    are read from the local replica and logged.

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
    # the first change after a quiet period goes out at once, a burst of calls costs one write.
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
