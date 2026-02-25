DEFAULT_REQUESTS_MAX_RECORDS = 2
DEFAULT_REQUESTS_LOG_INTERVAL = 5 * 60  # 300 seconds


class _RequestTrackingMixin(object):
  """
  Mixin that adds chainstore-based request/response tracking to FastAPI plugins.

  Opt-in: set REQUESTS_CSTORE_HKEY in plugin config to enable.
  When not set (None), all methods are no-ops.

  Config keys:
    REQUESTS_CSTORE_HKEY : str or None  -- chainstore hash key (None = disabled)
    REQUESTS_MAX_RECORDS : int          -- max recent requests in deque (default 2)
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
    """Call from on_init(). Initializes tracking state if enabled."""
    self.__rt_recent_requests = None
    self.__rt_last_log_time = 0
    self.__rt_dirty = False
    if self.__rt_cstore_hkey:
      self.__rt_recent_requests = self.deque(maxlen=self.__rt_max_records)
    return

  def _track_request(self, request):
    """
    Called from on_request (monitor thread). Records request start.

    NOTE: does NOT write to chainstore — only appends to the in-memory deque
    and marks it dirty. The actual chainstore write is deferred to
    _track_response / _maybe_log_tracked_requests which run on the main thread,
    avoiding timer corruption from concurrent thread access.
    """
    if self.__rt_recent_requests is None:
      return
    try:
      value = request.get('value')
      request_id = request.get('id')
      endpoint = value[0] if isinstance(value, (list, tuple)) and len(value) > 0 else 'unknown'
      record = {
        'id': request_id,
        'endpoint': endpoint,
        'date_start': self.datetime.now(self.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'date_complete': None,
      }
      self.__rt_recent_requests.append(record)
      self.__rt_dirty = True
    except Exception as e:
      self.P(f"Error tracking request in cstore: {e}", color='r')
    return

  def _track_response(self, method, response):
    """Called from the response processing flow (main thread). Stamps completion time and flushes to chainstore."""
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
    if self.__rt_dirty:
      self.__rt_save()
    return

  def __rt_save(self):
    """Write recent requests to chainstore (main thread only)."""
    self.chainstore_hset(
      hkey=self.__rt_cstore_hkey,
      key=self.ee_id,
      value=list(self.__rt_recent_requests),
      debug=True
    )
    self.__rt_dirty = False
    return

  def _maybe_log_and_save_tracked_requests(self):
    """Call from process() (main thread). Flushes dirty data and periodically logs cross-node request data."""
    if self.__rt_recent_requests is None:
      return
    if self.__rt_dirty:
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
