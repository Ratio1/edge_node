from typing import Any

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

__VER__ = '0.2.3'

# Namespaces the node's own plugins keep in the chain store; they reach them through the plugin API, not over this
# HTTP API. Every data endpoint refuses a name that starts with one of these entries (each an exact name or a prefix).
SYSTEM_NAMESPACES = (
  # The composed key of a hash record, "hs:<hash of the hash key>:<field>" (built by chainstore_hset): refused so
  # the plain get and set cannot address a hash record by its raw key. A hash key with this prefix is refused too.
  "hs:",
  # dAuth: DAUTH_JOB_SECRETS, DAUTH_JOB_SECRET_REVISIONS, DAUTH_REVOKED_UNLICENSED_NODES and DAUTH_REQUESTS.
  "DAUTH_",
  # Deeploy: the job hashes DEEPLOY_DEPLOYED_JOBS, DEEPLOY_OPERATIONS and DEEPLOY_NODE_OPERATIONS, and DEEPLOY_REQUESTS.
  "DEEPLOY_",
  # Node key rotations, each one a signed proof written by dAuth servers.
  "NODE_KEY_ROTATIONS",
  # Tunnels Manager: tunnels_manager_secrets and tunnels_manager_tcp_routes.
  "tunnels_manager_",
  # Container-app file sync records, published by the node's container-app plugin.
  "CHAINSTORE_SYNC",
  # Deeploy Plus+ preferred-node lists, one per CSP owner.
  "plus_preferred_nodes",
  # Liveness marks of the chain-distribution monitor.
  "chain_dist_monitor",
  # Edge inference API: the capacity records and the delegated request and result mailboxes of a balancing group.
  "inference_api:",
)
# The exact hash keys the node's own plugins use, which the prefixes above stand for. A hash endpoint also refuses a
# hash key whose index (the hash part of its records' raw keys, as chainstore_hset composes it) equals the index of
# one of these, since its records are stored under the same raw keys.
SYSTEM_HASH_KEYS = (
  # dAuth: job secrets, their revisions, revoked unlicensed nodes, and the request log of the dAuth manager.
  "DAUTH_JOB_SECRETS", "DAUTH_JOB_SECRET_REVISIONS", "DAUTH_REVOKED_UNLICENSED_NODES", "DAUTH_REQUESTS",
  # Deeploy: the jobs hash, the operation and node-operation hashes, and the request log of the Deeploy manager.
  "DEEPLOY_DEPLOYED_JOBS", "DEEPLOY_OPERATIONS", "DEEPLOY_NODE_OPERATIONS", "DEEPLOY_REQUESTS",
  # Node key rotations.
  "NODE_KEY_ROTATIONS",
  # Tunnels Manager: tunnel credentials and TCP routes (the plugin's default TCP_ROUTES_HKEY).
  "tunnels_manager_secrets", "tunnels_manager_tcp_routes",
  # Container-app file sync records.
  "CHAINSTORE_SYNC",
  # Deeploy Plus+ preferred-node lists.
  "plus_preferred_nodes",
  # Liveness marks of the chain-distribution monitor.
  "chain_dist_monitor",
  # Edge inference API of the default balancing group; a named group's hash keys depend on the node's configuration.
  "inference_api:capacity:default", "inference_api:req:default", "inference_api:res:default",
)


_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': 31234,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  # Request-driven API with no process() of its own, running on every node: instead of lapping ~30 times a
  # second while idle, a lap with nothing queued blocks up to 0.25 s on the core wake-up event, which a
  # request, an input, an instance command or a stop ends at once. A core without this key ignores it.
  'IDLE_LOOP_WAIT' : 0.25,
  
  'CSTORE_VERBOSE' : 11,

  'DEBUG': False,
  'FORCE_DEBUG_EACH_NTH_API_CALL': 50,
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class CstoreManagerApiPlugin(BasePlugin):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for decentralized authentication.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(CstoreManagerApiPlugin, self).__init__(**kwargs)
    self.__forced_debug_window = None
    return
  
  
  def Pd(self, s, *args,  **kwargs):
    """
    Print a message to the console.
    """
    if self.cfg_debug:
      s = "[DEBUG] " + s
      self.P(s, *args, **kwargs)
    return


  def _make_empty_forced_debug_window(self):
    """
    Build the mutable state used for one forced-summary window.

    Returns
    -------
    dict
      Fresh per-window aggregation state. The dictionary contains:

      ``total_calls`` : int
        Number of API calls observed in the current window.
      ``total_errors`` : int
        Number of failed API calls observed in the current window.
      ``endpoints`` : dict
        Per-endpoint latency and error aggregates.
      ``targets`` : dict
        Counts keyed by logical CStore namespace. For hash operations this is
        the ``hkey``. For key/value operations this is the prefix before the
        first ``:`` in the key.

    Notes
    -----
    The window is intentionally small and reset after every emitted summary so
    the log line reflects recent usage instead of lifetime totals.
    """
    return {
      "total_calls": 0,
      "total_errors": 0,
      "endpoints": {},
      "targets": {},
    }


  def _get_force_debug_each_nth_api_call(self):
    """
    Return the configured forced-summary interval.

    Returns
    -------
    int
      Positive integer threshold for periodic summaries. Returns ``0`` when
      the feature is disabled or configured with an invalid value.

    Notes
    -----
    The implementation falls back to ``CONFIG`` so unit tests can execute the
    plugin without the full runtime configuration machinery that normally
    materializes ``cfg_*`` attributes.
    """
    configured_value = getattr(
      self,
      "cfg_force_debug_each_nth_api_call",
      self.CONFIG.get("FORCE_DEBUG_EACH_NTH_API_CALL", 0),
    )
    if isinstance(configured_value, bool) or not isinstance(configured_value, int):
      return 0
    return max(0, configured_value)


  def _get_forced_debug_window(self):
    """
    Return the active forced-summary window, creating it lazily.

    Returns
    -------
    dict
      Mutable aggregation state for the current forced-summary window.
    """
    if self.__forced_debug_window is None:
      self.__forced_debug_window = self._make_empty_forced_debug_window()
    return self.__forced_debug_window


  def _reset_forced_debug_window(self):
    """
    Reset forced-summary aggregation after one summary emission.

    Returns
    -------
    None
    """
    self.__forced_debug_window = self._make_empty_forced_debug_window()
    return


  def _get_usage_target(self, endpoint_name, key=None, hkey=None):
    """
    Resolve the logical CStore namespace associated with one API call.

    Parameters
    ----------
    endpoint_name : str
      API endpoint identifier such as ``"get"`` or ``"hgetall"``.
    key : str, optional
      Flat key for ``get`` and ``set`` requests.
    hkey : str, optional
      Hash namespace for ``hget``, ``hset``, ``hgetall``, and ``hsync``.

    Returns
    -------
    str or None
      Namespace label used in periodic summaries. Hash operations return the
      provided ``hkey`` as-is. Flat key operations return the prefix before the
      first ``:`` so related keys such as ``run:slot-1`` and ``run:slot-2`` are
      grouped together. Returns ``None`` when no stable label can be derived.
    """
    if endpoint_name in {"hget", "hgetall", "hset", "hsync"}:
      if isinstance(hkey, str) and len(hkey) > 0:
        return hkey
      return None

    if not isinstance(key, str) or len(key) == 0:
      return None

    prefix, _, _ = key.partition(":")
    return prefix or key


  def _emit_forced_debug_summary(self, window):
    """
    Emit one compact usage summary for the just-completed window.

    Parameters
    ----------
    window : dict
      Aggregation state produced by ``_record_forced_debug_call``.

    Returns
    -------
    None

    Notes
    -----
    The output is intentionally short. It includes overall call and error
    counts, per-endpoint latency aggregates, and a compact view of the most
    frequently accessed logical targets on this node.
    """
    endpoint_parts = []
    for endpoint_name in sorted(window["endpoints"]):
      endpoint_stats = window["endpoints"][endpoint_name]
      avg_duration_s = endpoint_stats["total_duration_s"] / endpoint_stats["count"]
      endpoint_parts.append(
        (
          f"{endpoint_name}[count={endpoint_stats['count']},"
          f"err={endpoint_stats['errors']},"
          f"avg={avg_duration_s:.4f}s,"
          f"min={endpoint_stats['min_duration_s']:.4f}s,"
          f"max={endpoint_stats['max_duration_s']:.4f}s]"
        )
      )

    sorted_targets = sorted(
      window["targets"].items(),
      key=lambda item: (-item[1], item[0]),
    )[:3]
    targets_summary = ",".join(f"{target}({count})" for target, count in sorted_targets) or "n/a"

    self.P(
      "CStore API usage summary: "
      f"calls={window['total_calls']} "
      f"errors={window['total_errors']} "
      f"endpoints={'; '.join(endpoint_parts) or 'n/a'} "
      f"targets={targets_summary}"
    )
    return


  def _record_forced_debug_call(self, endpoint_name, duration_s, ok=True, key=None, hkey=None):
    """
    Record one API call in the current forced-summary window.

    Parameters
    ----------
    endpoint_name : str
      API endpoint identifier such as ``"get"``, ``"hset"``, or ``"hsync"``.
    duration_s : float
      Elapsed call duration in seconds.
    ok : bool, optional
      Whether the call completed successfully. Failed calls contribute to error
      counters and are still included in latency statistics. Default is
      ``True``.
    key : str, optional
      Flat key associated with the call.
    hkey : str, optional
      Hash namespace associated with the call.

    Returns
    -------
    None

    Notes
    -----
    This path is inactive when ``DEBUG`` is enabled because detailed per-call
    debugging is already available in that mode.
    """
    if self.cfg_debug:
      return

    threshold = self._get_force_debug_each_nth_api_call()
    if threshold <= 0:
      return

    window = self._get_forced_debug_window()
    window["total_calls"] += 1
    if not ok:
      window["total_errors"] += 1

    endpoint_stats = window["endpoints"].setdefault(
      endpoint_name,
      {
        "count": 0,
        "errors": 0,
        "total_duration_s": 0.0,
        "min_duration_s": None,
        "max_duration_s": 0.0,
      },
    )
    endpoint_stats["count"] += 1
    if not ok:
      endpoint_stats["errors"] += 1
    endpoint_stats["total_duration_s"] += duration_s
    if endpoint_stats["min_duration_s"] is None or duration_s < endpoint_stats["min_duration_s"]:
      endpoint_stats["min_duration_s"] = duration_s
    if duration_s > endpoint_stats["max_duration_s"]:
      endpoint_stats["max_duration_s"] = duration_s

    target = self._get_usage_target(endpoint_name=endpoint_name, key=key, hkey=hkey)
    if target is not None:
      window["targets"][target] = window["targets"].get(target, 0) + 1

    if window["total_calls"] >= threshold:
      self._emit_forced_debug_summary(window)
      self._reset_forced_debug_window()
    return


  def _run_api_call(self, endpoint_name, operation, *, key=None, hkey=None):
    """
    Execute one API operation with shared timing and summary accounting.

    Every data endpoint runs through here, so this is also where a request for
    a system namespace is refused: the namespace the request addresses (``hkey``
    on the hash endpoints, the raw ``key`` on the plain get and set) is checked
    against ``SYSTEM_NAMESPACES`` before ``operation`` runs, and on the hash
    endpoints the index of ``hkey`` (``get_hash(hkey, algorithm='sha256',
    length=10)``, as ``chainstore_hset`` composes it) is compared with the
    indexes of ``SYSTEM_HASH_KEYS``. A refused request leaves one red log line
    naming the endpoint and the first 64 characters of the namespace, never
    the value, and is not counted in the forced-summary window.

    Parameters
    ----------
    endpoint_name : str
      Human-readable endpoint label used in debug and summary logs.
    operation : callable
      Zero-argument callable that performs the actual CStore operation.
    key : str, optional
      Flat key of ``get`` and ``set``, or the field of ``hget`` and ``hset``;
      also used for usage grouping.
    hkey : str, optional
      Hash namespace of the hash endpoints; also used for usage grouping.

    Returns
    -------
    Any
      Result returned by ``operation``. For a system namespace, the error
      answer ``{"error": str, "status_code": 403, "logged": True}`` instead,
      and ``operation`` does not run.

    Raises
    ------
    Exception
      Re-raises any exception from ``operation`` after the failed call is
      recorded in the forced-summary window.

    Examples
    --------
    >>> plugin._run_api_call("hget", lambda: 1, key="node-1", hkey="ratio1:backend:offline_nodes_notifier:v1")
    1
    >>> plugin._run_api_call("hget", lambda: 1, key="7", hkey="DEEPLOY_DEPLOYED_JOBS")["status_code"]
    403
    """
    # The namespace the request addresses: the hash key on the hash endpoints, the raw key on plain get and set.
    namespace = key if hkey is None else hkey
    # Refuse a namespace kept by the node's own plugins before the store is touched: a name with a system prefix,
    # or a hash key whose index, composed as chainstore_hset composes it, equals the index of a system hash key.
    if namespace.startswith(SYSTEM_NAMESPACES) or (
      hkey is not None
      and self.get_hash(hkey, algorithm='sha256', length=10)
      in [self.get_hash(name, algorithm='sha256', length=10) for name in SYSTEM_HASH_KEYS]
    ):
      # Log the namespace cut to 64 characters, so a caller cannot write arbitrarily long log lines.
      self.P(f"CStore {endpoint_name} refused for system namespace '{namespace[:64]}'", color='r')
      # The error answer the web-app base gives for a failed request, with 403: this API does not serve it.
      return {
        "error": f"Namespace '{namespace}' is reserved for the node's plugins.", "status_code": 403, "logged": True,
      }
    start_timer = self.time()
    try:
      result = operation()
    except Exception:
      elapsed_time = self.time() - start_timer
      self._record_forced_debug_call(
        endpoint_name=endpoint_name,
        duration_s=elapsed_time,
        ok=False,
        key=key,
        hkey=hkey,
      )
      raise

    elapsed_time = self.time() - start_timer
    self.Pd(f"CStore {endpoint_name} took {elapsed_time:.4f} seconds")
    self._record_forced_debug_call(
      endpoint_name=endpoint_name,
      duration_s=elapsed_time,
      ok=True,
      key=key,
      hkey=hkey,
    )
    return result
  


  def on_init(self):
    super(CstoreManagerApiPlugin, self).on_init()
    my_address = self.bc.address
    my_eth_address = self.bc.eth_address
    self.P("Started {} plugin on {} / {}".format(
      self.__class__.__name__, my_address, my_eth_address,
    ))
    return


  ### DANGER ZONE: Disabled endpoints that expose all keys in chainstore ###
  # def __get_keys(self):
  #   result = []
  #   _data = self.plugins_shmem.get('__chain_storage', {})
  #   if isinstance(_data, dict):
  #     result = list(_data.keys())
  #   return result

  ### END DANGER ZONE ###

  @BasePlugin.endpoint(method="get", require_token=False)
  def get_status(self):   # /get_status
    """
    Get the current status of the chainstore API.
    
    Returns:
        dict: A dictionary containing the status information
    """
    return {"ok": True, "message": "CStore Manager API is running."}
  

  @BasePlugin.endpoint(method="post", require_token=False)
  def set(self, key: str, value: Any, chainstore_peers: list = None):
    """
    Set a key-value pair in the chainstore with any value type.

    ``key`` is a raw key. A key in a system namespace (``SYSTEM_NAMESPACES``)
    is refused, and so is a raw key in the composed form of a hash record
    (``hs:<hash of the hash key>:<field>``, as ``chainstore_hset`` builds it):
    hash records are written only through ``hset``.

    Parameters
    ----------
    key : str
      The key to store the value under.
    value : Any
      The value to store (any type supported by chainstore).
    chainstore_peers : list, optional
      Extra chainstore peers.

    Returns
    -------
    bool or dict
      The result of the write operation, or for a refused key the error answer
      ``{"error": str, "status_code": 403, "logged": True}``.

    Examples
    --------
    >>> plugin.set(key="app:counter", value=3)
    True
    >>> plugin.set(key="hs:0123456789:ZmllbGQ=", value=3)["status_code"]
    403
    """
    if chainstore_peers is None:
      chainstore_peers = []

    return self._run_api_call(
      "set",
      lambda: self.chainstore_set(
        key=key,
        value=value,
        debug=self.cfg_debug,
        extra_peers=chainstore_peers,
      ),
      key=key,
    )

  @BasePlugin.endpoint(method="get", require_token=False)
  def get(self, key: str):
    """
    Retrieve a value from the chainstore by key.

    ``key`` is a raw key. A key in a system namespace (``SYSTEM_NAMESPACES``)
    is refused, and so is a raw key in the composed form of a hash record
    (``hs:<hash of the hash key>:<field>``, as ``chainstore_hset`` builds it):
    hash records are read only through ``hget`` and ``hgetall``.

    Parameters
    ----------
    key : str
      The key to retrieve the value for.

    Returns
    -------
    Any
      The value associated with the given key, or None if not found. For a
      refused key, the error answer ``{"error": str, "status_code": 403,
      "logged": True}``.

    Examples
    --------
    >>> plugin.get(key="app:counter")
    3
    >>> plugin.get(key="hs:0123456789:ZmllbGQ=")["status_code"]
    403
    """
    return self._run_api_call(
      "get",
      lambda: self.chainstore_get(key=key, debug=self.cfg_debug),
      key=key,
    )


  @BasePlugin.endpoint(method="post", require_token=False)
  def hset(self, hkey: str, key: str, value: Any, chainstore_peers: list = None):
    """
    Set a field-value pair within a hash in the chainstore.

    A hash key in a system namespace (``SYSTEM_NAMESPACES``) is refused, and
    so is one whose index equals the index of a system hash key
    (``SYSTEM_HASH_KEYS``).

    Parameters
    ----------
    hkey : str
      The hash key (outer key).
    key : str
      The field key within the hash.
    value : Any
      The value to store for the field (any type supported by chainstore).
    chainstore_peers : list, optional
      Extra chainstore peers.

    Returns
    -------
    bool or dict
      The result of the write operation, or for a refused hash key the error
      answer ``{"error": str, "status_code": 403, "logged": True}``.

    Examples
    --------
    >>> plugin.hset(hkey="ratio1:backend:offline_nodes_notifier:v1", key="node-1", value={"seen": 1})
    True
    """
    # Log request
    if chainstore_peers is None:
      chainstore_peers = []

    return self._run_api_call(
      "hset",
      lambda: self.chainstore_hset(
        hkey=hkey,
        key=key,
        value=value,
        debug=self.cfg_debug,
        extra_peers=chainstore_peers,
      ),
      key=key,
      hkey=hkey,
    )


  @BasePlugin.endpoint(method="get", require_token=False)
  def hget(self, hkey: str, key: str):
    """
    Retrieve a field value from a hset in the chainstore.

    A hash key in a system namespace (``SYSTEM_NAMESPACES``) is refused, and
    so is one whose index equals the index of a system hash key
    (``SYSTEM_HASH_KEYS``).

    Parameters
    ----------
    hkey : str
      The hash key (outer key).
    key : str
      The field key within the hset.

    Returns
    -------
    Any
      The value associated with the given field in the hset, or None if not
      found. For a refused hash key, the error answer ``{"error": str,
      "status_code": 403, "logged": True}``.

    Examples
    --------
    >>> plugin.hget(hkey="ratio1:backend:offline_nodes_notifier:v1", key="node-1")
    {'seen': 1}
    """
    return self._run_api_call(
      "hget",
      lambda: self.chainstore_hget(hkey=hkey, key=key, debug=self.cfg_debug),
      key=key,
      hkey=hkey,
    )


  @BasePlugin.endpoint(method="get", require_token=False)
  def hgetall(self, hkey: str):
    """
    Retrieve all field-value pairs from a hset in the chainstore.

    A hash key in a system namespace (``SYSTEM_NAMESPACES``) is refused, and
    so is one whose index equals the index of a system hash key
    (``SYSTEM_HASH_KEYS``).

    Parameters
    ----------
    hkey : str
      The hash key to retrieve all fields for.

    Returns
    -------
    dict
      A dictionary containing all field-value pairs in the hset, with Any type
      values. For a refused hash key, the error answer ``{"error": str,
      "status_code": 403, "logged": True}``.

    Examples
    --------
    >>> plugin.hgetall(hkey="ratio1:backend:offline_nodes_notifier:v1")
    {'node-1': {'seen': 1}}
    """
    return self._run_api_call(
      "hgetall",
      lambda: self.chainstore_hgetall(hkey=hkey, debug=self.cfg_debug),
      hkey=hkey,
    )


  @BasePlugin.endpoint(method="post", require_token=False)
  def hsync(self, hkey: str, chainstore_peers: list = None):
    """
    Refresh one hash namespace from live peer state.

    Parameters
    ----------
    hkey : str
      Logical hash namespace that should be merged from peer data.
    chainstore_peers : list, optional
      Additional peer addresses to target for this request. When omitted, the
      wrapper leaves peer selection untouched so ``chainstore_hsync`` can use
      its normal default-peer behavior.

    Returns
    -------
    dict
      Result envelope returned by ``chainstore_hsync``. On success it includes
      the refreshed ``hkey``, the accepted ``source_peer``, and
      ``merged_fields``. For a hash key in a system namespace
      (``SYSTEM_NAMESPACES``) or with the index of a system hash key
      (``SYSTEM_HASH_KEYS``), the error answer ``{"error": str,
      "status_code": 403, "logged": True}`` instead, and nothing is synced.

    Notes
    -----
    This wrapper is intentionally thin. The merge-only semantics, allowed-peer
    filtering, and timeout behavior all live in `naeural_core`.

    Examples
    --------
    >>> plugin.hsync(hkey="ratio1:backend:offline_nodes_notifier:v1")["hkey"]
    'ratio1:backend:offline_nodes_notifier:v1'
    """
    return self._run_api_call(
      "hsync",
      lambda: self.chainstore_hsync(
        hkey=hkey,
        debug=self.cfg_debug,
        extra_peers=chainstore_peers,
      ),
      hkey=hkey,
    )
