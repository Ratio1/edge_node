"""
BASE_INFERENCE_API Plugin

Production-Grade Inference API

This plugin exposes a hardened, FastAPI-powered interface for generic inference.
It keeps the lightweight loopback data flow used by the
Ratio1 node while adding security, observability, and request lifecycle
management.

It can work with both async and sync requests.
In case of sync requests, they will be processed using PostponedRequest objects.
Otherwise, the request_id will be returned immediately, and the client can poll for results.

Highlights
- Can be exposed through tunneling for remote access or kept local-only for third-party apps hosted through Ratio1.
- We recommend using it locally paired with a third-party app that manages the rate limiting, authentication, and
  request tracking (e.g., a web app built with Streamlit, Gradio, or Flask).
- In case of need for remote access, it can be exposed through tunneling with bearer-token authentication and a
built-in rate limiting mechanism.
- Supports any AI engine supported by Ratio1 through the Loopback plugin type.
- Durable, restart-safe request tracking with health/metrics/list endpoints
- Async + sync inference payload layout
- Automatic timeout handling, TTL-based eviction, and persistence to cacheapi

In case of no tunneling and local-only access, authentication will be disabled by default.
For tunneling export `INFERENCE_API_TOKEN` (comma-separated values for multiple clients) to enforce token
checks or provide the tokens through the `PREDEFINED_AUTH_TOKENS` config parameter.

Available Endpoints:
- POST /predict - Compute prediction (sync)
- POST /predict_async - Compute prediction (async)
- GET /health - Health check
- GET /status - Status of API
- GET /metrics - Retrieve API metrics
- GET /request_status - Check for current status of async request results

# TODO: find a legit example for generic inference API configuration
#  or keep class as abstract only?
Example pipeline configuration:
{
  "NAME": "local_inference_api",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "BASE_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "llm_interface",
          "AI_ENGINE": "llama_cpp",
          "STARTUP_AI_ENGINE_PARAMS": {
            "HF_TOKEN": "<hf_token_if_needed>",
            "MODEL_FILENAME": "llama-3.2-1b-instruct-q4_k_m.gguf",
            "MODEL_NAME": "hugging-quants/Llama-3.2-1B-Instruct-Q4_K_M-GGUF",
            "SERVER_COLLECTOR_TIMEDELTA": 360000
          }
        }
      ]
    }
  ]
}

Example balanced peer configuration (Node A):
{
  "NAME": "balanced_inference_api_node_a",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "BASE_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "llm_api_a",
          "AI_ENGINE": "llama_cpp",
          "REQUEST_BALANCING_ENABLED": true,
          "REQUEST_BALANCING_GROUP": "llm_cluster_prod",
          "REQUEST_BALANCING_CAPACITY": 1
        }
      ]
    }
  ]
}

Example balanced peer configuration (Node B):
{
  "NAME": "balanced_inference_api_node_b",
  "TYPE": "Loopback",
  "PLUGINS": [
    {
      "SIGNATURE": "BASE_INFERENCE_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "llm_api_b",
          "AI_ENGINE": "llama_cpp",
          "REQUEST_BALANCING_ENABLED": true,
          "REQUEST_BALANCING_GROUP": "llm_cluster_prod",
          "REQUEST_BALANCING_CAPACITY": 1
        }
      ]
    }
  ]
}
"""
from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin
from extensions.business.mixins.base_agent_mixin import _BaseAgentMixin, BASE_AGENT_MIXIN_CONFIG

from typing import Any, Dict, List, Optional


__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,
  **BASE_AGENT_MIXIN_CONFIG,

  # MANDATORY SETTING IN ORDER TO RECEIVE REQUESTS
  "ALLOW_EMPTY_INPUTS": True,  # allow processing even when no input data is present

  # MANDATORY LOOPBACK SETTINGS
  "IS_LOOPBACK_PLUGIN": True,
  "TUNNEL_ENGINE_ENABLED": False,
  "API_TITLE": "Local Inference API",
  "API_SUMMARY": "FastAPI server for local-only inference.",

  "PROCESS_DELAY": 0,
  "REQUEST_TIMEOUT": 600,  # 10 minutes
  "SAVE_PERIOD": 300,  # 5 minutes

  "LOG_REQUESTS_STATUS_EVERY_SECONDS": 5,  # log pending request status every 5 seconds

  "REQUEST_TTL_SECONDS": 60 * 60 * 2,  # keep historical results for 2 hours
  "RATE_LIMIT_PER_MINUTE": 5,
  "AUTH_TOKEN_ENV": "INFERENCE_API_TOKEN",
  "PREDEFINED_AUTH_TOKENS": [],  # e.g. ["token1", "token2"]
  "ALLOW_ANONYMOUS_ACCESS": True,

  "METRICS_REFRESH_SECONDS": 5 * 60,  # 5 minutes
  "REQUEST_BALANCING_ENABLED": False,
  "REQUEST_BALANCING_GROUP": None,
  "REQUEST_BALANCING_CAPACITY": 1,
  "REQUEST_BALANCING_PENDING_LIMIT": None,
  "REQUEST_BALANCING_ANNOUNCE_PERIOD": 60,
  "REQUEST_BALANCING_PEER_STALE_SECONDS": 180,
  "REQUEST_BALANCING_MAILBOX_POLL_PERIOD": 1,
  "REQUEST_BALANCING_CAPACITY_CSTORE_TIMEOUT": 2,
  "REQUEST_BALANCING_CAPACITY_CSTORE_MAX_RETRIES": 0,
  "REQUEST_BALANCING_CAPACITY_WARN_PERIOD": 60,
  "REQUEST_BALANCING_MAX_CSTORE_BYTES": 512 * 1024,
  "REQUEST_BALANCING_REQUEST_TTL_SECONDS": None,
  "REQUEST_BALANCING_RESULT_TTL_SECONDS": None,

  # Semaphore key for paired plugin synchronization (e.g., with WAR containers)
  # When set, this plugin will signal readiness and expose env vars to paired plugins
  "SEMAPHORE": None,

  "VALIDATION_RULES": {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  }
}


class BaseInferenceApiPlugin(
  BasePlugin,
  _BaseAgentMixin
):
  CONFIG = _CONFIG

  STATUS_PENDING = "pending"
  STATUS_COMPLETED = "completed"
  STATUS_FAILED = "failed"
  STATUS_TIMEOUT = "timeout"

  @staticmethod
  def balanced_endpoint(func):
    """Mark an endpoint as eligible for peer request balancing.

    Parameters
    ----------
    func : callable
        Endpoint function to decorate.

    Returns
    -------
    callable
        The same function with balancing metadata attached.
    """
    func.__balanced_endpoint__ = True
    return func

  def on_init(self):
    """
    Initialize plugin state and restore persisted request metadata.

    Returns
    -------
    None
      Method has no return value; it prepares in-memory stores, metrics, and persistence.
    """
    super(BaseInferenceApiPlugin, self).on_init()
    if not self.cfg_ai_engine:
      err_msg = f"AI_ENGINE must be specified for {self.get_signature()} plugin."
      self.P(err_msg)
      raise ValueError(err_msg)
    # endif AI_ENGINE not specified
    self._request_last_log_time: Dict[str, float] = {}
    self._requests: Dict[str, Dict[str, Any]] = {}
    self._api_errors: Dict[str, Dict[str, Any]] = {}
    # TODO: add inference metrics tracking (latency, tokens, etc)
    self._metrics = {
      'requests_total': 0,
      'requests_completed': 0,
      'requests_failed': 0,
      'requests_timeout': 0,
      'requests_active': 0,
    }
    self._rate_limit_state: Dict[str, Dict[str, Any]] = {}
    self._active_execution_slots = set()
    self._pending_request_ids = self.deque()
    self._queued_request_ids = set()
    self._seen_delegation_ids = {}
    self._executor_request_map = {}
    # This is different from self.last_error_time in BasePlugin
    # self.last_error_time tracks unhandled errors that occur in the plugin loop
    # This one tracks all errors that occur during API request handling
    self.last_handled_error_time = None
    self.last_metrics_refresh = 0
    self.last_persistence_save = 0
    self._last_capacity_announce = 0.0
    self._last_capacity_warn = 0.0
    self._last_balancing_mailbox_poll = 0.0
    self.load_persistence_data()
    tunneling_str = f"(with tunneling enabled)" if self.cfg_tunnel_engine_enabled else ""
    start_msg = f"{self.get_signature()} initialized{tunneling_str}.\n"
    lst_endpoint_names = list(self._endpoints.keys())
    endpoints_str = ", ".join([f"/{endpoint_name}" for endpoint_name in lst_endpoint_names])
    start_msg += f"\t\tEndpoints: {endpoints_str}\n"
    start_msg += f"\t\tAI Engine: {self.cfg_ai_engine}\n"
    start_msg += f"\t\tLoopback key: loopback_dct_{self._stream_id}"
    self.P(start_msg)
    self._publish_capacity_record(force=True)
    return

  def _json_dumps(self, data):
    """Serialize data using a deterministic compact JSON representation.

    Parameters
    ----------
    data : Any
        JSON-serializable value.

    Returns
    -------
    str
        Compact JSON string with sorted keys.
    """
    return self.json_dumps(data, sort_keys=True, separators=(',', ':'))

  def _normalize_balancing_group(self):
    """Return the configured balancing group in canonical form.

    Returns
    -------
    str or None
        Trimmed group name, or `None` when balancing has no configured group.
    """
    group = getattr(self, 'cfg_request_balancing_group', None)
    if isinstance(group, str):
      group = group.strip()
    return group or None

  def _capacity_hkey(self):
    """Return the ChainStore hash key for capacity records.

    Returns
    -------
    str
        Capacity hash key scoped by balancing group.
    """
    group = self._normalize_balancing_group() or "default"
    return f"inference_api:capacity:{group}"

  def _request_hkey(self):
    """Return the ChainStore hash key for delegated request envelopes.

    Returns
    -------
    str
        Request mailbox hash key scoped by balancing group.
    """
    group = self._normalize_balancing_group() or "default"
    return f"inference_api:req:{group}"

  def _result_hkey(self):
    """Return the ChainStore hash key for delegated result envelopes.

    Returns
    -------
    str
        Result mailbox hash key scoped by balancing group.
    """
    group = self._normalize_balancing_group() or "default"
    return f"inference_api:res:{group}"

  def _get_instance_balance_key(self):
    """Build the unique balancing identity for this plugin instance.

    Returns
    -------
    str
        Stable key composed from node, stream, signature, and instance id.
    """
    return ":".join([
      str(self.ee_addr),
      str(self.get_stream_id()),
      str(self.get_signature()),
      str(self.get_instance_id()),
    ])

  def _get_balancing_capacity(self):
    """Return the configured local execution capacity.

    Returns
    -------
    int
        Positive number of concurrent local execution slots.
    """
    value = getattr(self, 'cfg_request_balancing_capacity', 1)
    if isinstance(value, bool) or not isinstance(value, int):
      return 1
    return max(1, value)

  def _get_pending_limit(self):
    """Return the maximum number of queued pending requests.

    Returns
    -------
    int
        Configured pending limit, or a capacity-based default.
    """
    configured = getattr(self, 'cfg_request_balancing_pending_limit', None)
    if isinstance(configured, int) and configured > 0:
      return configured
    return max(8, 4 * self._get_balancing_capacity())

  def _is_balancing_enabled(self):
    """Return whether request balancing is enabled and configured.

    Returns
    -------
    bool
        `True` when the feature flag is enabled and a balancing group exists.
    """
    return bool(
      getattr(self, 'cfg_request_balancing_enabled', False) and
      self._normalize_balancing_group() is not None
    )

  def _get_peer_stale_seconds(self):
    """Return the peer capacity-record staleness threshold.

    Returns
    -------
    float
        Minimum-positive stale interval in seconds.
    """
    value = getattr(self, 'cfg_request_balancing_peer_stale_seconds', 180)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
      return 180.0
    return max(1.0, float(value))

  def _get_mailbox_poll_period(self):
    """Return the delegated mailbox polling period.

    Returns
    -------
    float
        Non-negative polling interval in seconds.
    """
    value = getattr(self, 'cfg_request_balancing_mailbox_poll_period', 1)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
      return 1.0
    return max(0.0, float(value))

  def _get_capacity_cstore_timeout(self):
    """Return timeout used for advisory capacity ChainStore writes.

    Returns
    -------
    float
        Non-negative timeout in seconds.
    """
    value = getattr(self, 'cfg_request_balancing_capacity_cstore_timeout', 2)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
      return 2.0
    return max(0.0, float(value))

  def _get_capacity_cstore_max_retries(self):
    """Return retry count for advisory capacity ChainStore writes.

    Returns
    -------
    int
        Non-negative retry count.
    """
    value = getattr(self, 'cfg_request_balancing_capacity_cstore_max_retries', 0)
    if isinstance(value, bool) or not isinstance(value, int):
      return 0
    return max(0, value)

  def _get_capacity_warn_period(self):
    """Return warning throttle period for capacity publish failures.

    Returns
    -------
    float
        Non-negative warning interval in seconds.
    """
    value = getattr(self, 'cfg_request_balancing_capacity_warn_period', 60)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
      return 60.0
    return max(0.0, float(value))

  def _get_request_balancing_ttl_seconds(self):
    """Return delegated request mailbox TTL.

    Returns
    -------
    float
        Positive TTL in seconds, defaulting to the request timeout.
    """
    value = getattr(self, 'cfg_request_balancing_request_ttl_seconds', None)
    if isinstance(value, (int, float)) and value > 0:
      return float(value)
    return float(self.cfg_request_timeout)

  def _get_result_balancing_ttl_seconds(self):
    """Return delegated result mailbox TTL.

    Returns
    -------
    float
        Positive TTL in seconds, defaulting to the request retention TTL.
    """
    value = getattr(self, 'cfg_request_balancing_result_ttl_seconds', None)
    if isinstance(value, (int, float)) and value > 0:
      return float(value)
    return float(self.cfg_request_ttl_seconds)

  def _get_max_cstore_bytes(self):
    """Return maximum encoded ChainStore transport envelope size.

    Returns
    -------
    int
        Minimum-bounded byte limit.
    """
    value = getattr(self, 'cfg_request_balancing_max_cstore_bytes', 512 * 1024)
    if isinstance(value, bool) or not isinstance(value, int):
      return 512 * 1024
    return max(4096, value)

  def _get_capacity_used(self):
    """Return the number of locally reserved execution slots.

    Returns
    -------
    int
        Count of active local execution reservations.
    """
    return len(self._active_execution_slots)

  def _get_capacity_free(self):
    """Return currently free local execution slots.

    Returns
    -------
    int
        Non-negative free slot count.
    """
    return max(0, self._get_balancing_capacity() - self._get_capacity_used())

  def _can_accept_execution(self):
    """Return whether this instance can reserve another local slot.

    Returns
    -------
    bool
        `True` when at least one execution slot is free.
    """
    return self._get_capacity_free() > 0

  def _decrement_active_requests(self):
    """Decrease the active request metric without allowing underflow.

    Returns
    -------
    None
        Updates the in-memory active request counter.
    """
    self._metrics['requests_active'] = max(0, self._metrics.get('requests_active', 0) - 1)
    return

  def _is_current_instance_capacity_record(self, record):
    """Return whether a capacity record belongs to this plugin instance.

    Parameters
    ----------
    record : dict
        Capacity record read from ChainStore.

    Returns
    -------
    bool
        `True` when the record identifies this exact node, stream, signature,
        and instance.
    """
    if not isinstance(record, dict):
      return False
    return (
      record.get('ee_addr') == self.ee_addr and
      record.get('pipeline') == self.get_stream_id() and
      record.get('signature') == self.get_signature() and
      record.get('instance_id') == self.get_instance_id()
    )

  def _get_seen_delegation_deadline(self, envelope, now_ts):
    """Return the retention deadline for a consumed delegation id.

    Parameters
    ----------
    envelope : dict
        Delegated request envelope.
    now_ts : float
        Current timestamp.

    Returns
    -------
    float
        Timestamp after which the delegation id can be forgotten.
    """
    expires_at = envelope.get('expires_at') if isinstance(envelope, dict) else None
    if isinstance(expires_at, (int, float)):
      base_ts = max(float(expires_at), now_ts)
    else:
      base_ts = now_ts
    return base_ts + self._get_request_balancing_ttl_seconds()

  def _build_executor_owner_key(self, delegation_context):
    """Build the origin ownership key for executor-side delegated work.

    Parameters
    ----------
    delegation_context : dict
        Delegation metadata copied from the request envelope.

    Returns
    -------
    str or None
        Stable origin/request key, or `None` when required metadata is missing.
    """
    origin_addr = delegation_context.get('origin_addr')
    origin_request_id = delegation_context.get('origin_request_id')
    if not origin_addr or not origin_request_id:
      return None
    return f"{origin_addr}:{origin_request_id}"

  def _reserve_execution_slot(self, request_id):
    """Reserve a local execution slot for a request.

    Parameters
    ----------
    request_id : str
        Request identifier.

    Returns
    -------
    bool
        `True` when the slot is already reserved or was reserved now.
    """
    if request_id in self._active_execution_slots:
      return True
    if not self._can_accept_execution():
      return False
    self._active_execution_slots.add(request_id)
    request_data = self._requests.get(request_id)
    if isinstance(request_data, dict):
      request_data['slot_reserved'] = True
      request_data['slot_reserved_at'] = self.time()
    self._publish_capacity_record(force=True)
    return True

  def _release_execution_slot(self, request_id):
    """Release a previously reserved local execution slot.

    Parameters
    ----------
    request_id : str
        Request identifier.

    Returns
    -------
    None
        Updates slot metadata and publishes advisory capacity.
    """
    self._active_execution_slots.discard(request_id)
    request_data = self._requests.get(request_id)
    if isinstance(request_data, dict):
      request_data['slot_reserved'] = False
      request_data['slot_released_at'] = self.time()
    self._publish_capacity_record(force=True)
    return

  def _build_capacity_record(self):
    """Build the advisory capacity record published to peers.

    Returns
    -------
    dict
        Capacity and readiness information for this plugin instance.
    """
    capacity_total = self._get_balancing_capacity()
    capacity_used = self._get_capacity_used()
    capacity_free = max(0, capacity_total - capacity_used)
    return {
      'protocol_version': 1,
      'balancer_group': self._normalize_balancing_group(),
      'ee_addr': self.ee_addr,
      'pipeline': self.get_stream_id(),
      'signature': self.get_signature(),
      'instance_id': self.get_instance_id(),
      'capacity_total': capacity_total,
      'capacity_used': capacity_used,
      'capacity_free': capacity_free,
      'max_cstore_bytes': self._get_max_cstore_bytes(),
      'updated_at': self.time(),
      # Keep both fields: capacity_free is numeric slot availability, while
      # accepting_requests is admission/readiness policy and may be false even
      # when slots are physically free, e.g. during serving cold start.
      'accepting_requests': capacity_free > 0,
    }

  def _publish_capacity_record(self, force=False):
    """Publish local capacity as advisory soft-state.

    Parameters
    ----------
    force : bool, optional
        Publish immediately even when the announce period has not elapsed.

    Returns
    -------
    None
        Writes the capacity record when balancing is enabled.

    Notes
    -----
    Capacity records are advisory soft-state, including forced reserve/release
    publishes. Local `_active_execution_slots` remains the authoritative
    admission control; peers repair stale capacity views on later announces.
    """
    if not self._is_balancing_enabled():
      return
    now_ts = self.time()
    if (not force) and (now_ts - self._last_capacity_announce) < getattr(
      self, 'cfg_request_balancing_announce_period', 60
    ):
      return
    ok = self.chainstore_hset(
      hkey=self._capacity_hkey(),
      key=self._get_instance_balance_key(),
      value=self._build_capacity_record(),
      timeout=self._get_capacity_cstore_timeout(),
      max_retries=self._get_capacity_cstore_max_retries(),
    )
    self._last_capacity_announce = now_ts
    if not ok:
      warn_period = self._get_capacity_warn_period()
      if warn_period <= 0 or (now_ts - self._last_capacity_warn) >= warn_period:
        self.P(
          "Capacity record publish was not confirmed; treating it as soft-state and will retry on the next announce.",
          color="y",
        )
        self._last_capacity_warn = now_ts
    return

  def _compress_transport_value(self, data):
    """Compress a JSON-serializable value for ChainStore transport.

    Parameters
    ----------
    data : Any
        JSON-serializable transport body.

    Returns
    -------
    str
        Compressed text representation.
    """
    text = self._json_dumps(data)
    return self.log.compress_text(text)

  def _decompress_transport_value(self, data):
    """Decompress a ChainStore transport body.

    Parameters
    ----------
    data : str
        Compressed transport value.

    Returns
    -------
    Any
        Decoded JSON body.
    """
    raw = self.log.decompress_text(data)
    return self.json_loads(raw)

  def _build_transport_envelope(self, body, kind, **extra_fields):
    """Build a compressed ChainStore request/result envelope.

    Parameters
    ----------
    body : Any
        JSON-serializable envelope body.
    kind : str
        Envelope kind, usually `"request"` or `"result"`.
    **extra_fields
        Metadata fields copied into the envelope.

    Returns
    -------
    tuple[dict, int]
        Envelope dictionary and encoded byte size.
    """
    envelope = {
      'protocol_version': 1,
      'body_codec': 'zlib+base64+json',
      'body_format_version': 1,
      **extra_fields,
    }
    body_key = 'compressed_result_body' if kind == 'result' else 'compressed_request_body'
    envelope[body_key] = self._compress_transport_value(body)
    encoded_size = len(self._json_dumps(envelope).encode('utf-8'))
    return envelope, encoded_size

  def _decode_transport_envelope_body(self, envelope):
    """Decode the compressed body from a transport envelope.

    Parameters
    ----------
    envelope : dict
        ChainStore transport envelope.

    Returns
    -------
    Any
        Decoded request or result body.
    """
    body_key = 'compressed_result_body' if 'compressed_result_body' in envelope else 'compressed_request_body'
    return self._decompress_transport_value(envelope[body_key])

  def _is_endpoint_balanced(self, endpoint_name):
    """Return whether an endpoint has balancing metadata.

    Parameters
    ----------
    endpoint_name : str
        Registered endpoint name.

    Returns
    -------
    bool
        `True` when the endpoint was decorated with `balanced_endpoint`.
    """
    endpoint = self._endpoints.get(endpoint_name)
    if endpoint and getattr(endpoint, '__balanced_endpoint__', False):
      return True
    endpoint_func = getattr(self.__class__, endpoint_name, None)
    return bool(endpoint_func and getattr(endpoint_func, '__balanced_endpoint__', False))

  def _should_try_balancing_for_endpoint(self, endpoint_name):
    """Return whether balancing should be attempted for an endpoint.

    Parameters
    ----------
    endpoint_name : str
        Registered endpoint name.

    Returns
    -------
    bool
        `True` when balancing is enabled and the endpoint is eligible.
    """
    return self._is_balancing_enabled() and self._is_endpoint_balanced(endpoint_name)

  def _chainstore_hset_targeted(self, hkey, key, value, target_peer):
    """Write a ChainStore value only to a specific peer.

    Parameters
    ----------
    hkey : str
        ChainStore hash key.
    key : str
        Entry key.
    value : Any
        Value to write. `None` is used for cleanup markers.
    target_peer : str
        Peer node address.

    Returns
    -------
    Any
        Result returned by `chainstore_hset`.
    """
    return self.chainstore_hset(
      hkey=hkey,
      key=key,
      value=value,
      extra_peers=[target_peer],
      include_default_peers=False,
      include_configured_peers=False,
      timeout=self._get_capacity_cstore_timeout(),
      max_retries=self._get_capacity_cstore_max_retries(),
    )

  def _cleanup_targeted_cstore_entry(self, hkey, key, target_peer, mirror_peer=None):
    """Remove a targeted ChainStore mailbox entry.

    Parameters
    ----------
    hkey : str
        ChainStore hash key.
    key : str
        Entry key.
    target_peer : str
        Preferred peer holding the entry.
    mirror_peer : str or None, optional
        Alternate peer used when the preferred peer is the current node.

    Returns
    -------
    bool or Any
        `False` when no target is available, otherwise the targeted write
        result.
    """
    effective_target = target_peer
    if effective_target == self.ee_addr:
      effective_target = mirror_peer
    if not effective_target:
      return False
    return self._chainstore_hset_targeted(
      hkey=hkey,
      key=key,
      value=None,
      target_peer=effective_target,
    )

  def _select_execution_peer(self):
    """Select an eligible peer for delegated execution.

    Returns
    -------
    dict or None
        Capacity record for the selected peer, or `None` when no peer can
        accept work.
    """
    if not self._is_balancing_enabled():
      return None
    records = self.chainstore_hgetall(self._capacity_hkey()) or {}
    now_ts = self.time()
    eligible = []
    for record in records.values():
      if not isinstance(record, dict):
        continue
      if self._is_current_instance_capacity_record(record):
        continue
      if record.get('balancer_group') != self._normalize_balancing_group():
        continue
      if record.get('signature') != self.get_signature():
        continue
      updated_at = record.get('updated_at')
      if not isinstance(updated_at, (int, float)):
        continue
      if (now_ts - float(updated_at)) > self._get_peer_stale_seconds():
        continue
      if ('accepting_requests' in record) and (not record.get('accepting_requests')):
        continue
      free = record.get('capacity_free')
      if not isinstance(free, int):
        total = record.get('capacity_total', 0)
        used = record.get('capacity_used', 0)
        if isinstance(total, int) and isinstance(used, int):
          free = max(0, total - used)
        else:
          free = 0
      if free <= 0:
        continue
      eligible.append((free, record))
    if not eligible:
      return None
    best_free = max(item[0] for item in eligible)
    best = [item[1] for item in eligible if item[0] == best_free]
    return best[int(self.np.random.randint(len(best)))]

  def _build_executor_endpoint_kwargs(self, request_data):
    """Build endpoint keyword arguments for delegated execution.

    Parameters
    ----------
    request_data : dict
        Tracked request metadata.

    Returns
    -------
    dict
        Parameters forwarded to the endpoint on the executor node.
    """
    kwargs = dict(request_data.get('parameters') or {})
    metadata = request_data.get('metadata')
    if metadata is not None:
      kwargs['metadata'] = metadata
    return kwargs

  def _enqueue_pending_request(self, request_id):
    """Queue a request for later local or delegated scheduling.

    Parameters
    ----------
    request_id : str
        Request identifier.

    Returns
    -------
    bool
        `True` when queued or already queued, `False` when the queue is full.
    """
    if request_id in self._queued_request_ids:
      return True
    if len(self._pending_request_ids) >= self._get_pending_limit():
      return False
    self._pending_request_ids.append(request_id)
    self._queued_request_ids.add(request_id)
    request_data = self._requests.get(request_id)
    if isinstance(request_data, dict):
      request_data['queue_state'] = 'queued'
      request_data['queued_at'] = self.time()
    return True

  def _build_delegated_request_envelope(self, request_id, request_data, target_record, endpoint_name):
    """Build the mailbox envelope for a delegated request.

    Parameters
    ----------
    request_id : str
        Origin request identifier.
    request_data : dict
        Tracked request metadata.
    target_record : dict
        Selected executor capacity record.
    endpoint_name : str
        Endpoint to call on the executor.

    Returns
    -------
    tuple[str, dict, int]
        Delegation id, envelope, and encoded envelope size.
    """
    delegation_id = self.uuid()
    now_ts = self.time()
    body = {
      'endpoint_name': endpoint_name,
      'endpoint_kwargs': self._build_executor_endpoint_kwargs(request_data),
    }
    envelope, encoded_size = self._build_transport_envelope(
      body,
      kind='request',
      delegation_id=delegation_id,
      origin_request_id=request_id,
      endpoint_name=endpoint_name,
      status='submitted',
      origin_addr=self.ee_addr,
      origin_alias=getattr(self, 'eeid', None),
      origin_instance_id=self.get_instance_id(),
      target_addr=target_record.get('ee_addr'),
      target_instance_id=target_record.get('instance_id'),
      created_at=now_ts,
      updated_at=now_ts,
      expires_at=now_ts + self._get_request_balancing_ttl_seconds(),
    )
    return delegation_id, envelope, encoded_size

  def _write_delegated_request(self, request_id, request_data, target_record, endpoint_name):
    """Write a delegated request envelope to the selected executor.

    Parameters
    ----------
    request_id : str
        Origin request identifier.
    request_data : dict
        Tracked request metadata.
    target_record : dict
        Selected executor capacity record.
    endpoint_name : str
        Endpoint to call on the executor.

    Returns
    -------
    tuple[str or None, str or None]
        Delegation id on success, otherwise `None` and an error message.
    """
    try:
      delegation_id, envelope, encoded_size = self._build_delegated_request_envelope(
        request_id=request_id,
        request_data=request_data,
        target_record=target_record,
        endpoint_name=endpoint_name,
      )
    except Exception as exc:
      return None, f"could not encode delegated request envelope: {exc}"
    if encoded_size > self._get_max_cstore_bytes():
      return None, 'encoded request envelope exceeds balancing transport limit'
    ok = self._chainstore_hset_targeted(
      hkey=self._request_hkey(),
      key=delegation_id,
      value=envelope,
      target_peer=target_record['ee_addr'],
    )
    if not ok:
      return None, 'delegated request write was not confirmed'
    request_data['delegation_id'] = delegation_id
    request_data['delegation_target_addr'] = target_record['ee_addr']
    request_data['delegation_target_instance_id'] = target_record.get('instance_id')
    request_data['delegation_status'] = 'submitted'
    request_data['delegated_at'] = self.time()
    request_data['delegation_last_sent_at'] = request_data['delegated_at']
    request_data['delegation_envelope'] = envelope
    request_data['execution_mode'] = 'delegated'
    request_data['queue_state'] = 'delegated'
    return delegation_id, None

  def _apply_result_to_request(self, request_id, result_body, fallback_status):
    """Apply a delegated executor result to the origin request.

    Parameters
    ----------
    request_id : str
        Origin request identifier.
    result_body : dict
        Decoded result body returned by the executor.
    fallback_status : str
        Status used when the result body does not include one.

    Returns
    -------
    None
        Mutates request state and metrics.
    """
    request_data = self._requests.get(request_id)
    if request_data is None:
      return
    status = result_body.get('status', fallback_status)
    now_ts = self.time()
    request_data['updated_at'] = now_ts
    request_data['finished_at'] = now_ts
    request_data['result'] = self._annotate_result_with_node_roles(
      result_payload=result_body,
      request_data=request_data,
    )
    request_data['delegation_status'] = status
    if status in {self.STATUS_COMPLETED, 'completed'}:
      request_data['status'] = self.STATUS_COMPLETED
      self._metrics['requests_completed'] += 1
    else:
      request_data['status'] = self.STATUS_FAILED
      request_data['error'] = result_body.get('error', 'Delegated request failed.')
      self._metrics['requests_failed'] += 1
    self._decrement_active_requests()
    return

  def _is_request_terminal(self, request_data):
    """Return whether a request has reached a final state.

    Parameters
    ----------
    request_data : dict or Any
        Tracked request metadata.

    Returns
    -------
    bool
        `True` for completed, failed, or timeout requests.
    """
    if not isinstance(request_data, dict):
      return False
    return request_data.get('status') in {
      self.STATUS_COMPLETED,
      self.STATUS_FAILED,
      self.STATUS_TIMEOUT,
    }

  def _dispatch_local_request(self, request_id, request_data):
    """Dispatch a request through the local loopback serving path.

    Parameters
    ----------
    request_id : str
        Request identifier.
    request_data : dict
        Tracked request metadata.

    Returns
    -------
    bool
        Always `True` after payload submission.
    """
    payload_kwargs = self.compute_payload_kwargs_from_predict_params(
      request_id=request_id,
      request_data=request_data,
    )
    request_data['dispatched_at'] = self.time()
    request_data['queue_state'] = 'running'
    self.Pd(
      f"Dispatching request {request_id} :: {self.json_dumps(payload_kwargs, indent=2)[:500]}"
    )
    self.add_payload_by_fields(
      **payload_kwargs,
      signature=self.get_signature()
    )
    return True

  def _fail_request(self, request_id, error_message, status=None):
    """Mark a request as failed or timed out.

    Parameters
    ----------
    request_id : str
        Request identifier.
    error_message : str
        Error text stored on the request.
    status : str or None, optional
        Final status override.

    Returns
    -------
    bool
        `True` when the request was transitioned, otherwise `False`.
    """
    request_data = self._requests.get(request_id)
    if request_data is None:
      return False
    if self._is_request_terminal(request_data):
      return False
    now_ts = self.time()
    final_status = status or self.STATUS_FAILED
    request_data['status'] = final_status
    request_data['error'] = error_message
    request_data['updated_at'] = now_ts
    request_data['finished_at'] = now_ts
    request_data['result'] = {
      'status': final_status,
      'error': error_message,
      'request_id': request_id,
    }
    self._annotate_result_with_node_roles(
      result_payload=request_data['result'],
      request_data=request_data,
    )
    if final_status == self.STATUS_TIMEOUT:
      self._metrics['requests_timeout'] += 1
    else:
      self._metrics['requests_failed'] += 1
    self._decrement_active_requests()
    return True

  def _attempt_schedule_request(self, request_id, request_data, endpoint_name):
    """Try to schedule a pending request locally or on a peer.

    Parameters
    ----------
    request_id : str
        Request identifier.
    request_data : dict
        Tracked request metadata.
    endpoint_name : str
        Endpoint requested by the client.

    Returns
    -------
    bool
        `True` when the request is terminal, dispatched locally, or delegated.
    """
    if self._is_request_terminal(request_data):
      return True
    if self._can_accept_execution():
      if not self._reserve_execution_slot(request_id):
        return False
      request_data['execution_mode'] = 'local'
      return self._dispatch_local_request(request_id=request_id, request_data=request_data)
    target_record = self._select_execution_peer()
    if not target_record:
      return False
    delegation_id, err = self._write_delegated_request(
      request_id=request_id,
      request_data=request_data,
      target_record=target_record,
      endpoint_name=endpoint_name,
    )
    if delegation_id is None:
      self.Pd(f"Could not delegate request {request_id}: {err}")
      self._fail_request(request_id=request_id, error_message=err)
      return True
    return True

  def _schedule_pending_requests(self):
    """Schedule queued requests while capacity or peers are available.

    Returns
    -------
    None
        Requeues requests that cannot be scheduled yet.
    """
    if not self._is_balancing_enabled():
      return
    queue_len = len(self._pending_request_ids)
    for _ in range(queue_len):
      request_id = self._pending_request_ids.popleft()
      self._queued_request_ids.discard(request_id)
      request_data = self._requests.get(request_id)
      if request_data is None or self._is_request_terminal(request_data):
        continue
      if request_data.get('status') != self.STATUS_PENDING:
        continue
      endpoint_name = request_data.get('endpoint_name') or 'predict'
      if self._attempt_schedule_request(
        request_id=request_id,
        request_data=request_data,
        endpoint_name=endpoint_name,
      ):
        continue
      self._pending_request_ids.append(request_id)
      self._queued_request_ids.add(request_id)
    return

  def _retry_same_peer_delegations(self):
    """Re-send delegated requests that remain unconsumed by their peer.

    Returns
    -------
    None
        Updates the last-send timestamp for retried delegations.

    Notes
    -----
    TODO: V2 should reroute to alternate peers when the selected executor
    repeatedly fails to consume a delegated request.
    """
    if not self._is_balancing_enabled():
      return
    retry_after = max(1.0, self._get_mailbox_poll_period())
    now_ts = self.time()
    for request_id, request_data in self._requests.items():
      if request_data.get('status') != self.STATUS_PENDING:
        continue
      if request_data.get('execution_mode') != 'delegated':
        continue
      target_addr = request_data.get('delegation_target_addr')
      envelope = request_data.get('delegation_envelope')
      if not target_addr or not isinstance(envelope, dict):
        continue
      last_sent_at = request_data.get('delegation_last_sent_at', 0)
      if (now_ts - last_sent_at) < retry_after:
        continue
      self._chainstore_hset_targeted(
        hkey=self._request_hkey(),
        key=request_data['delegation_id'],
        value=envelope,
        target_peer=target_addr,
      )
      request_data['delegation_last_sent_at'] = now_ts
    return

  def _build_delegated_result_envelope(self, request_id, request_data):
    """Build the mailbox envelope for a delegated execution result.

    Parameters
    ----------
    request_id : str
        Local executor request identifier.
    request_data : dict
        Tracked executor request metadata.

    Returns
    -------
    tuple[dict, int]
        Result envelope and encoded envelope size.
    """
    result_body = request_data.get('result') or {
      'status': request_data.get('status', self.STATUS_FAILED),
      'error': request_data.get('error', 'Delegated execution failed.'),
      'request_id': request_data.get('origin_request_id', request_id),
    }
    if isinstance(result_body, dict):
      result_body = dict(result_body)
    if request_data.get('status') in {self.STATUS_FAILED, self.STATUS_TIMEOUT}:
      result_body.setdefault('error', request_data.get('error'))
    result_body.setdefault('status', request_data.get('status', self.STATUS_FAILED))
    origin_request_id = request_data.get('origin_request_id', request_id)
    result_body['request_id'] = origin_request_id
    if 'REQUEST_ID' in result_body:
      result_body['REQUEST_ID'] = origin_request_id
    self._annotate_result_with_node_roles(
      result_payload=result_body,
      request_data=request_data,
    )
    return self._build_transport_envelope(
      result_body,
      kind='result',
      delegation_id=request_data.get('delegation_id'),
      origin_request_id=request_data.get('origin_request_id', request_id),
      status=request_data.get('status', self.STATUS_FAILED),
      origin_addr=request_data.get('origin_addr'),
      origin_instance_id=request_data.get('origin_instance_id'),
      target_addr=self.ee_addr,
      target_instance_id=self.get_instance_id(),
      created_at=request_data.get('created_at', self.time()),
      updated_at=self.time(),
      expires_at=self.time() + self._get_result_balancing_ttl_seconds(),
    )

  def _build_result_overflow_body(self, request_id, request_data):
    """Build a compact failure result when the full result is too large.

    Parameters
    ----------
    request_id : str
        Local executor request identifier.
    request_data : dict
        Tracked executor request metadata.

    Returns
    -------
    dict
        Failure body compatible with delegated result transport.
    """
    return {
      'status': self.STATUS_FAILED,
      'request_id': request_data.get('origin_request_id', request_id),
      'error': 'encoded result envelope exceeds balancing transport limit',
    }

  def _mark_executor_result_overflow(self, request_id, request_data, now_ts):
    """Mark an executor-side delegated result as failed due to envelope size.

    Parameters
    ----------
    request_id : str
        Local executor request identifier.
    request_data : dict
        Tracked executor request metadata.
    now_ts : float
        Current timestamp.

    Returns
    -------
    dict
        Compact failure result body to publish back to the origin.
    """
    previous_status = request_data.get('status')
    overflow_body = self._build_result_overflow_body(request_id, request_data)
    if previous_status == self.STATUS_COMPLETED:
      self._metrics['requests_completed'] = max(0, self._metrics.get('requests_completed', 0) - 1)
      self._metrics['requests_failed'] += 1
    elif previous_status == self.STATUS_TIMEOUT:
      self._metrics['requests_timeout'] = max(0, self._metrics.get('requests_timeout', 0) - 1)
      self._metrics['requests_failed'] += 1
    elif previous_status != self.STATUS_FAILED:
      self._metrics['requests_failed'] += 1
    request_data['status'] = self.STATUS_FAILED
    request_data['error'] = overflow_body['error']
    request_data['result'] = overflow_body
    request_data['updated_at'] = now_ts
    request_data['finished_at'] = now_ts
    return overflow_body

  def _build_node_identity(self, role, node_addr=None, node_alias=None):
    """Build node-role fields for a result payload.

    Parameters
    ----------
    role : str
        Role prefix such as `EXECUTOR` or `DELEGATOR`.
    node_addr : str or None, optional
        Node address.
    node_alias : str or None, optional
        Node alias.

    Returns
    -------
    dict
        Role-prefixed node identity fields.
    """
    return {
      f'{role}_NODE_ADDR': node_addr,
      f'{role}_NODE_ALIAS': node_alias,
    }

  def _get_current_node_identity(self, role):
    """Build node-role identity fields for the current node.

    Parameters
    ----------
    role : str
        Role prefix such as `EXECUTOR` or `DELEGATOR`.

    Returns
    -------
    dict
        Current node identity fields.
    """
    return self._build_node_identity(
      role=role,
      node_addr=self.ee_addr,
      node_alias=getattr(self, 'eeid', None),
    )

  def _get_request_delegator_identity(self, request_data=None):
    """Return delegator identity for a request.

    Parameters
    ----------
    request_data : dict or None, optional
        Tracked request metadata.

    Returns
    -------
    dict
        Origin node identity when available, otherwise current node identity.
    """
    if isinstance(request_data, dict):
      origin_addr = request_data.get('origin_addr')
      origin_alias = request_data.get('origin_alias')
      if origin_addr is not None or origin_alias is not None:
        return self._build_node_identity(
          role='DELEGATOR',
          node_addr=origin_addr,
          node_alias=origin_alias,
        )
    return self._get_current_node_identity('DELEGATOR')

  def _extract_node_identity_from_result(self, result_payload, role):
    """Extract existing node-role identity fields from a result payload.

    Parameters
    ----------
    result_payload : dict or Any
        Result payload to inspect.
    role : str
        Role prefix such as `EXECUTOR` or `DELEGATOR`.

    Returns
    -------
    dict or None
        Extracted role identity, or `None` when absent.
    """
    if not isinstance(result_payload, dict):
      return None
    node_addr = result_payload.get(f'{role}_NODE_ADDR')
    node_alias = result_payload.get(f'{role}_NODE_ALIAS')
    if node_addr is None and node_alias is None:
      return None
    return self._build_node_identity(
      role=role,
      node_addr=node_addr,
      node_alias=node_alias,
    )

  def _infer_execution_started_at(self, request_data=None):
    """Infer when a request started execution or delegation.

    Parameters
    ----------
    request_data : dict or None, optional
        Tracked request metadata.

    Returns
    -------
    float or None
        First available execution-start timestamp.
    """
    if not isinstance(request_data, dict):
      return None
    for key in ('slot_reserved_at', 'dispatched_at', 'delegated_at'):
      value = request_data.get(key)
      if isinstance(value, (int, float)):
        return float(value)
    return None

  def _build_elapsed_fields(self, request_data=None):
    """Build elapsed-time result fields from request timestamps.

    Parameters
    ----------
    request_data : dict or None, optional
        Tracked request metadata.

    Returns
    -------
    dict
        Balancing and inference elapsed-time fields when timestamps are
        available.
    """
    if not isinstance(request_data, dict):
      return {}
    created_at = request_data.get('created_at')
    finished_at = request_data.get('finished_at')
    execution_started_at = self._infer_execution_started_at(request_data=request_data)
    if not isinstance(created_at, (int, float)) or not isinstance(finished_at, (int, float)):
      return {}
    fields = {}
    if isinstance(execution_started_at, (int, float)):
      balancing_elapsed = max(0.0, float(execution_started_at) - float(created_at))
      inference_elapsed = max(0.0, float(finished_at) - float(execution_started_at))
      fields['BALANCING_ELAPSED_TIME'] = balancing_elapsed
      fields['INFERENCE_ELAPSED_TIME'] = inference_elapsed
    else:
      fields['BALANCING_ELAPSED_TIME'] = max(0.0, float(finished_at) - float(created_at))
    return fields

  def _make_json_safe(self, value):
    """Convert common non-JSON scalar/container values into JSON-safe values.

    Parameters
    ----------
    value : Any
        Value to sanitize.

    Returns
    -------
    Any
        JSON-safe representation where possible.
    """
    if isinstance(value, dict):
      return {
        self._make_json_safe(key): self._make_json_safe(item)
        for key, item in value.items()
      }
    if isinstance(value, (list, tuple)):
      return [self._make_json_safe(item) for item in value]
    if isinstance(value, set):
      return [self._make_json_safe(item) for item in value]
    if hasattr(value, 'item') and callable(getattr(value, 'item')):
      try:
        return self._make_json_safe(value.item())
      except Exception:
        pass
    if hasattr(value, 'tolist') and callable(getattr(value, 'tolist')):
      try:
        return self._make_json_safe(value.tolist())
      except Exception:
        pass
    return value

  def _annotate_result_with_node_roles(
      self,
      result_payload,
      request_data=None,
      executor_identity=None,
      delegator_identity=None,
  ):
    """Attach executor/delegator identities and elapsed timings to a result.

    Parameters
    ----------
    result_payload : dict or Any
        Result payload to annotate.
    request_data : dict or None, optional
        Tracked request metadata used for delegator and timing fields.
    executor_identity : dict or None, optional
        Explicit executor identity override.
    delegator_identity : dict or None, optional
        Explicit delegator identity override.

    Returns
    -------
    dict or Any
        Annotated and JSON-safe result payload, or the original non-dict value.
    """
    if not isinstance(result_payload, dict):
      return result_payload
    result_payload.pop('EXECUTOR_NODE_NETWORK', None)
    result_payload.pop('DELEGATOR_NODE_NETWORK', None)
    identities = [
      executor_identity or
      self._extract_node_identity_from_result(result_payload, 'EXECUTOR') or
      self._get_current_node_identity('EXECUTOR'),
      delegator_identity or
      self._extract_node_identity_from_result(result_payload, 'DELEGATOR') or
      self._get_request_delegator_identity(request_data=request_data),
    ]
    for identity in identities:
      for key, value in identity.items():
        if value is not None:
          result_payload.setdefault(key, value)
    for key, value in self._build_elapsed_fields(request_data=request_data).items():
      result_payload.setdefault(key, value)
    sanitized_payload = self._make_json_safe(result_payload)
    if isinstance(sanitized_payload, dict):
      result_payload.clear()
      result_payload.update(sanitized_payload)
    return result_payload

  def _annotate_result_with_executor_identity(self, result_payload, executor_identity=None):
    """Attach executor identity to a result payload.

    Parameters
    ----------
    result_payload : dict or Any
        Result payload to annotate.
    executor_identity : dict or None, optional
        Explicit executor identity override.

    Returns
    -------
    dict or Any
        Annotated result payload.
    """
    return self._annotate_result_with_node_roles(
      result_payload=result_payload,
      executor_identity=executor_identity or self._get_current_node_identity('EXECUTOR'),
    )

  def _publish_executor_results(self):
    """Publish completed delegated results back to origin nodes.

    Returns
    -------
    None
        Writes result envelopes and cleans consumed request mailbox entries.
    """
    if not self._is_balancing_enabled():
      return
    now_ts = self.time()
    for request_id, request_data in self._requests.items():
      if not request_data.get('delegated_execution'):
        continue
      if request_data.get('delegated_result_sent_at') is not None:
        continue
      if not self._is_request_terminal(request_data):
        continue
      origin_addr = request_data.get('origin_addr')
      if not origin_addr:
        continue
      envelope, encoded_size = self._build_delegated_result_envelope(
        request_id=request_id,
        request_data=request_data,
      )
      if encoded_size > self._get_max_cstore_bytes():
        overflow_body = self._mark_executor_result_overflow(
          request_id=request_id,
          request_data=request_data,
          now_ts=now_ts,
        )
        envelope, _ = self._build_transport_envelope(
          overflow_body,
          kind='result',
          delegation_id=request_data.get('delegation_id'),
          origin_request_id=request_data.get('origin_request_id', request_id),
          status=self.STATUS_FAILED,
          origin_addr=request_data.get('origin_addr'),
          origin_instance_id=request_data.get('origin_instance_id'),
          target_addr=self.ee_addr,
          target_instance_id=self.get_instance_id(),
          created_at=request_data.get('created_at', now_ts),
          updated_at=now_ts,
          expires_at=now_ts + self._get_result_balancing_ttl_seconds(),
        )
      self._chainstore_hset_targeted(
        hkey=self._result_hkey(),
        key=request_data.get('delegation_id'),
        value=envelope,
        target_peer=origin_addr,
      )
      self._cleanup_targeted_cstore_entry(
        hkey=self._request_hkey(),
        key=request_data.get('delegation_id'),
        target_peer=self.ee_addr,
        mirror_peer=origin_addr,
      )
      request_data['delegated_result_sent_at'] = now_ts
      owner_key = self._build_executor_owner_key(request_data)
      if owner_key and self._executor_request_map.get(owner_key) == request_id:
        self._executor_request_map.pop(owner_key, None)
    return

  def _poll_delegated_requests(self):
    """Consume delegated request envelopes addressed to this node.

    Returns
    -------
    None
        Starts local endpoint execution for accepted envelopes and publishes
        immediate failure results for invalid envelopes.
    """
    if not self._is_balancing_enabled():
      return
    records = self.chainstore_hgetall(self._request_hkey()) or {}
    now_ts = self.time()
    for delegation_id, envelope in records.items():
      if not isinstance(envelope, dict):
        continue
      if envelope.get('target_addr') != self.ee_addr:
        continue
      if envelope.get('target_instance_id') not in {None, self.get_instance_id()}:
        continue
      expires_at = envelope.get('expires_at')
      if isinstance(expires_at, (int, float)) and now_ts > float(expires_at):
        self._cleanup_targeted_cstore_entry(
          hkey=self._request_hkey(),
          key=delegation_id,
          target_peer=self.ee_addr,
          mirror_peer=envelope.get('origin_addr'),
        )
        continue
      if delegation_id in self._seen_delegation_ids:
        continue
      if not self._can_accept_execution():
        continue
      try:
        request_body = self._decode_transport_envelope_body(envelope)
      except Exception as exc:
        failure_body = {
          'status': self.STATUS_FAILED,
          'request_id': envelope.get('origin_request_id'),
          'error': f'Invalid delegated request payload: {exc}',
        }
        result_envelope, _ = self._build_transport_envelope(
          failure_body,
          kind='result',
          delegation_id=delegation_id,
          origin_request_id=envelope.get('origin_request_id'),
          status=self.STATUS_FAILED,
          origin_addr=envelope.get('origin_addr'),
          origin_instance_id=envelope.get('origin_instance_id'),
          target_addr=self.ee_addr,
          target_instance_id=self.get_instance_id(),
          created_at=envelope.get('created_at', now_ts),
          updated_at=now_ts,
          expires_at=now_ts + self._get_result_balancing_ttl_seconds(),
        )
        self._chainstore_hset_targeted(
          hkey=self._result_hkey(),
          key=delegation_id,
          value=result_envelope,
          target_peer=envelope.get('origin_addr'),
        )
        self._cleanup_targeted_cstore_entry(
          hkey=self._request_hkey(),
          key=delegation_id,
          target_peer=self.ee_addr,
          mirror_peer=envelope.get('origin_addr'),
        )
        continue
      endpoint_name = request_body.get('endpoint_name')
      endpoint_kwargs = request_body.get('endpoint_kwargs') or {}
      handler = getattr(self, endpoint_name, None)
      if not callable(handler):
        self._seen_delegation_ids[delegation_id] = self._get_seen_delegation_deadline(envelope, now_ts)
        continue
      self._seen_delegation_ids[delegation_id] = self._get_seen_delegation_deadline(envelope, now_ts)
      result = handler(
        authorization=None,
        _force_local_execution=True,
        _delegated_execution=True,
        _delegation_context={
          'delegation_id': delegation_id,
          'origin_request_id': envelope.get('origin_request_id'),
          'origin_addr': envelope.get('origin_addr'),
          'origin_alias': envelope.get('origin_alias'),
          'origin_instance_id': envelope.get('origin_instance_id'),
          'target_addr': envelope.get('target_addr'),
          'target_instance_id': envelope.get('target_instance_id'),
          'endpoint_name': endpoint_name,
          'created_at': envelope.get('created_at'),
          'expires_at': envelope.get('expires_at'),
        },
        **endpoint_kwargs
      )
      if isinstance(result, dict) and result.get('error'):
        failure_body = {
          'status': self.STATUS_FAILED,
          'request_id': envelope.get('origin_request_id'),
          'error': result.get('error'),
        }
        result_envelope, _ = self._build_transport_envelope(
          failure_body,
          kind='result',
          delegation_id=delegation_id,
          origin_request_id=envelope.get('origin_request_id'),
          status=self.STATUS_FAILED,
          origin_addr=envelope.get('origin_addr'),
          origin_instance_id=envelope.get('origin_instance_id'),
          target_addr=self.ee_addr,
          target_instance_id=self.get_instance_id(),
          created_at=envelope.get('created_at', now_ts),
          updated_at=now_ts,
          expires_at=now_ts + self._get_result_balancing_ttl_seconds(),
        )
        self._chainstore_hset_targeted(
          hkey=self._result_hkey(),
          key=delegation_id,
          value=result_envelope,
          target_peer=envelope.get('origin_addr'),
        )
        self._cleanup_targeted_cstore_entry(
          hkey=self._request_hkey(),
          key=delegation_id,
          target_peer=self.ee_addr,
          mirror_peer=envelope.get('origin_addr'),
        )
    return

  def _poll_delegated_results(self):
    """Consume delegated result envelopes addressed to this origin node.

    Returns
    -------
    None
        Applies decoded results to origin requests and removes consumed mailbox
        entries.
    """
    if not self._is_balancing_enabled():
      return
    records = self.chainstore_hgetall(self._result_hkey()) or {}
    now_ts = self.time()
    for delegation_id, envelope in records.items():
      if not isinstance(envelope, dict):
        continue
      if envelope.get('origin_addr') != self.ee_addr:
        continue
      expires_at = envelope.get('expires_at')
      if isinstance(expires_at, (int, float)) and now_ts > float(expires_at):
        self._cleanup_targeted_cstore_entry(
          hkey=self._result_hkey(),
          key=delegation_id,
          target_peer=self.ee_addr,
          mirror_peer=envelope.get('target_addr'),
        )
        continue
      request_id = envelope.get('origin_request_id')
      request_data = self._requests.get(request_id)
      if request_data is None:
        continue
      if request_data.get('delegation_id') != delegation_id:
        continue
      try:
        result_body = self._decode_transport_envelope_body(envelope)
      except Exception as exc:
        result_body = {
          'status': self.STATUS_FAILED,
          'request_id': request_id,
          'error': f'Invalid delegated result payload: {exc}',
        }
      self._apply_result_to_request(
        request_id=request_id,
        result_body=result_body,
        fallback_status=envelope.get('status', self.STATUS_FAILED),
      )
      self._cleanup_targeted_cstore_entry(
        hkey=self._result_hkey(),
        key=delegation_id,
        target_peer=self.ee_addr,
        mirror_peer=envelope.get('target_addr'),
      )
    return

  def _cleanup_balancing_state(self):
    """Clean expired in-memory request-balancing bookkeeping.

    Returns
    -------
    None
        Removes stale seen-delegation ids when balancing is enabled.
    """
    if not self._is_balancing_enabled():
      return
    now_ts = self.time()
    for delegation_id, retention_deadline in list(self._seen_delegation_ids.items()):
      if retention_deadline < now_ts:
        self._seen_delegation_ids.pop(delegation_id, None)
    return

  def _reconcile_requests(self):
    """Reconcile request terminal states and release completed slots.

    Returns
    -------
    None
        Updates timeout/failure state, queue membership, and slot reservations.
    """
    for request_id, request_data in self._requests.items():
      self.maybe_mark_request_timeout(request_id=request_id, request_data=request_data)
      self.maybe_mark_request_failed(request_id=request_id, request_data=request_data)
      if self._is_request_terminal(request_data):
        self._queued_request_ids.discard(request_id)
        if request_id in self._pending_request_ids:
          try:
            self._pending_request_ids.remove(request_id)
          except ValueError:
            pass
        if request_data.get('slot_reserved'):
          self._release_execution_slot(request_id)
    return

  def _get_payload_field(self, data: dict, key: str, default=None):
    """
    Retrieve a value from payload data using case-insensitive lookup.

    Parameters
    ----------
    data : dict
      Payload dictionary to search.
    key : str
      Target key to retrieve (case-insensitive).
    default : Any, optional
      Fallback value when the key is not present.

    Returns
    -------
    Any
      Matched value from the payload or the provided default.
    """
    if not isinstance(data, dict):
      return default
    if key in data:
      return data[key]
    key_upper = key.upper()
    if key_upper in data:
      return data[key_upper]
    return default

  def _iter_struct_payloads(self, data):
    """
    Normalize structured payload containers into a flat iterable of payload dicts.

    Parameters
    ----------
    data : list, dict, or None
      Structured payload container returned by the data API.

    Returns
    -------
    list[dict]
      Flat list of payload dictionaries.
    """
    if isinstance(data, list):
      return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
      return [item for item in data.values() if isinstance(item, dict)]
    return []

  def _extract_request_id_from_payload(self, payload, key_candidates=None):
    """
    Extract a request id from a structured payload using case-insensitive keys.

    Parameters
    ----------
    payload : dict or None
      Structured payload to inspect.
    key_candidates : list[str] or None, optional
      Candidate keys checked in order.

    Returns
    -------
    str or None
      Extracted request id when present.
    """
    keys = key_candidates or ["request_id", "REQUEST_ID"]
    if not isinstance(payload, dict):
      return None
    for key in keys:
      value = self._get_payload_field(payload, key)
      if value is not None:
        return value
    return None

  def _build_owned_payloads_by_request_id(self, data, key_candidates=None):
    """
    Build a payload map limited to requests owned by the current plugin instance.

    Parameters
    ----------
    data : list, dict, or None
      Structured payload container returned by the data API.
    key_candidates : list[str] or None, optional
      Candidate request-id keys checked in order.

    Returns
    -------
    dict[str, dict]
      Mapping from request id to the corresponding owned payload.
    """
    owned_payloads = {}
    for payload in self._iter_struct_payloads(data):
      request_id = self._extract_request_id_from_payload(
        payload=payload,
        key_candidates=key_candidates,
      )
      if request_id is None or request_id not in self._requests:
        continue
      owned_payloads.setdefault(request_id, payload)
    return owned_payloads

  def _setup_semaphore_env(self):
    """
    Set semaphore environment variables for bundled plugins.
    This method is called by _semaphore_maybe_auto_signal(),
    which is called by the process_wrapper() method, thus
    it's executed after the on_init() method => self.port will
    already be allocated automatically if not already explicit.
    """
    super(BaseInferenceApiPlugin, self)._setup_semaphore_env()
    localhost_ip = self.log.get_localhost_ip()
    self.semaphore_set_env('API_HOST', localhost_ip)
    return

  """PERSISTENCE + STATUS"""
  if True:
    def load_persistence_data(self):
      """
      Restore cached request data, errors, and metrics from persistence.

      Returns
      -------
      None
        Updates in-memory state if cached data is available.
      """
      cached_data = self.cacheapi_load_pickle()
      if cached_data is not None:
        # Useful only for debugging purposes
        self._requests = cached_data.get('_requests', {})
        self._api_errors = cached_data.get('_api_errors', {})
        self._metrics = cached_data.get('_metrics', {})
        self.last_handled_error_time = cached_data.get('last_handled_error_time', None)
      # endif cached_data is not None
      return

    def maybe_save_persistence_data(self, force=False):
      """
      Persist current request tracking state when needed.

      Parameters
      ----------
      force : bool, optional
        If True, persistence is forced regardless of elapsed time.

      Returns
      -------
      None
        Saves request, error, and metric data when the save interval has elapsed or force is True.
      """
      if force or (self.time() - self.last_persistence_save) > self.cfg_save_period:
        data_to_save = {
          '_requests': self._requests,
          '_api_errors': self._api_errors,
          '_metrics': self._metrics,
          'last_handled_error_time': self.last_handled_error_time,
        }
        self.cacheapi_save_pickle(data_to_save)
        self.last_persistence_save = self.time()
      # endif needs saving
      return

    def cleanup_expired_requests(self):
      """
      Remove completed requests that exceeded the TTL window.

      Returns
      -------
      None
        Evicts expired request entries and logs eviction counts when applicable.
      """
      ttl_seconds = self.cfg_request_ttl_seconds
      if ttl_seconds <= 0:
        return
      now_ts = self.time()
      expired_ids = []
      for request_id, request_data in self._requests.items():
        finished_at = request_data.get('finished_at')
        if finished_at is None:
          continue
        if (now_ts - finished_at) > ttl_seconds:
          expired_ids.append(request_id)
      for request_id in expired_ids:
        self._requests.pop(request_id, None)
      if expired_ids:
        self.Pd(f"Evicted {len(expired_ids)} completed requests due to TTL policy.")
      return

    def record_api_error(self, request_id: Optional[str], error_message: str):
      """
      Record an API handling error and update metrics.

      Parameters
      ----------
      request_id : str or None
        Identifier of the request that failed, if available.
      error_message : str
        Description of the error encountered.

      Returns
      -------
      None
        Stores the error entry and increments failure metrics.
      """
      self.last_handled_error_time = self.time()
      key = request_id or f"error_{self.last_handled_error_time}"
      self._api_errors[key] = {
        'request_id': request_id,
        'message': error_message,
        'ts': self.last_handled_error_time,
      }
      self._metrics['requests_failed'] += 1
      return

    def get_status(self):
      """
      Compute the current status of the API based on recent errors.

      Returns
      -------
      str
        'ok' when healthy, otherwise a degraded status annotated with time since last error.
      """
      last_error_time = self.last_handled_error_time
      status = "ok"
      if last_error_time is not None:
        delta_seconds = (self.time() - last_error_time)
        if delta_seconds < 300:
          status = f"degraded (last error {int(delta_seconds)}s ago)"
        # endif enough time has passed since last error
      # endif last_error_time is not None
      return status
  """END PERSISTENCE + STATUS"""

  """SECURITY + RATE LIMITING"""
  if True:
    def check_allow_all_requests(self):
      """
      In case the API is not using tunneling and is only accessible locally,
      we can allow all requests without token checks.

      Returns
      -------
      bool
        True if all requests are allowed without authentication.
      """
      if self.cfg_is_loopback_plugin and not self.cfg_tunnel_engine_enabled:
        return True
      return False

    def env_allowed_tokens(self):
      """
      Retrieve allowed tokens from the configured environment variable.

      Returns
      -------
      list of str
        Token strings parsed from the configured auth environment variable.
      """
      env_name = self.cfg_auth_token_env
      if not env_name:
        return []
      raw_value = self.os_environ.get(env_name, '').strip()
      if not raw_value:
        return []
      return [token.strip() for token in raw_value.split(',') if token.strip()]

    def _configured_tokens(self) -> List[str]:
      """
      Aggregate authentication tokens from environment and configuration.

      Returns
      -------
      list of str
        Unique list of tokens allowed for request authorization.
      """
      env_tokens = self.env_allowed_tokens()
      predefined_tokens = self.cfg_predefined_auth_tokens or []
      all_tokens = set(env_tokens + predefined_tokens)
      return list(all_tokens)

    def authorize_request(self, authorization: Optional[str]) -> str:
      """
      Validate the authorization header and return the associated subject.

      Parameters
      ----------
      authorization : str or None
        Value of the Authorization header, expected to contain a bearer token.

      Returns
      -------
      str
        Identified subject token or 'anonymous' when anonymous access is permitted.

      Raises
      ------
      PermissionError
        If authorization is required and the provided token is missing or invalid.
      """
      if self.check_allow_all_requests():
        # TODO: should the apps using this API also have identification tokens for usage analytics?
        return "anonymous"
      tokens = self._configured_tokens()
      if not tokens:
        if not self.cfg_allow_anonymous_access:
          raise PermissionError(
            "Authorization required but no tokens were configured. Provide tokens via INFERENCE_API_TOKEN."
          )
        return "anonymous"
      if authorization is None:
        raise PermissionError("Missing Authorization header.")
      token = authorization
      if token.startswith('Bearer '):
        token = token[7:]
      token = token.strip()
      if token not in tokens:
        raise PermissionError("Invalid Authorization token.")
      return token

    def enforce_rate_limit(self, subject: str):
      """
      Enforce per-subject rate limiting when configured.

      Parameters
      ----------
      subject : str
        Identifier for the client or token being rate limited.

      Returns
      -------
      None
        Increments rate limit counters or raises if the limit is exceeded.

      Raises
      ------
      RuntimeError
        When the subject exceeds the configured requests-per-minute threshold.
      """
      # TODO: maybe make the rate limit window configurable
      if self.check_allow_all_requests():
        return
      limit = self.cfg_rate_limit_per_minute
      if limit <= 0:
        return
      bucket_key = subject or 'anonymous'
      now_minute = int(self.time() // 60)
      bucket = self._rate_limit_state.get(bucket_key)
      if bucket is None or bucket['minute'] != now_minute:
        bucket = {'minute': now_minute, 'count': 0}
        self._rate_limit_state[bucket_key] = bucket
      if bucket['count'] >= limit:
        raise RuntimeError(
          f"Rate limit exceeded for subject '{bucket_key}'. Max {limit} requests per minute."
        )
      bucket['count'] += 1
      return
  """END SECURITY + RATE LIMITING"""


  """REQUEST TRACKING"""
  if True:
    def refresh_metrics(self):
      """
      Update the active request count based on current request statuses.

      Returns
      -------
      None
        Recomputes in-memory metrics for active requests.
      """
      self._metrics['requests_active'] = sum(
        1 for req in self._requests.values() if req['status'] == self.STATUS_PENDING
      )
      # Maybe update other metrics here if needed
      # Need to consider if expired requests should be counted in total metrics.
      return

    def maybe_refresh_metrics(self):
      """
      Refresh metrics when the refresh interval has elapsed.

      Returns
      -------
      None
        Triggers metric recomputation based on cfg_metrics_refresh_seconds.
      """
      # For performance, we only refresh metrics every cfg_metrics_refresh_seconds
      now_ts = self.time()
      if (now_ts - self.last_metrics_refresh) > self.cfg_metrics_refresh_seconds:
        self.refresh_metrics()
        self.last_metrics_refresh = now_ts
      return

    def maybe_mark_request_failed(self, request_id: str, request_data: Dict[str, Any]):
      """
      Mark a pending request as failed when an error is attached.

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      request_data : dict
        Stored request record containing status and error information.

      Returns
      -------
      bool
        True when the request transitions to failed, False otherwise.
      """
      if request_data['status'] == self.STATUS_FAILED:
        return True
      if request_data['status'] != self.STATUS_PENDING:
        return False
      error = request_data.get('error', None)
      if error is None:
        return False
      self.P(f"Request {request_id} failed: {error}")
      request_data['status'] = self.STATUS_FAILED
      request_data['updated_at'] = self.time()
      request_data['result'] = {
        'error': error,
        'status': self.STATUS_FAILED,
        'request_id': request_id,
      }
      self._annotate_result_with_node_roles(
        result_payload=request_data['result'],
        request_data=request_data,
      )
      self._metrics['requests_failed'] += 1
      self._decrement_active_requests()
      return True

    def maybe_mark_request_timeout(self, request_id: str, request_data: Dict[str, Any]):
      """
      Mark a pending request as timed out when exceeding the configured timeout.

      Parameters
      ----------
      request_id : str
        Identifier of the tracked request.
      request_data : dict
        Stored request record containing timestamps and timeout settings.

      Returns
      -------
      bool
        True when the request transitions to timeout, False otherwise.
      """
      if request_data['status'] == self.STATUS_TIMEOUT:
        return True
      if request_data['status'] != self.STATUS_PENDING:
        return False
      timeout = request_data.get('timeout', self.cfg_request_timeout)
      # No timeout configured
      if timeout is None or timeout <= 0:
        return False
      if (self.time() - request_data['created_at']) <= timeout:
        return False
      self.P(f"Request {request_id} timed out after {timeout} seconds.")
      request_data['status'] = self.STATUS_TIMEOUT
      request_data['updated_at'] = self.time()
      request_data['error'] = f"Request timed out after {timeout} seconds."
      request_data['result'] = {
        'error': request_data['error'],
        'status': self.STATUS_TIMEOUT,
        'request_id': request_id,
        'timeout': timeout,
      }
      self._annotate_result_with_node_roles(
        result_payload=request_data['result'],
        request_data=request_data,
      )
      self._metrics['requests_timeout'] += 1
      self._decrement_active_requests()
      return True

    def solve_postponed_request(self, request_id: str):
      """
      Resolve or requeue a postponed request by checking its current status.

      Parameters
      ----------
      request_id : str
        Identifier of the request to resolve.

      Returns
      -------
      dict
        Request result when completed or failed, or a PostponedRequest for pending work.
      """
      if request_id in self._requests:
        last_logged_status = self._request_last_log_time.get(request_id, 0)
        if (self.time() - last_logged_status) > self.cfg_log_requests_status_every_seconds:
          self.Pd(f"Checking status of request ID {request_id}...")
          self._request_last_log_time[request_id] = self.time()
        # endif logging status
        request_data = self._requests[request_id]

        self.maybe_mark_request_timeout(request_id=request_id, request_data=request_data)
        self.maybe_mark_request_failed(request_id=request_id, request_data=request_data)
        if request_data['status'] != self.STATUS_PENDING:
          return request_data['result']
        # endif request not pending
      else:
        self.Pd(f"Request ID {request_id} not found in requests.")
        return {
          'status': 'error',
          "error": f"Request ID {request_id} not found.",
          'request_id': request_id,
        }
      # endif request exists
      return self.create_postponed_request(
        solver_method=self.solve_postponed_request,
        method_kwargs={
          "request_id": request_id
        }
      )

    def register_request(
        self,
        subject: str,
        parameters: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        request_id: Optional[str] = None,
    ):
      """
      Register a new inference request and initialize tracking metadata.

      Parameters
      ----------
      subject : str
        Identifier representing the caller (token or user).
      parameters : dict
        Request parameters to forward to the inference engine.
      metadata : dict, optional
        Additional metadata to store with the request.
      timeout : int or None, optional
        Override for request timeout in seconds.

      Returns
      -------
      tuple
        Generated request_id and the stored request data dictionary.
      """
      request_id = request_id or self.uuid()
      start_time = self.time()
      request_data = {
        "request_id": request_id,
        'subject': subject,
        'parameters': parameters,
        'metadata': metadata or {},
        'status': self.STATUS_PENDING,
        'created_at': start_time,
        'updated_at': start_time,
        'timeout': timeout or self.cfg_request_timeout,
        'result': None,
        'error': None,
      }
      self._requests[request_id] = request_data
      self._metrics['requests_total'] += 1
      self._metrics['requests_active'] += 1
      return request_id, request_data

    def serialize_request(self, request_id: str):
      """
      Produce a client-friendly view of a tracked request.

      Parameters
      ----------
      request_id : str
        Identifier of the request to serialize.

      Returns
      -------
      dict or None
        Serialized request data including status and metadata, or None if not found.
      """
      request_data = self._requests.get(request_id)
      if request_data is None:
        return None
      serialized = {
        'request_id': request_id,
        'status': request_data['status'],
        'created_at': request_data['created_at'],
        'updated_at': request_data['updated_at'],
        'metadata': request_data.get('metadata') or {},
        'subject': request_data.get('subject'),
      }
      if request_data['status'] != self.STATUS_PENDING:
        serialized['result'] = request_data['result']
      if request_data.get('error') is not None:
        serialized['error'] = request_data['error']
      return serialized
  """END REQUEST TRACKING"""

  """API ENDPOINTS"""
  if True:
    @BasePlugin.endpoint(method="GET")
    def health(self):
      """
      Health check endpoint exposing plugin status and metrics.

      Returns
      -------
      dict
        Status information including uptime, last error time, and request metrics.
      """
      return {
        "status": self.get_status(),
        "pipeline": self.get_stream_id(),
        "plugin": self.get_signature(),
        "instance_id": self.get_instance_id(),
        "loopback_enabled": self.cfg_is_loopback_plugin,
        "uptime": self.get_alive_time(),
        "last_error_time": self.last_handled_error_time,
        "total_errors": len(self._api_errors),
        "metrics": self._metrics,
      }

    @BasePlugin.endpoint(method="GET")
    def status(self):
      """
      Status endpoint summarizing API state.

      Returns
      -------
      dict
        Basic service info plus counts of pending and completed requests.
      """
      pending = len([
        rid for rid, data in self._requests.items()
        if data.get('status') == self.STATUS_PENDING
      ])
      completed = len([
        rid for rid, data in self._requests.items()
        if data.get('status') == self.STATUS_COMPLETED
      ])
      return {
        "status": self.get_status(),
        "service": self.cfg_api_summary,
        "version": __VER__,
        "stream_id": self.get_stream_id(),
        "plugin": self.get_signature(),
        "instance_id": self.get_instance_id(),
        "total_requests": len(self._requests),
        "pending_requests": pending,
        "completed_requests": completed,
        "uptime_seconds": self.get_alive_time(),
      }

    @BasePlugin.endpoint(method="GET")
    def metrics(self):
      """
      Metrics endpoint summarizing request counts and active requests.

      Returns
      -------
      dict
        Metric counters and identifiers of currently pending requests.
      """
      self.maybe_refresh_metrics()
      return {
        "metrics": self._metrics,
        "active_requests": [
          rid for rid, data in self._requests.items()
          if data['status'] == self.STATUS_PENDING
        ],
        'errors_tracked': len(self._api_errors),
      }

    @BasePlugin.endpoint(method="GET")
    def request_status(self, request_id: str, return_full: bool = False):
      """
      Retrieve the status and result of a previously submitted request.

      Parameters
      ----------
      request_id : str
        The unique identifier of the request to retrieve.
      return_full : bool, optional
        If True, return the full serialized request data including status and result.

      Returns
      -------
      dict
        If return_full is True, returns the full serialized request data.
        If the request is still pending, returns only the request_id and status.
        If the request is completed, returns the result of the request.
        If the request_id is not found, returns an error message.
      """
      serialized = self.serialize_request(request_id=request_id)
      if serialized is None:
        return {
          "error": f"Request ID {request_id} not found.",
          'request_id': request_id,
        }
      if return_full:
        return serialized
      if serialized['status'] == self.STATUS_PENDING:
        return {
          'request_id': request_id,
          'status': serialized['status'],
        }
      return serialized['result']

    @BasePlugin.endpoint(method="POST")
    def predict(
        self,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Synchronous prediction entrypoint.

      Parameters
      ----------
      authorization : str or None, optional
        Authorization token supplied by the caller.
      **kwargs
        Additional parameters forwarded to request handling.

      Returns
      -------
      dict
        Request result or error payload for synchronous processing.
      """
      return self._predict_entrypoint(
        authorization=authorization,
        async_request=False,
        **kwargs
      )

    @BasePlugin.endpoint(method="POST")
    def predict_async(
        self,
        authorization: Optional[str] = None,
        **kwargs
    ):
      """
      Asynchronous prediction entrypoint.

      Parameters
      ----------
      authorization : str or None, optional
        Authorization token supplied by the caller.
      **kwargs
        Additional parameters forwarded to request handling.

      Returns
      -------
      dict
        Tracking information for the pending request or error payload.
      """
      return self._predict_entrypoint(
        authorization=authorization,
        async_request=True,
        **kwargs
      )
  """END API ENDPOINTS"""

  """CHAT COMPLETION SECTION"""
  if True:
    def check_predict_params(self, **kwargs):
      """
      Hook for checking generic predict parameters.
      Will have all the parameters passed to the /predict endpoint.
      Parameters
      ----------
      kwargs : dict
        The parameters to check.

      Returns
      -------
      str or None
        An error message if parameters are invalid, otherwise None.
      """
      return None

    def process_predict_params(self, **kwargs):
      """
      Hook for processing generic predict parameters.
      Will have all the parameters passed to the /predict endpoint.
      Parameters
      ----------
      kwargs : dict
        The parameters to process.

      Returns
      -------
      dict
        The processed parameters.
      """
      return kwargs

    def compute_payload_kwargs_from_predict_params(
        self,
        request_id: str,
        request_data: Dict[str, Any],
    ):
      """
      Build payload fields from request parameters for downstream processing.

      Parameters
      ----------
      request_id : str
        Identifier of the request being processed.
      request_data : dict
        Stored request record containing parameters and metadata.

      Returns
      -------
      dict
        Payload keyword arguments to dispatch to the inference engine.
      """
      return {
        'REQUEST_ID': request_id,
        **request_data,
      }

    def _predict_entrypoint(
        self,
        authorization: Optional[str],
        async_request: bool,
        **kwargs
    ):
      """
      Shared prediction handler performing auth, validation, and dispatch.

      Parameters
      ----------
      authorization : str or None
        Authorization token provided by the client.
      async_request : bool
        Whether the request should be processed asynchronously.
      **kwargs
        Arbitrary parameters passed to validation and request processing.

      Returns
      -------
      dict
        Response payload containing request status, errors, or results.
      """
      endpoint_name = 'predict_async' if async_request else 'predict'
      force_local_execution = bool(kwargs.pop('_force_local_execution', False))
      delegated_execution = bool(kwargs.pop('_delegated_execution', False))
      delegation_context = kwargs.pop('_delegation_context', None) or {}

      if delegated_execution:
        subject = f"delegated:{delegation_context.get('origin_addr', 'peer')}"
      else:
        try:
          subject = self.authorize_request(authorization)
          self.enforce_rate_limit(subject)
        except PermissionError as exc:
          return {'error': str(exc), 'status': 'unauthorized'}
        except RuntimeError as exc:
          return {'error': str(exc), 'status': 'rate_limited'}
        except Exception as exc:
          return {'error': f"Unexpected error: {str(exc)}", 'status': 'error'}
        # endtry

      err = self.check_predict_params(**kwargs)
      if err is not None:
        return {'error': err}
      parameters = self.process_predict_params(**kwargs)
      metadata = {}
      if 'metadata' in parameters:
        metadata = parameters.pop('metadata') or {}
      # endif 'metadata' in parameters
      request_id_override = None
      if delegated_execution:
        request_id_override = delegation_context.get('delegation_id')
      request_id, request_data = self.register_request(
        subject=subject,
        parameters=parameters,
        metadata=metadata,
        timeout=parameters.get('timeout'),
        request_id=request_id_override,
      )
      request_data['endpoint_name'] = endpoint_name
      request_data['async_request'] = async_request

      if delegated_execution:
        owner_key = self._build_executor_owner_key(delegation_context)
        if owner_key:
          self._executor_request_map[owner_key] = request_id
        request_data['delegated_execution'] = True
        request_data['delegation_id'] = delegation_context.get('delegation_id')
        request_data['origin_request_id'] = delegation_context.get('origin_request_id', request_id)
        request_data['origin_addr'] = delegation_context.get('origin_addr')
        request_data['origin_alias'] = delegation_context.get('origin_alias')
        request_data['origin_instance_id'] = delegation_context.get('origin_instance_id')
        request_data['delegation_expires_at'] = delegation_context.get('expires_at')

      if force_local_execution:
        if not self._reserve_execution_slot(request_id):
          self._fail_request(request_id, 'Executor has no free capacity.')
          return request_data['result']
        request_data['execution_mode'] = 'local'
        self._dispatch_local_request(
          request_id=request_id,
          request_data=request_data,
        )
      elif self._should_try_balancing_for_endpoint(endpoint_name):
        scheduled = self._attempt_schedule_request(
          request_id=request_id,
          request_data=request_data,
          endpoint_name=endpoint_name,
        )
        if not scheduled:
          if not self._enqueue_pending_request(request_id):
            self._fail_request(
              request_id=request_id,
              error_message='Inference API pending queue is full.',
            )
      else:
        self._dispatch_local_request(
          request_id=request_id,
          request_data=request_data,
        )

      if delegated_execution or force_local_execution:
        return request_data
      if async_request:
        response = {
          'request_id': request_id,
          'poll_url': f"/request_status?request_id={request_id}",
          'status': request_data['status'],
        }
        if request_data.get('status') != self.STATUS_PENDING:
          response['result'] = request_data.get('result')
          response['error'] = request_data.get('error')
        return response
      return self.solve_postponed_request(request_id=request_id)
  """END CHAT COMPLETION SECTION"""

  """INFERENCE HANDLING"""
  if True:
    def filter_valid_inference(self, inference):
      """
      Validate that an inference payload corresponds to a tracked request.

      Parameters
      ----------
      inference : dict
        Inference payload produced by the downstream engine.

      Returns
      -------
      bool
        True when the inference is accepted for processing, False otherwise.
      """
      is_valid = super(BaseInferenceApiPlugin, self).filter_valid_inference(inference=inference)
      if is_valid:
        request_id = inference.get('REQUEST_ID', None)
        if request_id is None or request_id not in self._requests:
          is_valid = False
      # endif not is_valid
      return is_valid
  """END INFERENCE HANDLING"""

  def process(self):
    """
    Main plugin loop handler to refresh metrics, prune requests, and process inferences.

    Returns
    -------
    None
      Drives inference handling for the current iteration.
    """
    self.maybe_refresh_metrics()
    now_ts = self.time()
    self._publish_capacity_record()
    if (now_ts - self._last_balancing_mailbox_poll) >= self._get_mailbox_poll_period():
      self._poll_delegated_results()
      self._poll_delegated_requests()
      self._schedule_pending_requests()
      self._retry_same_peer_delegations()
      self._last_balancing_mailbox_poll = now_ts
    data = self.dataapi_struct_datas()
    inferences = self.dataapi_struct_data_inferences()
    self.handle_inferences(inferences=inferences, data=data)
    self._reconcile_requests()
    self._publish_executor_results()
    self._cleanup_balancing_state()
    self.cleanup_expired_requests()
    self.maybe_save_persistence_data()
    return
