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

  "REQUEST_TTL_SECONDS": 60 * 60 * 2,  # keep historical results for 2 hours
  "RATE_LIMIT_PER_MINUTE": 5,
  "AUTH_TOKEN_ENV": "INFERENCE_API_TOKEN",
  "PREDEFINED_AUTH_TOKENS": [],  # e.g. ["token1", "token2"]
  "ALLOW_ANONYMOUS_ACCESS": True,

  "METRICS_REFRESH_SECONDS": 5 * 60,  # 5 minutes

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
    # This is different from self.last_error_time in BasePlugin
    # self.last_error_time tracks unhandled errors that occur in the plugin loop
    # This one tracks all errors that occur during API request handling
    self.last_handled_error_time = None
    self.last_metrics_refresh = 0
    self.last_persistence_save = 0
    self.load_persistence_data()
    tunneling_str = f"(with tunneling enabled)" if self.cfg_tunnel_engine_enabled else ""
    start_msg = f"{self.get_signature()} initialized{tunneling_str}.\n"
    lst_endpoint_names = list(self._endpoints.keys())
    endpoints_str = ", ".join([f"/{endpoint_name}" for endpoint_name in lst_endpoint_names])
    start_msg += f"\t\tEndpoints: {endpoints_str}\n"
    start_msg += f"\t\tAI Engine: {self.cfg_ai_engine}\n"
    start_msg += f"\t\tLoopback key: loopback_dct_{self._stream_id}"
    self.P(start_msg)
    return

  def _setup_semaphore_env(self):
    """Set semaphore environment variables for bundled plugins."""
    localhost_ip = self.log.get_localhost_ip()
    port = self.cfg_port
    self.semaphore_set_env('API_HOST', localhost_ip)
    if port:
      self.semaphore_set_env('API_PORT', str(port))
      self.semaphore_set_env('API_URL', f'http://{localhost_ip}:{port}')
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
      self._metrics['requests_failed'] += 1
      self._metrics['requests_active'] -= 1
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
      self._metrics['requests_timeout'] += 1
      self._metrics['requests_active'] -= 1
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
        self.Pd(f"Checking status of request ID {request_id}...")
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
        timeout: Optional[int] = None
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
      request_id = self.uuid()
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
      request_id, request_data = self.register_request(
        subject=subject,
        parameters=parameters,
        metadata=metadata,
        timeout=parameters.get('timeout')
      )
      payload_kwargs = self.compute_payload_kwargs_from_predict_params(
        request_id=request_id,
        request_data=request_data,
      )
      self.Pd(
        f"Dispatching request {request_id} :: {self.json_dumps(payload_kwargs, indent=2)[:500]}"
      )
      self.add_payload_by_fields(
        **payload_kwargs,
        signature=self.get_signature()
      )

      if async_request:
        return {
          'request_id': request_id,
          'poll_url': f"/request_status?request_id={request_id}",
          'status': self.STATUS_PENDING,
        }
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
    self.cleanup_expired_requests()
    self.maybe_save_persistence_data()
    data = self.dataapi_struct_datas()
    inferences = self.dataapi_struct_data_inferences()
    self.handle_inferences(inferences=inferences, data=data)
    return
