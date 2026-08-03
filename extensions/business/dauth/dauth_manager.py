"""
dauth_manager.py
================

This module implements the dAuth Manager plugin for the Ratio1e ecosystem. It provides a FastAPI web app
for decentralized authentication. The plugin is responsible for handling authentication requests and
providing authentication data to other nodes in the network using the dAuth protocol mainly defined in the
`extensions/business/dauth/dauth_mixin.py` module.





EE_HB_CONTAINS_PIPELINES=0
EE_HB_CONTAINS_ACTIVE_PLUGINS=1
EE_EPOCH_MANAGER_DEBUG=1
WHITELIST (oracles)




"""
import threading

from extensions.business.mixins.node_tags_mixin import _NodeTagsMixin
from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin
from extensions.business.mixins.request_tracking_mixin import _RequestTrackingMixin
from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY,
  _DauthMixin,
)
from extensions.business.dauth.dauth_registry import (
  dauth_registry_write_kwargs,
  load_dauth_registry_snapshot,
)

__VER__ = '0.3.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'DAUTH_VERBOSE' : False,
  'DAUTH_LOG_RESPONSE' : True,
  'LOG_REQUESTS' : True,
  
  'REQUESTS_CSTORE_HKEY': 'DAUTH_REQUESTS',
  'REQUESTS_MAX_RECORDS': 2,
  'REQUESTS_LOG_INTERVAL': 5 * 60,

  'DAUTH_JOB_SECRETS_HSYNC_INTERVAL': 10 * 60,
  'DAUTH_REGISTRY_REFRESH_INTERVAL': 60 * 60,
  'DAUTH_REGISTRY_REFRESH_RETRY_INTERVAL': 60,
  'DAUTH_REGISTRY_REFRESH_TIMEOUT': 30,
  'DAUTH_REGISTRY_MAX_PENDING_LOOKUPS': 2,

  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,
  
  # required ENV keys are defined in plugin template and should be added here  
  "AUTH_ENV_KEYS" : [
  ],

  # node-only ENV keys should be added in this list - these are keys that should
  # not get to the non-nodes
  "AUTH_NODE_ENV_KEYS" : [
  ],

  
  "AUTH_PREDEFINED_KEYS" : {
  },
  
  "COMMS_HOST_KEY" : "EE_MQTT_HOST",          # key to use for the comms host
  "COMMS_HOST_SEED_KEY" : "EE_MQTT_HOST_SEED", # key to use for the comms host seed

  "SUPERVISOR_KEYS" : [
    "EE_NGROK_EDGE_LABEL_EPOCH_MANAGER",
    "EE_NGROK_EDGE_LABEL_RELEASE_APP",
    "EE_NGROK_EDGE_LABEL_DAUTH_MANAGER",
    "EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER",
    "EE_NGROK_EDGE_LABEL_TUNNELS_MANAGER",
    
    "EE_TUNNEL_ENGINE",

    "EE_CLOUDFLARE_TOKEN_EPOCH_MANAGER",
    "EE_CLOUDFLARE_TOKEN_RELEASE_APP",
    "EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER",
    "EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER",
    "EE_CLOUDFLARE_TOKEN_TUNNELS_MANAGER",
    "EE_CLOUDFLARE_TOKEN_LIVENESS_API",
    
    "EE_MQTT_HOST_SEED" # this generates dynamically the EE_MQTT_HOST
  ],

  "DAUTH_ORACLE_ONLY_SUPERVISOR_KEYS": [
    "EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER",
  ],

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}



class DauthManagerPlugin(
  BasePlugin,
  _DauthMixin,
  _NodeTagsMixin,
  _RequestTrackingMixin,
  ):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for decentralized authentication.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(DauthManagerPlugin, self).__init__(**kwargs)
    self._dauth_server_enabled = None
    self._dauth_server_enabled_message = None
    self._dauth_registry_eth_oracles = None
    self._dauth_registry_internal_peers = None
    self._last_dauth_registry_refresh = None
    self._dauth_registry_refresh_failed = False
    self._dauth_registry_lookup_threads = []
    self._last_dauth_job_secrets_hsync = None
    self._dauth_web_app_initialized = False
    self._dauth_pause_teardown_succeeded = True
    return
  
  

  def on_init(self):
    self._check_dauth_server_enabled_on_start()
    super(DauthManagerPlugin, self).on_init()
    self._dauth_web_app_initialized = True
    if not self._is_dauth_server_enabled():
      self.on_pause()
    else:
      self._maybe_hsync_dauth_job_secrets()
    # endif
    my_address = self.bc.address
    my_eth_address = self.bc.eth_address
    self.P("Started {} plugin on {} / {}\n - Auth keys: {}\n - Predefined keys: {}".format(
      self.__class__.__name__, my_address, my_eth_address,
      self.cfg_auth_env_keys, self.cfg_auth_predefined_keys)
    )
    self._init_request_tracking()
    return

  def _check_dauth_server_enabled_on_start(self):
    if getattr(self, "_dauth_server_enabled", None) is not None:
      return self._dauth_server_enabled
    # endif

    return self._refresh_dauth_registry(force=True)

  def _refresh_dauth_registry(self, force=False):
    now = self.time()
    last_refresh = getattr(self, "_last_dauth_registry_refresh", None)
    refresh_interval = (
      self.cfg_dauth_registry_refresh_retry_interval
      if getattr(self, "_dauth_registry_refresh_failed", False)
      else self.cfg_dauth_registry_refresh_interval
    )
    if (
      not force
      and last_refresh is not None
      and now - last_refresh < refresh_interval
    ):
      return self._is_dauth_server_enabled()
    # endif

    self._last_dauth_registry_refresh = now
    previous_enabled = getattr(self, "_dauth_server_enabled", None)
    previous_eth_oracles = getattr(self, "_dauth_registry_eth_oracles", None)

    error = None
    try:
      peers, eth_oracles = self._load_dauth_registry_snapshot_with_timeout()
      enabled = self.bc.eth_address.lower() in [
        address.lower() for address in eth_oracles
      ]
    except Exception as e:
      enabled = False
      error = str(e)
    # end try

    message = None if enabled else error or "current node is not registered as a dAuth oracle"
    self._dauth_registry_eth_oracles = eth_oracles if enabled else None
    self._dauth_registry_internal_peers = peers if enabled else None
    self._dauth_registry_refresh_failed = error is not None
    self._dauth_server_enabled = enabled
    self._dauth_server_enabled_message = message
    registry_changed = previous_eth_oracles != self._dauth_registry_eth_oracles
    if enabled and (previous_enabled is not True or registry_changed):
      self.P(
        f"{self.__class__.__name__} dAuth registry gate is enabled "
        f"with {len(eth_oracles)} registered oracle(s)"
      )
    elif not enabled and (previous_enabled is not False or error is not None):
      self.P(
        f"{self.__class__.__name__} dAuth registry gate is disabled. "
        f"(cause: {message})",
        color='r',
        boxed=True
      )
    # endif
    return enabled

  def _load_dauth_registry_snapshot_with_timeout(self):
    lookup_threads = [
      thread for thread in getattr(self, "_dauth_registry_lookup_threads", [])
      if thread.is_alive()
    ]
    self._dauth_registry_lookup_threads = lookup_threads
    if len(lookup_threads) >= self.cfg_dauth_registry_max_pending_lookups:
      raise TimeoutError("too many dAuth registry lookups are still running")
    # endif

    result = {}

    def load_registry():
      try:
        result["snapshot"] = load_dauth_registry_snapshot(self)
      except Exception as exc:
        result["error"] = exc
      # end try
      return

    lookup_thread = threading.Thread(target=load_registry, daemon=True)
    self._dauth_registry_lookup_threads.append(lookup_thread)
    lookup_thread.start()
    lookup_thread.join(timeout=self.cfg_dauth_registry_refresh_timeout)
    if lookup_thread.is_alive():
      raise TimeoutError(
        f"dAuth registry lookup timed out after "
        f"{self.cfg_dauth_registry_refresh_timeout} seconds"
      )
    # endif

    self._dauth_registry_lookup_threads.remove(lookup_thread)
    error = result.get("error")
    if error is not None:
      raise error
    return result["snapshot"]

  def _is_dauth_server_enabled(self):
    return getattr(self, "_dauth_server_enabled", None) is True

  def should_pause(self):
    self._refresh_dauth_registry()
    return not self._is_dauth_server_enabled()

  def should_resume(self):
    self._refresh_dauth_registry()
    return self._is_dauth_server_enabled()

  def on_pause(self):
    if not getattr(self, "_dauth_web_app_initialized", False):
      return
    # endif

    self.set_plugin_ready(False)
    self._dauth_pause_teardown_succeeded = False
    self._stop_request_monitor.set()
    if self._request_monitor_thread is not None:
      self._request_monitor_thread.join(timeout=1.0)
    # endif

    self._maybe_close_start_commands()
    running_commands = [
      idx for idx, process in enumerate(self.start_commands_processes)
      if process is not None and process.poll() is None
    ]
    if running_commands:
      raise RuntimeError(f"Failed to stop start commands {running_commands} while pausing")
    if self._request_monitor_thread is not None and self._request_monitor_thread.is_alive():
      raise RuntimeError("Failed to stop the FastAPI request monitor while pausing")
    # endif

    with self._incoming_lock:
      self._incoming_requests.clear()
    # endwith
    self.postponed_requests.clear()
    while True:
      try:
        self._server_queue.get(False)
      except Exception:
        break
    # endwhile

    self._maybe_read_and_stop_all_log_readers()
    self.maybe_stop_tunnel_engine()
    tunnel_stop_started = self.time()
    while getattr(self, "tunnel_engine_started", False):
      if self.time() - tunnel_stop_started >= 1.0:
        raise RuntimeError("Failed to stop tunnel engine while pausing")
      self.sleep(0.01)
    # endwhile
    self.reset_tunnel_engine()

    nr_commands = len(self.get_start_commands())
    self.start_commands_started = [False] * nr_commands
    self.start_commands_finished = [False] * nr_commands
    self.start_commands_processes = [None] * nr_commands
    self.start_commands_start_time = [None] * nr_commands
    self._dauth_pause_teardown_succeeded = True
    return

  def on_resume(self):
    if not self._is_dauth_server_enabled():
      raise RuntimeError("Cannot resume an ineligible dAuth server")
    if not self._dauth_pause_teardown_succeeded:
      raise RuntimeError("Cannot resume after an incomplete web app teardown")
    # endif

    self.failed = False
    self._stop_request_monitor.clear()
    self._start_request_monitor_thread()
    return

  def on_log_handler(self, text, key=None):
    super(DauthManagerPlugin, self).on_log_handler(text, key=key)
    if self._is_dauth_server_enabled() and "Uvicorn running on " in text:
      self.set_plugin_ready(True)
    # endif
    return
    
  
  def on_request(self, request):
    self._track_request(request)
    return

  def on_response(self, method, response):
    self._track_response(method, response)
    return

  def process(self):
    self._maybe_hsync_dauth_job_secrets()
    # TODO: this will be re-enabled in the future.
    if False:
      self._maybe_log_and_save_tracked_requests()
    return

  def _maybe_hsync_dauth_job_secrets(self):
    if not self._is_dauth_server_enabled():
      return None

    now = self.time()
    last_sync = getattr(self, "_last_dauth_job_secrets_hsync", None)
    if (
      last_sync is not None
      and now - last_sync < self.cfg_dauth_job_secrets_hsync_interval
    ):
      return None

    self._last_dauth_job_secrets_hsync = now
    try:
      return self.chainstore_hsync(
        hkey=DAUTH_JOB_SECRETS_CSTORE_HKEY,
        **dauth_registry_write_kwargs(self),
      )
    except Exception as exc:
      self.P(f"Could not sync dAuth job secrets: {exc}", color="y")
    return None

  def __get_current_epoch(self):
    """
    Get the current epoch of the node.

    Returns
    -------
    int
        The current epoch of the node.
    """    
    return self.netmon.epoch_manager.get_current_epoch()
    
  
  def __sign(self, data):
    """
    Sign the given data using the blockchain engine.
    Returns the signature. 
    Use the data param as it will be modified in place.
    """
    signature = self.bc.sign(data, add_data=True, use_digest=True)
    return signature

  def __get_response(self, dct_data: dict):
    """
    TODO: move __get_response to base as a _get_response method or similar
    
    Create a response dictionary with the given data.

    Parameters
    ----------
    dct_data : dict
        The data to include in the response - data already prepared 

    Returns
    -------
    dict
        The input dictionary with the following keys added:
        - server_alias: str
            The literal alias of the current node.

        - server_time: str
            The current time in UTC of the current node.

        - server_current_epoch: int
            The current epoch of the current node.

        - server_uptime: str
            The time that the current node has been running.
    """
    try:
      str_utc_date = self.datetime.now(self.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
      # dct_data['server_id'] = self.node_addr # redundant due to the EE_SENDER
      dct_data['server_alias'] = self.node_id
      dct_data['server_version'] = self.ee_ver
      dct_data['server_time'] = str_utc_date
      dct_data['server_current_epoch'] = self.__get_current_epoch()
      dct_data['server_uptime'] = str(self.timedelta(seconds=int(self.time_alive)))
      self.__sign(dct_data) # add the signature over full data
    except Exception as e:
      self.P("Error in `get_response`: {}".format(e), color='r')
      preexisting_error = dct_data.get('error', "")
      dct_data['error'] = f"{preexisting_error} - {e}"
    return dct_data
   
  

  @BasePlugin.endpoint(method="post")
  # /get_auth_data
  def get_auth_data(self, body: dict):
    """
    Receive a request for authentication data from a node and return the data if the request is valid.

    Parameters
    ----------
    {
      "body" : {
        "EE_SENDER" : "sender node address",
        "EE_SIGN" : "sender signature on the message",
        "EE_HASH" : "message hash",
        "nonce" : "some-nonce"
        ... other data
      }      
    }    
    """
    if not self._is_dauth_server_enabled():
      response = self.__get_response({
        'error': 'dAuth server is not registered as a dAuth oracle'
      })
      return response

    try:
      data = self.process_dauth_request(body)
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      data = {
        'error' : str(e)
      }
    
    response = self.__get_response({
      **data
    })
    return response

  @BasePlugin.endpoint(method="post")
  # /add_secrets
  def add_secrets(self, body: dict):
    """
    Store a full job secret bundle from a protocol oracle.

    The signed request must include a hex-millisecond timestamp nonce no older
    than 120 seconds.
    """
    request_nonce = body.get("nonce") if isinstance(body, dict) else None
    if not self._is_dauth_server_enabled():
      response = self.__get_response({
        'error': 'dAuth server is not registered as a dAuth oracle',
        'nonce': request_nonce,
      })
      return response

    try:
      data = self.process_dauth_add_secrets_request(body)
    except Exception as e:
      self.P("Error processing add_secrets request: {}".format(e), color='r')
      data = {
        'error' : str(e)
      }

    response = self.__get_response({
      'nonce': request_nonce,
      **data
    })
    return response

  @BasePlugin.endpoint(method="post")
  # /get_secrets
  def get_secrets(self, body: dict):
    """
    Return an encrypted job secret bundle to a current R1FS job runner.

    The signed request must include a hex-millisecond timestamp nonce no older
    than 120 seconds. The signed response echoes that nonce.
    """
    request_nonce = body.get("nonce") if isinstance(body, dict) else None
    if not self._is_dauth_server_enabled():
      response = self.__get_response({
        'error': 'dAuth server is not registered as a dAuth oracle',
        'nonce': request_nonce,
      })
      return response

    try:
      data = self.process_dauth_get_secret_request(body)
    except Exception as e:
      self.P("Error processing get_secrets request: {}".format(e), color='r')
      data = {
        'error' : str(e)
      }

    response = self.__get_response({
      'nonce': request_nonce,
      **data
    })
    return response
