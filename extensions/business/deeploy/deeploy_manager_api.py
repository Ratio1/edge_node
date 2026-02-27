"""

Needs configuration based on injected `EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER`

"""
from naeural_core.main.net_mon import NetMonCt
from naeural_core import constants as ct
from .deeploy_job_mixin import _DeeployJobMixin

from .deeploy_mixin import _DeeployMixin
from .deeploy_target_nodes_mixin import _DeeployTargetNodesMixin
from extensions.business.mixins.node_tags_mixin import _NodeTagsMixin
from extensions.business.mixins.request_tracking_mixin import _RequestTrackingMixin
from .deeploy_const import (
  DEEPLOY_CREATE_REQUEST, DEEPLOY_CREATE_REQUEST_MULTI_PLUGIN, DEEPLOY_GET_APPS_REQUEST, DEEPLOY_DELETE_REQUEST,
  DEEPLOY_ERRORS, DEEPLOY_KEYS, DEEPLOY_SCALE_UP_JOB_WORKERS_REQUEST, DEEPLOY_STATUS, DEEPLOY_INSTANCE_COMMAND_REQUEST,
  DEEPLOY_APP_COMMAND_REQUEST, DEEPLOY_GET_ORACLE_JOB_DETAILS_REQUEST, DEEPLOY_GET_R1FS_JOB_PIPELINE_REQUEST,
  DEEPLOY_PLUGIN_DATA, JOB_APP_TYPES, JOB_APP_TYPES_ALL,
)
  

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

__VER__ = '0.6.0'


_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  'REQUEST_TIMEOUT': 300,
  'POSTPONED_POLL_INTERVAL': 0.5,

  'DEEPLOY_VERBOSE' : 10,
  'LOG_REQUESTS': True,

  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,
  'WARMUP_DELAY' : 300,
  'PIPELINES_CHECK_DELAY' : 300,
  'MIN_ETH_BALANCE' : 0.00005,

  'REQUESTS_CSTORE_HKEY': 'DEEPLOY_REQUESTS',
  'REQUESTS_LOG_INTERVAL' : 5 * 60,
  'REQUESTS_MAX_RECORDS' : 2,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}



class DeeployManagerApiPlugin(
  BasePlugin,
  _DeeployMixin,
  _DeeployTargetNodesMixin,
  _NodeTagsMixin,
  _DeeployJobMixin,
  _RequestTrackingMixin,
  ):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for decentralized authentication.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(DeeployManagerApiPlugin, self).__init__(**kwargs)
    return

  def check_debug_logging_enabled(self):
    return self.cfg_deeploy_verbose or super(DeeployManagerApiPlugin, self).check_debug_logging_enabled()

  def on_init(self):
    super(DeeployManagerApiPlugin, self).on_init()
    my_address = self.bc.address
    my_eth_address = self.bc.eth_address
    # supported_evm_types = self.bc.eth_types
    self.P("Started {} plugin on {} / {}".format(
        self.__class__.__name__, my_address, my_eth_address,
      )
    )
    self.__warmup_start_time = self.time()
    self.__last_pipelines_check_time = 0
    if not self.__check_eth_balance():
      self.P(
        f"Shutting down tunnel engine for {self.__class__.__name__} due to insufficient ETH balance "
        f"on {my_eth_address}. Please top up and restart the node.",
        color='r', boxed=True
      )
      self.maybe_stop_tunnel_engine()
    self._init_request_tracking()
    self.__pending_deploy_requests = {}
    return


  def on_request(self, request):
    self._track_request(request)
    return

  def on_response(self, method, response):
    self._track_response(method, response)
    return


  def __check_eth_balance(self):
    """
    Check if the oracle has enough ETH to cover gas fees for web3 transactions.
    Returns True if balance is sufficient, False otherwise.
    """
    try:
      eth_address = self.bc.eth_address
      balances = self.bc.get_addresses_balances([eth_address])
      eth_balance = balances.get(eth_address, {}).get("ethBalance", 0)
      if eth_balance < self.cfg_min_eth_balance:
        self.P(
          f"Insufficient ETH balance for oracle {eth_address}: "
          f"{eth_balance:.6f} ETH < {self.cfg_min_eth_balance} ETH minimum.",
          color='r'
        )
        return False
      return True
    except Exception as e:
      self.P(f"Failed to check ETH balance: {e}", color='r')
      return False

  def __ensure_eth_balance(self):
    """
    Check ETH balance and raise ValueError if insufficient for web3 transactions.
    Called at the top of mutating endpoints.
    """
    if not self.__check_eth_balance():
      raise ValueError(
        f"{DEEPLOY_ERRORS.GENERIC}: Oracle {self.bc.eth_address} does not have enough ETH "
        f"to cover gas fees. Please top up the address and retry."
      )

  def __handle_error(self, exc, request, extra_error_code=DEEPLOY_ERRORS.GENERIC):
    """
    Handle the error and return a response.
    """
    self.Pd("Error processing request: {}, Inputs: {}".format(exc, request), color='r')
    result = {
      DEEPLOY_KEYS.STATUS : DEEPLOY_STATUS.FAIL,
      DEEPLOY_KEYS.ERROR : str(exc),
      DEEPLOY_KEYS.REQUEST : request,
    }
    if self.cfg_deeploy_verbose > 1:
      lines = self.trace_info().splitlines()
      result[DEEPLOY_KEYS.TRACE] = lines[-20:-1]
    return result
    

  @BasePlugin.endpoint(method="post")
  # /get_apps
  def get_apps(
    self, 
    request: dict = DEEPLOY_GET_APPS_REQUEST
  ):
    """
    Get the list of apps that are running on the node.
    
    Parameters
    ----------
    
    nonce : str
        The nonce used for signing the request
        
    EE_ETH_SIGN : str
        The signature of the request
        
    EE_ETH_SENDER : str
        The sender of the request
        

    Returns
    -------
    dict
        
    """
    try:
      self.Pd(f"Called Deeploy get_apps endpoint")
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)
      
      apps = self._get_online_apps(
        owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER],
        project_id=inputs.get(DEEPLOY_KEYS.PROJECT_ID, None)
      )
      
      result = {
        DEEPLOY_KEYS.STATUS : DEEPLOY_STATUS.SUCCESS,
        DEEPLOY_KEYS.APPS: apps,
        DEEPLOY_KEYS.AUTH : auth_result,
      }
    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    response = self._get_response({
      **result
    })
    return response
  

  def _process_pipeline_request(
    self,
    request: dict,
    is_create: bool = True,
    async_mode: bool = False,
  ):
    """
    Common logic for processing pipeline create/update requests.
    
    Parameters
    ----------
    request : dict
        The request dictionary
    is_create : bool
        True for create operations, False for update operations
    async_mode : bool
        When True, return a pending state for PostponedRequest polling.

    Returns
    -------
    dict
        The response dictionary
    """
    try:
      self.__ensure_eth_balance()
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      normalized_request = self._normalize_plugins_input(self.deepcopy(request))
      if DEEPLOY_KEYS.PLUGINS in normalized_request:
        inputs[DEEPLOY_KEYS.PLUGINS] = normalized_request[DEEPLOY_KEYS.PLUGINS]
      auth_result = self.deeploy_get_auth_result(inputs)
      job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
      is_confirmable_job = inputs.chainstore_response

      pipeline_params = self._extract_pipeline_params(inputs)
      inputs[DEEPLOY_KEYS.PIPELINE_PARAMS] = pipeline_params

      # Validate plugins array structure and required fields for each plugin
      plugins_array = inputs.get(DEEPLOY_KEYS.PLUGINS)
      if plugins_array:
        self._validate_plugins_array(plugins_array)
      else:
        # This shouldn't happen after normalization, but handle as fallback
        raise ValueError(f"{DEEPLOY_ERRORS.REQUEST3}. No plugins array found after normalization.")

      app_alias = inputs.app_alias
      app_type = inputs.pipeline_input_type
      job_app_type = inputs.get(DEEPLOY_KEYS.JOB_APP_TYPE, None)
      if job_app_type:
        job_app_type = str(job_app_type).lower()
        if job_app_type not in JOB_APP_TYPES_ALL:
          raise ValueError(f"Invalid job_app_type '{job_app_type}'. Expected one of {JOB_APP_TYPES_ALL}.")
      else:
        job_app_type = self.deeploy_detect_job_app_type(self.deeploy_prepare_plugins(inputs))
        if job_app_type not in JOB_APP_TYPES_ALL:
          job_app_type = JOB_APP_TYPES.NATIVE
      self.P(f"Detected job app type: {job_app_type}")
      # persist job type so downstream mixins can adjust validations (e.g. native app resource checks)
      inputs[DEEPLOY_KEYS.JOB_APP_TYPE] = job_app_type
      inputs.job_app_type = job_app_type
      
      # Generate or get app_id based on operation type
      if is_create:
        app_id = (app_alias.lower()[:13] + "_" + self.uuid(7)).lower()
      else:
        app_id = inputs.get(DEEPLOY_KEYS.APP_ID, None)
        if not app_id:
          msg = f"{DEEPLOY_ERRORS.REQUEST13}: App ID is required."
          raise ValueError(msg)

      # check payment
      is_valid = self.deeploy_check_payment_and_job_owner(inputs, auth_result[DEEPLOY_KEYS.ESCROW_OWNER], is_create=is_create, debug=self.cfg_deeploy_verbose > 1)
      if not is_valid:
        msg = f"{DEEPLOY_ERRORS.PAYMENT1}: The request job is not paid, or the job is not sent by the job owner."
        raise ValueError(msg)
      # TODO: Add check if jobType resources match the requested resources.

      # Get nodes based on operation type
      discovered_plugin_instances = []
      deployment_nodes = []
      confirmation_nodes = []
      nodes_changed = False
      deeploy_specs_for_update = None
      if is_create:
        deployment_nodes = self._check_nodes_availability(inputs)
        confirmation_nodes = list(deployment_nodes)
        nodes_changed = True
      else:
        # Discover the live deployment so we can validate node affinity and reuse existing specs.
        pipeline_context = self._gather_running_pipeline_context(
          owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER],
          app_id=app_id,
          job_id=job_id,
        )
        discovered_plugin_instances = pipeline_context["discovered_instances"]
        current_nodes = pipeline_context["nodes"]
        deeploy_specs_for_update = pipeline_context["deeploy_specs"]
        self.P(f"Discovered plugin instances: {self.json_dumps(discovered_plugin_instances)}")

        requested_nodes = inputs.get(DEEPLOY_KEYS.TARGET_NODES, None)
        normalized_requested_nodes = [
          self._check_and_maybe_convert_address(node) for node in requested_nodes or []
        ] if requested_nodes else []
        if normalized_requested_nodes:
          # preserve order while removing duplicates
          seen = set()
          deployment_targets = []
          for node in normalized_requested_nodes:
            if node not in seen:
              seen.add(node)
              deployment_targets.append(node)
        else:
          deployment_targets = list(current_nodes)

        requested_nodes_count = inputs.get(DEEPLOY_KEYS.TARGET_NODES_COUNT, 0)
        if requested_nodes_count:
          if normalized_requested_nodes and requested_nodes_count != len(deployment_targets):
            msg = (
              f"{DEEPLOY_ERRORS.NODES2}: Update request specifies {requested_nodes_count} nodes "
              f"but {len(deployment_targets)} were provided."
            )
            raise ValueError(msg)
          if not normalized_requested_nodes and requested_nodes_count != len(current_nodes):
            msg = (
              f"{DEEPLOY_ERRORS.NODES2}: Update request must keep the original number of nodes "
              f"({len(current_nodes)}) when no explicit target node list is provided. Received {requested_nodes_count}."
            )
            raise ValueError(msg)

        if not deployment_targets:
          msg = f"{DEEPLOY_ERRORS.NODES2}: Update request must include at least one target node."
          raise ValueError(msg)

        inputs[DEEPLOY_KEYS.TARGET_NODES] = deployment_targets
        inputs.target_nodes = deployment_targets
        inputs[DEEPLOY_KEYS.TARGET_NODES_COUNT] = len(deployment_targets)
        inputs.target_nodes_count = len(deployment_targets)

        # Ensure plugin IDs are preserved for existing instances before any destructive action.
        self._ensure_plugin_instance_ids(
          inputs,
          discovered_plugin_instances=discovered_plugin_instances,
          owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER],
          app_id=app_id,
          job_id=job_id,
        )

        validated_nodes = self._check_nodes_availability(inputs)
        if set(validated_nodes) != set(deployment_targets):
          msg = (
            f"{DEEPLOY_ERRORS.NODES2}: Failed to validate requested target nodes. "
            f"Expected {deployment_targets}, validated {validated_nodes}."
          )
          raise ValueError(msg)

        if job_id is not None:
          try:
            self.delete_job_pipeline_from_r1fs(job_id, remove_chainstore_entry=True)
          except Exception as exc:
            self.Pd(f"Non-blocking R1FS cleanup error for job {job_id}: {exc}", color='y')

        # All validations passed; remove the running job and immediately redeploy.
        self.delete_pipeline_from_nodes(
          app_id=app_id,
          job_id=job_id,
          owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER],
          discovered_instances=discovered_plugin_instances,
        )

        deployment_nodes = list(validated_nodes)
        confirmation_nodes = list(validated_nodes)
        nodes_changed = set(current_nodes) != set(deployment_nodes)
        discovered_plugin_instances = []

      inputs[DEEPLOY_KEYS.TARGET_NODES] = deployment_nodes
      inputs.target_nodes = deployment_nodes
      inputs[DEEPLOY_KEYS.TARGET_NODES_COUNT] = len(deployment_nodes)
      inputs.target_nodes_count = len(deployment_nodes)

      if deeploy_specs_for_update is not None and not isinstance(deeploy_specs_for_update, dict):
        msg = (
          f"{DEEPLOY_ERRORS.REQUEST3}. Unexpected 'deeploy_specs' payload type "
          f"{type(deeploy_specs_for_update).__name__}."
        )
        raise ValueError(msg)
      deeploy_specs_payload = (
        self.deepcopy(deeploy_specs_for_update)
        if isinstance(deeploy_specs_for_update, dict)
        else {}
      )
      deeploy_specs_payload = self._ensure_deeploy_specs_job_config(
        deeploy_specs_payload,
        pipeline_params=pipeline_params,
      )

      dct_status, str_status, response_keys = self.check_and_deploy_pipelines(
        owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER],
        inputs=inputs,
        app_id=app_id,
        app_alias=app_alias,
        app_type=app_type,
        new_nodes=deployment_nodes,
        update_nodes=[],
        discovered_plugin_instances=discovered_plugin_instances,
        dct_deeploy_specs_create=deeploy_specs_payload,
        job_app_type=job_app_type,
        wait_for_responses=not async_mode,
      )

      return_request = request.get(DEEPLOY_KEYS.RETURN_REQUEST, False)
      if return_request:
        dct_request = self.deepcopy(request)
        dct_request.pop(DEEPLOY_KEYS.APP_PARAMS, None)
      else:
        # Build simplified request summary (no app_params - data is in plugins array now)
        dct_request = {
          DEEPLOY_KEYS.APP_ALIAS: app_alias,
          DEEPLOY_KEYS.TARGET_NODES: inputs.target_nodes,
          DEEPLOY_KEYS.TARGET_NODES_COUNT: inputs.target_nodes_count,
          DEEPLOY_KEYS.JOB_APP_TYPE: job_app_type,
        }

        # Include plugins count summary
        plugins_array = inputs.get(DEEPLOY_KEYS.PLUGINS)
        if plugins_array:
          dct_request['plugins_count'] = len(plugins_array)
        # if pipeline_params:
        #   dct_request[DEEPLOY_KEYS.PIPELINE_PARAMS] = pipeline_params

      if async_mode:
        if len(response_keys) == 0:
          if nodes_changed and not is_confirmable_job:
            eth_nodes = [self.bc.node_addr_to_eth_addr(node) for node in confirmation_nodes]
            eth_nodes = sorted(eth_nodes)
            try:
              self.P("Submitting blockchain update for job {} with nodes: {}".format(job_id, eth_nodes))
              self.bc.submit_node_update(
                job_id=job_id,
                nodes=eth_nodes,
              )
            except Exception as e:
              self.P(f"An error occurred while submitting node update for job {job_id}: {e}", color='r')
          result = {
            DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.COMMAND_DELIVERED,
            DEEPLOY_KEYS.STATUS_DETAILS: {},
            DEEPLOY_KEYS.APP_ID: app_id,
            DEEPLOY_KEYS.REQUEST: dct_request,
            DEEPLOY_KEYS.AUTH: auth_result,
          }
          response = self._get_response({
            **result
          })
          return response

        pending_state = {
          'kind': 'pipeline',
          'response_keys': response_keys,
          'dct_status': dct_status,
          'start_time': self.time(),
          'timeout': self.cfg_request_timeout,
          'next_check_ts': self.time() + self.cfg_postponed_poll_interval,
          'base_result': {
            DEEPLOY_KEYS.APP_ID: app_id,
            DEEPLOY_KEYS.REQUEST: dct_request,
            DEEPLOY_KEYS.AUTH: auth_result,
          },
          'confirm': {
            'nodes_changed': nodes_changed,
            'confirmation_nodes': confirmation_nodes,
            'is_confirmable_job': is_confirmable_job,
            'job_id': job_id,
          },
        }
        return {'__pending__': pending_state}

      if nodes_changed and str_status in [DEEPLOY_STATUS.SUCCESS, DEEPLOY_STATUS.COMMAND_DELIVERED]:
        if (dct_status is not None and is_confirmable_job and len(confirmation_nodes) == len(dct_status)) or not is_confirmable_job:
          eth_nodes = [self.bc.node_addr_to_eth_addr(node) for node in confirmation_nodes]
          eth_nodes = sorted(eth_nodes)
          try:
            self.P("Submitting blockchain update for job {} with nodes: {}".format(job_id, eth_nodes))
            self.bc.submit_node_update(
              job_id=job_id,
              nodes=eth_nodes,
            )
          except Exception as e:
            self.P(f"An error occurred while submitting node update for job {job_id}: {e}", color='r')
            raise e
        #endif
      #endif

      result = {
        DEEPLOY_KEYS.STATUS: str_status,
        DEEPLOY_KEYS.STATUS_DETAILS: dct_status,
        DEEPLOY_KEYS.APP_ID: app_id,
        DEEPLOY_KEYS.REQUEST: dct_request,
        DEEPLOY_KEYS.AUTH: auth_result,
      }

      if self.cfg_deeploy_verbose > 1:
        self.P(f"Request Result: {result}")
    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    
    response = self._get_response({
      **result
    })
    return response

  def _register_pending_deploy_request(self, pending_state):
    """
    Register a pending deploy request and return a PostponedRequest handle.

    Parameters
    ----------
    pending_state : dict
        State payload containing response keys, timeout, and metadata.

    Returns
    -------
    PostponedRequest
        Deferred request handle for polling in the plugin loop.
    """
    pending_id = self.uuid()
    pending_state['pending_id'] = pending_id
    self.__pending_deploy_requests[pending_id] = pending_state
    return self.create_postponed_request(
      solver_method=self.solve_postponed_deploy_request,
      method_kwargs={
        'pending_id': pending_id
      }
    )

  def maybe_mark_timed_out_request(self, pending_id: str, pending, now: float = None):
    """
    Check a pending request for timeout and return a response when expired.

    Parameters
    ----------
    pending_id : str
        Identifier of the pending deeploy request.
    pending : dict
        State payload containing response keys, timeout, and metadata.
    now : float
        Current timestamp.

    Returns
    -------
    dict or None
        Response dictionary if the request timed out, or None if still valid.

    """
    res = None
    if now is None:
      now = self.time()
    if (now - pending['start_time']) > pending['timeout']:
      if pending.get('kind') == 'scale_up':
        result = {
          DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.TIMEOUT,
          DEEPLOY_KEYS.STATUS_DETAILS: pending.get('dct_status', {}),
          DEEPLOY_KEYS.JOB_ID: pending.get('job_id'),
          DEEPLOY_KEYS.REQUEST: pending.get('request'),
          DEEPLOY_KEYS.AUTH: pending.get('auth'),
        }
      else:
        result = {
          DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.TIMEOUT,
          DEEPLOY_KEYS.STATUS_DETAILS: pending.get('dct_status', {}),
          **pending.get('base_result', {})
        }
      self.__pending_deploy_requests.pop(pending_id, None)
      res = self._get_response({
        **result
      })
    # endif pending request timed out
    return res

  def finalize_pending_request_pipeline(
      self, pending, dct_status, str_status
  ):
    """
    Finalize a pending pipeline request and optionally submit BC updates.

    Parameters
    ----------
    pending : dict
        Pending request state.
    dct_status : dict
        Collected response details keyed by response key.
    str_status : str
        Aggregate status string.

    Returns
    -------
    dict
        Final response payload for the pipeline request.
    """
    confirm = pending.get('confirm', {})
    nodes_changed = confirm.get('nodes_changed', False)
    is_confirmable_job = confirm.get('is_confirmable_job', False)
    confirmation_nodes = confirm.get('confirmation_nodes', [])
    job_id = confirm.get('job_id', None)
    if nodes_changed and str_status in [DEEPLOY_STATUS.SUCCESS, DEEPLOY_STATUS.COMMAND_DELIVERED]:
      if (dct_status is not None and is_confirmable_job and len(confirmation_nodes) == len(
              dct_status)) or not is_confirmable_job:
        eth_nodes = [self.bc.node_addr_to_eth_addr(node) for node in confirmation_nodes]
        eth_nodes = sorted(eth_nodes)
        try:
          self.P("Submitting blockchain update for job {} with nodes: {}".format(job_id, eth_nodes))
          self.bc.submit_node_update(
            job_id=job_id,
            nodes=eth_nodes,
          )
        except Exception as e:
          self.P(f"An error occurred while submitting node update for job {job_id}: {e}", color='r')
    # endif nodes changed and success or delivered

    return {
      DEEPLOY_KEYS.STATUS: str_status,
      DEEPLOY_KEYS.STATUS_DETAILS: dct_status,
      **pending.get('base_result', {})
    }

  def finalize_pending_request_scale_up(
      self, pending, dct_status, str_status
  ):
    """
    Finalize a pending scale-up request and submit BC confirmation.

    Parameters
    ----------
    pending : dict
        Pending request state.
    dct_status : dict
        Collected response details keyed by response key.
    str_status : str
        Aggregate status string.

    Returns
    -------
    dict
        Final response payload for the scale-up request.
    """
    job_id = pending.get('job_id')
    is_confirmable_job = pending.get('is_confirmable_job', False)
    nodes = list(
      cstore_response.get("node") for cstore_response in dct_status.values()
      if cstore_response.get("node") is not None
    )
    self.Pd(f"Nodes to confirm: {self.json_dumps(nodes, indent=2)}")
    self._submit_bc_job_confirmation(
      str_status=str_status,
      dct_status=dct_status,
      nodes=nodes,
      job_id=job_id,
      is_confirmable_job=is_confirmable_job,
    )
    return {
      DEEPLOY_KEYS.STATUS: str_status,
      DEEPLOY_KEYS.STATUS_DETAILS: dct_status,
      DEEPLOY_KEYS.JOB_ID: job_id,
      DEEPLOY_KEYS.REQUEST: pending.get('request'),
      DEEPLOY_KEYS.AUTH: pending.get('auth'),
    }

  def finalize_pending_request(
      self, pending, dct_status, str_status,
    ):
    """
    Finalize a pending request based on its kind.

    Parameters
    ----------
    pending : dict
        Pending request state.
    dct_status : dict
        Collected response details keyed by response key.
    str_status : str
        Aggregate status string.

    Returns
    -------
    dict
        Final response payload.
    """
    # Finalize pending request
    if pending.get('kind') == 'pipeline':
      result = self.finalize_pending_request_pipeline(
        pending=pending,
        dct_status=dct_status,
        str_status=str_status,
      )
    elif pending.get('kind') == 'scale_up':
      result = self.finalize_pending_request_scale_up(
        pending=pending,
        dct_status=dct_status,
        str_status=str_status,
      )
    else:
      result = {
        DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.FAIL,
        DEEPLOY_KEYS.ERROR: f"Unknown pending request kind: {pending.get('kind')}"
      }
    return result

  def solve_postponed_deploy_request(self, pending_id: str):
    """
    Resolve a pending deploy request by polling for chainstore responses.

    Parameters
    ----------
    pending_id : str
        Identifier of the pending deploy request.

    Returns
    -------
    dict or PostponedRequest
        Final response when complete or a PostponedRequest to continue polling.
    """
    pending = self.__pending_deploy_requests.get(pending_id)
    if not pending:
      result = {
        DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.FAIL,
        DEEPLOY_KEYS.ERROR: f"Pending request {pending_id} not found.",
      }
      return self._get_response({
        **result
      })

    now = self.time()
    # Not all requests are processed every iteration in order to lighten the load on the CPU
    postponed_kwargs = {
      'solver_method': self.solve_postponed_deploy_request,
      'method_kwargs': {'pending_id': pending_id},
    }
    if now < pending.get('next_check_ts', 0):
      return self.create_postponed_request(**postponed_kwargs)

    timeout_response = self.maybe_mark_timed_out_request(pending_id=pending_id, pending=pending, now=now)
    if timeout_response:
      return timeout_response

    dct_status, str_status, done = self._check_pipeline_responses_once(
      response_keys=pending['response_keys'],
      dct_status=pending.get('dct_status'),
    )
    pending['dct_status'] = dct_status

    if not done:
      pending['next_check_ts'] = now + self.cfg_postponed_poll_interval
      return self.create_postponed_request(**postponed_kwargs)

    result = self.finalize_pending_request(
      pending=pending,
      dct_status=dct_status,
      str_status=str_status,
    )

    self.__pending_deploy_requests.pop(pending_id, None)
    return self._get_response({
      **result
    })

  @BasePlugin.endpoint(method="post")
  # /create_pipeline
  def create_pipeline(
    self,
    request: dict = DEEPLOY_CREATE_REQUEST
  ):
    """
    Create a new pipeline on target node(s) with support for multiple plugins.

    Supports two request formats:
    1. **Plugin instances array (recommended)**: Use 'plugins' array for pipelines with multiple plugins
    2. **Legacy single-plugin format**: Provide 'plugin_signature'; legacy payloads are normalized into the plugins array

    Parameters
    ----------

    request: dict containing next fields:

      app_alias : str
          The name (alias) of the app to create

      pipeline_input_type : str
          The pipeline type (e.g., 'void', 'JeevesApiListener')

      job_id : int
          The job ID from blockchain

      target_nodes : list[str] or target_nodes_count : int
          Either specific nodes or count of nodes to deploy on

      job_tags : list
          Tags for filtering target nodes
          Example: ["KYB", "DC:HOSTINGER", "CT:FR|IT|RO", "REG:EU"]
      pipeline_params : dict, optional
          Additional pipeline-level parameters forwarded to the data capture thread. `null` falls back to `{}`.
          The provided keys are merged into the pipeline configuration at the top level.

      nonce : str
          The nonce used for signing the request

      EE_ETH_SIGN : str
          The signature of the request

      EE_ETH_SENDER : str
          The sender wallet address

      **Plugin instances:**
        plugins : list
            Array of plugin instance configurations. Each object represents ONE plugin instance:
            - plugin_signature : str (required)
                The plugin signature (e.g., 'CONTAINER_APP_RUNNER', 'EDGE_NODE_API_TEST')
            - **instance-specific parameters** (varies by plugin type)
                For CONTAINER_APP_RUNNER:
                  - IMAGE : str (required)
                  - CONTAINER_RESOURCES : dict (required)
                      - cpu : int | float
                      - memory : str (e.g., "4096m", "4g")
                  - CR, PORT, ENV, VOLUMES, TUNNEL_ENGINE_ENABLED, etc.
                For native plugins:
                  - Plugin-specific configuration parameters

      **Example request:**
        {
          "app_alias": "EdgeNodeApiTest",
          "pipeline_input_type": "void",
          "job_id": 123,
          "target_nodes_count": 1,
          "plugins": [
            {
              "plugin_signature": "EDGE_NODE_API_TEST"
            },
            {
              "plugin_signature": "CONTAINER_APP_RUNNER",
              "IMAGE": "tvitalii/ratio1-drive:latest",
              "CONTAINER_RESOURCES": {
                "cpu": 2,
                "memory": "4096m"
              },
              "PORT": 8080
            }
          ],
          "nonce": "0x...",
          "EE_ETH_SIGN": "0x...",
          "EE_ETH_SENDER": "0x..."
        }

      **Legacy single-plugin format (deprecated):**
        plugin_signature : str
            The signature of the single plugin to use. Configuration should remain embedded with the
            plugin instance data; legacy `app_params` payloads are normalized into the plugins array
            and omitted from responses.

    Returns
    -------
    dict
        Response containing:
        - status : str
        - app_id : str
        - status_details : dict
        - request : dict
        - auth : dict

    Notes
    -----
    - Multi-plugin pipelines are automatically classified as JOB_APP_TYPE.NATIVE
    - Single CONTAINER_APP_RUNNER is classified as GENERIC or SERVICE
    - Resource requirements are aggregated across all container plugins
    - Multiple instances of the same plugin: Include multiple objects with the same plugin_signature
    - Example: [{"plugin_signature": "PLUGIN_A", ...}, {"plugin_signature": "PLUGIN_A", ...}] creates 2 instances
    - For multi-plugin templates, see DEEPLOY_CREATE_REQUEST_MULTI_PLUGIN in deeploy_const.py

    TODO: (Vitalii)
      - Add support to get the ngrok url if NO edge/endpoint is provided but ngrok is STILL used
    TODO: (Vitalii)
      - Change from sync to async.
        Sending the jobs to nodes, while UI will do pooling for the job status.
        1. Request comes in. Response command sent.
        2. Move while checker for chainstore keys in process.
    """
    self.Pd(f"Called Deeploy create_pipeline endpoint")
    result = self._process_pipeline_request(request, is_create=True, async_mode=True)
    if isinstance(result, dict) and result.get('__pending__') is not None:
      return self._register_pending_deploy_request(result['__pending__'])
    return result

  @BasePlugin.endpoint(method="post")
  # /update_pipeline
  def update_pipeline(
    self,
    request: dict = DEEPLOY_CREATE_REQUEST
  ):
    """
    Update a pipeline on node(s) with support for multiple plugins.

    Supports the same formats as create_pipeline:
    1. **Plugin instances array**: Use 'plugins' array for pipelines with multiple plugins
    2. **Legacy format**: Provide 'plugin_signature'; legacy payloads are normalized into the plugins array

    Parameters
    ----------

    request: dict containing next fields:

      app_id : str
          The ID of the app to update (required for updates)

      app_alias : str
          The name (alias) of the app

      pipeline_input_type : str
          The pipeline type

      job_id : int
          The job ID from blockchain

      pipeline_params : dict, optional
          Additional pipeline-level parameters forwarded to the data capture thread. `null` falls back to `{}`.
          The provided keys are merged into the pipeline configuration at the top level.

      nonce : str
          The nonce used for signing the request

      EE_ETH_SIGN : str
          The signature of the request

      EE_ETH_SENDER : str
          The sender wallet address

      **Plugin instances:**
        plugins : list
            Array of plugin instance configurations. Each object represents ONE plugin instance:
            - plugin_signature : str (required)
            - instance_id : str (required when updating an existing plugin instance)
            - **instance-specific parameters** (payload merged into the instance configuration)
              - Omit instance_id to attach a brand new plugin instance; supported for native apps only

      **Legacy format:**
        plugin_signature : str
            The signature of the single plugin. Legacy payloads without the plugins array are
            normalized internally; any deprecated `app_params` field is ignored in responses.

    Returns
    -------
    dict
        Response containing update status and details

    Notes
    -----
    - Existing pipelines are stopped and redeployed in place; requests must reference the active node set.
    - Updates are applied to existing plugin instances on the same nodes
    - For multi-plugin pipelines, all plugins are updated with new configurations
    - Resource validation applies the same as create operations
    - The simplified plugins array format is the same as create_pipeline
    - New plugin instances can be introduced by omitting `instance_id` (native job type only)
    - See create_pipeline endpoint for detailed parameter documentation and examples

    """
    self.P(f"Received an update_pipeline request with body: {self.json_dumps(request)}")
    result = self._process_pipeline_request(request, is_create=False, async_mode=True)
    if isinstance(result, dict) and result.get('__pending__') is not None:
      return self._register_pending_deploy_request(result['__pending__'])
    return result

  @BasePlugin.endpoint(method="post")
  def scale_up_job_workers(self,
    request: dict = DEEPLOY_SCALE_UP_JOB_WORKERS_REQUEST
  ):
    """
    Scales up the number of workers for a given job (pipeline) on target node(s)
    This endpoint does the next job:
    1. Get nodes on which the job is running
    2. Update the config, chainstore_allowed, etc.
    3. Send update command to the nodes, on which it was running and send create command to the new nodes.
    4. Wait until all the responses are received via CSTORE and compose status response
    5. Return the status response
    Parameters
    ----------
    request: dict containing next fields:
      job_id : int
      app_id : str
      target_nodes : list[str]
      target_nodes_count : int
      node_res_req : dict
      nonce : str
      EE_ETH_SIGN : str
      EE_ETH_SENDER : str
    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      self.__ensure_eth_balance()
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)
      job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
      if not job_id:
        msg = f"{DEEPLOY_ERRORS.REQUEST13}: Job ID is required."
        raise ValueError(msg)

      is_confirmable_job = inputs.chainstore_response

      # check payment
      is_valid = self.deeploy_check_payment_and_job_owner(inputs, auth_result[DEEPLOY_KEYS.ESCROW_OWNER], is_create=False, debug=self.cfg_deeploy_verbose > 1)
      if not is_valid:
        msg = f"{DEEPLOY_ERRORS.PAYMENT1}: The request job is not paid, or the job is not sent by the job owner."
        raise ValueError(msg)
      
      running_apps_for_job = self._get_online_apps(job_id=job_id, owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER])

      # todo: check the count of running workers and compare with the amount of allowed workers count from blockchain.
      
      self.P(f"Discovered running apps for job: {self.json_dumps(running_apps_for_job)}")

      if not running_apps_for_job or not len(running_apps_for_job):
        msg = f"{DEEPLOY_ERRORS.NODES3}: No running workers found for provided job_id and owner '{auth_result[DEEPLOY_KEYS.ESCROW_OWNER]}'."
        raise ValueError(msg)
      
      update_nodes = list(running_apps_for_job.keys())
      new_nodes = self._check_nodes_availability(inputs)
      
      dct_status, str_status, response_keys = self.scale_up_job(
        new_nodes=new_nodes,
        update_nodes=update_nodes,
        owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER],
        job_id=job_id,
        running_apps_for_job=running_apps_for_job,
        wait_for_responses=False
      )

      return_request = request.get(DEEPLOY_KEYS.RETURN_REQUEST, False)
      if return_request:
        dct_request = self.deepcopy(request)
      else:
        dct_request = None

      if len(response_keys) == 0:
        if not is_confirmable_job:
          nodes = list(set(update_nodes + new_nodes))
          self.Pd(f"Nodes to confirm (non-confirmable job): {self.json_dumps(nodes, indent=2)}")
          self._submit_bc_job_confirmation(str_status=DEEPLOY_STATUS.COMMAND_DELIVERED,
                                           dct_status={},
                                           nodes=nodes,
                                           job_id=job_id,
                                           is_confirmable_job=is_confirmable_job)
        result = {
          DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.COMMAND_DELIVERED,
          DEEPLOY_KEYS.STATUS_DETAILS: dct_status,
          DEEPLOY_KEYS.JOB_ID: job_id,
          DEEPLOY_KEYS.REQUEST: dct_request,
          DEEPLOY_KEYS.AUTH: auth_result,
        }
        if self.cfg_deeploy_verbose > 1:
          self.P(f"Request Result: {result}")
        response = self._get_response({
          **result
        })
        return response

      pending_state = {
        'kind': 'scale_up',
        'response_keys': response_keys,
        'dct_status': {},
        'start_time': self.time(),
        'timeout': self.cfg_request_timeout,
        'next_check_ts': self.time() + self.cfg_postponed_poll_interval,
        'job_id': job_id,
        'is_confirmable_job': is_confirmable_job,
        'request': dct_request,
        'auth': auth_result,
      }
      return self._register_pending_deploy_request(pending_state)

    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    
    response = self._get_response({
      **result
    })
    return response

  @BasePlugin.endpoint(method="post")
  def delete_pipeline(self,
    request: dict = DEEPLOY_DELETE_REQUEST
  ):
    """
    Deletes a given app (pipeline) on target node(s)

    Parameters
    ----------
    request: dict containing next fields:
      app_id : str
      job_id: int
        app_id and job_id are interchangeable identifiers of job / pipeline
      target_nodes : list[str]
      nonce : str
      EE_ETH_SIGN : str
      EE_ETH_SENDER : str
    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      self.__ensure_eth_balance()
      self.Pd(f"Called Deeploy delete_pipeline endpoint")
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)
      job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
      app_id = inputs.get(DEEPLOY_KEYS.APP_ID, None)

      discovered_instances = self.delete_pipeline_from_nodes(app_id=app_id, job_id=job_id, owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER])
      request_payload = {
        DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.SUCCESS,
        DEEPLOY_KEYS.TARGETS: discovered_instances,
      }

      if job_id is not None:
        request_payload[DEEPLOY_KEYS.JOB_ID] = job_id
      elif app_id is not None:
        request_payload[DEEPLOY_KEYS.APP_ID] = app_id

      result = {
        DEEPLOY_KEYS.REQUEST : request_payload,
        DEEPLOY_KEYS.AUTH : auth_result,
      }
    
    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    
    response = self._get_response({
      **result
    })
    return response


  @BasePlugin.endpoint(method="post")
  def send_instance_command(self, 
    request: dict = DEEPLOY_INSTANCE_COMMAND_REQUEST
  ):
    """
    Sends a command to a given app instance on target node(s).
    
    IMPORTANT: This generic command does not make any discovery of the nodes, plugin or instances tied to the given app_id.
    It is the responsibility of the caller to provide the correct target_nodes, instance_id and plugin_signature. 

    Parameters
    ----------
    request: dict containing next keys:
      app_id : str
      target_nodes : list[str]
      plugin_signature : str
      instance_id : str
      instance_command : any
      nonce : str
      EE_ETH_SIGN : str
      EE_ETH_SENDER : str
    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      self.__ensure_eth_balance()
      self.Pd(f"Called Deeploy send_instance_command endpoint")
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)

      # Validate the request fields.
      self._validate_send_instance_command_request(inputs)

      self.send_instance_command_to_nodes(inputs, owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER])

      result = {
        DEEPLOY_KEYS.REQUEST : {
          DEEPLOY_KEYS.STATUS : DEEPLOY_STATUS.COMMAND_DELIVERED,
          DEEPLOY_KEYS.APP_ID : inputs.app_id,
          DEEPLOY_KEYS.TARGET_NODES : inputs.target_nodes,
        },
        DEEPLOY_KEYS.AUTH : auth_result,
      }

    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    
    response = self._get_response({
      **result
    })
    return response
  

  @BasePlugin.endpoint(method="post")
  def send_app_command(self, 
    request: dict = DEEPLOY_APP_COMMAND_REQUEST
  ):
    """
    Sends a command to a given app on all its target node(s).
    
    IMPORTANT: This function will discover the plugin instances and the nodes where the app is running.

    Parameters
    ----------
    request: dict with keys below:
      app_id : str
      job_id: int
        app_id and job_id are interchangeable identifiers of job / pipeline
      instance_command : any
      nonce : str
      EE_ETH_SIGN : str
      EE_ETH_SENDER : str
    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      self.__ensure_eth_balance()
      self.Pd(f"Called Deeploy send_app_command endpoint")
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)

      # Validate the request fields.
      self._validate_send_app_command_request(inputs)

      discovered_pipelines = self.discover_and_send_instance_command(inputs, owner=auth_result[DEEPLOY_KEYS.ESCROW_OWNER])
      targets = []
      for discovered_pipeline in discovered_pipelines:
        targets.append([discovered_pipeline[DEEPLOY_PLUGIN_DATA.NODE],
                        discovered_pipeline[DEEPLOY_PLUGIN_DATA.APP_ID],
                        discovered_pipeline[DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE],
                        discovered_pipeline[DEEPLOY_PLUGIN_DATA.INSTANCE_ID]])
      job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
      app_id = inputs.get(DEEPLOY_KEYS.APP_ID, None)

      request_payload = {
        DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.COMMAND_DELIVERED,
      }

      # Prefer JOB_ID if both are present; otherwise use APP_ID; add nothing if neither.
      if job_id is not None:
        request_payload[DEEPLOY_KEYS.JOB_ID] = job_id
      elif app_id is not None:
        request_payload[DEEPLOY_KEYS.APP_ID] = app_id

      result = {
        DEEPLOY_KEYS.REQUEST: request_payload,
        DEEPLOY_KEYS.TARGETS: targets,
        DEEPLOY_KEYS.AUTH: auth_result,
      }

    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    
    response = self._get_response({
      **result
    })
    return response

  @BasePlugin.endpoint(method="post")
  def get_oracle_job_details(
    self, 
    request: dict = DEEPLOY_GET_ORACLE_JOB_DETAILS_REQUEST
  ):
    """
    Get the details of a job by its job ID.
    This endpoint is restricted to oracles only.
    
    Parameters
    ----------
    request: dict containing next fields:
      job_id : int
        The job ID to retrieve details for
      nonce : str
      EE_ETH_SIGN : str
      EE_ETH_SENDER : str (must be an oracle)

    Returns
    -------
    dict
        A dictionary containing the job details
    """
    try:
      sender, inputs = self.deeploy_verify_and_get_inputs(request, require_sender_is_oracle=True, no_hash=False)
      job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)
      if not job_id:
        msg = f"{DEEPLOY_ERRORS.REQUEST11}: Job ID is required."
        raise ValueError(msg)
      
      apps = self._get_online_apps(job_id=job_id)
      found_app = None
      found_app_alias = None
      for node, app in apps.items():
        for pipeline_name, details in app.items():
          found_app = details
          found_app_alias = pipeline_name
          break
      if not found_app:
        msg = f"{DEEPLOY_ERRORS.REQUEST12}: Job with ID {job_id} not found."
        raise ValueError(msg)

      bc_job_details = self.bc.get_job_details(job_id=job_id)
      result = {
        DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.SUCCESS,
        DEEPLOY_KEYS.JOB_ID: job_id,
        DEEPLOY_KEYS.PROJECT_NAME: found_app.get(NetMonCt.DEEPLOY_SPECS, {}).get(DEEPLOY_KEYS.PROJECT_NAME, None),
        'job_name': found_app_alias,
        'job_type': bc_job_details.get("jobType")
      }
    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    response = self._get_response({
      **result
    })
    return response

  @BasePlugin.endpoint(method="post")
  # /get_r1fs_job_pipeline
  def get_r1fs_job_pipeline(
    self,
    request: dict = DEEPLOY_GET_R1FS_JOB_PIPELINE_REQUEST
  ):
    """
    Get the stored pipeline payload for a single job ID directly from R1FS/CSTORE.

    Parameters
    ----------
    request: dict containing next fields:
      job_id : int
      nonce : str
      EE_ETH_SIGN : str
      EE_ETH_SENDER : str

    Returns
    -------
    dict
        A dictionary with the stored pipeline payload from R1FS.
    """
    try:
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)
      job_id = inputs.get(DEEPLOY_KEYS.JOB_ID, None)

      if not job_id:
        msg = f"{DEEPLOY_ERRORS.REQUEST11}: Job ID is required."
        raise ValueError(msg)

      pipeline = self.get_job_pipeline_from_cstore(job_id)
      if pipeline is None:
        msg = f"{DEEPLOY_ERRORS.REQUEST12}: Pipeline payload for job {job_id} could not be loaded."
        raise ValueError(msg)

      pipeline_owner = pipeline.get("OWNER", None)
      request_owner = auth_result.get(DEEPLOY_KEYS.ESCROW_OWNER)
      if pipeline_owner != request_owner:
        msg = (
          f"{DEEPLOY_ERRORS.REQUEST13}: Job {job_id} does not belong to requesting owner "
          f"'{request_owner}'."
        )
        raise ValueError(msg)

      result = {
        DEEPLOY_KEYS.STATUS: DEEPLOY_STATUS.SUCCESS,
        DEEPLOY_KEYS.JOB_ID: job_id,
        DEEPLOY_KEYS.PIPELINE: pipeline,
        DEEPLOY_KEYS.AUTH: auth_result,
      }
    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry

    response = self._get_response({
      **result
    })
    return response

  def is_deeploy_warmed_up(self):
    return (self.time() - self.__warmup_start_time) > self.cfg_warmup_delay

  def process(self):
    if not self.is_deeploy_warmed_up():
      return

    if (self.time() - self.__last_pipelines_check_time) > self.cfg_pipelines_check_delay:
      try:
        self.check_running_pipelines_and_add_to_r1fs()
      except Exception as e:
        self.P(f"Error checking running pipelines: {e}", color='r')
      self.__last_pipelines_check_time = self.time()

    self._maybe_log_and_save_tracked_requests()
    return
