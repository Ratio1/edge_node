"""

Needs configuration based on injected `EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER`

"""
from naeural_core.main.net_mon import NetMonCt

from .deeploy_mixin import _DeeployMixin
from .deeploy_const import (
  DEEPLOY_CREATE_REQUEST, DEEPLOY_GET_APPS_REQUEST, DEEPLOY_DELETE_REQUEST,
  DEEPLOY_ERRORS, DEEPLOY_KEYS, DEEPLOY_STATUS, DEEPLOY_INSTANCE_COMMAND_REQUEST,
  DEEPLOY_APP_COMMAND_REQUEST, DEEPLOY_PLUGIN_DATA,
)
  

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin


__VER__ = '0.5.1'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'DEEPLOY_VERBOSE' : 10,
  
  'SUPRESS_LOGS_AFTER_INTERVAL' : 300,
  
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}



class DeeployManagerPlugin(
  BasePlugin,
  _DeeployMixin
  ):
  """
  This plugin is the dAuth FastAPI web app that provides an endpoints for decentralized authentication.
  """
  CONFIG = _CONFIG
  

  def __init__(self, **kwargs):
    super(DeeployManagerPlugin, self).__init__(**kwargs)
    return


  def on_init(self):
    super(DeeployManagerPlugin, self).on_init()
    my_address = self.bc.address
    my_eth_address = self.bc.eth_address
    # supported_evm_types = self.bc.eth_types
    self.P("Started {} plugin on {} / {}".format(
        self.__class__.__name__, my_address, my_eth_address,
      )
    )        
    return
  
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
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)
      
      apps = self._get_online_apps()
      
      # TODO: (Vitalii) filter apps by the sender address (OWNER)
      
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
  
  
  @BasePlugin.endpoint(method="post")
  # /create_pipeline
  def create_pipeline(
    self, 
    request: dict = DEEPLOY_CREATE_REQUEST
  ):
    """
    Create a new pipeline on a target node(s)
        

    Parameters
    ----------
    
    app_alias : str
        The name (alias) of the app to create
        
    plugin_signature : str
        The signature of the plugin to use
        
    target_nodes : list[str]
        The nodes to create the app on
        
    target_nodes_count : int
        The number of nodes to create the app on
        
    nonce : str
        The nonce used for signing the request
        
    app_params : dict
        The parameters to pass to the app such as:
          
          app_params.IMAGE : str
              The image to use for the app
          app_params.REGISTRY : str 
              The registry to use for the app
          app_params.USERNAME : str 
              The username to use for the app
          app_params.PASSWORD : str 
          
          
    TODO: (Vitalii)
      - Add support to get the ngrok url if NO edge/endpoint is provided but ngrok is STILL used
    
    """
    try:
      sender, inputs = self.deeploy_verify_and_get_inputs(request)   
      auth_result = self.deeploy_get_auth_result(inputs)

      app_alias = inputs.app_alias
      app_type = inputs.pipeline_input_type
      app_id = (app_alias.lower()[:8] + "_" + self.uuid(7)).lower()

      dct_status, str_status = self.check_and_deploy_pipelines(
        sender=sender, inputs=inputs, app_id=app_id, 
        app_alias=app_alias, app_type=app_type
      )

      return_request = request.get(DEEPLOY_KEYS.RETURN_REQUEST, False)
      if return_request:
        dct_request = self.deepcopy(request)
      else:
        dct_request = {
          DEEPLOY_KEYS.APP_ALIAS: app_alias,
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: inputs.plugin_signature,
          DEEPLOY_KEYS.TARGET_NODES: inputs.target_nodes,
          DEEPLOY_KEYS.TARGET_NODES_COUNT: inputs.target_nodes_count,
        }

      result = {
        DEEPLOY_KEYS.STATUS: str_status,
        DEEPLOY_KEYS.STATUS_DETAILS: dct_status,
        DEEPLOY_KEYS.APP_ID: app_id,
        DEEPLOY_KEYS.REQUEST: dct_request,
        DEEPLOY_KEYS.AUTH: auth_result,
      }

      if self.cfg_deeploy_verbose > 1:
        self.P(f"Request Result: {result}")

      # Safely add app_params if they exist and are not empty
      if hasattr(inputs, DEEPLOY_KEYS.APP_PARAMS):
        app_params = getattr(inputs, DEEPLOY_KEYS.APP_PARAMS, {})
        if isinstance(app_params, dict) and app_params:
          if DEEPLOY_KEYS.APP_PARAMS_IMAGE in app_params:
            result[DEEPLOY_KEYS.REQUEST][DEEPLOY_KEYS.APP_PARAMS_IMAGE] = app_params[DEEPLOY_KEYS.APP_PARAMS_IMAGE]
          if DEEPLOY_KEYS.APP_PARAMS_CR in app_params:
            result[DEEPLOY_KEYS.REQUEST][DEEPLOY_KEYS.APP_PARAMS_CR] = app_params[DEEPLOY_KEYS.APP_PARAMS_CR]
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
    app_id : str
        The identificator of the app to delete as given by the /create_pipeline endpoint
        knowing that all decentralized distributed pipelines share the same app_id
        
    target_nodes : list[str]
        The nodes to delete the app from
                
    nonce : str
        The nonce used for signing the request
        
    EE_ETH_SIGN : str
        The signature of the request
        
    EE_ETH_SENDER : str
        The sender of the request

    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)
      
      # TODO: move to the mixin when ready
      app_id = inputs.app_id
      nodes = [self._check_and_maybe_convert_address(node) for node in inputs.target_nodes]
      if len(nodes) == 0:
        msg = f"{DEEPLOY_ERRORS.NODES3}: No valid nodes provided"
        raise ValueError(msg)        
      for addr in nodes:
        self.P(f"Stopping pipeline '{app_id}' on {addr}")
        self.cmdapi_stop_pipeline(
          node_address=addr,
          name=inputs.app_id,
        )
      #endfor each target node
      
      result = {
        DEEPLOY_KEYS.REQUEST : {
          DEEPLOY_KEYS.STATUS : DEEPLOY_STATUS.SUCCESS,
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
  def send_instance_command(self, 
    request: dict = DEEPLOY_INSTANCE_COMMAND_REQUEST
  ):
    """
    Sends a command to a given app instance on target node(s).
    
    IMPORTANT: This generic command does not make any discovery of the nodes, plugin or instances tied to the given app_id.
    It is the responsibility of the caller to provide the correct target_nodes, instance_id and plugin_signature. 

    Parameters
    ----------
    app_id : str
        The identificator of the app to delete as given by the /create_pipeline endpoint
        knowing that all decentralized distributed pipelines share the same app_id
        
    target_nodes : list[str]
        The nodes where the app runs
        
    plugin_signature : str
        The signature of the plugin that will receive the command
    
    instance_id : str
        The plugin instance that will receive the command
        
    instance_command : any
        The command to send to each app instance (processed by each individual plugin instance)
                
    nonce : str
        The nonce used for signing the request
        
    EE_ETH_SIGN : str
        The signature of the request
        
    EE_ETH_SENDER : str
        The sender of the request

    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)

      self.send_instance_command_to_nodes(inputs)


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
    app_id : str
        The identificator of the app to delete as given by the /create_pipeline endpoint
        knowing that all decentralized distributed pipelines share the same app_id
                
    instance_command : any
        The command to send to each app instance (processed by each individual plugin instance)
                
    nonce : str
        The nonce used for signing the request
        
    EE_ETH_SIGN : str
        The signature of the request
        
    EE_ETH_SENDER : str
        The sender of the request

    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      sender, inputs = self.deeploy_verify_and_get_inputs(request)
      auth_result = self.deeploy_get_auth_result(inputs)
      
      discovered_pipelines = self.discover_and_send_pipeline_command(inputs)
      targets = []
      for discovered_pipeline in discovered_pipelines:
        targets.append([discovered_pipeline[DEEPLOY_PLUGIN_DATA.NODE],
                        discovered_pipeline[DEEPLOY_PLUGIN_DATA.APP_ID],
                        discovered_pipeline[DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE],
                        discovered_pipeline[DEEPLOY_PLUGIN_DATA.INSTANCE_ID]])
      result = {
        DEEPLOY_KEYS.REQUEST : {
          DEEPLOY_KEYS.STATUS : DEEPLOY_STATUS.COMMAND_DELIVERED,
          DEEPLOY_KEYS.APP_ID : inputs.app_id,
        },
        DEEPLOY_KEYS.TARGETS: targets,
        DEEPLOY_KEYS.AUTH : auth_result,
      }

    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    
    response = self._get_response({
      **result
    })
    return response  