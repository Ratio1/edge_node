"""

Needs configuration based on injected `EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER`

"""

from .deeploy_mixin import _DeeployMixin
from .deeploy_requests import *

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin


__VER__ = '0.5.1'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  'DEEPLOY_VERBOSE' : True,
  
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
  
  def _check_and_maybe_convert_address(self, node_addr, raise_if_error=True):
    result = None
    if node_addr.startswith("0x"):
      is_eth = self.bc.is_valid_eth_address(node_addr)
      if is_eth:
        result = self.bc.eth_addr_to_internal_addr(node_addr)
      else:
        is_internal = self.bc.is_valid_internal_address(node_addr)
        if is_internal:
          result = node_addr
        #endif
      #endif
    #endif
    if result is None:
      msg = "Invalid node address: {}".format(node_addr)
      if raise_if_error:
        raise ValueError(msg)
      else:
        self.P(msg, color='r')
    return result
  
  
  def __handle_error(self, exc, request):
    """
    Handle the error and return a response.
    """
    self.Pd("Error processing request: {}, Inputs: {}".format(exc, request), color='r')
    result = {
      'status' : 'fail',
      'error' : str(exc),
    }
    if self.cfg_deeploy_verbose:
      lines = self.trace_info().splitlines()
      result['trace'] = lines[-5:-1]
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
      apps = self._get_online_apps()
      #
      result = {        
        'status' : 'success',
        'apps': apps,
        'auth' : self.deeploy_get_auth_result(inputs),
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
    
    """
    try:
      sender, inputs = self.deeploy_verify_and_get_inputs(request)   
      
      # TODO: move to the mixin when ready
      plugins = self.deeploy_prepare_plugins(inputs)
      app_alias = inputs.app_alias
      app_type = inputs.pipeline_input_type 
      app_id = (app_alias.lower()[:8] + "_" + self.uuid(7)).lower()
      nodes = []
      for node in inputs.target_nodes:
        addr = self._check_and_maybe_convert_address(node)
        is_online = self.netmon.network_node_is_online(addr)
        if is_online:
          nodes.append(addr)
        else:
          raise ValueError("Node {} is not online".format(addr))
        #endif is_online
      #endfor each target node check address and status
      if len(nodes) == 0:
        raise ValueError("No valid nodes provided")        
      for addr in nodes:
        self.P(f"Starting pipeline '{app_alias}' on {addr}")
        if addr is not None:
          self.cmdapi_start_pipeline_by_params(
            name=app_id,
            app_alias=app_alias,
            pipeline_type=app_type,
            node_address=addr,
            owner=sender,
            url=inputs.pipeline_input_uri,
            plugins=plugins,
          )
        #endif addr is valid
      #endfor each target node
      
      result = {
        'status' : 'success',
        'app_id' : app_id,
        'request' : {
          'app_alias' : app_alias,
          'plugin_signature' : inputs.plugin_signature,
          'target_nodes' : inputs.target_nodes,
          'target_nodes_count' : inputs.target_nodes_count,
          'app_params_image' : inputs.app_params.IMAGE,
          'app_params_registry' : inputs.app_params.CR,
        },        
        'auth' : self.deeploy_get_auth_result(inputs),
      }
    
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
      
      # TODO: move to the mixin when ready
      app_id = inputs.app_id
      nodes = [self._check_and_maybe_convert_address(node) for node in inputs.target_nodes]
      if len(nodes) == 0:
        raise ValueError("No valid nodes provided")        
      for addr in nodes:
        self.P(f"Stopping pipeline '{app_id}' on {addr}")
        self.cmdapi_stop_pipeline(
          node_address=addr,
          name=inputs.app_id,
        )
      #endfor each target node
      
      result = {
        'request' : {
          'status' : 'success',          
          'app_id' : inputs.app_id,
          'target_nodes' : inputs.target_nodes,
        },
        'auth' : self.deeploy_get_auth_result(inputs),
      }
    
    except Exception as e:
      result = self.__handle_error(e, request)
    #endtry
    
    response = self._get_response({
      **result
    })
    return response
