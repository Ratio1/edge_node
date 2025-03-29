"""

Needs configuration based on injected `EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER`

"""

from .deeploy_mixin import _DeeployMixin
from .deeploy_requests import *

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin


__VER__ = '0.3.1'

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
      sender, inputs = self.deeploy_get_inputs(request)
      verified_sender = self.deeploy_verify_get_apps_request(inputs)
      assert sender == verified_sender, "Request verification failed. Sender: {}, Verified sender: {}".format(sender, verified_sender)      
      dct_auth = self.deeploy_get_auth_result(inputs, sender, verified_sender)
      apps = self._get_online_apps()
      result = {        
        'apps': apps,
        'status' : 'success',
        **dct_auth,
      }
    except Exception as e:
      self.P("Error processing request: {}, Inputs: {}".format(e, inputs), color='r')
      result = {
        'error' : str(e)
      }
      if self.cfg_deeploy_verbose:
        result['trace'] = self.trace_info()
      #endif
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
    
    app_name : str
        The name of the app to create
        
    plugin_signature : str
        The signature of the plugin to use
        
    target_nodes : list[str]
        The nodes to create the app on
        
    target_nodes_count : int
        The number of nodes to create the app on
        
    nonce : str
        The nonce used for signing the request
        
    app_params : dict
        The parameters to pass to the app
        
    app_params.IMAGE : str
        The image to use for the app
    app_params.REGISTRY : str 
        The registry to use for the app
    app_params.USERNAME : str 
        The username to use for the app
    app_params.PASSWORD : str 
    
    """
    try:
      sender, inputs = self.deeploy_get_inputs(request)
      verified_sender = self.deeploy_verify_create_request(inputs)
      assert sender == verified_sender, "Request verification failed. Sender: {}, Verified sender: {}".format(sender, verified_sender)
      dct_auth = self.deeploy_get_auth_result(inputs, sender, verified_sender)
      
      # TODO: move to the mixin when ready
      plugins = self.deeploy_prepare_plugins(inputs)
      app_name = inputs.app_name
      app_type = inputs.pipeline_input_type
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
        self.P(f"Starting pipeline '{app_name}' on {addr}")
        if addr is not None:
          self.cmdapi_start_pipeline_by_params(
            name=app_name,
            pipeline_type=app_type,
            node_address=addr,
            owner=sender,
            url=inputs.pipeline_input_uri,
            plugins=plugins,
          )
        #endif addr is valid
      #endfor each target node
      
      result = {
        'request' : {
          'app_name' : inputs.app_name,
          'plugin_signature' : inputs.plugin_signature,
          'target_nodes' : inputs.target_nodes,
          'target_nodes_count' : inputs.target_nodes_count,
          'app_params_image' : inputs.app_params.IMAGE,
          'app_params_registry' : inputs.app_params.CR,
        },        
        'status' : 'success',
        **dct_auth,
      }
    
    except Exception as e:
      self.P("Error processing request: {}, Inputs: {}".format(e, inputs), color='r')
      result = {
        'error' : str(e)
      }
      if self.cfg_deeploy_verbose:
        result['trace'] = self.trace_info()    
    
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
    app_name : str
        The name of the app to delete
        
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
      sender, inputs = self.deeploy_get_inputs(request)
      verified_sender = self.deeploy_verify_delete_request(inputs)
      assert sender == verified_sender, "Request verification failed. Sender: {}, Verified sender: {}".format(sender, verified_sender)
      dct_auth = self.deeploy_get_auth_result(inputs, sender, verified_sender)
      
      # TODO: move to the mixin when ready
      app_name = inputs.app_name
      nodes = [self._check_and_maybe_convert_address(node) for node in inputs.target_nodes]
      if len(nodes) == 0:
        raise ValueError("No valid nodes provided")        
      for addr in nodes:
        self.P(f"Stopping pipeline '{app_name}' on {addr}")
        self.cmdapi_stop_pipeline(
          node_address=addr,
          name=inputs.app_name,
        )
      #endfor each target node
      
      result = {
        'request' : {
          'app_name' : inputs.app_name,
          'target_nodes' : inputs.target_nodes,
        },
        'status' : 'success',
        **dct_auth,
      }
    
    except Exception as e:
      self.P("Error processing request: {}, Inputs: {}".format(e, inputs), color='r')
      result = {
        'error' : str(e)
      }
      if self.cfg_deeploy_verbose:
        result['trace'] = self.trace_info()      
    
    response = self._get_response({
      **result
    })
    return response
