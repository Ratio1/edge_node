"""


"""

from .deeploy_mixin import _DeeployMixin

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin
from naeural_core.constants import BASE_CT

__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  'PORT': None,
  
  'ASSETS' : 'nothing', # TODO: this should not be required in future
  
  
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
    self.P("Started {} plugin on {} / {}".format(
        self.__class__.__name__, my_address, my_eth_address,
      )
    )        
    return
    

  @BasePlugin.endpoint(method="post")
  # /get_apps
  def get_apps(
    self, 
    request: dict = {
      BASE_CT.BCctbase.ETH_SENDER: "0xethaddr355",
      BASE_CT.BCctbase.ETH_SIGN: "0xethsig123",
      "nonce" : "hex_nonce", # recoverable via int(nonce, 16)
    }
  ):
    """
    Get the list of apps that are running on the node.

    Returns
    -------
    dict
        
    """
    try:
      self.P("Received request for apps")
      inputs = self.NestedDotDict(request)
      verified_sender = self._verify_get_apps_request(inputs)
      sender = request[self.ct.BASE_CT.BCctbase.ETH_SENDER]
      result = {
        'apps': [],
        'auth' : {
          'sender' : sender,
          'verified_sender' : verified_sender,
        },
      }
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      result = {
        'error' : str(e)
      }
    response = self._get_response({
      **result
    })
    return response
    
    

  @BasePlugin.endpoint(method="post")
  # /create_pipeline
  def create_pipeline(
    self, 
    request: dict =  {
      "app_name" : "SOME_APP_NAME", 
      "plugin_signature" : "SOME_PLUGIN_01",
      "nonce" : "hex_nonce", # recoverable via int(nonce, 16)
      "target_nodes" : [
        "0xai_node_1",
        "0xai_node_2",
      ],
      "target_nodes_count" : 0,
      "app_params" : {
        "IMAGE" : "repo/image:tag",
        "REGISTRY" : "docker.io",
        "USERNAME" : "user",
        "PASSWORD" : "password",
        "PORT" : 5000,
        "OTHER_PARAM1" : "value1",
        "OTHER_PARAM2" : "value2",
        "OTHER_PARAM3" : "value3",
        "OTHER_PARAM4" : "value4",
        "OTHER_PARAM5" : "value5",
        "ENV" : {
          "ENV1" : "value1",
          "ENV2" : "value2",
          "ENV3" : "value3",
          "ENV4" : "value4",
        }
      }    
    }
  ):
    """
    Receive a request for creating a new pipeline on a target node

    Parameters
    ----------
    """
    try:
      self.P("Received request for new pipeline data")
      inputs = self.NestedDotDict(request)  
      verified_sender = self._verify_request(inputs)
      result = {
        'request' : {
          'app_name' : inputs.app_name,
          'plugin_signature' : inputs.plugin_signature,
          'nonce' : inputs.nonce,
          'target_nodes' : inputs.target_nodes,
          'target_nodes_count' : inputs.target_nodes_count,
          'app_params_image' : inputs.app_params.IMAGE,
          'app_params_registry' : inputs.app_params.REGISTRY,
        },        
        'auth' : {
          'sender' : inputs[self.ct.BASE_CT.BCctbase.ETH_SENDER],
          'verified_sender' : verified_sender,
        },
      }
    
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      result = {
        'error' : str(e)
      }
    
    response = self._get_response({
      **result
    })
    return response


  @BasePlugin.endpoint(method="post")
  def delete_pipeline(self, 
    request: dict = {
      "app_name" : "SOME_APP_NAME",
      "target_nodes" : [
        "0xai_node_1",
        "0xai_node_2",
      ],
      BASE_CT.BCctbase.ETH_SENDER: "0xethaddr355",
      BASE_CT.BCctbase.ETH_SIGN: "0xethsig123",
      "nonce" : "hex_nonce", # recoverable via int(nonce, 16)
    }
  ):
    """
    Receive a request for deleting a pipeline on a target node(s)

    Parameters
    ----------
    app_name : str
        The name of the app to delete
        
    target_nodes : list[str]
        The nodes to delete the app from

    Returns
    -------
    dict
        A dictionary with the result of the operation
    """
    try:
      self.P("Received request for deleting pipeline data")
      inputs = self.NestedDotDict(request)
      verified_sender = self._verify_delete_request(inputs)
      sender = request[self.ct.BASE_CT.BCctbase.ETH_SENDER]
      result = {
        'request' : {
          'app_name' : inputs.app_name,
          'plugin_signature' : inputs.plugin_signature,
          'nonce' : inputs.nonce,
          'target_nodes' : inputs.target_nodes,
        },
        'auth' : {
          'sender' : sender,
          'verified_sender' : verified_sender,
        },
      }
    
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      result = {
        'error' : str(e)
      }
    
    response = self._get_response({
      **result
    })
    return response
