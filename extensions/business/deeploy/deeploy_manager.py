"""
Examples:

Create request nonce 2025-03-28 10:36:37:
{
  "request": {
    "app_name": "SOME_APP_NAME",
    "plugin_signature": "SOME_PLUGIN_01",
    "nonce": "0x195dc533d7b",
    "target_nodes": [
      "0xai_Amfnbt3N-qg2-qGtywZIPQBTVlAnoADVRmSAsdDhlQ-6",
      "0xai_Amfnbt3N-qg2-qGtywZIPQBTVlAnoADVRmSAsdDhlQ-7"
    ],
    "target_nodes_count": 0,
    "app_params": {
      "IMAGE": "repo/image:tag",
      "REGISTRY": "docker.io",
      "USERNAME": "user",
      "PASSWORD": "password",
      "PORT": 5000,
      "OTHER_PARAM1": "value1",
      "OTHER_PARAM2": "value2",
      "OTHER_PARAM3": "value3",
      "OTHER_PARAM4": "value4",
      "OTHER_PARAM5": "value5",
      "ENV": {
        "ENV1": "value1",
        "ENV2": "value2",
        "ENV3": "value3",
        "ENV4": "value4"
      }
    },
    "EE_ETH_SIGN": "0x8350f9600dc872d2d37d25d8cbe672dd2d1ee23cc80366a9d3b0f30d2f3249872fac116db5aee6d88911a180fae6c4e7ec0e5750de320221b7a14e1cb6ad8ad91c",
    "EE_ETH_SENDER": "0x168f051A021E0cCaD836DA6968C09Fc5F0E92A06"
  }
}

Get apps request nonce 2025-03-28 10:36:37:
{
  "request": {
    "nonce": "0x195dc533d7b",
    "EE_ETH_SIGN": "0x35aef39f6e5cb32cefaecd5d852fa786e855e1d8bd4bacf78cc286103bf9bdb3600785710306ff72e2bc4bac76b99ca3ab920e16ca898c0692fbea0a2c1f043a1c",
    "EE_ETH_SENDER": "0x168f051A021E0cCaD836DA6968C09Fc5F0E92A06"
  }
}

Delete request nonce 2025-03-28 10:36:37:
{
  "request": {
    "app_name": "SOME_APP_NAME",
    "target_nodes": [
      "0xai_node_1",
      "0xai_node_2"
    ],
    "nonce": "0x195dc533d7b",
    "EE_ETH_SIGN": "0xfcab3eb3133edc1b35ec7866279160302635ab3b0159a7ec10c5ed0966bc30a634180b024ee477368ee0f413a581d122a070f9a5473922e9aa487c9a624270251c",
    "EE_ETH_SENDER": "0x168f051A021E0cCaD836DA6968C09Fc5F0E92A06"
  }
}


Needs configuration based on injected `EE_NGROK_EDGE_LABEL_DEEPLOY_MANAGER`

"""

from .deeploy_mixin import _DeeployMixin

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin


__VER__ = '0.2.1'

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
    

  @BasePlugin.endpoint(method="post")
  # /get_apps
  def get_apps(
    self, 
    request: dict = {
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
      sender, inputs = self.deeploy_get_inputs(request)
      verified_sender = self.deeploy_verify_get_apps_request(inputs)
      dct_auth = self.deeploy_get_auth_result(inputs, sender, verified_sender)
      apps = self._get_online_apps()
      result = {
        'apps': apps,
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
      sender, inputs = self.deeploy_get_inputs(request)
      verified_sender = self.deeploy_verify_create_request(inputs)
      dct_auth = self.deeploy_get_auth_result(inputs, sender, verified_sender)
      result = {
        'request' : {
          'app_name' : inputs.app_name,
          'plugin_signature' : inputs.plugin_signature,
          'target_nodes' : inputs.target_nodes,
          'target_nodes_count' : inputs.target_nodes_count,
          'app_params_image' : inputs.app_params.IMAGE,
          'app_params_registry' : inputs.app_params.REGISTRY,
        },        
        **dct_auth,
      }
    
    except Exception as e:
      self.P("Error processing request: {}, Inputs: {}".format(e, inputs), color='r')
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
      sender, inputs = self.deeploy_get_inputs(request)
      verified_sender = self.deeploy_verify_delete_request(inputs)
      dct_auth = self.deeploy_get_auth_result(inputs, sender, verified_sender)
      result = {
        'request' : {
          'app_name' : inputs.app_name,
          'target_nodes' : inputs.target_nodes,
        },
        **dct_auth,
      }
    
    except Exception as e:
      self.P("Error processing request: {}, Inputs: {}".format(e, inputs), color='r')
      result = {
        'error' : str(e)
      }
    
    response = self._get_response({
      **result
    })
    return response
