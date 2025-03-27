"""


"""

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin

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
    

  @BasePlugin.endpoint(method="get")
  # /get_apps
  def get_apps(self):
    """
    Get the list of apps that are running on the node.

    Returns
    -------
    dict
        
    """
    try:
      self.P("Received request for apps")
      data = {
        'apps': []
      }
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      data = {
        'error' : str(e)
      }
    response = self._get_response({
      **data
    })
    return response
    
    

  @BasePlugin.endpoint(method="post")
  # /create_pipeline
  def create_pipeline(
    self, 
    app_name: str = "some_app_name", 
    plugin_signature: str = "PLUGIN_SIGNATURE_01",  
    target_nodes: list[str] = ["0xai_node1", "0xai_node2"], 
    app_params: dict = {"param1": "value1", "param2": "value2"},
  ):
    """
    Receive a request for creating a new pipeline on a target node

    Parameters
    ----------
    """
    try:
      self.P("Received request for new pipeline data")
      data = {
        'name': app_name,
        'target_nodes': target_nodes,
        'signature': plugin_signature,
        'params': app_params
      }
    
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      data = {
        'error' : str(e)
      }
    
    response = self._get_response({
      **data
    })
    return response


  @BasePlugin.endpoint(method="get")
  def delete_pipeline(self, app_name, target_nodes):
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
      data = {
        'name': app_name,
        'target_nodes': target_nodes,
      }
    
    except Exception as e:
      self.P("Error processing request: {}".format(e), color='r')
      data = {
        'error' : str(e)
      }
    
    response = self._get_response({
      **data
    })
    return response
