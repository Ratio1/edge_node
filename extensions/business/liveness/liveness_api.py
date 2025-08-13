
from unittest import result
from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin
from ratio1.const.evm_net import EvmNetData, EVM_NET_DATA

__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  "MONITORED_SERVICES" : {
      "DAUTH-API": EvmNetData.DAUTH_URL_KEY,
      "ORACLE-API": EvmNetData.EE_ORACLE_API_URL_KEY,
      "DEEPLOY-API": EvmNetData.EE_DEEPLOY_API_URL_KEY
    },
  'PORT': None,
  # 'ASSETS': 'plugins/business/fastapi/epoch_manager',
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class LivenessApiPlugin(BasePlugin):
  """
  This plugin is a FastAPI web app that provides endpoints to interact with the
  EpochManager of the Neural Core.
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(LivenessApiPlugin, self).__init__(**kwargs)
    return
  

  def on_init(self):
    super(LivenessApiPlugin, self).on_init()
    self.const.BASE_CT.dAuth
    current_epoch = self.netmon.epoch_manager.get_current_epoch()
    self.P("Started {} plugin in epoch {}".format(
      self.__class__.__name__, current_epoch)
    )
    return
  

  def __get_service_url_mapping(self, service_key=''):
    dct_mapping = self.cfg_monitored_services
    url_key = dct_mapping.get(service_key.upper())
    evm_net = self.bc.get_evm_network()
    evm_net_data = EVM_NET_DATA.get(evm_net, {})
    url = evm_net_data.get(url_key, None)
    return url


  def __get_service_status(self, url=''):
    """
    Uses self.requests to test if the url is a live swagger-based api
    """
    if url is None:
      return {"error": "Service URL is not available."}
  
    response = self.requests.get(url, timeout=5)
    if response.status_code == 200:
      return {"status": "running"}
    else:
      return {"status": "stopped"}
    
    
  def __get_all_services_statuses(self):
    statuses = {}
    for service in self.cfg_monitored_services.keys():
      url = self.__get_service_url_mapping(service)
      statuses[service] = self.__get_service_status(url)
    return statuses

  @BasePlugin.endpoint
  # /get_liveness
  def get_liveness(self, service=None):
    """
    
    Parameters
    ----------

    service: str
        The name of the service to check the liveness for:
          "DAUTH-API"
          "ORACLE-API"
          "DEEPLOY-API"

    """
    try:
      if service is None:
        data = self.__get_all_services_statuses()
      else:
        data = {}
        url = self.__get_service_url_mapping(service)
        if url is None:
          data['error'] = f"Service '{service}' is not recognized or not available."
        else:
          data[service.upper()] = self.__get_service_status(url)
        #endif
    except Exception as e:
      data = {'error' : str(e)}
    #endtry
    
    response = self._get_response({
      'services' : {**data}
    })
    return response
