
import re
from urllib.parse import urlsplit, urlunsplit

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin
from ratio1.const.evm_net import EvmNetData

__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,
  
  "RESPONSE_FORMAT" : "RAW",

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




def to_docs_url(raw: str, default_scheme: str = "https") -> str:
  """
  Normalize an API URL to its origin and append '/docs'.

  Parameters
  ----------
  raw : str
    Input URL. Can be malformed (e.g., 'https:/host'), lack a scheme
    (e.g., 'host/path'), or include extra path/query/fragment.
  default_scheme : str, optional
    Scheme to assume when the input has none or has a non-HTTP(S) scheme.
    Defaults to 'https'.

  Returns
  -------
  str
    A normalized absolute URL ending with '/docs'. Examples:
    - 'http://url/something' -> 'http://url/docs'
    - 'url/something' -> 'https://url/docs'
    - 'https://url/' -> 'https://url/docs'
    - 'https:/url' -> 'https://url/docs'

  Notes
  -----
  - Uses Python's `urllib.parse` split/unsplit functions, which follow the
    generic URI syntax (RFC 3986) for component parsing/assembly.
  - The function recovers common user typos like a single slash after the
    scheme (e.g., 'https:/example.com').
  - Any path, query, or fragment is discarded and replaced with '/docs'.

  References
  ----------
  Python `urllib.parse` docs: https://docs.python.org/3/library/urllib.parse.html
  RFC 3986 URI syntax: https://datatracker.ietf.org/doc/html/rfc3986
  """
  if not raw or not isinstance(raw, str):
    raise ValueError("raw must be a non-empty string")

  s = raw.strip().replace("\\", "/")

  # Fix common typo: 'http:/host' -> 'http://host' (and https)
  s = re.sub(r"^(https?):/([^/])", r"\1://\2", s, flags=re.IGNORECASE)

  parts = urlsplit(s)  # (scheme, netloc, path, query, fragment)
  scheme = parts.scheme.lower()
  netloc = parts.netloc
  path = parts.path

  # Case 1: no scheme and no netloc -> treat first path segment as host
  if not scheme and not netloc:
    stripped = path.lstrip("/")
    if not stripped:
      raise ValueError(f"no host found in URL: {raw!r}")
    host, _, _rest = stripped.partition("/")
    scheme = default_scheme
    netloc = host

  # Case 2: scheme present but netloc empty (e.g., 'https:/host/...')
  elif scheme and not netloc:
    stripped = path.lstrip("/")
    host, _, _rest = stripped.partition("/")
    netloc = host

  # Enforce http/https only; otherwise fall back to default_scheme
  if scheme not in ("http", "https"):
    scheme = default_scheme

  return urlunsplit((scheme, netloc, "/docs", "", ""))


class LivenessApiPlugin(BasePlugin):
  """
  This plugin is a FastAPI web app that status info for various services
  """
  CONFIG = _CONFIG

  def __init__(self, **kwargs):
    super(LivenessApiPlugin, self).__init__(**kwargs)
    return
  

  def on_init(self):
    super(LivenessApiPlugin, self).on_init()
    self.evm_net_data = self.bc.get_evm_net_data()
    current_epoch = self.netmon.epoch_manager.get_current_epoch()
    data = self.__get_all_services_statuses()
    self.P("Started {} plugin in epoch {}. Services statuses:\n{}".format(
      self.__class__.__name__, current_epoch,
      self.json_dumps(data, indent=2),
    ))

    return
  

  def __get_service_url_mapping(self, service_key=''):
    dct_mapping = self.cfg_monitored_services
    url_key = dct_mapping.get(service_key.upper())
    url = self.evm_net_data.get(url_key, None)
    if url is None:
      url = url_key  # fallback to the key itself if not found
    return url


  def __get_service_status(self, url=''):
    """
    Uses self.requests to test if the url is a live swagger-based api
    """
    result = {}
    if url is None:
      return {"error": "Service URL is not available."}
    # now check that the url is in the format https://url/ and if it has any appended endpoints such as 
    # https://url/endpoint then delete "endpoint" and replace with /docs
    url = to_docs_url(url)

    self.P("Checking service status for URL: {}".format(url))
    response = self.requests.get(url, timeout=5)
    self.P("Received response {} for {}".format(response.status_code, url))
    result['status_code'] = response.status_code
    if response.status_code == 200:
      result["status"] = "live"
      result["message"] = "Service is running smoothly."
    else:
      result["status"] = "down"
      result["message"] = "Service is in maintenance mode."
    return result
    
    
  def __get_all_services_statuses(self):
    statuses = {}
    for service in self.cfg_monitored_services.keys():
      url = self.__get_service_url_mapping(service)
      statuses[service] = self.__get_service_status(url)
    return statuses

  @BasePlugin.endpoint
  # /get_liveness_data
  def get_liveness_data(self, service=None):
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
      'services' : {**data},
      'network'  : self.bc.get_evm_network(),
    })
    return response

  @BasePlugin.endpoint
  # /get_liveness_data
  def simple_liveness(self, service=None, extended_message : int = 0):
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
        response = "please provide data"
      else:
        url = self.__get_service_url_mapping(service)
        if url is None:
          response = "please provide a valid service"
        else:
          data = self.__get_service_status(url)
          if extended_message:
            response = data["message"]
          else:
            response = data["status"]
        #endif
        self.P("Responding simple liveness check '{}': {}".format(service, response))
    except Exception as e:
      response = 'error' + str(e)
    #endtry
    return response
