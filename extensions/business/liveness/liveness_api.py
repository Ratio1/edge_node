
import re
from urllib.parse import urlsplit, urlunsplit

from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin
from ratio1.const.evm_net import EvmNetData

__VER__ = '0.2.0'

_CONFIG = {
  **BasePlugin.CONFIG,
  
  "RESPONSE_FORMAT" : "RAW",

  "MONITORED_SERVICES" : {
      "DAUTH-API": {
        "url_key": EvmNetData.DAUTH_URL_KEY,
        "type": "api",
      },
      "ORACLE-API": {
        "url_key": EvmNetData.EE_ORACLE_API_URL_KEY,
        "type": "api",
      },
      "DEEPLOY-API": {
        "url_key": EvmNetData.EE_DEEPLOY_API_URL_KEY,
        "type": "api",
      },
      "DAPP-APP": {
        "url_key": EvmNetData.EE_DAPP_APP_URL_KEY,
        "type": "app",
        "expected_substring": "<title>Ratio1 App</title>",
      },
      "EXPLORER-APP": {
        "url_key": EvmNetData.EE_EXPLORER_APP_URL_KEY,
        "type": "app",
        "expected_substring": "<title>Ratio1 Explorer</title>",
      },
      "DEEPLOY-APP": {
        "url_key": EvmNetData.EE_DEEPLOY_APP_URL_KEY,
        "type": "app",
        "expected_substring": "<title>Ratio1 Deeploy</title>",
      },
    },
  'PORT': None,
  # 'ASSETS': 'plugins/business/fastapi/epoch_manager',
  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


def build_service_url(service_cfg):
  url = service_cfg.get("url", None)
  if url is None:
    return None
  svc_type = service_cfg.get("type", "api")
  if svc_type == "api":
    full_url = to_docs_url(url)
  else:
    full_url = url
  return full_url
  


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
  

  def __get_service_config(self, service_key):
    dct_mapping = self.cfg_monitored_services
    service_config = dct_mapping.get(service_key.upper())
    if service_config is None:
      return None
    url_key = service_config.get("url_key", None)
    url = self.evm_net_data.get(url_key, None)
    if url is None:
      url = url_key  # fallback to the key itself if not found
    service_config["url"] = url
    return service_config


  def __get_service_status(self, service_config):
    """
    Uses self.requests to test if the url is a live swagger-based api or frontend app.
    """
    result = {}
    url = build_service_url(service_config)
    if url is None:
      return {"error": "Service URL is not available."}
    expected_marker = service_config.get("expected_substring")

    self.P("Checking service status for URL: {}".format(url))
    response = self.requests.get(url, timeout=5)
    self.P("Received response {} for {}".format(response.status_code, url))
    result['status_code'] = response.status_code
    service_is_ok = False
    if response.status_code == 200:
      service_is_ok = True
      if expected_marker:
        service_is_ok = expected_marker.lower() in response.text.lower()
    if service_is_ok:
      result["status"] = "live"
      result["message"] = "Service is running smoothly."
      result["color"] = "#1B47F7"
    else:
      result["status"] = "down"
      result["message"] = "Service is in maintenance mode."
      result["color"] = "#F261A2"
    return result
    
    
  def __get_all_services_statuses(self):
    statuses = {}
    for service in self.cfg_monitored_services.keys():
      cfg = self.__get_service_config(service)
      statuses[service] = self.__get_service_status(cfg)
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
          "DAPP-APP"
          "EXPLORER-APP"
          "DEEPLOY-APP"

    """
    try:
      if service is None:
        data = self.__get_all_services_statuses()
      else:
        data = {}
        cfg = self.__get_service_config(service)
        if cfg is None:
          data['error'] = f"Service '{service}' is not recognized or not available."
        else:
          data[service.upper()] = self.__get_service_status(cfg)
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
        "DAPP-APP"
        "EXPLORER-APP"
        "DEEPLOY-APP"

    """
    try:
      if service is None:
        response = "please provide data"
      else:
        cfg = self.__get_service_config(service)
        if cfg is None:
          response = "please provide a valid service"
        else:
          data = self.__get_service_status(cfg)
          if extended_message == 1:
            response = data["message"]
          elif extended_message == 2:
            color = data["color"]
            response = color #f"<span style='color:{color}'>{data['message']}</span
          else:
            response = data["status"]
        #endif
        self.P("Responding simple liveness check '{}': {}".format(service, response))
    except Exception as e:
      response = 'error' + str(e)
    #endtry
    return response
