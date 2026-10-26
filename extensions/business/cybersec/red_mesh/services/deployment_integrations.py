"""RM-139: the resolved views of one deployment integration, for the STA read.

`configured` here means "has a destination and the credentials it needs", independent of
`ENABLED`, which the read reports beside it. It uses the export services' own checks, so the STA
read and the export path never disagree about what is missing.
"""
from .auth import credentials_missing
from .config import get_opencti_export_config, get_taxii_export_config, get_wazuh_export_config
from .misp_config import get_misp_export_config
from .opencti_export import _config_error as _opencti_config_error
from .taxii_export import _config_error as _taxii_config_error

_GETTERS = {
  "misp": get_misp_export_config,
  "opencti": get_opencti_export_config,
  "taxii": get_taxii_export_config,
  "wazuh": get_wazuh_export_config,
}


def _configured(integration_id, cfg):
  if integration_id == "misp":
    return bool(cfg["MISP_URL"] and cfg["MISP_API_KEY"])
  if integration_id == "opencti":
    return _opencti_config_error({**cfg, "ENABLED": True}) is None
  if integration_id == "taxii":
    return _taxii_config_error({**cfg, "ENABLED": True}) is None
  if cfg["MODE"] == "syslog":
    return bool(cfg["SYSLOG_HOST"])
  return bool(cfg["HTTP_URL"]) and credentials_missing(cfg) is None


def integration_config_views(owner, integration_id, row):
  """(deployment, effective, deployment_configured, configured) for the given override row."""
  getter = _GETTERS[integration_id]
  deployment = getter(owner, override=None)
  effective = getter(owner, override=row)
  return deployment, effective, _configured(integration_id, deployment), _configured(integration_id, effective)
